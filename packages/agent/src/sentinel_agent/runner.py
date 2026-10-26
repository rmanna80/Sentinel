"""Plans and runs a scan: per-check timeouts, cancellation, partial results, upload as it goes."""

from __future__ import annotations

import json
import logging
import queue
import threading
import time
import traceback
from collections.abc import Callable
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any, Protocol

from pydantic import BaseModel, ValidationError
from sentinel_core.checks import Check, CheckContext, NotApplicable, SkipCheck
from sentinel_core.models import (
    SCAN_TYPE_PROFILES,
    AgentJob,
    CheckOutput,
    CheckRunResult,
    CheckStatus,
    Evidence,
    FindingKind,
    HostInfo,
    PlannedCheck,
    PlanStatus,
    ScanPlan,
    ScanStatus,
    Severity,
    utcnow,
)
from sentinel_core.redaction import redact

from .registry import CheckRegistry
from .safe_commands import CommandCancelled, CommandFailed, CommandRefused, CommandTimedOut

log = logging.getLogger(__name__)

MAX_EVIDENCE_BYTES = 256 * 1024
MAX_EVENTS_PER_CHECK = 5000
MAX_SOFTWARE_PER_CHECK = 20000

ELEVATION_REASON = "Needs administrator rights. Run an elevated scan to include it."


class ResultSink(Protocol):
    def send_plan(self, plan: ScanPlan) -> None: ...

    def send_result(self, result: CheckRunResult) -> None: ...

    def heartbeat(self) -> bool:
        """Return True when the server asks for the scan to be cancelled."""
        ...


ContextFactory = Callable[[Check, BaseModel | None, Callable[[], bool]], CheckContext]


@dataclass
class _Planned:
    check: Check
    params: BaseModel | None


def build_plan(registry: CheckRegistry, job: AgentJob, host: HostInfo) -> tuple[list[PlannedCheck], list[_Planned]]:
    if job.check_ids:
        candidates = [c for cid in job.check_ids if (c := registry.get(cid)) is not None]
        unknown = [cid for cid in job.check_ids if cid not in registry]
        if unknown:
            log.warning("ignoring unknown check ids from server: %s", unknown)
    else:
        profiles = SCAN_TYPE_PROFILES[job.scan_type]
        candidates = [c for c in registry if type(c).profiles & profiles]

    planned: list[PlannedCheck] = []
    runnable: list[_Planned] = []
    for check in candidates:
        cls = type(check)
        status, reason, params = PlanStatus.PLANNED, None, None
        if host.os_family not in cls.platforms:
            status, reason = PlanStatus.NOT_APPLICABLE, f"Not available on {host.os_family.value.title()}"
        elif (why := check.applicable(host)) is not None:
            status, reason = PlanStatus.NOT_APPLICABLE, why
        elif cls.requires_elevation and not host.is_elevated:
            status, reason = PlanStatus.SKIPPED, ELEVATION_REASON
        elif cls.params_model is not None:
            raw = job.params.get(cls.id)
            if raw is None:
                status, reason = PlanStatus.SKIPPED, "This check needs parameters (for example targets or paths)."
            else:
                try:
                    params = cls.params_model.model_validate(raw)
                except ValidationError as exc:
                    status, reason = PlanStatus.SKIPPED, f"Invalid parameters: {exc.errors()[0]['msg']}"
        planned.append(
            PlannedCheck(
                check_id=cls.id, check_version=cls.version, title=cls.title, category=cls.category,
                status=status, reason=reason, data_collected=cls.data_collected,
                requires_elevation=cls.requires_elevation,
            )
        )
        if status is PlanStatus.PLANNED:
            runnable.append(_Planned(check, params))
    return planned, runnable


def finalize_output(output: CheckOutput) -> CheckOutput:
    """Redact secrets and cap sizes before anything leaves the agent."""
    evidence: list[Evidence] = []
    for ev in output.evidence:
        content, _ = redact(ev.content)
        raw = json.dumps(content, default=str)
        if len(raw.encode("utf-8")) > MAX_EVIDENCE_BYTES:
            content = {"truncated": True, "original_bytes": len(raw), "preview": raw[: MAX_EVIDENCE_BYTES // 2]}
        evidence.append(ev.model_copy(update={"content": content}))
    events = []
    for event in output.events[:MAX_EVENTS_PER_CHECK]:
        data, _ = redact(event.data)
        message, _ = redact(event.message)
        events.append(event.model_copy(update={"data": data, "message": message}))
    return output.model_copy(
        update={"evidence": evidence, "events": events, "software": output.software[:MAX_SOFTWARE_PER_CHECK]}
    )


def decide_status(output: CheckOutput) -> CheckStatus:
    for f in output.findings:
        if f.kind is not FindingKind.INFORMATIONAL and f.severity is not Severity.INFO:
            return CheckStatus.FAILED
    return CheckStatus.PASSED


@dataclass
class _Running:
    planned: _Planned
    started: float
    cancel: threading.Event
    future: Future[Any]
    started_at: Any = field(default_factory=utcnow)
    done: bool = False


class ScanRunner:
    def __init__(
        self,
        registry: CheckRegistry,
        host: HostInfo,
        context_factory: ContextFactory,
        sink: ResultSink,
        max_workers: int = 3,
        heartbeat_interval: float = 5.0,
        poll_interval: float = 0.2,
    ) -> None:
        self.registry = registry
        self.host = host
        self.context_factory = context_factory
        self.sink = sink
        self.max_workers = max_workers
        self.heartbeat_interval = heartbeat_interval
        self.poll_interval = poll_interval
        self.global_cancel = threading.Event()

    def run(self, job: AgentJob) -> ScanStatus:
        planned, runnable = build_plan(self.registry, job, self.host)
        self.sink.send_plan(ScanPlan(host=self.host, checks=planned, data_mode=job.data_mode))
        if not runnable:
            return ScanStatus.COMPLETED

        results: queue.Queue[CheckRunResult] = queue.Queue()
        recorded: set[str] = set()
        statuses: list[CheckStatus] = []
        pending = list(runnable)
        running: list[_Running] = []
        last_heartbeat = time.monotonic()

        def record(result: CheckRunResult) -> None:
            if result.check_id in recorded:
                return
            recorded.add(result.check_id)
            statuses.append(result.status)
            self.sink.send_result(result)

        # Not a context manager: a check stuck in pure Python must not block the scan from closing.
        pool = ThreadPoolExecutor(max_workers=self.max_workers, thread_name_prefix="check")
        try:
            while pending or any(not r.done for r in running):
                # start work while there is capacity
                while pending and sum(1 for r in running if not r.done) < self.max_workers:
                    if self.global_cancel.is_set():
                        break
                    item = pending.pop(0)
                    cancel = threading.Event()
                    future = pool.submit(self._execute, item, cancel, results)
                    running.append(_Running(item, time.monotonic(), cancel, future))

                # drain finished results
                while True:
                    try:
                        record(results.get_nowait())
                    except queue.Empty:
                        break

                now = time.monotonic()
                for entry in running:
                    if entry.done:
                        continue
                    if entry.future.done():
                        entry.done = True
                        continue
                    timeout = type(entry.planned.check).timeout_seconds
                    if now - entry.started > timeout:
                        entry.cancel.set()
                        entry.done = True
                        record(self._result(entry.planned.check, CheckStatus.TIMEOUT, entry.started_at,
                                            error=f"Did not finish within {timeout:.0f} seconds"))

                if now - last_heartbeat >= self.heartbeat_interval:
                    last_heartbeat = now
                    try:
                        if self.sink.heartbeat():
                            self.global_cancel.set()
                    except Exception as exc:  # network blips must not kill the scan
                        log.warning("heartbeat failed: %s", exc)

                if self.global_cancel.is_set() and pending:
                    for item in pending:
                        record(self._result(item.check, CheckStatus.CANCELLED, utcnow(),
                                            error="Scan cancelled before this check started"))
                    pending.clear()

                if pending or any(not r.done for r in running):
                    time.sleep(self.poll_interval)

            # final drain: results from checks that finished on the last loop
            while True:
                try:
                    record(results.get_nowait())
                except queue.Empty:
                    break
        finally:
            pool.shutdown(wait=False, cancel_futures=True)

        if self.global_cancel.is_set():
            return ScanStatus.CANCELLED
        if any(s in (CheckStatus.ERROR, CheckStatus.TIMEOUT) for s in statuses):
            return ScanStatus.PARTIAL
        return ScanStatus.COMPLETED

    # ------------------------------------------------------------------ one check
    def _execute(self, item: _Planned, cancel: threading.Event, results: queue.Queue[CheckRunResult]) -> None:
        check = item.check
        started_at = utcnow()

        def is_cancelled() -> bool:
            return cancel.is_set() or self.global_cancel.is_set()

        try:
            ctx = self.context_factory(check, item.params, is_cancelled)
            output = finalize_output(check.run(ctx))
            if cancel.is_set():
                return  # already recorded as a timeout
            results.put(self._result(check, decide_status(output), started_at, output=output))
        except SkipCheck as exc:
            results.put(self._result(check, CheckStatus.SKIPPED, started_at, skip=str(exc)))
        except NotApplicable as exc:
            results.put(self._result(check, CheckStatus.NOT_APPLICABLE, started_at, skip=str(exc)))
        except CommandCancelled:
            if not cancel.is_set():
                results.put(self._result(check, CheckStatus.CANCELLED, started_at, error="Cancelled"))
        except CommandTimedOut as exc:
            results.put(self._result(check, CheckStatus.TIMEOUT, started_at, error=str(exc)))
        except CommandRefused as exc:
            log.error("check %s tried an unregistered command: %s", type(check).id, exc)
            results.put(self._result(check, CheckStatus.ERROR, started_at, error=str(exc)))
        except CommandFailed as exc:
            detail = f"{exc}" + (f": {exc.stderr.strip()[:300]}" if exc.stderr.strip() else "")
            results.put(self._result(check, CheckStatus.ERROR, started_at, error=detail))
        except Exception as exc:
            log.error("check %s crashed:\n%s", type(check).id, traceback.format_exc())
            results.put(self._result(check, CheckStatus.ERROR, started_at, error=f"{type(exc).__name__}: {exc}"[:500]))

    def _result(
        self,
        check: Check,
        status: CheckStatus,
        started_at: Any,
        output: CheckOutput | None = None,
        skip: str | None = None,
        error: str | None = None,
    ) -> CheckRunResult:
        finished = utcnow()
        cls = type(check)
        return CheckRunResult(
            check_id=cls.id,
            check_version=cls.version,
            status=status,
            skip_reason=skip,
            error_message=error,
            started_at=started_at,
            finished_at=finished,
            duration_ms=max(0, int((finished - started_at).total_seconds() * 1000)),
            ran_elevated=self.host.is_elevated,
            output=output,
        )


class CollectingSink:
    """Collects a scan in memory (used by ``scan --local`` and tests)."""

    def __init__(self, cancel_after_heartbeats: int | None = None) -> None:
        self.plan: ScanPlan | None = None
        self.results: list[CheckRunResult] = []
        self._beats = 0
        self._cancel_after = cancel_after_heartbeats

    def send_plan(self, plan: ScanPlan) -> None:
        self.plan = plan

    def send_result(self, result: CheckRunResult) -> None:
        self.results.append(result)

    def heartbeat(self) -> bool:
        self._beats += 1
        return self._cancel_after is not None and self._beats >= self._cancel_after
