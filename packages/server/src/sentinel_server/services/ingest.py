"""Turns agent uploads into stored scans, evidence, findings, events, software and metrics."""

from __future__ import annotations

import hashlib
import json
import logging
from datetime import timedelta

from sentinel_core.models import (
    COMPLETED_CHECK_STATUSES,
    CheckRunResult,
    DataMode,
    HostInfo,
    MetricSample,
    ScanCompletion,
    ScanPlan,
    ScanStatus,
    Severity,
)
from sentinel_core.redaction import redact
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.orm import Session

from .. import audit
from ..config import Mode, Settings
from ..models import (
    CheckRun,
    Device,
    EvidenceRecord,
    FindingRecord,
    LogEventRecord,
    MetricSampleRecord,
    Scan,
    SoftwareRecord,
    now,
)
from . import hooks
from .findings import reconcile
from .scoring import scan_snapshot

log = logging.getLogger(__name__)

MAX_EVIDENCE_BYTES = 256 * 1024
# Per-result limits. The agent stays well inside them; anything larger is a protocol violation and is
# rejected whole (truncating findings would wrongly resolve the ones cut off).
MAX_FINDINGS_PER_RESULT = 2000
MAX_EVIDENCE_PER_RESULT = 100
MAX_EVENTS_PER_RESULT = 5000
MAX_SOFTWARE_PER_RESULT = 20000
MAX_METRICS_PER_RESULT = 200
MAX_EVENT_DATA_BYTES = 16 * 1024
TERMINAL_STATUSES = frozenset({ScanStatus.COMPLETED, ScanStatus.PARTIAL, ScanStatus.FAILED, ScanStatus.CANCELLED})


class IngestError(ValueError):
    pass


def apply_host(device: Device, host: HostInfo) -> None:
    device.hostname = host.hostname
    device.os_family = host.os_family.value
    device.os_name = host.os_name
    device.os_version = host.os_version
    device.os_build = host.os_build
    device.edition = host.edition
    device.arch = host.arch
    device.distro_id = host.distro_id
    device.distro_version = host.distro_version
    device.is_insider_build = host.is_insider_build
    device.agent_version = host.agent_version
    device.agent_elevated = host.is_elevated
    device.last_seen_at = now()


def _require_running(scan: Scan) -> None:
    if scan.status not in ("running",):
        raise IngestError(f"scan {scan.id} is {scan.status}, not running")


def extend_lease(scan: Scan, settings: Settings) -> None:
    scan.lease_expires_at = now() + timedelta(seconds=settings.agent_lease_seconds)


def record_plan(db: Session, scan: Scan, device: Device, plan: ScanPlan, settings: Settings) -> None:
    _require_running(scan)
    if plan.data_mode is DataMode.FIXTURE:
        if settings.mode is Mode.PRODUCTION:
            scan.status = ScanStatus.FAILED.value
            scan.error = "Fixture (demo) data was refused because the server runs in production mode."
            scan.completed_at = now()
            audit.record(db, f"device:{device.id}", "scan.fixture_refused", "scan", scan.id)
            db.commit()
            raise IngestError(scan.error)
        scan.data_mode = DataMode.FIXTURE.value
    apply_host(device, plan.host)
    scan.host_snapshot = plan.host.model_dump(mode="json")
    existing = {r.check_id: r for r in scan.check_runs}
    for p in plan.checks:
        run = existing.get(p.check_id) or CheckRun(scan_id=scan.id, check_id=p.check_id)
        run.check_version = p.check_version
        run.title = p.title
        run.category = p.category
        run.status = p.status.value  # planned | skipped | not_applicable
        run.skip_reason = p.reason
        run.data_collected = p.data_collected
        run.requires_elevation = p.requires_elevation
        if p.check_id not in existing:
            db.add(run)
            scan.check_runs.append(run)
    extend_lease(scan, settings)
    db.flush()


def _store_evidence(db: Session, run: CheckRun, result: CheckRunResult) -> list[int]:
    ids: list[int] = []
    assert result.output is not None
    for i, ev in enumerate(result.output.evidence):
        content, redacted = redact(ev.content)
        raw = json.dumps(content, sort_keys=True, default=str)
        if len(raw.encode("utf-8")) > MAX_EVIDENCE_BYTES:
            content = {"truncated": True, "original_bytes": len(raw), "preview": raw[: MAX_EVIDENCE_BYTES // 2]}
            raw = json.dumps(content, sort_keys=True)
        rec = EvidenceRecord(
            check_run_id=run.id, position=i, kind=ev.kind, source=ev.source[:300], content=content,
            content_sha256=hashlib.sha256(raw.encode("utf-8")).hexdigest(), size_bytes=len(raw),
            redacted=redacted, collected_at=ev.collected_at,
        )
        db.add(rec)
        db.flush()
        ids.append(rec.id)
    return ids


def _store_events(db: Session, device: Device, scan: Scan, result: CheckRunResult) -> list[LogEventRecord]:
    assert result.output is not None
    if not result.output.events:
        return []
    stored: list[LogEventRecord] = []
    for ev in result.output.events:
        data, _ = redact(ev.data)
        raw_data = json.dumps(data, default=str)
        if len(raw_data.encode("utf-8")) > MAX_EVENT_DATA_BYTES:
            data = {"truncated": True, "original_bytes": len(raw_data), "preview": raw_data[: MAX_EVENT_DATA_BYTES // 2]}
        message, _ = redact(ev.message)
        insert = pg_insert if db.get_bind().dialect.name == "postgresql" else sqlite_insert
        stmt = (
            insert(LogEventRecord)
            .values(
                device_id=device.id, source=ev.source, record_id=ev.record_id, event_id=ev.event_id,
                occurred_at=ev.occurred_at, category=ev.category, action=ev.action, outcome=ev.outcome,
                severity=ev.severity.value, user=ev.user, source_ip=ev.source_ip, process=ev.process,
                message=message, data=data, ingested_at=now(), scan_id=scan.id,
            )
            .on_conflict_do_nothing(index_elements=["device_id", "source", "record_id"])
        )
        res = db.execute(stmt)
        if res.rowcount:
            rec = db.execute(
                select(LogEventRecord).where(LogEventRecord.device_id == device.id,
                                             LogEventRecord.source == ev.source,
                                             LogEventRecord.record_id == ev.record_id)
            ).scalar_one()
            stored.append(rec)
    return stored


def _store_software(db: Session, device: Device, scan: Scan, result: CheckRunResult) -> int:
    """Upsert this check's software list and mark items it no longer reports as absent."""
    assert result.output is not None
    t = now()
    seen_ids: set[int] = set()
    ecosystems = {s.ecosystem for s in result.output.software}
    for s in result.output.software:
        loc = s.location or ""
        rec = db.execute(
            select(SoftwareRecord).where(
                SoftwareRecord.device_id == device.id, SoftwareRecord.ecosystem == s.ecosystem,
                SoftwareRecord.name == s.name, SoftwareRecord.version == s.version, SoftwareRecord.location == loc,
            )
        ).scalar_one_or_none()
        if rec is None:
            rec = SoftwareRecord(device_id=device.id, name=s.name, version=s.version, publisher=s.publisher,
                                 ecosystem=s.ecosystem, source=s.source, location=loc, install_date=s.install_date,
                                 first_seen_at=t, match_status="pending")
            db.add(rec)
        rec.last_seen_at = t
        rec.last_scan_id = scan.id
        if not rec.is_present:
            rec.is_present = True
            rec.match_status = "pending"
        db.flush()
        seen_ids.add(rec.id)
    if ecosystems:
        for rec in db.execute(
            select(SoftwareRecord).where(SoftwareRecord.device_id == device.id,
                                         SoftwareRecord.ecosystem.in_(ecosystems),
                                         SoftwareRecord.is_present.is_(True))
        ).scalars():
            if rec.id not in seen_ids:
                rec.is_present = False
    return len(seen_ids)


def _store_metrics(db: Session, device: Device, samples: list[MetricSample]) -> None:
    for m in samples[:200]:
        db.add(MetricSampleRecord(device_id=device.id, ts=m.ts, metric=m.metric[:128], value=float(m.value)))


def _check_limits(result: CheckRunResult) -> None:
    out = result.output
    if out is None:
        return
    for name, items, limit in (
        ("findings", out.findings, MAX_FINDINGS_PER_RESULT), ("evidence items", out.evidence, MAX_EVIDENCE_PER_RESULT),
        ("events", out.events, MAX_EVENTS_PER_RESULT), ("software items", out.software, MAX_SOFTWARE_PER_RESULT),
        ("metrics", out.metrics, MAX_METRICS_PER_RESULT),
    ):
        if len(items) > limit:
            raise IngestError(f"result for {result.check_id} has {len(items)} {name}; the limit is {limit}")


def record_result(db: Session, scan: Scan, device: Device, result: CheckRunResult, settings: Settings) -> CheckRun:
    _require_running(scan)
    _check_limits(result)
    run = next((r for r in scan.check_runs if r.check_id == result.check_id), None)
    if run is None:
        raise IngestError(f"check {result.check_id} was not in this scan's plan")
    if run.status not in ("planned",):
        raise IngestError(f"check {result.check_id} already has a result in scan {scan.id}")
    run.check_version = result.check_version
    run.status = result.status.value
    run.skip_reason = result.skip_reason
    run.error_message = result.error_message
    run.started_at = result.started_at
    run.finished_at = result.finished_at
    run.duration_ms = result.duration_ms
    run.ran_elevated = result.ran_elevated
    db.flush()

    if result.output is not None and result.status in COMPLETED_CHECK_STATUSES:
        evidence_ids = _store_evidence(db, run, result)
        created, reopened, _resolved = reconcile(
            db, device_id=device.id, scan=scan, check_run=run, findings=result.output.findings,
            evidence_ids=evidence_ids, category_default=run.category, scope=result.output.reconcile_scope,
        )
        run.finding_count = len(result.output.findings)
        if created or reopened:
            hooks.fire("findings_created", db, device, created + reopened)
        events = _store_events(db, device, scan, result)
        if events:
            hooks.fire("events_ingested", db, device, scan, events)
        if result.output.software:
            _store_software(db, device, scan, result)
            hooks.fire("software_ingested", db, device, scan, run)
        _store_metrics(db, device, result.output.metrics)
    elif result.output is not None:
        # Evidence from a check that did not complete is still worth keeping; findings are not applied.
        _store_evidence(db, run, result)
    extend_lease(scan, settings)
    device.last_seen_at = now()
    db.flush()
    return run


def complete_scan(db: Session, scan: Scan, completion: ScanCompletion, settings: Settings) -> Scan:
    if completion.status not in TERMINAL_STATUSES:
        raise IngestError(f"a scan cannot be completed as {completion.status.value}")
    if scan.status != "running":
        return scan
    status = completion.status
    unfinished = [r for r in scan.check_runs if r.status == "planned"]
    for r in unfinished:
        r.status = "error"
        r.error_message = "No result received from the agent"
    if unfinished and status is ScanStatus.COMPLETED:
        status = ScanStatus.PARTIAL
    scan.status = status.value
    scan.error = completion.error
    scan.completed_at = now()
    scan.lease_expires_at = None
    snap = scan_snapshot(db, scan, settings.min_score_coverage)
    scan.score = snap["score"]
    scan.coverage = snap["coverage"]
    scan.summary = snap
    db.flush()
    audit.record(db, f"device:{scan.device_id}", "scan.completed", "scan", scan.id,
                 {"status": scan.status, "score": scan.score, "coverage": scan.coverage})
    hooks.fire("scan_completed", db, scan)
    return scan


def expire_stale_scans(db: Session) -> int:
    """Running scans whose agent stopped heartbeating become failed."""
    t = now()
    n = 0
    stuck_before = t - timedelta(hours=6)
    for scan in db.execute(
        select(Scan).where(
            Scan.status == "running",
            ((Scan.lease_expires_at.is_not(None)) & (Scan.lease_expires_at < t))
            | ((Scan.lease_expires_at.is_(None)) & (Scan.started_at < stuck_before)),
        )
    ).scalars():
        for r in scan.check_runs:
            if r.status == "planned":
                r.status = "error"
                r.error_message = "Agent stopped responding"
        scan.status = ScanStatus.FAILED.value
        scan.error = "The agent stopped responding during this scan."
        scan.completed_at = t
        audit.record(db, "system", "scan.lease_expired", "scan", scan.id)
        hooks.fire("scan_completed", db, scan)
        n += 1
    return n


def severity_at_least(sev: str, minimum: str) -> bool:
    order = [s.value for s in (Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL)]
    return order.index(sev) >= order.index(minimum)


__all__ = ["FindingRecord", "IngestError", "complete_scan", "record_plan", "record_result"]
