"""Command-line entry point: ``sentinel-agent``."""

from __future__ import annotations

import argparse
import json
import logging
import logging.handlers
import sys
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from pydantic import BaseModel
from sentinel_core.checks import AgentState, Check, CheckContext
from sentinel_core.models import (
    AgentJob,
    CheckRunResult,
    CheckStatus,
    DataMode,
    HostInfo,
    MetricSample,
    ScanStatus,
    ScanType,
    utcnow,
)

from . import __version__
from .config import (
    AgentConfig,
    FileState,
    MemoryState,
    StagedState,
    agent_home,
    load_token,
    store_token,
    validate_server_url,
)
from .context import LiveContext, Recorder
from .hostinfo import current_host
from .registry import CheckRegistry, default_registry
from .runner import CollectingSink, ScanRunner
from .safe_commands import SafeCommandRunner
from .testing import FixtureContext

log = logging.getLogger("sentinel_agent")


def _setup_logging(verbose: bool) -> None:
    handler = logging.handlers.RotatingFileHandler(agent_home() / "agent.log", maxBytes=2_000_000, backupCount=3,
                                                   encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    console = logging.StreamHandler(sys.stderr)
    console.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))
    root = logging.getLogger()
    root.setLevel(logging.DEBUG if verbose else logging.INFO)
    root.addHandler(handler)
    root.addHandler(console)
    for noisy in ("httpx", "httpcore"):  # one line per HTTP request is noise, not information
        logging.getLogger(noisy).setLevel(logging.WARNING)


ContextFactory = Callable[[Check, BaseModel | None, Callable[[], bool]], CheckContext]


class LiveContextFactory:
    """Builds a LiveContext per check. Each check writes state (log cursors) to its own StagedState over the
    shared FileState, kept in ``staged`` by check id; nothing is saved until ``commit_sent`` is called for a
    result the server accepted. A local scan never commits, so it cannot consume events the server-run agent
    still has to upload."""

    def __init__(self, host: HostInfo, config: AgentConfig, recorder: Recorder | None = None,
                 state: AgentState | None = None) -> None:
        self.host = host
        self.config = config
        self.recorder = recorder
        self.state: AgentState = state if state is not None else FileState()
        self.staged: dict[str, StagedState] = {}
        self._lock = threading.Lock()

    def __call__(self, check: Check, params: BaseModel | None, cancelled: Callable[[], bool]) -> CheckContext:
        staged = StagedState(self.state)
        with self._lock:
            self.staged[type(check).id] = staged  # a new run of the check replaces any uncommitted state
        # Each check gets a runner that only knows its own declared commands.
        runner = SafeCommandRunner(type(check).commands, cancelled=cancelled,
                                   recorder=self.recorder.command if self.recorder else None)
        return LiveContext(self.host, runner, staged, self.config.as_mapping(), cancelled, params, self.recorder)

    def commit_sent(self, result: CheckRunResult) -> None:
        """ScanRunner ``on_sent`` callback: save the check's state only if it completed (passed or failed)."""
        with self._lock:
            staged = self.staged.pop(result.check_id, None)
        if staged is not None and result.status in (CheckStatus.PASSED, CheckStatus.FAILED):
            staged.commit()


def live_context_factory(host: HostInfo, config: AgentConfig, recorder: Recorder | None = None) -> LiveContextFactory:
    return LiveContextFactory(host, config, recorder)


def fixture_context_factory(fixture: dict[str, Any], host: HostInfo, config: AgentConfig) -> ContextFactory:
    state = MemoryState()

    def factory(check: Check, params: BaseModel | None, cancelled: Callable[[], bool]) -> CheckContext:
        return FixtureContext(host, fixture, params=params, config=config.as_mapping(), state=state,
                              cancelled=cancelled)

    return factory


def is_loopback_url(url: str) -> bool:
    from urllib.parse import urlparse

    return urlparse(url).hostname in ("127.0.0.1", "localhost", "::1")


def _load_fixture(path: str) -> tuple[dict[str, Any], HostInfo]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return data, HostInfo(**data["host"])


# --------------------------------------------------------------------------- commands


def cmd_checks(args: argparse.Namespace, registry: CheckRegistry) -> int:
    for d in sorted(registry.descriptors(), key=lambda d: d.id):
        plats = ",".join(p.value for p in d.platforms)
        elev = " [admin]" if d.requires_elevation else ""
        print(f"{d.id:<34} {plats:<14} {','.join(d.profiles):<10} {d.title}{elev}")
    return 0


def cmd_scan(args: argparse.Namespace, registry: CheckRegistry) -> int:
    config = AgentConfig.load()
    recorder = Recorder() if args.record else None
    if args.fixtures:
        fixture, host = _load_fixture(args.fixtures)
        factory = fixture_context_factory(fixture, host, config)
    else:
        host = current_host()
        factory = live_context_factory(host, config, recorder)
    params = json.loads(args.params) if args.params else {}
    job = AgentJob(
        scan_id=0,
        scan_type=ScanType(args.type) if not args.checks else ScanType.CUSTOM,
        check_ids=args.checks.split(",") if args.checks else None,
        params=params,
        data_mode=DataMode.FIXTURE if args.fixtures else DataMode.LIVE,
    )
    sink = CollectingSink()
    # No on_sent: a local scan never commits log cursors (its staged state is discarded with the factory).
    status = ScanRunner(registry, host, factory, sink, heartbeat_interval=3600).run(job)
    if recorder is not None:
        out = Path(args.record)
        out.mkdir(parents=True, exist_ok=True)
        fixture_out = {
            "_fixture": f"Recorded from {host.hostname} on {utcnow().isoformat()} by sentinel-agent {__version__}",
            "host": host.model_dump(mode="json"),
            "commands": recorder.commands,
            "registry": recorder.registry,
            "files": recorder.files,
        }
        target = out / f"{host.hostname}-{utcnow().strftime('%Y%m%d-%H%M%S')}.json"
        target.write_text(json.dumps(fixture_out, indent=2, default=str), encoding="utf-8")
        print(f"Recorded raw outputs to {target}", file=sys.stderr)
    if args.json:
        print(json.dumps({
            "status": status.value,
            "plan": sink.plan.model_dump(mode="json") if sink.plan else None,
            "results": [r.model_dump(mode="json") for r in sink.results],
        }, indent=2, default=str))
        return 0
    _print_human(sink, status)
    return 0


def _print_human(sink: CollectingSink, status: ScanStatus) -> None:
    assert sink.plan is not None
    print(f"Host: {sink.plan.host.hostname} ({sink.plan.host.os_name} {sink.plan.host.os_version}, "
          f"{'elevated' if sink.plan.host.is_elevated else 'standard user'})")
    for p in sink.plan.checks:
        if p.status.value != "planned":
            print(f"  [{p.status.value:<14}] {p.check_id}: {p.reason}")
    for r in sink.results:
        print(f"  [{r.status.value:<14}] {r.check_id} ({r.duration_ms} ms)"
              + (f": {r.skip_reason or r.error_message}" if (r.skip_reason or r.error_message) else ""))
        if r.output:
            for f in r.output.findings:
                print(f"      - {f.severity.value.upper():<8} {f.title}")
    print(f"Scan status: {status.value}")


def cmd_enroll(args: argparse.Namespace, registry: CheckRegistry) -> int:
    from .transport import ServerClient

    url = validate_server_url(args.server)
    # Demo mode enrolls as the fixture's machine, so the dashboard shows its name rather than this one's.
    host = _load_fixture(args.fixtures)[1] if args.fixtures else current_host()
    client = ServerClient(url)
    resp = client.enroll(args.code.strip(), host)
    where = store_token(url, resp.device_token)
    config = AgentConfig.load()
    config.server_url = url
    config.device_id = resp.device_id
    config.save()
    print(f"Enrolled as device {resp.device_id}. Token stored in {where}.")
    return 0


def _metrics() -> list[MetricSample]:
    import psutil

    now = utcnow()
    samples = [
        MetricSample(metric="cpu_percent", value=psutil.cpu_percent(interval=None), ts=now),
        MetricSample(metric="memory_percent", value=psutil.virtual_memory().percent, ts=now),
    ]
    try:
        root = "C:\\" if sys.platform == "win32" else "/"
        samples.append(MetricSample(metric="disk_percent", value=psutil.disk_usage(root).percent, ts=now))
    except OSError:
        pass
    return samples


def _telemetry_step(client: Any, engine: Any, host: HostInfo, config: AgentConfig) -> None:
    """One Sentinel X cycle inside the run loop: read Sysmon, correlate, ship detections. Never fatal."""
    from .telemetry.collector import CollectorError, SysmonCollector
    from .telemetry.pump import run_cycle

    runner = SafeCommandRunner(SysmonCollector.commands, cancelled=lambda: False)
    state = StagedState(FileState())
    ctx = LiveContext(host, runner, state, config.as_mapping(), lambda: False, None, None)
    try:
        detections = run_cycle(SysmonCollector(ctx), engine, client)
        state.commit()  # advance the telemetry cursor only after a clean cycle
        if detections:
            log.info("shipped %d behavioural detection(s)", len(detections))
    except CollectorError as exc:
        log.warning("telemetry skipped this cycle: %s", exc)


def cmd_run(args: argparse.Namespace, registry: CheckRegistry) -> int:
    from .transport import AuthError, ServerClient

    config = AgentConfig.load()
    if not config.server_url:
        print("Not enrolled. Run: sentinel-agent enroll --server http://127.0.0.1:8765 --code <code>", file=sys.stderr)
        return 2
    token = load_token(config.server_url)
    if not token:
        print("No device token found. Enroll again.", file=sys.stderr)
        return 2
    demo_elevated: tuple[HostInfo, ContextFactory] | None = None
    if args.fixtures:
        fixture, host = _load_fixture(args.fixtures)
        factory = fixture_context_factory(fixture, host, config)
        # Demo only: answer elevated jobs from the same fixture so admin-only views can be shown.
        # Nothing on this machine is read, and every result is tagged as fixture data.
        demo_host = host.model_copy(update={"is_elevated": True})
        demo_elevated = (demo_host, fixture_context_factory(fixture, demo_host, config))
        log.warning("DEMO MODE: results come from fixture %s and are tagged as fixture data", args.fixtures)
    else:
        host = current_host()
        factory = live_context_factory(host, config)
    if args.elevated and not host.is_elevated:
        print("--elevated needs an administrator shell. Use scripts/elevated-scan.ps1.", file=sys.stderr)
        return 2
    if args.elevated and not is_loopback_url(config.server_url):
        # The server URL comes from a file the standard user can edit; admin-only data stays on this machine.
        print("Elevated scans only report to a Sentinel server on this computer (127.0.0.1).", file=sys.stderr)
        return 2
    client = ServerClient(config.server_url, token)
    try:
        client.hello(host, registry.descriptors())
    except AuthError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    try:
        import psutil

        psutil.cpu_percent(interval=None)  # prime the counter
    except Exception:  # noqa: S110
        pass
    log.info("agent %s polling %s (%s)", __version__, config.server_url, "elevated" if host.is_elevated else "standard")
    telemetry_on = (args.telemetry or config.telemetry_enabled) and not args.fixtures and not args.elevated
    engine = None
    if telemetry_on:
        from sentinel_detect import Engine

        engine = Engine()
        log.info("Sentinel X telemetry enabled (reading Sysmon, shipping behavioural detections)")
    last_metrics = 0.0
    last_telemetry = 0.0
    idle_deadline = time.monotonic() + args.idle_exit if args.idle_exit else None
    while True:
        try:
            metrics_due = time.monotonic() - last_metrics >= config.metrics_interval_seconds
            if not args.fixtures and not args.elevated and metrics_due:
                last_metrics = time.monotonic()
                client.send_metrics(_metrics())
            if engine is not None and time.monotonic() - last_telemetry >= max(config.poll_interval_seconds, 15.0):
                last_telemetry = time.monotonic()
                _telemetry_step(client, engine, host, config)
            job = client.next_job(elevated=args.elevated)
            job_host, job_factory = host, factory
            if job is None and demo_elevated is not None and not args.elevated:
                job = client.next_job(elevated=True)
                if job is not None:
                    job_host, job_factory = demo_elevated
            if job is not None:
                if args.fixtures:
                    job = job.model_copy(update={"data_mode": DataMode.FIXTURE})
                _run_job(client, registry, job_host, job_factory, job)
                if args.once:
                    return 0
                if idle_deadline:
                    idle_deadline = time.monotonic() + args.idle_exit
            elif idle_deadline and time.monotonic() > idle_deadline:
                return 0
        except AuthError as exc:
            log.error("%s", exc)
            return 2
        except Exception as exc:
            log.warning("poll failed: %s", exc)
        time.sleep(config.poll_interval_seconds)


def _run_job(client: Any, registry: CheckRegistry, host: HostInfo, factory: ContextFactory, job: AgentJob) -> None:
    log.info("running scan %s (%s)", job.scan_id, job.scan_type.value)
    sink = client.scan_sink(job.scan_id)
    # Log cursors are saved only once the server has accepted the result that carried those events.
    on_sent = factory.commit_sent if isinstance(factory, LiveContextFactory) else None
    try:
        status = ScanRunner(registry, host, factory, sink, on_sent=on_sent).run(job)
        client.complete(job.scan_id, status)
    except Exception as exc:
        log.exception("scan %s failed", job.scan_id)
        try:
            client.complete(job.scan_id, ScanStatus.FAILED, error=f"{type(exc).__name__}: {exc}"[:500])
        except Exception:  # noqa: S110
            pass


def cmd_telemetry(args: argparse.Namespace, registry: CheckRegistry) -> int:
    """Run Sentinel X behavioural detection over Sysmon telemetry (live, or a saved export)."""
    from sentinel_detect import Engine
    from sentinel_detect.replay import _format

    from .telemetry.collector import CollectorError, ExportCollector, SysmonCollector

    try:
        if args.export:
            events = ExportCollector(args.export).collect()
            source = f"export {args.export}"
        else:
            config = AgentConfig.load()
            host = current_host()
            runner = SafeCommandRunner(SysmonCollector.commands, cancelled=lambda: False)
            state = StagedState(FileState())
            ctx = LiveContext(host, runner, state, config.as_mapping(), lambda: False, None, None)
            events = SysmonCollector(ctx).collect()
            state.commit()  # advance the cursor only after a clean read
            source = f"live Sysmon log on {host.hostname}"
    except CollectorError as exc:
        print(f"Telemetry unavailable: {exc}", file=sys.stderr)
        return 2

    detections = Engine().feed_stream(events)
    if args.json:
        print(json.dumps({"source": source, "events": len(events),
                          "detections": [d.model_dump(mode="json") for d in detections]}, indent=2, default=str))
        return 0
    print(f"Read {len(events)} telemetry events from {source}; {len(detections)} detection(s).")
    for d in detections:
        print()
        print(_format(d))
        print("-" * 78)
    return 0


def cmd_status(args: argparse.Namespace, registry: CheckRegistry) -> int:
    config = AgentConfig.load()
    host = current_host()
    print(f"Agent {__version__}, home {agent_home()}")
    print(f"Host {host.hostname}: {host.os_name} {host.os_version} {host.edition or ''} "
          f"({'elevated' if host.is_elevated else 'standard user'})")
    print(f"Server: {config.server_url or 'not enrolled'}; device id {config.device_id}")
    print(f"Registered checks: {len(registry)}")
    print(f"Malware scan folders: {config.malware_scan_paths or 'none configured'}")
    print(f"Project folders: {config.project_paths or 'none configured'}")
    return 0


def cmd_config(args: argparse.Namespace, registry: CheckRegistry) -> int:
    config = AgentConfig.load()
    changed = False
    for attr, values in (("malware_scan_paths", args.add_malware_path), ("project_paths", args.add_project_path)):
        for value in values or []:
            p = str(Path(value).resolve())
            if not Path(p).is_dir():
                print(f"{p} is not a folder", file=sys.stderr)
                return 2
            lst = getattr(config, attr)
            if p not in lst:
                lst.append(p)
                changed = True
    if changed:
        config.save()
    print(json.dumps(config.as_mapping(), indent=2))
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="sentinel-agent", description="Sentinel read-only security agent")
    p.add_argument("-v", "--verbose", action="store_true")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("checks", help="list registered checks")
    s = sub.add_parser("scan", help="run a scan locally without a server")
    s.add_argument("--local", action="store_true", help="accepted for clarity; scan always runs locally")
    s.add_argument("--type", default="full", choices=[t.value for t in ScanType if t is not ScanType.CUSTOM])
    s.add_argument("--checks", help="comma-separated check ids")
    s.add_argument("--params", help="JSON object of per-check parameters")
    s.add_argument("--json", action="store_true")
    s.add_argument("--record", metavar="DIR", help="save raw command output as a fixture file")
    s.add_argument("--fixtures", metavar="FILE", help="run against a fixture file instead of this machine")
    e = sub.add_parser("enroll", help="enroll this machine with a Sentinel server")
    e.add_argument("--server", required=True)
    e.add_argument("--code", required=True)
    e.add_argument("--fixtures", metavar="FILE", help="DEMO MODE: enroll as the machine described in a fixture file")
    r = sub.add_parser("run", help="poll the server for scan jobs")
    r.add_argument("--once", action="store_true")
    r.add_argument("--telemetry", action="store_true",
                   help="read Sysmon telemetry each cycle and ship behavioural detections (Sentinel X)")
    r.add_argument("--elevated", action="store_true", help="only take elevated scans (admin shell)")
    r.add_argument("--fixtures", metavar="FILE", help="DEMO MODE: answer jobs from a fixture file")
    r.add_argument("--idle-exit", type=float, default=0, help="exit after this many idle seconds")
    t = sub.add_parser("telemetry", help="run Sentinel X behavioural detection over Sysmon telemetry")
    t.add_argument("--export", metavar="FILE", help="analyze a saved Sysmon log export (XML) instead of the live log")
    t.add_argument("--json", action="store_true")
    sub.add_parser("status", help="show agent configuration")
    c = sub.add_parser("config", help="show or change agent configuration")
    c.add_argument("--add-malware-path", action="append")
    c.add_argument("--add-project-path", action="append")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    _setup_logging(args.verbose)
    registry = default_registry()
    handlers = {
        "checks": cmd_checks, "scan": cmd_scan, "enroll": cmd_enroll, "run": cmd_run,
        "telemetry": cmd_telemetry, "status": cmd_status, "config": cmd_config,
    }
    return handlers[args.cmd](args, registry)


__all__ = ["CheckStatus", "main"]
