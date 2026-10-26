"""Command-line entry point: ``sentinel-agent``."""

from __future__ import annotations

import argparse
import json
import logging
import logging.handlers
import sys
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from pydantic import BaseModel
from sentinel_core.checks import Check, CheckContext
from sentinel_core.models import (
    AgentJob,
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


ContextFactory = Callable[[Check, BaseModel | None, Callable[[], bool]], CheckContext]


def live_context_factory(host: HostInfo, config: AgentConfig, recorder: Recorder | None = None) -> ContextFactory:
    state = FileState()

    def factory(check: Check, params: BaseModel | None, cancelled: Callable[[], bool]) -> CheckContext:
        # Each check gets a runner that only knows its own declared commands.
        runner = SafeCommandRunner(type(check).commands, cancelled=cancelled,
                                   recorder=recorder.command if recorder else None)
        return LiveContext(host, runner, state, config.as_mapping(), cancelled, params, recorder)

    return factory


def fixture_context_factory(fixture: dict[str, Any], host: HostInfo, config: AgentConfig) -> ContextFactory:
    state = MemoryState()

    def factory(check: Check, params: BaseModel | None, cancelled: Callable[[], bool]) -> CheckContext:
        return FixtureContext(host, fixture, params=params, config=config.as_mapping(), state=state,
                              cancelled=cancelled)

    return factory


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
    host = current_host()
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
    if args.fixtures:
        fixture, host = _load_fixture(args.fixtures)
        factory = fixture_context_factory(fixture, host, config)
        log.warning("DEMO MODE: results come from fixture %s and are tagged as fixture data", args.fixtures)
    else:
        host = current_host()
        factory = live_context_factory(host, config)
    if args.elevated and not host.is_elevated:
        print("--elevated needs an administrator shell. Use scripts/elevated-scan.ps1.", file=sys.stderr)
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
    last_metrics = 0.0
    idle_deadline = time.monotonic() + args.idle_exit if args.idle_exit else None
    while True:
        try:
            if not args.fixtures and not args.elevated and time.monotonic() - last_metrics >= config.metrics_interval_seconds:
                last_metrics = time.monotonic()
                client.send_metrics(_metrics())
            job = client.next_job(elevated=args.elevated)
            if job is not None:
                if args.fixtures:
                    job = job.model_copy(update={"data_mode": DataMode.FIXTURE})
                _run_job(client, registry, host, factory, job)
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
    try:
        status = ScanRunner(registry, host, factory, sink).run(job)
        client.complete(job.scan_id, status)
    except Exception as exc:
        log.exception("scan %s failed", job.scan_id)
        try:
            client.complete(job.scan_id, ScanStatus.FAILED, error=f"{type(exc).__name__}: {exc}"[:500])
        except Exception:  # noqa: S110
            pass


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
    r = sub.add_parser("run", help="poll the server for scan jobs")
    r.add_argument("--once", action="store_true")
    r.add_argument("--elevated", action="store_true", help="only take elevated scans (admin shell)")
    r.add_argument("--fixtures", metavar="FILE", help="DEMO MODE: answer jobs from a fixture file")
    r.add_argument("--idle-exit", type=float, default=0, help="exit after this many idle seconds")
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
        "status": cmd_status, "config": cmd_config,
    }
    return handlers[args.cmd](args, registry)


__all__ = ["CheckStatus", "main"]
