import time

import pytest
from sentinel_agent import safe_commands
from sentinel_agent.checks._util import finding
from sentinel_agent.registry import CheckRegistry
from sentinel_agent.runner import ELEVATION_REASON, CollectingSink, ScanRunner, build_plan
from sentinel_agent.safe_commands import CommandRefused, CommandTimedOut, SafeCommandRunner
from sentinel_agent.testing import FixtureContext, linux_host, windows_host
from sentinel_core.checks import Check, SkipCheck
from sentinel_core.commands import CommandSpec, ParamKind
from sentinel_core.models import (
    AgentJob,
    CheckOutput,
    CheckStatus,
    PlanStatus,
    Platform,
    ScanStatus,
    ScanType,
    Severity,
)


class Passing(Check):
    id = "test.passing"
    version = "1"
    title = "passes"
    category = "configuration"
    platforms = frozenset({Platform.LINUX, Platform.WINDOWS})
    data_collected = "nothing"

    def run(self, ctx):
        return CheckOutput(evidence=[ctx.evidence("metric", "test", {"ok": True})])


class Failing(Passing):
    id = "test.failing"

    def run(self, ctx):
        return CheckOutput(evidence=[ctx.evidence("metric", "test", {})],
                           findings=[finding("test.bad", "x", "Bad", Severity.HIGH, "impact", "fix")])


class Crashing(Passing):
    id = "test.crashing"

    def run(self, ctx):
        raise RuntimeError("boom")


class Slow(Passing):
    id = "test.slow"
    timeout_seconds = 0.3

    def run(self, ctx):
        time.sleep(1.2)
        return CheckOutput()


class Skipping(Passing):
    id = "test.skipping"

    def run(self, ctx):
        raise SkipCheck("tool not installed")


class AdminOnly(Passing):
    id = "test.admin_only"
    requires_elevation = True


class WindowsOnly(Passing):
    id = "test.windows_only"
    platforms = frozenset({Platform.WINDOWS})


def _runner(checks, host=None, sink=None, **kw):
    host = host or linux_host()
    registry = CheckRegistry(checks)

    def factory(check, params, cancelled):
        return FixtureContext(host, {}, params=params, cancelled=cancelled)

    return ScanRunner(registry, host, factory, sink or CollectingSink(), poll_interval=0.02, **kw)


def test_plan_marks_platform_elevation_and_profiles():
    registry = CheckRegistry([Passing, AdminOnly, WindowsOnly])
    planned, runnable = build_plan(registry, AgentJob(scan_id=1, scan_type=ScanType.POSTURE), linux_host())
    by_id = {p.check_id: p for p in planned}
    assert by_id["test.passing"].status is PlanStatus.PLANNED
    assert by_id["test.admin_only"].status is PlanStatus.SKIPPED
    assert by_id["test.admin_only"].reason == ELEVATION_REASON
    assert by_id["test.windows_only"].status is PlanStatus.NOT_APPLICABLE
    assert [type(r.check).id for r in runnable] == ["test.passing"]


def test_one_crashing_check_does_not_stop_the_others():
    sink = CollectingSink()
    status = _runner([Passing, Crashing, Failing, Skipping], sink=sink).run(
        AgentJob(scan_id=1, scan_type=ScanType.POSTURE))
    by_id = {r.check_id: r for r in sink.results}
    assert by_id["test.passing"].status is CheckStatus.PASSED
    assert by_id["test.failing"].status is CheckStatus.FAILED
    assert by_id["test.crashing"].status is CheckStatus.ERROR
    assert "boom" in by_id["test.crashing"].error_message
    assert by_id["test.skipping"].status is CheckStatus.SKIPPED
    assert by_id["test.skipping"].skip_reason == "tool not installed"
    assert status is ScanStatus.PARTIAL


def test_timeout_is_recorded_and_scan_is_partial():
    sink = CollectingSink()
    status = _runner([Slow, Passing], sink=sink).run(AgentJob(scan_id=1, scan_type=ScanType.POSTURE))
    by_id = {r.check_id: r for r in sink.results}
    assert by_id["test.slow"].status is CheckStatus.TIMEOUT
    assert by_id["test.passing"].status is CheckStatus.PASSED
    assert status is ScanStatus.PARTIAL


def test_cancel_records_unstarted_checks_as_cancelled():
    slow_checks = []
    for i in range(4):
        slow_checks.append(type(f"Slow{i}", (Slow,), {"id": f"test.slow{i}", "timeout_seconds": 5}))
    sink = CollectingSink(cancel_after_heartbeats=1)
    status = _runner(slow_checks, sink=sink, max_workers=1, heartbeat_interval=0.05).run(
        AgentJob(scan_id=1, scan_type=ScanType.POSTURE))
    assert status is ScanStatus.CANCELLED
    assert sum(1 for r in sink.results if r.status is CheckStatus.CANCELLED) >= 3


def test_explicit_check_ids_ignore_unknown_ids():
    sink = CollectingSink()
    _runner([Passing, Failing], sink=sink).run(
        AgentJob(scan_id=1, scan_type=ScanType.CUSTOM, check_ids=["test.failing", "evil.unknown"]))
    assert [r.check_id for r in sink.results] == ["test.failing"]


def test_windows_check_skipped_on_linux_plan():
    sink = CollectingSink()
    _runner([WindowsOnly], host=windows_host(), sink=sink).run(AgentJob(scan_id=1, scan_type=ScanType.POSTURE))
    assert sink.results[0].status is CheckStatus.PASSED


# --------------------------------------------------------------------------- safe command runner

SLEEP = CommandSpec("t.sleep", "sleep", ("{seconds}",), params={"seconds": ParamKind.INT}, timeout=0.5)
ECHO = CommandSpec("t.echo", "echo", ("hello",))


@pytest.fixture
def fake_resolve(monkeypatch):
    monkeypatch.setattr(safe_commands, "resolve", lambda name: {"sleep": "/bin/sleep", "echo": "/bin/echo"}[name])


def test_unregistered_command_is_refused(fake_resolve):
    runner = SafeCommandRunner([ECHO])
    with pytest.raises(CommandRefused):
        runner.run(SLEEP, seconds=1)
    impostor = CommandSpec("t.echo", "echo", ("goodbye",))
    with pytest.raises(CommandRefused):
        runner.run(impostor)


def test_registered_command_runs_without_shell(fake_resolve):
    assert SafeCommandRunner([ECHO]).run(ECHO).stdout.strip() == "hello"


def test_command_timeout_kills_process(fake_resolve):
    start = time.monotonic()
    with pytest.raises(CommandTimedOut):
        SafeCommandRunner([SLEEP]).run(SLEEP, seconds=5)
    assert time.monotonic() - start < 3
