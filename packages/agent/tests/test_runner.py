import json
import time

import httpx
import pytest
from sentinel_agent import cli, safe_commands
from sentinel_agent.checks._util import finding
from sentinel_agent.config import AgentConfig, FileState, MemoryState, StagedState
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


# --------------------------------------------------------------------------- staged state: cursors saved only after upload

CURSOR_KEY = "cursor:test"


class CursorCheck(Passing):
    """Advances a cursor the way the log checks do: read it, collect, save the new position."""

    id = "test.cursor"

    def run(self, ctx):
        ctx.state.set(CURSOR_KEY, str(int(ctx.state.get(CURSOR_KEY) or "0") + 10))
        return CheckOutput(evidence=[ctx.evidence("metric", "test", {"cursor_seen": ctx.state.get(CURSOR_KEY)})])


class CursorThenSkip(Passing):
    id = "test.cursor_then_skip"

    def run(self, ctx):
        ctx.state.set(CURSOR_KEY, "999")
        raise SkipCheck("could not finish")


class _UploadSink(CollectingSink):
    def __init__(self, fail=False):
        super().__init__()
        self.fail = fail

    def send_result(self, result):
        if self.fail:
            raise httpx.ConnectError("server unreachable")
        super().send_result(result)


class _Client:
    def __init__(self, sink):
        self.sink = sink
        self.completed = []

    def scan_sink(self, scan_id):
        return self.sink

    def complete(self, scan_id, status, error=None):
        self.completed.append((status, error))


def _server_job(check, sink, state_value=None):
    if state_value is not None:
        FileState().set(CURSOR_KEY, state_value)
    host = linux_host()
    factory = cli.live_context_factory(host, AgentConfig())
    client = _Client(sink)
    cli._run_job(client, CheckRegistry([check]), host, factory, AgentJob(scan_id=7, scan_type=ScanType.POSTURE))
    return client, factory


def test_staged_state_reads_through_and_commits_on_demand():
    base = MemoryState({"a": "1"})
    staged = StagedState(base)
    staged.set("a", "2")
    staged.set("b", "3")
    assert (staged.get("a"), staged.get("b"), staged.get("c", "d")) == ("2", "3", "d")
    assert (base.get("a"), base.get("b")) == ("1", None) and staged.pending == {"a": "2", "b": "3"}
    staged.commit()
    assert (base.get("a"), base.get("b")) == ("2", "3") and staged.pending == {}
    staged.set("a", "4")
    staged.discard()
    assert staged.get("a") == "2"


def test_upload_success_advances_cursor():
    sink = _UploadSink()
    client, factory = _server_job(CursorCheck, sink, state_value="5")
    assert [r.status for r in sink.results] == [CheckStatus.PASSED]
    assert FileState().get(CURSOR_KEY) == "15"  # re-read from disk
    assert client.completed == [(ScanStatus.COMPLETED, None)] and factory.staged == {}


def test_upload_failure_does_not_advance_cursor():
    client, _ = _server_job(CursorCheck, _UploadSink(fail=True), state_value="5")
    assert client.completed[0][0] is ScanStatus.FAILED
    assert FileState().get(CURSOR_KEY) == "5"  # the next run reads the same events again


def test_skipped_check_does_not_commit_its_state():
    sink = _UploadSink()
    _server_job(CursorThenSkip, sink, state_value="5")
    assert [r.status for r in sink.results] == [CheckStatus.SKIPPED]
    assert FileState().get(CURSOR_KEY) == "5"


def test_local_scan_never_advances_cursor(monkeypatch, capsys):
    FileState().set(CURSOR_KEY, "5")
    monkeypatch.setattr(cli, "current_host", linux_host)
    args = cli.build_parser().parse_args(["scan", "--checks", CursorCheck.id, "--json"])
    assert cli.cmd_scan(args, CheckRegistry([CursorCheck])) == 0
    result = json.loads(capsys.readouterr().out)["results"][0]
    assert result["status"] == "passed"
    assert result["output"]["evidence"][0]["content"] == {"cursor_seen": "15"}  # it read from the saved cursor
    assert FileState().get(CURSOR_KEY) == "5"  # but did not consume the events


def test_on_sent_runs_only_after_a_successful_send():
    calls = []

    class Sink(CollectingSink):
        def send_result(self, result):
            calls.append(("send", result.check_id))
            super().send_result(result)

    _runner([Passing], sink=Sink(), on_sent=lambda r: calls.append(("sent", r.check_id))).run(
        AgentJob(scan_id=1, scan_type=ScanType.POSTURE))
    assert calls == [("send", "test.passing"), ("sent", "test.passing")]

    seen = []
    with pytest.raises(httpx.ConnectError):
        _runner([Passing], sink=_UploadSink(fail=True), on_sent=seen.append).run(
            AgentJob(scan_id=1, scan_type=ScanType.POSTURE))
    assert seen == []


def test_duplicate_check_ids_run_once():
    planned, runnable = build_plan(CheckRegistry([Passing]), AgentJob(
        scan_id=1, scan_type=ScanType.CUSTOM, check_ids=["test.passing", "test.passing"]), linux_host())
    assert len(planned) == 1 and len(runnable) == 1


def test_child_environment_pins_module_path_and_system_folders(monkeypatch, tmp_path):
    """A user-level PSModulePath or SystemRoot must never reach PowerShell (planted modules run as admin)."""
    from pathlib import Path

    from sentinel_agent import executables

    monkeypatch.setattr(safe_commands.sys, "platform", "win32")
    monkeypatch.setattr(executables, "windows_directory", lambda: Path("C:/Windows"))
    monkeypatch.setattr(executables, "known_folder", lambda fid: Path("C:/Program Files"))
    for k, v in {"PSModulePath": str(tmp_path / "evil-modules"), "SYSTEMROOT": str(tmp_path / "evilroot"),
                 "PATH": str(tmp_path / "evilbin"), "PYTHONPATH": str(tmp_path), "TEMP": "C:/Temp"}.items():
        monkeypatch.setenv(k, v)
    env = safe_commands._minimal_env()
    assert str(tmp_path) not in " ".join(env.values())
    assert env["PSMODULEPATH"].split(";") == [str(Path("C:/Windows/System32/WindowsPowerShell/v1.0/Modules")),
                                              str(Path("C:/Program Files/WindowsPowerShell/Modules"))]
    assert env["SYSTEMROOT"] == str(Path("C:/Windows")) and "PYTHONPATH" not in env and env["TEMP"] == "C:/Temp"
    assert env["PATH"].split(";")[0] == str(Path("C:/Windows/System32"))


def test_elevated_agent_refuses_a_remote_server(monkeypatch, capsys):
    from sentinel_agent import cli
    from sentinel_agent.config import AgentConfig

    AgentConfig(server_url="https://collector.example.com", device_id=1).save()
    monkeypatch.setattr(cli, "load_token", lambda url: "token")
    monkeypatch.setattr(cli, "current_host", lambda: windows_host(is_elevated=True))
    assert cli.main(["run", "--elevated", "--once"]) == 2
    assert "only report to a Sentinel server on this computer" in capsys.readouterr().err
    assert cli.is_loopback_url("http://127.0.0.1:8765") and not cli.is_loopback_url("https://127.0.0.1.example.com")
