"""Every check runs cleanly over the hand-written demo fixtures (not recordings of real machines)."""

import json
from pathlib import Path

import pytest
from sentinel_agent.config import MemoryState
from sentinel_agent.registry import default_registry
from sentinel_agent.runner import CollectingSink, ScanRunner
from sentinel_agent.testing import FixtureContext
from sentinel_core.models import AgentJob, CheckStatus, DataMode, HostInfo, ScanType

FIXTURES = Path(__file__).parent / "fixtures"
FILES = ("windows-home-demo.json", "linux-pi-demo.json")


def _scan(name: str, scan_type: ScanType, elevated: bool) -> CollectingSink:
    data = json.loads((FIXTURES / name).read_text(encoding="utf-8"))
    host = HostInfo(**{**data["host"], "is_elevated": elevated})
    state = MemoryState()

    def factory(check, params, cancelled):
        return FixtureContext(host, data, params=params, state=state, cancelled=cancelled)

    sink = CollectingSink()
    ScanRunner(default_registry(), host, factory, sink, poll_interval=0.01, heartbeat_interval=3600).run(
        AgentJob(scan_id=1, scan_type=scan_type, data_mode=DataMode.FIXTURE))
    return sink


@pytest.mark.parametrize("name", FILES)
def test_fixture_is_labelled_as_hand_written(name):
    data = json.loads((FIXTURES / name).read_text(encoding="utf-8"))
    assert next(iter(data)) == "_fixture"
    assert data["_fixture"].startswith("Hand-written demo data shaped like ")
    assert data["_fixture"].endswith("Not a recording of a real machine.")


@pytest.mark.parametrize("elevated", [False, True])
@pytest.mark.parametrize("scan_type", [ScanType.FULL, ScanType.POSTURE, ScanType.INVENTORY, ScanType.LOGS])
@pytest.mark.parametrize("name", FILES)
def test_no_check_errors_over_demo_fixture(name, scan_type, elevated):
    sink = _scan(name, scan_type, elevated)
    errors = {r.check_id: r.error_message for r in sink.results if r.status in (CheckStatus.ERROR, CheckStatus.TIMEOUT)}
    assert errors == {}
    assert sink.results, "the scan ran no checks"


def _by_id(sink):
    return {r.check_id: r for r in sink.results}


def test_windows_demo_tells_the_intended_story():
    res = _by_id(_scan("windows-home-demo.json", ScanType.FULL, elevated=True))
    software = {(s.name, s.version) for s in res["win.software.inventory"].output.software}
    assert ("Git", "2.43.0") in software and ("7-Zip 19.00 (x64)", "19.00") in software
    assert 20 <= len(software) <= 30
    assert res["win.os.inventory"].output.software[0].version == "10.0.26300.7171"
    startup = res["win.startup"].output.findings
    assert any("AppData\\Local\\Temp" in f.title for f in startup)
    assert [f.title for f in res["win.defender.status"].output.findings] == ["Virus definitions are 4 days old"]
    actions = [e.action for e in res["win.logs.security"].output.events]
    assert actions.count("logon_failed") >= 5 and "logon_success" in actions
    assert res["win.bitlocker"].status is CheckStatus.PASSED  # manage-bde fallback: Device encryption on
    assert res["win.accounts"].output.evidence[0].content["enabled_local_administrators"] == ["Ryan"]
    assert any(f.rule_id == "win.os.updates.insider_build" for f in res["win.os.updates"].output.findings)


def test_linux_demo_tells_the_intended_story():
    res = _by_id(_scan("linux-pi-demo.json", ScanType.FULL, elevated=True))
    assert {f.rule_id for f in res["linux.updates"].output.findings} == {"linux.updates.security_pending",
                                                                        "linux.updates.restart_required"}
    assert [f.rule_id for f in res["linux.ssh_config"].output.findings] == ["linux.ssh_config.password_auth"]
    pkgs = res["linux.packages"].output.software
    assert 35 <= len(pkgs) <= 45 and {p.ecosystem for p in pkgs} == {"Debian:12"}
    events = res["linux.logs.auth"].output.events
    burst = [e for e in events if e.action == "ssh_failed" and e.source_ip == "203.0.113.77"]
    assert len(burst) >= 10  # enough for the server's brute-force rule
    assert any(e.action == "ssh_success" for e in events)
    assert res["linux.firewall"].output.findings[0].rule_id == "linux.firewall.inactive"
