"""End to end: the real agent runner reports through the API; findings dedupe, resolve and reopen."""

from sentinel_agent.checks.common.resources import ResourceDiagnostics
from sentinel_agent.checks.windows.firewall import FIREWALL_PROFILES, FirewallProfiles
from sentinel_agent.checks.windows.uac import UacConfiguration
from sentinel_agent.testing import ps_json
from sentinel_core.models import DataMode

CHECKS = [FirewallProfiles, UacConfiguration, ResourceDiagnostics]


def firewall(public_enabled: bool) -> dict:
    return {
        "commands": {FIREWALL_PROFILES.name: ps_json([
            {"Name": "Domain", "Enabled": "True", "DefaultInboundAction": "NotConfigured"},
            {"Name": "Private", "Enabled": "True", "DefaultInboundAction": "NotConfigured"},
            {"Name": "Public", "Enabled": "True" if public_enabled else "False", "DefaultInboundAction": "Block"},
        ])},
        "registry": {},  # UAC reads nothing -> skipped, which must not resolve anything
        "system": {"cpu_percent": 5, "memory": {"total": 1, "available": 1, "percent": 40},
                   "disks": [], "boot_time": 0},
    }


def _open_firewall_findings(browser, device_id):
    items = browser.get("/api/findings", params={"device_id": device_id, "status": "all"}).json()["items"]
    return [f for f in items if f["rule_id"] == "win.firewall.profile_disabled"]


def test_finding_created_resolved_and_reopened(make_agent, browser):
    agent = make_agent(CHECKS)
    scan1 = agent.scan(firewall(public_enabled=False))
    assert scan1["status"] == "completed"
    runs = {r["check_id"]: r for r in scan1["check_runs"]}
    assert runs["win.firewall.profiles"]["status"] == "failed"
    assert runs["win.uac"]["status"] == "skipped"
    [f] = _open_firewall_findings(browser, agent.device_id)
    assert f["status"] == "new" and f["severity"] == "high"

    # same problem again: same finding, not a duplicate
    agent.scan(firewall(public_enabled=False))
    assert len(_open_firewall_findings(browser, agent.device_id)) == 1

    # a user cannot simply mark it resolved
    r = browser.patch(f"/api/findings/{f['id']}", json={"status": "resolved"})
    assert r.status_code == 409

    # fixed on the machine: a passing re-run resolves it, with verification recorded
    agent.scan(firewall(public_enabled=True))
    [f] = _open_firewall_findings(browser, agent.device_id)
    assert f["status"] == "resolved" and f["verified_resolved_at"]

    # and it comes back as reopened if the problem returns
    agent.scan(firewall(public_enabled=False))
    [f] = _open_firewall_findings(browser, agent.device_id)
    assert f["status"] == "reopened" and f["reopened_count"] == 1

    detail = browser.get(f"/api/findings/{f['id']}").json()
    assert {e["to_status"] for e in detail["events"]} >= {"new", "resolved", "reopened"}
    assert detail["observations"][0]["evidence"][0]["source"] == "Get-NetFirewallProfile"


def test_a_failed_check_never_resolves_a_finding(make_agent, browser):
    agent = make_agent(CHECKS)
    agent.scan(firewall(public_enabled=False))
    broken = firewall(public_enabled=True)
    broken["commands"][FIREWALL_PROFILES.name] = {"error": "failed", "message": "Get-NetFirewallProfile failed"}
    scan = agent.scan(broken)
    assert scan["status"] == "partial"
    [f] = _open_firewall_findings(browser, agent.device_id)
    assert f["status"] == "new"


def test_score_coverage_and_incomplete_marking(make_agent, browser):
    agent = make_agent(CHECKS)
    agent.scan(firewall(public_enabled=False))
    overview = browser.get("/api/dashboard/overview").json()
    # 2 of 3 applicable checks completed (UAC skipped): 67% coverage < 75% -> Incomplete, no number
    assert overview["checks_applicable"] == 3 and overview["checks_completed"] == 2
    assert overview["incomplete"] is True and overview["score"] is None
    assert overview["raw_score"] == 100 - 8
    assert overview["threat_level"] == "high"


def test_scan_diff_and_export(make_agent, browser):
    agent = make_agent(CHECKS)
    s1 = agent.scan(firewall(public_enabled=False))
    s2 = agent.scan(firewall(public_enabled=True))
    diff = browser.get(f"/api/scans/{s2['id']}/diff", params={"against": s1["id"]}).json()
    assert [f["rule_id"] for f in diff["resolved"]] == ["win.firewall.profile_disabled"]
    assert diff["new"] == []
    export = browser.get(f"/api/scans/{s1['id']}/export").json()
    assert export["data_mode"] == "live"
    assert any(r["check_id"] == "win.firewall.profiles" and r["evidence"] for r in export["check_runs"])


def test_verify_queues_a_rerun_of_only_that_check(make_agent, browser):
    agent = make_agent(CHECKS)
    agent.scan(firewall(public_enabled=False))
    [f] = _open_firewall_findings(browser, agent.device_id)
    scan = browser.post(f"/api/findings/{f['id']}/verify").json()
    assert scan["scan_type"] == "custom" and scan["check_ids"] == ["win.firewall.profiles"]


def test_cancel_running_scan(make_agent, browser):
    agent = make_agent(CHECKS)
    r = browser.post("/api/scans", json={"device_id": agent.device_id, "scan_type": "posture"})
    scan_id = r.json()["id"]
    assert browser.post(f"/api/scans/{scan_id}/cancel").json()["status"] == "cancelled"
    assert agent.client.next_job() is None


def test_fixture_data_is_refused_in_production(make_agent, browser, production):
    agent = make_agent(CHECKS)
    browser.post("/api/scans", json={"device_id": agent.device_id, "scan_type": "posture"})
    import httpx
    import pytest

    with pytest.raises(httpx.HTTPStatusError):
        agent.run_next(firewall(public_enabled=False), data_mode=DataMode.FIXTURE)
    scans = browser.get("/api/scans").json()["items"]
    assert scans[0]["status"] == "failed" and "Fixture" in scans[0]["error"]


def test_elevated_scans_wait_for_an_elevated_agent(make_agent, browser):
    agent = make_agent(CHECKS)
    browser.post("/api/scans", json={"device_id": agent.device_id, "scan_type": "posture", "elevated": True})
    assert agent.client.next_job(elevated=False) is None
    assert agent.client.next_job(elevated=True) is not None
