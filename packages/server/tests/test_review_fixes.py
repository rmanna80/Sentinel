"""Regression tests for issues found in the independent security review."""

from __future__ import annotations

import threading
from datetime import timedelta

import httpx
import pytest
from sentinel_core.checks import Check
from sentinel_core.models import CheckOutput, LogEvent, Platform, ScanCompletion, ScanStatus, Severity
from sentinel_server import audit
from sentinel_server.db import session_scope
from sentinel_server.models import LogEventRecord, OutboundRequest, Scan, now
from sentinel_server.services.ingest import expire_stale_scans

from .conftest import Browser


class Network(Check):
    id = "net.nmap_discovery"
    version = "1"
    title = "nmap"
    category = "network"
    platforms = frozenset({Platform.WINDOWS, Platform.LINUX})
    profiles = frozenset({"network"})
    data_collected = "test"

    def run(self, ctx):  # pragma: no cover - never reached in these tests
        return CheckOutput()


class Posture(Check):
    id = "test.posture"
    version = "1"
    title = "posture"
    category = "configuration"
    platforms = frozenset({Platform.WINDOWS, Platform.LINUX})
    data_collected = "test"

    def run(self, ctx):
        return CheckOutput(evidence=[ctx.evidence("metric", "test", {})])


# --------------------------------------------------------------------------- #3 scope bypass


def test_custom_scan_cannot_reach_network_checks(make_agent, browser: Browser):
    agent = make_agent([Network, Posture])
    r = browser.post("/api/scans", json={"device_id": agent.device_id, "scan_type": "custom",
                                         "check_ids": ["net.nmap_discovery"]})
    assert r.status_code == 422 and "Network security page" in r.json()["detail"]
    r = browser.post("/api/scans", json={
        "device_id": agent.device_id, "scan_type": "custom", "check_ids": ["test.posture"],
        "params": {"net.nmap_discovery": {"targets": ["8.8.8.0/24"]}}})
    assert r.status_code == 422 and "no parameters" in r.json()["detail"]
    for cid in ("net.http_headers", "net.tls_certificate", "malware.clamav"):
        r = browser.post("/api/scans", json={"device_id": agent.device_id, "scan_type": "custom", "check_ids": [cid]})
        assert r.status_code == 422, cid
    assert agent.client.next_job() is None


# --------------------------------------------------------------------------- #5 wedged scans and big uploads


def test_agent_cannot_complete_a_scan_as_running(make_agent, browser: Browser):
    agent = make_agent([Posture])
    scan_id = browser.post("/api/scans", json={"device_id": agent.device_id, "scan_type": "posture"}).json()["id"]
    job = agent.client.next_job()
    assert job is not None
    for bad in (ScanStatus.RUNNING, ScanStatus.QUEUED):
        r = agent.client._client.post(f"/api/agent/scans/{scan_id}/complete",
                                      json=ScanCompletion(status=bad).model_dump(mode="json"))
        assert r.status_code == 422
    assert browser.get(f"/api/scans/{scan_id}").json()["status"] == "running"


def test_cancel_ends_a_scan_whose_agent_stopped_heartbeating(make_agent, browser: Browser):
    agent = make_agent([Posture])
    scan_id = browser.post("/api/scans", json={"device_id": agent.device_id, "scan_type": "posture"}).json()["id"]
    agent.client.next_job()
    with session_scope() as db:
        scan = db.get(Scan, scan_id)
        scan.lease_expires_at = None
    assert browser.post(f"/api/scans/{scan_id}/cancel").json()["status"] == "cancelled"


def test_running_scan_without_lease_expires_eventually(make_agent, browser: Browser):
    agent = make_agent([Posture])
    scan_id = browser.post("/api/scans", json={"device_id": agent.device_id, "scan_type": "posture"}).json()["id"]
    agent.client.next_job()
    with session_scope() as db:
        scan = db.get(Scan, scan_id)
        scan.lease_expires_at = None
        scan.started_at = now() - timedelta(hours=7)
    with session_scope() as db:
        assert expire_stale_scans(db) == 1
    assert browser.get(f"/api/scans/{scan_id}").json()["status"] == "failed"


def test_oversized_agent_upload_is_refused(make_agent, browser: Browser):
    agent = make_agent([Posture])
    big = b'{"x":"' + b"a" * (33 * 1024 * 1024) + b'"}'
    r = agent.client._client.post("/api/agent/scans/1/results", content=big,
                                  headers={"content-type": "application/json"})
    assert r.status_code == 413
    r = browser.client.post("/api/auth/login", content=b"x" * (3 * 1024 * 1024),
                            headers={"content-type": "application/json"})
    assert r.status_code == 413


def test_too_many_items_and_unplanned_results_are_rejected(make_agent, browser: Browser):
    from sentinel_core.models import CheckRunResult, CheckStatus, Confidence, Finding, FindingKind

    agent = make_agent([Posture])
    scan_id = browser.post("/api/scans", json={"device_id": agent.device_id, "scan_type": "posture"}).json()["id"]
    job = agent.client.next_job()
    assert job is not None
    from sentinel_core.models import PlannedCheck, PlanStatus, ScanPlan

    plan = ScanPlan(host=agent.host, checks=[PlannedCheck(
        check_id="test.posture", check_version="1", title="posture", category="configuration",
        status=PlanStatus.PLANNED, data_collected="test", requires_elevation=False)])
    agent.client.scan_sink(scan_id).send_plan(plan)
    findings = [Finding(rule_id="test.f", subject_key=str(i), title="t", severity=Severity.LOW,
                        confidence=Confidence.HIGH, kind=FindingKind.VERIFIED, impact="i", remediation="r")
                for i in range(2001)]
    flood = CheckRunResult(check_id="test.posture", check_version="1", status=CheckStatus.FAILED, started_at=now(),
                           finished_at=now(), duration_ms=1, ran_elevated=False,
                           output=CheckOutput(findings=findings))
    r = agent.client._client.post(f"/api/agent/scans/{scan_id}/results", json=flood.model_dump(mode="json"))
    assert r.status_code == 409 and "limit is 2000" in r.json()["detail"]
    # a result for a check that was never planned is refused cleanly (409), not a server error
    stray = CheckRunResult(check_id="not.planned", check_version="1", status=CheckStatus.PASSED, started_at=now(),
                           finished_at=now(), duration_ms=1, ran_elevated=False)
    r = agent.client._client.post(f"/api/agent/scans/{scan_id}/results", json=stray.model_dump(mode="json"))
    assert r.status_code == 409 and "not in this scan's plan" in r.json()["detail"]


def test_event_data_is_capped(make_agent):
    class BigEvent(Posture):
        id = "test.big_event"

        def run(self, ctx):
            ev = LogEvent(source="linux:journal", record_id="1", occurred_at=now(), category="authentication",
                          action="ssh_failed", message="x", severity=Severity.LOW, data={"blob": "a" * 200_000})
            return CheckOutput(events=[ev])

    agent = make_agent([BigEvent])
    agent.scan({}, scan_type="posture")
    with session_scope() as db:
        [ev] = db.query(LogEventRecord).all()
        assert ev.data["truncated"] is True and len(ev.data["preview"]) <= 8 * 1024


# --------------------------------------------------------------------------- #6 audit chain under concurrency


def test_concurrent_audit_writes_keep_the_chain_intact(app, browser: Browser):
    barrier = threading.Barrier(8)
    errors: list[str] = []

    def worker(i: int) -> None:
        try:
            with session_scope() as db:
                barrier.wait()
                audit.record(db, f"user:t{i}", "test.concurrent")
        except Exception as exc:  # pragma: no cover - reported below
            errors.append(repr(exc))

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == []
    result = browser.get("/api/audit/verify").json()
    assert result["intact"] is True and result["latest_seq"] == result["entries"]


# --------------------------------------------------------------------------- #9 email obeys the outbound switch


def test_notification_email_obeys_outbound_switch_and_is_logged(browser: Browser, settings, monkeypatch):
    from sentinel_server.phases import notifications

    sent: list[str] = []

    class FakeSMTP:
        def __init__(self, host, port, timeout):
            self.host = host

        def starttls(self, context=None):
            pass

        def login(self, u, p):
            pass

        def send_message(self, msg):
            sent.append(msg["Subject"])

        def quit(self):
            pass

    monkeypatch.setattr(notifications, "smtp_class", FakeSMTP)
    browser.put("/api/settings/notifications", json={"email_enabled": True, "smtp_host": "smtp.example.com",
                                                     "email_to": "ryan@example.com", "smtp_from": "s@example.com"})
    monkeypatch.setattr(settings, "outbound_enabled", False)
    r = browser.post("/api/notifications/test-email").json()
    assert r["sent"] is False and "disabled" in r["detail"].lower() and sent == []
    monkeypatch.setattr(settings, "outbound_enabled", True)
    assert browser.post("/api/notifications/test-email").json()["sent"] is True
    with session_scope() as db:
        [row] = db.query(OutboundRequest).filter(OutboundRequest.integration == "email").all()
        assert row.host == "smtp.example.com" and "r***@example.com" in row.payload_summary
        assert "ryan@" not in row.payload_summary


@pytest.fixture(autouse=True)
def _reset_transport():
    from sentinel_server.integrations import http

    yield
    http.set_transport(None)


_ = httpx
