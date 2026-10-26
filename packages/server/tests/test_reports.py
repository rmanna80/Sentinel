"""Report generation (PDF, CSV, JSON), storage safety and the fixture-data banner."""

from __future__ import annotations

import csv
import hashlib
import io
import json
from typing import Any

from sentinel_agent.checks.common.resources import ResourceDiagnostics
from sentinel_agent.checks.windows.firewall import FIREWALL_PROFILES, FirewallProfiles
from sentinel_agent.checks.windows.uac import UacConfiguration
from sentinel_agent.testing import ps_json
from sentinel_core.models import DataMode
from sentinel_server.db import session_scope
from sentinel_server.models import AuditEntry, EmailCheck, EmailIdentity, LogEventRecord, Report, now
from sqlalchemy import select

CHECKS = [FirewallProfiles, UacConfiguration, ResourceDiagnostics]


def fixture(hostile_name: str | None = None) -> dict[str, Any]:
    """Hand-written fixture in the format the checks read (not a recording): Public firewall profile off.

    ``hostile_name`` adds a disabled profile with markup and odd characters in its name, which flows into
    the finding title, the remediation text and the evidence excerpt.
    """
    rows = [
        {"Name": "Domain", "Enabled": "True", "DefaultInboundAction": "NotConfigured"},
        {"Name": "Private", "Enabled": "True", "DefaultInboundAction": "NotConfigured"},
        {"Name": "Public", "Enabled": "False", "DefaultInboundAction": "Block"},
    ]
    if hostile_name is not None:
        rows.append({"Name": hostile_name, "Enabled": "False", "DefaultInboundAction": "Block"})
    return {
        "commands": {FIREWALL_PROFILES.name: ps_json(rows)},
        "registry": {},
        "system": {"cpu_percent": 5, "memory": {"total": 1, "available": 1, "percent": 40}, "disks": [],
                   "boot_time": 0},
    }


def _report(browser, kind: str, **kw: Any) -> dict[str, Any]:
    r = browser.post("/api/reports", json={"kind": kind, "title": "Monthly posture <review>", **kw})
    assert r.status_code == 201, r.text
    return r.json()


def test_pdf_csv_json_reports(make_agent, browser, settings):
    agent = make_agent(CHECKS)
    agent.scan(fixture("Lab<b>&</b> \u041f\u0440\u0438\u0432\u0435\u0442 \U0001F600 \x07"))
    with session_scope() as db:
        ident = EmailIdentity(email="ryan.manna@example.com", label="personal")
        db.add(ident)
        db.flush()
        db.add(EmailCheck(identity_id=ident.id, status="found", breach_count=1,
                          breaches=[{"Name": "Adobe", "Title": "Adobe <script>", "BreachDate": "2013-10-04"}]))
    reports_dir = (settings.data_dir / "reports").resolve()

    pdf = _report(browser, "pdf", device_id=agent.device_id, days=7)
    path = reports_dir / pdf["file_name"]
    assert path.resolve().parent == reports_dir
    data = path.read_bytes()
    assert data.startswith(b"%PDF")
    assert hashlib.sha256(data).hexdigest() == pdf["sha256"] and len(data) == pdf["size_bytes"]
    assert pdf["scope"]["days"] == 7 and pdf["scope"]["fixture_data"] is False
    dl = browser.get(f"/api/reports/{pdf['id']}/download")
    assert dl.status_code == 200 and dl.content == data
    assert dl.headers["content-type"] == "application/pdf"
    assert "sentinel-monthly-posture-review" in dl.headers["content-disposition"]

    js = _report(browser, "json")
    body = json.loads(browser.get(f"/api/reports/{js['id']}/download").content)
    assert body["fixture_data"] is False and body["fixture_notice"] is None
    assert body["executive_summary"]["score_display"] == "Incomplete"
    assert body["executive_summary"]["open_by_severity"] == {"critical": 0, "high": 1, "medium": 1, "low": 0,
                                                              "info": 0}
    actions = body["executive_summary"]["recommended_actions"]
    assert [a["severity"] for a in actions] == ["high", "medium"]
    assert actions[0]["action"].startswith("Firewall is off for the Public profile on TEST-PC: Open Windows Security")
    assert "Lab<b>&</b>" in actions[1]["action"]
    assert body["evidence_excerpts"][0]["source"] == "Get-NetFirewallProfile"
    assert len(body["evidence_excerpts"][0]["excerpt"]) <= 1500 + len("\n... [truncated]")
    assert body["email_exposure"][0]["email_masked"] == "r***a@example.com"
    assert "ryan.manna" not in json.dumps(body)
    assert any(c["check_id"] == "win.uac" for c in body["limitations"]["checks_not_run"])
    assert any("No findings does not mean secure" in s for s in body["limitations"]["statements"])
    assert body["severity_ratings"]["weights"]["critical"] == 20

    c = _report(browser, "csv")
    rows = list(csv.DictReader(io.StringIO(browser.get(f"/api/reports/{c['id']}/download").content.decode("utf-8-sig"))))
    assert [r["severity"] for r in rows] == ["high", "medium"]
    assert all(r["rule_id"] == "win.firewall.profile_disabled" for r in rows)

    listing = browser.get("/api/reports").json()
    assert [r["id"] for r in listing] == [c["id"], js["id"], pdf["id"]]
    with session_scope() as db:
        assert len(db.execute(select(AuditEntry).where(AuditEntry.action == "report.created")).scalars().all()) == 3

    assert browser.delete(f"/api/reports/{pdf['id']}").status_code == 204
    assert not path.exists()
    assert browser.get(f"/api/reports/{pdf['id']}/download").status_code == 404


def test_reports_handle_an_empty_database(browser, settings):
    for kind in ("pdf", "csv", "json"):
        rep = _report(browser, kind)
        content = browser.get(f"/api/reports/{rep['id']}/download").content
        assert hashlib.sha256(content).hexdigest() == rep["sha256"]
    body = json.loads(browser.get(f"/api/reports/{rep['id']}/download").content)
    assert body["findings"] == [] and body["executive_summary"]["score"] is None
    assert body["limitations"]["statements"][0] == "No devices were in scope, so nothing was assessed."


def test_fixture_data_banner_flag(make_agent, browser):
    agent = make_agent(CHECKS)
    browser.post("/api/scans", json={"device_id": agent.device_id, "scan_type": "posture"})
    agent.run_next(fixture(), data_mode=DataMode.FIXTURE)
    rep = _report(browser, "json")
    body = json.loads(browser.get(f"/api/reports/{rep['id']}/download").content)
    assert body["fixture_data"] is True and body["fixture_scan_ids"]
    assert body["fixture_notice"].startswith("DEMO DATA")
    assert rep["scope"]["fixture_data"] is True
    pdf = _report(browser, "pdf")
    assert browser.get(f"/api/reports/{pdf['id']}/download").content.startswith(b"%PDF")
    assert pdf["scope"]["fixture_data"] is True


def test_download_refuses_paths_outside_the_reports_folder(browser, settings, tmp_path):
    secret = tmp_path / "secret.txt"
    secret.write_text("top secret")
    rep = _report(browser, "csv")
    for bad in ("../secret.txt", str(secret), "..%2Fsecret.txt", "../../data/sentinel.db", "x.csv", "a" * 32 + ".exe"):
        with session_scope() as db:
            r = db.get(Report, rep["id"])
            assert r is not None
            r.file_name = bad
        resp = browser.get(f"/api/reports/{rep['id']}/download")
        assert resp.status_code == 403, bad
        assert b"top secret" not in resp.content
    # deleting a tampered row never touches the outside file
    assert browser.delete(f"/api/reports/{rep['id']}").status_code == 204
    assert secret.read_text() == "top secret"


def test_report_input_validation(browser, settings):
    assert browser.post("/api/reports", json={"kind": "exe", "title": "x"}).status_code == 422
    assert browser.post("/api/reports", json={"kind": "pdf", "title": "x" * 121}).status_code == 422
    assert browser.post("/api/reports", json={"kind": "pdf", "title": "   "}).status_code == 422
    assert browser.post("/api/reports", json={"kind": "pdf", "title": "x", "days": 0}).status_code == 422
    assert browser.post("/api/reports", json={"kind": "pdf", "title": "x", "days": 366}).status_code == 422
    assert browser.post("/api/reports", json={"kind": "pdf", "title": "x", "device_id": 999}).status_code == 404
    rep = _report(browser, "json", title="../../etc/passwd")
    assert rep["file_name"].endswith(".json") and "/" not in rep["file_name"] and ".." not in rep["file_name"]
    assert (settings.data_dir / "reports" / rep["file_name"]).is_file()


def test_pdf_survives_hostile_text(make_agent, browser):
    agent = make_agent(CHECKS)
    agent.scan(fixture('<para><font name="x">]]> & </b> \u202e ' + "W" * 300))
    with session_scope() as db:
        db.add(LogEventRecord(device_id=agent.device_id, source="s", record_id="1", occurred_at=now(),
                              category="c", action="a", message="<img src=x>", data={}))
    pdf = _report(browser, "pdf")
    assert browser.get(f"/api/reports/{pdf['id']}/download").content.startswith(b"%PDF")
