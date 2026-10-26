"""Analytics computed from seeded data, nulls with reasons, and findings export."""

from __future__ import annotations

import csv
import io
import json
from datetime import timedelta
from typing import Any

from sentinel_agent.checks.common.resources import ResourceDiagnostics
from sentinel_agent.checks.windows.firewall import FIREWALL_PROFILES, FirewallProfiles
from sentinel_agent.checks.windows.uac import UacConfiguration
from sentinel_agent.testing import ps_json
from sentinel_server.db import session_scope
from sentinel_server.models import (
    Alert,
    AuditEntry,
    EmailCheck,
    EmailIdentity,
    FindingRecord,
    MetricSampleRecord,
    RemediationTask,
    now,
)
from sqlalchemy import select

CHECKS = [FirewallProfiles, UacConfiguration, ResourceDiagnostics]


def fixture() -> dict[str, Any]:
    """Hand-written fixture in the format the checks read (not a recording): Public firewall profile off."""
    return {
        "commands": {FIREWALL_PROFILES.name: ps_json([
            {"Name": "Domain", "Enabled": "True", "DefaultInboundAction": "NotConfigured"},
            {"Name": "Private", "Enabled": "True", "DefaultInboundAction": "NotConfigured"},
            {"Name": "Public", "Enabled": "False", "DefaultInboundAction": "Block"},
        ])},
        "registry": {},
        "system": {"cpu_percent": 5, "memory": {"total": 1, "available": 1, "percent": 40}, "disks": [],
                   "boot_time": 0},
    }


def _finding(device_id: int, n: int, **kw: Any) -> FindingRecord:
    base: dict[str, Any] = dict(
        device_id=device_id, fingerprint=f"seed-{n}", rule_id=f"seed.rule{n}", check_id="seed.check",
        subject_key=f"s{n}", title=f"Seeded finding {n}", category="configuration", severity="medium",
        confidence="high", finding_kind="verified", status="new", impact="impact", remediation="Do the fix.",
    )
    base.update(kw)
    return FindingRecord(**base)


def seed(device_id: int) -> dict[str, int]:
    t = now()
    with session_scope() as db:
        # resolved in the window after 4 and 2 days -> MTTR 3.0
        db.add(_finding(device_id, 1, status="resolved", first_seen_at=t - timedelta(days=10),
                        verified_resolved_at=t - timedelta(days=6), reopened_count=2))
        db.add(_finding(device_id, 2, status="resolved", first_seen_at=t - timedelta(days=5),
                        verified_resolved_at=t - timedelta(days=3)))
        # resolved before the window: not part of MTTR
        db.add(_finding(device_id, 3, status="resolved", first_seen_at=t - timedelta(days=100),
                        verified_resolved_at=t - timedelta(days=60)))
        vuln = _finding(device_id, 4, severity="critical", category="vulnerability", source="vuln_matcher",
                        affected_software="openssl 3.0.1", cve_id="CVE-2099-0001", first_seen_at=t - timedelta(days=2),
                        remediation="=HYPERLINK(\"http://evil\")")
        db.add(vuln)
        db.add(_finding(device_id, 5, severity="high", category="vulnerability", source="vuln_matcher",
                        affected_software="openssl 3.0.1", status="confirmed", first_seen_at=t - timedelta(days=1)))
        db.flush()
        db.add(RemediationTask(finding_id=vuln.id, title="Patch", due_date=(t - timedelta(days=1)).date().isoformat()))
        db.add(RemediationTask(finding_id=vuln.id, title="Later", due_date=(t + timedelta(days=5)).date().isoformat()))
        db.add(RemediationTask(finding_id=vuln.id, title="Done", status="done"))
        for i, (sev, days_ago) in enumerate([("high", 1), ("high", 1), ("low", 3)]):
            ts = t - timedelta(days=days_ago)
            db.add(Alert(device_id=device_id, rule_id="seed.alert", dedupe_key=f"seed-{i}", title="Brute force",
                         description="d", severity=sev, confidence="medium", kind="heuristic", first_event_at=ts,
                         last_event_at=ts, detected_at=ts))
        db.add(MetricSampleRecord(device_id=device_id, ts=t - timedelta(days=2), metric="cpu_percent", value=10))
        db.add(MetricSampleRecord(device_id=device_id, ts=t - timedelta(days=2), metric="cpu_percent", value=30))
        db.add(MetricSampleRecord(device_id=device_id, ts=t - timedelta(days=2), metric="disk_percent:C:\\", value=71))
        db.add(MetricSampleRecord(device_id=device_id, ts=t - timedelta(days=2), metric="disk_percent:D:\\", value=93))
        ident = EmailIdentity(email="ryan@example.com")
        db.add(ident)
        db.flush()
        db.add(EmailCheck(identity_id=ident.id, checked_at=t - timedelta(days=4), status="found", breach_count=2))
        db.add(EmailCheck(identity_id=ident.id, checked_at=t - timedelta(days=1), status="unavailable"))
        return {"vuln": vuln.id, "identity": ident.id}


def test_analytics_on_seeded_data(make_agent, browser):
    agent = make_agent(CHECKS)
    scan = agent.scan(fixture())
    cancelled = browser.post("/api/scans", json={"device_id": agent.device_id, "scan_type": "posture"}).json()
    browser.post(f"/api/scans/{cancelled['id']}/cancel")
    ids = seed(agent.device_id)

    a = browser.get("/api/analytics", params={"days": 30}).json()
    assert a["mean_time_to_remediate_days"] == 3.0 and a["mean_time_to_remediate_count"] == 2
    # open: agent firewall (high) + seeded critical + seeded high (confirmed)
    assert a["vulns_by_severity"] == {"critical": 1, "high": 2, "medium": 0, "low": 0, "info": 0}
    assert a["vulns_by_category"]["vulnerability"] == 2
    [dev] = a["findings_by_device"]
    assert dev["open"] == 3 and dev["by_severity"]["high"] == 2
    assert a["repeated_misconfigurations"] == [{"rule_id": "seed.rule1", "title": "Seeded finding 1",
                                                "reopened_total": 2, "devices": 1}]
    weeks = a["new_vs_resolved_by_week"]
    assert sum(w["new"] for w in weeks) == 5  # firewall + seeds 1, 2, 4, 5 (seed 3 was first seen 100 days ago)
    assert sum(w["resolved"] for w in weeks) == 2
    assert [p["scan_id"] for p in a["score_history"]] == [scan["id"]]
    assert a["score_history"][0]["raw_score"] == 92 and a["score_history"][0]["score"] is None
    assert sum(w["completed"] for w in a["scan_outcomes"]) == 1
    assert sum(w["cancelled"] for w in a["scan_outcomes"]) == 1
    assert a["success_rate"] == 0.5
    assert a["outstanding_tasks"] == {"open": 2, "overdue": 1}
    alerts = {d["date"]: d for d in a["alerts_over_time"] if d["total"]}
    assert sorted(d["high"] for d in alerts.values()) == [0, 2] and sum(d["low"] for d in alerts.values()) == 1
    day = (now() - timedelta(days=2)).date().isoformat()
    health = {h["date"]: h for h in a["health_history"]}
    assert health[day] == {"date": day, "cpu_avg": 20.0, "memory_avg": None, "disk_max": 93.0}
    assert [e["breach_count"] for e in a["email_exposure_history"]] == [2, None]
    # software inventory was never collected: null with a reason, not zero
    assert a["top_affected_software"] is None
    assert "inventory" in a["unavailable"]["top_affected_software"]
    assert "vulns_by_severity" not in a["unavailable"]

    high_only = browser.get("/api/analytics", params={"severity": "high"}).json()
    assert high_only["vulns_by_severity"]["critical"] == 0 and high_only["vulns_by_severity"]["high"] == 2
    assert high_only["mean_time_to_remediate_days"] is None
    assert "verified as resolved" in high_only["unavailable"]["mean_time_to_remediate_days"]
    assert sum(d["low"] for d in high_only["alerts_over_time"]) == 0
    assert browser.get("/api/analytics", params={"severity": "urgent"}).status_code == 422
    assert browser.get("/api/analytics", params={"device_id": 999}).status_code == 404
    assert ids["vuln"]


def test_analytics_with_no_data_is_null_with_reasons(browser):
    a = browser.get("/api/analytics").json()
    for key in ("score_history", "vulns_by_severity", "vulns_by_category", "top_affected_software",
                "findings_by_device", "new_vs_resolved_by_week", "alerts_over_time", "email_exposure_history",
                "scan_outcomes", "success_rate", "health_history", "mean_time_to_remediate_days",
                "repeated_misconfigurations"):
        assert a[key] is None, key
        assert a["unavailable"][key], key
    assert a["outstanding_tasks"] == {"open": 0, "overdue": 0}


def test_software_matched_gives_top_affected_software(make_agent, browser):
    from sentinel_server.models import SoftwareRecord

    agent = make_agent(CHECKS)
    agent.scan(fixture())
    seed(agent.device_id)
    with session_scope() as db:
        db.add(SoftwareRecord(device_id=agent.device_id, name="openssl", version="3.0.1", ecosystem="Debian:12",
                              source="dpkg", match_status="matched"))
    a = browser.get("/api/analytics").json()
    assert a["top_affected_software"] == [{"name": "openssl 3.0.1", "count": 2}]


def test_export_findings_csv_and_json(make_agent, browser):
    agent = make_agent(CHECKS)
    agent.scan(fixture())
    seed(agent.device_id)
    r = browser.get("/api/export/findings", params={"format": "csv"})
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/csv")
    assert "attachment" in r.headers["content-disposition"]
    rows = list(csv.DictReader(io.StringIO(r.content.decode("utf-8-sig"))))
    assert len(rows) == 3 and rows[0]["severity"] == "critical"
    assert rows[0]["remediation"].startswith("'=")  # spreadsheet formula injection neutralised
    fw = next(x for x in rows if x["rule_id"] == "win.firewall.profile_disabled")
    assert fw["evidence_source"] == "Get-NetFirewallProfile" and fw["last_seen_data_mode"] == "live"

    j = browser.get("/api/export/findings", params={"format": "json", "status": "all", "source": "vuln_matcher",
                                                    "severity": ["critical"]})
    data = json.loads(j.content)
    assert [d["cve_id"] for d in data] == ["CVE-2099-0001"]
    assert browser.get("/api/export/findings", params={"format": "xml"}).status_code == 422
    with session_scope() as db:
        entries = db.execute(select(AuditEntry).where(AuditEntry.action == "findings.exported")).scalars().all()
        assert [e.detail["format"] for e in entries] == ["csv", "json"]
        assert entries[1].detail["count"] == 1
