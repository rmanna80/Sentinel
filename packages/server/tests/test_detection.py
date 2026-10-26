"""Detection rules, alert dedupe, incident correlation, rule toggles and IOC matching.

Events are hand-written to match the agent's normalized LogEvent shape; they are not recordings.
"""

from __future__ import annotations

import json
import secrets as pysecrets
from datetime import timedelta
from typing import Any

from sentinel_core.checks import Check
from sentinel_core.models import CheckOutput, LogEvent, Platform
from sentinel_server.db import session_scope
from sentinel_server.models import Alert, AuditEntry, Device, LogEventRecord, Notification, now
from sentinel_server.phases import detection
from sqlalchemy import select

H1 = "a" * 63 + "1"
H2 = "0123456789abcdef" * 4


class FixtureLogs(Check):
    """Test-only check: returns the LogEvents (and optional evidence) given in the fixture files."""

    id = "test.fixture_logs"
    version = "1"
    title = "Fixture log events (test only)"
    category = "logs"
    platforms = frozenset({Platform.WINDOWS, Platform.LINUX})
    profiles = frozenset({"logs"})
    data_collected = "Hand-written test events"

    def run(self, ctx: Any) -> CheckOutput:
        events = [LogEvent.model_validate(e) for e in json.loads(ctx.read_text("events.json"))]
        content: Any = {"events": len(events)}
        if ctx.path_exists("evidence.json"):
            content = json.loads(ctx.read_text("evidence.json"))
        return CheckOutput(events=events, evidence=[ctx.evidence("log_summary", "fixture", content)])


def ev(action: str, at, *, user: str | None = None, ip: str | None = None, source: str = "windows:Security",
       data: dict | None = None, message: str | None = None, severity: str = "info", process: str | None = None,
       category: str = "authentication") -> dict[str, Any]:
    return {"source": source, "record_id": pysecrets.token_hex(8), "occurred_at": at.isoformat(),
            "category": category, "action": action, "severity": severity, "user": user, "source_ip": ip,
            "process": process, "message": message or f"{action} for {user or '-'} from {ip or '-'}",
            "data": data or {}, "outcome": "failure" if "fail" in action else "success"}


def logs_fixture(events: list[dict], evidence: Any = None) -> dict[str, Any]:
    files = {"events.json": json.dumps(events)}
    if evidence is not None:
        files["evidence.json"] = json.dumps(evidence)
    return {"files": files}


def add_device(name: str = "PC-1") -> int:
    with session_scope() as db:
        d = Device(name=name, hostname=name, os_family="windows", os_name="Windows 11", os_version="24H2",
                   arch="AMD64", agent_version="0.1.0", token_hash=pysecrets.token_hex(32))
        db.add(d)
        db.flush()
        return d.id


def ingest(device_id: int, specs: list[dict], *, run_hook: bool = True) -> list[int]:
    """Store events directly and call the detection handler the way the ingest path does."""
    with session_scope() as db:
        device = db.get(Device, device_id)
        recs = []
        for s in specs:
            from datetime import datetime

            rec = LogEventRecord(device_id=device_id, source=s["source"], record_id=s["record_id"],
                                 occurred_at=datetime.fromisoformat(s["occurred_at"]), category=s["category"],
                                 action=s["action"], outcome=s["outcome"], severity=s["severity"], user=s["user"],
                                 source_ip=s["source_ip"], process=s["process"], message=s["message"],
                                 data=s["data"])
            db.add(rec)
            recs.append(rec)
        db.flush()
        if run_hook:
            detection.on_events_ingested(db, device, None, recs)
        return [r.id for r in recs]


def alerts(browser, **params) -> list[dict]:
    r = browser.get("/api/alerts", params=params)
    assert r.status_code == 200, r.text
    return r.json()["items"]


# --------------------------------------------------------------------------- brute force via the real agent


def test_bruteforce_threshold_and_dedupe_across_uploads(make_agent, browser):
    agent = make_agent([FixtureLogs])
    t0 = now() - timedelta(hours=3)
    ip = "203.0.113.9"
    first = [ev("logon_failed", t0 + timedelta(minutes=i), user="administrator", ip=ip) for i in range(6)]
    scan = agent.scan(logs_fixture(first), scan_type="logs")
    assert scan["status"] == "completed"
    assert alerts(browser, rule_id="det.bruteforce") == []  # 6 failures: under the threshold

    second = [ev("ssh_failed" if i % 2 else "logon_failed", t0 + timedelta(minutes=10 + i), user="admin", ip=ip)
              for i in range(6)]
    agent.scan(logs_fixture(second), scan_type="logs")
    [a] = alerts(browser, rule_id="det.bruteforce")
    assert a["severity"] == "high" and a["kind"] == "heuristic" and a["entity"] == ip
    assert a["event_count"] == 12

    third = [ev("logon_failed", t0 + timedelta(minutes=20 + i), user="admin", ip=ip) for i in range(4)]
    agent.scan(logs_fixture(third), scan_type="logs")
    [b] = alerts(browser, rule_id="det.bruteforce")
    assert b["id"] == a["id"] and b["event_count"] == 16  # one burst, one alert, updated
    assert b["last_event_at"] > a["last_event_at"]

    detail = browser.get(f"/api/alerts/{a['id']}").json()
    assert detail["events_total"] == 16 and len(detail["evidence"]["event_ids"]) == 16
    assert detail["evidence"]["counts_by_action"] == {"logon_failed": 13, "ssh_failed": 3}
    assert detail["evidence"]["samples"] and detail["investigation_steps"]
    assert "Sentinel does not block anything" in detail["remediation"]
    assert sorted(detail["evidence"]["users"]) == ["admin", "administrator"]

    with session_scope() as db:
        notes = db.execute(select(Notification).where(Notification.kind == "alert")).scalars().all()
        assert [n.link for n in notes] == [f"/threats/alerts/{a['id']}"]
        assert db.get(Alert, a["id"]).dedupe_key == detection._dedupe_key(
            "det.bruteforce", agent.device_id, ip, detection._bucket(
                db.get(Alert, a["id"]).first_event_at, timedelta(minutes=60)))

    # a burst a day later is a separate alert
    later = [ev("logon_failed", t0 + timedelta(days=1, minutes=i), user="admin", ip=ip) for i in range(10)]
    agent.scan(logs_fixture(later), scan_type="logs")
    assert len(alerts(browser, rule_id="det.bruteforce")) == 2


def test_bruteforce_by_user_when_there_is_no_ip(browser):
    dev = add_device()
    t0 = now() - timedelta(hours=1)
    ingest(dev, [ev("logon_failed", t0 + timedelta(minutes=i * 5), user="Bob", ip="-") for i in range(9)])
    assert alerts(browser, rule_id="det.bruteforce") == []
    ingest(dev, [ev("logon_failed", t0 + timedelta(minutes=50), user="bob")])
    [a] = alerts(browser, rule_id="det.bruteforce")
    assert a["entity"] == "bob" and a["event_count"] == 10


def test_failures_spread_over_more_than_an_hour_do_not_alert(browser):
    dev = add_device()
    t0 = now() - timedelta(hours=10)
    ingest(dev, [ev("logon_failed", t0 + timedelta(minutes=i * 7), ip="192.0.2.1") for i in range(12)])
    assert alerts(browser, rule_id="det.bruteforce") == []


# --------------------------------------------------------------------------- brute force followed by success


def test_bruteforce_success_and_incident_correlation(browser):
    dev = add_device("FRONT-DESK")
    t0 = now() - timedelta(hours=1)
    ip = "198.51.100.7"
    burst = [ev("logon_failed", t0 + timedelta(minutes=i), user="alice", ip=ip) for i in range(12)]
    burst.append(ev("logon_success", t0 + timedelta(minutes=12), user="alice", ip=ip))
    ingest(dev, burst)

    [bf] = alerts(browser, rule_id="det.bruteforce")
    [ok] = alerts(browser, rule_id="det.bruteforce_success")
    assert ok["severity"] == "critical" and ok["confidence"] == "medium" and ok["kind"] == "heuristic"
    assert ok["entity"] == "alice" and ok["event_count"] == 13
    assert bf["incident_id"] is not None and bf["incident_id"] == ok["incident_id"]

    inc = browser.get(f"/api/incidents/{ok['incident_id']}").json()
    assert inc["title"] == "Possible account compromise: alice"
    assert inc["severity"] == "critical" and inc["status"] == "open"
    assert {"user:alice", f"ip:{ip}"} <= set(inc["entities"])
    assert {a["id"] for a in inc["alerts"]} == {bf["id"], ok["id"]}
    assert "2 alerts on FRONT-DESK" in inc["summary"]

    # the same account then adds someone to Administrators: joins the incident
    ingest(dev, [ev("group_member_added", t0 + timedelta(minutes=20), user="alice", category="account_management",
                    data={"TargetSid": "S-1-5-32-544", "MemberSid": "S-1-5-21-1-2-3-1010", "MemberName": "eve"})])
    [grp] = alerts(browser, rule_id="det.admin_group_add")
    assert grp["incident_id"] == ok["incident_id"]
    inc = browser.get(f"/api/incidents/{ok['incident_id']}").json()
    assert len(inc["alerts"]) == 3 and inc["alert_count"] == 3

    # an alert with no shared account or address stays on its own
    ingest(dev, [ev("realtime_protection_disabled", t0 + timedelta(minutes=25), user="SYSTEM",
                    source="windows:Microsoft-Windows-Windows Defender/Operational", category="malware")])
    [rtp] = alerts(browser, rule_id="det.realtime_protection_disabled")
    assert rtp["incident_id"] is None and rtp["kind"] == "verified"

    # a user summary is kept; closing is audited
    r = browser.patch(f"/api/incidents/{inc['id']}", json={"status": "closed", "summary": "Was the help desk."})
    assert r.status_code == 200 and r.json()["status"] == "closed" and r.json()["closed_at"]
    assert r.json()["summary"] == "Was the help desk."
    assert browser.get("/api/incidents", params={"status": "open"}).json()["total"] == 0


def test_success_after_too_few_failures_is_not_an_alert(browser):
    dev = add_device()
    t0 = now() - timedelta(hours=1)
    specs = [ev("ssh_failed", t0 + timedelta(minutes=i), user="pi", ip="10.0.0.5", source="linux:journal")
             for i in range(4)]
    specs.append(ev("ssh_success", t0 + timedelta(minutes=5), user="pi", ip="10.0.0.5", source="linux:journal"))
    ingest(dev, specs)
    assert alerts(browser, rule_id="det.bruteforce_success") == []
    # one more failure before a later success crosses the threshold, in a later upload
    ingest(dev, [ev("ssh_failed", t0 + timedelta(minutes=6), user="pi", ip="10.0.0.5", source="linux:journal"),
                 ev("ssh_success", t0 + timedelta(minutes=7), user="pi", ip="10.0.0.5", source="linux:journal")])
    [a] = alerts(browser, rule_id="det.bruteforce_success")
    assert a["entity"] == "pi"


# --------------------------------------------------------------------------- single-event rules


def test_admin_group_add_only_for_administrators(browser):
    dev = add_device()
    t = now() - timedelta(minutes=30)
    ingest(dev, [ev("group_member_added", t, user="bob", category="account_management",
                    data={"TargetSid": "S-1-5-32-555", "MemberSid": "S-1-5-21-9-9-9-1001"})])
    assert alerts(browser, rule_id="det.admin_group_add") == []
    ingest(dev, [ev("group_member_added", t, user="bob", category="account_management",
                    data={"TargetSid": "S-1-5-32-544", "MemberSid": "S-1-5-21-9-9-9-1001"})])
    [a] = alerts(browser, rule_id="det.admin_group_add")
    assert a["severity"] == "high" and a["kind"] == "verified" and a["entity"] == "S-1-5-21-9-9-9-1001"
    detail = browser.get(f"/api/alerts/{a['id']}").json()
    assert "Changed by: bob." in detail["description"]


def test_service_rules_split_suspicious_and_ordinary_installs(browser):
    dev = add_device()
    t = now() - timedelta(minutes=30)
    sys_ = "windows:System"
    ingest(dev, [
        ev("service_installed", t, source=sys_, category="service",
           data={"ServiceName": "Updater", "ImagePath": "C:\\Users\\bob\\AppData\\Local\\Temp\\upd.exe"}),
        ev("service_installed", t, source=sys_, category="service",
           data={"ServiceName": "PSvc", "ImagePath": "%COMSPEC% /c powershell.exe -nop -w hidden -enc SQBFAFgA"}),
        ev("service_installed", t, source=sys_, category="service",
           data={"ServiceName": "FooAgent", "ServiceFileName": "\"C:\\Program Files\\Foo\\agent.exe\" --service"}),
    ])
    sus = {a["entity"] for a in alerts(browser, rule_id="det.suspicious_service")}
    assert sus == {"Updater", "PSvc"}
    [plain] = alerts(browser, rule_id="det.service_installed")
    assert plain["entity"] == "FooAgent" and plain["severity"] == "low"
    assert detection.is_suspicious_service_path("powershell -EncodedCommand AAAA")
    assert detection.is_suspicious_service_path("C:\\Users\\Public\\x.exe")
    assert not detection.is_suspicious_service_path("C:\\Windows\\System32\\svchost.exe -k netsvcs")


def test_other_verified_rules(browser):
    dev = add_device()
    t = now() - timedelta(minutes=30)
    defender = "windows:Microsoft-Windows-Windows Defender/Operational"
    ingest(dev, [
        ev("audit_log_cleared", t, user="mallory", category="audit"),
        ev("account_created", t, user="mallory", category="account_management", data={"TargetUserName": "svc-x"}),
        ev("malware_detected", t, source=defender, category="malware",
           data={"Threat Name": "Trojan:Win32/Test", "Path": "C:\\Users\\bob\\Downloads\\x.exe"}),
        ev("account_locked_out", t, user="carol", category="account_management"),
    ])
    by_rule = {a["rule_id"]: a for a in alerts(browser)}
    assert by_rule["det.audit_log_cleared"]["severity"] == "high"
    assert by_rule["det.new_local_account"]["entity"] == "svc-x" and by_rule["det.new_local_account"]["severity"] == "medium"
    assert by_rule["det.malware_detected"]["title"] == "Defender reported Trojan:Win32/Test"
    assert by_rule["det.account_lockout"]["severity"] == "medium"
    # the log clear and new account share the account "mallory": correlated
    assert by_rule["det.audit_log_cleared"]["incident_id"] == by_rule["det.new_local_account"]["incident_id"] is not None


def test_sudo_failures(browser):
    dev = add_device()
    t = now() - timedelta(minutes=30)
    ingest(dev, [ev("sudo_failed", t + timedelta(minutes=i * 2), user="pi", source="linux:journal",
                    category="privilege") for i in range(3)])
    [a] = alerts(browser, rule_id="det.sudo_failures")
    assert a["severity"] == "medium" and a["event_count"] == 3


# --------------------------------------------------------------------------- workflow, rules, audit


def test_alert_update_is_audited_and_validated(browser):
    dev = add_device()
    ingest(dev, [ev("audit_log_cleared", now() - timedelta(minutes=5), user="bob", category="audit")])
    [a] = alerts(browser)
    assert browser.patch(f"/api/alerts/{a['id']}", json={"status": "deleted"}).status_code == 422
    r = browser.patch(f"/api/alerts/{a['id']}", json={"status": "false_positive", "notes": "Planned maintenance"})
    assert r.status_code == 200 and r.json()["status"] == "false_positive" and r.json()["notes"] == "Planned maintenance"
    assert alerts(browser, status="open") == []
    assert len(alerts(browser, status=["false_positive", "resolved"])) == 1
    with session_scope() as db:
        entry = db.execute(select(AuditEntry).where(AuditEntry.action == "alert.updated")).scalar_one()
        assert entry.detail["to"] == "false_positive" and entry.actor == "user:ryan"
    assert browser.get("/api/alerts/999999").status_code == 404


def test_disabled_rule_does_not_fire(browser):
    dev = add_device()
    r = browser.patch("/api/rules/det.new_local_account", json={"enabled": False})
    assert r.status_code == 200 and r.json()["enabled"] is False
    ingest(dev, [ev("account_created", now() - timedelta(minutes=10), user="admin", category="account_management",
                    data={"TargetUserName": "ghost"})])
    assert alerts(browser, rule_id="det.new_local_account") == []
    rules = {r["id"]: r for r in browser.get("/api/rules").json()}
    assert rules["det.new_local_account"]["enabled"] is False and rules["det.bruteforce"]["enabled"] is True
    assert rules["det.bruteforce"]["threshold"] == 10 and rules["det.bruteforce"]["window_minutes"] == 60
    assert len(rules) == len(detection.RULE_LIST)

    browser.patch("/api/rules/det.new_local_account", json={"enabled": True})
    ingest(dev, [ev("account_created", now() - timedelta(minutes=5), user="admin", category="account_management",
                    data={"TargetUserName": "ghost2"})])
    assert len(alerts(browser, rule_id="det.new_local_account")) == 1
    rules = {r["id"]: r for r in browser.get("/api/rules").json()}
    assert rules["det.new_local_account"]["alert_count"] == 1
    assert browser.patch("/api/rules/det.nope", json={"enabled": False}).status_code == 404
    with session_scope() as db:
        assert db.execute(select(AuditEntry).where(AuditEntry.action == "rule.updated")).scalars().all()


def test_alert_routes_need_a_session(anon):
    assert anon.get("/api/alerts").status_code == 401
    assert anon.get("/api/rules").status_code == 401
    assert anon.get("/api/iocs").status_code == 401


# --------------------------------------------------------------------------- IOC hashes


def test_ioc_import_and_match(make_agent, browser):
    assert browser.post("/api/iocs", json=[{"sha256": "not-a-hash"}]).status_code == 422
    r = browser.post("/api/iocs", json=[{"sha256": H1.upper(), "label": "dropper from report"},
                                        {"sha256": H2}, {"sha256": H2}])
    assert r.status_code == 200 and r.json()["added"] == 2 and r.json()["total"] == 2
    listing = browser.get("/api/iocs").json()
    assert listing["total"] == 2 and "ships no hash feed" in listing["note"]
    assert {i["sha256"] for i in listing["items"]} == {H1, H2}

    agent = make_agent([FixtureLogs])
    events = [ev("process_created", now() - timedelta(minutes=5), category="process",
                 data={"Hashes": f"MD5=00,SHA256={H1.upper()}", "Image": "C:\\Temp\\x.exe"})]
    evidence = {"files": [{"path": "C:\\Users\\bob\\Downloads\\tool.exe", "sha256": H2}]}
    agent.scan(logs_fixture(events, evidence), scan_type="logs")

    with session_scope() as db:
        assert detection.match_iocs(db) == 2
    hits = {a["entity"]: a for a in alerts(browser, rule_id="det.ioc_hash_match")}
    assert set(hits) == {H1, H2}
    assert hits[H1]["severity"] == "high" and hits[H1]["kind"] == "verified" and hits[H1]["event_count"] == 1
    d2 = browser.get(f"/api/alerts/{hits[H2]['id']}").json()
    assert d2["evidence"]["evidence_matches"][0]["source"] == "fixture" and d2["events_total"] == 0
    assert d2["evidence"]["ioc_sha256"] == H2
    d1 = browser.get(f"/api/alerts/{hits[H1]['id']}").json()
    assert d1["evidence"]["ioc_label"] == "dropper from report" and d1["events_total"] == 1

    with session_scope() as db:  # nothing new: no new or changed alerts
        detection.tick(db)
    assert len(alerts(browser, rule_id="det.ioc_hash_match")) == 2

    assert browser.delete(f"/api/iocs/{H2}").status_code == 204
    assert browser.delete(f"/api/iocs/{H2}").status_code == 404
    assert browser.get("/api/iocs").json()["total"] == 1


def test_find_hashes_walks_nested_json():
    found = detection.find_hashes({"a": [{"b": f"x {H1} y"}, H2.upper()], H1: 1, "short": "abc", "long": "f" * 65})
    assert found == {H1, H2}
