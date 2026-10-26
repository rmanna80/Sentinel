"""Log search filters, event detail, statistics and retention.

Events are hand-written to match the agent's normalized LogEvent shape; they are not recordings.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sentinel_server.db import session_scope
from sentinel_server.models import Alert, AlertEventLink, LogEventRecord, MetricSampleRecord, now
from sentinel_server.phases import logs
from sentinel_server.services.app_settings import set_setting
from sqlalchemy import func, select

from .test_detection import FixtureLogs, add_device, ev, ingest, logs_fixture


def _day(dt: datetime) -> str:
    return dt.astimezone(UTC).date().isoformat()


def seed(browser) -> dict:
    a, b = add_device("ALPHA"), add_device("BRAVO")
    t = now().replace(hour=12, minute=0, second=0, microsecond=0)
    if t > now():
        t -= timedelta(days=1)
    yday = t - timedelta(days=1)
    ingest(a, [
        ev("logon_failed", t, user="alice", ip="10.0.0.9", severity="low", message="An account failed to log on"),
        ev("logon_failed", t + timedelta(minutes=1), user="alice", ip="10.0.0.9", severity="low"),
        ev("logon_success", t + timedelta(minutes=2), user="alice", ip="10.0.0.9"),
        ev("logon_success", yday, user="bob", ip="10.0.0.4"),
        ev("audit_log_cleared", yday, user="mallory", severity="high", category="audit",
           message="The audit log was cleared"),
        ev("service_installed", t, source="windows:System", category="service", severity="medium",
           process="C:\\Windows\\System32\\services.exe", data={"ServiceName": "Foo", "ImagePath": "C:\\foo.exe"}),
    ])
    ingest(b, [
        ev("ssh_failed", t, user="pi", ip="192.0.2.50", source="linux:journal", severity="low"),
        ev("sudo_command", t, user="pi", source="linux:journal", category="privilege",
           message="pi : COMMAND=/usr/bin/apt update"),
        ev("logon_failed", t - timedelta(days=30), user="old", ip="10.9.9.9"),
    ])
    return {"a": a, "b": b, "t": t, "yday": yday}


def search(browser, **params) -> dict:
    r = browser.get("/api/logs", params=params)
    assert r.status_code == 200, r.text
    return r.json()


def test_search_filters(browser):
    s = seed(browser)
    everything = search(browser)
    assert everything["total"] == 9
    times = [i["occurred_at"] for i in everything["items"]]
    assert times == sorted(times, reverse=True)  # newest first

    assert search(browser, device_id=s["b"])["total"] == 3
    assert search(browser, severity=["low", "high"])["total"] == 4
    assert search(browser, category="audit")["items"][0]["action"] == "audit_log_cleared"
    assert search(browser, action="logon_success")["total"] == 2
    assert search(browser, action=["logon_success", "ssh_failed"])["total"] == 3
    assert search(browser, source="linux:journal")["total"] == 2
    assert search(browser, since=(s["t"] - timedelta(hours=1)).isoformat())["total"] == 6
    assert search(browser, until=(s["t"] - timedelta(days=2)).isoformat())["total"] == 1
    assert search(browser, q="10.0.0.9")["total"] == 3  # source IP
    assert search(browser, q="MALLORY")["total"] == 1  # user, case-insensitive
    assert search(browser, q="services.exe")["total"] == 1  # process
    assert search(browser, q="apt update")["total"] == 1  # message
    assert search(browser, q="100%")["total"] == 0  # LIKE wildcards are literal
    page = search(browser, limit=2, offset=2)
    assert len(page["items"]) == 2 and page["total"] == 9
    assert browser.get("/api/logs", params={"limit": 5000}).status_code == 422


def test_event_detail_has_data_and_linked_alerts(browser):
    s = seed(browser)
    [cleared] = search(browser, action="audit_log_cleared")["items"]
    detail = browser.get(f"/api/logs/{cleared['id']}").json()
    assert detail["device_name"] == "ALPHA" and detail["message"] == "The audit log was cleared"
    [alert] = detail["alerts"]
    assert alert["rule_id"] == "det.audit_log_cleared"
    [svc] = search(browser, action="service_installed")["items"]
    assert browser.get(f"/api/logs/{svc['id']}").json()["data"]["ServiceName"] == "Foo"
    assert browser.get("/api/logs/999999").status_code == 404
    assert s["a"]


def test_stats(browser):
    s = seed(browser)
    stats = browser.get("/api/logs/stats", params={"days": 7}).json()
    assert len(stats["logons_by_day"]) == 7 and len(stats["events_by_day"]) == 7
    assert stats["logons_by_day"][-1]["date"] == _day(now())
    by_day = {d["date"]: d for d in stats["logons_by_day"]}
    assert by_day[_day(s["t"])] == {"date": _day(s["t"]), "success": 1, "failure": 3}
    assert by_day[_day(s["yday"])]["success"] == 1
    sev = {d["date"]: d for d in stats["events_by_day"]}
    assert sev[_day(s["yday"])]["high"] == 1 and sev[_day(s["t"])]["medium"] == 1 and sev[_day(s["t"])]["low"] == 3
    assert stats["total_events"] == 8  # the 30-day-old event is outside the window
    assert stats["alerts_by_severity"]["high"] == 1  # the cleared log
    assert stats["alerts_by_severity"]["low"] == 1  # the service install
    top = {a["action"]: a["count"] for a in stats["top_actions"]}
    assert top["logon_failed"] == 2 and top["logon_success"] == 2
    devices = {d["device_name"]: d["count"] for d in stats["events_by_device"]}
    assert devices == {"ALPHA": 6, "BRAVO": 2}
    assert stats["repeated_patterns"][0] == {"action": "logon_failed", "user": "alice", "source_ip": "10.0.0.9",
                                             "count": 2}

    only_b = browser.get("/api/logs/stats", params={"days": 2, "device_id": s["b"]}).json()  # t: today or yesterday
    assert only_b["total_events"] == 2 and only_b["alerts_by_severity"]["high"] == 0
    assert [d["device_name"] for d in only_b["events_by_device"]] == ["BRAVO"]
    assert browser.get("/api/logs/stats", params={"days": 0}).status_code == 422


def test_events_from_a_real_agent_upload_are_searchable(make_agent, browser):
    agent = make_agent([FixtureLogs])
    agent.scan(logs_fixture([ev("ssh_failed", now() - timedelta(minutes=3), user="root", ip="198.51.100.1",
                                source="linux:journal", message="Failed password for root")]), scan_type="logs")
    [item] = search(browser, device_id=agent.device_id)["items"]
    assert item["action"] == "ssh_failed" and item["scan_id"] is not None


def test_retention_deletes_old_rows_and_cascades_alert_links(browser):
    dev = add_device()
    old = now() - timedelta(days=100)
    old_ids = ingest(dev, [ev("audit_log_cleared", old, user="x", category="audit")])
    ingest(dev, [ev("logon_success", now() - timedelta(days=1), user="y")])
    with session_scope() as db:
        db.add(MetricSampleRecord(device_id=dev, ts=old, metric="cpu_percent", value=5))
        db.add(MetricSampleRecord(device_id=dev, ts=now() - timedelta(days=89), metric="cpu_percent", value=7))
        assert db.execute(select(func.count()).select_from(AlertEventLink)
                          .where(AlertEventLink.log_event_id == old_ids[0])).scalar_one() == 1

    with session_scope() as db:
        removed = logs.apply_retention(db)
    assert removed == {"log_events": 1, "metric_samples": 1}
    with session_scope() as db:
        assert db.get(LogEventRecord, old_ids[0]) is None
        assert db.execute(select(func.count()).select_from(LogEventRecord)).scalar_one() == 1
        assert db.execute(select(func.count()).select_from(AlertEventLink)).scalar_one() == 0
        assert db.execute(select(func.count()).select_from(Alert)).scalar_one() == 1  # the alert itself stays
        assert [m.value for m in db.execute(select(MetricSampleRecord)).scalars()] == [7]

    with session_scope() as db:  # nothing left to delete; shorter retention from settings is honored
        assert logs.apply_retention(db) == {"log_events": 0, "metric_samples": 0}
        set_setting(db, "retention", {"log_event_days": 0, "metric_days": 30})
    with session_scope() as db:
        assert logs.apply_retention(db) == {"log_events": 0, "metric_samples": 1}  # 0 days = keep forever

    with session_scope() as db:
        logs._last_retention.pop(str(db.get_bind().url), None)
        logs.tick(db)  # runs without error, then throttles
        logs.tick(db)
        assert str(db.get_bind().url) in logs._last_retention
