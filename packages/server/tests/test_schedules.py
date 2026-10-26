"""Scheduled scans: next-run math (with DST), CRUD, run-now, due runs, missed runs and failure notices."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sentinel_server.db import session_scope
from sentinel_server.models import AuditEntry, Notification, Scan, Schedule, now
from sentinel_server.phases import schedules
from sentinel_server.phases.schedules import compute_next_run
from sqlalchemy import select

from .test_detection import FixtureLogs, logs_fixture

NY = "America/New_York"


def utc(*args: int) -> datetime:
    return datetime(*args, tzinfo=UTC)


# --------------------------------------------------------------------------- next-run math


def test_daily_keeps_local_time_across_dst_changes():
    # 09:00 New York is 13:00 UTC in summer (EDT) and 14:00 UTC in winter (EST); DST ends 2026-11-01.
    first = compute_next_run("daily", "09:00", NY, utc(2026, 10, 31, 12, 0))
    assert first == utc(2026, 10, 31, 13, 0)
    second = compute_next_run("daily", "09:00", NY, first)
    assert second == utc(2026, 11, 1, 14, 0)
    assert second - first == timedelta(hours=25)
    # spring forward 2026-03-08: 09:00 EST -> 09:00 EDT
    assert compute_next_run("daily", "09:00", NY, utc(2026, 3, 7, 14, 0)) == utc(2026, 3, 8, 13, 0)


def test_nonexistent_and_ambiguous_local_times():
    # 02:30 does not exist on 2026-03-08 in New York: it runs one hour later, 03:30 EDT (07:30 UTC)
    assert compute_next_run("daily", "02:30", NY, utc(2026, 3, 8, 0, 0)) == utc(2026, 3, 8, 7, 30)
    # 01:30 happens twice on 2026-11-01: runs once, at the first (EDT) occurrence
    run = compute_next_run("daily", "01:30", NY, utc(2026, 11, 1, 0, 0))
    assert run == utc(2026, 11, 1, 5, 30)
    assert compute_next_run("daily", "01:30", NY, run) == utc(2026, 11, 2, 6, 30)


def test_weekly_monthly_and_hourly():
    # 2026-10-26 is a Monday; weekly on Monday (0) at 08:15 local
    assert compute_next_run("weekly", "08:15", NY, utc(2026, 10, 26, 13, 0), day_of_week=0) == \
        utc(2026, 11, 2, 13, 15)  # this Monday's 08:15 EDT (12:15 UTC) passed; next Monday is EST
    assert compute_next_run("weekly", "08:15", NY, utc(2026, 10, 26, 11, 0), day_of_week=0) == \
        utc(2026, 10, 26, 12, 15)
    assert compute_next_run("monthly", "23:00", "UTC", utc(2026, 1, 28, 23, 0), day_of_month=28) == \
        utc(2026, 2, 28, 23, 0)
    assert compute_next_run("hourly", "00:20", NY, utc(2026, 10, 26, 10, 25)) == utc(2026, 10, 26, 11, 20)
    assert compute_next_run("hourly", "00:20", NY, utc(2026, 10, 26, 10, 19, 59)) == utc(2026, 10, 26, 10, 20)
    # half-hour offset zone: local minute 00 is UTC minute 30
    assert compute_next_run("hourly", "09:00", "Asia/Kolkata", utc(2026, 10, 26, 10, 0)) == utc(2026, 10, 26, 10, 30)


# --------------------------------------------------------------------------- CRUD


def make(browser, device_id: int, **kw) -> dict:
    body = {"name": "Nightly", "device_id": device_id, "scan_type": "logs", "frequency": "daily",
            "time_of_day": "02:00", **kw}
    r = browser.post("/api/schedules", json=body)
    assert r.status_code == 201, r.text
    return r.json()


def test_crud_validation_and_audit(make_agent, browser):
    agent = make_agent([FixtureLogs])
    s = make(browser, agent.device_id)
    assert s["timezone"] == NY and s["enabled"] is True and s["device_name"] == "TEST-PC"
    nxt = datetime.fromisoformat(s["next_run_at"])
    assert nxt > now() and nxt - now() <= timedelta(days=1, hours=1)

    bad = [
        {"timezone": "Mars/Olympus"},
        {"time_of_day": "25:00"},
        {"frequency": "weekly"},  # needs day_of_week
        {"frequency": "monthly", "day_of_month": 31},
        {"scan_type": "network"},
        {"frequency": "yearly"},
    ]
    for extra in bad:
        body = {"name": "x", "device_id": agent.device_id, "scan_type": "full", **extra}
        assert browser.post("/api/schedules", json=body).status_code == 422, extra
    assert browser.post("/api/schedules", json={"name": "x", "device_id": 999}).status_code == 404

    r = browser.patch(f"/api/schedules/{s['id']}", json={"frequency": "weekly", "day_of_week": 6, "time_of_day": "07:45"})
    assert r.status_code == 200
    up = r.json()
    local = datetime.fromisoformat(up["next_run_at"]).astimezone(schedules._zone(NY))
    assert local.weekday() == 6 and (local.hour, local.minute) == (7, 45)
    assert browser.patch(f"/api/schedules/{s['id']}", json={"frequency": "monthly"}).status_code == 422

    off = browser.patch(f"/api/schedules/{s['id']}", json={"enabled": False}).json()
    assert off["enabled"] is False and off["next_run_at"] is None
    assert browser.patch(f"/api/schedules/{s['id']}", json={"timezone": "Nowhere/Land"}).status_code == 422
    assert [x["id"] for x in browser.get("/api/schedules").json()] == [s["id"]]
    assert browser.get(f"/api/schedules/{s['id']}").json()["name"] == "Nightly"

    assert browser.delete(f"/api/schedules/{s['id']}").status_code == 204
    assert browser.get(f"/api/schedules/{s['id']}").status_code == 404
    with session_scope() as db:
        actions = [a.action for a in db.execute(select(AuditEntry).where(AuditEntry.action.like("schedule.%"))
                                                .order_by(AuditEntry.id)).scalars()]
    assert actions == ["schedule.created", "schedule.updated", "schedule.updated", "schedule.deleted"]


def test_routes_need_a_session(anon):
    assert anon.get("/api/schedules").status_code == 401


# --------------------------------------------------------------------------- run-now and due runs


def test_run_now_queues_a_scheduled_scan_the_agent_runs(make_agent, browser):
    agent = make_agent([FixtureLogs])
    s = make(browser, agent.device_id)
    r = browser.post(f"/api/schedules/{s['id']}/run-now")
    assert r.status_code == 201
    scan = r.json()
    assert scan["reason"] == "scheduled" and scan["scan_type"] == "logs" and scan["status"] == "queued"
    assert browser.post(f"/api/schedules/{s['id']}/run-now").status_code == 409  # still queued
    agent.run_next(logs_fixture([]))
    after = browser.get(f"/api/schedules/{s['id']}").json()
    assert after["last_scan_id"] == scan["id"] and after["last_scan_status"] == "completed"
    assert after["next_run_at"] == s["next_run_at"]  # timetable unchanged
    with session_scope() as db:
        assert db.get(Scan, scan["id"]).schedule_id == s["id"]
        assert db.execute(select(AuditEntry).where(AuditEntry.action == "schedule.run_now")).scalar_one()


def _set_next(schedule_id: int, when: datetime) -> None:
    with session_scope() as db:
        db.get(Schedule, schedule_id).next_run_at = when


def test_due_schedule_queues_once_and_skips_while_previous_runs(make_agent, browser):
    agent = make_agent([FixtureLogs])
    s = make(browser, agent.device_id, frequency="hourly", time_of_day="00:00")
    # the server was down for three days: only one catch-up run, then back on the timetable
    _set_next(s["id"], now() - timedelta(days=3))
    with session_scope() as db:
        assert schedules.run_due(db, now()) == 1
    with session_scope() as db:
        sched = db.get(Schedule, s["id"])
        assert now() < sched.next_run_at <= now() + timedelta(hours=1)
        scans = db.execute(select(Scan).where(Scan.schedule_id == s["id"])).scalars().all()
        assert len(scans) == 1 and scans[0].reason == "scheduled" and scans[0].requested_by is None

    # due again while that scan is still queued: skipped (and noted), timetable advances
    _set_next(s["id"], now() - timedelta(minutes=1))
    with session_scope() as db:
        assert schedules.run_due(db, now()) == 0
        assert db.execute(select(AuditEntry).where(AuditEntry.action == "schedule.skipped")).scalar_one()
        assert db.get(Schedule, s["id"]).next_run_at > now()

    # disabled schedules never run
    browser.patch(f"/api/schedules/{s['id']}", json={"enabled": False})
    _set_next(s["id"], now() - timedelta(minutes=1))
    with session_scope() as db:
        db.get(Schedule, s["id"]).enabled = False
    with session_scope() as db:
        assert schedules.run_due(db, now()) == 0


# --------------------------------------------------------------------------- missed runs and failures


def test_missed_scheduled_scan_is_cancelled_and_notified(make_agent, browser, settings):
    agent = make_agent([FixtureLogs])
    s = make(browser, agent.device_id)
    scan = browser.post(f"/api/schedules/{s['id']}/run-now").json()
    with session_scope() as db:  # nothing happens inside the grace period
        assert schedules.detect_missed(db, now()) == 0
    with session_scope() as db:
        later = now() + timedelta(minutes=settings.scheduled_scan_grace_minutes + 1)
        assert schedules.detect_missed(db, later) == 1
    with session_scope() as db:
        rec = db.get(Scan, scan["id"])
        assert rec.status == "cancelled" and rec.error == schedules.MISSED_ERROR
        assert db.get(Schedule, s["id"]).consecutive_failures == 1
        [n] = db.execute(select(Notification).where(Notification.kind == "schedule_missed")).scalars().all()
        assert n.dedupe_key == f"schedule-missed:{scan['id']}" and n.severity == "medium"  # below "high", forced
    assert agent.client.next_job() is None  # the agent no longer gets the stale job
    with session_scope() as db:  # idempotent
        assert schedules.detect_missed(db, now() + timedelta(days=1)) == 0
    # a manual scan that waits long is not a missed schedule
    browser.post("/api/scans", json={"device_id": agent.device_id, "scan_type": "logs"})
    with session_scope() as db:
        assert schedules.detect_missed(db, now() + timedelta(days=1)) == 0


def test_failed_scheduled_scan_notifies_and_success_resets(make_agent, browser):
    agent = make_agent([FixtureLogs])
    s = make(browser, agent.device_id)
    scan = browser.post(f"/api/schedules/{s['id']}/run-now").json()
    job = agent.client.next_job()
    assert job is not None and job.scan_id == scan["id"]
    from sentinel_core.models import ScanStatus

    agent.client.complete(job.scan_id, ScanStatus.FAILED, error="Agent crashed")
    with session_scope() as db:
        assert db.get(Schedule, s["id"]).consecutive_failures == 1
        notes = db.execute(select(Notification).where(Notification.kind == "scan_failed")).scalars().all()
        # exactly one notice: the notifications module leaves scheduled scans to this module
        assert [n.dedupe_key for n in notes] == [f"scan-failed:{scan['id']}"]
        assert "Scheduled scan failed: Nightly" in notes[0].title

    browser.post(f"/api/schedules/{s['id']}/run-now")
    agent.run_next(logs_fixture([]))
    assert browser.get(f"/api/schedules/{s['id']}").json()["consecutive_failures"] == 0


def test_tick_runs_due_schedules(make_agent, browser):
    agent = make_agent([FixtureLogs])
    s = make(browser, agent.device_id)
    _set_next(s["id"], now() - timedelta(seconds=5))
    with session_scope() as db:
        schedules.tick(db)
    job = agent.client.next_job()
    assert job is not None
    with session_scope() as db:
        assert db.get(Scan, job.scan_id).schedule_id == s["id"]
