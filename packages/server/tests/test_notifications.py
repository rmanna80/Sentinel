"""In-app notifications, finding and scan-failure notices, quiet hours and the email digest (fake SMTP)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sentinel_agent.checks.windows.firewall import FIREWALL_PROFILES, FirewallProfiles
from sentinel_agent.testing import ps_json
from sentinel_core.models import ScanStatus
from sentinel_server.db import session_scope
from sentinel_server.models import AuditEntry, Notification, now
from sentinel_server.phases import notifications
from sentinel_server.services import secrets
from sentinel_server.services.app_settings import get_setting, set_setting
from sentinel_server.services.notify import notify
from sqlalchemy import select


class FakeSMTP:
    """Records what would have been sent. Nothing leaves the test."""

    sent: list[Any] = []
    instances: list[FakeSMTP] = []
    fail_with: Exception | None = None

    def __init__(self, host: str, port: int, timeout: float) -> None:
        self.host, self.port, self.timeout = host, port, timeout
        self.tls = False
        self.login_args: tuple[str, str] | None = None
        self.closed = False
        FakeSMTP.instances.append(self)

    def starttls(self, context: Any = None) -> None:
        self.tls = True

    def login(self, user: str, password: str) -> None:
        self.login_args = (user, password)

    def send_message(self, msg: Any) -> None:
        if FakeSMTP.fail_with is not None:
            raise FakeSMTP.fail_with
        FakeSMTP.sent.append(msg)

    def quit(self) -> None:
        self.closed = True


@pytest.fixture
def fake_smtp(monkeypatch):
    FakeSMTP.sent, FakeSMTP.instances, FakeSMTP.fail_with = [], [], None
    monkeypatch.setattr(notifications, "smtp_class", FakeSMTP)
    yield FakeSMTP


@pytest.fixture
def email_on(settings, fake_smtp, monkeypatch):
    store: dict[str, str] = {"smtp_password": "app-password-123"}
    monkeypatch.setattr(secrets, "get_secret", lambda name: store.get(name))
    with session_scope() as db:
        set_setting(db, "notifications", {"email_enabled": True, "smtp_host": "smtp.example.test", "smtp_port": 2525,
                                          "smtp_username": "me@example.test", "smtp_from": "sentinel@example.test",
                                          "email_to": "me@example.test, partner@example.test",
                                          "smtp_starttls": True, "timezone": "America/New_York",
                                          "min_severity": "high"})
    return store


def update_prefs(**changes: Any) -> None:
    """Change some notification settings, keeping the rest (like PUT /api/settings/notifications)."""
    with session_scope() as db:
        set_setting(db, "notifications", {**get_setting(db, "notifications"), **changes})


def add(severity: str = "high", title: str = "Something", *, kind: str = "system", created: datetime | None = None,
        key: str | None = None) -> int:
    with session_scope() as db:
        n = notify(db, severity=severity, kind=kind, title=title, dedupe_key=key, force=True)
        assert n is not None
        if created is not None:
            n.created_at = created
        return n.id


# --------------------------------------------------------------------------- in-app list and read state


def test_list_unread_first_and_read_state(browser):
    old_unread = add("high", "old unread", created=now() - timedelta(hours=5))
    read_one = add("critical", "newest but read")
    new_unread = add("medium", "new unread", created=now() - timedelta(minutes=1))
    assert browser.post(f"/api/notifications/{read_one}/read").json()["read_at"] is not None

    items = browser.get("/api/notifications").json()
    assert [i["id"] for i in items] == [new_unread, old_unread, read_one]
    assert [i["id"] for i in browser.get("/api/notifications", params={"limit": 1}).json()] == [new_unread]
    count = browser.get("/api/notifications/unread-count").json()
    assert count == {"unread": 2, "by_severity": {"high": 1, "medium": 1}}

    assert browser.post("/api/notifications/read-all").json() == {"marked": 2}
    assert browser.get("/api/notifications/unread-count").json()["unread"] == 0
    assert browser.post("/api/notifications/999999/read").status_code == 404
    assert browser.client.post("/api/notifications/read-all").status_code == 403  # CSRF enforced
    with session_scope() as db:
        actions = {a.action for a in db.execute(select(AuditEntry)).scalars()}
    assert {"notification.read", "notification.read_all"} <= actions


def test_routes_need_a_session(anon):
    assert anon.get("/api/notifications").status_code == 401
    assert anon.get("/api/notifications/unread-count").status_code == 401


# --------------------------------------------------------------------------- hooks


def _firewall(public_enabled: bool) -> dict:
    return {"commands": {FIREWALL_PROFILES.name: ps_json([
        {"Name": "Domain", "Enabled": "True", "DefaultInboundAction": "NotConfigured"},
        {"Name": "Private", "Enabled": "True", "DefaultInboundAction": "NotConfigured"},
        {"Name": "Public", "Enabled": "True" if public_enabled else "False", "DefaultInboundAction": "Block"},
    ])}}


def test_findings_notify_with_threshold_and_reopen(make_agent, browser):
    agent = make_agent([FirewallProfiles])
    agent.scan(_firewall(public_enabled=False))
    items = browser.get("/api/notifications").json()
    [n] = [i for i in items if i["kind"] == "finding"]
    assert n["severity"] == "high" and n["link"].startswith("/vulnerabilities/") and "TEST-PC" in n["title"]
    finding_id = int(n["link"].rsplit("/", 1)[1])

    agent.scan(_firewall(public_enabled=False))  # same finding again: no new notification
    assert len([i for i in browser.get("/api/notifications").json() if i["kind"] == "finding"]) == 1
    agent.scan(_firewall(public_enabled=True))  # resolved
    agent.scan(_firewall(public_enabled=False))  # reopened: a new notice
    findings = [i for i in browser.get("/api/notifications").json() if i["kind"] == "finding"]
    assert len(findings) == 2 and findings[0]["title"].startswith("Reopened")
    with session_scope() as db:
        keys = {n.dedupe_key for n in db.execute(select(Notification).where(Notification.kind == "finding")).scalars()}
    assert keys == {f"finding:{finding_id}:0", f"finding:{finding_id}:1"}

    # raise the threshold: a high finding no longer notifies
    update_prefs(min_severity="critical")
    agent.scan(_firewall(public_enabled=True))
    agent.scan(_firewall(public_enabled=False))
    assert len([i for i in browser.get("/api/notifications").json() if i["kind"] == "finding"]) == 2


def test_failed_manual_scan_is_notified(make_agent, browser):
    agent = make_agent([FirewallProfiles])
    scan = browser.post("/api/scans", json={"device_id": agent.device_id, "scan_type": "posture"}).json()
    job = agent.client.next_job()
    agent.client.complete(job.scan_id, ScanStatus.FAILED, error="Out of memory")
    [n] = [i for i in browser.get("/api/notifications").json() if i["kind"] == "scan_failed"]
    assert n["severity"] == "medium" and n["body"] == "Out of memory" and n["link"] == f"/scans/{scan['id']}"


# --------------------------------------------------------------------------- email digest


def test_digest_email_with_fake_smtp(browser, email_on, fake_smtp):
    a = add("high", "Brute force from 203.0.113.9")
    b = add("critical", "Sign-in after failures")
    old = add("high", "Two days old", created=now() - timedelta(days=2))
    with session_scope() as db:
        assert notifications.send_digest(db) == 2
    [msg] = fake_smtp.sent
    smtp = fake_smtp.instances[0]
    assert (smtp.host, smtp.port, smtp.timeout) == ("smtp.example.test", 2525, 20)
    assert smtp.tls and smtp.closed and smtp.login_args == ("me@example.test", "app-password-123")
    assert msg["To"] == "me@example.test, partner@example.test" and msg["From"] == "sentinel@example.test"
    assert msg["Subject"] == "[Sentinel] 2 notifications (highest: critical)"
    body = msg.get_content()
    assert "Brute force from 203.0.113.9" in body and "Sign-in after failures" in body
    assert "Two days old" not in body and "app-password-123" not in body
    with session_scope() as db:
        assert db.get(Notification, a).emailed_at and db.get(Notification, b).emailed_at
        assert db.get(Notification, old).emailed_at is None
    with session_scope() as db:  # nothing unsent: nothing sent
        notifications.tick(db)
    assert len(fake_smtp.sent) == 1


def test_email_failure_is_retried_next_tick(browser, email_on, fake_smtp):
    n = add("high", "Retry me")
    fake_smtp.fail_with = OSError("connection refused")
    with session_scope() as db:
        assert notifications.send_digest(db) == 0
    with session_scope() as db:
        assert db.get(Notification, n).emailed_at is None
    fake_smtp.fail_with = None
    with session_scope() as db:
        assert notifications.send_digest(db) == 1
    assert fake_smtp.sent[0]["Subject"] == "[Sentinel] Retry me"


def test_quiet_hours_hold_email_until_they_end(browser, email_on, fake_smtp):
    update_prefs(quiet_hours_enabled=True, quiet_start="22:00", quiet_end="07:00", timezone="America/New_York")
    n = add("critical", "At night")
    night = datetime(2026, 10, 27, 3, 30, tzinfo=UTC)  # 23:30 in New York (EDT)
    morning = datetime(2026, 10, 27, 11, 5, tzinfo=UTC)  # 07:05 in New York
    with session_scope() as db:
        db.get(Notification, n).created_at = night
    with session_scope() as db:
        assert notifications.send_digest(db, night) == 0
        assert notifications.send_digest(db, night + timedelta(hours=6)) == 0  # 05:30 local, still quiet
    with session_scope() as db:
        assert db.get(Notification, n).emailed_at is None  # held, not dropped
    with session_scope() as db:
        assert notifications.send_digest(db, morning) == 1
    assert fake_smtp.sent[0]["Subject"] == "[Sentinel] At night"
    prefs = {"quiet_hours_enabled": True, "quiet_start": "09:00", "quiet_end": "17:00", "timezone": "UTC"}
    assert notifications.in_quiet_hours(prefs, datetime(2026, 1, 1, 12, 0, tzinfo=UTC))
    assert not notifications.in_quiet_hours(prefs, datetime(2026, 1, 1, 17, 0, tzinfo=UTC))


def test_email_needs_full_configuration(browser, email_on, fake_smtp):
    add("high", "Not sent")
    email_on.pop("smtp_password")  # username set but no stored password
    with session_scope() as db:
        assert notifications.send_digest(db) == 0
    r = browser.post("/api/notifications/test-email").json()
    assert r["sent"] is False and "smtp_password" in r["detail"]
    update_prefs(smtp_username="", smtp_host="")
    assert "smtp_host" in browser.post("/api/notifications/test-email").json()["detail"]
    update_prefs(smtp_host="smtp.example.test")
    with session_scope() as db:  # no username: no password needed, so this one is sent
        assert notifications.send_digest(db) == 1
    assert fake_smtp.instances[-1].login_args is None
    add("high", "Off")
    update_prefs(email_enabled=False)
    with session_scope() as db:
        assert notifications.send_digest(db) == 0
    assert len(fake_smtp.sent) == 1


def test_test_email_sends_now_and_is_audited(browser, email_on, fake_smtp):
    r = browser.post("/api/notifications/test-email")
    assert r.status_code == 200 and r.json()["sent"] is True
    assert fake_smtp.sent[0]["Subject"] == "[Sentinel] Test email"
    fake_smtp.fail_with = OSError("bad auth")
    assert browser.post("/api/notifications/test-email").json() == {"sent": False,
                                                                     "detail": "Sending failed: OSError: bad auth"}
    with session_scope() as db:
        entries = db.execute(select(AuditEntry).where(AuditEntry.action == "notification.test_email")).scalars().all()
    assert [e.detail["sent"] for e in entries] == [True, False]
    assert all("app-password-123" not in str(e.detail) for e in entries)
