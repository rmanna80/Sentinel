"""Phase 2/6: in-app notifications and the optional email digest.

``services.notify.notify`` creates notification rows (with dedupe and the severity threshold). This module
lists them, marks them read, turns new findings and failed manual scans into notifications, and sends
unsent ones as one digest email per background tick when email is configured.

Email is sent only when ``notifications.email_enabled`` is on, ``smtp_host``, ``email_to`` and ``smtp_from``
are set, and (when ``smtp_username`` is set) the ``smtp_password`` secret exists. During quiet hours
emails are held, not dropped: they go out in the first digest after quiet hours end. A failed send is
logged and retried on the next tick. Email never blocks the in-app notifications.
"""

from __future__ import annotations

import logging
import smtplib
import ssl
from datetime import datetime, time, timedelta
from email.message import EmailMessage
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict
from sqlalchemy import func, select, update
from sqlalchemy.orm import Session

from .. import audit
from ..db import get_db
from ..deps import AuthContext, current_auth
from ..models import Device, FindingRecord, Notification, Scan, now
from ..services import hooks, secrets
from ..services.app_settings import get_setting
from ..services.notify import notify

log = logging.getLogger(__name__)

router = APIRouter(prefix="/api/notifications", tags=["notifications"])

DIGEST_WINDOW = timedelta(hours=24)
DIGEST_MAX_ITEMS = 200
SMTP_TIMEOUT = 20
SEV_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# Injectable for tests: anything with smtplib.SMTP's constructor and the methods used below.
smtp_class: Any = smtplib.SMTP


# =========================================================================== schemas


class NotificationOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    created_at: datetime
    severity: str
    kind: str
    title: str
    body: str
    link: str | None
    read_at: datetime | None
    emailed_at: datetime | None
    suppressed_reason: str | None


class UnreadCount(BaseModel):
    unread: int
    by_severity: dict[str, int]


class ReadAllResult(BaseModel):
    marked: int


class TestEmailResult(BaseModel):
    sent: bool
    detail: str


# =========================================================================== email helpers


class EmailNotConfigured(Exception):
    pass


def email_config(db: Session) -> dict[str, Any]:
    """The usable email settings, or raise ``EmailNotConfigured`` with the reason."""
    prefs = get_setting(db, "notifications") or {}
    if not prefs.get("email_enabled"):
        raise EmailNotConfigured("Email notifications are turned off")
    missing = [k for k in ("smtp_host", "email_to", "smtp_from") if not str(prefs.get(k) or "").strip()]
    if missing:
        raise EmailNotConfigured("Missing email settings: " + ", ".join(missing))
    password = None
    if str(prefs.get("smtp_username") or "").strip():
        password = secrets.get_secret("smtp_password")
        if not password:
            raise EmailNotConfigured("An SMTP username is set but the smtp_password secret is not stored")
    return {**prefs, "password": password}


def _tz(name: str | None) -> ZoneInfo:
    try:
        return ZoneInfo(name or "UTC")
    except (ZoneInfoNotFoundError, ValueError):
        return ZoneInfo("UTC")


def _hhmm(value: Any, default: str) -> time:
    try:
        h, m = str(value or default).split(":")
        return time(int(h), int(m))
    except ValueError:
        h, m = default.split(":")
        return time(int(h), int(m))


def in_quiet_hours(prefs: dict[str, Any], t: datetime) -> bool:
    if not prefs.get("quiet_hours_enabled"):
        return False
    local = t.astimezone(_tz(prefs.get("timezone"))).time().replace(second=0, microsecond=0)
    start = _hhmm(prefs.get("quiet_start"), "22:00")
    end = _hhmm(prefs.get("quiet_end"), "07:00")
    if start == end:
        return False
    if start < end:
        return start <= local < end
    return local >= start or local < end  # wraps past midnight


def _recipients(value: str) -> list[str]:
    return [a.strip() for a in value.replace(";", ",").split(",") if a.strip()]


def _send(cfg: dict[str, Any], subject: str, body: str) -> None:
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = cfg["smtp_from"].strip()
    msg["To"] = ", ".join(_recipients(cfg["email_to"]))
    msg.set_content(body)
    server = smtp_class(cfg["smtp_host"].strip(), int(cfg.get("smtp_port") or 587), timeout=SMTP_TIMEOUT)
    try:
        if cfg.get("smtp_starttls", True):
            server.starttls(context=ssl.create_default_context())
        username = str(cfg.get("smtp_username") or "").strip()
        if username:
            server.login(username, cfg["password"])
        server.send_message(msg)
    finally:
        try:
            server.quit()
        except Exception as exc:
            log.debug("SMTP quit failed: %s", exc)


def _digest_body(items: list[Notification], t: datetime, tz: ZoneInfo) -> str:
    lines = [f"Sentinel: {len(items)} new notification(s).", ""]
    for n in items:
        when = n.created_at.astimezone(tz).strftime("%Y-%m-%d %H:%M %Z")
        lines.append(f"[{n.severity.upper()}] {n.title}")
        lines.append(f"    {when}" + (f"  ({n.link})" if n.link else ""))
        if n.body:
            lines.append("    " + n.body.strip().replace("\n", "\n    ")[:600])
        lines.append("")
    lines.append("Open Sentinel on this computer to see details. Links are paths in the Sentinel dashboard.")
    lines.append("This email was sent by your own Sentinel server. Nothing was changed on any device.")
    return "\n".join(lines)


def send_digest(db: Session, t: datetime | None = None) -> int:
    """Email unsent notifications from the last 24 hours as one message. Returns the number sent."""
    t = t or now()
    try:
        cfg = email_config(db)
    except EmailNotConfigured:
        return 0
    if in_quiet_hours(cfg, t):
        return 0  # held, not dropped: they are still unsent when quiet hours end
    items = list(db.execute(select(Notification).where(
        Notification.emailed_at.is_(None), Notification.suppressed_reason.is_(None),
        Notification.created_at >= t - DIGEST_WINDOW).order_by(Notification.created_at)
        .limit(DIGEST_MAX_ITEMS)).scalars())
    if not items:
        return 0
    worst = max(items, key=lambda n: SEV_ORDER.get(n.severity, 0))
    subject = (f"[Sentinel] {items[0].title}" if len(items) == 1
               else f"[Sentinel] {len(items)} notifications (highest: {worst.severity})")
    try:
        _send(cfg, subject[:200], _digest_body(items, t, _tz(cfg.get("timezone"))))
    except Exception as exc:  # network, TLS, auth: log and retry next tick
        log.warning("notification email failed; will retry next tick: %s", f"{type(exc).__name__}: {exc}"[:300])
        return 0
    for n in items:
        n.emailed_at = t
    db.flush()
    return len(items)


def tick(db: Session) -> None:
    send_digest(db)


# =========================================================================== hooks


def on_findings_created(db: Session, device: Device, findings: list[FindingRecord]) -> None:
    for f in findings:
        reopened = f.reopened_count > 0 and f.status == "reopened"
        prefix = "Reopened" if reopened else "New"
        notify(db, severity=f.severity, kind="finding", title=f"{prefix} {f.severity} finding on {device.name}: "
               f"{f.title}", body=f.impact[:1000], link=f"/vulnerabilities/{f.id}",
               dedupe_key=f"finding:{f.id}:{f.reopened_count}")


def on_scan_completed(db: Session, scan: Scan) -> None:
    if scan.status != "failed" or scan.reason == "scheduled":
        return  # scheduled scans are reported by the schedules module
    device = db.get(Device, scan.device_id)
    name = device.name if device else f"device {scan.device_id}"
    notify(db, severity="medium", kind="scan_failed", force=True,
           title=f"{scan.scan_type.title()} scan failed on {name}",
           body=scan.error or "The scan did not complete.", link=f"/scans/{scan.id}",
           dedupe_key=f"scan-failed:{scan.id}")


def register_hooks() -> None:
    hooks.register("findings_created", on_findings_created)
    hooks.register("scan_completed", on_scan_completed)


# =========================================================================== routes


@router.get("", response_model=list[NotificationOut])
def list_notifications(limit: int = Query(50, ge=1, le=500), unread_only: bool = False,
                       auth: AuthContext = Depends(current_auth), db: Session = Depends(get_db)) -> list[Notification]:
    q = select(Notification)
    if unread_only:
        q = q.where(Notification.read_at.is_(None))
    q = q.order_by(Notification.read_at.is_not(None), Notification.created_at.desc(), Notification.id.desc())
    return list(db.execute(q.limit(limit)).scalars())


@router.get("/unread-count", response_model=UnreadCount)
def unread_count(auth: AuthContext = Depends(current_auth), db: Session = Depends(get_db)) -> UnreadCount:
    rows = db.execute(select(Notification.severity, func.count()).where(Notification.read_at.is_(None))
                      .group_by(Notification.severity)).all()
    by = {s: n for s, n in rows}
    return UnreadCount(unread=sum(by.values()), by_severity=by)


@router.post("/{notification_id}/read", response_model=NotificationOut)
def mark_read(notification_id: int, auth: AuthContext = Depends(current_auth),
              db: Session = Depends(get_db)) -> Notification:
    n = db.get(Notification, notification_id)
    if n is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No such notification")
    if n.read_at is None:
        n.read_at = now()
        audit.record(db, auth.actor, "notification.read", "notification", n.id)
        db.commit()
    return n


@router.post("/read-all", response_model=ReadAllResult)
def mark_all_read(auth: AuthContext = Depends(current_auth), db: Session = Depends(get_db)) -> ReadAllResult:
    res = db.execute(update(Notification).where(Notification.read_at.is_(None)).values(read_at=now())
                     .execution_options(synchronize_session=False))
    marked = int(getattr(res, "rowcount", 0) or 0)
    audit.record(db, auth.actor, "notification.read_all", "notification", None, {"marked": marked})
    db.commit()
    return ReadAllResult(marked=marked)


@router.post("/test-email", response_model=TestEmailResult)
def test_email(auth: AuthContext = Depends(current_auth), db: Session = Depends(get_db)) -> TestEmailResult:
    """Send one test message now (ignores quiet hours). Reports the outcome; never the password."""
    try:
        cfg = email_config(db)
    except EmailNotConfigured as exc:
        audit.record(db, auth.actor, "notification.test_email", None, None, {"sent": False, "reason": str(exc)})
        db.commit()
        return TestEmailResult(sent=False, detail=str(exc))
    body = ("This is a test message from your Sentinel server. If you can read it, notification email works.\n"
            f"Sent at {now():%Y-%m-%d %H:%M} UTC.")
    try:
        _send(cfg, "[Sentinel] Test email", body)
        result = TestEmailResult(sent=True, detail=f"Sent to {', '.join(_recipients(cfg['email_to']))}")
    except Exception as exc:
        result = TestEmailResult(sent=False, detail=f"Sending failed: {type(exc).__name__}: {exc}"[:300])
    audit.record(db, auth.actor, "notification.test_email", None, None,
                 {"sent": result.sent, "host": cfg["smtp_host"]})
    db.commit()
    return result
