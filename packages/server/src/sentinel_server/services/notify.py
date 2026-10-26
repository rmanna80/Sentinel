"""Create in-app notifications with dedupe and a severity threshold.

Delivery (email, quiet hours) is handled by the notifications phase module, which sends
rows whose ``emailed_at`` is empty. Any module may call ``notify``.
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import Notification
from .app_settings import get_setting

_ORDER = ["info", "low", "medium", "high", "critical"]


def meets_threshold(severity: str, minimum: str) -> bool:
    try:
        return _ORDER.index(severity) >= _ORDER.index(minimum)
    except ValueError:
        return True


def notify(
    db: Session,
    *,
    severity: str,
    kind: str,
    title: str,
    body: str = "",
    link: str | None = None,
    dedupe_key: str | None = None,
    force: bool = False,
) -> Notification | None:
    """Insert a notification unless an identical one (same dedupe key) already exists.

    Notifications under the configured minimum severity are not created, except system
    notices passed with ``force=True`` (for example a scheduled scan that never ran).
    """
    prefs = get_setting(db, "notifications")
    if not force and not meets_threshold(severity, prefs.get("min_severity", "high")):
        return None
    if dedupe_key:
        existing = db.execute(select(Notification).where(Notification.dedupe_key == dedupe_key)).scalar_one_or_none()
        if existing is not None:
            return None
    n = Notification(severity=severity, kind=kind, title=title[:300], body=body, link=link, dedupe_key=dedupe_key)
    db.add(n)
    db.flush()
    return n
