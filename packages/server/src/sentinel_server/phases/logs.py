"""Phase 2: search and statistics over normalized log events, and retention of logs and metrics.

Log events are written by ``services.ingest`` from agent uploads (already redacted there). This module
only reads them, except for retention, which deletes events and metric samples older than the
``retention`` app settings. Alert links cascade with the events they point to.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict
from sqlalchemy import delete, func, or_, select
from sqlalchemy.orm import Session

from ..db import get_db
from ..deps import AuthContext, current_auth
from ..models import Alert, AlertEventLink, Device, LogEventRecord, MetricSampleRecord, now
from ..services.app_settings import get_setting

log = logging.getLogger(__name__)

router = APIRouter(prefix="/api/logs", tags=["logs"])

SEVERITIES = ("info", "low", "medium", "high", "critical")
LOGON_SUCCESS = ("logon_success", "ssh_success")
LOGON_FAILURE = ("logon_failed", "ssh_failed")
RETENTION_EVERY = timedelta(minutes=10)

_last_retention: dict[str, datetime] = {}  # per database URL


# --------------------------------------------------------------------------- schemas


class LogEventOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    device_id: int
    source: str
    record_id: str
    event_id: str | None
    occurred_at: datetime
    category: str
    action: str
    outcome: str | None
    severity: str
    user: str | None
    source_ip: str | None
    process: str | None
    message: str
    ingested_at: datetime
    scan_id: int | None


class LinkedAlert(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    rule_id: str
    title: str
    severity: str
    status: str
    incident_id: int | None


class LogEventDetail(LogEventOut):
    data: dict[str, Any]
    device_name: str | None
    alerts: list[LinkedAlert]


class LogPage(BaseModel):
    items: list[LogEventOut]
    total: int


class DayLogons(BaseModel):
    date: str
    success: int
    failure: int


class DayEvents(BaseModel):
    date: str
    info: int
    low: int
    medium: int
    high: int
    critical: int


class ActionCount(BaseModel):
    action: str
    count: int


class DeviceCount(BaseModel):
    device_id: int
    device_name: str | None
    count: int


class RepeatedPattern(BaseModel):
    action: str
    user: str | None
    source_ip: str | None
    count: int


class LogStats(BaseModel):
    days: int
    since: datetime
    device_id: int | None
    total_events: int
    logons_by_day: list[DayLogons]
    events_by_day: list[DayEvents]
    alerts_by_severity: dict[str, int]
    top_actions: list[ActionCount]
    events_by_device: list[DeviceCount]
    repeated_patterns: list[RepeatedPattern]


# --------------------------------------------------------------------------- helpers


def _aware(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    return dt.replace(tzinfo=UTC) if dt.tzinfo is None else dt.astimezone(UTC)


def _like(q: str) -> str:
    escaped = q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{escaped}%"


def _day(value: Any) -> str:
    # SQLite returns 'YYYY-MM-DD' strings, PostgreSQL returns date objects
    return str(value)[:10]


# --------------------------------------------------------------------------- routes


@router.get("", response_model=LogPage)
def search_logs(
    device_id: int | None = None,
    severity: list[str] | None = Query(None),
    category: str | None = Query(None, max_length=64),
    action: list[str] | None = Query(None),
    source: str | None = Query(None, max_length=128),
    since: datetime | None = None,
    until: datetime | None = None,
    q: str | None = Query(None, max_length=200, description="Keyword in message, user, source IP or process"),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    auth: AuthContext = Depends(current_auth),
    db: Session = Depends(get_db),
) -> LogPage:
    stmt = select(LogEventRecord)
    if device_id is not None:
        stmt = stmt.where(LogEventRecord.device_id == device_id)
    if severity:
        stmt = stmt.where(LogEventRecord.severity.in_(severity))
    if category:
        stmt = stmt.where(LogEventRecord.category == category)
    if action:
        stmt = stmt.where(LogEventRecord.action.in_(action))
    if source:
        stmt = stmt.where(LogEventRecord.source == source)
    if since is not None:
        stmt = stmt.where(LogEventRecord.occurred_at >= _aware(since))
    if until is not None:
        stmt = stmt.where(LogEventRecord.occurred_at <= _aware(until))
    if q:
        like = _like(q)
        stmt = stmt.where(or_(LogEventRecord.message.ilike(like, escape="\\"),
                              LogEventRecord.user.ilike(like, escape="\\"),
                              LogEventRecord.source_ip.ilike(like, escape="\\"),
                              LogEventRecord.process.ilike(like, escape="\\")))
    total = db.execute(select(func.count()).select_from(stmt.subquery())).scalar_one()
    rows = db.execute(stmt.order_by(LogEventRecord.occurred_at.desc(), LogEventRecord.id.desc())
                      .limit(limit).offset(offset)).scalars().all()
    return LogPage(items=[LogEventOut.model_validate(r) for r in rows], total=total)


@router.get("/stats", response_model=LogStats)
def log_stats(days: int = Query(7, ge=1, le=365), device_id: int | None = None,
              auth: AuthContext = Depends(current_auth), db: Session = Depends(get_db)) -> LogStats:
    """Counts over the last ``days`` UTC calendar days, today included."""
    today = now().date()
    first_day = today - timedelta(days=days - 1)
    since = datetime(first_day.year, first_day.month, first_day.day, tzinfo=UTC)
    dates = [(first_day + timedelta(days=i)).isoformat() for i in range(days)]

    conds = [LogEventRecord.occurred_at >= since]
    if device_id is not None:
        conds.append(LogEventRecord.device_id == device_id)
    day = func.date(LogEventRecord.occurred_at)

    logons = {d: {"success": 0, "failure": 0} for d in dates}
    for d, act, n in db.execute(
        select(day, LogEventRecord.action, func.count())
        .where(*conds, LogEventRecord.action.in_(LOGON_SUCCESS + LOGON_FAILURE))
        .group_by(day, LogEventRecord.action)
    ).all():
        key = _day(d)
        if key in logons:
            logons[key]["success" if act in LOGON_SUCCESS else "failure"] += n

    by_sev = {d: dict.fromkeys(SEVERITIES, 0) for d in dates}
    total = 0
    for d, sev, n in db.execute(
        select(day, LogEventRecord.severity, func.count()).where(*conds).group_by(day, LogEventRecord.severity)
    ).all():
        total += n
        key = _day(d)
        if key in by_sev and sev in by_sev[key]:
            by_sev[key][sev] += n

    alert_q = select(Alert.severity, func.count()).where(Alert.last_event_at >= since)
    if device_id is not None:
        alert_q = alert_q.where(Alert.device_id == device_id)
    alerts = dict.fromkeys(SEVERITIES, 0)
    for sev, n in db.execute(alert_q.group_by(Alert.severity)).all():
        alerts[sev] = alerts.get(sev, 0) + n

    cnt = func.count().label("n")
    top_actions = [ActionCount(action=a, count=n) for a, n in db.execute(
        select(LogEventRecord.action, cnt).where(*conds).group_by(LogEventRecord.action)
        .order_by(cnt.desc(), LogEventRecord.action).limit(10)).all()]

    per_device = db.execute(select(LogEventRecord.device_id, cnt).where(*conds).group_by(LogEventRecord.device_id)
                            .order_by(cnt.desc())).all()
    names = {d.id: d.name for d in db.execute(
        select(Device).where(Device.id.in_([r[0] for r in per_device]))).scalars()} if per_device else {}
    events_by_device = [DeviceCount(device_id=i, device_name=names.get(i), count=n) for i, n in per_device]

    patterns = [RepeatedPattern(action=a, user=u, source_ip=ip, count=n) for a, u, ip, n in db.execute(
        select(LogEventRecord.action, LogEventRecord.user, LogEventRecord.source_ip, cnt).where(*conds)
        .group_by(LogEventRecord.action, LogEventRecord.user, LogEventRecord.source_ip)
        .having(func.count() >= 2).order_by(cnt.desc(), LogEventRecord.action).limit(10)).all()]

    return LogStats(
        days=days, since=since, device_id=device_id, total_events=total,
        logons_by_day=[DayLogons(date=d, **logons[d]) for d in dates],
        events_by_day=[DayEvents(date=d, **by_sev[d]) for d in dates],
        alerts_by_severity=alerts, top_actions=top_actions, events_by_device=events_by_device,
        repeated_patterns=patterns,
    )


@router.get("/{event_id}", response_model=LogEventDetail)
def get_log_event(event_id: int, auth: AuthContext = Depends(current_auth),
                  db: Session = Depends(get_db)) -> LogEventDetail:
    ev = db.get(LogEventRecord, event_id)
    if ev is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No such log event")
    device = db.get(Device, ev.device_id)
    alerts = db.execute(select(Alert).join(AlertEventLink, AlertEventLink.alert_id == Alert.id)
                        .where(AlertEventLink.log_event_id == ev.id).order_by(Alert.id)).scalars().all()
    data = LogEventOut.model_validate(ev).model_dump()
    return LogEventDetail(**data, data=ev.data or {}, device_name=device.name if device else None,
                          alerts=[LinkedAlert.model_validate(a) for a in alerts])


# --------------------------------------------------------------------------- retention


def _days(value: Any) -> int | None:
    try:
        n = int(value)
    except (TypeError, ValueError):
        return None
    return n if n > 0 else None  # 0 or empty means keep forever


def apply_retention(db: Session, now_: datetime | None = None) -> dict[str, int]:
    """Delete log events and metric samples older than the configured number of days."""
    t = now_ or now()
    settings = get_setting(db, "retention") or {}
    removed = {"log_events": 0, "metric_samples": 0}
    log_days = _days(settings.get("log_event_days"))
    if log_days:
        cutoff = t - timedelta(days=log_days)
        # per-device probes use the (device_id, occurred_at) index, so an idle run stays cheap
        for device_id in db.execute(select(Device.id)).scalars().all():
            old = (LogEventRecord.device_id == device_id, LogEventRecord.occurred_at < cutoff)
            if db.execute(select(LogEventRecord.id).where(*old).limit(1)).first():
                res = db.execute(delete(LogEventRecord).where(*old).execution_options(synchronize_session=False))
                removed["log_events"] += int(getattr(res, "rowcount", 0) or 0)
    metric_days = _days(settings.get("metric_days"))
    if metric_days:
        cutoff = t - timedelta(days=metric_days)
        if db.execute(select(MetricSampleRecord.id).where(MetricSampleRecord.ts < cutoff).limit(1)).first():
            res = db.execute(delete(MetricSampleRecord).where(MetricSampleRecord.ts < cutoff)
                             .execution_options(synchronize_session=False))
            removed["metric_samples"] = int(getattr(res, "rowcount", 0) or 0)
    if removed["log_events"] or removed["metric_samples"]:
        log.info("retention removed %s", removed)
    return removed


def tick(db: Session) -> None:
    """Retention runs at most every few minutes; the existence checks keep an idle run cheap."""
    key = str(getattr(db.get_bind(), "url", "default"))
    t = now()
    last = _last_retention.get(key)
    if last is not None and t - last < RETENTION_EVERY:
        return
    _last_retention[key] = t
    apply_retention(db, t)
