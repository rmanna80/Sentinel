"""Phase 2: scheduled scans, missed-run detection and failure notices.

A schedule is a wall-clock rule in an IANA time zone ("every Monday at 09:00 America/New_York").
``next_run_at`` is stored as aware UTC and recomputed from the local rule after every run, so daylight
saving changes never shift the local time. A local time that does not exist (spring forward) is moved
later by the length of the gap; an ambiguous one (fall back) runs once, at the first occurrence.

The background ``tick`` queues due scans through ``api.scans.queue_scan`` and then advances the schedule.
After downtime it queues at most one catch-up run, never a burst. A scheduled scan the agent has not
picked up within ``scheduled_scan_grace_minutes`` is cancelled and reported as missed.
"""

from __future__ import annotations

import logging
from datetime import UTC, date, datetime, time, timedelta
from typing import Any, Literal
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from fastapi import APIRouter, Depends, HTTPException, Response, status
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import audit
from ..api.scans import queue_scan
from ..config import get_settings
from ..db import get_db
from ..deps import AuthContext, current_auth
from ..models import Device, Scan, Schedule, now
from ..schemas import ScanOut
from ..services import hooks
from ..services.notify import notify

log = logging.getLogger(__name__)

router = APIRouter(prefix="/api/schedules", tags=["schedules"])

DEFAULT_TZ = "America/New_York"
ACTIVE_SCAN = ("queued", "running")
MISSED_ERROR = "The agent did not pick up this scheduled scan (was it running?)"
SCAN_TYPES = ("full", "posture", "inventory", "logs")

Frequency = Literal["hourly", "daily", "weekly", "monthly"]
ScanTypeLit = Literal["full", "posture", "inventory", "logs"]
HHMM = r"^([01]\d|2[0-3]):[0-5]\d$"


# =========================================================================== next-run math


def _zone(name: str) -> ZoneInfo:
    try:
        return ZoneInfo(name)
    except (ZoneInfoNotFoundError, ValueError) as exc:
        raise ValueError(f"Unknown time zone: {name}") from exc


def _wall_to_utc(day: date, hhmm: time, tz: ZoneInfo) -> datetime:
    """Local wall-clock time to aware UTC (PEP 495, fold=0).

    An ambiguous time (fall back) resolves to its first occurrence. A nonexistent time (spring forward)
    resolves with the pre-transition offset, i.e. it is moved later by the length of the gap
    (02:30 on a 1-hour spring-forward day runs at 03:30).
    """
    return datetime.combine(day, hhmm, tzinfo=tz).astimezone(UTC)


def _parse_hhmm(value: str) -> time:
    h, m = value.split(":")
    return time(int(h), int(m))


def compute_next_run(frequency: str, time_of_day: str, tz_name: str, after: datetime, *,
                     day_of_week: int | None = None, day_of_month: int | None = None) -> datetime:
    """The first run strictly after ``after`` (aware), as aware UTC."""
    tz = _zone(tz_name)
    at = _parse_hhmm(time_of_day or "00:00")
    after = after.astimezone(UTC)
    local_after = after.astimezone(tz)

    if frequency == "hourly":
        # Every real hour at the configured local minute. Walking real instants means a DST change
        # neither skips nor doubles a run, and zones with 30/45-minute offsets still get the local minute.
        start = after.replace(second=0, microsecond=0) + timedelta(minutes=1)
        for i in range(24 * 60):
            candidate = start + timedelta(minutes=i)
            if candidate.astimezone(tz).minute == at.minute:
                return candidate
        raise ValueError("could not compute the next run")  # pragma: no cover

    day = local_after.date() - timedelta(days=1)  # start a day early; the loop finds the first one after
    for _ in range(800):
        if frequency == "daily":
            ok = True
        elif frequency == "weekly":
            ok = day.weekday() == (day_of_week if day_of_week is not None else 0)
        elif frequency == "monthly":
            ok = day.day == (day_of_month or 1)
        else:
            raise ValueError(f"Unknown frequency: {frequency}")
        if ok:
            run = _wall_to_utc(day, at, tz)
            if run > after:
                return run
        day += timedelta(days=1)
    raise ValueError("could not compute the next run")  # pragma: no cover


def next_run_for(s: Schedule, after: datetime) -> datetime:
    return compute_next_run(s.frequency, s.time_of_day, s.timezone, after, day_of_week=s.day_of_week,
                            day_of_month=s.day_of_month)


# =========================================================================== schemas


class ScheduleBase(BaseModel):
    @field_validator("timezone", check_fields=False)
    @classmethod
    def _tz(cls, v: str | None) -> str | None:
        if v is None:
            return v
        try:
            _zone(v)
        except ValueError as exc:
            raise ValueError(str(exc)) from exc
        return v


class ScheduleCreate(ScheduleBase):
    name: str = Field(min_length=1, max_length=128)
    device_id: int
    scan_type: ScanTypeLit = "full"
    frequency: Frequency = "daily"
    time_of_day: str = Field(default="09:00", pattern=HHMM)
    day_of_week: int | None = Field(default=None, ge=0, le=6)
    day_of_month: int | None = Field(default=None, ge=1, le=28)
    timezone: str = Field(default=DEFAULT_TZ, max_length=64)
    enabled: bool = True

    @model_validator(mode="after")
    def _days(self) -> ScheduleCreate:
        _check_days(self.frequency, self.day_of_week, self.day_of_month)
        return self


class ScheduleUpdate(ScheduleBase):
    name: str | None = Field(default=None, min_length=1, max_length=128)
    device_id: int | None = None
    scan_type: ScanTypeLit | None = None
    frequency: Frequency | None = None
    time_of_day: str | None = Field(default=None, pattern=HHMM)
    day_of_week: int | None = Field(default=None, ge=0, le=6)
    day_of_month: int | None = Field(default=None, ge=1, le=28)
    timezone: str | None = Field(default=None, max_length=64)
    enabled: bool | None = None


def _check_days(frequency: str, day_of_week: int | None, day_of_month: int | None) -> None:
    if frequency == "weekly" and day_of_week is None:
        raise ValueError("A weekly schedule needs day_of_week (0 = Monday ... 6 = Sunday)")
    if frequency == "monthly" and day_of_month is None:
        raise ValueError("A monthly schedule needs day_of_month (1 to 28)")


class ScheduleOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    device_id: int
    device_name: str | None = None
    scan_type: str
    frequency: str
    time_of_day: str
    day_of_week: int | None
    day_of_month: int | None
    timezone: str
    enabled: bool
    next_run_at: datetime | None
    last_run_at: datetime | None
    last_scan_id: int | None
    last_scan_status: str | None = None
    consecutive_failures: int
    created_at: datetime


# =========================================================================== helpers


def _out(db: Session, s: Schedule) -> ScheduleOut:
    out = ScheduleOut.model_validate(s)
    device = db.get(Device, s.device_id)
    out.device_name = device.name if device else None
    if s.last_scan_id is not None and (scan := db.get(Scan, s.last_scan_id)) is not None:
        out.last_scan_status = scan.status
    return out


def _get(db: Session, schedule_id: int) -> Schedule:
    s = db.get(Schedule, schedule_id)
    if s is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No such schedule")
    return s


def _device(db: Session, device_id: int) -> Device:
    device = db.get(Device, device_id)
    if device is None or not device.is_active:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No such device")
    return device


def _active_scan(db: Session, s: Schedule) -> Scan | None:
    return db.execute(select(Scan).where(Scan.schedule_id == s.id, Scan.status.in_(ACTIVE_SCAN))
                      .order_by(Scan.requested_at.desc()).limit(1)).scalar_one_or_none()


def _queue(db: Session, s: Schedule, device: Device, actor: str, user_id: int | None, t: datetime) -> Scan:
    scan = queue_scan(db, device=device, scan_type=s.scan_type, actor=actor, user_id=user_id, reason="scheduled",
                      schedule_id=s.id)
    s.last_run_at = t
    s.last_scan_id = scan.id
    return scan


def _describe(s: Schedule) -> dict[str, Any]:
    return {"name": s.name, "device_id": s.device_id, "scan_type": s.scan_type, "frequency": s.frequency,
            "time_of_day": s.time_of_day, "day_of_week": s.day_of_week, "day_of_month": s.day_of_month,
            "timezone": s.timezone, "enabled": s.enabled}


# =========================================================================== routes


@router.get("", response_model=list[ScheduleOut])
def list_schedules(device_id: int | None = None, auth: AuthContext = Depends(current_auth),
                   db: Session = Depends(get_db)) -> list[ScheduleOut]:
    q = select(Schedule)
    if device_id is not None:
        q = q.where(Schedule.device_id == device_id)
    rows = db.execute(q.order_by(Schedule.next_run_at.is_(None), Schedule.next_run_at, Schedule.id)).scalars()
    return [_out(db, s) for s in rows]


@router.post("", response_model=ScheduleOut, status_code=201)
def create_schedule(body: ScheduleCreate, auth: AuthContext = Depends(current_auth),
                    db: Session = Depends(get_db)) -> ScheduleOut:
    _device(db, body.device_id)
    s = Schedule(name=body.name.strip(), device_id=body.device_id, scan_type=body.scan_type,
                 frequency=body.frequency, time_of_day=body.time_of_day,
                 day_of_week=body.day_of_week if body.frequency == "weekly" else None,
                 day_of_month=body.day_of_month if body.frequency == "monthly" else None,
                 timezone=body.timezone, enabled=body.enabled, created_by=auth.user.id, consecutive_failures=0)
    s.next_run_at = next_run_for(s, now()) if s.enabled else None
    db.add(s)
    db.flush()
    audit.record(db, auth.actor, "schedule.created", "schedule", s.id, _describe(s))
    db.commit()
    return _out(db, s)


@router.get("/{schedule_id}", response_model=ScheduleOut)
def get_schedule(schedule_id: int, auth: AuthContext = Depends(current_auth),
                 db: Session = Depends(get_db)) -> ScheduleOut:
    return _out(db, _get(db, schedule_id))


@router.patch("/{schedule_id}", response_model=ScheduleOut)
def update_schedule(schedule_id: int, body: ScheduleUpdate, auth: AuthContext = Depends(current_auth),
                    db: Session = Depends(get_db)) -> ScheduleOut:
    s = _get(db, schedule_id)
    before = _describe(s)
    fields = {f for f in body.model_fields_set if getattr(body, f) is not None or f in ("day_of_week", "day_of_month")}
    if "device_id" in fields:
        _device(db, body.device_id)  # type: ignore[arg-type]
    for f in fields:
        value = getattr(body, f)
        setattr(s, f, value.strip() if f == "name" else value)
    try:
        _check_days(s.frequency, s.day_of_week, s.day_of_month)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    if s.frequency != "weekly":
        s.day_of_week = None
    if s.frequency != "monthly":
        s.day_of_month = None
    if fields & {"frequency", "time_of_day", "day_of_week", "day_of_month", "timezone", "enabled"}:
        s.next_run_at = next_run_for(s, now()) if s.enabled else None
    if "enabled" in fields and s.enabled:
        s.consecutive_failures = 0
    after = _describe(s)
    audit.record(db, auth.actor, "schedule.updated", "schedule", s.id,
                 {k: {"from": before[k], "to": after[k]} for k in after if before[k] != after[k]})
    db.commit()
    return _out(db, s)


@router.delete("/{schedule_id}", status_code=204)
def delete_schedule(schedule_id: int, auth: AuthContext = Depends(current_auth),
                    db: Session = Depends(get_db)) -> Response:
    s = _get(db, schedule_id)
    detail = _describe(s)
    db.delete(s)
    audit.record(db, auth.actor, "schedule.deleted", "schedule", schedule_id, detail)
    db.commit()
    return Response(status_code=204)


@router.post("/{schedule_id}/run-now", response_model=ScanOut, status_code=201)
def run_now(schedule_id: int, auth: AuthContext = Depends(current_auth), db: Session = Depends(get_db)) -> Scan:
    """Queue this schedule's scan immediately. The regular timetable is unchanged."""
    s = _get(db, schedule_id)
    device = _device(db, s.device_id)
    if (active := _active_scan(db, s)) is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, f"This schedule's scan {active.id} is still {active.status}")
    scan = _queue(db, s, device, auth.actor, auth.user.id, now())
    audit.record(db, auth.actor, "schedule.run_now", "schedule", s.id, {"scan_id": scan.id})
    db.commit()
    return scan


# =========================================================================== background


def detect_missed(db: Session, t: datetime) -> int:
    """Scheduled scans still queued after the grace period are cancelled and reported."""
    grace = timedelta(minutes=get_settings().scheduled_scan_grace_minutes)
    missed = 0
    for scan in db.execute(select(Scan).where(Scan.status == "queued", Scan.reason == "scheduled",
                                              Scan.requested_at <= t - grace)).scalars().all():
        scan.status = "cancelled"
        scan.error = MISSED_ERROR
        scan.completed_at = t
        schedule = db.get(Schedule, scan.schedule_id) if scan.schedule_id is not None else None
        device = db.get(Device, scan.device_id)
        device_name = device.name if device else f"device {scan.device_id}"
        if schedule is not None:
            schedule.consecutive_failures += 1
        audit.record(db, "system", "schedule.missed", "scan", scan.id,
                     {"schedule_id": scan.schedule_id, "device_id": scan.device_id})
        name = schedule.name if schedule is not None else "Scheduled scan"
        notify(db, severity="medium", kind="schedule_missed", force=True,
               title=f"Scheduled scan missed: {name} on {device_name}",
               body=(f"{MISSED_ERROR} It was queued at {scan.requested_at:%Y-%m-%d %H:%M} UTC and not picked up "
                     f"within {int(grace.total_seconds() // 60)} minutes."),
               link=f"/scans/{scan.id}", dedupe_key=f"schedule-missed:{scan.id}")
        missed += 1
    return missed


def run_due(db: Session, t: datetime) -> int:
    queued = 0
    due = db.execute(select(Schedule).where(Schedule.enabled.is_(True), Schedule.next_run_at.is_not(None),
                                            Schedule.next_run_at <= t).order_by(Schedule.next_run_at)).scalars().all()
    for s in due:
        device = db.get(Device, s.device_id)
        if device is None or not device.is_active:
            log.info("schedule %s skipped: device %s is not active", s.id, s.device_id)
            audit.record(db, "system", "schedule.skipped", "schedule", s.id, {"reason": "device not active"})
        elif (active := _active_scan(db, s)) is not None:
            log.info("schedule %s skipped: scan %s is still %s", s.id, active.id, active.status)
            audit.record(db, "system", "schedule.skipped", "schedule", s.id,
                         {"reason": f"previous scan still {active.status}", "scan_id": active.id})
        else:
            _queue(db, s, device, "system", None, t)
            queued += 1
        # Advance from now, not from the missed slot: one catch-up run at most after downtime.
        s.next_run_at = next_run_for(s, t)
    return queued


def tick(db: Session) -> None:
    t = now()
    detect_missed(db, t)
    run_due(db, t)


def on_scan_completed(db: Session, scan: Scan) -> None:
    if scan.reason != "scheduled" or scan.schedule_id is None:
        return
    s = db.get(Schedule, scan.schedule_id)
    if s is None:
        return
    if scan.status == "failed":
        s.consecutive_failures += 1
        device = db.get(Device, scan.device_id)
        device_name = device.name if device else f"device {scan.device_id}"
        notify(db, severity="medium", kind="scan_failed", force=True,
               title=f"Scheduled scan failed: {s.name} on {device_name}",
               body=(scan.error or "The scan did not complete.")
               + (f" This schedule has failed {s.consecutive_failures} times in a row."
                  if s.consecutive_failures > 1 else ""),
               link=f"/scans/{scan.id}", dedupe_key=f"scan-failed:{scan.id}")
    elif scan.status in ("completed", "partial"):
        s.consecutive_failures = 0


def register_hooks() -> None:
    hooks.register("scan_completed", on_scan_completed)
