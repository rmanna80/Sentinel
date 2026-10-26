"""Phase 6: analytics over stored data, and findings export.

Every metric is computed from what is stored. When a metric cannot be computed (nothing was
collected for it), it is returned as null and listed in ``unavailable`` with the reason; it is
never estimated or filled in.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import date, datetime, timedelta
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .. import audit
from ..db import get_db
from ..deps import AuthContext, current_auth
from ..models import (
    Alert,
    Device,
    EmailCheck,
    EmailIdentity,
    FindingRecord,
    LogEventRecord,
    MetricSampleRecord,
    RemediationTask,
    Scan,
    SoftwareRecord,
    now,
)
from ..services.findings import OPEN
from ..services.report_builder import FINDING_COLUMNS, finding_rows, render_json, write_csv
from ..services.scoring import POSTURE_SCAN_TYPES

router = APIRouter(prefix="/api", tags=["analytics"])

SEVERITIES = ["critical", "high", "medium", "low", "info"]
SEV_RANK = {s: i for i, s in enumerate(reversed(SEVERITIES))}
FINISHED = ("completed", "partial", "failed", "cancelled")


# =========================================================================== schemas


class AnalyticsFilters(BaseModel):
    days: int
    since: datetime
    until: datetime
    device_id: int | None
    device_ids: list[int]
    severity: list[str] | None
    category: str | None
    notes: list[str]


class ScoreHistoryPoint(BaseModel):
    ts: datetime
    scan_id: int
    device_id: int
    score: int | None
    raw_score: int | None
    coverage: float | None


class SoftwareCount(BaseModel):
    name: str
    count: int


class DeviceFindings(BaseModel):
    device_id: int
    name: str
    open: int
    by_severity: dict[str, int]


class WeekNewResolved(BaseModel):
    week_start: date
    new: int
    resolved: int


class AlertDay(BaseModel):
    date: date
    total: int
    critical: int
    high: int
    medium: int
    low: int
    info: int


class EmailExposurePoint(BaseModel):
    checked_at: datetime
    identity_id: int
    status: str
    breach_count: int | None


class ScanWeek(BaseModel):
    week_start: date
    completed: int
    partial: int
    failed: int
    cancelled: int


class HealthDay(BaseModel):
    date: date
    cpu_avg: float | None
    memory_avg: float | None
    disk_max: float | None


class TaskCounts(BaseModel):
    open: int
    overdue: int


class RepeatedMisconfiguration(BaseModel):
    rule_id: str
    title: str
    reopened_total: int
    devices: int


class Analytics(BaseModel):
    filters: AnalyticsFilters
    score_history: list[ScoreHistoryPoint] | None
    vulns_by_severity: dict[str, int] | None = Field(
        description="Open findings (check findings and matched vulnerabilities) by severity")
    vulns_by_category: dict[str, int] | None = Field(description="Open findings by category")
    top_affected_software: list[SoftwareCount] | None
    findings_by_device: list[DeviceFindings] | None
    new_vs_resolved_by_week: list[WeekNewResolved] | None
    alerts_over_time: list[AlertDay] | None
    email_exposure_history: list[EmailExposurePoint] | None
    scan_outcomes: list[ScanWeek] | None
    success_rate: float | None = Field(description="Completed scans / finished scans in the period")
    health_history: list[HealthDay] | None
    mean_time_to_remediate_days: float | None
    mean_time_to_remediate_count: int = Field(description="How many verified resolutions the mean is based on")
    outstanding_tasks: TaskCounts
    repeated_misconfigurations: list[RepeatedMisconfiguration] | None
    unavailable: dict[str, str]


# =========================================================================== helpers


def week_start(d: datetime | date) -> date:
    day = d.date() if isinstance(d, datetime) else d
    return day - timedelta(days=day.weekday())


def _as_date(value: Any) -> date:
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, date):
        return value
    return date.fromisoformat(str(value)[:10])


def _weeks(since: datetime, until: datetime) -> list[date]:
    out, w = [], week_start(since)
    end = week_start(until)
    while w <= end:
        out.append(w)
        w += timedelta(days=7)
    return out


def _days(since: datetime, until: datetime) -> list[date]:
    out, d = [], since.date()
    while d <= until.date():
        out.append(d)
        d += timedelta(days=1)
    return out


def _check_severities(severity: list[str] | None) -> list[str] | None:
    if not severity:
        return None
    bad = [s for s in severity if s not in SEVERITIES]
    if bad:
        raise HTTPException(422, f"Unknown severity: {bad}. Use {SEVERITIES}.")
    return severity


def _scope(db: Session, device_id: int | None) -> list[int]:
    if device_id is not None:
        if db.get(Device, device_id) is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "No such device")
        return [device_id]
    return list(db.execute(select(Device.id).where(Device.is_active.is_(True)).order_by(Device.id)).scalars())


# =========================================================================== analytics


@router.get("/analytics", response_model=Analytics)
def analytics(
    days: int = Query(30, ge=1, le=365),
    device_id: int | None = None,
    severity: list[str] | None = Query(None, description="Limit finding and alert metrics to these severities"),
    category: str | None = Query(None, max_length=64, description="Limit finding metrics to this category"),
    auth: AuthContext = Depends(current_auth),
    db: Session = Depends(get_db),
) -> Analytics:
    sevs = _check_severities(severity)
    ids = _scope(db, device_id)
    until = now()
    since = until - timedelta(days=days)
    today = until.date()
    unavailable: dict[str, str] = {}
    names = dict(db.execute(select(Device.id, Device.name).where(Device.id.in_(ids))).all())

    def finding_filter(q: Any) -> Any:
        q = q.where(FindingRecord.device_id.in_(ids))
        if sevs:
            q = q.where(FindingRecord.severity.in_(sevs))
        if category:
            q = q.where(FindingRecord.category == category)
        return q

    scanned = db.execute(select(func.count(Scan.id)).where(
        Scan.device_id.in_(ids), Scan.status.in_(("completed", "partial")))).scalar_one()
    no_scan_reason = ("No devices are in scope." if not ids
                      else "No scan has completed for the devices in scope, so there are no findings to count.")

    # ---- score history
    score_history: list[ScoreHistoryPoint] | None = [
        ScoreHistoryPoint(ts=s.completed_at, scan_id=s.id, device_id=s.device_id, score=s.score,
                          raw_score=(s.summary or {}).get("raw_score"), coverage=s.coverage)
        for s in db.execute(select(Scan).where(
            Scan.device_id.in_(ids), Scan.completed_at.is_not(None), Scan.completed_at >= since,
            Scan.scan_type.in_(POSTURE_SCAN_TYPES), Scan.status.in_(("completed", "partial")),
        ).order_by(Scan.completed_at, Scan.id)).scalars()
        if s.completed_at is not None
    ]
    if not score_history:
        score_history = None
        unavailable["score_history"] = "No full or posture scan completed in this period."

    # ---- open findings
    vulns_by_severity: dict[str, int] | None = None
    vulns_by_category: dict[str, int] | None = None
    findings_by_device: list[DeviceFindings] | None = None
    repeated: list[RepeatedMisconfiguration] | None = None
    new_vs_resolved: list[WeekNewResolved] | None = None
    if scanned:
        open_rows = db.execute(finding_filter(
            select(FindingRecord.device_id, FindingRecord.severity, FindingRecord.category)
            .where(FindingRecord.status.in_(OPEN)))).all()
        vulns_by_severity = {s: 0 for s in SEVERITIES}
        cats: dict[str, int] = defaultdict(int)
        per_dev: dict[int, dict[str, int]] = {i: {s: 0 for s in SEVERITIES} for i in ids}
        for dev, sev, cat in open_rows:
            vulns_by_severity[sev] = vulns_by_severity.get(sev, 0) + 1
            cats[cat] += 1
            per_dev.setdefault(dev, {s: 0 for s in SEVERITIES})[sev] = per_dev[dev].get(sev, 0) + 1
        vulns_by_category = dict(sorted(cats.items(), key=lambda kv: (-kv[1], kv[0])))
        findings_by_device = sorted(
            (DeviceFindings(device_id=d, name=names.get(d, str(d)), open=sum(c.values()), by_severity=c)
             for d, c in per_dev.items()),
            key=lambda x: (-x.open, x.name))

        rep: dict[str, dict[str, Any]] = {}
        for f in db.execute(finding_filter(select(FindingRecord).where(FindingRecord.reopened_count > 0))).scalars():
            r = rep.setdefault(f.rule_id, {"rule_id": f.rule_id, "title": f.title, "reopened_total": 0, "devices": set()})
            r["reopened_total"] += f.reopened_count
            r["devices"].add(f.device_id)
        repeated = [RepeatedMisconfiguration(rule_id=r["rule_id"], title=r["title"], reopened_total=r["reopened_total"],
                                             devices=len(r["devices"]))
                    for r in sorted(rep.values(), key=lambda r: (-r["reopened_total"], r["rule_id"]))][:20]

        weeks = {w: [0, 0] for w in _weeks(since, until)}
        for (ts,) in db.execute(finding_filter(select(FindingRecord.first_seen_at)
                                               .where(FindingRecord.first_seen_at >= since))).all():
            weeks.setdefault(week_start(ts), [0, 0])[0] += 1
        for (ts,) in db.execute(finding_filter(select(FindingRecord.verified_resolved_at)
                                               .where(FindingRecord.verified_resolved_at >= since))).all():
            weeks.setdefault(week_start(ts), [0, 0])[1] += 1
        new_vs_resolved = [WeekNewResolved(week_start=w, new=n, resolved=r) for w, (n, r) in sorted(weeks.items())]
    else:
        for k in ("vulns_by_severity", "vulns_by_category", "findings_by_device", "repeated_misconfigurations",
                  "new_vs_resolved_by_week"):
            unavailable[k] = no_scan_reason

    # ---- top affected software
    top_software: list[SoftwareCount] | None = None
    sw_total = db.execute(select(func.count(SoftwareRecord.id)).where(SoftwareRecord.device_id.in_(ids))).scalar_one()
    sw_matched = db.execute(select(func.count(SoftwareRecord.id)).where(
        SoftwareRecord.device_id.in_(ids), SoftwareRecord.match_status.in_(("matched", "no_source")))).scalar_one()
    if not sw_total:
        unavailable["top_affected_software"] = ("No software inventory has been collected; run an inventory or full "
                                                "scan.")
    elif not sw_matched:
        unavailable["top_affected_software"] = ("The software inventory has not been checked against vulnerability "
                                                "data yet.")
    else:
        rows = db.execute(finding_filter(
            select(FindingRecord.affected_software, func.count(FindingRecord.id).label("n"))
            .where(FindingRecord.status.in_(OPEN), FindingRecord.affected_software.is_not(None))
            .group_by(FindingRecord.affected_software)
            .order_by(func.count(FindingRecord.id).desc(), FindingRecord.affected_software)
            .limit(10))).all()
        top_software = [SoftwareCount(name=n, count=c) for n, c in rows]

    # ---- alerts over time
    alerts_over_time: list[AlertDay] | None = None
    logs_in_period = db.execute(select(func.count(LogEventRecord.id)).where(
        LogEventRecord.device_id.in_(ids), LogEventRecord.ingested_at >= since)).scalar_one()
    aq = select(func.date(Alert.detected_at), Alert.severity, func.count(Alert.id)).where(
        Alert.device_id.in_(ids), Alert.detected_at >= since)
    if sevs:
        aq = aq.where(Alert.severity.in_(sevs))
    alert_rows = db.execute(aq.group_by(func.date(Alert.detected_at), Alert.severity)).all()
    if not logs_in_period and not alert_rows:
        unavailable["alerts_over_time"] = ("No log events were collected in this period, so alert activity cannot be "
                                           "assessed; run a logs or full scan.")
    else:
        by_day: dict[date, dict[str, int]] = {d: {s: 0 for s in SEVERITIES} for d in _days(since, until)}
        for d, sev, n in alert_rows:
            by_day.setdefault(_as_date(d), {s: 0 for s in SEVERITIES})[sev] = n
        alerts_over_time = [AlertDay(date=d, total=sum(c.values()), **{s: c.get(s, 0) for s in SEVERITIES})
                            for d, c in sorted(by_day.items())]

    # ---- email exposure (account-wide; not tied to devices)
    email_history: list[EmailExposurePoint] | None = None
    if not db.execute(select(func.count(EmailIdentity.id))).scalar_one():
        unavailable["email_exposure_history"] = "No email addresses are monitored."
    else:
        checks = db.execute(select(EmailCheck).where(EmailCheck.checked_at >= since)
                            .order_by(EmailCheck.checked_at, EmailCheck.id)).scalars().all()
        if not checks:
            unavailable["email_exposure_history"] = "No email exposure checks ran in this period."
        else:
            email_history = [EmailExposurePoint(
                checked_at=c.checked_at, identity_id=c.identity_id, status=c.status,
                breach_count=c.breach_count if c.status in ("found", "not_found") else None) for c in checks]

    # ---- scan outcomes
    scan_outcomes: list[ScanWeek] | None = None
    success_rate: float | None = None
    finished = db.execute(select(Scan.status, Scan.completed_at).where(
        Scan.device_id.in_(ids), Scan.status.in_(FINISHED), Scan.completed_at.is_not(None),
        Scan.completed_at >= since)).all()
    if not finished:
        unavailable["scan_outcomes"] = "No scans finished in this period."
        unavailable["success_rate"] = "No scans finished in this period."
    else:
        sweeks: dict[date, dict[str, int]] = {w: dict.fromkeys(FINISHED, 0) for w in _weeks(since, until)}
        for st, ts in finished:
            sweeks.setdefault(week_start(ts), dict.fromkeys(FINISHED, 0))[st] += 1
        scan_outcomes = [ScanWeek(week_start=w, **c) for w, c in sorted(sweeks.items())]
        success_rate = round(sum(1 for st, _ in finished if st == "completed") / len(finished), 4)

    # ---- device health
    health: list[HealthDay] | None = None
    day = func.date(MetricSampleRecord.ts)
    base = select(day, func.avg(MetricSampleRecord.value), func.max(MetricSampleRecord.value)).where(
        MetricSampleRecord.device_id.in_(ids), MetricSampleRecord.ts >= since)
    cpu = {_as_date(d): a for d, a, _ in db.execute(base.where(MetricSampleRecord.metric == "cpu_percent").group_by(day))}
    mem = {_as_date(d): a for d, a, _ in db.execute(base.where(MetricSampleRecord.metric == "memory_percent")
                                                     .group_by(day))}
    disk = {_as_date(d): m for d, _, m in db.execute(base.where(MetricSampleRecord.metric.like("disk_percent%"))
                                                      .group_by(day))}
    health_days = sorted(set(cpu) | set(mem) | set(disk))
    if not health_days:
        unavailable["health_history"] = "No CPU, memory or disk samples were collected in this period."
    else:
        def r(v: float | None) -> float | None:
            return None if v is None else round(float(v), 2)

        health = [HealthDay(date=d, cpu_avg=r(cpu.get(d)), memory_avg=r(mem.get(d)), disk_max=r(disk.get(d)))
                  for d in health_days]

    # ---- mean time to remediate
    resolved = db.execute(finding_filter(select(FindingRecord.first_seen_at, FindingRecord.verified_resolved_at).where(
        FindingRecord.status == "resolved", FindingRecord.verified_resolved_at.is_not(None),
        FindingRecord.verified_resolved_at >= since))).all()
    mttr: float | None = None
    if resolved:
        total = sum((res - first).total_seconds() for first, res in resolved)
        mttr = round(total / len(resolved) / 86400, 2)
    else:
        unavailable["mean_time_to_remediate_days"] = "No finding was verified as resolved in this period."

    # ---- remediation tasks
    tq = (select(RemediationTask.due_date).join(FindingRecord, FindingRecord.id == RemediationTask.finding_id)
          .where(RemediationTask.status == "open"))
    task_dues = db.execute(finding_filter(tq)).scalars().all()
    overdue = sum(1 for d in task_dues if d and d < today.isoformat())

    notes = ["Email exposure is account-wide; the device filter does not apply to it."]
    if sevs or category:
        notes.append("Severity filters apply to findings, alerts and tasks; the category filter applies to findings "
                     "and tasks. Scans, health and email exposure are not filtered by them.")
    return Analytics(
        filters=AnalyticsFilters(days=days, since=since, until=until, device_id=device_id, device_ids=ids,
                                 severity=sevs, category=category, notes=notes),
        score_history=score_history, vulns_by_severity=vulns_by_severity, vulns_by_category=vulns_by_category,
        top_affected_software=top_software, findings_by_device=findings_by_device,
        new_vs_resolved_by_week=new_vs_resolved, alerts_over_time=alerts_over_time,
        email_exposure_history=email_history, scan_outcomes=scan_outcomes, success_rate=success_rate,
        health_history=health, mean_time_to_remediate_days=mttr, mean_time_to_remediate_count=len(resolved),
        outstanding_tasks=TaskCounts(open=len(task_dues), overdue=overdue), repeated_misconfigurations=repeated,
        unavailable=unavailable,
    )


# =========================================================================== export


@router.get("/export/findings", response_class=Response,
            responses={200: {"content": {"text/csv": {}, "application/json": {}},
                             "description": "The matching findings as a file download"}})
def export_findings(
    fmt: Literal["csv", "json"] = Query("csv", alias="format"),
    status_filter: str = Query("open", alias="status", max_length=32, description="open, all, or one status"),
    severity: list[str] | None = Query(None),
    device_id: int | None = None,
    category: str | None = Query(None, max_length=64),
    source: str | None = Query(None, max_length=32),
    auth: AuthContext = Depends(current_auth),
    db: Session = Depends(get_db),
) -> Response:
    sevs = _check_severities(severity)
    q = select(FindingRecord)
    if device_id is not None:
        q = q.where(FindingRecord.device_id == device_id)
    if status_filter == "open":
        q = q.where(FindingRecord.status.in_(OPEN))
    elif status_filter != "all":
        q = q.where(FindingRecord.status == status_filter)
    if sevs:
        q = q.where(FindingRecord.severity.in_(sevs))
    if category:
        q = q.where(FindingRecord.category == category)
    if source:
        q = q.where(FindingRecord.source == source)
    findings = list(db.execute(q.order_by(FindingRecord.device_id, FindingRecord.id)).scalars())
    findings.sort(key=lambda f: (-SEV_RANK.get(f.severity, 0), f.device_id, f.id))
    rows = finding_rows(db, findings)
    filters = {"status": status_filter, "severity": sevs, "device_id": device_id, "category": category,
               "source": source}
    audit.record(db, auth.actor, "findings.exported", "findings", None,
                 {"format": fmt, "count": len(rows), "filters": filters})
    db.commit()
    stamp = now().strftime("%Y%m%d-%H%M%S")
    if fmt == "csv":
        body, media = write_csv(rows, FINDING_COLUMNS), "text/csv; charset=utf-8"
    else:
        body, media = render_json(rows), "application/json"
    return Response(content=body, media_type=media,
                    headers={"Content-Disposition": f'attachment; filename="sentinel-findings-{stamp}.{fmt}"'})
