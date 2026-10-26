"""The overview page: one call with everything the main dashboard shows."""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy import case, func, select
from sqlalchemy.orm import Session

from ..config import Settings
from ..db import get_db
from ..deps import AuthContext, current_auth, settings_dep
from ..models import Alert, Device, FindingRecord, LogEventRecord, Scan, Schedule, now
from ..schemas import DeviceSummary, FindingOut, ScanOut
from ..services.findings import OPEN
from ..services.scoring import fleet_posture
from .devices import summarize

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])

SEV_ORDER = case({"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0},
                 value=FindingRecord.severity, else_=0)


class ScorePoint(BaseModel):
    scan_id: int
    device_id: int
    ts: datetime
    score: int | None
    raw_score: int | None
    coverage: float | None


class RecentEvent(BaseModel):
    kind: str  # alert | log | scan
    ts: datetime
    severity: str
    title: str
    device_id: int | None
    link: str


class Overview(BaseModel):
    score: int | None
    raw_score: int
    coverage: float | None
    incomplete: bool
    checks_completed: int
    checks_applicable: int
    threat_level: str
    open_findings: int
    unresolved_findings: int
    vulnerabilities: int
    open_alerts: int
    suspicious_events_24h: int
    severity_counts: dict[str, int]
    last_scan: ScanOut | None
    last_successful_scan_at: datetime | None
    next_scheduled_at: datetime | None
    devices: list[DeviceSummary]
    recent_events: list[RecentEvent]
    score_history: list[ScorePoint]
    recommended_actions: list[FindingOut]
    data_mode_notice: str | None
    score_basis: str


@router.get("/overview", response_model=Overview)
def overview(device_id: int | None = None, days: int = Query(30, ge=1, le=365),
             auth: AuthContext = Depends(current_auth), db: Session = Depends(get_db),
             settings: Settings = Depends(settings_dep)) -> Overview:
    devices = list(db.execute(select(Device).where(Device.is_active.is_(True)).order_by(Device.name)).scalars())
    ids = [d.id for d in devices if device_id is None or d.id == device_id]
    posture = fleet_posture(db, ids, settings.min_score_coverage)
    open_q = select(FindingRecord).where(FindingRecord.status.in_(OPEN), FindingRecord.device_id.in_(ids))
    open_findings = list(db.execute(open_q).scalars())
    severity_counts = {s: 0 for s in ("critical", "high", "medium", "low", "info")}
    for f in open_findings:
        severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1
    unresolved = sum(1 for f in open_findings if f.status != "accepted_risk")
    vulns = sum(1 for f in open_findings if f.source == "vuln_matcher" or f.category == "vulnerability")

    open_alerts = db.execute(select(func.count(Alert.id)).where(
        Alert.status.in_(("new", "acknowledged", "investigating")), Alert.device_id.in_(ids))).scalar_one()
    since24 = now() - timedelta(hours=24)
    suspicious = db.execute(select(func.count(LogEventRecord.id)).where(
        LogEventRecord.device_id.in_(ids), LogEventRecord.occurred_at >= since24,
        LogEventRecord.severity.in_(("low", "medium", "high", "critical")))).scalar_one()

    last_scan = db.execute(select(Scan).where(Scan.device_id.in_(ids)).order_by(Scan.requested_at.desc())
                           .limit(1)).scalar_one_or_none()
    last_ok = db.execute(select(func.max(Scan.completed_at)).where(
        Scan.device_id.in_(ids), Scan.status == "completed")).scalar_one()
    next_sched = db.execute(select(func.min(Schedule.next_run_at)).where(
        Schedule.enabled.is_(True), Schedule.device_id.in_(ids))).scalar_one()

    since = now() - timedelta(days=days)
    history = [
        ScorePoint(scan_id=s.id, device_id=s.device_id, ts=s.completed_at, score=s.score,
                   raw_score=(s.summary or {}).get("raw_score"), coverage=s.coverage)
        for s in db.execute(select(Scan).where(
            Scan.device_id.in_(ids), Scan.completed_at.is_not(None), Scan.completed_at >= since,
            Scan.scan_type.in_(("full", "posture")), Scan.status.in_(("completed", "partial")),
        ).order_by(Scan.completed_at)).scalars()
        if s.completed_at is not None
    ]

    recent: list[RecentEvent] = []
    for a in db.execute(select(Alert).where(Alert.device_id.in_(ids)).order_by(Alert.detected_at.desc())
                        .limit(8)).scalars():
        recent.append(RecentEvent(kind="alert", ts=a.detected_at, severity=a.severity, title=a.title,
                                  device_id=a.device_id, link=f"/threats/alerts/{a.id}"))
    for e in db.execute(select(LogEventRecord).where(
            LogEventRecord.device_id.in_(ids), LogEventRecord.severity.in_(("medium", "high", "critical")))
            .order_by(LogEventRecord.occurred_at.desc()).limit(8)).scalars():
        recent.append(RecentEvent(kind="log", ts=e.occurred_at, severity=e.severity, title=e.message[:200],
                                  device_id=e.device_id, link=f"/logs?event={e.id}"))
    for s in db.execute(select(Scan).where(Scan.device_id.in_(ids), Scan.completed_at.is_not(None))
                        .order_by(Scan.completed_at.desc()).limit(5)).scalars():
        sev = "info" if s.status == "completed" else "medium"
        recent.append(RecentEvent(kind="scan", ts=s.completed_at, severity=sev,  # type: ignore[arg-type]
                                  title=f"{s.scan_type.title()} scan {s.status}", device_id=s.device_id,
                                  link=f"/scans/{s.id}"))
    recent.sort(key=lambda r: r.ts, reverse=True)

    actions = db.execute(
        select(FindingRecord).where(FindingRecord.status.in_(OPEN - {"accepted_risk"}),
                                    FindingRecord.device_id.in_(ids),
                                    FindingRecord.severity.in_(("critical", "high", "medium")))
        .order_by(FindingRecord.kev.desc(), SEV_ORDER.desc(), FindingRecord.cvss_score.desc().nulls_last(),
                  FindingRecord.last_seen_at.desc())
        .limit(6)
    ).scalars().all()

    fixture_scans = db.execute(select(func.count(Scan.id)).where(Scan.device_id.in_(ids),
                                                                 Scan.data_mode == "fixture")).scalar_one()
    notice = None
    if fixture_scans:
        notice = (f"{fixture_scans} scan(s) on this view used fixture (demo) data, not live data from a device.")

    return Overview(
        score=posture.score, raw_score=posture.raw_score, coverage=posture.coverage, incomplete=posture.incomplete,
        checks_completed=posture.checks_completed, checks_applicable=posture.checks_applicable,
        threat_level=posture.threat_level, open_findings=len(open_findings), unresolved_findings=unresolved,
        vulnerabilities=vulns, open_alerts=open_alerts, suspicious_events_24h=suspicious,
        severity_counts=severity_counts, last_scan=ScanOut.model_validate(last_scan) if last_scan else None,
        last_successful_scan_at=last_ok, next_scheduled_at=next_sched,
        devices=[summarize(db, d, settings) for d in devices if d.id in ids],
        recent_events=recent[:12], score_history=history,
        recommended_actions=[FindingOut.model_validate(f) for f in actions], data_mode_notice=notice,
        score_basis=("100 minus 20 per critical, 8 per high, 3 per medium and 1 per low open finding "
                     "(verified, or heuristic at high confidence). Shown only when at least "
                     f"{int(settings.min_score_coverage * 100)}% of applicable checks completed."),
    )


def _unused(_: Any) -> None:  # pragma: no cover
    pass
