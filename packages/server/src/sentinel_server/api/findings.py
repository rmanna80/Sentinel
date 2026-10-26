"""Findings list, detail with evidence, workflow updates, verification re-runs and remediation tasks."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import case, func, or_, select
from sqlalchemy.orm import Session

from .. import audit
from ..db import get_db
from ..deps import AuthContext, current_auth
from ..models import (
    CheckRun,
    Device,
    EvidenceRecord,
    FindingEvent,
    FindingObservation,
    FindingRecord,
    RemediationTask,
    now,
)
from ..schemas import (
    EvidenceOut,
    FindingDetail,
    FindingOut,
    FindingUpdate,
    Page,
    ScanOut,
    TaskCreate,
    TaskOut,
    TaskUpdate,
)
from ..services.findings import OPEN, USER_TRANSITIONS, TransitionError, apply_user_update
from .scans import queue_scan, scoped_checks

router = APIRouter(prefix="/api", tags=["findings"])

SEVERITY_ORDER = case(
    {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}, value=FindingRecord.severity, else_=0
)


@router.get("/findings", response_model=Page[FindingOut])
def list_findings(
    device_id: int | None = None,
    status_filter: str = Query("open", alias="status", description="open, all, or one status"),
    severity: list[str] | None = Query(None),
    category: str | None = None,
    kind: str | None = None,
    source: str | None = None,
    check_id: str | None = None,
    kev: bool | None = None,
    q: str | None = Query(None, max_length=200),
    sort: str = Query("severity", pattern="^(severity|last_seen|first_seen|cvss)$"),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    auth: AuthContext = Depends(current_auth),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    stmt = select(FindingRecord)
    if device_id is not None:
        stmt = stmt.where(FindingRecord.device_id == device_id)
    if status_filter == "open":
        stmt = stmt.where(FindingRecord.status.in_(OPEN))
    elif status_filter != "all":
        stmt = stmt.where(FindingRecord.status == status_filter)
    if severity:
        stmt = stmt.where(FindingRecord.severity.in_(severity))
    if category:
        stmt = stmt.where(FindingRecord.category == category)
    if kind:
        stmt = stmt.where(FindingRecord.finding_kind == kind)
    if source:
        stmt = stmt.where(FindingRecord.source == source)
    if check_id:
        stmt = stmt.where(FindingRecord.check_id == check_id)
    if kev is not None:
        stmt = stmt.where(FindingRecord.kev.is_(kev))
    if q:
        like = f"%{q}%"
        stmt = stmt.where(or_(FindingRecord.title.ilike(like), FindingRecord.cve_id.ilike(like),
                              FindingRecord.affected_software.ilike(like), FindingRecord.rule_id.ilike(like)))
    total = db.execute(select(func.count()).select_from(stmt.subquery())).scalar_one()
    order = {
        "severity": [SEVERITY_ORDER.desc(), FindingRecord.kev.desc(), FindingRecord.last_seen_at.desc()],
        "last_seen": [FindingRecord.last_seen_at.desc()],
        "first_seen": [FindingRecord.first_seen_at.desc()],
        "cvss": [FindingRecord.cvss_score.desc().nulls_last(), SEVERITY_ORDER.desc()],
    }[sort]
    items = db.execute(stmt.order_by(*order).limit(limit).offset(offset)).scalars().all()
    return {"items": items, "total": total}


def _get(db: Session, finding_id: int) -> FindingRecord:
    f = db.get(FindingRecord, finding_id)
    if f is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No such finding")
    return f


def _detail(db: Session, f: FindingRecord) -> dict[str, Any]:
    data = FindingOut.model_validate(f).model_dump()
    device = db.get(Device, f.device_id)
    data["device_name"] = device.name if device else str(f.device_id)
    data["events"] = db.execute(select(FindingEvent).where(FindingEvent.finding_id == f.id)
                                .order_by(FindingEvent.created_at.desc())).scalars().all()
    observations = []
    obs_rows = db.execute(
        select(FindingObservation, CheckRun.scan_id)
        .join(CheckRun, CheckRun.id == FindingObservation.check_run_id)
        .where(FindingObservation.finding_id == f.id)
        .order_by(FindingObservation.observed_at.desc())
        .limit(20)
    ).all()
    for obs, scan_id in obs_rows:
        evidence = []
        if obs.evidence_ids:
            evidence = [EvidenceOut.model_validate(e) for e in db.execute(
                select(EvidenceRecord).where(EvidenceRecord.id.in_(obs.evidence_ids))).scalars()]
        observations.append({"scan_id": scan_id, "check_run_id": obs.check_run_id, "observed_at": obs.observed_at,
                             "evidence": evidence})
    data["observations"] = observations
    data["tasks"] = db.execute(select(RemediationTask).where(RemediationTask.finding_id == f.id)
                               .order_by(RemediationTask.created_at)).scalars().all()
    data["allowed_statuses"] = sorted(USER_TRANSITIONS.get(f.status, set()))
    return data


@router.get("/findings/{finding_id}", response_model=FindingDetail)
def get_finding(finding_id: int, auth: AuthContext = Depends(current_auth), db: Session = Depends(get_db)) -> dict[str, Any]:
    return _detail(db, _get(db, finding_id))


@router.patch("/findings/{finding_id}", response_model=FindingDetail)
def update_finding(finding_id: int, body: FindingUpdate, auth: AuthContext = Depends(current_auth),
                   db: Session = Depends(get_db)) -> dict[str, Any]:
    f = _get(db, finding_id)
    try:
        apply_user_update(db, f, auth.actor, status=body.status, note=body.note, owner=body.owner,
                          target_date=body.target_date, fields_set=body.model_fields_set)
    except (TransitionError, ValueError) as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc
    db.commit()
    return _detail(db, f)


@router.post("/findings/{finding_id}/verify", response_model=ScanOut, status_code=201)
def verify_finding(finding_id: int, auth: AuthContext = Depends(current_auth), db: Session = Depends(get_db)) -> Any:
    """Queue a re-run of the check that produced this finding. Only that run can resolve it."""
    f = _get(db, finding_id)
    device = db.get(Device, f.device_id)
    if device is None or not device.is_active:
        raise HTTPException(status.HTTP_409_CONFLICT, "The device is no longer enrolled")
    if f.source != "agent":
        # vulnerability findings are re-evaluated from a fresh software inventory
        scan = queue_scan(db, device=device, scan_type="inventory", actor=auth.actor, user_id=auth.user.id,
                          reason="verify")
    elif scoped_checks(device, [f.check_id]):
        # Re-running a network or malware check needs its targets or folders; a bare re-run would skip and
        # prove nothing, so the person re-runs it where the scope is chosen.
        raise HTTPException(status.HTTP_409_CONFLICT,
                            "Re-run this check from the Network security page (or the agent's malware folders) "
                            "with the same targets; a passing re-run there resolves it.")
    else:
        elevated = any(c.get("id") == f.check_id and c.get("requires_elevation")
                       for c in device.checks_catalog or [])
        scan = queue_scan(db, device=device, scan_type="custom", actor=auth.actor, user_id=auth.user.id,
                          check_ids=[f.check_id], reason="verify", elevated=elevated)
    db.add(FindingEvent(finding_id=f.id, actor=auth.actor, note=f"Verification re-run requested (scan {scan.id})"))
    db.commit()
    return scan


@router.post("/findings/{finding_id}/tasks", response_model=TaskOut, status_code=201)
def create_task(finding_id: int, body: TaskCreate, auth: AuthContext = Depends(current_auth),
                db: Session = Depends(get_db)) -> RemediationTask:
    f = _get(db, finding_id)
    task = RemediationTask(finding_id=f.id, title=body.title, owner=body.owner, due_date=body.due_date,
                           notes=body.notes)
    db.add(task)
    db.flush()
    audit.record(db, auth.actor, "task.created", "task", task.id, {"finding_id": f.id})
    db.commit()
    return task


@router.get("/tasks", response_model=list[TaskOut])
def list_tasks(status_filter: str = Query("open", alias="status"), auth: AuthContext = Depends(current_auth),
               db: Session = Depends(get_db)) -> list[RemediationTask]:
    q = select(RemediationTask).order_by(RemediationTask.due_date.is_(None), RemediationTask.due_date)
    if status_filter != "all":
        q = q.where(RemediationTask.status == status_filter)
    return list(db.execute(q).scalars())


@router.patch("/tasks/{task_id}", response_model=TaskOut)
def update_task(task_id: int, body: TaskUpdate, auth: AuthContext = Depends(current_auth),
                db: Session = Depends(get_db)) -> RemediationTask:
    task = db.get(RemediationTask, task_id)
    if task is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No such task")
    for field in body.model_fields_set:
        setattr(task, field, getattr(body, field))
    if "status" in body.model_fields_set:
        task.completed_at = now() if body.status == "done" else None
    audit.record(db, auth.actor, "task.updated", "task", task.id, {"fields": sorted(body.model_fields_set)})
    db.commit()
    return task


@router.get("/evidence/{evidence_id}", response_model=EvidenceOut)
def get_evidence(evidence_id: int, auth: AuthContext = Depends(current_auth),
                 db: Session = Depends(get_db)) -> EvidenceRecord:
    ev = db.get(EvidenceRecord, evidence_id)
    if ev is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No such evidence")
    return ev
