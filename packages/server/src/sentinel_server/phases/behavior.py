"""Sentinel X behavioural detections: the read/triage API for conclusions shipped by the agent's engine.

The agent posts detections to ``/api/agent/detections`` (device-authenticated, in :mod:`..api.agent`); this
module is the user side — listing, filtering, viewing the evidence, and acknowledging or dismissing. Nothing
here runs anything: a detection's ``events`` and ``process_tree`` are stored evidence, shown for review only.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from .. import audit
from ..db import get_db
from ..deps import AuthContext, current_auth
from ..models import BehaviorDetection

router = APIRouter(prefix="/api/behavior", tags=["behavior"])

SEVERITIES = ("critical", "high", "medium", "low", "info")


class DetectionOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    device_id: int | None
    rule_id: str
    title: str
    summary: str
    severity: str
    confidence: str
    technique_ids: list[str]
    technique_names: list[str]
    host: str
    first_ts: datetime
    last_ts: datetime
    count: int
    status: str
    created_at: datetime


class DetectionDetail(DetectionOut):
    explanation: str
    process_guids: list[str]
    events: list[dict[str, Any]]
    process_tree: list[dict[str, Any]]


class DetectionPage(BaseModel):
    items: list[DetectionOut]
    total: int


class StatusUpdate(BaseModel):
    status: str = Field(pattern=r"^(new|acknowledged|dismissed)$")


class RuleCount(BaseModel):
    rule_id: str
    title: str
    count: int


class BehaviorSummary(BaseModel):
    total: int
    new: int
    acknowledged: int
    dismissed: int
    by_severity: dict[str, int]
    hosts: int
    top_rules: list[RuleCount]
    note: str


# --------------------------------------------------------------------------- routes


@router.get("/detections", response_model=DetectionPage)
def list_detections(
    status_filter: str | None = Query(None, alias="status"),
    severity: str | None = None,
    host: str | None = None,
    q: str | None = None,
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    auth: AuthContext = Depends(current_auth),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    stmt = select(BehaviorDetection)
    if status_filter == "all":
        pass
    elif status_filter:
        stmt = stmt.where(BehaviorDetection.status == status_filter)
    else:
        stmt = stmt.where(BehaviorDetection.status != "dismissed")  # default view hides dismissed
    if severity:
        stmt = stmt.where(BehaviorDetection.severity == severity)
    if host:
        stmt = stmt.where(BehaviorDetection.host == host)
    if q:
        like = f"%{q}%"
        stmt = stmt.where(or_(BehaviorDetection.title.ilike(like), BehaviorDetection.summary.ilike(like)))
    total = db.execute(select(func.count()).select_from(stmt.subquery())).scalar_one()
    items = db.execute(
        stmt.order_by(BehaviorDetection.last_ts.desc()).limit(limit).offset(offset)
    ).scalars().all()
    return {"items": items, "total": total}


@router.get("/detections/{detection_id}", response_model=DetectionDetail)
def get_detection(detection_id: int, auth: AuthContext = Depends(current_auth),
                  db: Session = Depends(get_db)) -> BehaviorDetection:
    det = db.get(BehaviorDetection, detection_id)
    if det is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No such detection")
    return det


@router.patch("/detections/{detection_id}", response_model=DetectionDetail)
def update_detection(detection_id: int, body: StatusUpdate, auth: AuthContext = Depends(current_auth),
                     db: Session = Depends(get_db)) -> BehaviorDetection:
    det = db.get(BehaviorDetection, detection_id)
    if det is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No such detection")
    det.status = body.status
    audit.record(db, auth.actor, "behavior.detection_status_changed", "behavior_detection", det.id,
                 {"status": body.status})
    db.commit()
    db.refresh(det)
    return det


@router.get("/summary", response_model=BehaviorSummary)
def behavior_summary(auth: AuthContext = Depends(current_auth), db: Session = Depends(get_db)) -> BehaviorSummary:
    def count_where(*where: Any) -> int:
        return db.execute(select(func.count(BehaviorDetection.id)).where(*where)).scalar_one()

    open_only = BehaviorDetection.status != "dismissed"
    by_severity = {
        sev: count_where(BehaviorDetection.severity == sev, open_only) for sev in SEVERITIES
    }
    top = db.execute(
        select(BehaviorDetection.rule_id, func.min(BehaviorDetection.title), func.count(BehaviorDetection.id))
        .where(open_only).group_by(BehaviorDetection.rule_id)
        .order_by(func.count(BehaviorDetection.id).desc()).limit(5)
    ).all()
    return BehaviorSummary(
        total=count_where(),
        new=count_where(BehaviorDetection.status == "new"),
        acknowledged=count_where(BehaviorDetection.status == "acknowledged"),
        dismissed=count_where(BehaviorDetection.status == "dismissed"),
        by_severity=by_severity,
        hosts=db.execute(select(func.count(func.distinct(BehaviorDetection.host)))).scalar_one(),
        top_rules=[RuleCount(rule_id=r, title=t or r, count=c) for r, t, c in top],
        note="Behavioural detections correlated from OS telemetry on your devices. These are conclusions with "
             "evidence, not raw events; investigate before acting. Nothing is remediated automatically.",
    )
