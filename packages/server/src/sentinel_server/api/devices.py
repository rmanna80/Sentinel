"""Device inventory, enrollment codes and health metrics."""

from __future__ import annotations

from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .. import audit
from ..config import Settings
from ..db import get_db
from ..deps import AuthContext, current_auth, settings_dep
from ..models import Device, EnrollmentCode, MetricSampleRecord, Scan, now
from ..schemas import DeviceSummary, DeviceUpdate, EnrollmentCodeOut, MetricPoint, MetricSeries
from ..security import hash_token, new_enrollment_code, normalize_code
from ..services.scoring import device_posture

router = APIRouter(prefix="/api/devices", tags=["devices"])

ONLINE_WINDOW = timedelta(minutes=2)


def latest_metrics(db: Session, device_id: int) -> dict[str, float]:
    out: dict[str, float] = {}
    sub = (
        select(MetricSampleRecord.metric, func.max(MetricSampleRecord.ts).label("ts"))
        .where(MetricSampleRecord.device_id == device_id)
        .group_by(MetricSampleRecord.metric)
        .subquery()
    )
    rows = db.execute(
        select(MetricSampleRecord.metric, MetricSampleRecord.value)
        .join(sub, (MetricSampleRecord.metric == sub.c.metric) & (MetricSampleRecord.ts == sub.c.ts))
        .where(MetricSampleRecord.device_id == device_id)
    ).all()
    for metric, value in rows:
        out[metric] = value
    return out


def summarize(db: Session, d: Device, settings: Settings) -> DeviceSummary:
    p = device_posture(db, d.id, settings.min_score_coverage)
    online = d.last_seen_at is not None and now() - d.last_seen_at < ONLINE_WINDOW
    return DeviceSummary.model_validate({
        **{c: getattr(d, c) for c in DeviceSummary.model_fields if hasattr(d, c)},
        "online": online, "score": p.score, "raw_score": p.raw_score, "coverage": p.coverage,
        "incomplete": p.incomplete, "open_findings": p.open_findings, "threat_level": p.threat_level,
        "counts": p.counts, "latest_metrics": latest_metrics(db, d.id),
    })


@router.get("", response_model=list[DeviceSummary])
def list_devices(include_revoked: bool = False, auth: AuthContext = Depends(current_auth),
                 db: Session = Depends(get_db), settings: Settings = Depends(settings_dep)) -> list[DeviceSummary]:
    q = select(Device).order_by(Device.name)
    if not include_revoked:
        q = q.where(Device.is_active.is_(True))
    return [summarize(db, d, settings) for d in db.execute(q).scalars()]


@router.get("/{device_id}", response_model=DeviceSummary)
def get_device(device_id: int, auth: AuthContext = Depends(current_auth), db: Session = Depends(get_db),
               settings: Settings = Depends(settings_dep)) -> DeviceSummary:
    d = db.get(Device, device_id)
    if d is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No such device")
    return summarize(db, d, settings)


@router.patch("/{device_id}", response_model=DeviceSummary)
def rename_device(device_id: int, body: DeviceUpdate, auth: AuthContext = Depends(current_auth),
                  db: Session = Depends(get_db), settings: Settings = Depends(settings_dep)) -> DeviceSummary:
    d = db.get(Device, device_id)
    if d is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No such device")
    audit.record(db, auth.actor, "device.renamed", "device", d.id, {"from": d.name, "to": body.name})
    d.name = body.name
    db.commit()
    return summarize(db, d, settings)


@router.delete("/{device_id}", status_code=204)
def revoke_device(device_id: int, auth: AuthContext = Depends(current_auth), db: Session = Depends(get_db)) -> Response:
    """Revoke the device token. History is kept; the agent must enroll again."""
    d = db.get(Device, device_id)
    if d is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No such device")
    d.is_active = False
    d.token_hash = hash_token("revoked:" + d.token_hash)
    for scan in db.execute(select(Scan).where(Scan.device_id == d.id, Scan.status == "queued")).scalars():
        scan.status = "cancelled"
        scan.completed_at = now()
    audit.record(db, auth.actor, "device.revoked", "device", d.id)
    db.commit()
    return Response(status_code=204)


@router.post("/enrollment-codes", response_model=EnrollmentCodeOut)
def create_enrollment_code(auth: AuthContext = Depends(current_auth), db: Session = Depends(get_db),
                           settings: Settings = Depends(settings_dep)) -> EnrollmentCodeOut:
    code = new_enrollment_code()
    expires = now() + timedelta(minutes=settings.enrollment_code_minutes)
    db.add(EnrollmentCode(code_hash=hash_token(normalize_code(code)), created_by=auth.user.id, expires_at=expires))
    audit.record(db, auth.actor, "device.enrollment_code_created", None, None, {"expires_at": expires.isoformat()})
    db.commit()
    server = f"http://127.0.0.1:{settings.port}"
    return EnrollmentCodeOut(code=code, expires_at=expires,
                             command=f"uv run sentinel-agent enroll --server {server} --code {code}")


@router.get("/{device_id}/metrics", response_model=list[MetricSeries])
def device_metrics(device_id: int, hours: int = Query(24, ge=1, le=24 * 90), metric: list[str] | None = Query(None),
                   auth: AuthContext = Depends(current_auth), db: Session = Depends(get_db)) -> list[MetricSeries]:
    since: datetime = now() - timedelta(hours=hours)
    q = select(MetricSampleRecord).where(MetricSampleRecord.device_id == device_id, MetricSampleRecord.ts >= since)
    if metric:
        q = q.where(MetricSampleRecord.metric.in_(metric))
    series: dict[str, list[MetricPoint]] = {}
    for m in db.execute(q.order_by(MetricSampleRecord.ts)).scalars():
        series.setdefault(m.metric, []).append(MetricPoint(ts=m.ts, value=m.value))
    # Downsample long series to at most ~300 points so charts stay light.
    out = []
    for name, points in sorted(series.items()):
        step = max(1, len(points) // 300)
        out.append(MetricSeries(metric=name, points=points[::step]))
    return out
