"""Endpoints the agent calls. Authenticated by device token only; user sessions do not work here."""

from __future__ import annotations

from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from sentinel_core.models import (
    AgentHello,
    AgentJob,
    CheckRunResult,
    DataMode,
    EnrollRequest,
    EnrollResponse,
    HeartbeatResponse,
    MetricSample,
    ScanCompletion,
    ScanPlan,
    ScanType,
)
from sentinel_core.telemetry import Detection
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import audit
from ..config import Settings
from ..db import get_db
from ..deps import client_ip, current_device, settings_dep
from ..models import BehaviorDetection, Device, EnrollmentCode, MetricSampleRecord, Scan, now
from ..security import hash_token, new_token, normalize_code, rate_limiter
from ..services.ingest import IngestError, apply_host, complete_scan, extend_lease, record_plan, record_result
from ..services.notify import notify

MAX_DETECTIONS_PER_POST = 500
NOTIFY_SEVERITIES = {"critical", "high"}

router = APIRouter(prefix="/api/agent", tags=["agent"])


@router.post("/enroll", response_model=EnrollResponse)
def enroll(body: EnrollRequest, request: Request, db: Session = Depends(get_db),
           settings: Settings = Depends(settings_dep)) -> EnrollResponse:
    if not rate_limiter.allow("enroll", client_ip(request), 10, 60):
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Too many enrollment attempts")
    code = db.execute(
        select(EnrollmentCode).where(EnrollmentCode.code_hash == hash_token(normalize_code(body.code)))
    ).scalar_one_or_none()
    if code is None or code.used_at is not None or code.expires_at <= now():
        audit.record(db, "anonymous", "device.enroll_failed", None, None, {"ip": client_ip(request)})
        db.commit()
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Enrollment code is invalid, used or expired")
    token = new_token()
    device = Device(name=body.host.hostname, hostname=body.host.hostname, os_family=body.host.os_family.value,
                    os_name=body.host.os_name, os_version=body.host.os_version, arch=body.host.arch,
                    agent_version=body.host.agent_version, token_hash=hash_token(token))
    apply_host(device, body.host)
    db.add(device)
    db.flush()
    code.used_at = now()
    code.device_id = device.id
    audit.record(db, "system", "device.enrolled", "device", device.id, {"hostname": device.hostname})
    db.commit()
    return EnrollResponse(device_id=device.id, device_token=token)


@router.post("/hello", status_code=204)
def hello(body: AgentHello, device: Device = Depends(current_device), db: Session = Depends(get_db)) -> Response:
    apply_host(device, body.host)
    device.checks_catalog = [d.model_dump(mode="json") for d in body.checks]
    db.commit()
    return Response(status_code=204)


@router.get("/jobs/next", response_model=None, responses={200: {"model": AgentJob}, 204: {"description": "No job"}})
def next_job(elevated: bool = Query(False), device: Device = Depends(current_device), db: Session = Depends(get_db),
             settings: Settings = Depends(settings_dep)) -> Response | AgentJob:
    device.last_seen_at = now()
    scan = db.execute(
        select(Scan)
        .where(Scan.device_id == device.id, Scan.status == "queued", Scan.elevated.is_(elevated))
        .order_by(Scan.requested_at)
        .limit(1)
    ).scalar_one_or_none()
    if scan is None:
        db.commit()
        return Response(status_code=204)
    if scan.cancel_requested:
        scan.status = "cancelled"
        scan.completed_at = now()
        db.commit()
        return Response(status_code=204)
    t = now()
    scan.status = "running"
    scan.claimed_at = t
    scan.started_at = t
    scan.agent_version = device.agent_version
    scan.lease_expires_at = t + timedelta(seconds=settings.agent_lease_seconds)
    db.commit()
    return AgentJob(scan_id=scan.id, scan_type=ScanType(scan.scan_type), check_ids=scan.check_ids,
                    params=scan.params or {}, data_mode=DataMode(scan.data_mode))


def _own_scan(db: Session, device: Device, scan_id: int) -> Scan:
    scan = db.get(Scan, scan_id)
    if scan is None or scan.device_id != device.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No such scan for this device")
    return scan


@router.post("/scans/{scan_id}/plan", status_code=204)
def plan(scan_id: int, body: ScanPlan, device: Device = Depends(current_device), db: Session = Depends(get_db),
         settings: Settings = Depends(settings_dep)) -> Response:
    scan = _own_scan(db, device, scan_id)
    try:
        record_plan(db, scan, device, body, settings)
    except IngestError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc
    db.commit()
    return Response(status_code=204)


@router.post("/scans/{scan_id}/results", status_code=204)
def results(scan_id: int, body: CheckRunResult, device: Device = Depends(current_device),
            db: Session = Depends(get_db), settings: Settings = Depends(settings_dep)) -> Response:
    scan = _own_scan(db, device, scan_id)
    try:
        record_result(db, scan, device, body, settings)
    except IngestError as exc:
        db.rollback()
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc
    db.commit()
    return Response(status_code=204)


@router.post("/scans/{scan_id}/heartbeat", response_model=HeartbeatResponse)
def heartbeat(scan_id: int, device: Device = Depends(current_device), db: Session = Depends(get_db),
              settings: Settings = Depends(settings_dep)) -> HeartbeatResponse:
    scan = _own_scan(db, device, scan_id)
    if scan.status == "running":
        extend_lease(scan, settings)
    device.last_seen_at = now()
    db.commit()
    return HeartbeatResponse(cancel=scan.cancel_requested or scan.status != "running")


@router.post("/scans/{scan_id}/complete", status_code=204)
def complete(scan_id: int, body: ScanCompletion, device: Device = Depends(current_device),
             db: Session = Depends(get_db), settings: Settings = Depends(settings_dep)) -> Response:
    scan = _own_scan(db, device, scan_id)
    try:
        complete_scan(db, scan, body, settings)
    except IngestError as exc:
        raise HTTPException(422, str(exc)) from exc
    db.commit()
    return Response(status_code=204)


@router.post("/detections", status_code=204)
def ingest_detections(body: list[Detection], device: Device = Depends(current_device),
                      db: Session = Depends(get_db)) -> Response:
    """Receive behavioural detections from the agent's detection engine (conclusions only, with evidence).

    A detection is upserted on (device, dedup_key): a repeat of the same behaviour updates the one row and
    bumps its count rather than piling up. Nothing in the payload is ever executed."""
    device.last_seen_at = now()
    for det in body[:MAX_DETECTIONS_PER_POST]:
        events = [e.model_dump(mode="json") for e in det.events]
        tree = [p.model_dump(mode="json") for p in det.process_tree]
        existing = db.execute(select(BehaviorDetection).where(
            BehaviorDetection.device_id == device.id,
            BehaviorDetection.dedup_key == det.dedup_key)).scalar_one_or_none()
        if existing is not None:
            existing.count += 1
            existing.last_ts = max(existing.last_ts, det.last_ts)
            existing.severity = det.severity.value
            existing.events, existing.process_tree = events, tree  # keep the latest occurrence's evidence
            continue
        row = BehaviorDetection(
            device_id=device.id, rule_id=det.rule_id, title=det.title[:300], summary=det.summary[:1000],
            explanation=det.explanation, severity=det.severity.value, confidence=det.confidence.value,
            technique_ids=det.technique_ids, technique_names=det.technique_names,
            host=(det.host or device.hostname)[:256], dedup_key=det.dedup_key[:512],
            process_guids=det.process_guids, events=events, process_tree=tree,
            first_ts=det.first_ts, last_ts=det.last_ts, count=1, status="new",
        )
        db.add(row)
        db.flush()
        if det.severity.value in NOTIFY_SEVERITIES:
            notify(db, severity=det.severity.value, kind="behavior",
                   title=f"Behavioural detection: {det.title}"[:300], body=det.summary,
                   link=f"/behavior/{row.id}", dedupe_key=f"behavior:{device.id}:{det.dedup_key}")
            row.notified = True
    audit.record(db, f"device:{device.id}", "behavior.detections_ingested", "device", device.id,
                 {"count": len(body[:MAX_DETECTIONS_PER_POST])})
    db.commit()
    return Response(status_code=204)


@router.post("/metrics", status_code=204)
def metrics(body: list[MetricSample], device: Device = Depends(current_device),
            db: Session = Depends(get_db)) -> Response:
    for m in body[:50]:
        db.add(MetricSampleRecord(device_id=device.id, ts=m.ts, metric=m.metric[:128], value=float(m.value)))
    device.last_seen_at = now()
    db.commit()
    return Response(status_code=204)


