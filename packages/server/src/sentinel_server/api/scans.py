"""Requesting, watching, cancelling, comparing and exporting scans."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .. import audit
from ..db import get_db
from ..deps import AuthContext, current_auth
from ..models import CheckRun, Device, EvidenceRecord, FindingObservation, FindingRecord, Scan, now
from ..schemas import CheckCatalogEntry, FindingOut, Page, ScanCreate, ScanDetail, ScanDiff, ScanOut

router = APIRouter(prefix="/api", tags=["scans"])

NEEDS_PARAMS = {"network", "malware"}
# Checks that act on targets or folders. They only run through their own pages (network scope controls,
# agent-configured malware folders), never through a generic or custom scan.
SCOPED_CHECK_IDS = frozenset({"net.nmap_discovery", "net.tls_certificate", "net.http_headers", "malware.clamav"})


def scoped_checks(device: Device, check_ids: list[str]) -> list[str]:
    """Check ids that must not run from a generic scan: the fixed list plus anything the agent describes
    as a network/malware check or as needing parameters."""
    catalog = {c.get("id"): c for c in device.checks_catalog or []}
    out = []
    for cid in check_ids:
        c = catalog.get(cid) or {}
        if (cid in SCOPED_CHECK_IDS or set(c.get("profiles") or []) & NEEDS_PARAMS or c.get("params_schema")):
            out.append(cid)
    return out


def queue_scan(db: Session, *, device: Device, scan_type: str, actor: str, user_id: int | None,
               check_ids: list[str] | None = None, params: dict[str, Any] | None = None, elevated: bool = False,
               reason: str = "manual", schedule_id: int | None = None) -> Scan:
    scan = Scan(device_id=device.id, scan_type=scan_type, check_ids=check_ids, params=params or {},
                elevated=elevated, requested_by=user_id, reason=reason, schedule_id=schedule_id)
    db.add(scan)
    db.flush()
    audit.record(db, actor, "scan.requested", "scan", scan.id,
                 {"device_id": device.id, "type": scan_type, "elevated": elevated, "reason": reason,
                  "checks": check_ids})
    return scan


@router.post("/scans", response_model=ScanOut, status_code=201)
def create_scan(body: ScanCreate, auth: AuthContext = Depends(current_auth), db: Session = Depends(get_db)) -> Scan:
    device = db.get(Device, body.device_id)
    if device is None or not device.is_active:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No such device")
    if body.scan_type == "custom" and not body.check_ids:
        raise HTTPException(422, "A custom scan needs check ids")
    if body.scan_type in NEEDS_PARAMS:
        raise HTTPException(422,
                            f"Start {body.scan_type} scans from their own page, which applies scope controls")
    if body.params:
        raise HTTPException(422, "Generic scans take no parameters; checks that need targets or folders run from "
                                 "their own pages")
    if body.check_ids and (blocked := scoped_checks(device, body.check_ids)):
        raise HTTPException(422, f"{', '.join(blocked)} must be started from the Network security page (scope "
                                 "controls) or uses the malware folders configured on the agent")
    known = {c["id"] for c in device.checks_catalog or []}
    if body.check_ids and known:
        unknown = [c for c in body.check_ids if c not in known]
        if unknown:
            raise HTTPException(422, f"Unknown checks for this device: {unknown}")
    scan = queue_scan(db, device=device, scan_type=body.scan_type, actor=auth.actor, user_id=auth.user.id,
                      check_ids=body.check_ids, params={}, elevated=body.elevated)
    db.commit()
    return scan


@router.get("/scans", response_model=Page[ScanOut])
def list_scans(device_id: int | None = None, status_filter: str | None = Query(None, alias="status"),
               scan_type: str | None = None, limit: int = Query(50, ge=1, le=500), offset: int = Query(0, ge=0),
               auth: AuthContext = Depends(current_auth), db: Session = Depends(get_db)) -> dict[str, Any]:
    q = select(Scan)
    if device_id is not None:
        q = q.where(Scan.device_id == device_id)
    if status_filter:
        q = q.where(Scan.status == status_filter)
    if scan_type:
        q = q.where(Scan.scan_type == scan_type)
    total = db.execute(select(func.count()).select_from(q.subquery())).scalar_one()
    items = db.execute(q.order_by(Scan.requested_at.desc()).limit(limit).offset(offset)).scalars().all()
    return {"items": items, "total": total}


def _progress(scan: Scan) -> dict[str, int]:
    out = {"total": 0, "planned": 0, "done": 0}
    for r in scan.check_runs:
        out["total"] += 1
        out[r.status] = out.get(r.status, 0) + 1
        if r.status != "planned":
            out["done"] += 1
    return out


@router.get("/scans/{scan_id}", response_model=ScanDetail)
def get_scan(scan_id: int, auth: AuthContext = Depends(current_auth), db: Session = Depends(get_db)) -> dict[str, Any]:
    scan = db.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No such scan")
    data = ScanOut.model_validate(scan).model_dump()
    data["check_runs"] = sorted(scan.check_runs, key=lambda r: (r.category, r.check_id))
    data["host_snapshot"] = scan.host_snapshot
    data["progress"] = _progress(scan)
    return data


@router.post("/scans/{scan_id}/cancel", response_model=ScanOut)
def cancel_scan(scan_id: int, auth: AuthContext = Depends(current_auth), db: Session = Depends(get_db)) -> Scan:
    scan = db.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No such scan")
    if scan.status == "queued":
        scan.status = "cancelled"
        scan.completed_at = now()
    elif scan.status == "running":
        scan.cancel_requested = True
        if scan.lease_expires_at is None or scan.lease_expires_at < now():
            # The agent is not heartbeating, so it cannot hear the request: end the scan here.
            scan.status = "cancelled"
            scan.completed_at = now()
            scan.error = "Cancelled while the agent was not responding"
    else:
        raise HTTPException(status.HTTP_409_CONFLICT, f"Scan is already {scan.status}")
    audit.record(db, auth.actor, "scan.cancel_requested", "scan", scan.id)
    db.commit()
    return scan


def _fingerprints_in_scan(db: Session, scan_id: int) -> dict[int, FindingRecord]:
    rows = db.execute(
        select(FindingRecord)
        .join(FindingObservation, FindingObservation.finding_id == FindingRecord.id)
        .join(CheckRun, CheckRun.id == FindingObservation.check_run_id)
        .where(CheckRun.scan_id == scan_id)
    ).scalars().unique()
    return {f.id: f for f in rows}


@router.get("/scans/{scan_id}/diff", response_model=ScanDiff)
def diff_scans(scan_id: int, against: int = Query(..., description="The earlier scan to compare with"),
               auth: AuthContext = Depends(current_auth), db: Session = Depends(get_db)) -> ScanDiff:
    scan, base = db.get(Scan, scan_id), db.get(Scan, against)
    if scan is None or base is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No such scan")
    if scan.device_id != base.device_id:
        raise HTTPException(422, "Both scans must be of the same device")
    now_f, base_f = _fingerprints_in_scan(db, scan.id), _fingerprints_in_scan(db, base.id)
    completed_checks = {r.check_id for r in scan.check_runs if r.status in ("passed", "failed")}

    def out(fs: list[FindingRecord]) -> list[FindingOut]:
        return [FindingOut.model_validate(f) for f in sorted(fs, key=lambda f: f.id)]

    return ScanDiff(
        base_scan_id=base.id, scan_id=scan.id,
        new=out([f for i, f in now_f.items() if i not in base_f]),
        # "resolved" only where the later scan actually ran the check; a skipped check proves nothing
        resolved=out([f for i, f in base_f.items() if i not in now_f and f.check_id in completed_checks]),
        unchanged=out([f for i, f in now_f.items() if i in base_f]),
    )


@router.get("/scans/{scan_id}/export")
def export_scan(scan_id: int, auth: AuthContext = Depends(current_auth), db: Session = Depends(get_db)) -> dict[str, Any]:
    scan = db.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No such scan")
    findings = _fingerprints_in_scan(db, scan.id)
    runs = []
    for r in sorted(scan.check_runs, key=lambda r: r.check_id):
        ev = db.execute(select(EvidenceRecord).where(EvidenceRecord.check_run_id == r.id)
                        .order_by(EvidenceRecord.position)).scalars()
        runs.append({
            "check_id": r.check_id, "version": r.check_version, "title": r.title, "status": r.status,
            "skip_reason": r.skip_reason, "error": r.error_message, "ran_elevated": r.ran_elevated,
            "data_collected": r.data_collected, "duration_ms": r.duration_ms,
            "evidence": [{"kind": e.kind, "source": e.source, "sha256": e.content_sha256, "content": e.content,
                          "redacted": e.redacted, "collected_at": e.collected_at.isoformat()} for e in ev],
        })
    audit.record(db, auth.actor, "scan.exported", "scan", scan.id)
    db.commit()
    return {
        "sentinel_export": 1,
        "data_mode": scan.data_mode,
        "scan": ScanOut.model_validate(scan).model_dump(mode="json"),
        "host": scan.host_snapshot,
        "check_runs": runs,
        "findings": [FindingOut.model_validate(f).model_dump(mode="json") for f in findings.values()],
        "limitations": "Only the checks listed ran. A check that passed means that one condition was not "
                       "observed; it does not mean the device is secure.",
    }


@router.get("/checks", response_model=list[CheckCatalogEntry])
def check_catalog(auth: AuthContext = Depends(current_auth), db: Session = Depends(get_db)) -> list[CheckCatalogEntry]:
    merged: dict[str, dict[str, Any]] = {}
    for d in db.execute(select(Device).where(Device.is_active.is_(True))).scalars():
        for c in d.checks_catalog or []:
            entry = merged.setdefault(c["id"], {**c, "device_ids": []})
            entry["device_ids"].append(d.id)
    return [CheckCatalogEntry.model_validate(v) for v in sorted(merged.values(), key=lambda v: v["id"])]
