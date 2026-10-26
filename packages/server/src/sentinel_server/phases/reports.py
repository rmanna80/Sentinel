"""Phase 6: PDF, CSV and JSON reports, built on this machine from stored data."""

from __future__ import annotations

import hashlib
import logging
import re
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from fastapi.responses import FileResponse
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import audit
from ..config import Settings
from ..db import get_db
from ..deps import AuthContext, current_auth, settings_dep
from ..models import Device, Report
from ..services.report_builder import collect, render

log = logging.getLogger(__name__)

router = APIRouter(prefix="/api/reports", tags=["reports"])

MEDIA_TYPES = {"pdf": "application/pdf", "csv": "text/csv; charset=utf-8", "json": "application/json"}
_STORED_NAME = re.compile(r"^[0-9a-f]{32}\.(pdf|csv|json)$")


class ReportCreate(BaseModel):
    kind: Literal["pdf", "csv", "json"]
    title: str = Field(min_length=1, max_length=120)
    device_id: int | None = None
    days: int = Field(30, ge=1, le=365)

    @field_validator("title")
    @classmethod
    def _title(cls, v: str) -> str:
        v = " ".join(v.split())
        if not v:
            raise ValueError("title must not be blank")
        return v


class ReportOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    created_at: datetime
    created_by: int | None
    kind: str
    title: str
    scope: dict[str, Any]
    file_name: str
    sha256: str
    size_bytes: int


def reports_dir(settings: Settings) -> Path:
    path = (settings.data_dir / "reports").resolve()
    path.mkdir(parents=True, exist_ok=True)
    return path


def safe_report_path(settings: Settings, file_name: str) -> Path | None:
    """The stored file's path, or None if the name could point anywhere outside the reports folder."""
    if not isinstance(file_name, str) or not _STORED_NAME.fullmatch(file_name):
        return None
    root = reports_dir(settings)
    candidate = (root / file_name).resolve()
    if candidate.parent != root:
        return None
    return candidate


def _download_name(report: Report) -> str:
    slug = re.sub(r"[^A-Za-z0-9]+", "-", report.title).strip("-").lower()[:60] or "report"
    return f"sentinel-{slug}-{report.created_at:%Y%m%d-%H%M}.{report.kind}"


@router.post("", response_model=ReportOut, status_code=201)
def create_report(body: ReportCreate, auth: AuthContext = Depends(current_auth), db: Session = Depends(get_db),
                  settings: Settings = Depends(settings_dep)) -> Report:
    if body.device_id is not None and db.get(Device, body.device_id) is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No such device")
    data = collect(db, settings, title=body.title, device_id=body.device_id, days=body.days)
    content = render(data, body.kind)
    file_name = f"{uuid.uuid4().hex}.{body.kind}"  # generated here, never taken from input
    path = safe_report_path(settings, file_name)
    assert path is not None
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_bytes(content)
    tmp.replace(path)
    digest = hashlib.sha256(content).hexdigest()
    scope = {"device_id": body.device_id, "days": body.days, "fixture_data": data["fixture_data"],
             "devices": [d["id"] for d in data["scope"]["devices"]], "since": data["scope"]["since"],
             "until": data["scope"]["until"]}
    report = Report(created_by=auth.user.id, kind=body.kind, title=body.title, scope=scope, file_name=file_name,
                    sha256=digest, size_bytes=len(content))
    try:
        db.add(report)
        db.flush()
        audit.record(db, auth.actor, "report.created", "report", report.id,
                     {"kind": body.kind, "device_id": body.device_id, "days": body.days, "sha256": digest,
                      "size_bytes": len(content), "fixture_data": data["fixture_data"]})
        db.commit()
    except Exception:
        db.rollback()
        path.unlink(missing_ok=True)
        raise
    return report


@router.get("", response_model=list[ReportOut])
def list_reports(limit: int = Query(200, ge=1, le=1000), auth: AuthContext = Depends(current_auth),
                 db: Session = Depends(get_db)) -> list[Report]:
    return list(db.execute(select(Report).order_by(Report.created_at.desc(), Report.id.desc()).limit(limit)).scalars())


def _get(db: Session, report_id: int) -> Report:
    r = db.get(Report, report_id)
    if r is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No such report")
    return r


@router.get("/{report_id}", response_model=ReportOut)
def get_report(report_id: int, auth: AuthContext = Depends(current_auth), db: Session = Depends(get_db)) -> Report:
    return _get(db, report_id)


@router.get("/{report_id}/download", response_model=None)
def download_report(report_id: int, auth: AuthContext = Depends(current_auth), db: Session = Depends(get_db),
                    settings: Settings = Depends(settings_dep)) -> FileResponse:
    r = _get(db, report_id)
    path = safe_report_path(settings, r.file_name)
    if path is None:
        log.warning("refused report %s: stored file name is not a generated report name", r.id)
        raise HTTPException(status.HTTP_403_FORBIDDEN, "The report file is not inside the reports folder")
    if not path.is_file():
        raise HTTPException(status.HTTP_410_GONE, "The report file is missing from disk")
    audit.record(db, auth.actor, "report.downloaded", "report", r.id, {"kind": r.kind})
    db.commit()
    return FileResponse(path, media_type=MEDIA_TYPES.get(r.kind, "application/octet-stream"),
                        filename=_download_name(r), headers={"X-Content-SHA256": r.sha256})


@router.delete("/{report_id}", status_code=204)
def delete_report(report_id: int, auth: AuthContext = Depends(current_auth), db: Session = Depends(get_db),
                  settings: Settings = Depends(settings_dep)) -> Response:
    r = _get(db, report_id)
    path = safe_report_path(settings, r.file_name)
    if path is not None:
        path.unlink(missing_ok=True)
    else:
        log.warning("report %s has an unexpected file name; database row removed, no file touched", r.id)
    db.delete(r)
    audit.record(db, auth.actor, "report.deleted", "report", report_id, {"kind": r.kind, "file_removed": path is not None})
    db.commit()
    return Response(status_code=204)
