"""Audit history, application settings, integration secrets and the outbound-data log."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .. import audit
from ..db import get_db
from ..deps import AuthContext, current_auth
from ..models import AuditEntry, OutboundRequest
from ..schemas import AuditOut, AuditVerify, Page
from ..services import secrets
from ..services.app_settings import DEFAULTS, get_setting, set_setting

router = APIRouter(prefix="/api", tags=["admin"])

# Secret names an integration may store. Nothing else can be written through the API.
SECRET_NAMES = {"hibp_api_key", "nvd_api_key", "smtp_password"}


@router.get("/audit", response_model=Page[AuditOut])
def list_audit(action: str | None = None, actor: str | None = None, limit: int = Query(100, ge=1, le=1000),
               offset: int = Query(0, ge=0), auth: AuthContext = Depends(current_auth),
               db: Session = Depends(get_db)) -> dict[str, Any]:
    q = select(AuditEntry)
    if action:
        q = q.where(AuditEntry.action.startswith(action))
    if actor:
        q = q.where(AuditEntry.actor == actor)
    total = db.execute(select(func.count()).select_from(q.subquery())).scalar_one()
    items = db.execute(q.order_by(AuditEntry.id.desc()).limit(limit).offset(offset)).scalars().all()
    return {"items": items, "total": total}


@router.get("/audit/verify", response_model=AuditVerify)
def verify_audit(auth: AuthContext = Depends(current_auth), db: Session = Depends(get_db)) -> AuditVerify:
    intact, bad = audit.verify_chain(db)
    n = db.execute(select(func.count(AuditEntry.id))).scalar_one()
    return AuditVerify(intact=intact, first_bad_id=bad, entries=n)


@router.get("/settings")
def get_settings_all(auth: AuthContext = Depends(current_auth), db: Session = Depends(get_db)) -> dict[str, Any]:
    return {key: get_setting(db, key) for key in DEFAULTS}


@router.put("/settings/{key}")
def put_setting(key: str, body: dict[str, Any], auth: AuthContext = Depends(current_auth),
                db: Session = Depends(get_db)) -> dict[str, Any]:
    if key not in DEFAULTS:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Unknown settings group")
    default = DEFAULTS[key]
    unknown = set(body) - set(default)
    if unknown:
        raise HTTPException(422, f"Unknown settings: {sorted(unknown)}")
    merged = {**get_setting(db, key), **body}
    value = set_setting(db, key, merged)
    audit.record(db, auth.actor, "settings.updated", "settings", key, {"fields": sorted(body)})
    db.commit()
    return value


class SecretIn(BaseModel):
    value: str = Field(min_length=1, max_length=512)


class SecretStatus(BaseModel):
    name: str
    configured: bool
    backend: str


@router.get("/secrets", response_model=list[SecretStatus])
def list_secrets(auth: AuthContext = Depends(current_auth)) -> list[SecretStatus]:
    backend = secrets.backend_name()
    return [SecretStatus(name=n, configured=secrets.has_secret(n), backend=backend) for n in sorted(SECRET_NAMES)]


@router.put("/secrets/{name}", response_model=SecretStatus)
def put_secret(name: str, body: SecretIn, auth: AuthContext = Depends(current_auth),
               db: Session = Depends(get_db)) -> SecretStatus:
    if name not in SECRET_NAMES:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Unknown secret")
    where = secrets.set_secret(name, body.value.strip())
    audit.record(db, auth.actor, "secret.set", "secret", name, {"stored_in": where})  # never the value
    db.commit()
    return SecretStatus(name=name, configured=True, backend=secrets.backend_name())


@router.delete("/secrets/{name}", status_code=204)
def delete_secret(name: str, auth: AuthContext = Depends(current_auth), db: Session = Depends(get_db)) -> Response:
    if name not in SECRET_NAMES:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Unknown secret")
    secrets.delete_secret(name)
    audit.record(db, auth.actor, "secret.deleted", "secret", name)
    db.commit()
    return Response(status_code=204)


class OutboundOut(BaseModel):
    model_config = {"from_attributes": True}
    id: int
    ts: Any
    integration: str
    method: str
    host: str
    path: str
    purpose: str
    payload_summary: str
    status_code: int | None
    duration_ms: int | None
    error: str | None


@router.get("/outbound", response_model=Page[OutboundOut])
def list_outbound(integration: str | None = None, limit: int = Query(100, ge=1, le=1000),
                  offset: int = Query(0, ge=0), auth: AuthContext = Depends(current_auth),
                  db: Session = Depends(get_db)) -> dict[str, Any]:
    q = select(OutboundRequest)
    if integration:
        q = q.where(OutboundRequest.integration == integration)
    total = db.execute(select(func.count()).select_from(q.subquery())).scalar_one()
    items = db.execute(q.order_by(OutboundRequest.id.desc()).limit(limit).offset(offset)).scalars().all()
    return {"items": items, "total": total}
