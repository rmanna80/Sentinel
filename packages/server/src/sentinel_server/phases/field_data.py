"""Field Data: store, show and correlate data the user captured with their own equipment.

This is the import side only. Sentinel does not drive any radio or capture anything itself; a person uploads
a file their own tooling produced (for example a passive Wi-Fi survey from scripts/field/wifi-survey.sh).
The correlation is defensive: against the networks you tell Sentinel are yours, it flags an access point
broadcasting your SSID from an unknown radio (a possible evil twin) and any of your own networks that are
open or using WEP. Other people's networks are listed as "unknown" and never treated as targets.
"""

from __future__ import annotations

import hashlib
import io
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .. import audit
from ..db import get_db
from ..deps import AuthContext, current_auth
from ..models import FieldCapture, FieldObservation
from ..services.app_settings import get_setting, set_setting
from ..services.notify import notify

router = APIRouter(prefix="/api/field", tags=["field-data"])

MAX_CSV_BYTES = 1_500_000
MAX_OBSERVATIONS = 5000
_AP_HEADER_PREFIX = "BSSID,"
_STATION_HEADER_PREFIX = "Station MAC,"


def normalize_privacy(raw: str) -> str:
    up = raw.upper()
    if "WPA3" in up:
        return "wpa3"
    if "WPA2" in up:
        return "wpa2"
    if "WPA" in up:
        return "wpa"
    if "WEP" in up:
        return "wep"
    if "OPN" in up or not up.strip():
        return "open"
    return up.strip().lower()[:16]


def parse_airodump_csv(text: str) -> list[dict[str, Any]]:
    """Parse the access-point section of an airodump-ng CSV into observation dicts.

    Only the AP table is read; the station (client) section is ignored, so no client MAC addresses are stored.
    """
    aps: list[dict[str, Any]] = []
    in_aps = False
    reader = io.StringIO(text)
    for line in reader:
        row = line.rstrip("\n")
        if row.startswith(_AP_HEADER_PREFIX):
            in_aps = True
            continue
        if row.startswith(_STATION_HEADER_PREFIX):
            break
        if not in_aps or not row.strip():
            continue
        cols = [c.strip() for c in row.split(",")]
        if len(cols) < 14:
            continue
        bssid = cols[0].upper()
        if len(bssid) != 17 or bssid.count(":") != 5:
            continue
        essid = cols[13]
        aps.append({
            "bssid": bssid, "ssid": essid, "channel": cols[3], "privacy": normalize_privacy(cols[5]),
            "cipher": cols[6], "auth": cols[7], "power": cols[4], "first_seen": cols[1], "last_seen": cols[2],
        })
        if len(aps) >= MAX_OBSERVATIONS:
            break
    return aps


def _classify_ap(ap: dict[str, Any], own_ssids: set[str], own_bssids: set[str]) -> tuple[str, str, str]:
    """Return (classification, severity, note) for one access point."""
    ssid = (ap.get("ssid") or "").strip()
    bssid = (ap.get("bssid") or "").upper()
    privacy = ap.get("privacy", "open")
    ssid_is_mine = bool(ssid) and ssid.lower() in own_ssids
    bssid_is_mine = bssid in own_bssids
    if ssid_is_mine and not bssid_is_mine:
        return ("rogue_suspect", "high",
                f"An access point ({bssid}) is broadcasting your network name \"{ssid}\" but is not a radio you "
                "listed as yours. This can be an evil-twin access point. Confirm it is your own hardware; if not, "
                "do not connect to that SSID and investigate where it is coming from.")
    if bssid_is_mine and privacy in ("open", "wep"):
        sev = "high" if privacy == "open" else "medium"
        word = "has no encryption" if privacy == "open" else "uses WEP, which is broken"
        return ("weak_own", sev, f"Your access point \"{ssid or bssid}\" {word}. Reconfigure it to WPA2 or WPA3.")
    if bssid_is_mine or ssid_is_mine:
        return ("own", "info", "")
    return ("unknown", "info", "")


# --------------------------------------------------------------------------- schemas


class ObservationIn(BaseModel):
    kind: str = Field(default="generic", max_length=32)
    key: str = Field(default="", max_length=256)
    label: str = Field(default="", max_length=256)
    data: dict[str, Any] = Field(default_factory=dict)


class CaptureIn(BaseModel):
    kind: str = Field(pattern=r"^(wifi_survey|rf_survey|host_report|generic)$")
    source_label: str = Field(default="", max_length=128)
    notes: str = Field(default="", max_length=4000)
    airodump_csv: str | None = Field(default=None, max_length=MAX_CSV_BYTES)
    observations: list[ObservationIn] | None = Field(default=None, max_length=MAX_OBSERVATIONS)


class ObservationOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    kind: str
    key: str
    label: str
    data: dict[str, Any]
    classification: str
    severity: str
    note: str


class CaptureOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    kind: str
    source_label: str
    notes: str
    uploaded_at: datetime
    original_format: str
    sha256: str
    size_bytes: int
    record_count: int
    summary: dict[str, Any]


class CaptureDetail(CaptureOut):
    observations: list[ObservationOut]


class CapturePage(BaseModel):
    items: list[CaptureOut]
    total: int


class KnownNetworks(BaseModel):
    own_ssids: list[str] = Field(default_factory=list, max_length=200)
    own_bssids: list[str] = Field(default_factory=list, max_length=200)


class FieldSummary(BaseModel):
    captures: int
    access_points: int
    rogue_suspects: int
    weak_own: int
    own: int
    unknown: int
    known_networks: KnownNetworks
    note: str


# --------------------------------------------------------------------------- routes


def _own(db: Session) -> tuple[set[str], set[str]]:
    cfg = get_setting(db, "field_data")
    return ({s.strip().lower() for s in cfg.get("own_ssids", []) if s.strip()},
            {b.strip().upper() for b in cfg.get("own_bssids", []) if b.strip()})


@router.get("/known-networks", response_model=KnownNetworks)
def get_known_networks(auth: AuthContext = Depends(current_auth), db: Session = Depends(get_db)) -> KnownNetworks:
    cfg = get_setting(db, "field_data")
    return KnownNetworks(own_ssids=cfg.get("own_ssids", []), own_bssids=cfg.get("own_bssids", []))


@router.put("/known-networks", response_model=KnownNetworks)
def put_known_networks(body: KnownNetworks, auth: AuthContext = Depends(current_auth),
                       db: Session = Depends(get_db)) -> KnownNetworks:
    ssids = [s.strip() for s in body.own_ssids if s.strip()][:200]
    bssids = []
    for b in body.own_bssids:
        b = b.strip().upper()
        if b and (len(b) != 17 or b.count(":") != 5):
            raise HTTPException(422, f"{b!r} is not a MAC address like AA:BB:CC:DD:EE:FF")
        if b:
            bssids.append(b)
    set_setting(db, "field_data", {"own_ssids": ssids, "own_bssids": bssids[:200]})
    audit.record(db, auth.actor, "field.known_networks_updated", None, None,
                 {"ssids": len(ssids), "bssids": len(bssids)})
    db.commit()
    return KnownNetworks(own_ssids=ssids, own_bssids=bssids)


def _build_observations(body: CaptureIn, own_ssids: set[str], own_bssids: set[str]) -> tuple[list[dict[str, Any]], str, str]:
    """Return (observation dicts, original raw text for hashing, original_format)."""
    if body.airodump_csv is not None:
        aps = parse_airodump_csv(body.airodump_csv)
        obs = []
        for ap in aps:
            classification, severity, note = _classify_ap(ap, own_ssids, own_bssids)
            obs.append({"kind": "access_point", "key": ap["bssid"], "label": ap.get("ssid") or "(hidden)",
                        "data": ap, "classification": classification, "severity": severity, "note": note})
        return obs, body.airodump_csv, "airodump_csv"
    obs = []
    for o in (body.observations or [])[:MAX_OBSERVATIONS]:
        classification, severity, note = "unknown", "info", ""
        if o.kind == "access_point":
            ap = {"bssid": (o.key or "").upper(), "ssid": o.label, **o.data}
            classification, severity, note = _classify_ap(ap, own_ssids, own_bssids)
        obs.append({"kind": o.kind, "key": o.key, "label": o.label, "data": o.data,
                    "classification": classification, "severity": severity, "note": note})
    import json as _json

    return obs, _json.dumps([o.model_dump() for o in (body.observations or [])], sort_keys=True), "json"


@router.post("/captures", response_model=CaptureDetail, status_code=201)
def create_capture(body: CaptureIn, auth: AuthContext = Depends(current_auth),
                   db: Session = Depends(get_db)) -> dict[str, Any]:
    if body.airodump_csv is None and not body.observations:
        raise HTTPException(422, "Provide either airodump_csv or observations")
    own_ssids, own_bssids = _own(db)
    obs, raw, fmt = _build_observations(body, own_ssids, own_bssids)
    summary = {
        "access_points": sum(1 for o in obs if o["kind"] == "access_point"),
        "rogue_suspects": sum(1 for o in obs if o["classification"] == "rogue_suspect"),
        "weak_own": sum(1 for o in obs if o["classification"] == "weak_own"),
        "own": sum(1 for o in obs if o["classification"] == "own"),
        "unknown": sum(1 for o in obs if o["classification"] == "unknown"),
        "open": sum(1 for o in obs if o.get("data", {}).get("privacy") == "open"),
    }
    capture = FieldCapture(
        kind=body.kind, source_label=body.source_label[:128], notes=body.notes, uploaded_by=auth.user.id,
        original_format=fmt, sha256=hashlib.sha256(raw.encode("utf-8")).hexdigest(),
        size_bytes=len(raw.encode("utf-8")), record_count=len(obs), summary=summary,
    )
    db.add(capture)
    db.flush()
    for o in obs:
        db.add(FieldObservation(capture_id=capture.id, **o))
    audit.record(db, auth.actor, "field.capture_uploaded", "field_capture", capture.id,
                 {"kind": body.kind, "records": len(obs), "rogue_suspects": summary["rogue_suspects"]})
    db.flush()
    for o in obs:
        if o["classification"] in ("rogue_suspect", "weak_own"):
            notify(db, severity=o["severity"], kind="field",
                   title=f"Wi-Fi survey: {o['note'][:200]}", body=o["note"],
                   link=f"/field/{capture.id}", dedupe_key=f"field:{capture.id}:{o['key']}:{o['classification']}")
    db.commit()
    return _detail(db, capture)


def _detail(db: Session, capture: FieldCapture) -> dict[str, Any]:
    data = CaptureOut.model_validate(capture).model_dump()
    obs = db.execute(select(FieldObservation).where(FieldObservation.capture_id == capture.id)
                     .order_by(FieldObservation.severity.desc(), FieldObservation.id)).scalars().all()
    data["observations"] = [ObservationOut.model_validate(o) for o in obs]
    return data


@router.get("/captures", response_model=CapturePage)
def list_captures(kind: str | None = None, limit: int = Query(50, ge=1, le=500), offset: int = Query(0, ge=0),
                  auth: AuthContext = Depends(current_auth), db: Session = Depends(get_db)) -> dict[str, Any]:
    stmt = select(FieldCapture)
    if kind:
        stmt = stmt.where(FieldCapture.kind == kind)
    total = db.execute(select(func.count()).select_from(stmt.subquery())).scalar_one()
    items = db.execute(stmt.order_by(FieldCapture.uploaded_at.desc()).limit(limit).offset(offset)).scalars().all()
    return {"items": items, "total": total}


@router.get("/captures/{capture_id}", response_model=CaptureDetail)
def get_capture(capture_id: int, auth: AuthContext = Depends(current_auth),
                db: Session = Depends(get_db)) -> dict[str, Any]:
    capture = db.get(FieldCapture, capture_id)
    if capture is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No such capture")
    return _detail(db, capture)


@router.delete("/captures/{capture_id}", status_code=204)
def delete_capture(capture_id: int, auth: AuthContext = Depends(current_auth),
                   db: Session = Depends(get_db)) -> Response:
    capture = db.get(FieldCapture, capture_id)
    if capture is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No such capture")
    db.delete(capture)
    audit.record(db, auth.actor, "field.capture_deleted", "field_capture", capture_id)
    db.commit()
    return Response(status_code=204)


@router.get("/summary", response_model=FieldSummary)
def field_summary(auth: AuthContext = Depends(current_auth), db: Session = Depends(get_db)) -> FieldSummary:
    def count(classification: str) -> int:
        return db.execute(select(func.count(FieldObservation.id)).where(
            FieldObservation.classification == classification)).scalar_one()

    cfg = get_setting(db, "field_data")
    return FieldSummary(
        captures=db.execute(select(func.count(FieldCapture.id))).scalar_one(),
        access_points=db.execute(select(func.count(FieldObservation.id)).where(
            FieldObservation.kind == "access_point")).scalar_one(),
        rogue_suspects=count("rogue_suspect"), weak_own=count("weak_own"), own=count("own"),
        unknown=count("unknown"),
        known_networks=KnownNetworks(own_ssids=cfg.get("own_ssids", []), own_bssids=cfg.get("own_bssids", [])),
        note="Upload a passive Wi-Fi survey (scripts/field/wifi-survey.sh). Add your own SSIDs and AP MAC "
             "addresses under Known networks so Sentinel can spot an evil twin or a weakly-secured network of yours.",
    )
