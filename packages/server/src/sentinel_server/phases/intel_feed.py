"""Threat-intelligence advisory feed.

Pulls security stories from Hacker News, matches them against this install's software inventory and open
findings, and surfaces them as advisories a person reads. It deliberately does NOT modify any check code:
the most it will do is draft a plain-text "possible coverage gap" note (``suggested_coverage``) for a human
to review. Nothing an advisory carries is ever executed.
"""

from __future__ import annotations

import logging
import re
from datetime import timedelta
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from .. import audit
from ..db import get_db
from ..deps import AuthContext, current_auth
from ..integrations import hackernews, http
from ..models import Advisory, FindingRecord, IntelSync, SoftwareRecord, now
from ..services.app_settings import get_setting, integration_enabled
from ..services.findings import OPEN
from ..services.notify import notify

log = logging.getLogger(__name__)
router = APIRouter(prefix="/api", tags=["advisories"])
SYNC_SOURCE = "hackernews"

# Common words in product names that would match far too many headlines.
_STOPWORDS = frozenset({
    "microsoft", "windows", "google", "apple", "adobe", "oracle", "system", "systems", "software", "update",
    "security", "client", "server", "service", "services", "tools", "driver", "drivers", "runtime", "framework",
    "library", "package", "edition", "version", "release", "manager", "studio", "office", "player", "viewer",
    "application", "desktop", "mobile", "cloud", "online", "standard", "professional", "community", "enterprise",
    "python", "node", "data", "core", "based", "intel", "amd", "nvidia", "realtek", "common", "shared",
})
_WORD = re.compile(r"[a-z0-9][a-z0-9.+#-]{2,}")


def _inventory_terms(db: Session) -> dict[str, str]:
    """Map a distinctive lowercase product token -> the software name it came from (present software only)."""
    terms: dict[str, str] = {}
    rows = db.execute(select(SoftwareRecord.name).where(SoftwareRecord.is_present.is_(True)).distinct()).scalars()
    for name in rows:
        for tok in _WORD.findall(name.lower()):
            if len(tok) >= 4 and tok not in _STOPWORDS and tok.isascii():
                terms.setdefault(tok, name)
    return terms


def _kev_cves(db: Session) -> set[str]:
    row = db.get(IntelSync, "kev")
    data = (row.data if row is not None else None) or {}
    return {c.upper() for c in (data.get("cves") or {})}


def _open_finding_cves(db: Session) -> set[str]:
    rows = db.execute(select(FindingRecord.cve_id).where(FindingRecord.cve_id.is_not(None),
                                                         FindingRecord.status.in_(OPEN))).scalars()
    return {c.upper() for c in rows if c}


def _match(item: hackernews.HnItem, terms: dict[str, str], kev: set[str], open_cves: set[str]) -> dict[str, Any]:
    text = f"{item.title} {item.url or ''}".lower()
    words = set(_WORD.findall(text))
    hit_software = sorted({terms[w] for w in words if w in terms})[:10]
    kev_hits = sorted(set(item.cve_ids) & kev)
    finding_hits = sorted(set(item.cve_ids) & open_cves)
    matched = bool(hit_software or kev_hits or finding_hits)
    if kev_hits or finding_hits:
        severity = "high"
    elif hit_software:
        severity = "medium"
    else:
        severity = "info"
    detail: dict[str, Any] = {}
    if hit_software:
        detail["software"] = hit_software
    if kev_hits:
        detail["kev_cves"] = kev_hits
    if finding_hits:
        detail["finding_cves"] = finding_hits
    return {"matched": matched, "severity_hint": severity, "match_detail": detail,
            "suggested_coverage": _suggest(hit_software, kev_hits, finding_hits)}


def _suggest(software: list[str], kev_cves: list[str], finding_cves: list[str]) -> str | None:
    """A plain-text note for a human to review. Never code, never applied automatically."""
    if finding_cves:
        return (f"This references {', '.join(finding_cves)}, which matches an open finding on your fleet. "
                "Confirm it is the same issue and prioritise that finding.")
    if kev_cves:
        return (f"{', '.join(kev_cves)} is in CISA's Known Exploited Vulnerabilities list (actively exploited). "
                "Check whether anything you run is affected and patch it first.")
    if software:
        return (f"You have {', '.join(software)} in your inventory. Check whether your version is affected; "
                "turn on OSV/NVD matching under Integrations, or read the vendor advisory. "
                "If it applies, track it as a finding. Sentinel will not change any check on its own.")
    return None


def _upsert(db: Session, item: hackernews.HnItem, match: dict[str, Any]) -> tuple[Advisory, bool]:
    adv = db.execute(select(Advisory).where(Advisory.source == SYNC_SOURCE,
                                            Advisory.external_id == item.object_id)).scalar_one_or_none()
    created = adv is None
    if adv is None:
        adv = Advisory(source=SYNC_SOURCE, external_id=item.object_id, status="new", fetched_at=now())
        db.add(adv)
    adv.title = item.title
    adv.url = item.url
    adv.author = item.author
    adv.score = item.points
    adv.tags = item.tags
    adv.cve_ids = item.cve_ids
    adv.published_at = item.created_at
    adv.matched = match["matched"]
    adv.match_detail = match["match_detail"]
    adv.severity_hint = match["severity_hint"]
    adv.suggested_coverage = match["suggested_coverage"]
    db.flush()
    return adv, created


def _due(row: IntelSync | None, refresh_hours: int) -> bool:
    if row is None or row.last_synced_at is None:
        return True
    if (row.data or {}).get("refresh_requested"):
        return True
    return now() - row.last_synced_at >= timedelta(hours=max(1, refresh_hours))


def tick(db: Session) -> None:
    if not integration_enabled(db, SYNC_SOURCE):
        return
    cfg = get_setting(db, "integrations").get(SYNC_SOURCE, {})
    row = db.get(IntelSync, SYNC_SOURCE)
    if not _due(row, int(cfg.get("refresh_hours", 6))):
        return
    if row is None:
        row = IntelSync(source=SYNC_SOURCE)
        db.add(row)
    since = row.last_synced_at - timedelta(hours=1) if row.last_synced_at else now() - timedelta(days=7)
    try:
        items = hackernews.fetch(min_points=int(cfg.get("min_points", 20)), since=since)
    except http.OutboundDisabled:
        row.status, row.detail = "disabled", "Outbound connections are turned off"
        return
    except http.OutboundError as exc:
        row.status, row.detail = "error", str(exc)[:500]
        return
    terms, kev, open_cves = _inventory_terms(db), _kev_cves(db), _open_finding_cves(db)
    new_matched = 0
    for item in items:
        match = _match(item, terms, kev, open_cves)
        adv, created = _upsert(db, item, match)
        if created and adv.matched and not adv.notified:
            adv.notified = True
            new_matched += 1
            notify(db, severity=adv.severity_hint, kind="advisory",
                   title=f"Security news may affect you: {adv.title}", body=adv.suggested_coverage or "",
                   link=f"/advisories/{adv.id}", dedupe_key=f"advisory:{adv.id}")
    row.last_synced_at = now()
    row.status = "ok"
    row.detail = f"{len(items)} stories, {new_matched} new and matched to your inventory"
    row.data = {"refresh_requested": False}


# --------------------------------------------------------------------------- API


class AdvisoryOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    source: str
    title: str
    url: str | None
    summary: str
    author: str | None
    score: int | None
    tags: list[str]
    cve_ids: list[str]
    matched: bool
    match_detail: dict[str, Any]
    severity_hint: str
    suggested_coverage: str | None
    status: str
    published_at: Any
    fetched_at: Any
    read_at: Any


class AdvisoryPage(BaseModel):
    items: list[AdvisoryOut]
    total: int


class AdvisoryUpdate(BaseModel):
    status: str  # new | read | pinned | dismissed


class FeedStatus(BaseModel):
    enabled: bool
    outbound_enabled: bool
    last_synced_at: Any
    status: str
    detail: str | None
    total: int
    new_count: int
    matched_open: int
    pinned: int
    note: str


_ALLOWED_STATUS = {"new", "read", "pinned", "dismissed"}


@router.get("/advisories", response_model=AdvisoryPage)
def list_advisories(status_filter: str | None = Query(None, alias="status"), matched: bool | None = None,
                    source: str | None = None, q: str | None = Query(None, max_length=200),
                    limit: int = Query(50, ge=1, le=500), offset: int = Query(0, ge=0),
                    auth: AuthContext = Depends(current_auth), db: Session = Depends(get_db)) -> dict[str, Any]:
    stmt = select(Advisory)
    if status_filter == "all":
        pass  # include dismissed
    elif status_filter:
        stmt = stmt.where(Advisory.status == status_filter)
    else:
        stmt = stmt.where(Advisory.status != "dismissed")  # the default view hides dismissed
    if matched is not None:
        stmt = stmt.where(Advisory.matched.is_(matched))
    if source:
        stmt = stmt.where(Advisory.source == source)
    if q:
        like = f"%{q}%"
        stmt = stmt.where(or_(Advisory.title.ilike(like), Advisory.summary.ilike(like)))
    total = db.execute(select(func.count()).select_from(stmt.subquery())).scalar_one()
    order = [Advisory.matched.desc(), Advisory.published_at.desc().nulls_last()]
    items = db.execute(stmt.order_by(*order).limit(limit).offset(offset)).scalars().all()
    return {"items": items, "total": total}


@router.get("/advisories/summary", response_model=FeedStatus)
def advisory_summary(auth: AuthContext = Depends(current_auth), db: Session = Depends(get_db)) -> FeedStatus:
    from ..config import get_settings

    row = db.get(IntelSync, SYNC_SOURCE)
    total = db.execute(select(func.count(Advisory.id))).scalar_one()
    new_count = db.execute(select(func.count(Advisory.id)).where(Advisory.status == "new")).scalar_one()
    matched_open = db.execute(select(func.count(Advisory.id)).where(
        Advisory.matched.is_(True), Advisory.status.in_(("new", "read", "pinned")))).scalar_one()
    pinned = db.execute(select(func.count(Advisory.id)).where(Advisory.status == "pinned")).scalar_one()
    return FeedStatus(
        enabled=integration_enabled(db, SYNC_SOURCE), outbound_enabled=get_settings().outbound_enabled,
        last_synced_at=row.last_synced_at if row else None, status=row.status if row else "never",
        detail=row.detail if row else None, total=total, new_count=new_count, matched_open=matched_open,
        pinned=pinned,
        note="Headlines from Hacker News matched to your inventory. Advisories are information to read; "
             "Sentinel never changes a check on its own.",
    )


@router.get("/advisories/{advisory_id}", response_model=AdvisoryOut)
def get_advisory(advisory_id: int, auth: AuthContext = Depends(current_auth), db: Session = Depends(get_db)) -> Advisory:
    adv = db.get(Advisory, advisory_id)
    if adv is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No such advisory")
    if adv.status == "new":
        adv.status = "read"
        adv.read_at = now()
        db.commit()
    return adv


@router.patch("/advisories/{advisory_id}", response_model=AdvisoryOut)
def update_advisory(advisory_id: int, body: AdvisoryUpdate, auth: AuthContext = Depends(current_auth),
                    db: Session = Depends(get_db)) -> Advisory:
    adv = db.get(Advisory, advisory_id)
    if adv is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No such advisory")
    if body.status not in _ALLOWED_STATUS:
        raise HTTPException(422, f"status must be one of {sorted(_ALLOWED_STATUS)}")
    adv.status = body.status
    if body.status in ("read", "pinned") and adv.read_at is None:
        adv.read_at = now()
    audit.record(db, auth.actor, "advisory.updated", "advisory", adv.id, {"status": body.status})
    db.commit()
    return adv


@router.post("/intel/feed/refresh", response_model=FeedStatus)
def refresh_feed(auth: AuthContext = Depends(current_auth), db: Session = Depends(get_db)) -> FeedStatus:
    if not integration_enabled(db, SYNC_SOURCE):
        raise HTTPException(409, "The Hacker News feed is turned off. Turn it on under Integrations first.")
    row = db.get(IntelSync, SYNC_SOURCE)
    if row is None:
        row = IntelSync(source=SYNC_SOURCE)
        db.add(row)
    row.data = {**(row.data or {}), "refresh_requested": True}
    audit.record(db, auth.actor, "advisory.refresh_requested")
    db.commit()
    return advisory_summary(auth, db)
