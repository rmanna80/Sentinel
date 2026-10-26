"""Phase 3: software inventory views and version-aware vulnerability matching.

Matching itself lives in ``services/vuln_matcher.py``; this module wires its hook and tick into the
app and serves the inventory, summary, intel status and vulnerability detail routes. Vulnerability
findings are served by ``/api/findings?source=vuln_matcher``.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from .. import audit
from ..config import get_settings
from ..db import get_db
from ..deps import AuthContext, current_auth
from ..integrations import cvss, nvd, osv
from ..models import Device, FindingRecord, IntelSync, SoftwareRecord, VulnRecord
from ..schemas import ORM, Page
from ..services import hooks
from ..services import vuln_matcher as vm
from ..services.app_settings import integration_enabled
from ..services.findings import OPEN
from ..services.secrets import has_secret

router = APIRouter(prefix="/api", tags=["vulnerabilities"])


def register_hooks() -> None:
    hooks.register("software_ingested", vm.on_software_ingested)
    hooks.register("scan_completed", vm.on_scan_completed)


def tick(db: Session) -> None:
    vm.tick(db)


# =========================================================================== schemas


class SoftwareOut(ORM):
    id: int
    device_id: int
    name: str
    version: str | None
    publisher: str | None
    ecosystem: str
    source: str
    location: str
    install_date: str | None
    first_seen_at: datetime
    last_seen_at: datetime
    last_scan_id: int | None
    is_present: bool
    match_status: str
    match_source: str | None
    match_reason: str | None = None
    open_vulnerabilities: int = 0


class IntelSourceStatus(BaseModel):
    source: str
    label: str
    enabled: bool
    status: str  # never | ok | error | disabled
    last_synced_at: datetime | None
    detail: str | None
    sync_requested: bool
    api_key_configured: bool | None = None  # NVD only
    rate_limit: str | None = None


class QueueStatus(BaseModel):
    waiting: int
    retrying: int
    last_error: str | None


class IntelStatus(BaseModel):
    outbound_enabled: bool
    sources: list[IntelSourceStatus]
    queue: QueueStatus
    kev_catalog_version: str | None
    kev_count: int | None
    msrc_documents: list[str]
    nvd_products_cached: int


class SyncRequest(BaseModel):
    source: Literal["osv", "nvd", "msrc", "kev", "epss", "all"]


class SyncAccepted(BaseModel):
    requested: list[str]
    message: str


class CountItem(BaseModel):
    key: str
    count: int


class AffectedSoftware(BaseModel):
    name: str
    ecosystem: str
    open_findings: int
    highest_severity: str
    kev: bool


class MatchCounts(BaseModel):
    matched: int
    no_source: int
    error: int
    pending: int


class VulnSummary(BaseModel):
    device_id: int | None
    open_total: int
    by_severity: dict[str, int]
    by_ecosystem: list[CountItem]
    by_source: dict[str, int]
    top_affected_software: list[AffectedSoftware]
    kev_count: int
    with_fixed_version: int
    items: MatchCounts
    items_by_ecosystem: dict[str, MatchCounts]
    nvd_not_enriched: int
    nvd_undecidable: int
    not_compared_reasons: list[str]
    last_matched_at: datetime | None
    sources: list[IntelSourceStatus]


class CvssMetricExplained(BaseModel):
    metric: str
    metric_name: str
    value: str
    value_name: str
    meaning: str


class VulnDetail(BaseModel):
    vuln_id: str
    source: str
    aliases: list[str]
    cve_id: str | None
    summary: str | None
    details: str | None
    severity: str | None
    cvss_score: float | None
    cvss_vector: str | None
    cvss_version: str | None
    cvss_source: str | None
    cvss_severity: str | None
    cvss_summary: str | None
    cvss_explained: list[CvssMetricExplained]
    published: str | None
    modified: str | None
    references: list[str]
    nvd_status: str | None
    enrichment_note: str | None
    kev: bool
    kev_date_added: str | None
    kev_ransomware: str | None
    epss: float | None
    epss_percentile: float | None
    fetched_at: datetime
    open_findings: int


# =========================================================================== helpers

_SEVERITIES = ["critical", "high", "medium", "low", "info"]


def _status_rows(db: Session) -> dict[str, IntelSync | None]:
    return {s: db.get(IntelSync, s) for s in (vm.QUEUE, *vm.SOURCES)}


def _source_statuses(db: Session, rows: dict[str, IntelSync | None] | None = None) -> list[IntelSourceStatus]:
    rows = rows or _status_rows(db)
    out = []
    key = has_secret("nvd_api_key")
    for s in vm.SOURCES:
        row = rows.get(s)
        enabled = integration_enabled(db, s)
        data = row.data if row is not None and isinstance(row.data, dict) else {}
        status_value = (row.status if row is not None else "never") if enabled else "disabled"
        out.append(IntelSourceStatus(
            source=s, label=vm.SOURCE_LABELS[s], enabled=enabled, status=status_value,
            last_synced_at=row.last_synced_at if row is not None else None,
            detail=(row.detail if row is not None else None) if enabled else "Turned off in Settings > Integrations",
            sync_requested=bool(data.get("force_requested_at")),
            api_key_configured=key if s == "nvd" else None,
            rate_limit=(f"{nvd.LIMIT_WITH_KEY if key else nvd.LIMIT_WITHOUT_KEY} requests per 30 seconds"
                        if s == "nvd" else None),
        ))
    return out


def _counts(rows: list[tuple[str, int]]) -> MatchCounts:
    d = {k: 0 for k in ("matched", "no_source", "error", "pending")}
    for k, n in rows:
        d[k if k in d else "pending"] += n
    return MatchCounts(**d)


# =========================================================================== routes


@router.get("/software", response_model=Page[SoftwareOut])
def list_software(
    device_id: int | None = None,
    ecosystem: str | None = Query(None, max_length=64),
    q: str | None = Query(None, max_length=200),
    match_status: Literal["matched", "no_source", "pending", "error"] | None = None,
    present_only: bool = True,
    limit: int = Query(200, ge=1, le=2000),
    offset: int = Query(0, ge=0),
    auth: AuthContext = Depends(current_auth),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    stmt = select(SoftwareRecord)
    if device_id is not None:
        stmt = stmt.where(SoftwareRecord.device_id == device_id)
    if ecosystem:
        stmt = stmt.where(SoftwareRecord.ecosystem == ecosystem)
    if q:
        like = f"%{q}%"
        stmt = stmt.where(or_(SoftwareRecord.name.ilike(like), SoftwareRecord.publisher.ilike(like),
                              SoftwareRecord.version.ilike(like), SoftwareRecord.location.ilike(like)))
    if match_status:
        stmt = stmt.where(SoftwareRecord.match_status == match_status)
    if present_only:
        stmt = stmt.where(SoftwareRecord.is_present.is_(True))
    total = db.execute(select(func.count()).select_from(stmt.subquery())).scalar_one()
    rows = db.execute(stmt.order_by(func.lower(SoftwareRecord.name), SoftwareRecord.id).limit(limit).offset(offset)
                      ).scalars().all()
    notes = vm.item_notes(db, device_id)
    open_counts: dict[tuple[int, str], int] = {}
    device_ids = sorted({r.device_id for r in rows})
    if device_ids:
        for dev, affected in db.execute(select(FindingRecord.device_id, FindingRecord.affected_software).where(
                FindingRecord.source == vm.SOURCE, FindingRecord.status.in_(OPEN),
                FindingRecord.device_id.in_(device_ids))).all():
            for part in (affected or "").split(", "):
                if part:
                    open_counts[(dev, part)] = open_counts.get((dev, part), 0) + 1
    items = []
    for r in rows:
        out = SoftwareOut.model_validate(r)
        out.match_reason = notes.get(r.id) or vm.generic_reason(r)
        out.open_vulnerabilities = open_counts.get((r.device_id, f"{r.name} {r.version or ''}".strip()), 0)
        items.append(out)
    return {"items": items, "total": total}


@router.get("/vulnerabilities/summary", response_model=VulnSummary)
def vulnerability_summary(device_id: int | None = None, auth: AuthContext = Depends(current_auth),
                          db: Session = Depends(get_db)) -> VulnSummary:
    if device_id is not None and db.get(Device, device_id) is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No such device")
    fq = select(FindingRecord).where(FindingRecord.source == vm.SOURCE, FindingRecord.status.in_(OPEN))
    if device_id is not None:
        fq = fq.where(FindingRecord.device_id == device_id)
    findings = db.execute(fq).scalars().all()
    by_sev = {s: 0 for s in _SEVERITIES}
    by_eco: dict[str, int] = {}
    by_src: dict[str, int] = {}
    software: dict[tuple[str, str], AffectedSoftware] = {}
    for f in findings:
        by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
        eco = vm.ecosystem_of_subject(f.subject_key)
        by_eco[eco] = by_eco.get(eco, 0) + 1
        src = f.rule_id.removeprefix("vuln.")
        by_src[src] = by_src.get(src, 0) + 1
        name = "Windows" if f.subject_key.startswith("kb:") else f.subject_key.split("|")[1]
        entry = software.get((eco, name))
        if entry is None:
            entry = software[(eco, name)] = AffectedSoftware(name=name, ecosystem=eco, open_findings=0,
                                                              highest_severity=f.severity, kev=False)
        entry.open_findings += 1
        entry.kev = entry.kev or f.kev
        if _SEVERITIES.index(f.severity) < _SEVERITIES.index(entry.highest_severity):
            entry.highest_severity = f.severity
    top = sorted(software.values(), key=lambda s: (_SEVERITIES.index(s.highest_severity), not s.kev,
                                                   -s.open_findings, s.name.lower()))[:10]
    sq = select(SoftwareRecord.ecosystem, SoftwareRecord.match_status, func.count()).where(
        SoftwareRecord.is_present.is_(True))
    if device_id is not None:
        sq = sq.where(SoftwareRecord.device_id == device_id)
    per_eco: dict[str, list[tuple[str, int]]] = {}
    all_rows: list[tuple[str, int]] = []
    for eco, st, n in db.execute(sq.group_by(SoftwareRecord.ecosystem, SoftwareRecord.match_status)).all():
        per_eco.setdefault(eco, []).append((st, n))
        all_rows.append((st, n))
    runs = vm.done_runs(db, device_id)
    nvd_row = db.get(IntelSync, "nvd")
    products = ((nvd_row.data if nvd_row is not None else None) or {}).get("products") or {}
    not_enriched: set[str] = set()
    for key in {k for r in runs for k in r.get("nvd_products") or []}:
        ids = (products.get(key) or {}).get("not_enriched") or []
        not_enriched.update(ids if isinstance(ids, list) else [])
    undecidable = {c for r in runs for c in r.get("nvd_undecidable") or []}
    reasons = sorted({r["not_reconciled_reason"] for r in runs if r.get("not_reconciled_reason")})
    processed = [d for r in runs if (d := vm.parse_time(r.get("processed_at")))]
    return VulnSummary(
        device_id=device_id, open_total=len(findings), by_severity=by_sev,
        by_ecosystem=[CountItem(key=k, count=v) for k, v in sorted(by_eco.items(), key=lambda kv: (-kv[1], kv[0]))],
        by_source=by_src, top_affected_software=top, kev_count=sum(1 for f in findings if f.kev),
        with_fixed_version=sum(1 for f in findings if f.fixed_version),
        items=_counts(all_rows), items_by_ecosystem={k: _counts(v) for k, v in sorted(per_eco.items())},
        nvd_not_enriched=len(not_enriched), nvd_undecidable=len(undecidable), not_compared_reasons=reasons,
        last_matched_at=max(processed) if processed else None, sources=_source_statuses(db),
    )


@router.get("/intel/status", response_model=IntelStatus)
def intel_status(auth: AuthContext = Depends(current_auth), db: Session = Depends(get_db)) -> IntelStatus:
    rows = _status_rows(db)
    q = rows.get(vm.QUEUE)
    qdata = q.data if q is not None and isinstance(q.data, dict) else {}
    items = qdata.get("items") or []
    retrying = [e for e in items if e.get("attempts")]
    kev_data = (rows["kev"].data if rows.get("kev") is not None else None) or {}
    msrc_data = (rows["msrc"].data if rows.get("msrc") is not None else None) or {}
    nvd_data = (rows["nvd"].data if rows.get("nvd") is not None else None) or {}
    return IntelStatus(
        outbound_enabled=get_settings().outbound_enabled, sources=_source_statuses(db, rows),
        queue=QueueStatus(waiting=len(items), retrying=len(retrying),
                          last_error=next((e.get("last_error") for e in retrying if e.get("last_error")), None)),
        kev_catalog_version=kev_data.get("catalogVersion"), kev_count=kev_data.get("count"),
        msrc_documents=sorted((msrc_data.get("documents") or {}).keys()),
        nvd_products_cached=len(nvd_data.get("products") or {}),
    )


@router.post("/intel/sync", response_model=SyncAccepted, status_code=202)
def intel_sync(body: SyncRequest, auth: AuthContext = Depends(current_auth), db: Session = Depends(get_db)) -> SyncAccepted:
    sources = vm.SOURCES if body.source == "all" else (body.source,)
    disabled = [s for s in sources if not integration_enabled(db, s)]
    if body.source != "all" and disabled:
        raise HTTPException(status.HTTP_409_CONFLICT, f"{vm.SOURCE_LABELS[body.source]} is turned off in "
                                                      "Settings > Integrations")
    requested = vm.request_sync(db, body.source)
    audit.record(db, auth.actor, "intel.sync_requested", "intel", body.source, {"sources": requested})
    db.commit()
    return SyncAccepted(requested=requested, message="The sync runs in the background within the next minute.")


@router.get("/vulns/{vuln_id}", response_model=VulnDetail)
def vulnerability_detail(vuln_id: str, auth: AuthContext = Depends(current_auth),
                         db: Session = Depends(get_db)) -> VulnDetail:
    if len(vuln_id) > 64:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No such vulnerability")
    rec = db.execute(select(VulnRecord).where(VulnRecord.vuln_id == vuln_id)).scalar_one_or_none()
    if rec is None:
        # Looked up by CVE: prefer a record that stands for exactly that CVE (DEBIAN-CVE-…, a GHSA with it
        # as alias) over a bundle advisory (DSA, USN, a KB) that merely lists it.
        candidates = db.execute(select(VulnRecord).where(VulnRecord.cve_id == vuln_id)).scalars().all()

        def rank(r: VulnRecord) -> tuple[int, int, float]:
            own = vuln_id in r.vuln_id or (r.source == "osv" and isinstance(r.raw, dict)
                                           and vuln_id in osv.own_cves(r.raw))
            return (0 if own else 1, 0 if r.source != "msrc" else 1, -r.fetched_at.timestamp())

        rec = min(candidates, key=rank) if candidates else None
    if rec is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No such vulnerability in the local cache")
    version = cvss.vector_version(rec.cvss_vector)
    enrichment = None
    if rec.source == "nvd":
        raw = rec.raw if isinstance(rec.raw, dict) else {}
        if not nvd.has_configurations(raw):
            enrichment = ("NVD has not analysed this CVE (status: " + (rec.nvd_status or "unknown") + "), so it lists "
                          "no affected product versions. Sentinel cannot version-match it and does not report it as a "
                          "finding.")
        if rec.cvss_source and rec.cvss_source.startswith("CNA"):
            note = "The score comes from the CVE Numbering Authority because NVD has not scored it."
            enrichment = f"{enrichment} {note}" if enrichment else note
    open_q = select(func.count()).select_from(FindingRecord).where(
        FindingRecord.source == vm.SOURCE, FindingRecord.status.in_(OPEN),
        or_(FindingRecord.vuln_id == rec.vuln_id, FindingRecord.cve_id == (rec.cve_id or rec.vuln_id)))
    return VulnDetail(
        vuln_id=rec.vuln_id, source=rec.source, aliases=list(rec.aliases or []), cve_id=rec.cve_id,
        summary=rec.summary, details=rec.details, severity=rec.severity, cvss_score=rec.cvss_score,
        cvss_vector=rec.cvss_vector, cvss_version=version, cvss_source=rec.cvss_source,
        cvss_severity=cvss.severity_band(rec.cvss_score, version) if rec.cvss_score is not None else None,
        cvss_summary=cvss.summary_sentence(rec.cvss_vector),
        cvss_explained=[CvssMetricExplained(**e) for e in cvss.explain(rec.cvss_vector)],
        published=rec.published, modified=rec.modified, references=list(rec.references or []),
        nvd_status=rec.nvd_status, enrichment_note=enrichment, kev=rec.kev, kev_date_added=rec.kev_date_added,
        kev_ransomware=rec.kev_ransomware, epss=rec.epss, epss_percentile=rec.epss_percentile,
        fetched_at=rec.fetched_at, open_findings=db.execute(open_q).scalar_one(),
    )
