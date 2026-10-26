"""Version-aware vulnerability matching for inventory check runs, plus KEV, EPSS and MSRC syncs.

Flow:

* ``on_software_ingested`` (hook, database only) marks the check's software as pending and puts
  (device, scan, check run, check id, ecosystems) on a small queue stored in ``IntelSync("vuln_queue")``.
* ``tick`` takes the queue, matches ALL present software of that check's ecosystems (OSV for
  Debian/Ubuntu/PyPI/npm, Microsoft's update guide for the Windows OS build, NVD for a curated list
  of Windows apps) and reconciles the results like an agent check run, so findings dedupe, resolve
  (verified, because the inventory was re-read) and reopen the usual way.
* If any source fails, nothing is reconciled (an incomplete set would wrongly resolve findings): the
  items are marked ``error`` and the run is retried later with backoff.

All network work happens before the first database write of a tick, so ingestion is never blocked
behind a slow download. Every write to shared ``IntelSync`` rows re-reads them under the write lock.
"""

from __future__ import annotations

import copy
import logging
import re
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from sentinel_core.models import SEVERITY_RANK, Confidence, Finding, FindingKind, Severity
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.orm import Session

from ..config import get_settings
from ..integrations import cvss, epss, kev, msrc, nvd, osv
from ..integrations.http import OutboundDisabled
from ..models import CheckRun, Device, FindingRecord, IntelSync, Scan, SoftwareRecord, VulnRecord, now
from . import hooks
from .app_settings import integration_enabled
from .findings import OPEN, reconcile
from .secrets import get_secret

log = logging.getLogger(__name__)

QUEUE = "vuln_queue"
SOURCES = ("osv", "msrc", "nvd", "kev", "epss")
SOURCE_LABELS = {
    "osv": "OSV.dev (Debian, Ubuntu, PyPI, npm packages)",
    "msrc": "Microsoft Security Update Guide (Windows builds)",
    "nvd": "NIST NVD (curated list of common Windows apps)",
    "kev": "CISA Known Exploited Vulnerabilities",
    "epss": "FIRST EPSS exploitation likelihood",
}
SOURCE = "vuln_matcher"
CATEGORY = "vulnerability"

OSV_REFRESH = timedelta(days=7)
NVD_REFRESH = timedelta(hours=24)
MSRC_REFRESH = timedelta(hours=24)
DAILY = timedelta(hours=24)
SYNC_RETRY = timedelta(hours=1)
EPSS_MISSING_RETRY = timedelta(hours=1)
MAX_BACKOFF = timedelta(hours=6)
MAX_OSV_DETAILS_PER_TICK = 300
MAX_RUNS_PER_TICK = 5
TICK_BUDGET_SECONDS = 20.0
UNRATED_SEVERITY = Severity.MEDIUM
UNRATED_NOTE = ("No source has rated this vulnerability's severity yet; Sentinel lists it as medium "
                "until one does.")

WINDOWS_OS_ECOSYSTEMS = ("windows-os",)
REASON_NOT_CURATED = ("Not in Sentinel's curated list of Windows apps that NVD describes reliably; "
                      "matching by name alone would produce false alarms")
REASON_DISABLED = "{label} is turned off in Settings > Integrations"
REASON_OUTBOUND_OFF = "Outbound connections are turned off, so no vulnerability source can be asked"


# =========================================================================== small helpers


def _iso(dt: datetime | None) -> str | None:
    return dt.isoformat() if dt else None


def _parse(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(str(value))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=now().tzinfo)


parse_time = _parse


def _older_than(dt: datetime | None, age: timedelta, t: datetime) -> bool:
    return dt is None or t - dt >= age


def _data(row: IntelSync | None) -> dict[str, Any]:
    return copy.deepcopy(row.data) if row is not None and isinstance(row.data, dict) else {}


def ensure_rows(db: Session) -> None:
    """Create the IntelSync rows if missing. As a write statement it also takes SQLite's write lock."""
    insert = pg_insert if db.get_bind().dialect.name == "postgresql" else sqlite_insert
    db.execute(insert(IntelSync).values([{"source": s, "status": "never", "data": {}} for s in (QUEUE, *SOURCES)])
               .on_conflict_do_nothing(index_elements=["source"]))


def source_for(ecosystem: str) -> str | None:
    if ecosystem in WINDOWS_OS_ECOSYSTEMS:
        return "msrc"
    if ecosystem == "windows-registry":
        return "nvd"
    if osv.supports(ecosystem):
        return "osv"
    return None


def ecosystem_of_subject(subject_key: str) -> str:
    if subject_key.startswith("kb:"):
        return "windows-os"
    return subject_key.split("|", 1)[0]


def run_key(device_id: int, check_id: str) -> str:
    return f"{device_id}|{check_id}"


def _windows_build(device: Device) -> int | None:
    b = msrc.parse_build(device.os_build)
    return b[2] if b else None


def generic_reason(item: SoftwareRecord) -> str | None:
    """Why an item has its match status, when no run-specific note says more."""
    src = source_for(item.ecosystem)
    if item.match_status == "pending":
        return "Waiting for the next vulnerability lookup"
    if item.match_status == "error":
        return "The last lookup failed; it will be retried automatically"
    if item.match_status == "matched":
        return {"osv": "Checked against OSV.dev", "nvd": "Checked against NVD's product data",
                "msrc": "Checked against Microsoft's security update guide"}.get(item.match_source or "", "Checked")
    if src is None:
        return f"No reliable vulnerability source covers the '{item.ecosystem}' ecosystem"
    if src == "nvd":
        return REASON_NOT_CURATED
    if not item.version:
        return "No version number was reported, so it cannot be compared"
    return None


# =========================================================================== hook


_NON_DISTRO = {"windows-registry", "windows-os", "PyPI", "npm"}
KNOWN_CHECK_ECOSYSTEMS: dict[str, Callable[[str], bool]] = {
    "win.software.inventory": lambda e: e == "windows-registry",
    "win.os.inventory": lambda e: e in WINDOWS_OS_ECOSYSTEMS,
    "linux.packages": lambda e: e not in _NON_DISTRO,
    "dev.dependencies": lambda e: e in ("PyPI", "npm"),
}


def on_software_ingested(db: Session, device: Device, scan: Scan, check_run: CheckRun) -> None:
    """Database only: mark this check's software pending and queue it for matching."""
    rows = db.execute(select(SoftwareRecord).where(SoftwareRecord.device_id == device.id,
                                                   SoftwareRecord.last_scan_id == scan.id,
                                                   SoftwareRecord.is_present.is_(True))).scalars().all()
    if not rows:
        return
    belongs = KNOWN_CHECK_ECOSYSTEMS.get(check_run.check_id)
    if belongs is not None:
        ecosystems = sorted({r.ecosystem for r in rows if belongs(r.ecosystem)})
    else:
        # Unknown inventory check: the ingest stamps every item of one result with the same
        # last_seen_at, so the newest stamp in this scan identifies the ecosystems just reported.
        latest = max(r.last_seen_at for r in rows)
        ecosystems = sorted({r.ecosystem for r in rows if r.last_seen_at == latest})
    if not ecosystems:
        return
    for r in rows:
        if r.ecosystem in ecosystems:
            r.match_status = "pending"
    retire_dropped_ecosystems(db, device.id, scan.id, check_run.check_id, ecosystems)
    enqueue(db, device_id=device.id, scan_id=scan.id, check_run_id=check_run.id, check_id=check_run.check_id,
            ecosystems=ecosystems)


def on_scan_completed(db: Session, scan: Scan) -> None:
    """An inventory check that completed but reported no software at all (ingest fires no software hook
    then): everything it reported before is gone, so its items become absent and it is matched again,
    which resolves its findings. Database only."""
    row = db.get(IntelSync, QUEUE)
    data = _data(row)
    done, items = data.get("done") or {}, data.get("items") or []
    for run in scan.check_runs:
        if run.status not in ("passed", "failed"):
            continue
        key = run_key(scan.device_id, run.check_id)
        known = done.get(key)
        queued = next((e for e in items if e.get("device_id") == scan.device_id and e.get("check_id") == run.check_id),
                      None)
        if known is None and queued is None:
            continue  # never an inventory check that reported software
        if run.id in {(known or {}).get("check_run_id"), (queued or {}).get("check_run_id")}:
            continue  # it reported software in this scan and is already queued
        ecosystems = set((known or {}).get("ecosystems") or []) | set((queued or {}).get("ecosystems") or [])
        if not ecosystems:
            continue  # nothing was present before either
        for r in db.execute(select(SoftwareRecord).where(
                SoftwareRecord.device_id == scan.device_id, SoftwareRecord.ecosystem.in_(sorted(ecosystems)),
                SoftwareRecord.is_present.is_(True))).scalars():
            r.is_present = False
        enqueue(db, device_id=scan.device_id, scan_id=scan.id, check_run_id=run.id, check_id=run.check_id,
                ecosystems=[])


def retire_dropped_ecosystems(db: Session, device_id: int, scan_id: int, check_id: str, ecosystems: list[str]) -> None:
    """Items of an ecosystem this check reported last time but not now (e.g. after a distro upgrade from
    Debian:12 to Debian:13) were not seen in this scan, so they are no longer present."""
    row = db.get(IntelSync, QUEUE)
    data = _data(row)
    before: set[str] = set((data.get("done") or {}).get(run_key(device_id, check_id), {}).get("ecosystems") or [])
    for e in data.get("items") or []:
        if e.get("device_id") == device_id and e.get("check_id") == check_id:
            before.update(e.get("ecosystems") or [])
    dropped = sorted(before - set(ecosystems))
    if not dropped:
        return
    for r in db.execute(select(SoftwareRecord).where(
            SoftwareRecord.device_id == device_id, SoftwareRecord.ecosystem.in_(dropped),
            SoftwareRecord.is_present.is_(True), SoftwareRecord.last_scan_id != scan_id)).scalars():
        r.is_present = False


def enqueue(db: Session, *, device_id: int, scan_id: int, check_run_id: int, check_id: str,
            ecosystems: list[str]) -> None:
    ensure_rows(db)
    row = db.get(IntelSync, QUEUE, populate_existing=True, with_for_update=True)
    assert row is not None
    data = _data(row)
    items = [e for e in data.get("items", []) if not (e.get("device_id") == device_id and e.get("check_id") == check_id)]
    items.append({"device_id": device_id, "scan_id": scan_id, "check_run_id": check_run_id, "check_id": check_id,
                  "ecosystems": ecosystems, "queued_at": _iso(now()), "attempts": 0, "next_at": None,
                  "last_error": None})
    data["items"] = items
    row.data = data
    row.status = "ok"
    row.detail = f"{len(items)} inventory run(s) waiting for matching"


# =========================================================================== caches


OWNER_PRIORITY = {"msrc": 3, "nvd": 2, "osv": 1}


class VulnCache:
    """VulnRecord rows by vuln_id, loaded on demand; new rows stay pending until the write phase.

    A CVE id can be both an NVD record and an OSV record id. NVD needs its copy persisted (it is not
    downloaded per vulnerability), so the higher-priority source owns the row and the other keeps its
    copy in memory for the current tick only (OSV simply downloads it again next time).
    """

    def __init__(self, db: Session, stamp: Callable[[VulnRecord], None] | None = None) -> None:
        self.db = db
        self.stamp = stamp
        self.rows: dict[str, VulnRecord | None] = {}
        self.memory: dict[str, dict[str, Any]] = {}  # records we could not store (id owned by another source)

    def load(self, ids: Iterable[str]) -> None:
        missing = [i for i in dict.fromkeys(ids) if i not in self.rows]
        for start in range(0, len(missing), 500):
            chunk = missing[start:start + 500]
            stmt = select(VulnRecord).where(VulnRecord.vuln_id.in_(chunk))
            found = {r.vuln_id: r for r in self.db.execute(stmt).scalars()}
            for i in chunk:
                self.rows[i] = found.get(i)

    def get(self, vuln_id: str) -> VulnRecord | None:
        if vuln_id not in self.rows:
            self.load([vuln_id])
        return self.rows.get(vuln_id)

    def raw(self, vuln_id: str, source: str) -> dict[str, Any] | None:
        if vuln_id in self.memory:
            return self.memory[vuln_id]
        row = self.get(vuln_id)
        if row is None or row.source != source or not isinstance(row.raw, dict):
            return None
        return row.raw

    def put(self, vuln_id: str, source: str, raw: dict[str, Any], **fields: Any) -> VulnRecord | None:
        row = self.get(vuln_id)
        if row is not None and row.source != source:
            if OWNER_PRIORITY.get(source, 0) < OWNER_PRIORITY.get(row.source, 0):
                self.memory[vuln_id] = raw
                return None
            row.source = source
            row.nvd_status = None
        self.memory.pop(vuln_id, None)
        if row is None:
            row = VulnRecord(vuln_id=vuln_id, source=source)
            self.db.add(row)
            self.rows[vuln_id] = row
        row.raw = raw
        row.fetched_at = now()
        for k, v in fields.items():
            setattr(row, k, v)
        if self.stamp is not None:
            self.stamp(row)
        return row


def _osv_fields(record: dict[str, Any]) -> dict[str, Any]:
    rating = osv.record_rating(record)
    rid = str(record.get("id"))
    return dict(
        aliases=[i for i in osv.all_ids(record) if i != rid][:100],
        cve_id=osv.cve_of(record),
        summary=(record.get("summary") or None),
        details=(str(record.get("details"))[:20000] if record.get("details") else None),
        cvss_score=rating.score if rating else None,
        cvss_vector=(rating.vector[:200] if rating and rating.vector else None),
        cvss_source=(rating.source[:128] if rating else None),
        severity=(rating.severity if rating else None),
        published=record.get("published"),
        modified=record.get("modified"),
        references=osv.references(record, 30),
    )


def _nvd_fields(record: dict[str, Any]) -> dict[str, Any]:
    score = nvd.pick_score(record.get("metrics"))
    desc = nvd.english_description(record)
    refs = [f"https://nvd.nist.gov/vuln/detail/{record.get('id')}", *(record.get("references") or [])]
    return dict(
        aliases=[], cve_id=record.get("id"), summary=None, details=desc[:20000] if desc else None,
        cvss_score=score.score, cvss_vector=score.vector[:200] if score.vector else None,
        cvss_source=score.source, severity=cvss.finding_severity(score.score, score.version),
        published=record.get("published"), modified=record.get("lastModified"),
        references=list(dict.fromkeys(refs))[:30], nvd_status=(str(record.get("vulnStatus"))[:64]
                                                              if record.get("vulnStatus") else None),
    )


# =========================================================================== run outcome


class Deferred(Exception):
    """Not an error: the run continues on a later tick (rate limit or download budget)."""

    def __init__(self, until: datetime, reason: str) -> None:
        super().__init__(reason)
        self.until = until
        self.reason = reason


@dataclass
class ItemResult:
    status: str  # matched | no_source | error | pending
    source: str | None = None
    reason: str | None = None


@dataclass
class RunOutcome:
    entry: dict[str, Any]
    device: Device | None = None
    scan: Scan | None = None
    check_run: CheckRun | None = None
    items: list[SoftwareRecord] = field(default_factory=list)
    ecosystems: list[str] = field(default_factory=list)
    results: dict[int, ItemResult] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)
    stats: dict[str, int] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
    disabled: list[str] = field(default_factory=list)
    deferred: Deferred | None = None
    drop_reason: str | None = None
    nvd_products: list[str] = field(default_factory=list)
    nvd_undecidable: list[str] = field(default_factory=list)

    @property
    def ready(self) -> bool:
        return self.drop_reason is None and self.deferred is None and not self.errors and not self.disabled

    def bump(self, key: str, n: int = 1) -> None:
        self.stats[key] = self.stats.get(key, 0) + n

    @property
    def key(self) -> str:
        return run_key(self.entry["device_id"], self.entry["check_id"])


@dataclass
class SyncDelta:
    status: str | None = None
    detail: str | None = None
    synced: bool = False
    attempted: bool = False
    data: dict[str, Any] = field(default_factory=dict)
    clear_force: str | None = None


# =========================================================================== finding construction


def _cut(s: str, n: int) -> str:
    return s if len(s) <= n else s[: n - 1] + "…"


def _sev(value: str | None) -> Severity:
    try:
        return Severity(value) if value else UNRATED_SEVERITY
    except ValueError:
        return UNRATED_SEVERITY


def _first_sentence(text: str | None, limit: int = 600) -> str:
    if not text:
        return ""
    text = re.sub(r"\s+", " ", text).strip()
    m = re.match(r"(.{20,}?[.!?])(\s|$)", text)
    return _cut(m.group(1) if m else text, limit)


def _merge_findings(findings: list[tuple[Finding, str | None]]) -> list[Finding]:
    """One finding per subject (the same vulnerable package in several projects becomes one finding)."""
    merged: dict[str, tuple[Finding, list[str], list[str], list[str]]] = {}
    for f, location in findings:
        key = f.subject_key.strip().lower()
        if key not in merged:
            merged[key] = (f, [f.affected_software or ""], [f.fixed_version or ""], [location] if location else [])
            continue
        base, affected, fixed, locations = merged[key]
        affected.append(f.affected_software or "")
        fixed.append(f.fixed_version or "")
        if location:
            locations.append(location)
        if SEVERITY_RANK[f.severity] > SEVERITY_RANK[base.severity]:
            merged[key] = (f, affected, fixed, locations)
    out = []
    for f, affected, fixed, locations in merged.values():
        aff = ", ".join(a for a in dict.fromkeys(affected) if a)
        fix = ", ".join(x for x in dict.fromkeys(fixed) if x) or None
        impact = f.impact
        locs = list(dict.fromkeys(locations))
        if locs:
            impact = _cut(f"{impact} Found in: {', '.join(locs)}.", 4000)
        out.append(f.model_copy(update={"affected_software": _cut(aff, 512) or None,
                                        "fixed_version": _cut(fix, 256) if fix else None, "impact": impact}))
    return out


def _upgrade_hint(ecosystem: str, name: str, fixed: str) -> str:
    base = ecosystem.split(":", 1)[0]
    if base in ("Debian", "Ubuntu"):
        return " Install your distribution's updates, for example with 'sudo apt update && sudo apt upgrade'."
    if ecosystem == "PyPI":
        return f" For example: pip install --upgrade \"{name}>={fixed}\" in that project's environment."
    if ecosystem == "npm":
        return f" For example: npm install {name}@^{fixed} in that project, or update the package that depends on it."
    return ""


def osv_finding(item: SoftwareRecord, members: list[dict[str, Any]], representative: str,
                rating: osv.Rating, fixed: str | None, cve: str | None, end_of_life: bool = False) -> Finding:
    name, version, eco = item.name, item.version or "", item.ecosystem
    rep = next((m for m in members if m.get("id") == representative), members[0])
    summary = next((str(m["summary"]) for m in members if m.get("summary")), None)
    label = cve or representative
    title = _cut(f"{label} in {name} {version}" + (f": {summary}" if summary else ""), 300)
    what = summary or _first_sentence(next((m.get("details") for m in members if m.get("details")), None))
    impact_parts = [what or f"{name} {version} is listed as affected by {label}."]
    if rating.note:
        impact_parts.append(rating.note + ".")
    if rating.severity is None:
        impact_parts.append(UNRATED_NOTE)
    if end_of_life:
        impact_parts.append(f"{eco.split(':', 1)[0]} no longer provides security updates for this package "
                            "in this release.")
        remediation = (f"{eco.split(':', 1)[0]} no longer provides security updates for {name} in this release. "
                       "Upgrade to a supported release, or remove the package if it is not needed.")
    elif fixed:
        remediation = f"Update {name} to {fixed} or later.{_upgrade_hint(eco, name, fixed)}"
    else:
        remediation = (f"No fixed version of {name} is listed yet. Remove it if it is not needed, limit its exposure, "
                       "and re-scan after the maintainers publish a fix.")
    refs = []
    for m in members:
        refs += osv.references(m, 10)
    return Finding(
        rule_id="vuln.osv", subject_key=_cut(f"{eco}|{name}|{representative}", 512), title=title,
        severity=_sev(rating.severity), confidence=Confidence.HIGH, kind=FindingKind.VERIFIED,
        impact=_cut(" ".join(p.strip() for p in impact_parts if p), 4000), remediation=_cut(remediation, 8000),
        references=list(dict.fromkeys(refs))[:20], evidence_refs=[], category=CATEGORY,
        vuln_id=_cut(str(rep.get("id")), 64), cve_id=cve, cvss_score=rating.score,
        cvss_vector=rating.vector[:200] if rating.vector else None, cvss_source=_cut(rating.source, 128),
        affected_software=_cut(f"{name} {version}".strip(), 512), fixed_version=_cut(fixed, 256) if fixed else None,
    )


def nvd_finding(item: SoftwareRecord, app: nvd.CuratedApp, inst: nvd.Installed, record: dict[str, Any],
                match: nvd.ConfigMatch) -> Finding:
    cve = str(record.get("id"))
    score = nvd.pick_score(record.get("metrics"))
    severity = cvss.finding_severity(score.score, score.version) if score.score is not None else None
    status = record.get("vulnStatus")
    impact = [_first_sentence(nvd.english_description(record)) or f"{app.label} {inst.version} is affected by {cve}."]
    if severity is None:
        impact.append(UNRATED_NOTE)
    if status:
        impact.append(f"NVD analysis status: {status}.")
    impact.append(f"Matched by comparing the installed version with NVD's affected-version data for {app.label}.")
    if match.fixed_version:
        remediation = f"Update {app.label} to {match.fixed_version} or later."
    elif match.last_affected:
        remediation = f"Update {app.label} to a version newer than {match.last_affected}."
    else:
        remediation = f"Update {app.label} to the latest version; check the vendor's security advisory for {cve}."
    refs = [f"https://nvd.nist.gov/vuln/detail/{cve}", *(record.get("references") or [])[:10]]
    shown_version = inst.version + (f" {inst.update}" if inst.update else "")
    return Finding(
        rule_id="vuln.nvd", subject_key=_cut(f"windows-registry|{app.label}|{cve}", 512),
        title=_cut(f"{cve} in {app.label} {shown_version}", 300), severity=_sev(severity),
        confidence=Confidence.MEDIUM, kind=FindingKind.HEURISTIC, impact=_cut(" ".join(impact), 4000),
        remediation=remediation, references=list(dict.fromkeys(refs))[:20], evidence_refs=[], category=CATEGORY,
        vuln_id=cve, cve_id=cve, cvss_score=score.score, cvss_vector=score.vector[:200] if score.vector else None,
        cvss_source=score.source, affected_software=_cut(f"{item.name} {item.version or ''}".strip(), 512),
        fixed_version=match.fixed_version,
    )


def msrc_finding(item: SoftwareRecord, product: str, entry: dict[str, Any]) -> Finding:
    kb = entry["kb"]
    cves = entry.get("cves") or {}
    score, vector, top = msrc.kb_score(entry)
    severity, source = msrc.kb_severity(entry)
    exploited = sorted(c for c, i in cves.items() if i.get("exploited"))
    ranked = sorted(cves.items(), key=lambda kv: (-(kv[1].get("score") or 0), kv[0]))
    examples = ", ".join(f"{c} ({i.get('title')})" for c, i in ranked[:3])
    impact = (f"Microsoft's update KB{kb} fixes {len(cves)} vulnerabilit{'y' if len(cves) == 1 else 'ies'} in {product}"
              + (f", including {examples}" if examples else "") + ".")
    if exploited:
        impact += f" Microsoft reports active exploitation of {', '.join(exploited[:5])}."
    if severity is None:
        impact += " " + UNRATED_NOTE
    fixed = str(entry.get("fixed_build") or "")
    remediation = ("Open Settings > Windows Update and select 'Check for updates', install everything offered, "
                   f"then restart. KB{kb} brings Windows to build {fixed} or later.")
    refs = [u for u in [entry.get("url"), f"https://support.microsoft.com/help/{kb}"] if u]
    refs += [f"https://msrc.microsoft.com/update-guide/vulnerability/{c}" for c, _ in ranked[:10]]
    return Finding(
        rule_id="vuln.msrc", subject_key=f"kb:{kb}", title=_cut(f"Windows update KB{kb} is not installed", 300),
        severity=_sev(severity), confidence=Confidence.HIGH, kind=FindingKind.VERIFIED, impact=_cut(impact, 4000),
        remediation=remediation, references=list(dict.fromkeys(refs))[:20], evidence_refs=[], category=CATEGORY,
        vuln_id=f"KB{kb}", cve_id=top, cvss_score=score, cvss_vector=vector[:200] if vector else None,
        cvss_source=source, affected_software=_cut(f"{item.name} {item.version or ''}".strip(), 512),
        fixed_version=fixed or None,
    )


# =========================================================================== the tick


class Tick:
    def __init__(self, db: Session, budget_seconds: float = TICK_BUDGET_SECONDS) -> None:
        self.db = db
        self.t = now()
        self.deadline = time.monotonic() + budget_seconds
        self.rows = {s: db.get(IntelSync, s) for s in (QUEUE, *SOURCES)}
        self.data = {s: _data(r) for s, r in self.rows.items()}
        self.deltas: dict[str, SyncDelta] = {}
        self.vulns = VulnCache(db, self.stamp_record)
        self.outcomes: list[RunOutcome] = []
        self.requeue: set[str] = set()
        self.kev_map: dict[str, list[Any]] = dict(self.data["kev"].get("cves") or {})
        self.epss_map: dict[str, list[Any]] = dict(self.data["epss"].get("scores") or {})
        self.kev_changed = False
        self.epss_changed = False
        self.osv_details_fetched = 0
        self.msrc_digests: list[dict[str, Any]] | None = None
        self.msrc_failure: Exception | None = None
        self.enabled = {s: integration_enabled(db, s) for s in SOURCES}

    # ------------------------------------------------------------------ sync bookkeeping

    def delta(self, source: str) -> SyncDelta:
        return self.deltas.setdefault(source, SyncDelta())

    def forced(self, source: str) -> str | None:
        token = self.data[source].get("force_requested_at")
        return str(token) if token else None

    def refresh_before(self, source: str) -> datetime | None:
        """Cached data fetched before this moment must be downloaded again (set by 'Sync now')."""
        stamps = [d for d in (_parse(self.data[source].get("refresh_before")), _parse(self.forced(source))) if d]
        return max(stamps) if stamps else None

    def last_synced(self, source: str) -> datetime | None:
        row = self.rows.get(source)
        return row.last_synced_at if row is not None else None

    def last_attempt(self, source: str) -> datetime | None:
        return _parse(self.data[source].get("last_attempt_at"))

    def due(self, source: str, every: timedelta) -> bool:
        if self.forced(source):
            return True
        if not _older_than(self.last_synced(source), every, self.t):
            return False
        return _older_than(self.last_attempt(source), SYNC_RETRY, self.t)

    def _handled(self, source: str, d: SyncDelta) -> None:
        if source in ("kev", "epss", "msrc"):  # osv and nvd refreshes are handled by apply_forced_refresh
            d.clear_force = self.forced(source) or d.clear_force

    def ok(self, source: str, detail: str, **data: Any) -> None:
        d = self.delta(source)
        d.status, d.detail, d.synced, d.attempted = "ok", detail, True, True
        d.data.update(data)
        self._handled(source, d)

    def failed(self, source: str, detail: str, exc: BaseException | None = None) -> None:
        d = self.delta(source)
        if isinstance(exc, OutboundDisabled):
            d.status, d.detail, d.attempted = "disabled", REASON_OUTBOUND_OFF, True
        else:
            d.status, d.detail, d.attempted = "error", _cut(detail, 1000), True
        self._handled(source, d)

    def disabled(self, source: str) -> None:
        d = self.delta(source)
        d.status, d.detail = "disabled", "Turned off in Settings > Integrations"
        self._handled(source, d)

    # ------------------------------------------------------------------ KEV / EPSS / MSRC

    def has_present_software(self, ecosystems: tuple[str, ...] | None = None) -> bool:
        q = select(SoftwareRecord.id).where(SoftwareRecord.is_present.is_(True))
        if ecosystems:
            q = q.where(SoftwareRecord.ecosystem.in_(ecosystems))
        return self.db.execute(q.limit(1)).first() is not None

    def sync_kev(self) -> None:
        if not self.enabled["kev"]:
            if self.forced("kev") or (self.rows["kev"] is not None and self.rows["kev"].status != "disabled"):
                self.disabled("kev")
            return
        if not self.due("kev", DAILY) or not (self.forced("kev") or self.has_present_software()):
            return
        try:
            catalog = kev.fetch_catalog()
        except Exception as exc:  # any failure is reported, never raised
            self.failed("kev", f"Could not download the KEV catalog: {exc}", exc)
            return
        self.kev_map = catalog["cves"]
        self.kev_changed = True
        self.ok("kev", f"{catalog['count']} known exploited vulnerabilities (catalog {catalog.get('catalogVersion')})",
                cves=catalog["cves"], catalogVersion=catalog.get("catalogVersion"),
                dateReleased=catalog.get("dateReleased"), count=catalog["count"])

    def open_vuln_cves(self, extra: Iterable[Finding] = ()) -> set[str]:
        cves: set[str] = set()
        kbs: set[str] = set()
        for cve_id, vuln_id in self.db.execute(
            select(FindingRecord.cve_id, FindingRecord.vuln_id).where(FindingRecord.source == SOURCE,
                                                                      FindingRecord.status.in_(OPEN))
        ).all():
            if vuln_id and vuln_id.startswith("KB"):
                kbs.add(vuln_id)
            elif cve_id:
                cves.add(cve_id)
        for f in extra:
            if f.vuln_id and f.vuln_id.startswith("KB"):
                kbs.add(f.vuln_id)
            elif f.cve_id:
                cves.add(f.cve_id)
        self.vulns.load(kbs)
        for kb in kbs:
            row = self.vulns.get(kb)
            if row is not None:
                cves.update(a for a in row.aliases or [] if a.startswith("CVE-"))
        return cves

    def sync_epss(self) -> None:
        if not self.enabled["epss"]:
            if self.forced("epss") or (self.rows["epss"] is not None and self.rows["epss"].status != "disabled"):
                self.disabled("epss")
            return
        new_findings = [f for o in self.outcomes if o.ready for f in o.findings]
        wanted = self.open_vuln_cves(new_findings)
        if not wanted:
            if self.forced("epss"):
                self.ok("epss", "No open vulnerability findings with CVE identifiers", scores={})
            return
        missing = wanted - set(self.epss_map)
        full = self.due("epss", DAILY)
        if not full and (not missing or not _older_than(self.last_attempt("epss"), EPSS_MISSING_RETRY, self.t)):
            return
        ask = sorted(wanted if full else missing)
        try:
            scores = epss.fetch_scores(ask)
        except Exception as exc:  # reported, never raised
            self.failed("epss", f"Could not download EPSS scores: {exc}", exc)
            return
        merged = {} if full else {k: v for k, v in self.epss_map.items() if k in wanted}
        for cve, s in scores.items():
            merged[cve] = [s["epss"], s.get("percentile"), s.get("date")] if s else [None, None, None]
        self.epss_map = merged
        self.epss_changed = True
        have = sum(1 for v in merged.values() if v and v[0] is not None)
        self.ok("epss", f"Scores for {have} of {len(wanted)} CVEs in open findings", scores=merged)

    def msrc(self, force: bool = False) -> list[dict[str, Any]]:
        """The newest three monthly digests, downloading only documents that changed."""
        if self.msrc_digests is not None:
            return self.msrc_digests
        if self.msrc_failure is not None:
            raise self.msrc_failure
        try:
            return self._load_msrc(force)
        except Exception as exc:
            self.msrc_failure = exc
            raise

    def _load_msrc(self, force: bool) -> list[dict[str, Any]]:
        cached: dict[str, Any] = dict(self.data["msrc"].get("documents") or {})
        fresh = not _older_than(self.last_synced("msrc"), MSRC_REFRESH, self.t)
        if cached and fresh and not force:
            self.msrc_digests = sorted(cached.values(), key=lambda d: str(d.get("initial_release") or ""), reverse=True)
            return self.msrc_digests
        index = msrc.fetch_index()[: msrc.MONTHS]
        if not index:
            raise msrc.MsrcError("Microsoft's update list is empty")
        docs: dict[str, Any] = {}
        downloaded = 0
        for entry in index:
            old = cached.get(entry["ID"])
            if old and not force and old.get("current_release") == entry.get("CurrentReleaseDate"):
                docs[entry["ID"]] = old
                continue
            d = msrc.digest(msrc.fetch_document(entry), entry)
            d["id"] = entry["ID"]
            d["initial_release"] = entry.get("InitialReleaseDate")
            docs[entry["ID"]] = d
            downloaded += 1
        if set(docs) != set(cached) or downloaded:
            self.requeue.add("msrc")
        self.ok("msrc", f"Using {', '.join(sorted(docs))}; downloaded {downloaded} updated document(s)",
                documents=docs)
        self.msrc_digests = sorted(docs.values(), key=lambda d: str(d.get("initial_release") or ""), reverse=True)
        return self.msrc_digests

    def sync_msrc(self) -> None:
        if not self.enabled["msrc"]:
            if self.forced("msrc"):
                self.disabled("msrc")
            return
        forced = bool(self.forced("msrc"))
        if not forced and not (self.due("msrc", MSRC_REFRESH) and self.has_present_software(WINDOWS_OS_ECOSYSTEMS)):
            return
        try:
            self.msrc(force=forced)
        except Exception as exc:  # reported, never raised
            self.failed("msrc", f"Could not download Microsoft's update data: {exc}", exc)

    # ------------------------------------------------------------------ queue processing

    def due_entries(self) -> list[dict[str, Any]]:
        """Queued runs that are due, then earlier runs to redo now: those skipped while a source was
        off (and it is back on), and those using a source a person asked to refresh."""
        queue = self.data[QUEUE]
        items = [e for e in queue.get("items", []) if isinstance(e, dict)]
        ready = [e for e in items if not e.get("next_at") or (_parse(e["next_at"]) or self.t) <= self.t]
        ready.sort(key=lambda e: str(e.get("queued_at") or ""))
        pending = {run_key(e["device_id"], e["check_id"]) for e in items}
        forced = {src for src in ("osv", "nvd", "msrc") if self.forced(src) and self.enabled[src]}
        redo = set(self.unreconciled_ready(queue))
        for key, done in sorted((queue.get("done") or {}).items()):
            if key in pending:
                continue
            uses = {source_for(eco) for eco in done.get("ecosystems") or []}
            if key in redo or uses & forced:
                ready.append({"device_id": done["device_id"], "scan_id": done["scan_id"],
                              "check_run_id": done["check_run_id"], "check_id": done["check_id"],
                              "ecosystems": done.get("ecosystems") or [], "queued_at": _iso(self.t), "attempts": 0,
                              "next_at": None, "last_error": None, "synthetic": True})
        return ready

    def process_queue(self) -> None:
        for entry in self.due_entries()[:MAX_RUNS_PER_TICK]:
            if time.monotonic() > self.deadline:
                break
            outcome = RunOutcome(entry=entry)
            try:
                self.match_run(outcome)
            except Exception as exc:  # a bug in one run must not stop the others
                log.exception("vulnerability matching failed for %s", outcome.key)
                outcome.errors.append(f"Internal error: {exc}")
            self.outcomes.append(outcome)

    def run_ecosystems(self, entry: dict[str, Any]) -> list[str]:
        """This check's ecosystems now, before (recorded), and in its open findings."""
        ecos = set(entry.get("ecosystems") or [])
        done = (self.data[QUEUE].get("done") or {}).get(run_key(entry["device_id"], entry["check_id"])) or {}
        ecos.update(done.get("ecosystems") or [])
        for subject in self.db.execute(select(FindingRecord.subject_key).where(
                FindingRecord.device_id == entry["device_id"], FindingRecord.check_id == entry["check_id"],
                FindingRecord.source == SOURCE, FindingRecord.status.in_(OPEN))).scalars():
            ecos.add(ecosystem_of_subject(subject))
        return sorted(ecos)

    def match_run(self, o: RunOutcome) -> None:
        e = o.entry
        o.device = self.db.get(Device, e["device_id"])
        o.scan = self.db.get(Scan, e["scan_id"])
        o.check_run = self.db.get(CheckRun, e["check_run_id"])
        if o.device is None or o.scan is None or o.check_run is None:
            o.drop_reason = "device, scan or check run no longer exists"
            return
        o.ecosystems = self.run_ecosystems(e)
        o.items = list(self.db.execute(select(SoftwareRecord).where(
            SoftwareRecord.device_id == o.device.id, SoftwareRecord.is_present.is_(True),
            SoftwareRecord.ecosystem.in_(o.ecosystems))).scalars())
        groups: dict[str | None, list[SoftwareRecord]] = {}
        for item in o.items:
            groups.setdefault(source_for(item.ecosystem), []).append(item)
        for src, items in groups.items():
            if src is None:
                for it in items:
                    o.results[it.id] = ItemResult("no_source")
                continue
            if not self.enabled[src]:
                o.disabled.append(src)
                self.disabled(src)
                for it in items:
                    o.results[it.id] = ItemResult("no_source", None, REASON_DISABLED.format(label=SOURCE_LABELS[src]))
                continue
            try:
                {"osv": self.match_osv, "nvd": self.match_nvd, "msrc": self.match_msrc}[src](o, items)
            except Deferred as d:
                o.deferred = d
                return
            except OutboundDisabled as exc:
                o.disabled.append(src)
                self.failed(src, REASON_OUTBOUND_OFF, exc)
                for it in items:
                    o.results[it.id] = ItemResult("no_source", None, REASON_OUTBOUND_OFF)
            except Exception as exc:  # every source failure is reported, never guessed around
                log.warning("%s lookup failed for %s: %s", src, o.key, exc)
                o.errors.append(f"{src}: {exc}")
                self.failed(src, f"Lookup failed: {exc}")

    # ------------------------------------------------------------------ OSV

    def osv_stale(self, vuln_id: str, modified: str | None) -> bool:
        row = self.vulns.get(vuln_id)
        if row is None or row.source != "osv" or not isinstance(row.raw, dict):
            return True
        if modified and row.modified and modified != row.modified:
            return True
        refresh_before = self.refresh_before("osv")
        if refresh_before and row.fetched_at < refresh_before:
            return True
        return _older_than(row.fetched_at, OSV_REFRESH, self.t)

    def match_osv(self, o: RunOutcome, items: list[SoftwareRecord]) -> None:
        keys: dict[tuple[str, str, str], osv.Query] = {}
        for it in items:
            if not it.version:
                o.results[it.id] = ItemResult("no_source", None, "No version number was reported, so it cannot be compared")
                continue
            keys.setdefault((it.ecosystem, it.name, it.version), osv.Query(it.name, it.ecosystem, it.version))
        if not keys:
            return
        order = list(keys)
        answers = osv.query_batch([keys[k] for k in order])
        ids_for = {k: [vid for vid, _ in ans] for k, ans in zip(order, answers, strict=True)}
        modified = {vid: mod for ans in answers for vid, mod in ans}
        self.vulns.load(modified)
        stale = [vid for vid in modified if self.osv_stale(vid, modified[vid])]
        budget = MAX_OSV_DETAILS_PER_TICK - self.osv_details_fetched
        for vid in stale[:max(budget, 0)]:
            record = osv.get_vuln(vid)
            self.osv_details_fetched += 1
            if record is None:
                continue  # OSV no longer serves it; it cannot be described, so it is left out
            self.vulns.put(vid, "osv", osv.slim(record), **_osv_fields(record))
        if len(stale) > budget:
            self.ok("osv", f"Downloading vulnerability details ({budget} this round, {len(stale) - budget} to go)")
            raise Deferred(self.t + timedelta(seconds=1), "more OSV details to download")
        found: list[tuple[Finding, str | None]] = []
        for it in items:
            if not it.version:
                continue
            ids = ids_for[(it.ecosystem, it.name, it.version)]
            records = {vid: r for vid in ids if (r := self.vulns.raw(vid, "osv")) is not None}
            for group in osv.group_records(ids, records):
                members = [records[i] for i in group.ids]
                if osv.distro_unimportant(members, it.name, it.ecosystem):
                    o.bump("distro_unimportant")
                    continue
                rating = osv.best_rating(members, it.name, it.ecosystem)
                fixed = next((f for m in members if (f := osv.fixed_version(m, it.name, it.ecosystem, it.version))), None)
                eol = osv.distro_end_of_life(members, it.name, it.ecosystem)
                found.append((osv_finding(it, members, group.representative, rating, fixed, osv.group_cve(members), eol),
                              it.location or None))
            o.results[it.id] = ItemResult("matched", "osv")
        o.findings.extend(_merge_findings(found))
        self.ok("osv", f"Checked {len(keys)} package version(s); {len(modified)} known vulnerability record(s) matched")

    # ------------------------------------------------------------------ NVD (curated Windows apps)

    def nvd_product(self, vendor: str, product: str, api_key: str | None) -> list[str]:
        key = nvd.product_key(vendor, product)
        products = self.delta("nvd").data.setdefault("products", dict(self.data["nvd"].get("products") or {}))
        cached = products.get(key)
        fetched = _parse(cached.get("fetched_at")) if cached else None
        refresh_before = self.refresh_before("nvd")
        if fetched and not _older_than(fetched, NVD_REFRESH, self.t) and not (refresh_before and fetched < refresh_before):
            return list(cached.get("cve_ids") or []) if cached else []
        try:
            records = nvd.fetch_product(vendor, product, api_key)
        except nvd.RateLimited as rl:
            how = "with an API key" if api_key else "without an API key (add one in Settings to go 10x faster)"
            d = self.delta("nvd")
            d.detail = f"Pacing requests to NVD's limit {how}; continuing shortly"
            raise Deferred(self.t + timedelta(seconds=max(rl.wait, 1.0)), "NVD rate limit") from rl
        records = [r for r in records if r.get("id")]
        ids = [str(r["id"]) for r in records]
        self.vulns.load(ids)
        for r in records:
            self.vulns.put(str(r["id"]), "nvd", r, **_nvd_fields(r))
        products[key] = {"fetched_at": _iso(self.t), "cve_ids": ids,
                         "not_enriched": [str(r["id"]) for r in records
                                          if not nvd.has_configurations(r) and r.get("vulnStatus") != "Rejected"]}
        self.ok("nvd", f"Downloaded {len(ids)} CVE record(s) for {vendor}:{product}")
        return ids

    def match_nvd(self, o: RunOutcome, items: list[SoftwareRecord]) -> None:
        assert o.device is not None
        api_key = get_secret("nvd_api_key")
        build = _windows_build(o.device)
        plan: list[tuple[SoftwareRecord, nvd.CuratedApp, nvd.Installed]] = []
        for it in items:
            app = nvd.match_app(it.name)
            if app is None:
                o.results[it.id] = ItemResult("no_source", None, REASON_NOT_CURATED)
                continue
            inst = nvd.installed_for(app, it.name, it.version, build)
            if inst is None:
                o.results[it.id] = ItemResult("no_source", None, "No usable version number was reported")
                continue
            plan.append((it, app, inst))
        cve_ids: dict[tuple[str, str], list[str]] = {}
        for _, app, _ in plan:
            for vendor, product in app.cpes:
                if (vendor, product) not in cve_ids:
                    cve_ids[(vendor, product)] = self.nvd_product(vendor, product, api_key)
        found: list[tuple[Finding, str | None]] = []
        not_enriched: set[str] = set()
        undecidable: set[str] = set()
        for it, app, inst in plan:
            ids = list(dict.fromkeys(i for pair in app.cpes for i in cve_ids.get(pair, [])))
            self.vulns.load(ids)
            for cve in ids:
                record = self.vulns.raw(cve, "nvd")
                if record is None or record.get("vulnStatus") == "Rejected":
                    continue
                verdict = nvd.evaluate(record, inst)
                if verdict.status == "affected" and verdict.match is not None:
                    found.append((nvd_finding(it, app, inst, record, verdict.match), None))
                elif verdict.status == "no_config":
                    not_enriched.add(cve)
                elif verdict.status == "unknown":
                    undecidable.add(cve)
            o.results[it.id] = ItemResult("matched", "nvd")
        o.bump("nvd_not_enriched", len(not_enriched))
        o.bump("nvd_undecidable", len(undecidable))
        o.nvd_products = sorted({nvd.product_key(v, p) for _, app, _ in plan for v, p in app.cpes})
        o.nvd_undecidable = sorted(undecidable)[:1000]
        o.findings.extend(_merge_findings(found))

    # ------------------------------------------------------------------ MSRC (Windows build)

    def match_msrc(self, o: RunOutcome, items: list[SoftwareRecord]) -> None:
        assert o.device is not None
        server = "server" in f"{o.device.os_name} {o.device.edition or ''}".lower()
        for it in items:
            if server:
                o.results[it.id] = ItemResult("no_source", None, "Windows Server editions are not mapped to Microsoft's "
                                                                  "product names yet, so updates are not compared")
                continue
            build = msrc.parse_build(it.version) or msrc.parse_build(o.device.os_build)
            product = msrc.product_name(build[2], o.device.arch) if build else None
            if o.device.is_insider_build or build is None or product is None:
                o.results[it.id] = ItemResult("no_source", None, msrc.NOT_COVERED)
                continue
            result = msrc.evaluate(self.msrc(), product, build)
            if not result["covered"]:
                o.results[it.id] = ItemResult("no_source", None, result["reason"])
                continue
            for entry in result["missing"]:
                o.findings.append(msrc_finding(it, product, entry))
                self.store_kb(product, entry)
            latest = result["latest_kb"]
            o.results[it.id] = ItemResult("matched", "msrc", f"{product}; latest update in Microsoft's data: KB{latest}")

    def store_kb(self, product: str, entry: dict[str, Any]) -> None:
        kb = f"KB{entry['kb']}"
        score, vector, top = msrc.kb_score(entry)
        severity, source = msrc.kb_severity(entry)
        cves = sorted(entry.get("cves") or {})
        refs = [u for u in [entry.get("url")] if u] + [f"https://msrc.microsoft.com/update-guide/vulnerability/{c}"
                                                         for c in cves[:20]]
        self.vulns.load([kb])
        self.vulns.put(kb, "msrc", entry, aliases=cves, cve_id=top,
                       summary=f"Windows security update {kb} for {product}",
                       details=f"Fixes {len(cves)} vulnerabilities: {', '.join(cves)}"[:20000],
                       cvss_score=score, cvss_vector=vector[:200] if vector else None, cvss_source=source,
                       severity=severity, modified=entry.get("document"), references=refs)

    # ------------------------------------------------------------------ write phase

    def write(self) -> None:
        db = self.db
        ensure_rows(db)  # first write statement: from here on this tick holds the write lock
        db.flush()  # vulnerability records downloaded in the read phase
        rows = {s: db.get(IntelSync, s, populate_existing=True, with_for_update=True) for s in (QUEUE, *SOURCES)}
        queue = _data(rows[QUEUE])
        queue.setdefault("items", [])
        queue.setdefault("done", {})
        for src, d in self.deltas.items():
            self.apply_delta(rows[src], d)
        processed: set[str] = set()
        for o in self.outcomes:
            self.apply_outcome(o, queue)
            processed.add(o.key)
        self.apply_forced_refresh(rows, queue, processed)
        self.requeue_unreconciled(queue, processed)
        if self.kev_changed or self.epss_changed:
            self.refresh_intel_everywhere()
        qrow = rows[QUEUE]
        assert qrow is not None
        qrow.data = queue
        waiting = len(queue["items"])
        retrying = sum(1 for e in queue["items"] if e.get("attempts"))
        qrow.status = "ok" if not retrying else "error"
        qrow.detail = f"{waiting} inventory run(s) waiting" + (f", {retrying} retrying after errors" if retrying else "")
        db.flush()

    def apply_delta(self, row: IntelSync | None, d: SyncDelta) -> None:
        if row is None:
            return
        data = _data(row)
        data.update(d.data)
        if d.attempted:
            data["last_attempt_at"] = _iso(self.t)
        if d.clear_force and data.get("force_requested_at") == d.clear_force:
            data.pop("force_requested_at", None)
        row.data = data
        if d.status:
            row.status = d.status
        if d.detail:
            row.detail = d.detail
        if d.synced:
            row.last_synced_at = self.t

    def apply_forced_refresh(self, rows: dict[str, IntelSync | None], queue: dict[str, Any], processed: set[str]) -> None:
        """'Sync now' for a matching source: re-match every inventory that uses it, with fresh data."""
        sources = set(self.requeue)
        for src in ("osv", "nvd", "msrc"):
            stamp = self.forced(src)
            if not stamp:
                continue
            row = rows[src]
            assert row is not None
            data = _data(row)
            if data.get("force_requested_at") == stamp:
                data.pop("force_requested_at", None)
            if self.enabled[src]:
                sources.add(src)
                if src in ("osv", "nvd"):
                    data["refresh_before"] = stamp
                    if src not in self.deltas:
                        row.detail = "Refresh requested; data is downloaded again with the next matching run"
            else:
                row.status, row.detail = "disabled", "Turned off in Settings > Integrations"
            row.data = data
        for src in ("kev", "epss"):  # a request that nothing handled (should not happen) must not stick
            stamp = self.forced(src)
            row = rows[src]
            if stamp and row is not None and src not in self.deltas:
                data = _data(row)
                if data.get("force_requested_at") == stamp:
                    data.pop("force_requested_at", None)
                    row.data = data
        if not sources:
            return
        pending = {run_key(e["device_id"], e["check_id"]) for e in queue["items"]}
        for key, done in queue["done"].items():
            if key in pending or key in processed:
                continue
            if not any(source_for(eco) in sources for eco in done.get("ecosystems") or []):
                continue
            self.requeue_done(queue, done, "refresh")

    def unreconciled_ready(self, queue: dict[str, Any], processed: set[str] | None = None) -> list[str]:
        """Runs skipped because a source was off, whose sources are all usable again."""
        processed = processed or set()
        if not get_settings().outbound_enabled:
            return []
        pending = {run_key(e["device_id"], e["check_id"]) for e in queue.get("items") or []}
        out = []
        for key, done in (queue.get("done") or {}).items():
            if done.get("reconciled", True) or key in pending or key in processed:
                continue
            needed = {source_for(eco) for eco in done.get("ecosystems") or []} - {None}
            if all(self.enabled.get(str(src)) for src in needed):
                out.append(key)
        return out

    def requeue_unreconciled(self, queue: dict[str, Any], processed: set[str]) -> None:
        """Runs skipped because a source was off are matched again once it is back on."""
        for key in self.unreconciled_ready(queue, processed):
            self.requeue_done(queue, queue["done"][key], "re-enabled")

    def requeue_done(self, queue: dict[str, Any], done: dict[str, Any], reason: str) -> None:
        queue["items"].append({"device_id": done["device_id"], "scan_id": done["scan_id"],
                               "check_run_id": done["check_run_id"], "check_id": done["check_id"],
                               "ecosystems": done.get("ecosystems") or [], "queued_at": _iso(self.t),
                               "attempts": 0, "next_at": None, "last_error": None, "reason": reason})

    def apply_outcome(self, o: RunOutcome, queue: dict[str, Any]) -> None:
        items: list[dict[str, Any]] = queue["items"]
        current = next((e for e in items if e.get("device_id") == o.entry["device_id"]
                        and e.get("check_id") == o.entry["check_id"]), None)
        if current is not None and current.get("check_run_id") != o.entry["check_run_id"]:
            return  # a newer inventory arrived while we worked; it will be matched next
        if current is None and o.entry.get("synthetic") and (o.errors or o.deferred is not None):
            current = {k: v for k, v in o.entry.items() if k != "synthetic"}
            items.append(current)  # a redo that could not finish now goes on the queue for a retry
        if o.drop_reason is not None:
            if current is not None:
                items.remove(current)
            queue["done"].pop(o.key, None)
            return
        if o.deferred is not None:
            if current is not None:
                current["next_at"] = _iso(o.deferred.until)
            return
        if o.errors:
            if current is not None:
                current["attempts"] = int(current.get("attempts") or 0) + 1
                backoff = min(timedelta(minutes=2) * (2 ** (current["attempts"] - 1)), MAX_BACKOFF)
                current["next_at"] = _iso(self.t + backoff)
                current["last_error"] = _cut("; ".join(o.errors), 1000)
            for it in o.items:
                it.match_status, it.match_source = "error", None
            return
        if current is not None:
            items.remove(current)
        reconciled = not o.disabled
        for it in o.items:
            r = o.results.get(it.id)
            if r is None:
                it.match_status, it.match_source = ("pending" if o.disabled else "no_source"), None
            else:
                it.match_status, it.match_source = r.status, r.source
        if reconciled:
            self.reconcile(o)
        by_id = {it.id: it for it in o.items}
        notes = {str(i): r.reason for i, r in o.results.items()
                 if r.reason and i in by_id and r.reason != generic_reason(by_id[i])}
        queue["done"][o.key] = {
            "device_id": o.entry["device_id"], "check_id": o.entry["check_id"], "scan_id": o.entry["scan_id"],
            "check_run_id": o.entry["check_run_id"], "processed_at": _iso(self.t),
            "ecosystems": sorted(set(o.entry.get("ecosystems") or []) | {it.ecosystem for it in o.items}),
            "reconciled": reconciled, "findings": len(o.findings), "stats": o.stats, "notes": notes,
            "nvd_products": o.nvd_products, "nvd_undecidable": o.nvd_undecidable,
            "not_reconciled_reason": (None if reconciled else
                                      "Not compared: " + ", ".join(sorted(set(o.disabled))) + " unavailable"),
        }

    def reconcile(self, o: RunOutcome) -> None:
        assert o.device is not None and o.scan is not None and o.check_run is not None
        created, reopened, _resolved = reconcile(
            self.db, device_id=o.device.id, scan=o.scan, check_run=o.check_run, findings=o.findings, evidence_ids=[],
            category_default=CATEGORY, source=SOURCE, reconcile_check_id=o.check_run.check_id,
        )
        self.db.flush()
        open_records = list(self.db.execute(select(FindingRecord).where(
            FindingRecord.device_id == o.device.id, FindingRecord.check_id == o.check_run.check_id,
            FindingRecord.source == SOURCE, FindingRecord.status.in_(OPEN))).scalars())
        self.apply_intel(open_records)
        if created or reopened:
            hooks.fire("findings_created", self.db, o.device, created + reopened)

    def kb_cves(self, vuln_id: str) -> list[str]:
        row = self.vulns.get(vuln_id)
        return [a for a in (row.aliases or []) if a.startswith("CVE-")] if row is not None else []

    def apply_intel(self, records: Iterable[FindingRecord]) -> None:
        records = list(records)
        self.vulns.load(r.vuln_id for r in records if r.vuln_id and r.vuln_id.startswith("KB"))
        for f in records:
            is_kb = bool(f.vuln_id and f.vuln_id.startswith("KB"))
            cves = self.kb_cves(str(f.vuln_id)) if is_kb else ([f.cve_id] if f.cve_id else [])
            f.kev = any(c in self.kev_map for c in cves)
            scores = [s[0] for c in cves if (s := self.epss_map.get(c)) and s[0] is not None]
            f.epss = max(scores) if scores else None

    @staticmethod
    def record_cves(r: VulnRecord) -> list[str]:
        if r.source == "msrc":
            return [a for a in r.aliases or [] if a.startswith("CVE-")]
        return [r.cve_id] if r.cve_id else []

    def stamp_record(self, r: VulnRecord) -> None:
        """KEV and EPSS facts for one cached record, from the catalogs this server already holds."""
        cves = self.record_cves(r)
        hit = next((c for c in cves if c in self.kev_map), None)
        info = self.kev_map.get(hit) if hit else None
        r.kev = hit is not None
        r.kev_date_added = str(info[0])[:16] if info and info[0] else None
        r.kev_ransomware = str(info[1])[:16] if info and info[1] else None
        if r.source != "msrc":
            s = self.epss_map.get(r.cve_id or "")
            if s and s[0] is not None:
                r.epss, r.epss_percentile = s[0], s[1]

    def refresh_intel_everywhere(self) -> None:
        db = self.db
        if self.kev_changed:
            kev_ids = set(self.kev_map)
            touched: dict[int, VulnRecord] = {}
            ids = sorted(kev_ids)
            for start in range(0, len(ids), 500):
                for r in db.execute(select(VulnRecord).where(VulnRecord.cve_id.in_(ids[start:start + 500]))).scalars():
                    touched[r.id] = r
            for r in db.execute(select(VulnRecord).where(VulnRecord.kev.is_(True))).scalars():
                touched[r.id] = r
            for r in db.execute(select(VulnRecord).where(VulnRecord.source == "msrc")).scalars():
                touched[r.id] = r
            for r in touched.values():
                self.stamp_record(r)
        if self.epss_changed:
            ids = sorted(self.epss_map)
            for start in range(0, len(ids), 500):
                for r in db.execute(select(VulnRecord).where(VulnRecord.cve_id.in_(ids[start:start + 500]))).scalars():
                    s = self.epss_map.get(r.cve_id or "")
                    if s:
                        r.epss, r.epss_percentile = s[0], s[1]
        self.apply_intel(db.execute(select(FindingRecord).where(FindingRecord.source == SOURCE,
                                                               FindingRecord.status.in_(OPEN))).scalars())


def tick(db: Session, budget_seconds: float = TICK_BUDGET_SECONDS) -> None:
    """Background work: syncs that are due, then queued inventory runs. Never commits."""
    t = Tick(db, budget_seconds)
    t.sync_kev()
    t.sync_msrc()
    t.process_queue()
    t.sync_epss()
    if t.deltas or t.outcomes or t.requeue or any(t.forced(s) for s in SOURCES) or t.unreconciled_ready(t.data[QUEUE]):
        t.write()



# =========================================================================== read helpers for the API


def queue_state(db: Session) -> dict[str, Any]:
    return _data(db.get(IntelSync, QUEUE))


def done_runs(db: Session, device_id: int | None = None) -> list[dict[str, Any]]:
    runs = list((queue_state(db).get("done") or {}).values())
    return [r for r in runs if device_id is None or r.get("device_id") == device_id]


def item_notes(db: Session, device_id: int | None = None) -> dict[int, str]:
    out: dict[int, str] = {}
    for run in done_runs(db, device_id):
        for k, v in (run.get("notes") or {}).items():
            if str(k).isdigit():
                out[int(k)] = v
    return out


def request_sync(db: Session, source: str) -> list[str]:
    """Flag sources for the next tick. Returns the sources flagged."""
    ensure_rows(db)
    sources = list(SOURCES) if source == "all" else [source]
    stamp = _iso(now())
    for s in sources:
        row = db.get(IntelSync, s, populate_existing=True, with_for_update=True)
        assert row is not None
        data = _data(row)
        data["force_requested_at"] = stamp
        row.data = data
    return sources
