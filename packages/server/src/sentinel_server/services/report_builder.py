"""Report data collection and rendering (PDF, CSV, JSON).

Everything in a report comes from stored data. Recommended actions and summaries are fixed
template text filled with stored values; no language model is involved. A value that cannot be
computed is reported as unavailable, never estimated.
"""

from __future__ import annotations

import csv
import io
import json
import re
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Any
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    CondPageBreak,
    KeepTogether,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)
from sqlalchemy import case, func, or_, select
from sqlalchemy.orm import Session

from .. import __version__
from ..config import Settings
from ..models import (
    Alert,
    Device,
    EmailCheck,
    EmailIdentity,
    EvidenceRecord,
    FindingObservation,
    FindingRecord,
    Incident,
    Scan,
    now,
)
from .assistant_tools import KIND_MEANING, SCORE_FORMULA, SEVERITY_MEANING, finding_evidence
from .findings import OPEN
from .scoring import OPEN_ALERT_STATUSES, WEIGHTS, device_posture, fleet_posture, latest_posture_scan

SEVERITIES = ["critical", "high", "medium", "low", "info"]
SEV_RANK = {s: i for i, s in enumerate(reversed(SEVERITIES))}
SEV_ORDER = case(SEV_RANK, value=FindingRecord.severity, else_=0)
ALERT_SEV_ORDER = case(SEV_RANK, value=Alert.severity, else_=0)
NOT_RUN = ("skipped", "error", "timeout", "cancelled")
PDF_FINDINGS_LIMIT = 300
EVIDENCE_FINDINGS = 8
EXCERPT_CHARS = 1500
CHUNK = 500

FINDING_COLUMNS = [
    "id", "device_id", "device", "severity", "title", "status", "kind", "confidence", "category", "source",
    "rule_id", "check_id", "first_seen_at", "last_seen_at", "verified_resolved_at", "reopened_count", "owner",
    "target_date", "cve_id", "vuln_id", "cvss_score", "cvss_vector", "epss", "kev", "affected_software",
    "fixed_version", "evidence_source", "last_seen_data_mode", "impact", "remediation",
]


# =========================================================================== helpers


def iso(dt: datetime | None) -> str | None:
    return dt.isoformat() if dt else None


def mask_email(email: str) -> str:
    local, sep, domain = (email or "").partition("@")
    if not sep:
        return "***"
    shown = local[0] + "***" + (local[-1] if len(local) > 2 else "")
    return f"{shown}@{domain}"


_FORMULA_START = ("=", "+", "-", "@", "\t", "\r")


def csv_safe(value: Any) -> str:
    """Text for a CSV cell that a spreadsheet will not run as a formula."""
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, int | float):
        return str(value)
    text = value if isinstance(value, str) else json.dumps(value, default=str, ensure_ascii=False)
    if text.startswith(_FORMULA_START):
        return "'" + text
    return text


def write_csv(rows: list[dict[str, Any]], columns: list[str]) -> bytes:
    buf = io.StringIO(newline="")
    w = csv.writer(buf, quoting=csv.QUOTE_MINIMAL, lineterminator="\r\n")
    w.writerow(columns)
    for r in rows:
        w.writerow([csv_safe(r.get(c)) for c in columns])
    return ("﻿" + buf.getvalue()).encode("utf-8")  # BOM so spreadsheet apps detect UTF-8


def _chunks(ids: list[int]) -> list[list[int]]:
    return [ids[i:i + CHUNK] for i in range(0, len(ids), CHUNK)]


def evidence_sources(db: Session, findings: list[FindingRecord]) -> dict[int, str | None]:
    """The source (command, registry path, API) of the newest evidence item behind each finding."""
    first_ev: dict[int, int] = {}
    for chunk in _chunks([f.id for f in findings]):
        rows = db.execute(select(FindingObservation).where(FindingObservation.finding_id.in_(chunk))
                          .order_by(FindingObservation.observed_at.desc(), FindingObservation.id.desc())).scalars()
        for obs in rows:
            if obs.finding_id not in first_ev and obs.evidence_ids:
                first_ev[obs.finding_id] = obs.evidence_ids[0]
    sources: dict[int, str] = {}
    for chunk in _chunks(sorted(set(first_ev.values()))):
        for ev_id, src in db.execute(select(EvidenceRecord.id, EvidenceRecord.source)
                                     .where(EvidenceRecord.id.in_(chunk))).all():
            sources[ev_id] = src
    out: dict[int, str | None] = {}
    for f in findings:
        src = sources.get(first_ev.get(f.id, -1))
        if src is None and f.source == "vuln_matcher":
            src = "vulnerability matching" + (f" ({f.cvss_source})" if f.cvss_source else "")
        out[f.id] = src
    return out


def scan_modes(db: Session, scan_ids: set[int]) -> dict[int, str]:
    modes: dict[int, str] = {}
    for chunk in _chunks(sorted(scan_ids)):
        modes.update(dict(db.execute(select(Scan.id, Scan.data_mode).where(Scan.id.in_(chunk))).all()))
    return modes


def finding_rows(db: Session, findings: list[FindingRecord], names: dict[int, str] | None = None) -> list[dict[str, Any]]:
    if names is None:
        names = dict(db.execute(select(Device.id, Device.name)).all())
    sources = evidence_sources(db, findings)
    modes = scan_modes(db, {f.last_seen_scan_id for f in findings if f.last_seen_scan_id})
    return [{
        "id": f.id, "device_id": f.device_id, "device": names.get(f.device_id), "severity": f.severity,
        "title": f.title, "status": f.status, "kind": f.finding_kind, "confidence": f.confidence,
        "category": f.category, "source": f.source, "rule_id": f.rule_id, "check_id": f.check_id,
        "first_seen_at": iso(f.first_seen_at), "last_seen_at": iso(f.last_seen_at),
        "verified_resolved_at": iso(f.verified_resolved_at), "reopened_count": f.reopened_count, "owner": f.owner,
        "target_date": f.target_date, "cve_id": f.cve_id, "vuln_id": f.vuln_id, "cvss_score": f.cvss_score,
        "cvss_vector": f.cvss_vector, "epss": f.epss, "kev": f.kev, "affected_software": f.affected_software,
        "fixed_version": f.fixed_version, "evidence_source": sources.get(f.id),
        "last_seen_data_mode": modes.get(f.last_seen_scan_id) if f.last_seen_scan_id else None,
        "impact": f.impact, "remediation": f.remediation,
    } for f in findings]


def _first_sentence(text: str, limit: int = 220) -> str:
    text = " ".join((text or "").split())
    m = re.match(r"(.+?[.!?])(\s|$)", text)
    s = m.group(1) if m else text
    return s if len(s) <= limit else s[: limit - 3].rstrip() + "..."


def recommended_action(f: FindingRecord, device: str) -> str:
    """Fixed template text built from the finding's stored remediation."""
    lead = "Known to be exploited (CISA KEV): patch first. " if f.kev else ""
    fix = _first_sentence(f.remediation) or "No remediation advice is stored; review the finding."
    return f"{lead}{f.title} on {device}: {fix}"


# =========================================================================== collection


def collect(db: Session, settings: Settings, *, title: str, device_id: int | None = None, days: int = 30) -> dict[str, Any]:
    t = now()
    since = t - timedelta(days=days)
    min_cov = settings.min_score_coverage
    if device_id is not None:
        dev = db.get(Device, device_id)
        devices = [dev] if dev else []
    else:
        devices = list(db.execute(select(Device).where(Device.is_active.is_(True)).order_by(Device.name)).scalars())
    ids = [d.id for d in devices]
    names = {d.id: d.name for d in devices}

    # ---- posture
    fleet = fleet_posture(db, ids, min_cov)
    device_rows = []
    basis_scans: list[tuple[Device, Scan | None]] = []
    for d in devices:
        p = device_posture(db, d.id, min_cov)
        basis_scans.append((d, latest_posture_scan(db, d.id)))
        device_rows.append({
            "device_id": d.id, "name": d.name, "hostname": d.hostname, "os": f"{d.os_name} {d.os_version}".strip(),
            "last_seen_at": iso(d.last_seen_at), "score": p.score, "raw_score": p.raw_score, "coverage": p.coverage,
            "incomplete": p.incomplete, "open_findings": p.open_findings, "threat_level": p.threat_level,
            "basis_scan_id": p.basis_scan_id, "agent_elevated": d.agent_elevated,
        })

    # ---- findings
    open_findings = list(db.execute(
        select(FindingRecord).where(FindingRecord.status.in_(OPEN), FindingRecord.device_id.in_(ids))
        .order_by(SEV_ORDER.desc(), FindingRecord.kev.desc(), FindingRecord.cvss_score.desc().nulls_last(),
                  FindingRecord.last_seen_at.desc(), FindingRecord.id)
    ).scalars())
    resolved = list(db.execute(
        select(FindingRecord).where(FindingRecord.device_id.in_(ids), FindingRecord.status == "resolved",
                                    FindingRecord.verified_resolved_at >= since)
        .order_by(FindingRecord.verified_resolved_at.desc())
    ).scalars())
    counts = {s: 0 for s in SEVERITIES}
    for f in open_findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    open_rows = finding_rows(db, open_findings, names)
    resolved_rows = finding_rows(db, resolved, names)

    actionable = [f for f in open_findings if f.status != "accepted_risk" and f.severity in ("critical", "high", "medium")]
    actionable.sort(key=lambda f: (not f.kev, -SEV_RANK.get(f.severity, 0), -(f.cvss_score or 0), f.id))
    actions = [{"finding_id": f.id, "severity": f.severity, "title": f.title, "device": names.get(f.device_id),
                "kev": f.kev, "action": recommended_action(f, names.get(f.device_id, str(f.device_id)))}
               for f in actionable[:5]]

    excerpts = []
    for f in open_findings[:EVIDENCE_FINDINGS]:
        ev = finding_evidence(db, f.id, 1)
        if ev:
            e = ev[0]
            excerpts.append({"finding_id": f.id, "title": f.title, "severity": f.severity,
                             "device": names.get(f.device_id), "evidence_id": e["evidence_id"], "scan_id": e["scan_id"],
                             "kind": e["kind"], "source": e["source"], "collected_at": e["collected_at"],
                             "redacted": e["redacted"], "sha256": e["content_sha256"], "excerpt": e["excerpt"],
                             "truncated": e["truncated"]})

    groups: dict[str, dict[tuple[str, str], dict[str, Any]]] = {s: {} for s in SEVERITIES}
    for f in open_findings:
        key = (f.rule_id, f.remediation)
        g = groups.setdefault(f.severity, {}).setdefault(key, {
            "rule_id": f.rule_id, "title": f.title, "remediation": f.remediation, "finding_ids": [], "devices": [],
            "accepted_risk": 0})
        g["finding_ids"].append(f.id)
        dn = names.get(f.device_id, str(f.device_id))
        if dn not in g["devices"]:
            g["devices"].append(dn)
        if f.status == "accepted_risk":
            g["accepted_risk"] += 1
    remediation = {s: list(groups.get(s, {}).values()) for s in SEVERITIES}

    # ---- scans
    scans = list(db.execute(select(Scan).where(Scan.device_id.in_(ids), Scan.requested_at >= since)
                            .order_by(Scan.requested_at.desc())).scalars())
    fixture_ids = list(db.execute(select(Scan.id).where(Scan.device_id.in_(ids), Scan.data_mode == "fixture")
                                  .order_by(Scan.id)).scalars())
    fixture_notice = None
    if fixture_ids:
        fixture_notice = (f"DEMO DATA: {len(fixture_ids)} scan(s) in this report's scope used fixture (demo) data, "
                          "not live observations of a device. Findings from those scans do not describe a real "
                          "machine.")

    # ---- alerts & incidents
    alerts_window = list(db.execute(select(Alert).where(Alert.device_id.in_(ids), Alert.detected_at >= since)).scalars())
    alert_sev = {s: 0 for s in SEVERITIES}
    alert_kind: dict[str, int] = defaultdict(int)
    alert_status: dict[str, int] = defaultdict(int)
    for a in alerts_window:
        alert_sev[a.severity] = alert_sev.get(a.severity, 0) + 1
        alert_kind[a.kind] += 1
        alert_status[a.status] += 1
    open_alerts = list(db.execute(
        select(Alert).where(Alert.device_id.in_(ids), Alert.status.in_(OPEN_ALERT_STATUSES))
        .order_by(ALERT_SEV_ORDER.desc(), Alert.detected_at.desc()).limit(25)).scalars())
    open_alert_total = db.execute(select(func.count(Alert.id)).where(
        Alert.device_id.in_(ids), Alert.status.in_(OPEN_ALERT_STATUSES))).scalar_one()
    incidents = list(db.execute(
        select(Incident).where(Incident.device_id.in_(ids),
                               or_(Incident.opened_at >= since, Incident.status != "closed"))
        .order_by(Incident.opened_at.desc()).limit(25)).scalars())

    # ---- email exposure (not tied to devices)
    email_rows = []
    for ident in db.execute(select(EmailIdentity).order_by(EmailIdentity.id)).scalars():
        last = db.execute(select(EmailCheck).where(EmailCheck.identity_id == ident.id)
                          .order_by(EmailCheck.checked_at.desc(), EmailCheck.id.desc()).limit(1)).scalar_one_or_none()
        breaches = []
        if last is not None:
            for b in (last.breaches or [])[:20]:
                if isinstance(b, dict):
                    breaches.append({"name": str(b.get("Title") or b.get("Name") or b.get("name") or "unnamed")[:120],
                                     "date": str(b.get("BreachDate") or b.get("breach_date") or "")[:20] or None})
        email_rows.append({
            "identity_id": ident.id, "email_masked": mask_email(ident.email), "label": ident.label,
            "last_checked_at": iso(last.checked_at) if last else None, "status": last.status if last else "never_checked",
            "breach_count": last.breach_count if last and last.status in ("found", "not_found") else None,
            "breaches": breaches, "source": last.source if last else None,
        })

    # ---- limitations
    skipped_checks, needs_elevation, no_posture = [], [], []
    for d, scan in basis_scans:
        if scan is None:
            no_posture.append(d.name)
            continue
        for r in sorted(scan.check_runs, key=lambda r: r.check_id):
            if r.status in NOT_RUN:
                skipped_checks.append({"device": d.name, "scan_id": scan.id, "check_id": r.check_id, "title": r.title,
                                       "status": r.status, "reason": r.skip_reason or r.error_message})
            if r.requires_elevation and not r.ran_elevated and r.status not in ("passed", "failed", "not_applicable"):
                needs_elevation.append({"device": d.name, "scan_id": scan.id, "check_id": r.check_id, "title": r.title})
    statements = [
        "No findings does not mean secure: a passed check only shows that one specific condition was not observed "
        "at scan time.",
        "Sentinel reports only what its checks observed and what stored vulnerability data matched; it does not "
        "test every possible weakness.",
        "Heuristic findings and alerts are suspicious patterns that need a person to confirm or dismiss them.",
        f"The score is shown only when at least {min_cov:.0%} of applicable checks completed; otherwise it is "
        "reported as Incomplete.",
    ]
    if not devices:
        statements.insert(0, "No devices were in scope, so nothing was assessed.")
    if no_posture:
        statements.append("No completed posture scan exists for: " + ", ".join(no_posture) + ".")
    if fixture_notice:
        statements.append(fixture_notice)

    coverage = fleet.coverage
    score_display = (f"{fleet.score}/100" if fleet.score is not None else "Incomplete")
    return {
        "sentinel_report": 1,
        "generator": f"Sentinel {__version__}",
        "title": title,
        "generated_at": iso(t),
        "scope": {"device_id": device_id, "devices": [{"id": d.id, "name": d.name} for d in devices], "days": days,
                  "since": iso(since), "until": iso(t)},
        "fixture_data": bool(fixture_ids),
        "fixture_scan_ids": fixture_ids[:100],
        "fixture_notice": fixture_notice,
        "executive_summary": {
            "score": fleet.score, "raw_score": fleet.raw_score, "coverage": coverage, "incomplete": fleet.incomplete,
            "score_display": score_display, "checks_completed": fleet.checks_completed,
            "checks_applicable": fleet.checks_applicable, "threat_level": fleet.threat_level,
            "open_findings": len(open_findings), "open_by_severity": counts, "counted_by_severity": fleet.counts,
            "open_alerts": open_alert_total, "resolved_in_period": len(resolved), "recommended_actions": actions,
        },
        "devices": device_rows,
        "findings": open_rows,
        "resolved_in_period": resolved_rows,
        "evidence_excerpts": excerpts,
        "severity_ratings": {"severities": SEVERITY_MEANING, "kinds": KIND_MEANING,
                             "weights": {s.value: w for s, w in WEIGHTS.items()}, "score_formula": SCORE_FORMULA},
        "remediation": remediation,
        "alerts": {
            "in_period_by_severity": alert_sev, "in_period_by_kind": dict(alert_kind),
            "in_period_by_status": dict(alert_status), "in_period_total": len(alerts_window),
            "open_total": open_alert_total,
            "open": [{"id": a.id, "title": a.title, "severity": a.severity, "kind": a.kind, "confidence": a.confidence,
                      "status": a.status, "device": names.get(a.device_id), "detected_at": iso(a.detected_at),
                      "event_count": a.event_count} for a in open_alerts],
        },
        "incidents": [{"id": i.id, "title": i.title, "severity": i.severity, "status": i.status,
                       "device": names.get(i.device_id), "opened_at": iso(i.opened_at), "closed_at": iso(i.closed_at)}
                      for i in incidents],
        "email_exposure": email_rows,
        "scans": [{"id": s.id, "device": names.get(s.device_id), "scan_type": s.scan_type, "status": s.status,
                   "data_mode": s.data_mode, "requested_at": iso(s.requested_at), "completed_at": iso(s.completed_at),
                   "score": s.score, "coverage": s.coverage} for s in scans],
        "limitations": {"coverage": coverage, "checks_completed": fleet.checks_completed,
                        "checks_applicable": fleet.checks_applicable, "checks_not_run": skipped_checks,
                        "needs_elevation": needs_elevation, "devices_without_posture_scan": no_posture,
                        "statements": statements},
    }


# =========================================================================== CSV / JSON


def render_csv(data: dict[str, Any]) -> bytes:
    return write_csv(data["findings"] + data["resolved_in_period"], FINDING_COLUMNS)


def render_json(data: Any) -> bytes:
    return json.dumps(data, indent=2, default=str, ensure_ascii=False).encode("utf-8")


# =========================================================================== PDF


NAVY = colors.HexColor("#1e293b")
MUTED = colors.HexColor("#64748b")
RULE = colors.HexColor("#cbd5e1")
ZEBRA = colors.HexColor("#f8fafc")
SEV_COLORS = {
    "critical": (colors.HexColor("#7f1d1d"), colors.HexColor("#fee2e2")),
    "high": (colors.HexColor("#b91c1c"), colors.HexColor("#ffedd5")),
    "medium": (colors.HexColor("#92400e"), colors.HexColor("#fef3c7")),
    "low": (colors.HexColor("#1d4ed8"), colors.HexColor("#dbeafe")),
    "info": (colors.HexColor("#374151"), colors.HexColor("#f3f4f6")),
    "informational": (colors.HexColor("#374151"), colors.HexColor("#f3f4f6")),
}

_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def clean(value: Any) -> str:
    """Plain text safe to place inside reportlab Paragraph markup."""
    text = "" if value is None else str(value)
    text = text.encode("utf-8", "replace").decode("utf-8")
    text = _CONTROL.sub("?", text.replace("\t", "    "))
    return escape(text)


def mono_markup(text: str, width: int = 100) -> str:
    lines: list[str] = []
    for line in (text or "").replace("\r\n", "\n").split("\n"):
        line = line.replace("\t", "    ")
        while len(line) > width:
            lines.append(line[:width])
            line = line[width:]
        lines.append(line)
    out = []
    for line in lines:
        esc = clean(line)
        body = esc.lstrip(" ")
        out.append("&nbsp;" * (len(esc) - len(body)) + body)
    return "<br/>".join(out)


def fmt_dt(value: str | None, with_time: bool = True) -> str:
    if not value:
        return "-"
    try:
        dt = datetime.fromisoformat(value)
    except ValueError:
        return value
    return dt.strftime("%Y-%m-%d %H:%M UTC" if with_time else "%Y-%m-%d")


def _styles() -> dict[str, ParagraphStyle]:
    base = ParagraphStyle("Body", fontName="Helvetica", fontSize=9.5, leading=13, textColor=NAVY, spaceAfter=4)
    return {
        "body": base,
        "cover_title": ParagraphStyle("CoverTitle", parent=base, fontName="Helvetica-Bold", fontSize=26, leading=32,
                                      spaceAfter=10),
        "cover_sub": ParagraphStyle("CoverSub", parent=base, fontSize=12, leading=17, textColor=MUTED),
        "h1": ParagraphStyle("H1", parent=base, fontName="Helvetica-Bold", fontSize=16, leading=20, spaceBefore=6,
                             spaceAfter=8),
        "h2": ParagraphStyle("H2", parent=base, fontName="Helvetica-Bold", fontSize=11.5, leading=15, spaceBefore=8,
                             spaceAfter=4),
        "small": ParagraphStyle("Small", parent=base, fontSize=8, leading=10.5, textColor=MUTED),
        "cell": ParagraphStyle("Cell", parent=base, fontSize=8, leading=10, spaceAfter=0),
        "cell_bold": ParagraphStyle("CellBold", parent=base, fontName="Helvetica-Bold", fontSize=8, leading=10,
                                    spaceAfter=0),
        "head": ParagraphStyle("Head", parent=base, fontName="Helvetica-Bold", fontSize=8, leading=10, spaceAfter=0,
                               textColor=colors.white),
        "mono": ParagraphStyle("Mono", parent=base, fontName="Courier", fontSize=7, leading=8.6, spaceAfter=0),
        "banner": ParagraphStyle("Banner", parent=base, fontName="Helvetica-Bold", fontSize=11, leading=15,
                                 textColor=colors.white, spaceAfter=0),
        "big": ParagraphStyle("Big", parent=base, fontName="Helvetica-Bold", fontSize=18, leading=22, spaceAfter=0),
        "big_small": ParagraphStyle("BigSmall", parent=base, fontName="Helvetica-Bold", fontSize=13, leading=22,
                                    spaceAfter=0),
        "label": ParagraphStyle("Label", parent=base, fontSize=7.5, leading=9.5, textColor=MUTED, spaceAfter=0),
    }


def _table(rows: list[list[Any]], widths: list[float], *, header: bool = True, zebra: bool = True,
           extra: list[tuple[Any, ...]] | None = None) -> Table:
    t = Table(rows, colWidths=widths, repeatRows=1 if header else 0, hAlign="LEFT")
    style: list[tuple[Any, ...]] = [
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 4), ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 3), ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("LINEBELOW", (0, 0), (-1, -1), 0.25, RULE),
    ]
    if header:
        style.append(("BACKGROUND", (0, 0), (-1, 0), NAVY))
    if zebra:
        for i in range(1 if header else 0, len(rows)):
            if i % 2 == 0:
                style.append(("BACKGROUND", (0, i), (-1, i), ZEBRA))
    t.setStyle(TableStyle(style + (extra or [])))
    return t


def _sev_cell(sev: str, st: dict[str, ParagraphStyle]) -> Paragraph:
    fg, _ = SEV_COLORS.get(sev, SEV_COLORS["info"])
    style = ParagraphStyle(f"sev-{sev}", parent=st["cell_bold"], textColor=fg)
    return Paragraph(clean(sev.upper()), style)


def _sev_bg(sev: str) -> colors.Color:
    return SEV_COLORS.get(sev, SEV_COLORS["info"])[1]


def render_pdf(data: dict[str, Any]) -> bytes:
    st = _styles()
    buf = io.BytesIO()
    title = data["title"]
    margin = 0.75 * inch
    width = letter[0] - 2 * margin
    doc = SimpleDocTemplate(buf, pagesize=letter, leftMargin=margin, rightMargin=margin, topMargin=0.8 * inch,
                            bottomMargin=0.75 * inch, title=title, author="Sentinel", creator=data["generator"],
                            subject="Security assessment report")
    generated = fmt_dt(data["generated_at"])
    fixture = data["fixture_data"]

    def chrome(canvas: Any, doc_: Any, cover: bool) -> None:
        canvas.saveState()
        canvas.setFont("Helvetica", 7.5)
        canvas.setFillColor(MUTED)
        if not cover:
            canvas.drawString(margin, letter[1] - 0.5 * inch, (title[:90] + ("..." if len(title) > 90 else "")))
            canvas.drawRightString(letter[0] - margin, letter[1] - 0.5 * inch, "Sentinel security report")
            canvas.setStrokeColor(RULE)
            canvas.line(margin, letter[1] - 0.55 * inch, letter[0] - margin, letter[1] - 0.55 * inch)
        foot = f"Generated {generated} by {data['generator']}  |  Confidential: contains security details"
        if fixture:
            canvas.setFillColor(SEV_COLORS["high"][0])
            foot = "DEMO / FIXTURE DATA IN SCOPE  |  " + foot
        canvas.drawString(margin, 0.45 * inch, foot)
        canvas.setFillColor(MUTED)
        canvas.drawRightString(letter[0] - margin, 0.45 * inch, f"Page {doc_.page}")
        canvas.restoreState()

    story: list[Any] = []
    P = Paragraph

    # ---- cover
    scope = data["scope"]
    dev_names = ", ".join(d["name"] for d in scope["devices"]) or "no devices"
    story += [Spacer(1, 1.3 * inch), P(clean(title), st["cover_title"]),
              P("Security assessment report", st["cover_sub"]), Spacer(1, 0.25 * inch)]
    cover_rows = [
        [P("Generated", st["label"]), P(clean(generated), st["cell"])],
        [P("Scope", st["label"]), P(clean(("Device: " if scope["device_id"] else "All enrolled devices: ") + dev_names),
                                    st["cell"])],
        [P("Period", st["label"]), P(clean(f"Last {scope['days']} day(s): {fmt_dt(scope['since'], False)} to "
                                           f"{fmt_dt(scope['until'], False)}"), st["cell"])],
        [P("Prepared by", st["label"]), P(clean(f"{data['generator']} (local-first; generated on this machine)"),
                                          st["cell"])],
    ]
    story.append(_table(cover_rows, [1.2 * inch, width - 1.2 * inch], header=False, zebra=False))
    story.append(Spacer(1, 0.3 * inch))
    if fixture:
        banner = Table([[P(clean(data["fixture_notice"]), st["banner"])]], colWidths=[width])
        banner.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), SEV_COLORS["high"][0]),
                                    ("BOX", (0, 0), (-1, -1), 2, SEV_COLORS["critical"][0]),
                                    ("LEFTPADDING", (0, 0), (-1, -1), 10), ("RIGHTPADDING", (0, 0), (-1, -1), 10),
                                    ("TOPPADDING", (0, 0), (-1, -1), 10), ("BOTTOMPADDING", (0, 0), (-1, -1), 10)]))
        story.append(banner)
        story.append(Spacer(1, 0.2 * inch))
    story.append(P("This report lists what Sentinel's checks observed and what stored vulnerability data matched. "
                   "It is evidence-based but not exhaustive; see Assessment limitations.", st["small"]))
    story.append(PageBreak())

    # ---- executive summary
    ex = data["executive_summary"]
    story.append(P("1. Executive summary", st["h1"]))
    cov = f"{ex['coverage']:.0%}" if ex["coverage"] is not None else "unknown"

    def tile(value: Any) -> Paragraph:
        text = str(value)
        return P(clean(text), st["big"] if len(text) <= 7 else st["big_small"])

    score_note = (f"{ex['checks_completed']} of {ex['checks_applicable']} applicable checks completed ({cov})."
                  if ex["checks_applicable"] else "No posture checks have completed yet.")
    if ex["incomplete"]:
        score_note += f" Too few checks completed for a reliable score; the raw score was {ex['raw_score']}/100."
    tiles = [[P("Security score", st["label"]), P("Check coverage", st["label"]), P("Threat level", st["label"]),
              P("Open findings", st["label"]), P("Open alerts", st["label"])],
             [tile(ex["score_display"]), tile(cov), tile(ex["threat_level"].title()), tile(ex["open_findings"]),
              tile(ex["open_alerts"])]]
    tile_t = Table(tiles, colWidths=[width / 5] * 5)
    tile_t.setStyle(TableStyle([("BOX", (0, 0), (-1, -1), 0.5, RULE), ("INNERGRID", (0, 0), (-1, -1), 0.5, RULE),
                                ("BACKGROUND", (0, 0), (-1, -1), ZEBRA), ("TOPPADDING", (0, 0), (-1, -1), 6),
                                ("BOTTOMPADDING", (0, 0), (-1, -1), 6), ("LEFTPADDING", (0, 0), (-1, -1), 8)]))
    story += [tile_t, Spacer(1, 4), P(clean(score_note), st["small"]), Spacer(1, 6)]

    sev_rows = [[P(clean(h), st["head"]) for h in ["Severity", *[s.title() for s in SEVERITIES]]],
                [P("Open findings", st["cell_bold"]), *[P(str(ex["open_by_severity"].get(s, 0)), st["cell"])
                                                        for s in SEVERITIES]],
                [P("Counted in score", st["cell_bold"]), *[P(str(ex["counted_by_severity"].get(s, 0)), st["cell"])
                                                           for s in SEVERITIES]]]
    story.append(_table(sev_rows, [1.5 * inch] + [(width - 1.5 * inch) / 5] * 5))
    story.append(P(clean(f"{ex['resolved_in_period']} finding(s) were verified as resolved in this period."),
                   st["small"]))
    story.append(P("Top recommended actions", st["h2"]))
    if ex["recommended_actions"]:
        for i, a in enumerate(ex["recommended_actions"], 1):
            story.append(P(f"<b>{i}. [{clean(a['severity'].upper())}]</b> {clean(a['action'])} "
                           f"<font color='#64748b'>(finding #{a['finding_id']})</font>", st["body"]))
    else:
        story.append(P("No open critical, high or medium findings need action in this scope.", st["body"]))
    if data["devices"]:
        story.append(P("Devices", st["h2"]))
        rows = [[P(clean(h), st["head"]) for h in ("Device", "Operating system", "Score", "Coverage", "Open", "Threat")]]
        for d in data["devices"]:
            rows.append([P(clean(d["name"]), st["cell_bold"]), P(clean(d["os"]), st["cell"]),
                         P(clean(f"{d['score']}/100" if d["score"] is not None else "Incomplete"), st["cell"]),
                         P(clean(f"{d['coverage']:.0%}" if d["coverage"] is not None else "-"), st["cell"]),
                         P(str(d["open_findings"]), st["cell"]), P(clean(d["threat_level"]), st["cell"])])
        story.append(_table(rows, [1.5 * inch, 2.4 * inch, 0.85 * inch, 0.75 * inch, 0.6 * inch,
                                   width - 6.1 * inch]))

    # ---- technical findings
    story += [PageBreak(), P("2. Technical findings", st["h1"])]
    findings = data["findings"]
    if findings:
        story.append(P(clean(f"{len(findings)} open finding(s), most severe first."
                             + (f" The first {PDF_FINDINGS_LIMIT} are listed; the CSV and JSON reports contain all."
                                if len(findings) > PDF_FINDINGS_LIMIT else "")), st["small"]))
        rows = [[P(clean(h), st["head"]) for h in ("Severity", "Finding", "Device", "Status", "First seen",
                                                    "Evidence source")]]
        extra: list[tuple[Any, ...]] = []
        for i, f in enumerate(findings[:PDF_FINDINGS_LIMIT], 1):
            title_markup = f"<font color='#64748b'>#{f['id']}</font> {clean(f['title'])}"
            if f["cve_id"]:
                title_markup += f" <font color='#64748b'>({clean(f['cve_id'])})</font>"
            if f["kind"] == "heuristic":
                title_markup += " <font color='#92400e'>[heuristic]</font>"
            rows.append([_sev_cell(f["severity"], st), P(title_markup, st["cell"]), P(clean(f["device"]), st["cell"]),
                         P(clean(f["status"].replace("_", " ")), st["cell"]),
                         P(clean(fmt_dt(f["first_seen_at"], False)), st["cell"]),
                         P(clean(f["evidence_source"] or "-"), st["cell"])])
            extra.append(("BACKGROUND", (0, i), (0, i), _sev_bg(f["severity"])))
        story.append(_table(rows, [0.75 * inch, 2.45 * inch, 1.0 * inch, 0.8 * inch, 0.75 * inch, 1.25 * inch],
                            extra=extra))
    else:
        story.append(P("No open findings are recorded for this scope. This is not proof that the devices are "
                       "secure; see Assessment limitations.", st["body"]))
    if data["resolved_in_period"]:
        story.append(P("Verified resolved in this period", st["h2"]))
        rows = [[P(clean(h), st["head"]) for h in ("Severity", "Finding", "Device", "Resolved")]]
        for f in data["resolved_in_period"][:100]:
            rows.append([_sev_cell(f["severity"], st), P(clean(f"#{f['id']} {f['title']}"), st["cell"]),
                         P(clean(f["device"]), st["cell"]), P(clean(fmt_dt(f["verified_resolved_at"])), st["cell"])])
        story.append(_table(rows, [0.75 * inch, 3.6 * inch, 1.3 * inch, width - 5.65 * inch]))

    # ---- evidence
    story += [CondPageBreak(2.5 * inch), P("3. Supporting evidence", st["h1"])]
    if data["evidence_excerpts"]:
        story.append(P("The newest evidence item recorded for each of the most severe open findings, as stored "
                       f"(secrets redacted at collection, cut to about {EXCERPT_CHARS} characters).", st["small"]))
        for e in data["evidence_excerpts"]:
            head = P(f"<b>#{e['finding_id']} {clean(e['title'])}</b> <font color='#64748b'>({clean(e['severity'])}, "
                     f"{clean(e['device'])})</font>", st["body"])
            meta = P(clean(f"{e['kind']} from {e['source']}, collected {fmt_dt(e['collected_at'])}, scan {e['scan_id']}, "
                           f"sha256 {e['sha256'][:16]}..." + (" (redacted)" if e["redacted"] else "")), st["small"])
            box = Table([[P(mono_markup(e["excerpt"]), st["mono"])]], colWidths=[width])
            box.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), ZEBRA), ("BOX", (0, 0), (-1, -1), 0.5, RULE),
                                     ("LEFTPADDING", (0, 0), (-1, -1), 6), ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                                     ("TOPPADDING", (0, 0), (-1, -1), 5), ("BOTTOMPADDING", (0, 0), (-1, -1), 5)]))
            story += [KeepTogether([head, meta]), box, Spacer(1, 8)]
    else:
        story.append(P("No evidence items are linked to open findings in this scope.", st["body"]))

    # ---- severity ratings
    sr = data["severity_ratings"]
    story += [CondPageBreak(2.5 * inch), P("4. Severity ratings and score", st["h1"])]
    rows = [[P(clean(h), st["head"]) for h in ("Rating", "Meaning", "Score weight")]]
    for s in SEVERITIES:
        rows.append([_sev_cell(s, st), P(clean(sr["severities"][s].split(": ", 1)[-1]), st["cell"]),
                     P(str(sr["weights"].get(s, 0)), st["cell"])])
    story.append(_table(rows, [0.9 * inch, width - 1.9 * inch, 1.0 * inch]))
    story.append(Spacer(1, 6))
    for k in ("verified", "heuristic", "informational"):
        story.append(P(clean(sr["kinds"][k]), st["body"]))
    story.append(P("<b>Score formula.</b> " + clean(sr["score_formula"]), st["body"]))

    # ---- remediation
    story += [CondPageBreak(2.5 * inch), P("5. Remediation recommendations", st["h1"]),
              P("Steps for a person to carry out. Sentinel never runs them. After a fix, use Verify on the finding to "
                "re-run its check; only a passing re-run marks it resolved.", st["small"])]
    any_rem = False
    for s in SEVERITIES:
        items = data["remediation"].get(s) or []
        if not items:
            continue
        any_rem = True
        story.append(P(clean(f"{s.title()} ({len(items)})"), st["h2"]))
        for it in items[:60]:
            devs = ", ".join(it["devices"][:6]) + (" and more" if len(it["devices"]) > 6 else "")
            ids = ", ".join(f"#{i}" for i in it["finding_ids"][:8])
            note = f" {it['accepted_risk']} marked as accepted risk." if it["accepted_risk"] else ""
            story.append(P(f"<b>{clean(it['title'])}</b> <font color='#64748b'>({clean(devs)}; findings "
                           f"{clean(ids)}){clean(note)}</font><br/>{clean(it['remediation'] or 'No advice stored.')}",
                           st["body"]))
    if not any_rem:
        story.append(P("There are no open findings to remediate in this scope.", st["body"]))

    # ---- alerts & incidents
    al = data["alerts"]
    story += [CondPageBreak(2.5 * inch), P("6. Alerts and incidents", st["h1"])]
    story.append(P(clean(
        f"{al['in_period_total']} alert(s) detected in this period; {al['open_total']} open now. By severity: "
        + ", ".join(f"{s} {al['in_period_by_severity'].get(s, 0)}" for s in SEVERITIES) + ". "
        + ("By kind: " + ", ".join(f"{k} {n}" for k, n in sorted(al["in_period_by_kind"].items())) + ". "
           if al["in_period_by_kind"] else "")
        + "Heuristic alerts are suspicious patterns, not confirmed compromises."), st["body"]))
    if al["open"]:
        rows = [[P(clean(h), st["head"]) for h in ("Severity", "Alert", "Kind", "Device", "Detected", "Status")]]
        for a in al["open"]:
            rows.append([_sev_cell(a["severity"], st), P(clean(f"#{a['id']} {a['title']}"), st["cell"]),
                         P(clean(a["kind"]), st["cell"]), P(clean(a["device"]), st["cell"]),
                         P(clean(fmt_dt(a["detected_at"])), st["cell"]), P(clean(a["status"]), st["cell"])])
        story.append(_table(rows, [0.75 * inch, 2.35 * inch, 0.75 * inch, 1.0 * inch, 1.2 * inch,
                                   width - 6.05 * inch]))
    if data["incidents"]:
        story.append(P("Incidents", st["h2"]))
        rows = [[P(clean(h), st["head"]) for h in ("Severity", "Incident", "Device", "Opened", "Status")]]
        for i in data["incidents"]:
            rows.append([_sev_cell(i["severity"], st), P(clean(f"#{i['id']} {i['title']}"), st["cell"]),
                         P(clean(i["device"]), st["cell"]), P(clean(fmt_dt(i["opened_at"])), st["cell"]),
                         P(clean(i["status"]), st["cell"])])
        story.append(_table(rows, [0.75 * inch, 2.9 * inch, 1.1 * inch, 1.3 * inch, width - 6.05 * inch]))
    elif not al["open"]:
        story.append(P("No open alerts or incidents in this scope.", st["body"]))

    # ---- email exposure
    story += [CondPageBreak(2 * inch), P("7. Email exposure", st["h1"])]
    if data["email_exposure"]:
        story.append(P("Monitored addresses are masked. Breach data comes from the configured breach service at the "
                       "time of the last check.", st["small"]))
        rows = [[P(clean(h), st["head"]) for h in ("Address", "Last checked", "Status", "Breaches", "Breach names")]]
        for e in data["email_exposure"]:
            bnames = ", ".join(b["name"] for b in e["breaches"][:8]) + (" ..." if len(e["breaches"]) > 8 else "")
            rows.append([P(clean(e["email_masked"] + (f" ({e['label']})" if e["label"] else "")), st["cell"]),
                         P(clean(fmt_dt(e["last_checked_at"])), st["cell"]),
                         P(clean(e["status"].replace("_", " ")), st["cell"]),
                         P(clean("-" if e["breach_count"] is None else e["breach_count"]), st["cell"]),
                         P(clean(bnames or "-"), st["cell"])])
        story.append(_table(rows, [1.7 * inch, 1.2 * inch, 0.9 * inch, 0.7 * inch, width - 4.5 * inch]))
    else:
        story.append(P("No email addresses are monitored, so email exposure was not assessed.", st["body"]))

    # ---- limitations
    lim = data["limitations"]
    story += [CondPageBreak(2.5 * inch), P("8. Assessment limitations", st["h1"])]
    for s in lim["statements"]:
        story.append(P("&bull; " + clean(s), st["body"]))
    cov = f"{lim['coverage']:.0%}" if lim["coverage"] is not None else "unknown"
    story.append(P(clean(f"Coverage: {lim['checks_completed']} of {lim['checks_applicable']} applicable checks completed "
                         f"({cov}) in the latest posture scan of each device."), st["body"]))
    if lim["checks_not_run"]:
        story.append(P("Checks that did not run", st["h2"]))
        rows = [[P(clean(h), st["head"]) for h in ("Device", "Check", "Result", "Reason")]]
        for c in lim["checks_not_run"][:150]:
            rows.append([P(clean(c["device"]), st["cell"]), P(clean(f"{c['title']} ({c['check_id']})"), st["cell"]),
                         P(clean(c["status"]), st["cell"]), P(clean(c["reason"] or "-"), st["cell"])])
        story.append(_table(rows, [1.1 * inch, 2.4 * inch, 0.7 * inch, width - 4.2 * inch]))
    if lim["needs_elevation"]:
        story.append(P("Checks that need administrator rights", st["h2"]))
        story.append(P(clean("These checks did not run with administrator rights. Run an elevated scan to include them: "
                             + "; ".join(f"{c['title']} on {c['device']}" for c in lim["needs_elevation"][:60]) + "."),
                       st["body"]))

    doc.build(story, onFirstPage=lambda c, d: chrome(c, d, True), onLaterPages=lambda c, d: chrome(c, d, False))
    return buf.getvalue()


def render(data: dict[str, Any], kind: str) -> bytes:
    if kind == "pdf":
        return render_pdf(data)
    if kind == "csv":
        return render_csv(data)
    if kind == "json":
        return render_json(data)
    raise ValueError(f"unknown report kind {kind}")


__all__ = ["FINDING_COLUMNS", "collect", "csv_safe", "finding_rows", "mask_email", "render", "write_csv"]
