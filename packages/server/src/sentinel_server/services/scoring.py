"""The security score. Documented in docs/scoring.md; never random, never decorative."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from sentinel_core.models import OPEN_FINDING_STATUSES, SEVERITY_RANK, CheckStatus, Severity
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import Alert, CheckRun, FindingRecord, Scan

WEIGHTS = {Severity.CRITICAL: 20, Severity.HIGH: 8, Severity.MEDIUM: 3, Severity.LOW: 1, Severity.INFO: 0}
OPEN_STATUSES = [s.value for s in OPEN_FINDING_STATUSES]
OPEN_ALERT_STATUSES = ["new", "acknowledged", "investigating"]
POSTURE_SCAN_TYPES = ("full", "posture")


def counts_toward_score(f: FindingRecord) -> bool:
    """Verified findings count; heuristics count only at high confidence; informational never."""
    if f.severity == Severity.INFO.value or f.finding_kind == "informational":
        return False
    return f.finding_kind == "verified" or (f.finding_kind == "heuristic" and f.confidence == "high")


def score_from_counts(counts: dict[str, int]) -> int:
    deduction = sum(WEIGHTS[Severity(sev)] * n for sev, n in counts.items() if sev in Severity._value2member_map_)
    return max(0, 100 - deduction)


def coverage_of(runs: list[CheckRun]) -> tuple[int, int]:
    """(completed, applicable). Not-applicable checks are left out of both."""
    applicable = [r for r in runs if r.status != CheckStatus.NOT_APPLICABLE.value]
    completed = [r for r in applicable if r.status in (CheckStatus.PASSED.value, CheckStatus.FAILED.value)]
    return len(completed), len(applicable)


@dataclass
class Posture:
    score: int | None
    raw_score: int
    coverage: float | None
    checks_completed: int
    checks_applicable: int
    incomplete: bool
    counts: dict[str, int] = field(default_factory=dict)
    open_findings: int = 0
    threat_level: str = "informational"
    basis_scan_id: int | None = None

    def as_dict(self) -> dict[str, Any]:
        return self.__dict__.copy()


def open_finding_counts(db: Session, device_ids: list[int] | None = None) -> tuple[dict[str, int], int]:
    q = select(FindingRecord).where(FindingRecord.status.in_(OPEN_STATUSES))
    if device_ids is not None:
        q = q.where(FindingRecord.device_id.in_(device_ids))
    counts = {s.value: 0 for s in Severity}
    total = 0
    for f in db.execute(q).scalars():
        total += 1
        if counts_toward_score(f):
            counts[f.severity] += 1
    return counts, total


def threat_level(db: Session, device_ids: list[int] | None, counts: dict[str, int]) -> str:
    """Highest severity among open alerts and open counted findings."""
    q = select(Alert.severity).where(Alert.status.in_(OPEN_ALERT_STATUSES))
    if device_ids is not None:
        q = q.where(Alert.device_id.in_(device_ids))
    severities = [Severity(s) for s in db.execute(q).scalars()]
    severities += [Severity(s) for s, n in counts.items() if n > 0]
    if not severities:
        return "informational"
    top = max(severities, key=lambda s: SEVERITY_RANK[s])
    return "informational" if top is Severity.INFO else top.value


def latest_posture_scan(db: Session, device_id: int) -> Scan | None:
    return db.execute(
        select(Scan)
        .where(Scan.device_id == device_id, Scan.scan_type.in_(POSTURE_SCAN_TYPES),
               Scan.status.in_(("completed", "partial", "cancelled")))
        .order_by(Scan.completed_at.desc())
        .limit(1)
    ).scalar_one_or_none()


def device_posture(db: Session, device_id: int, min_coverage: float) -> Posture:
    counts, total_open = open_finding_counts(db, [device_id])
    raw = score_from_counts(counts)
    scan = latest_posture_scan(db, device_id)
    completed, applicable = coverage_of(list(scan.check_runs)) if scan else (0, 0)
    coverage = (completed / applicable) if applicable else None
    incomplete = coverage is None or coverage < min_coverage
    return Posture(
        score=None if incomplete else raw, raw_score=raw, coverage=coverage, checks_completed=completed,
        checks_applicable=applicable, incomplete=incomplete, counts=counts, open_findings=total_open,
        threat_level=threat_level(db, [device_id], counts), basis_scan_id=scan.id if scan else None,
    )


def fleet_posture(db: Session, device_ids: list[int], min_coverage: float) -> Posture:
    """Across devices the score is the lowest device score: one weak machine is the weak point."""
    if not device_ids:
        return Posture(score=None, raw_score=100, coverage=None, checks_completed=0, checks_applicable=0,
                       incomplete=True, counts={s.value: 0 for s in Severity})
    per = [device_posture(db, d, min_coverage) for d in device_ids]
    counts = {s.value: sum(p.counts.get(s.value, 0) for p in per) for s in Severity}
    completed = sum(p.checks_completed for p in per)
    applicable = sum(p.checks_applicable for p in per)
    coverage = completed / applicable if applicable else None
    incomplete = any(p.incomplete for p in per)
    raw = min(p.raw_score for p in per)
    return Posture(
        score=None if incomplete else raw, raw_score=raw, coverage=coverage, checks_completed=completed,
        checks_applicable=applicable, incomplete=incomplete, counts=counts,
        open_findings=sum(p.open_findings for p in per),
        threat_level=threat_level(db, device_ids, counts),
    )


def scan_snapshot(db: Session, scan: Scan, min_coverage: float) -> dict[str, Any]:
    """Score and coverage frozen onto the scan when it completes, for score history."""
    completed, applicable = coverage_of(list(scan.check_runs))
    counts, _ = open_finding_counts(db, [scan.device_id])
    raw = score_from_counts(counts)
    coverage = completed / applicable if applicable else None
    statuses: dict[str, int] = {}
    for r in scan.check_runs:
        statuses[r.status] = statuses.get(r.status, 0) + 1
    return {
        "score": raw if coverage is not None and coverage >= min_coverage else None,
        "raw_score": raw,
        "coverage": coverage,
        "checks_completed": completed,
        "checks_applicable": applicable,
        "check_statuses": statuses,
        "open_counts": counts,
    }
