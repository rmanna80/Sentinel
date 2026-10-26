"""Finding lifecycle: dedupe by fingerprint, verified resolution, reopen, and user workflow."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sentinel_core.fingerprint import fingerprint
from sentinel_core.models import OPEN_FINDING_STATUSES, Finding, FindingStatus
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import audit
from ..models import CheckRun, FindingEvent, FindingObservation, FindingRecord, Scan, now

OPEN = {s.value for s in OPEN_FINDING_STATUSES}

# What a person may change a finding to. "resolved" is absent on purpose: only a passing
# re-run of the check that found it can resolve a finding.
USER_TRANSITIONS: dict[str, set[str]] = {
    "new": {"confirmed", "in_progress", "accepted_risk"},
    "confirmed": {"in_progress", "accepted_risk"},
    "in_progress": {"confirmed", "accepted_risk"},
    "accepted_risk": {"confirmed", "in_progress"},
    "reopened": {"confirmed", "in_progress", "accepted_risk"},
    "resolved": set(),
}


class TransitionError(ValueError):
    pass


def _event(db: Session, finding: FindingRecord, actor: str, from_status: str | None, to_status: str | None,
           note: str | None = None, changes: dict[str, Any] | None = None) -> None:
    db.add(FindingEvent(finding_id=finding.id, actor=actor, from_status=from_status, to_status=to_status,
                        note=note, changes=changes or {}))


def reconcile(
    db: Session,
    *,
    device_id: int,
    scan: Scan,
    check_run: CheckRun,
    findings: list[Finding],
    evidence_ids: list[int],
    category_default: str,
    source: str = "agent",
    scope: str = "",
    reconcile_check_id: str | None = None,
) -> tuple[list[FindingRecord], list[FindingRecord], list[FindingRecord]]:
    """Apply one completed check run's findings. Returns (created, reopened, resolved).

    Only call this for runs that completed (passed/failed). A skipped or failed run proves
    nothing, so it must never resolve anything.
    """
    check_id = reconcile_check_id or check_run.check_id
    t = check_run.finished_at or now()
    created: list[FindingRecord] = []
    reopened: list[FindingRecord] = []
    resolved: list[FindingRecord] = []

    existing = {
        f.fingerprint: f
        for f in db.execute(
            select(FindingRecord).where(
                FindingRecord.device_id == device_id,
                FindingRecord.check_id == check_id,
                FindingRecord.source == source,
                FindingRecord.scope == scope,
            )
        ).scalars()
    }
    seen: set[str] = set()
    for item in findings:
        fp = fingerprint(item.rule_id, device_id, item.subject_key, scope)
        if fp in seen:
            continue
        seen.add(fp)
        ev_ids = [evidence_ids[i] for i in item.evidence_refs if 0 <= i < len(evidence_ids)]
        rec = existing.get(fp)
        values: dict[str, Any] = dict(
            rule_id=item.rule_id, title=item.title, category=item.category or category_default,
            severity=item.severity.value, confidence=item.confidence.value, finding_kind=item.kind.value,
            impact=item.impact, remediation=item.remediation, references=list(item.references),
            subject_key=item.subject_key, vuln_id=item.vuln_id, cve_id=item.cve_id, cvss_score=item.cvss_score,
            cvss_vector=item.cvss_vector, cvss_source=item.cvss_source,
            affected_software=item.affected_software, fixed_version=item.fixed_version,
        )
        if rec is None:
            rec = FindingRecord(device_id=device_id, fingerprint=fp, check_id=check_id, source=source, scope=scope,
                                status=FindingStatus.NEW.value, first_seen_scan_id=scan.id,
                                last_seen_scan_id=scan.id, first_seen_at=t, last_seen_at=t, **values)
            db.add(rec)
            db.flush()
            _event(db, rec, "system", None, FindingStatus.NEW.value, f"Found by {check_id} in scan {scan.id}")
            created.append(rec)
        else:
            for k, v in values.items():
                setattr(rec, k, v)
            rec.last_seen_scan_id = scan.id
            rec.last_seen_at = t
            if rec.status == FindingStatus.RESOLVED.value:
                rec.status = FindingStatus.REOPENED.value
                rec.reopened_count += 1
                rec.verified_resolved_at = None
                rec.resolved_by_check_run_id = None
                _event(db, rec, "system", FindingStatus.RESOLVED.value, FindingStatus.REOPENED.value,
                       f"Seen again by {check_id} in scan {scan.id}")
                reopened.append(rec)
        db.add(FindingObservation(finding_id=rec.id, check_run_id=check_run.id, evidence_ids=ev_ids, observed_at=t))

    for fp, rec in existing.items():
        if fp in seen or rec.status not in OPEN:
            continue
        previous = rec.status
        rec.status = FindingStatus.RESOLVED.value
        rec.verified_resolved_at = t
        rec.resolved_by_check_run_id = check_run.id
        _event(db, rec, "system", previous, FindingStatus.RESOLVED.value,
               f"Verified resolved: {check_id} completed in scan {scan.id} without reporting it")
        resolved.append(rec)
    return created, reopened, resolved


def apply_user_update(
    db: Session,
    finding: FindingRecord,
    actor: str,
    *,
    status: str | None = None,
    note: str | None = None,
    owner: str | None = None,
    target_date: str | None = None,
    fields_set: set[str] | None = None,
) -> FindingRecord:
    fields_set = fields_set or set()
    changes: dict[str, Any] = {}
    from_status = finding.status
    if status is not None and status != finding.status:
        if status == FindingStatus.RESOLVED.value:
            raise TransitionError("A finding is resolved only when a re-run of its check no longer reports it. "
                                  "Use Verify to re-run the check.")
        allowed = USER_TRANSITIONS.get(finding.status, set())
        if status not in allowed:
            raise TransitionError(f"Cannot change status from {finding.status} to {status}")
        finding.status = status
        if status == FindingStatus.CONFIRMED.value and finding.acknowledged_at is None:
            finding.acknowledged_at = now()
    if "owner" in fields_set and owner != finding.owner:
        changes["owner"] = {"from": finding.owner, "to": owner}
        finding.owner = owner
    if "target_date" in fields_set and target_date != finding.target_date:
        if target_date is not None:
            datetime.strptime(target_date, "%Y-%m-%d")  # raises ValueError on bad input
        changes["target_date"] = {"from": finding.target_date, "to": target_date}
        finding.target_date = target_date
    if from_status != finding.status or changes or note:
        _event(db, finding, actor, from_status if from_status != finding.status else None,
               finding.status if from_status != finding.status else None, note, changes)
        audit.record(db, actor, "finding.update", "finding", finding.id,
                     {"from": from_status, "to": finding.status, "changes": changes, "note": bool(note)})
    return finding
