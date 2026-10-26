"""Small helpers shared by checks."""

from __future__ import annotations

from typing import Any

from sentinel_core.models import Confidence, Finding, FindingKind, Severity

WIN = "windows"


def finding(
    rule_id: str,
    subject_key: str,
    title: str,
    severity: Severity,
    impact: str,
    remediation: str,
    *,
    confidence: Confidence = Confidence.HIGH,
    kind: FindingKind = FindingKind.VERIFIED,
    references: list[str] | None = None,
    evidence_refs: list[int] | None = None,
    category: str | None = None,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        subject_key=subject_key,
        title=title,
        severity=severity,
        confidence=confidence,
        kind=kind,
        impact=impact,
        remediation=remediation,
        references=references or [],
        evidence_refs=evidence_refs if evidence_refs is not None else [0],
        category=category,
    )


def as_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def is_home_edition(edition: str | None) -> bool:
    return bool(edition) and edition.lower().startswith("home")  # type: ignore[union-attr]
