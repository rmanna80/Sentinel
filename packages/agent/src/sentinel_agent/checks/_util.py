"""Small helpers shared by checks."""

from __future__ import annotations

import ntpath
import posixpath
import re
from datetime import UTC, datetime
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


def parse_iso(value: Any) -> datetime | None:
    """Parse an ISO 8601 timestamp (PowerShell's ``ToString('o')`` included). Naive values are taken as UTC."""
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        dt = datetime.fromisoformat(value.strip())
    except ValueError:
        return None
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=UTC)


def join_path(base: str, *parts: str) -> str:
    """Join paths using Windows rules for a Windows-style base, POSIX rules otherwise (tests run on Linux)."""
    if re.match(r"^[A-Za-z]:[\\/]", base) or base.startswith("\\\\"):
        return ntpath.join(base, *parts)
    return posixpath.join(base, *parts)


def windows_temp_like(path: str) -> str | None:
    """Return which risky user-writable folder a Windows path points into, or None."""
    p = path.replace("/", "\\").lower()
    for marker, label in (
        ("\\appdata\\local\\temp\\", "AppData\\Local\\Temp"),
        ("%temp%\\", "Temp"),
        ("%tmp%\\", "Temp"),
        ("\\temp\\", "Temp"),
        ("\\downloads\\", "Downloads"),
        ("\\users\\public\\", "Users\\Public"),
    ):
        if marker in p:
            return label
    return None


def ok_int(value: Any, default: int = 0) -> int:
    parsed = as_int(value)
    return default if parsed is None else parsed


def ps_list(value: Any) -> list[Any]:
    """Like ``as_list`` but also unwraps Windows PowerShell 5.1's ``{"value": [...], "Count": n}`` array quirk."""
    if isinstance(value, dict) and set(value) <= {"value", "Count"} and isinstance(value.get("value"), list):
        return list(value["value"])
    if value is None:
        return []
    return value if isinstance(value, list) else [value]
