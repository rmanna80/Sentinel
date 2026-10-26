"""Remove secrets from evidence before it is stored or logged."""

from __future__ import annotations

import re
from typing import Any

_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"(?i)(password|passwd|pwd|secret|token|api[_-]?key|authorization)\s*[=:]\s*\S+"), r"\1=[REDACTED]"),
    (re.compile(r"(?i)bearer\s+[A-Za-z0-9._~+/=-]{8,}"), "Bearer [REDACTED]"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "[REDACTED-AWS-KEY]"),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"), "[REDACTED-GITHUB-TOKEN]"),
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"), "[REDACTED-PRIVATE-KEY]"),
]
_SECRET_KEYS = re.compile(r"(?i)^(password|passwd|pwd|secret|token|api[_-]?key|authorization|cookie)$")


def redact_text(text: str) -> tuple[str, bool]:
    changed = False
    for pattern, repl in _PATTERNS:
        text, n = pattern.subn(repl, text)
        changed = changed or n > 0
    return text, changed


def redact(value: Any) -> tuple[Any, bool]:
    """Recursively redact strings and secret-named keys. Returns (value, was_redacted)."""
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, dict):
        changed = False
        out: dict[Any, Any] = {}
        for k, v in value.items():
            if isinstance(k, str) and _SECRET_KEYS.match(k) and v not in (None, "", False):
                out[k] = "[REDACTED]"
                changed = True
                continue
            out[k], c = redact(v)
            changed = changed or c
        return out, changed
    if isinstance(value, list):
        changed = False
        items = []
        for v in value:
            nv, c = redact(v)
            items.append(nv)
            changed = changed or c
        return items, changed
    return value, False
