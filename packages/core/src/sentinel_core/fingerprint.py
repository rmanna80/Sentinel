"""Stable identity for a finding across scans."""

from __future__ import annotations

import hashlib


def fingerprint(rule_id: str, device_id: int, subject_key: str, scope: str = "") -> str:
    """SHA-256 of rule, device, subject and reconcile scope.

    The same problem seen in the next scan maps to the same fingerprint, so it updates
    the existing finding instead of creating a duplicate (and later, a duplicate alert).
    """
    raw = "\x1f".join([rule_id, str(device_id), subject_key.strip().lower(), scope])
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()
