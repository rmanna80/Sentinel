"""Tamper-evident audit log: every row carries the hash of the row before it."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import AuditEntry, now

GENESIS = "0" * 64


def _digest(prev_hash: str, ts: datetime, actor: str, action: str, target_type: str | None,
            target_id: str | None, detail: dict[str, Any]) -> str:
    payload = json.dumps(
        {"prev": prev_hash, "ts": ts.isoformat(), "actor": actor, "action": action,
         "target_type": target_type, "target_id": target_id, "detail": detail},
        sort_keys=True, default=str, separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def record(db: Session, actor: str, action: str, target_type: str | None = None,
           target_id: object | None = None, detail: dict[str, Any] | None = None) -> AuditEntry:
    """Append an audit entry. The caller commits."""
    last = db.execute(select(AuditEntry).order_by(AuditEntry.id.desc()).limit(1)).scalar_one_or_none()
    prev = last.hash if last else GENESIS
    ts = now().replace(microsecond=0)
    clean_detail = json.loads(json.dumps(detail or {}, default=str))
    tid = str(target_id) if target_id is not None else None
    entry = AuditEntry(ts=ts, actor=actor, action=action, target_type=target_type, target_id=tid,
                       detail=clean_detail, prev_hash=prev,
                       hash=_digest(prev, ts, actor, action, target_type, tid, clean_detail))
    db.add(entry)
    db.flush()
    return entry


def verify_chain(db: Session) -> tuple[bool, int | None]:
    """Return (intact, first_bad_id)."""
    prev = GENESIS
    for entry in db.execute(select(AuditEntry).order_by(AuditEntry.id)).scalars():
        expected = _digest(prev, entry.ts, entry.actor, entry.action, entry.target_type, entry.target_id,
                           entry.detail)
        if entry.prev_hash != prev or entry.hash != expected:
            return False, entry.id
        prev = entry.hash
    return True, None
