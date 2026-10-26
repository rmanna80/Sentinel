"""Tamper-evident audit log.

Entries are inserted unsealed inside the caller's transaction. Right after that transaction commits, a
single process-wide sealer numbers them (``seq``) in commit order and chains each one to the previous
with SHA-256. Sealing after commit is what keeps the chain intact when requests run concurrently:
nothing is chained to a row another transaction has not committed yet.

What the chain proves: an edit to any sealed row, or a row removed from the middle, is detected.
What it cannot prove: someone who can write the database file can rebuild the whole chain, or delete
the newest rows. The latest sequence number and hash are shown on the Audit page so they can be noted.
"""

from __future__ import annotations

import hashlib
import json
import logging
import threading
from datetime import datetime
from typing import Any

from sqlalchemy import event, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .models import AuditEntry, now

log = logging.getLogger(__name__)

GENESIS = "0" * 64
_seal_lock = threading.Lock()


def _digest(prev_hash: str, seq: int, ts: datetime, actor: str, action: str, target_type: str | None,
            target_id: str | None, detail: dict[str, Any]) -> str:
    payload = json.dumps(
        {"prev": prev_hash, "seq": seq, "ts": ts.isoformat(), "actor": actor, "action": action,
         "target_type": target_type, "target_id": target_id, "detail": detail},
        sort_keys=True, default=str, separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def record(db: Session, actor: str, action: str, target_type: str | None = None,
           target_id: object | None = None, detail: dict[str, Any] | None = None) -> AuditEntry:
    """Append an unsealed audit entry. The caller commits; sealing follows the commit automatically."""
    ts = now().replace(microsecond=0)
    clean_detail = json.loads(json.dumps(detail or {}, default=str))
    entry = AuditEntry(ts=ts, actor=actor, action=action, target_type=target_type,
                       target_id=str(target_id) if target_id is not None else None,
                       detail=clean_detail, prev_hash="", hash="", seq=None)
    db.add(entry)
    db.flush()
    db.info["audit_pending"] = True
    return entry


def seal(bind: Any | None = None) -> int:
    """Chain every committed, unsealed entry. Returns how many were sealed."""
    from .db import get_engine

    engine = bind or get_engine()
    with _seal_lock:
        for attempt in range(3):
            with Session(engine) as db:
                last = db.execute(select(AuditEntry).where(AuditEntry.seq.is_not(None))
                                  .order_by(AuditEntry.seq.desc()).limit(1)).scalar_one_or_none()
                prev, seq = (last.hash, last.seq) if last is not None and last.seq is not None else (GENESIS, 0)
                pending = list(db.execute(select(AuditEntry).where(AuditEntry.seq.is_(None))
                                          .order_by(AuditEntry.id)).scalars())
                for e in pending:
                    seq += 1
                    e.seq = seq
                    e.prev_hash = prev
                    e.hash = _digest(prev, seq, e.ts, e.actor, e.action, e.target_type, e.target_id, e.detail)
                    prev = e.hash
                try:
                    db.commit()
                    return len(pending)
                except IntegrityError:  # another process sealed at the same moment; start again from its end
                    db.rollback()
                    if attempt == 2:
                        raise
    return 0


@event.listens_for(Session, "after_commit")
def _seal_after_commit(session: Session) -> None:
    if session.info.pop("audit_pending", False):
        try:
            seal(session.get_bind())
        except Exception:
            log.exception("could not seal audit entries; they will be sealed on the next attempt")


def verify_chain(db: Session) -> tuple[bool, int | None]:
    """Return (intact, first_bad_id) over sealed entries, sealing anything committed but unsealed first."""
    seal(db.get_bind())
    prev = GENESIS
    rows = db.execute(select(AuditEntry).where(AuditEntry.seq.is_not(None)).order_by(AuditEntry.seq)).scalars()
    for expected_seq, entry in enumerate(rows, start=1):
        assert entry.seq is not None
        digest = _digest(prev, entry.seq, entry.ts, entry.actor, entry.action, entry.target_type, entry.target_id,
                         entry.detail)
        if entry.seq != expected_seq or entry.prev_hash != prev or entry.hash != digest:
            return False, entry.id
        prev = entry.hash
    return True, None


def head(db: Session) -> tuple[int, str]:
    """(latest sequence number, its hash): note these down to detect later truncation."""
    last = db.execute(select(AuditEntry).where(AuditEntry.seq.is_not(None))
                      .order_by(AuditEntry.seq.desc()).limit(1)).scalar_one_or_none()
    return (last.seq or 0, last.hash) if last else (0, GENESIS)


def unsealed_count(db: Session) -> int:
    return db.execute(select(func.count(AuditEntry.id)).where(AuditEntry.seq.is_(None))).scalar_one()
