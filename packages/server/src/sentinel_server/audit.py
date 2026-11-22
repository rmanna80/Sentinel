"""Tamper-evident audit log.

Entries are inserted unsealed inside the caller's transaction. Right after that transaction commits, a
single process-wide sealer numbers them (``seq``) in commit order and chains each one to the previous
with SHA-256. Sealing after commit is what keeps the chain intact when requests run concurrently:
nothing is chained to a row another transaction has not committed yet.

What the chain proves: an edit to any sealed row, or a row removed from the middle, is detected.

The chain alone cannot stop someone who can write the database file from recomputing every hash. So each
time entries are sealed, the new head is also signed with an Ed25519 key kept outside the database (see
``audit_signing``). A rebuilt chain has no valid signature. ``export_bundle`` writes the entries, signatures
and public key to one file that ``audit_verify`` can check on any machine, without this server.

What still cannot be proven from the database alone: that the newest rows were not removed along with their
signatures. Note the latest sequence number and the key fingerprint, both shown by ``verify-audit``.
"""

from __future__ import annotations

import json
import logging
import threading
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlalchemy import event, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from . import audit_signing
from .audit_verify import FORMAT, GENESIS, VERSION, entry_digest, signature_valid
from .models import AuditEntry, AuditSignature, now

log = logging.getLogger(__name__)

_seal_lock = threading.Lock()


def _digest(prev_hash: str, seq: int, ts: datetime, actor: str, action: str, target_type: str | None,
            target_id: str | None, detail: dict[str, Any]) -> str:
    return entry_digest(prev_hash, seq, ts.isoformat(), actor, action, target_type, target_id, detail)


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
                except IntegrityError:  # another process sealed at the same moment; start again from its end
                    db.rollback()
                    if attempt == 2:
                        raise
                    continue
                _sign_head(db, seq, prev)
                return len(pending)
    return 0


def _sign_head(db: Session, seq: int, entry_hash: str) -> None:
    """Sign the chain head unless it already is. Never raises: an unsigned tail is reported by verification."""
    if seq == 0:
        return
    try:
        if db.execute(select(AuditSignature.id).where(AuditSignature.seq == seq)).first() is not None:
            return
        key_id, signature = audit_signing.sign(seq, entry_hash)
        db.add(AuditSignature(seq=seq, entry_hash=entry_hash, key_id=key_id, signature=signature))
        db.commit()
    except IntegrityError:  # another process signed the same head first
        db.rollback()
    except Exception:
        db.rollback()
        log.exception("could not sign the audit chain head; it will be signed on the next attempt")


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


# --------------------------------------------------------------------------- signatures and export


@dataclass
class SignatureStatus:
    state: str  # ok | unsigned_tail | no_signatures | invalid | other_key
    key_id: str
    signatures: int
    signed_through: int  # highest sequence number covered by a signature that verifies with the current key
    latest_seq: int
    detail: str

    @property
    def ok(self) -> bool:
        return self.state == "ok"


def verify_signatures(db: Session) -> SignatureStatus:
    """Check every stored signature against the chain and the current signing key."""
    seal(db.get_bind())
    latest_seq, _ = head(db)
    key_id, public_key = audit_signing.key_id(), audit_signing.public_key_b64()
    rows = list(db.execute(select(AuditSignature).order_by(AuditSignature.seq)).scalars())
    hashes = {seq: digest for seq, digest in db.execute(
        select(AuditEntry.seq, AuditEntry.hash).where(AuditEntry.seq.in_([r.seq for r in rows] or [0])))}
    signed_through, other_key = 0, 0

    def status(state: str, detail: str) -> SignatureStatus:
        return SignatureStatus(state, key_id, len(rows), signed_through, latest_seq, detail)

    for row in rows:
        if hashes.get(row.seq) != row.entry_hash:
            return status("invalid", f"The signature at entry {row.seq} does not match the entry now stored there: "
                                     "the log was changed after it was signed.")
        if row.key_id != key_id:
            other_key += 1
            continue
        if not signature_valid(public_key, row.seq, row.entry_hash, row.signature):
            return status("invalid", f"The signature at entry {row.seq} is not valid.")
        signed_through = max(signed_through, row.seq)
    if latest_seq == 0:
        return status("ok", "The audit log is empty.")
    if other_key and signed_through < latest_seq:
        return status("other_key", f"{other_key} signature(s) were made with a signing key that is no longer in the "
                                   "credential store, so they cannot be checked here. If you did not reset the "
                                   "key, treat the log as unverified.")
    if not rows:
        return status("no_signatures", "No signatures are stored for this log.")
    if signed_through < latest_seq:
        return status("unsigned_tail", f"Entries after {signed_through} are not covered by a signature.")
    return status("ok", f"Every entry up to {latest_seq} is covered by a valid signature from key {key_id}.")


def export_bundle(db: Session) -> dict[str, Any]:
    """Everything needed to verify the log elsewhere: sealed entries, signatures, and the public key."""
    seal(db.get_bind())
    entries = [
        {"seq": e.seq, "ts": e.ts.isoformat(), "actor": e.actor, "action": e.action, "target_type": e.target_type,
         "target_id": e.target_id, "detail": e.detail, "prev_hash": e.prev_hash, "hash": e.hash}
        for e in db.execute(select(AuditEntry).where(AuditEntry.seq.is_not(None)).order_by(AuditEntry.seq)).scalars()
    ]
    signatures = [
        {"seq": s.seq, "entry_hash": s.entry_hash, "key_id": s.key_id, "signature": s.signature,
         "signed_at": s.signed_at.isoformat()}
        for s in db.execute(select(AuditSignature).order_by(AuditSignature.seq)).scalars()
    ]
    return {"format": FORMAT, "version": VERSION, "exported_at": now().isoformat(),
            "key_id": audit_signing.key_id(), "public_key": audit_signing.public_key_b64(),
            "entries": entries, "signatures": signatures}

