"""Verify an exported audit log with nothing but this file, the export and the ``cryptography`` package.

This module deliberately imports no other part of Sentinel and touches no database. An audit export is a JSON
file holding every sealed entry, the Ed25519 signatures over the chain, and the public key they were made
with; :func:`verify_bundle` re-derives every hash and checks every signature. Give the file to an auditor, or
copy this module to another machine, and the result does not depend on trusting the server that produced it.

What a passing verification proves, and what it does not:

* every entry is exactly as it was when it was sealed, and none is missing from the middle;
* the chain up to ``signed_through`` was signed by the holder of the private key named by ``key_id``;
* it does **not** prove nothing was removed from the end after the last signature you already knew about, and
  it does **not** prove the key belongs to who you think. Compare ``key_id`` with the one you noted when the
  server was set up (``sentinel-server verify-audit`` prints it), and note the latest sequence number.
"""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass, field
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

GENESIS = "0" * 64
FORMAT = "sentinel-audit-export"
VERSION = 1
_DOMAIN = b"sentinel-audit-v1"  # binds a signature to this purpose, so it can never be replayed as anything else


def entry_digest(prev_hash: str, seq: int, ts_iso: str, actor: str, action: str, target_type: str | None,
                 target_id: str | None, detail: dict[str, Any]) -> str:
    """The hash that chains one audit entry to the one before it."""
    payload = json.dumps(
        {"prev": prev_hash, "seq": seq, "ts": ts_iso, "actor": actor, "action": action,
         "target_type": target_type, "target_id": target_id, "detail": detail},
        sort_keys=True, default=str, separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def signed_message(seq: int, entry_hash: str) -> bytes:
    """What is signed: the position and hash of one entry. Because entries are chained, that covers all before it."""
    return _DOMAIN + b"\n" + str(seq).encode("ascii") + b"\n" + entry_hash.encode("ascii")


def key_id_of(public_key: bytes) -> str:
    """A short fingerprint of a public key, for people to compare."""
    return hashlib.sha256(public_key).hexdigest()[:16]


def signature_valid(public_key_b64: str, seq: int, entry_hash: str, signature_b64: str) -> bool:
    try:
        key = Ed25519PublicKey.from_public_bytes(base64.b64decode(public_key_b64, validate=True))
        key.verify(base64.b64decode(signature_b64, validate=True), signed_message(seq, entry_hash))
    except (InvalidSignature, ValueError, TypeError):
        return False
    return True


@dataclass
class Verdict:
    ok: bool = True
    entries: int = 0
    signatures: int = 0
    signed_through: int = 0  # the highest sequence number covered by a valid signature
    latest_seq: int = 0
    latest_hash: str = GENESIS
    key_id: str = ""
    problems: list[str] = field(default_factory=list)

    def fail(self, problem: str) -> None:
        self.ok = False
        if len(self.problems) < 50:
            self.problems.append(problem)


def verify_bundle(bundle: Any, expected_key_id: str | None = None) -> Verdict:
    """Check an export end to end. ``expected_key_id`` is the fingerprint you noted earlier, if you have one."""
    verdict = Verdict()
    if not isinstance(bundle, dict) or bundle.get("format") != FORMAT:
        verdict.fail("this is not a Sentinel audit export")
        return verdict
    if bundle.get("version") != VERSION:
        verdict.fail(f"export version {bundle.get('version')!r} is not understood by this verifier")
        return verdict
    entries, signatures, public_key = bundle.get("entries"), bundle.get("signatures"), bundle.get("public_key")
    if not isinstance(entries, list) or not isinstance(signatures, list) or not isinstance(public_key, str):
        verdict.fail("the export is missing its entries, signatures or public key")
        return verdict
    try:
        verdict.key_id = key_id_of(base64.b64decode(public_key, validate=True))
    except ValueError:
        verdict.fail("the public key is not valid base64")
        return verdict
    if expected_key_id and expected_key_id.lower() != verdict.key_id:
        verdict.fail(f"the export was signed with key {verdict.key_id}, not the expected {expected_key_id.lower()}")

    hashes: dict[int, str] = {}
    prev = GENESIS
    for position, entry in enumerate(entries, start=1):
        try:
            seq = int(entry["seq"])
            digest = entry_digest(prev, seq, str(entry["ts"]), str(entry["actor"]), str(entry["action"]),
                                  entry.get("target_type"), entry.get("target_id"), entry.get("detail") or {})
            if seq != position:
                verdict.fail(f"entry {position} is numbered {seq}: an entry is missing or out of order")
                break
            if entry.get("prev_hash") != prev or entry.get("hash") != digest:
                verdict.fail(f"entry {seq} does not match its hash: it was changed after it was sealed")
                break
        except (KeyError, TypeError, ValueError):
            verdict.fail(f"entry {position} is malformed")
            break
        hashes[seq] = prev = digest
        verdict.entries, verdict.latest_seq, verdict.latest_hash = position, seq, digest

    for sig in signatures:
        try:
            seq, entry_hash, signature = int(sig["seq"]), str(sig["entry_hash"]), str(sig["signature"])
        except (KeyError, TypeError, ValueError):
            verdict.fail("a signature record is malformed")
            continue
        verdict.signatures += 1
        if sig.get("key_id") != verdict.key_id:
            verdict.fail(f"the signature at entry {seq} was made with a different key ({sig.get('key_id')})")
        elif hashes.get(seq) != entry_hash:
            verdict.fail(f"the signature at entry {seq} does not match the entry in this export")
        elif not signature_valid(public_key, seq, entry_hash, signature):
            verdict.fail(f"the signature at entry {seq} is not valid")
        else:
            verdict.signed_through = max(verdict.signed_through, seq)
    if verdict.entries and verdict.signed_through < verdict.latest_seq:
        verdict.fail(f"entries after {verdict.signed_through} are not covered by a signature"
                     if verdict.signed_through else "no valid signature covers these entries")
    return verdict
