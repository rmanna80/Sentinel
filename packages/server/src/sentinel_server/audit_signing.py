"""The audit log's signing key.

The hash chain in :mod:`.audit` detects an edit to a sealed entry, but anyone who can write the database file
can recompute every hash and present a chain that verifies. Signing closes that: each time entries are sealed,
the new head of the chain is signed with an Ed25519 key that is **not in the database**. It lives in the
operating system's credential store (Windows Credential Manager, the Linux Secret Service) or, where there is
none, in the same private file as Sentinel's other secrets. A rebuilt chain then has no valid signature.

Be clear about the limit. This defends against a database file that is edited by someone, or something,
without access to this user's credential store: a tampered backup, another account, a copy altered on another
machine. Code running as the signed-in user can read the credential store too. The key's fingerprint is what
you compare over time; note it once.
"""

from __future__ import annotations

import base64
import logging
import threading

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .audit_verify import key_id_of, signed_message
from .services import secrets

log = logging.getLogger(__name__)

SECRET_NAME = "audit-signing-key"  # noqa: S105 - the name of the secret, not its value
_lock = threading.Lock()
_cached: Ed25519PrivateKey | None = None


def reset_cache() -> None:
    """Forget the loaded key (tests switch data folders; a running server never needs this)."""
    global _cached
    with _lock:
        _cached = None


def _load_or_create() -> Ed25519PrivateKey:
    global _cached
    with _lock:
        if _cached is not None:
            return _cached
        stored = secrets.get_secret(SECRET_NAME)
        if stored:
            try:
                _cached = Ed25519PrivateKey.from_private_bytes(base64.b64decode(stored, validate=True))
                return _cached
            except ValueError:
                log.error("the stored audit signing key is unreadable; a new key will be created and earlier "
                          "signatures will be reported as made with a key that is no longer present")
        key = Ed25519PrivateKey.generate()
        raw = key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                                serialization.NoEncryption())
        where = secrets.set_secret(SECRET_NAME, base64.b64encode(raw).decode("ascii"))
        log.info("created the audit signing key %s (stored in the %s)", key_id_of(_public_bytes(key)), where)
        _cached = key
        return key


def _public_bytes(key: Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def public_key_b64() -> str:
    return base64.b64encode(_public_bytes(_load_or_create())).decode("ascii")


def key_id() -> str:
    return key_id_of(_public_bytes(_load_or_create()))


def sign(seq: int, entry_hash: str) -> tuple[str, str]:
    """Sign the chain head at ``seq``. Returns (key id, base64 signature)."""
    key = _load_or_create()
    signature = key.sign(signed_message(seq, entry_hash))
    return key_id_of(_public_bytes(key)), base64.b64encode(signature).decode("ascii")
