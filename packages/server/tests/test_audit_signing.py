"""Audit signatures: a chain rebuilt by someone with the database but not the key no longer verifies."""

from __future__ import annotations

import copy
import json

import pytest
from sentinel_server import audit, audit_signing, cli
from sentinel_server.audit_verify import GENESIS, entry_digest, verify_bundle
from sentinel_server.db import session_scope
from sentinel_server.models import AuditEntry, AuditSignature
from sentinel_server.services import secrets
from sqlalchemy import select


def _some_activity(browser, n: int = 3) -> None:
    for i in range(n):
        assert browser.post("/api/assistant/conversations", json={"title": f"c{i}"}).status_code == 201


def _rebuild_chain(db) -> None:
    """What an attacker with write access to the database can do: recompute every hash so the chain verifies."""
    prev = GENESIS
    for e in db.execute(select(AuditEntry).order_by(AuditEntry.seq)).scalars():
        e.prev_hash = prev
        e.hash = entry_digest(prev, e.seq, e.ts.isoformat(), e.actor, e.action, e.target_type, e.target_id, e.detail)
        prev = e.hash


def test_every_sealed_head_is_signed_and_verifies(browser):
    _some_activity(browser)
    with session_scope() as db:
        status = audit.verify_signatures(db)
        seq, _ = audit.head(db)
        rows = list(db.execute(select(AuditSignature).order_by(AuditSignature.seq)).scalars())
    assert status.ok and status.state == "ok" and status.signed_through == seq == status.latest_seq
    assert rows and rows[-1].seq == seq and {r.key_id for r in rows} == {audit_signing.key_id()}
    assert len(status.key_id) == 16

    verify = browser.get("/api/audit/verify").json()
    assert verify["intact"] is True and verify["signature_state"] == "ok"
    assert verify["signing_key_id"] == status.key_id and verify["signed_through"] == verify["latest_seq"]


def test_the_key_is_not_in_the_database_and_survives_a_restart(browser, settings):
    _some_activity(browser, 1)
    key_before = audit_signing.key_id()
    stored = secrets.get_secret(audit_signing.SECRET_NAME)
    assert stored and stored not in (settings.data_dir / "sentinel.db").read_bytes().decode("latin-1")
    audit_signing.reset_cache()  # as after a server restart
    assert audit_signing.key_id() == key_before


def test_rebuilt_chain_passes_the_hash_check_but_fails_the_signature_check(browser):
    _some_activity(browser)
    with session_scope() as db:
        victim = db.execute(select(AuditEntry).where(AuditEntry.action == "auth.setup")).scalar_one()
        victim.actor = "user:someone-else"
        _rebuild_chain(db)
    with session_scope() as db:
        intact, bad = audit.verify_chain(db)
        status = audit.verify_signatures(db)
    assert intact is True and bad is None  # the weakness the hash chain alone has
    assert status.state == "invalid" and "changed after it was signed" in status.detail
    assert cli.main(["verify-audit"]) == 1
    assert browser.get("/api/audit/verify").json()["signature_state"] == "invalid"


def test_forged_signature_rows_do_not_verify(browser):
    _some_activity(browser)
    with session_scope() as db:
        db.execute(select(AuditEntry).order_by(AuditEntry.seq)).scalars().first().actor = "user:edited"
        _rebuild_chain(db)
        db.flush()  # the attacker also points every signature row at the new hashes, but cannot sign them
        hashes = dict(db.execute(select(AuditEntry.seq, AuditEntry.hash)).all())
        for row in db.execute(select(AuditSignature)).scalars():
            row.entry_hash = hashes[row.seq]
    with session_scope() as db:
        status = audit.verify_signatures(db)
    assert status.state == "invalid" and "is not valid" in status.detail


def test_deleted_signatures_and_a_lost_key_are_reported_not_hidden(browser):
    _some_activity(browser)
    with session_scope() as db:
        for row in db.execute(select(AuditSignature)).scalars():
            db.delete(row)
    with session_scope() as db:
        # verification seals and signs the current head again, so removing signatures cannot leave a silent gap
        assert audit.verify_signatures(db).ok

    secrets.delete_secret(audit_signing.SECRET_NAME)
    audit_signing.reset_cache()
    with session_scope() as db:
        status = audit.verify_signatures(db)
    assert status.state == "other_key" and "no longer in the credential store" in status.detail
    assert not status.ok


def test_export_verifies_offline_and_detects_every_kind_of_tampering(browser, tmp_path, capsys):
    _some_activity(browser)
    out = tmp_path / "audit.json"
    assert cli.main(["export-audit", "--out", str(out)]) == 0
    key_id = audit_signing.key_id()
    assert key_id in capsys.readouterr().out
    bundle = json.loads(out.read_text(encoding="utf-8"))
    assert bundle["format"] == "sentinel-audit-export" and bundle["key_id"] == key_id and len(bundle["entries"]) >= 4

    good = verify_bundle(bundle, key_id)
    assert good.ok and good.problems == [] and good.signed_through == good.latest_seq == len(bundle["entries"])
    assert cli.main(["verify-audit-export", str(out), "--key-id", key_id]) == 0
    assert "Verified" in capsys.readouterr().out
    assert cli.main(["verify-audit-export", str(out)]) == 0
    assert "not who signed it" in capsys.readouterr().out

    def tampered(change) -> list[str]:
        copy_ = copy.deepcopy(bundle)
        change(copy_)
        return verify_bundle(copy_, key_id).problems

    assert "changed after it was sealed" in tampered(lambda b: b["entries"][1].update(actor="user:x"))[0]
    assert "changed after it was sealed" in tampered(lambda b: b["entries"][0]["detail"].update(extra=1))[0]
    assert "missing or out of order" in tampered(lambda b: b["entries"].pop(1))[0]
    assert tampered(lambda b: b["signatures"].clear()) == ["no valid signature covers these entries"]
    assert any("not covered by a signature" in p for p in tampered(lambda b: b["signatures"].pop()))
    assert any("is not valid" in p for p in tampered(lambda b: b["signatures"][-1].update(signature="A" * 86 + "==")))
    assert any("does not match the entry" in p for p in tampered(lambda b: b["signatures"][-1].update(entry_hash="0" * 64)))
    # dropping the newest entries leaves a file that is internally consistent up to an older signature:
    # the limit the docs state, and why the latest sequence number is worth noting
    truncated = copy.deepcopy(bundle)
    keep = truncated["signatures"][0]["seq"]
    truncated["entries"] = truncated["entries"][:keep]
    truncated["signatures"] = truncated["signatures"][:1]
    short = verify_bundle(truncated, key_id)
    assert short.ok and short.latest_seq == keep < good.latest_seq

    assert verify_bundle(bundle, "0" * 16).problems[0].startswith("the export was signed with key")
    assert not verify_bundle({"format": "other"}).ok and not verify_bundle([]).ok
    assert not verify_bundle({**bundle, "version": 99}).ok

    edited = copy.deepcopy(bundle)
    edited["entries"][-1]["action"] = "edited"
    out.write_text(json.dumps(edited), encoding="utf-8")
    assert cli.main(["verify-audit-export", str(out), "--key-id", key_id]) == 1
    assert "NOT verified" in capsys.readouterr().out
    assert cli.main(["verify-audit-export", str(tmp_path / "missing.json")]) == 2


def test_an_attacker_resigning_with_their_own_key_is_caught_by_the_fingerprint(browser, tmp_path):
    _some_activity(browser)
    with session_scope() as db:
        real = audit.export_bundle(db)
    real_key = real["key_id"]

    secrets.delete_secret(audit_signing.SECRET_NAME)  # the attacker has the database, not the key: they make their own
    audit_signing.reset_cache()
    forged = copy.deepcopy(real)
    forged["entries"][0]["actor"] = "user:attacker"
    prev = GENESIS
    for e in forged["entries"]:
        e["prev_hash"] = prev
        e["hash"] = prev = entry_digest(prev, e["seq"], e["ts"], e["actor"], e["action"], e["target_type"],
                                         e["target_id"], e["detail"])
    key_id, signature = audit_signing.sign(forged["entries"][-1]["seq"], prev)
    forged.update(public_key=audit_signing.public_key_b64(), key_id=key_id,
                  signatures=[{"seq": forged["entries"][-1]["seq"], "entry_hash": prev, "key_id": key_id,
                               "signature": signature, "signed_at": "2026-01-01T00:00:00+00:00"}])
    assert verify_bundle(forged).ok  # internally consistent...
    caught = verify_bundle(forged, real_key)  # ...but not signed by the key the owner noted
    assert not caught.ok and "not the expected" in caught.problems[0]


def test_audit_export_download_is_itself_audited(browser):
    _some_activity(browser, 1)
    r = browser.get("/api/audit/export")
    assert r.status_code == 200 and "attachment" in r.headers["content-disposition"]
    assert verify_bundle(r.json(), audit_signing.key_id()).ok
    actions = [i["action"] for i in browser.get("/api/audit", params={"limit": 5}).json()["items"]]
    assert "audit.exported" in actions


@pytest.mark.parametrize("empty", [True])
def test_empty_log_is_ok(app, anon, empty):
    with session_scope() as db:
        status = audit.verify_signatures(db)
    assert status.ok and status.latest_seq == 0 and status.signatures == 0
