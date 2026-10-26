"""Phase 4: HIBP breach checks, classification, notifications, exports and Pwned Passwords relaying.

HIBP and Pwned Passwords responses here are hand-written to match the documented API v3 formats
(https://haveibeenpwned.com/API/v3); they are not recordings. No test touches the network.
"""

from __future__ import annotations

import csv
import hashlib
import io
from typing import Any

import httpx
import pytest
from sentinel_server.db import session_scope
from sentinel_server.integrations import hibp, http
from sentinel_server.models import Notification, OutboundRequest
from sentinel_server.services import secrets
from sqlalchemy import select

EMAIL = "Ryan.Test+alerts@Example.com"
NORMALIZED = "ryan.test+alerts@example.com"
API_KEY = "test-hibp-key-0123456789"


def breach(name: str, *, classes: tuple[str, ...] = ("Email addresses", "Passwords"), verified: bool = True,
           title: str | None = None, **flags: Any) -> dict[str, Any]:
    """One breach in the full (truncateResponse=false) API v3 breach model."""
    return {"Name": name, "Title": title or name, "Domain": f"{name.lower()}.com", "BreachDate": "2019-05-01",
            "AddedDate": "2019-06-01T00:00:00Z", "ModifiedDate": "2019-06-01T00:00:00Z", "PwnCount": 1000,
            "Description": "<p>Sample &amp; <a href=\"https://example.com\">description</a></p>",
            "DataClasses": list(classes), "IsVerified": verified, "IsFabricated": False, "IsSensitive": False,
            "IsRetired": False, "IsSpamList": False, "IsMalware": False, "IsSubscriptionFree": False,
            "IsStealerLog": False, "LogoPath": "https://logos.haveibeenpwned.com/x.png", "Attribution": None, **flags}


class FakeApi:
    def __init__(self) -> None:
        self.replies: list[httpx.Response] = []
        self.requests: list[httpx.Request] = []

    def reply(self, status: int, body: Any = None, headers: dict[str, str] | None = None, text: str | None = None) -> None:
        if text is not None:
            self.replies.append(httpx.Response(status, text=text, headers=headers))
        else:
            self.replies.append(httpx.Response(status, json=body, headers=headers))

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        return self.replies.pop(0)


class Clock:
    def __init__(self) -> None:
        self.t = 1000.0
        self.sleeps: list[float] = []

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.t += seconds


@pytest.fixture(autouse=True)
def clock(monkeypatch) -> Clock:
    # never touch the developer's real OS credential store from a test
    monkeypatch.setattr(secrets, "backend_name", lambda: "file")
    c = Clock()
    monkeypatch.setattr(hibp, "_clock", lambda: c.t)
    monkeypatch.setattr(hibp, "_sleep", c.sleep)
    hibp.reset()
    yield c
    hibp.reset()


@pytest.fixture
def fake() -> FakeApi:
    f = FakeApi()
    http.set_transport(httpx.MockTransport(f.handler))
    yield f
    http.set_transport(None)


@pytest.fixture
def hibp_on(browser) -> None:
    assert browser.put("/api/settings/integrations", json={"hibp": {"enabled": True}}).status_code == 200
    assert browser.put("/api/secrets/hibp_api_key", json={"value": API_KEY}).status_code == 200


@pytest.fixture
def identity(browser) -> dict[str, Any]:
    r = browser.post("/api/email/identities", json={"email": EMAIL, "label": "Personal", "ownership_confirmed": True})
    assert r.status_code == 201, r.text
    return r.json()


def check(browser, identity_id: int) -> dict[str, Any]:
    r = browser.post(f"/api/email/identities/{identity_id}/check")
    assert r.status_code == 200, r.text
    return r.json()


# --------------------------------------------------------------------------- identities


def test_identity_requires_ownership_confirmation(browser):
    assert browser.post("/api/email/identities", json={"email": EMAIL}).status_code == 422
    for not_true in (False, "yes", 1):
        r = browser.post("/api/email/identities", json={"email": EMAIL, "ownership_confirmed": not_true})
        assert r.status_code == 422, not_true
    for bad in ("not-an-email", "a@b", "two@@example.com", "x@example.com\nBcc: y@example.com"):
        r = browser.post("/api/email/identities", json={"email": bad, "ownership_confirmed": True})
        assert r.status_code == 422, bad
    r = browser.post("/api/email/identities", json={"email": f"  {EMAIL} ", "ownership_confirmed": True})
    assert r.status_code == 201
    created = r.json()
    assert created["email"] == NORMALIZED and created["masked_email"] == "r***@example.com"
    assert created["latest_status"] is None and created["breach_count"] is None
    dup = browser.post("/api/email/identities", json={"email": NORMALIZED, "ownership_confirmed": True})
    assert dup.status_code == 409

    [listed] = browser.get("/api/email/identities").json()
    assert listed["id"] == created["id"]
    assert browser.delete(f"/api/email/identities/{created['id']}").status_code == 204
    assert browser.get("/api/email/identities").json() == []

    audit = browser.get("/api/audit", params={"action": "email."}).json()["items"]
    assert {a["action"] for a in audit} == {"email.identity_added", "email.identity_deleted"}
    assert NORMALIZED not in str(audit) and "ryan.test" not in str(audit)


def test_status_endpoint(browser, hibp_on):
    s = browser.get("/api/email/status").json()
    assert s["hibp_enabled"] is True and s["hibp_key_configured"] is True and s["pwned_passwords_enabled"] is True
    assert "k-anonymity" in s["privacy_note"] and "10 requests per minute" in s["tier_note"]


# --------------------------------------------------------------------------- HIBP checks


def test_check_without_key_is_unavailable_and_sends_nothing(browser, fake, identity):
    result = check(browser, identity["id"])
    assert result["status"] == "unavailable"
    assert result["manual_check_url"] == "https://haveibeenpwned.com"
    assert len(result["how_to_enable"]) == 2 and result["payload_summary"] is None
    assert "Live check unavailable" in result["explanation"] and "haveibeenpwned.com" in result["explanation"]

    browser.put("/api/settings/integrations", json={"hibp": {"enabled": True}})
    result = check(browser, identity["id"])
    assert result["status"] == "unavailable" and len(result["how_to_enable"]) == 1
    assert "API key" in result["how_to_enable"][0]
    assert fake.requests == []
    history = browser.get(f"/api/email/identities/{identity['id']}/history").json()
    assert [h["status"] for h in history] == ["unavailable", "unavailable"]
    [listed] = browser.get("/api/email/identities").json()
    assert listed["latest_status"] == "unavailable" and listed["last_checked_at"] is None


def test_found_classifies_breaches_and_never_calls_a_spam_list_a_breach(browser, fake, hibp_on, identity):
    fake.reply(200, [
        breach("Adobe", classes=("Email addresses", "Password hints", "Passwords", "Usernames")),
        breach("SpamCorp", classes=("Email addresses",), verified=False, IsSpamList=True),
        breach("Unconfirmed", classes=("Email addresses", "Phone numbers"), verified=False),
        breach("Invented", IsFabricated=True),
        breach("StealerLogs", classes=("Email addresses", "Passwords", "Website URLs"), IsStealerLog=True,
               IsMalware=True),
    ])
    result = check(browser, identity["id"])
    assert result["status"] == "found"
    assert result["breach_count"] == 3  # confirmed + unverified + stealer log; not spam, not fabricated
    groups = {k: [b["name"] for b in v] for k, v in result["groups"].items()}
    assert groups == {"confirmed": ["Adobe"], "unverified": ["Unconfirmed"], "malware": ["StealerLogs"],
                      "spam_list": ["SpamCorp"], "fabricated": ["Invented"]}
    spam = result["groups"]["spam_list"][0]
    assert spam["counts_as_breach"] is False and spam["classification"] == "spam_list"
    assert result["counts"]["passwords_exposed"] == 2 and result["counts"]["spam_list"] == 1
    adobe = result["groups"]["confirmed"][0]
    assert adobe["description"] == "Sample & description" and adobe["passwords_exposed"] is True

    rec_ids = [r["id"] for r in result["recommendations"]]
    assert rec_ids[:3] == ["change_password", "enable_mfa", "password_manager"]
    assert {"password_hints", "phone_numbers", "malware_cleanup", "spam_list", "unverified_note",
            "fabricated_note", "hygiene_email_account"} <= set(rec_ids)
    change = next(r for r in result["recommendations"] if r["id"] == "change_password")
    assert change["priority"] == "high" and set(change["breaches"]) == {"Adobe", "StealerLogs"}
    assert "Invented" not in change["breaches"]
    assert result["payload_summary"] == "full email address (Core tiers have no k-anonymity search)"
    assert "Creative Commons" in result["attribution"]

    [req] = fake.requests
    assert req.url.host == "haveibeenpwned.com"
    assert req.url.raw_path == b"/api/v3/breachedaccount/ryan.test%2Balerts%40example.com?truncateResponse=false"
    assert req.headers["hibp-api-key"] == API_KEY and req.headers["user-agent"].startswith("Sentinel")

    with session_scope() as db:
        logged = db.execute(select(OutboundRequest).where(OutboundRequest.integration == "hibp")).scalar_one()
        assert "ryan.test" not in logged.path and "r***@example.com" in logged.path
        assert API_KEY not in logged.path
    assert NORMALIZED not in browser.get("/api/audit").text
    [listed] = browser.get("/api/email/identities").json()
    assert listed["latest_status"] == "found" and listed["breach_count"] == 3 and listed["last_checked_at"]


def test_not_found_explains_that_absence_is_not_proof(browser, fake, hibp_on, identity):
    fake.reply(404)
    result = check(browser, identity["id"])
    assert result["status"] == "not_found" and result["breach_count"] == 0
    assert "does not prove" in result["explanation"]
    assert all(r["id"].startswith("hygiene_") for r in result["recommendations"])
    [listed] = browser.get("/api/email/identities").json()
    assert listed["breach_count"] == 0 and listed["latest_status"] == "not_found"


def test_rejected_key_rate_limit_and_backoff(browser, fake, hibp_on, identity, clock):
    fake.reply(401)
    result = check(browser, identity["id"])
    assert result["status"] == "error" and result["error"] == "API key rejected"
    assert result["recommendations"] == [] and result["manual_check_url"]

    fake.reply(429, headers={"retry-after": "7"})
    result = check(browser, identity["id"])
    assert result["status"] == "error" and result["retry_after"] == 7 and "7 seconds" in result["error"]
    assert len(fake.requests) == 2

    # still inside retry-after: nothing is sent
    result = check(browser, identity["id"])
    assert result["status"] == "error" and result["retry_after"] and result["payload_summary"] is None
    assert len(fake.requests) == 2

    clock.t += 8
    fake.reply(503)
    result = check(browser, identity["id"])
    assert result["status"] == "error" and "503" in result["error"]
    history = browser.get(f"/api/email/identities/{identity['id']}/history").json()
    assert [h["status"] for h in history] == ["error"] * 4
    [listed] = browser.get("/api/email/identities").json()
    assert listed["breach_count"] is None  # never checked successfully: unknown, not zero


def test_calls_are_spaced_to_respect_ten_per_minute(browser, fake, hibp_on, identity, clock):
    for _ in range(3):
        fake.reply(404)
    check(browser, identity["id"])
    check(browser, identity["id"])
    assert clock.sleeps == [pytest.approx(6.5)]
    clock.t += 30
    check(browser, identity["id"])
    assert len(clock.sleeps) == 1


def test_new_breach_notifies_once(browser, fake, hibp_on, identity):
    browser.put("/api/settings/notifications", json={"min_severity": "medium"})
    adobe = breach("Adobe")
    canva = breach("Canva", classes=("Email addresses", "Names", "Physical addresses"))
    spam = breach("SpamCorp", classes=("Email addresses",), IsSpamList=True)

    def notifications() -> list[tuple[str, str, str | None]]:
        with session_scope() as db:
            rows = db.execute(select(Notification).order_by(Notification.id)).scalars()
            return [(n.severity, n.kind, n.dedupe_key) for n in rows]

    fake.reply(200, [adobe])
    assert check(browser, identity["id"])["new_breaches"] == ["Adobe"]
    assert notifications() == [("high", "email_breach", f"breach:{identity['id']}:Adobe")]

    fake.reply(200, [adobe])
    assert check(browser, identity["id"])["new_breaches"] == []
    fake.reply(401)  # a failed check is not a baseline
    check(browser, identity["id"])
    fake.reply(200, [adobe, canva, spam])
    assert check(browser, identity["id"])["new_breaches"] == ["Canva"]
    assert notifications() == [("high", "email_breach", f"breach:{identity['id']}:Adobe"),
                               ("medium", "email_breach", f"breach:{identity['id']}:Canva")]

    fake.reply(200, [adobe, canva, spam])
    check(browser, identity["id"])
    assert len(notifications()) == 2


def test_report_export_json_and_csv(browser, fake, hibp_on, identity):
    fake.reply(200, [breach("Adobe"), breach("Formula", title="=HYPERLINK(\"http://evil\")",
                                             classes=("Email addresses",))])
    check(browser, identity["id"])
    r = browser.get(f"/api/email/identities/{identity['id']}/report", params={"format": "csv"})
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/csv")
    assert "attachment" in r.headers["content-disposition"]
    rows = list(csv.DictReader(io.StringIO(r.text)))
    assert {row["name"] for row in rows} == {"Adobe", "Formula"}
    formula = next(row for row in rows if row["name"] == "Formula")
    assert formula["title"].startswith("'=")  # neutralised for spreadsheets
    adobe = next(row for row in rows if row["name"] == "Adobe")
    assert adobe["classification"] == "confirmed" and adobe["data_classes"] == "Email addresses; Passwords"

    report = browser.get(f"/api/email/identities/{identity['id']}/report").json()
    assert report["identity"]["email"] == NORMALIZED
    assert report["counts"]["breaches"] == 2 and len(report["breaches"]) == 2
    assert report["recommendations"] and "Creative Commons" in report["attribution"]
    assert [h["status"] for h in report["history"]] == ["found"]
    assert browser.get(f"/api/email/identities/{identity['id']}/report", params={"format": "xml"}).status_code == 422
    assert browser.get("/api/email/identities/999/report").status_code == 404


def test_domain_check_requires_verification(browser, fake, hibp_on):
    assert browser.post("/api/email/domains/not_a_domain/check").status_code == 422
    fake.reply(403)
    r = browser.post("/api/email/domains/Example.com/check").json()
    assert r["status"] == "not_verified" and r["domain"] == "example.com"
    assert len(r["verification_methods"]) == 4 and "verify" in r["explanation"]

    fake.reply(200, {"alias1": ["Adobe"], "alias2": ["Adobe", "Gawker", "Stratfor"]})
    r = browser.post("/api/email/domains/example.com/check").json()
    assert r["status"] == "found" and r["result"]["alias_count"] == 2
    assert r["result"]["breaches"] == {"Adobe": 2, "Gawker": 1, "Stratfor": 1}
    assert fake.requests[-1].url.path == "/api/v3/breacheddomain/example.com"
    history = browser.get("/api/email/domains").json()
    assert [h["status"] for h in history] == ["found", "not_verified"]


def test_domain_check_unavailable_without_key(browser, fake):
    r = browser.post("/api/email/domains/example.com/check").json()
    assert r["status"] == "unavailable" and fake.requests == []


# --------------------------------------------------------------------------- Pwned Passwords


def _range_body(rows: list[tuple[str, int]]) -> str:
    return "".join(f"{suffix}:{count}\r\n" for suffix, count in rows)


def test_pwned_range_removes_padding_and_sends_only_the_prefix(browser, fake):
    password_hash = hashlib.sha1(b"correct horse battery staple").hexdigest().upper()  # noqa: S324 - the API's format
    prefix, suffix = password_hash[:5], password_hash[5:]
    fake.reply(200, text=_range_body([(f"{1:035X}", 3), (suffix, 42), (f"{2:035X}", 0), (f"{3:035X}", 0)]))

    # what the browser does: send the prefix only, then compare suffixes locally
    r = browser.get(f"/api/email/pwned-range/{prefix.lower()}")
    assert r.status_code == 200
    rows = r.json()["suffixes"]
    assert rows == [{"suffix": f"{1:035X}", "count": 3}, {"suffix": suffix, "count": 42}]
    assert {row["suffix"]: row["count"] for row in rows}.get(suffix) == 42

    [req] = fake.requests
    assert str(req.url) == f"https://api.pwnedpasswords.com/range/{prefix}"
    assert req.content == b"" and req.headers["add-padding"] == "true"
    assert "hibp-api-key" not in req.headers
    outbound_text = str(req.url) + str(dict(req.headers))
    assert suffix not in outbound_text and password_hash not in outbound_text

    audit = browser.get("/api/audit", params={"action": "email.password_checked"}).json()["items"]
    assert len(audit) == 1 and prefix not in str(audit) and prefix.lower() not in str(audit)
    with session_scope() as db:
        logged = db.execute(select(OutboundRequest).where(OutboundRequest.integration == "pwned_passwords")).scalar_one()
        assert prefix not in logged.path and logged.payload_summary == "first 5 characters of a SHA-1 hash"


def test_pwned_range_prefix_validation(browser, fake):
    full_hash = hashlib.sha1(b"hunter2").hexdigest()  # noqa: S324
    for bad in ("ABCD", "ABCDEF", "GHIJK", "AB-CD", full_hash):
        assert browser.get(f"/api/email/pwned-range/{bad}").status_code == 422, bad
    assert fake.requests == []


def test_pwned_range_is_rate_limited(browser, fake):
    for _ in range(31):
        fake.reply(200, text=_range_body([(f"{1:035X}", 1)]))
    for i in range(30):
        assert browser.get("/api/email/pwned-range/ABCDE").status_code == 200, i
    r = browser.get("/api/email/pwned-range/ABCDE")
    assert r.status_code == 429 and r.headers["retry-after"] == "60"
    assert len(fake.requests) == 30


def test_pwned_range_disabled(browser, fake):
    browser.put("/api/settings/integrations", json={"pwned_passwords": {"enabled": False}})
    assert browser.get("/api/email/pwned-range/ABCDE").status_code == 503
    assert fake.requests == []
