"""Security regression tests for the server's own defenses."""

from sentinel_server.db import session_scope
from sentinel_server.models import AuditEntry
from sqlalchemy import update

from .conftest import PASSWORD


def test_setup_requires_the_printed_token_and_a_strong_password(app, anon):
    assert anon.get("/api/auth/state").json()["needs_setup"] is True
    bad = anon.post("/api/auth/setup", json={"setup_token": "wrong-token", "username": "ryan", "password": PASSWORD})
    assert bad.status_code == 403
    weak = anon.post("/api/auth/setup", json={"setup_token": app.state.setup_token, "username": "ryan",
                                              "password": "short"})
    assert weak.status_code == 422
    ok = anon.post("/api/auth/setup", json={"setup_token": app.state.setup_token, "username": "ryan",
                                            "password": PASSWORD})
    assert ok.status_code == 200
    again = anon.post("/api/auth/setup", json={"setup_token": "anything", "username": "eve", "password": PASSWORD})
    assert again.status_code == 409


def test_unexpected_host_header_is_rejected(anon):
    """DNS rebinding: a page that rebinds its name to 127.0.0.1 still sends its own Host header."""
    r = anon.get("/api/health", headers={"Host": "attacker.example"})
    assert r.status_code == 421
    assert anon.get("/api/health").status_code == 200


def test_security_headers_present(anon):
    r = anon.get("/api/health")
    assert "frame-ancestors 'none'" in r.headers["content-security-policy"]
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["cache-control"] == "no-store"


def test_state_changing_requests_need_csrf_token(browser):
    no_token = browser.client.post("/api/devices/enrollment-codes")
    assert no_token.status_code == 403
    wrong = browser.client.post("/api/devices/enrollment-codes", headers={"X-CSRF-Token": "nope"})
    assert wrong.status_code == 403
    assert browser.post("/api/devices/enrollment-codes").status_code == 200


def test_user_routes_reject_anonymous_and_device_tokens(make_agent, anon, browser):
    agent = make_agent([])
    browser.client.cookies.clear()
    assert anon.get("/api/findings").status_code == 401
    # a valid device token is not a user session
    token = agent.client._client.headers["Authorization"]
    assert anon.get("/api/findings", headers={"Authorization": token}).status_code == 401


def test_agent_routes_reject_user_sessions(browser):
    r = browser.get("/api/agent/jobs/next")
    assert r.status_code == 401


def test_login_rate_limit_and_lockout(browser, anon):
    browser.client.cookies.clear()
    codes = [anon.post("/api/auth/login", json={"username": "ryan", "password": "wrong"}).status_code
             for _ in range(6)]
    assert codes[:5] == [401] * 5
    assert codes[5] == 429


def test_unknown_user_and_wrong_password_look_the_same(browser, anon):
    browser.client.cookies.clear()
    a = anon.post("/api/auth/login", json={"username": "nobody", "password": "x"})
    b = anon.post("/api/auth/login", json={"username": "ryan", "password": "x"})
    assert a.status_code == b.status_code == 401
    assert a.json() == b.json()


def test_enrollment_codes_are_single_use(browser):
    from sentinel_agent.testing import windows_host
    from sentinel_core.models import EnrollRequest

    code = browser.post("/api/devices/enrollment-codes").json()["code"]
    body = EnrollRequest(code=code, host=windows_host()).model_dump(mode="json")
    assert browser.client.post("/api/agent/enroll", json=body).status_code == 200
    assert browser.client.post("/api/agent/enroll", json=body).status_code == 403


def test_revoked_device_token_stops_working(make_agent, browser):
    agent = make_agent([])
    assert browser.delete(f"/api/devices/{agent.device_id}").status_code == 204
    import pytest
    from sentinel_agent.transport import AuthError

    with pytest.raises(AuthError):
        agent.client.next_job()


def test_audit_chain_detects_tampering(browser):
    assert browser.get("/api/audit/verify").json()["intact"] is True
    with session_scope() as db:
        db.execute(update(AuditEntry).where(AuditEntry.id == 1).values(actor="user:mallory"))
    result = browser.get("/api/audit/verify").json()
    assert result["intact"] is False and result["first_bad_id"] == 1


def test_secrets_are_write_only(browser):
    r = browser.put("/api/secrets/hibp_api_key", json={"value": "super-secret-key"})
    assert r.status_code == 200 and r.json()["configured"] is True
    listing = browser.get("/api/secrets").text
    assert "super-secret-key" not in listing
    audit = browser.get("/api/audit").text
    assert "super-secret-key" not in audit
    assert browser.put("/api/secrets/arbitrary", json={"value": "x"}).status_code == 404


def test_spa_fallback_does_not_serve_files_outside_static(anon):
    r = anon.get("/../../etc/passwd")
    assert "root:" not in r.text


def test_assistant_url_must_stay_on_this_machine(browser):
    r = browser.put("/api/settings/integrations",
                    json={"ollama": {"enabled": True, "url": "http://evil.example:11434", "model": "llama3.1:8b"}})
    assert r.status_code == 422
    ok = browser.put("/api/settings/integrations",
                     json={"ollama": {"enabled": True, "url": "http://127.0.0.1:11434", "model": "llama3.1:8b"}})
    assert ok.status_code == 200 and ok.json()["ollama"]["enabled"] is True
