"""Threat-intelligence advisory feed: Hacker News fetch, inventory matching, human-reviewed advisories."""

from __future__ import annotations

import httpx
import pytest
from sentinel_server.db import session_scope
from sentinel_server.integrations import http
from sentinel_server.models import Advisory, IntelSync, Notification, SoftwareRecord, now
from sentinel_server.phases import intel_feed
from sentinel_server.services import app_settings

from .conftest import Browser


@pytest.fixture(autouse=True)
def _reset_transport():
    yield
    http.set_transport(None)


@pytest.fixture
def feed_on(monkeypatch):
    monkeypatch.setitem(app_settings.DEFAULTS["integrations"], "hackernews",
                        {"enabled": True, "min_points": 20, "refresh_hours": 6})


def _hn(hits: list[dict]) -> httpx.MockTransport:
    def handler(req: httpx.Request) -> httpx.Response:
        assert "hn.algolia.com" in str(req.url)  # nothing else is contacted
        return httpx.Response(200, json={"hits": hits})

    return httpx.MockTransport(handler)


def _hit(object_id: str, title: str, points: int = 100, url: str = "https://example.com/x") -> dict:
    return {"objectID": object_id, "title": title, "points": points, "author": "someone",
            "created_at_i": int(now().timestamp()), "url": url}


def _seed_software(name: str) -> None:
    from sentinel_server.models import Device
    from sqlalchemy import select

    with session_scope() as db:
        dev = db.execute(select(Device)).scalars().first()
        if dev is None:
            dev = Device(name="pc", hostname="pc", os_family="windows", os_name="Windows 11", os_version="24H2",
                         arch="AMD64", agent_version="0.1.0", token_hash="x")
            db.add(dev)
            db.flush()
        db.add(SoftwareRecord(device_id=dev.id, name=name, version="1.0", ecosystem="windows-registry",
                              source="test", is_present=True))


def test_matched_advisory_is_created_and_notifies(browser: Browser, feed_on):
    _seed_software("OpenVPN Connect")
    http.set_transport(_hn([
        _hit("1", "Critical OpenVPN vulnerability lets attackers run code"),
        _hit("2", "A nice article about gardening in autumn"),
    ]))
    with session_scope() as db:
        intel_feed.tick(db)
    advisories = browser.get("/api/advisories").json()["items"]
    titles = {a["title"]: a for a in advisories}
    assert "Critical OpenVPN vulnerability lets attackers run code" in titles
    matched = titles["Critical OpenVPN vulnerability lets attackers run code"]
    assert matched["matched"] is True and matched["severity_hint"] == "medium"
    assert "OpenVPN Connect" in matched["match_detail"]["software"]
    assert matched["suggested_coverage"] and "will not change any check" in matched["suggested_coverage"]
    # the unrelated story is stored but not matched
    assert titles["A nice article about gardening in autumn"]["matched"] is False
    # a medium-severity match is below the default "high" notify threshold, so no notification yet
    with session_scope() as db:
        assert db.query(Notification).filter(Notification.kind == "advisory").count() == 0


def test_kev_cve_raises_severity(browser: Browser, feed_on):
    with session_scope() as db:
        db.add(IntelSync(source="kev", data={"cves": {"CVE-2026-9999": ["2026-10-01", "Known"]}}))
    http.set_transport(_hn([_hit("3", "Exploitation of CVE-2026-9999 seen in the wild")]))
    with session_scope() as db:
        intel_feed.tick(db)
    [adv] = browser.get("/api/advisories", params={"matched": "true"}).json()["items"]
    assert adv["severity_hint"] == "high" and "CVE-2026-9999" in adv["cve_ids"]
    assert "Known Exploited" in adv["suggested_coverage"]
    with session_scope() as db:  # a high-severity match does reach the notification threshold
        assert db.query(Notification).filter(Notification.kind == "advisory").count() == 1


def test_feed_off_does_nothing_and_refresh_is_409(browser: Browser):
    http.set_transport(_hn([_hit("9", "Some RCE vulnerability")]))
    with session_scope() as db:
        intel_feed.tick(db)  # integration disabled by default
    assert browser.get("/api/advisories").json()["total"] == 0
    assert browser.post("/api/intel/feed/refresh").status_code == 409


def test_outbound_off_records_disabled(browser: Browser, feed_on, settings, monkeypatch):
    monkeypatch.setattr(settings, "outbound_enabled", False)
    with session_scope() as db:
        intel_feed.tick(db)
    status = browser.get("/api/advisories/summary").json()
    assert status["enabled"] is True and status["outbound_enabled"] is False
    with session_scope() as db:
        row = db.get(IntelSync, "hackernews")
        assert row is not None and row.status == "disabled"


def test_read_and_dismiss_workflow(browser: Browser, feed_on):
    http.set_transport(_hn([_hit("5", "OpenSSL security release")]))
    with session_scope() as db:
        intel_feed.tick(db)
    adv = browser.get("/api/advisories").json()["items"][0]
    assert browser.get(f"/api/advisories/{adv['id']}").json()["status"] == "read"  # reading marks it read
    assert browser.patch(f"/api/advisories/{adv['id']}", json={"status": "pinned"}).json()["status"] == "pinned"
    browser.patch(f"/api/advisories/{adv['id']}", json={"status": "dismissed"})
    assert browser.get("/api/advisories").json()["total"] == 0  # dismissed hidden by default
    assert browser.get("/api/advisories", params={"status": "all"}).json()["total"] == 1


def test_refetch_updates_not_duplicates(browser: Browser, feed_on):
    http.set_transport(_hn([_hit("7", "Log4j style vulnerability", points=50)]))
    with session_scope() as db:
        intel_feed.tick(db)
        db.get(IntelSync, "hackernews").last_synced_at = None  # force due again
    http.set_transport(_hn([_hit("7", "Log4j style vulnerability (updated)", points=250)]))
    with session_scope() as db:
        intel_feed.tick(db)
    items = browser.get("/api/advisories").json()
    assert items["total"] == 1 and items["items"][0]["title"].endswith("(updated)")
    with session_scope() as db:
        assert db.query(Advisory).count() == 1
