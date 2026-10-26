"""Phase 5: scope controls, scan previews, out-of-scope rejection, queueing and the network summary."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sentinel_server.db import session_scope
from sentinel_server.models import CheckRun, EvidenceRecord, FindingRecord, Scan, ScopeEntry
from sqlalchemy import select

NMAP = "nmap -sT -T3 --top-ports {n} -sV --version-light -oX - {target}"


def add(browser, kind: str, value: str, **kw: Any):
    return browser.post("/api/network/scope", json={"kind": kind, "value": value, **kw})


@pytest.fixture
def device_id(make_agent) -> int:
    return make_agent([]).device_id


# --------------------------------------------------------------------------- scope


def test_cidr_size_limits(browser):
    assert add(browser, "cidr", "10.0.0.0/8").status_code == 422
    assert add(browser, "cidr", "fd00::/48").status_code == 422
    assert add(browser, "cidr", "not-a-cidr").status_code == 422
    r = add(browser, "cidr", "192.168.1.77/24")
    assert r.status_code == 201
    entry = r.json()
    assert entry["value"] == "192.168.1.0/24" and entry["is_public"] is False and entry["authorization"] is None
    assert add(browser, "cidr", "10.20.0.0/16").status_code == 201
    assert add(browser, "cidr", "fd00:1:2:3::/64").status_code == 201
    assert add(browser, "cidr", "192.168.1.0/24").status_code == 409


def test_host_and_url_validation(browser):
    assert add(browser, "host", "bad host!").status_code == 422
    assert add(browser, "host", "-oX").status_code == 422
    assert add(browser, "host", "10.0.0.0/24").status_code == 422
    assert add(browser, "url", "ftp://nas.lan/").status_code == 422
    assert add(browser, "url", "https:///nohost").status_code == 422
    assert add(browser, "url", "https://user:pw@nas.lan/").status_code == 422
    for kind, value, normalized in [("host", "NAS.lan", "nas.lan"), ("host", "printer.home.arpa", "printer.home.arpa"),
                                    ("host", "127.0.0.1", "127.0.0.1"), ("host", "fe80::1", "fe80::1"),
                                    ("url", "HTTPS://Router.local:443/admin", "https://router.local/admin")]:
        r = add(browser, kind, value)
        assert r.status_code == 201, (value, r.text)
        assert r.json()["value"] == normalized and r.json()["is_public"] is False


def test_public_targets_need_the_exact_authorization_sentence(browser):
    for kind, value in [("host", "8.8.8.8"), ("host", "example.com"), ("cidr", "8.8.4.0/24"),
                        ("url", "https://example.org/")]:
        assert add(browser, kind, value).status_code == 422
        r = add(browser, kind, value, confirm_public=f"i am authorized to test {value}")
        assert r.status_code == 422 and f"I am authorized to test {value}" in r.json()["detail"]
        r = add(browser, kind, value, confirm_public=f"I am authorized to test {value}")
        assert r.status_code == 201, r.text
        assert r.json()["is_public"] is True and r.json()["authorization"] == f"I am authorized to test {value}"
    audit = browser.get("/api/audit", params={"action": "network.scope_added"}).json()["items"]
    assert any(a["detail"]["authorization"] == "I am authorized to test 8.8.8.8" for a in audit)


def test_scope_enable_disable_and_delete(browser):
    entry = add(browser, "host", "nas.lan", note="file server").json()
    r = browser.patch(f"/api/network/scope/{entry['id']}", json={"enabled": False})
    assert r.status_code == 200 and r.json()["enabled"] is False and r.json()["note"] == "file server"
    assert browser.patch("/api/network/scope/999", json={"enabled": True}).status_code == 404
    assert browser.delete(f"/api/network/scope/{entry['id']}").status_code == 204
    assert browser.get("/api/network/scope").json() == []
    actions = {a["action"] for a in browser.get("/api/audit", params={"action": "network."}).json()["items"]}
    assert actions == {"network.scope_added", "network.scope_updated", "network.scope_deleted"}


# --------------------------------------------------------------------------- preview


def test_discovery_preview_commands_are_exact(browser, device_id):
    add(browser, "cidr", "192.168.1.0/24")
    add(browser, "host", "nas.lan")
    r = browser.post("/api/network/preview", json={"device_id": device_id, "kind": "discovery",
                                                   "targets": ["192.168.1.0/24", "192.168.1.10", "NAS.lan"]})
    assert r.status_code == 200, r.text
    p = r.json()
    assert p["check_id"] == "net.nmap_discovery"
    assert p["params"] == {"targets": ["192.168.1.0/24", "192.168.1.10", "nas.lan"], "top_ports": 100}
    assert p["commands"] == [
        "nmap -sT -T3 --top-ports 100 -sV --version-light -oX - 192.168.1.0/24",
        "nmap -sT -T3 --top-ports 100 -sV --version-light -oX - 192.168.1.10",
        "nmap -sT -T3 --top-ports 100 -sV --version-light -oX - nas.lan",
    ]
    assert "TCP connect scan of the 100 most common ports" in p["behavior"]
    for phrase in ("sends no exploits", "no NSE scripts", "no OS fingerprinting", "not stealthy", "can log"):
        assert phrase in p["behavior"]
    assert any("own network position" in w for w in p["warnings"])
    assert not any("Public targets" in w for w in p["warnings"])
    assert p["estimated_seconds"] > 0

    r = browser.post("/api/network/preview", json={"device_id": device_id, "kind": "discovery",
                                                   "targets": ["192.168.1.5"], "top_ports": 1000})
    assert r.json()["commands"] == [NMAP.format(n=1000, target="192.168.1.5")]
    assert r.json()["params"]["top_ports"] == 1000
    for bad in (9, 1001):
        r = browser.post("/api/network/preview", json={"device_id": device_id, "kind": "discovery",
                                                       "targets": ["192.168.1.5"], "top_ports": bad})
        assert r.status_code == 422


def test_preview_warns_about_public_and_large_ranges(browser, device_id):
    add(browser, "cidr", "10.20.0.0/16")
    add(browser, "cidr", "8.8.4.0/24", confirm_public="I am authorized to test 8.8.4.0/24")
    p = browser.post("/api/network/preview", json={"device_id": device_id, "kind": "discovery",
                                                   "targets": ["10.20.0.0/22", "8.8.4.7"]}).json()
    warnings = " ".join(p["warnings"])
    assert "Public targets: 8.8.4.7" in warnings
    assert "10.20.0.0/22 (1024 addresses)" in warnings


def test_tls_and_header_previews(browser, device_id):
    add(browser, "host", "nas.lan")
    add(browser, "cidr", "192.168.1.0/24")
    add(browser, "url", "https://example.org/status", confirm_public="I am authorized to test https://example.org/status")
    r = browser.post("/api/network/preview", json={"device_id": device_id, "kind": "tls",
                                                   "targets": ["nas.lan:8443", "192.168.1.20", "nas.lan:8443"]})
    assert r.status_code == 200, r.text
    p = r.json()
    assert p["check_id"] == "net.tls_certificate" and p["commands"] == []
    assert p["params"] == {"endpoints": ["nas.lan:8443", "192.168.1.20:443"]}

    r = browser.post("/api/network/preview", json={"device_id": device_id, "kind": "headers",
                                                   "targets": ["http://192.168.1.20:8080/", "https://example.org/status"]})
    assert r.status_code == 200, r.text
    p = r.json()
    assert p["check_id"] == "net.http_headers"
    assert p["params"] == {"urls": ["http://192.168.1.20:8080/", "https://example.org/status"]}
    assert any("Public targets: https://example.org/status" in w for w in p["warnings"])
    # an exact URL entry does not put other paths on that public host in scope
    r = browser.post("/api/network/preview", json={"device_id": device_id, "kind": "headers",
                                                   "targets": ["https://example.org/admin"]})
    assert r.status_code == 422 and "https://example.org/admin" in r.json()["detail"]


def test_out_of_scope_targets_are_named(browser, device_id):
    add(browser, "cidr", "192.168.1.0/24")
    disabled = add(browser, "host", "nas.lan").json()
    browser.patch(f"/api/network/scope/{disabled['id']}", json={"enabled": False})
    cases = [
        ("discovery", ["192.168.1.4", "192.168.2.4"], "192.168.2.4"),
        ("discovery", ["192.168.0.0/23"], "192.168.0.0/23"),  # larger than the scope entry
        ("discovery", ["nas.lan"], "nas.lan"),  # disabled entry grants nothing
        ("discovery", ["printer.lan"], "printer.lan"),  # hostnames are never resolved to match a CIDR
        ("tls", ["10.0.0.1:443"], "10.0.0.1:443"),
        ("headers", ["https://nas.lan/"], "https://nas.lan/"),
    ]
    for kind, targets, named in cases:
        r = browser.post("/api/network/preview", json={"device_id": device_id, "kind": kind, "targets": targets})
        assert r.status_code == 422, (kind, targets)
        assert named in r.json()["detail"]
    r = browser.post("/api/network/preview", json={"device_id": device_id, "kind": "discovery",
                                                   "targets": ["-sS 192.168.1.4"]})
    assert r.status_code == 422
    r = browser.post("/api/network/preview", json={"device_id": 999, "kind": "discovery", "targets": ["192.168.1.4"]})
    assert r.status_code == 404


# --------------------------------------------------------------------------- scans


def test_scan_requires_acknowledgement_and_queues_the_right_check(browser, make_agent):
    agent = make_agent([])
    add(browser, "cidr", "192.168.1.0/24")
    body = {"device_id": agent.device_id, "kind": "discovery", "targets": ["192.168.1.0/24"], "top_ports": 50}
    assert browser.post("/api/network/scans", json=body).status_code == 422
    assert browser.post("/api/network/scans", json={**body, "acknowledged": False}).status_code == 422
    assert browser.post("/api/network/scans", json={**body, "acknowledged": "yes"}).status_code == 422
    out = browser.post("/api/network/scans", json={**body, "targets": ["10.1.1.1"], "acknowledged": True})
    assert out.status_code == 422 and "10.1.1.1" in out.json()["detail"]

    r = browser.post("/api/network/scans", json={**body, "acknowledged": True})
    assert r.status_code == 201, r.text
    scan = r.json()
    assert scan["status"] == "queued" and scan["scan_type"] == "network" and scan["reason"] == "network"
    assert scan["check_ids"] == ["net.nmap_discovery"]
    with session_scope() as db:
        row = db.get(Scan, scan["id"])
        assert row.params == {"net.nmap_discovery": {"targets": ["192.168.1.0/24"], "top_ports": 50}}

    job = agent.client.next_job()
    assert job is not None and job.scan_id == scan["id"]
    audit = browser.get("/api/audit", params={"action": "network.scan_requested"}).json()["items"]
    assert audit[0]["detail"]["targets"] == ["192.168.1.0/24"] and audit[0]["detail"]["acknowledged"] is True

    # scope is re-validated at queue time: disabling the entry blocks the same request
    [entry] = browser.get("/api/network/scope").json()
    browser.patch(f"/api/network/scope/{entry['id']}", json={"enabled": False})
    assert browser.post("/api/network/scans", json={**body, "acknowledged": True}).status_code == 422

    # the generic scan endpoint still refuses network scans
    r = browser.post("/api/scans", json={"device_id": agent.device_id, "scan_type": "network"})
    assert r.status_code == 422


def test_tls_scan_params(browser, device_id):
    add(browser, "host", "nas.lan")
    r = browser.post("/api/network/scans", json={"device_id": device_id, "kind": "tls", "targets": ["nas.lan"],
                                                 "acknowledged": True})
    assert r.status_code == 201
    with session_scope() as db:
        row = db.get(Scan, r.json()["id"])
        assert row.check_ids == ["net.tls_certificate"]
        assert row.params == {"net.tls_certificate": {"endpoints": ["nas.lan:443"]}}


# --------------------------------------------------------------------------- summary


def _seed(device_id: int) -> dict[str, Any]:
    t0 = datetime(2026, 10, 1, 12, 0, tzinfo=UTC)
    with session_scope() as db:
        old = Scan(device_id=device_id, scan_type="posture", status="completed", requested_at=t0, completed_at=t0)
        new = Scan(device_id=device_id, scan_type="posture", status="completed", requested_at=t0 + timedelta(days=1),
                   completed_at=t0 + timedelta(days=1))
        net = Scan(device_id=device_id, scan_type="network", status="completed", check_ids=["net.nmap_discovery"],
                   requested_at=t0 + timedelta(days=2))
        db.add_all([old, new, net])
        db.flush()

        def run(scan: Scan, check_id: str, status: str, finished: datetime, content: Any | None = None) -> None:
            r = CheckRun(scan_id=scan.id, check_id=check_id, check_version="1", title=check_id, category="network",
                         status=status, finished_at=finished)
            db.add(r)
            db.flush()
            if content is not None:
                db.add(EvidenceRecord(check_run_id=r.id, position=0, kind="command_output", source="fixture",
                                      content=content, content_sha256="0" * 64, size_bytes=10, collected_at=finished))

        run(old, "net.listening", "passed", t0, [{"port": 22}])
        run(new, "net.listening", "failed", t0 + timedelta(days=1), [{"port": 3389, "process": "svchost"}])
        run(old, "net.interfaces", "passed", t0, {"adapters": ["eth0"]})
        run(new, "net.interfaces", "skipped", t0 + timedelta(days=1))  # a skip never replaces real evidence
        run(new, "win.network_profile", "error", t0 + timedelta(days=1))
        db.add(FindingRecord(device_id=device_id, fingerprint="f" * 64, rule_id="net.rdp_exposed", check_id="net.listening",
                             subject_key="tcp/3389", title="RDP listening on all interfaces", category="network",
                             severity="high", confidence="high", finding_kind="verified", status="new",
                             impact="i", remediation="r"))
        db.add(FindingRecord(device_id=device_id, fingerprint="e" * 64, rule_id="net.old", check_id="net.listening",
                             subject_key="tcp/23", title="Telnet", category="network", severity="high",
                             confidence="high", finding_kind="verified", status="resolved", impact="i", remediation="r"))
        db.add(FindingRecord(device_id=device_id, fingerprint="d" * 64, rule_id="win.uac", check_id="win.uac",
                             subject_key="uac", title="UAC off", category="system", severity="high",
                             confidence="high", finding_kind="verified", status="new", impact="i", remediation="r"))
        return {"network_scan": net.id}


def test_summary_passes_through_latest_completed_evidence(browser, device_id):
    seeded = _seed(device_id)
    s = browser.get("/api/network/summary", params={"device_id": device_id}).json()
    assert set(s["facts"]) == {"net.listening", "net.interfaces", "net.dns_config", "win.network_profile",
                                 "win.wifi_security"}
    listening = s["facts"]["net.listening"]
    assert listening["status"] == "failed"
    assert listening["evidence"][0]["content"] == [{"port": 3389, "process": "svchost"}]
    assert s["facts"]["net.interfaces"]["evidence"][0]["content"] == {"adapters": ["eth0"]}
    assert s["facts"]["net.dns_config"] is None and s["facts"]["win.network_profile"] is None
    assert [f["rule_id"] for f in s["findings"]] == ["net.rdp_exposed"]
    assert [x["id"] for x in s["scans"]] == [seeded["network_scan"]]
    assert browser.get("/api/network/summary", params={"device_id": 999}).status_code == 404


def test_scope_entries_persist_authorization(browser):
    add(browser, "host", "example.com", confirm_public="I am authorized to test example.com")
    with session_scope() as db:
        entry = db.execute(select(ScopeEntry)).scalar_one()
        assert entry.authorization == "I am authorized to test example.com" and entry.created_by is not None


def test_target_count_respects_the_agents_limit(browser, make_agent):
    agent = make_agent([])
    assert browser.post("/api/network/scope", json={"kind": "cidr", "value": "192.168.50.0/24"}).status_code in (200, 201)
    targets = [f"192.168.50.{i}" for i in range(1, 18)]  # 17 > 16
    r = browser.post("/api/network/preview", json={"device_id": agent.device_id, "kind": "discovery", "targets": targets})
    assert r.status_code == 422 and "At most 16" in r.json()["detail"]
