"""End to end: the real agent runner uploads inventory, the matcher's tick asks (mocked) intel sources,
and vulnerability findings dedupe, resolve and survive network failures like agent findings do.

All upstream responses are hand-written to match the documented formats (OSV.dev, NVD CVE API 2.0,
MSRC CVRF v3.0, CISA KEV, FIRST EPSS). They are not recordings, and no test touches the network.
"""

from __future__ import annotations

import json
from datetime import timedelta
from typing import Any

import httpx
import pytest
from sentinel_agent.testing import linux_host, windows_host
from sentinel_core.checks import Check, CheckContext
from sentinel_core.models import CheckOutput, Platform, SoftwareItem
from sentinel_server.db import session_scope
from sentinel_server.integrations import http, nvd
from sentinel_server.models import AuditEntry, FindingRecord, IntelSync, OutboundRequest, SoftwareRecord, VulnRecord
from sentinel_server.models import now as real_now
from sentinel_server.phases import vulns
from sentinel_server.services import app_settings, secrets
from sentinel_server.services import vuln_matcher as vm

from .test_integrations_vuln import cvrf_document


@pytest.fixture(autouse=True)
def _vulnerability_sources_enabled(monkeypatch):
    """Server integrations are off by default (local-first); these tests exercise them switched on."""
    from sentinel_server.services import app_settings as _settings

    for name in ("osv", "nvd", "kev", "epss", "msrc"):
        monkeypatch.setitem(_settings.DEFAULTS["integrations"], name, {"enabled": True})

INVENTORY_FILE = "/sentinel-test/inventory.json"


def inventory_check(check_id: str) -> type[Check]:
    class TestInventory(Check):
        id = check_id
        version = "1"
        title = f"Test inventory ({check_id})"
        category = "inventory"
        platforms = frozenset({Platform.WINDOWS, Platform.LINUX})
        profiles = frozenset({"inventory"})
        data_collected = "Installed software names and versions (test fixture)"

        def run(self, ctx: CheckContext) -> CheckOutput:
            items = json.loads(ctx.read_text(INVENTORY_FILE))
            return CheckOutput(software=[SoftwareItem(source="test fixture", **i) for i in items])

    TestInventory.__name__ = f"TestInventory_{check_id.replace('.', '_')}"
    return TestInventory


def inventory(*items: dict[str, Any]) -> dict[str, Any]:
    return {"files": {INVENTORY_FILE: json.dumps(list(items))}}


def pkg(name: str, version: str | None, ecosystem: str, location: str | None = None) -> dict[str, Any]:
    return {"name": name, "version": version, "ecosystem": ecosystem, "location": location}


# =========================================================================== fake upstream services


V75 = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
V98 = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"


def debian_record(vid: str, cve: str, fixed: str, modified: str = "2026-10-01T00:00:00Z") -> dict[str, Any]:
    return {"id": vid, "upstream": [cve], "modified": modified, "published": "2026-09-01T00:00:00Z",
            "details": "A malicious certificate can crash programs that use OpenSSL to check it.",
            "severity": [{"type": "CVSS_V3", "score": V75}],
            "references": [{"type": "ADVISORY", "url": f"https://security-tracker.debian.org/tracker/{cve}"}],
            "affected": [{"package": {"name": "openssl", "ecosystem": "Debian:12", "purl": "pkg:deb/debian/openssl"},
                          "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": fixed}]}],
                          "ecosystem_specific": {"urgency": "medium"}}]}


GHSA = {"id": "GHSA-h5c8-rqwp-cp95", "aliases": ["CVE-2024-56201", "PYSEC-2024-999"], "modified": "2026-01-01T00:00:00Z",
        "summary": "Jinja has a sandbox breakout through malicious filenames",
        "database_specific": {"severity": "MODERATE"},
        "severity": [{"type": "CVSS_V4", "score": "CVSS:4.0/AV:N/AC:L/AT:P/PR:L/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"}],
        "affected": [{"package": {"name": "jinja2", "ecosystem": "PyPI"},
                      "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "3.0.0"}, {"fixed": "3.1.5"}]}]}]}
PYSEC = {"id": "PYSEC-2024-999", "aliases": ["CVE-2024-56201", "GHSA-h5c8-rqwp-cp95"], "modified": "2026-01-01T00:00:00Z",
         "affected": [{"package": {"name": "jinja2", "ecosystem": "PyPI"},
                       "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "3.1.5"}]}]}]}


def nvd_cve(cve: str, configurations: list[dict[str, Any]], status: str = "Analyzed",
            metrics: dict[str, Any] | None = None) -> dict[str, Any]:
    return {"cve": {"id": cve, "sourceIdentifier": "chrome-cve-admin@google.com", "vulnStatus": status,
                    "published": "2026-09-10T00:00:00.000", "lastModified": "2026-09-12T00:00:00.000",
                    "descriptions": [{"lang": "en", "value": f"Use after free in Chrome ({cve}) allows a remote attacker "
                                                            "to run code via a crafted page."}],
                    "metrics": metrics or {}, "configurations": configurations,
                    "references": [{"url": "https://chromereleases.googleblog.com/", "source": "x", "tags": []}]}}


def chrome_range(end: str) -> list[dict[str, Any]]:
    return [{"nodes": [{"operator": "OR", "negate": False, "cpeMatch": [
        {"vulnerable": True, "criteria": "cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*", "versionEndExcluding": end,
         "matchCriteriaId": "00000000-0000-0000-0000-000000000001"}]}]}]


class FakeIntel:
    """Mock transport answering OSV, NVD, MSRC, KEV and EPSS like the real services would."""

    def __init__(self) -> None:
        self.osv_vulns: dict[tuple[str, str, str], list[str]] = {}
        self.osv_records: dict[str, dict[str, Any]] = {}
        self.nvd_products: dict[str, list[dict[str, Any]]] = {}
        self.msrc_docs: dict[str, dict[str, Any]] = {}
        self.kev: list[dict[str, Any]] = []
        self.epss: dict[str, float] = {}
        self.fail: set[str] = set()  # hosts that answer 503
        self.calls: list[httpx.Request] = []

    def count(self, host: str, path_prefix: str = "") -> int:
        return sum(1 for r in self.calls if r.url.host == host and r.url.path.startswith(path_prefix))

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.calls.append(request)
        host = request.url.host
        if host in self.fail:
            return httpx.Response(503, json={"error": "service unavailable"})
        if host == "api.osv.dev":
            if request.url.path == "/v1/querybatch":
                results = []
                for q in json.loads(request.content)["queries"]:
                    key = (q["package"]["ecosystem"], q["package"]["name"], q["version"])
                    ids = self.osv_vulns.get(key, [])
                    results.append({"vulns": [{"id": i, "modified": self.osv_records[i]["modified"]} for i in ids]}
                                   if ids else {})
                return httpx.Response(200, json={"results": results})
            vid = request.url.path.rsplit("/", 1)[1]
            rec = self.osv_records.get(vid)
            return httpx.Response(200, json=rec) if rec else httpx.Response(404, json={"code": 5})
        if host == "services.nvd.nist.gov":
            match = request.url.params["virtualMatchString"].removeprefix("cpe:2.3:a:")
            items = self.nvd_products.get(match, [])
            return httpx.Response(200, json={"resultsPerPage": len(items), "startIndex": 0, "totalResults": len(items),
                                             "format": "NVD_CVE", "version": "2.0", "vulnerabilities": items})
        if host == "api.msrc.microsoft.com":
            if request.url.path == "/cvrf/v3.0/updates":
                months = sorted(self.msrc_docs, reverse=True)
                return httpx.Response(200, json={"value": [
                    {"ID": m, "Alias": m, "DocumentTitle": f"{m} Security Updates", "Severity": None,
                     "InitialReleaseDate": f"2026-{['Aug', 'Sep', 'Oct'].index(m[5:]) + 8:02d}-10T07:00:00Z",
                     "CurrentReleaseDate": "2026-10-20T07:00:00Z",
                     "CvrfUrl": f"https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/{m}"} for m in months]})
            return httpx.Response(200, json=self.msrc_docs[request.url.path.rsplit("/", 1)[1]])
        if host == "www.cisa.gov":
            return httpx.Response(200, json={"title": "CISA Catalog of Known Exploited Vulnerabilities",
                                             "catalogVersion": "2026.10.24", "dateReleased": "2026-10-24T17:00:00.000Z",
                                             "count": len(self.kev), "vulnerabilities": self.kev})
        if host == "api.first.org":
            cves = request.url.params["cve"].split(",")
            data = [{"cve": c, "epss": f"{self.epss[c]:.9f}", "percentile": "0.950000000", "date": "2026-10-25"}
                    for c in cves if c in self.epss]
            return httpx.Response(200, json={"status": "OK", "status-code": 200, "version": "1.0", "total": len(data),
                                             "offset": 0, "limit": 100, "data": data})
        return httpx.Response(404)


@pytest.fixture
def intel(monkeypatch, settings):
    fake = FakeIntel()
    http.set_transport(httpx.MockTransport(fake))
    monkeypatch.setattr(secrets, "backend_name", lambda: "file")  # never touch a real credential store
    nvd.limiter(False).reset()
    nvd.limiter(True).reset()
    yield fake
    http.set_transport(None)
    nvd.limiter(False).reset()
    nvd.limiter(True).reset()


def tick(shift: timedelta | None = None, monkeypatch: pytest.MonkeyPatch | None = None) -> None:
    if shift is not None:
        assert monkeypatch is not None
        monkeypatch.setattr(vm, "now", lambda: real_now() + shift)
    with session_scope() as db:
        vulns.tick(db)


def vuln_findings(browser, device_id: int, status: str = "all") -> list[dict[str, Any]]:
    r = browser.get("/api/findings", params={"device_id": device_id, "status": status, "source": "vuln_matcher"})
    assert r.status_code == 200, r.text
    return r.json()["items"]


def software(browser, device_id: int, **params: Any) -> dict[str, dict[str, Any]]:
    r = browser.get("/api/software", params={"device_id": device_id, **params})
    assert r.status_code == 200, r.text
    return {f"{i['name']} {i['version']}": i for i in r.json()["items"]}


def setup_osv(fake: FakeIntel) -> None:
    fake.osv_records["DEBIAN-CVE-2026-1111"] = debian_record("DEBIAN-CVE-2026-1111", "CVE-2026-1111", "3.0.15-1~deb12u1")
    # a bundle advisory for the same CVE must not create a second finding
    fake.osv_records["DSA-6001-1"] = {"id": "DSA-6001-1", "upstream": ["CVE-2026-1111"],
                                      "modified": "2026-10-01T00:00:00Z", "affected": []}
    fake.osv_vulns[("Debian:12", "openssl", "3.0.11-1~deb12u2")] = ["DEBIAN-CVE-2026-1111", "DSA-6001-1"]
    fake.osv_records[GHSA["id"]] = GHSA
    fake.osv_records[PYSEC["id"]] = PYSEC
    fake.osv_vulns[("PyPI", "jinja2", "3.1.4")] = [GHSA["id"], PYSEC["id"]]


DEB = linux_host()


# =========================================================================== OSV end to end


def test_osv_match_upgrade_resolves(make_agent, browser, intel):
    setup_osv(intel)
    Inv = inventory_check("test.inventory")
    agent = make_agent([Inv], DEB)
    scan = agent.scan(inventory(pkg("openssl", "3.0.11-1~deb12u2", "Debian:12"), pkg("bash", "5.2.15-2+b7", "Debian:12"),
                                pkg("jinja2", "3.1.4", "PyPI", "/home/pi/app"),
                                pkg("jinja2", "3.1.4", "PyPI", "/home/pi/other")), scan_type="inventory")
    assert scan["status"] == "completed"
    # the upload hook is database-only: nothing has gone out yet, every item waits for the tick
    assert intel.calls == []
    assert {i["match_status"] for i in software(browser, agent.device_id).values()} == {"pending"}

    tick()
    found = {f["rule_id"] + ":" + f["subject_key"]: f for f in vuln_findings(browser, agent.device_id)}
    assert set(found) == {"vuln.osv:Debian:12|openssl|DEBIAN-CVE-2026-1111", "vuln.osv:PyPI|jinja2|GHSA-h5c8-rqwp-cp95"}
    ssl = found["vuln.osv:Debian:12|openssl|DEBIAN-CVE-2026-1111"]
    assert ssl["cve_id"] == "CVE-2026-1111" and ssl["vuln_id"] == "DEBIAN-CVE-2026-1111"
    assert ssl["cvss_score"] == 7.5 and ssl["cvss_vector"] == V75 and ssl["severity"] == "high"
    assert ssl["cvss_source"] == "OSV: CVSS 3.1 (DEBIAN-CVE-2026-1111)"
    assert ssl["finding_kind"] == "verified" and ssl["confidence"] == "high" and ssl["category"] == "vulnerability"
    assert ssl["affected_software"] == "openssl 3.0.11-1~deb12u2" and ssl["fixed_version"] == "3.0.15-1~deb12u1"
    assert ssl["remediation"].startswith("Update openssl to 3.0.15-1~deb12u1 or later.")
    assert ssl["check_id"] == "test.inventory" and ssl["status"] == "new"
    jinja = found["vuln.osv:PyPI|jinja2|GHSA-h5c8-rqwp-cp95"]
    # GHSA and PYSEC describe the same CVE: one finding; the CVSS 4.0 vector is kept but not scored
    assert jinja["severity"] == "medium" and jinja["cvss_score"] is None and jinja["cvss_vector"].startswith("CVSS:4.0")
    assert jinja["cve_id"] == "CVE-2024-56201" and jinja["fixed_version"] == "3.1.5"
    assert "/home/pi/app" in jinja["impact"] and "/home/pi/other" in jinja["impact"]  # two projects, one finding

    items = software(browser, agent.device_id)
    assert items["openssl 3.0.11-1~deb12u2"]["match_status"] == "matched"
    assert items["openssl 3.0.11-1~deb12u2"]["match_source"] == "osv"
    assert items["openssl 3.0.11-1~deb12u2"]["open_vulnerabilities"] == 1
    assert items["bash 5.2.15-2+b7"]["match_status"] == "matched"

    # honest outbound log: names and versions leave the machine, and the log says so
    with session_scope() as db:
        batch = db.query(OutboundRequest).filter_by(integration="osv", method="POST").one()
        assert batch.payload_summary == "package names and versions (3 packages; Debian:12, PyPI)"
        assert db.query(VulnRecord).filter_by(vuln_id="DEBIAN-CVE-2026-1111").one().cve_id == "CVE-2026-1111"

    # a second identical scan: same findings, no duplicates; details come from the cache
    detail_calls = intel.count("api.osv.dev", "/v1/vulns/")
    agent.scan(inventory(pkg("openssl", "3.0.11-1~deb12u2", "Debian:12"), pkg("bash", "5.2.15-2+b7", "Debian:12"),
                         pkg("jinja2", "3.1.4", "PyPI", "/home/pi/app")), scan_type="inventory")
    tick()
    assert len(vuln_findings(browser, agent.device_id, "open")) == 2
    assert intel.count("api.osv.dev", "/v1/vulns/") == detail_calls

    # upgraded package: the re-read inventory proves it, so the finding is verified resolved
    agent.scan(inventory(pkg("openssl", "3.0.15-1~deb12u1", "Debian:12"), pkg("bash", "5.2.15-2+b7", "Debian:12"),
                         pkg("jinja2", "3.1.4", "PyPI", "/home/pi/app")), scan_type="inventory")
    tick()
    after = {f["subject_key"]: f for f in vuln_findings(browser, agent.device_id)}
    resolved = after["Debian:12|openssl|DEBIAN-CVE-2026-1111"]
    assert resolved["status"] == "resolved" and resolved["verified_resolved_at"]
    assert after["PyPI|jinja2|GHSA-h5c8-rqwp-cp95"]["status"] == "new"
    items = software(browser, agent.device_id, present_only=False)
    assert items["openssl 3.0.11-1~deb12u2"]["is_present"] is False
    assert "openssl 3.0.11-1~deb12u2" not in software(browser, agent.device_id)


def test_network_failure_never_resolves(make_agent, browser, intel, monkeypatch):
    setup_osv(intel)
    agent = make_agent([inventory_check("test.inventory")], DEB)
    agent.scan(inventory(pkg("openssl", "3.0.11-1~deb12u2", "Debian:12")), scan_type="inventory")
    tick()
    [f] = vuln_findings(browser, agent.device_id)
    assert f["status"] == "new"

    # the package is upgraded, but OSV is down: nothing may be resolved on incomplete data
    intel.fail.add("api.osv.dev")
    agent.scan(inventory(pkg("openssl", "3.0.15-1~deb12u1", "Debian:12")), scan_type="inventory")
    tick()
    [f] = vuln_findings(browser, agent.device_id)
    assert f["status"] == "new" and f["verified_resolved_at"] is None
    items = software(browser, agent.device_id)
    assert items["openssl 3.0.15-1~deb12u1"]["match_status"] == "error"
    status = browser.get("/api/intel/status").json()
    assert status["queue"]["retrying"] == 1 and "503" in status["queue"]["last_error"]
    assert next(s for s in status["sources"] if s["source"] == "osv")["status"] == "error"

    # an immediate tick does not hammer the service (backoff)
    calls = len(intel.calls)
    tick()
    assert intel.count("api.osv.dev") == sum(1 for r in intel.calls[:calls] if r.url.host == "api.osv.dev")

    # the service recovers; after the backoff the retry completes and resolves with full data
    intel.fail.clear()
    tick(timedelta(minutes=5), monkeypatch)
    [f] = vuln_findings(browser, agent.device_id)
    assert f["status"] == "resolved" and f["verified_resolved_at"]
    assert software(browser, agent.device_id)["openssl 3.0.15-1~deb12u1"]["match_status"] == "matched"
    assert browser.get("/api/intel/status").json()["queue"] == {"waiting": 0, "retrying": 0, "last_error": None}


def test_disabled_source_does_not_resolve(make_agent, browser, intel):
    setup_osv(intel)
    agent = make_agent([inventory_check("test.inventory")], DEB)
    agent.scan(inventory(pkg("openssl", "3.0.11-1~deb12u2", "Debian:12")), scan_type="inventory")
    tick()
    with session_scope() as db:
        integrations = app_settings.get_setting(db, "integrations")
        integrations["osv"]["enabled"] = False
        app_settings.set_setting(db, "integrations", integrations)
    agent.scan(inventory(pkg("openssl", "3.0.15-1~deb12u1", "Debian:12")), scan_type="inventory")
    calls = len(intel.calls)
    tick()
    assert intel.count("api.osv.dev") == sum(1 for r in intel.calls[:calls] if r.url.host == "api.osv.dev")
    [f] = vuln_findings(browser, agent.device_id)
    assert f["status"] == "new"  # not compared, so not resolved
    item = software(browser, agent.device_id)["openssl 3.0.15-1~deb12u1"]
    assert item["match_status"] == "no_source" and "turned off" in item["match_reason"]
    summary = browser.get("/api/vulnerabilities/summary", params={"device_id": agent.device_id}).json()
    assert summary["not_compared_reasons"] == [
        "Not compared: OSV.dev (Debian, Ubuntu, PyPI, npm packages) turned off. Turn it on in Integrations to compare "
        "this software."]

    # turned back on: the skipped inventory is matched without waiting for another scan
    with session_scope() as db:
        integrations["osv"]["enabled"] = True
        app_settings.set_setting(db, "integrations", integrations)
    tick()
    [f] = vuln_findings(browser, agent.device_id)
    assert f["status"] == "resolved"


def test_inventory_check_reporting_nothing_resolves(make_agent, browser, intel):
    setup_osv(intel)
    agent = make_agent([inventory_check("test.inventory")], DEB)
    agent.scan(inventory(pkg("jinja2", "3.1.4", "PyPI", "/home/pi/app")), scan_type="inventory")
    tick()
    assert vuln_findings(browser, agent.device_id)[0]["status"] == "new"
    agent.scan(inventory(), scan_type="inventory")  # the project was deleted: the check reports no packages
    tick()
    assert vuln_findings(browser, agent.device_id)[0]["status"] == "resolved"


# =========================================================================== KEV and EPSS


def test_kev_and_epss_update_findings(make_agent, browser, intel, monkeypatch):
    setup_osv(intel)
    intel.kev = [{"cveID": "CVE-2026-1111", "vendorProject": "OpenSSL", "product": "OpenSSL",
                  "vulnerabilityName": "OpenSSL Denial of Service", "dateAdded": "2026-10-20",
                  "shortDescription": "x", "requiredAction": "Apply updates per vendor instructions.",
                  "dueDate": "2026-11-10", "knownRansomwareCampaignUse": "Known", "notes": "", "cwes": ["CWE-787"]}]
    intel.epss = {"CVE-2026-1111": 0.42, "CVE-2024-56201": 0.0123}
    agent = make_agent([inventory_check("test.inventory")], DEB)
    agent.scan(inventory(pkg("openssl", "3.0.11-1~deb12u2", "Debian:12"), pkg("jinja2", "3.1.4", "PyPI")),
               scan_type="inventory")
    tick()
    found = {f["cve_id"]: f for f in vuln_findings(browser, agent.device_id)}
    assert found["CVE-2026-1111"]["kev"] is True and found["CVE-2026-1111"]["epss"] == pytest.approx(0.42)
    assert found["CVE-2024-56201"]["kev"] is False and found["CVE-2024-56201"]["epss"] == pytest.approx(0.0123)
    assert browser.get("/api/findings", params={"kev": True, "source": "vuln_matcher"}).json()["total"] == 1

    detail = browser.get("/api/vulns/DEBIAN-CVE-2026-1111").json()
    assert detail["kev"] is True and detail["kev_date_added"] == "2026-10-20" and detail["kev_ransomware"] == "Known"
    assert detail["epss"] == pytest.approx(0.42) and detail["epss_percentile"] == pytest.approx(0.95)
    assert detail["cvss_severity"] == "high" and detail["cvss_version"] == "3.1"
    assert [m["metric"] for m in detail["cvss_explained"]] == ["AV", "AC", "PR", "UI", "S", "C", "I", "A"]
    assert detail["cvss_summary"].startswith("Remotely exploitable over a network")
    assert "https://osv.dev/vulnerability/DEBIAN-CVE-2026-1111" in detail["references"]
    assert browser.get("/api/vulns/CVE-2026-1111").json()["vuln_id"] == "DEBIAN-CVE-2026-1111"  # by CVE alias
    assert browser.get("/api/vulns/CVE-1999-0001").status_code == 404

    # KEV is synced daily, not on every tick
    assert intel.count("www.cisa.gov") == 1
    tick()
    assert intel.count("www.cisa.gov") == 1
    # the CVE leaves the catalog: the next daily sync clears the flag everywhere
    intel.kev = []
    tick(timedelta(hours=25), monkeypatch)
    assert intel.count("www.cisa.gov") == 2
    found = {f["cve_id"]: f for f in vuln_findings(browser, agent.device_id)}
    assert found["CVE-2026-1111"]["kev"] is False
    assert browser.get("/api/vulns/DEBIAN-CVE-2026-1111").json()["kev"] is False


def test_manual_sync_request_is_audited_and_honored(make_agent, browser, intel):
    setup_osv(intel)
    agent = make_agent([inventory_check("test.inventory")], DEB)
    agent.scan(inventory(pkg("openssl", "3.0.11-1~deb12u2", "Debian:12")), scan_type="inventory")
    tick()
    assert intel.count("www.cisa.gov") == 1
    r = browser.post("/api/intel/sync", json={"source": "kev"})
    assert r.status_code == 202 and r.json()["requested"] == ["kev"]
    status = browser.get("/api/intel/status").json()
    assert next(s for s in status["sources"] if s["source"] == "kev")["sync_requested"] is True
    tick()
    assert intel.count("www.cisa.gov") == 2
    status = browser.get("/api/intel/status").json()
    kev_status = next(s for s in status["sources"] if s["source"] == "kev")
    assert kev_status["sync_requested"] is False and kev_status["status"] == "ok"
    with session_scope() as db:
        assert db.query(AuditEntry).filter_by(action="intel.sync_requested").count() == 1

    # refreshing OSV re-downloads details and re-matches existing inventories
    details = intel.count("api.osv.dev", "/v1/vulns/")
    assert browser.post("/api/intel/sync", json={"source": "osv"}).status_code == 202
    tick()  # flags the inventory for re-matching
    tick()
    assert intel.count("api.osv.dev", "/v1/vulns/") > details
    assert browser.post("/api/intel/sync", json={"source": "bogus"}).status_code == 422


# =========================================================================== MSRC (Windows build)


def setup_msrc(fake: FakeIntel) -> None:
    fake.msrc_docs = {
        "2026-Oct": cvrf_document("2026-Oct", "5066835", "10.0.26100.6899",
                                  [("CVE-2026-1001", 7.8, True), ("CVE-2026-1002", 8.8, False)]),
        "2026-Sep": cvrf_document("2026-Sep", "5065426", "10.0.26100.6584", [("CVE-2026-0901", 9.8, False)]),
        "2026-Aug": cvrf_document("2026-Aug", "5063878", "10.0.26100.4946", [("CVE-2026-0801", 5.5, False)]),
    }
    fake.kev = [{"cveID": "CVE-2026-1001", "dateAdded": "2026-10-14", "knownRansomwareCampaignUse": "Unknown"}]


def windows_os(build: str) -> dict[str, Any]:
    return pkg("Microsoft Windows", build, "windows-os")


def test_msrc_missing_kbs(make_agent, browser, intel):
    setup_msrc(intel)
    agent = make_agent([inventory_check("win.os.inventory")], windows_host(os_build="10.0.26100.6584"))
    agent.scan(inventory(windows_os("10.0.26100.6584")), scan_type="inventory")
    tick()
    [f] = vuln_findings(browser, agent.device_id)
    assert f["rule_id"] == "vuln.msrc" and f["subject_key"] == "kb:5066835" and f["vuln_id"] == "KB5066835"
    assert f["title"] == "Windows update KB5066835 is not installed"
    assert f["cvss_score"] == 8.8 and f["cve_id"] == "CVE-2026-1002" and f["severity"] == "high"
    assert f["kev"] is True  # one of its CVEs is in KEV
    assert f["fixed_version"] == "10.0.26100.6899" and f["finding_kind"] == "verified"
    assert "CVE-2026-1001" in f["impact"] and "active exploitation" in f["impact"]
    item = software(browser, agent.device_id)["Microsoft Windows 10.0.26100.6584"]
    assert item["match_status"] == "matched" and item["match_source"] == "msrc"
    assert "Windows 11 Version 24H2 for x64-based Systems" in item["match_reason"]
    detail = browser.get("/api/vulns/KB5066835").json()
    assert detail["aliases"] == ["CVE-2026-1001", "CVE-2026-1002"] and detail["kev"] is True
    assert intel.count("api.msrc.microsoft.com", "/cvrf/v3.0/cvrf/") == 3

    # an older build misses all three monthly updates
    agent.scan(inventory(windows_os("10.0.26100.4061")), scan_type="inventory")
    tick()
    open_kbs = sorted(f["subject_key"] for f in vuln_findings(browser, agent.device_id, "open"))
    assert open_kbs == ["kb:5063878", "kb:5065426", "kb:5066835"]
    assert intel.count("api.msrc.microsoft.com", "/cvrf/v3.0/cvrf/") == 3  # documents cached for a day

    # fully updated: every KB finding is verified resolved
    agent.scan(inventory(windows_os("10.0.26100.6899")), scan_type="inventory")
    tick()
    assert vuln_findings(browser, agent.device_id, "open") == []
    assert {f["status"] for f in vuln_findings(browser, agent.device_id)} == {"resolved"}


def test_msrc_skips_insider_and_unknown_builds(make_agent, browser, intel):
    setup_msrc(intel)
    agent = make_agent([inventory_check("win.os.inventory")],
                       windows_host(os_build="10.0.27924.1000", is_insider_build=True))
    agent.scan(inventory(windows_os("10.0.27924.1000")), scan_type="inventory")
    tick()
    assert vuln_findings(browser, agent.device_id) == []
    item = software(browser, agent.device_id)["Microsoft Windows 10.0.27924.1000"]
    assert item["match_status"] == "no_source"
    assert item["match_reason"] == "Insider or unrecognized build; Microsoft's update guide does not cover it"

    insider_on_release_build = make_agent([inventory_check("win.os.inventory")],
                                          windows_host(hostname="DEV-PC", os_build="10.0.26100.4061",
                                                       is_insider_build=True))
    insider_on_release_build.scan(inventory(windows_os("10.0.26100.4061")), scan_type="inventory")
    tick()
    assert vuln_findings(browser, insider_on_release_build.device_id) == []


# =========================================================================== NVD (curated Windows apps)


def setup_nvd(fake: FakeIntel) -> None:
    primary = {"cvssMetricV31": [{"source": "nvd@nist.gov", "type": "Primary", "cvssData": {
        "version": "3.1", "vectorString": V98, "baseScore": 9.8, "baseSeverity": "CRITICAL"}}]}
    cna_only = {"cvssMetricV31": [{"source": "chrome-cve-admin@google.com", "type": "Secondary", "cvssData": {
        "version": "3.1", "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", "baseScore": 8.8,
        "baseSeverity": "HIGH"}}]}
    fake.nvd_products["google:chrome"] = [
        nvd_cve("CVE-2026-2001", chrome_range("124.0.6367.201"), metrics=primary),
        nvd_cve("CVE-2026-2002", chrome_range("125.0.6422.60"), status="Modified", metrics=cna_only),
        nvd_cve("CVE-2026-2003", chrome_range("120.0.0.0"), metrics=primary),  # already fixed in our version
        nvd_cve("CVE-2026-2004", [], status="Deferred", metrics=cna_only),  # not enriched: never a finding
        nvd_cve("CVE-2026-2005", [], status="Received"),
    ]


def test_nvd_curated_apps(make_agent, browser, intel):
    setup_nvd(intel)
    agent = make_agent([inventory_check("win.software.inventory")], windows_host())
    agent.scan(inventory(pkg("Google Chrome", "124.0.6367.91", "windows-registry"),
                         pkg("Spotify", "1.2.40.599", "windows-registry"),
                         pkg("Contoso Chrome Helper", "1.0", "windows-registry")), scan_type="inventory")
    tick()
    found = {f["cve_id"]: f for f in vuln_findings(browser, agent.device_id)}
    assert set(found) == {"CVE-2026-2001", "CVE-2026-2002"}
    f1, f2 = found["CVE-2026-2001"], found["CVE-2026-2002"]
    assert f1["rule_id"] == "vuln.nvd" and f1["confidence"] == "medium" and f1["subject_key"] == (
        "windows-registry|Google Chrome|CVE-2026-2001")
    assert f1["cvss_score"] == 9.8 and f1["cvss_source"] == "NVD" and f1["severity"] == "critical"
    assert f1["fixed_version"] == "124.0.6367.201"
    assert f1["remediation"] == "Update Google Chrome to 124.0.6367.201 or later."
    assert f2["cvss_score"] == 8.8 and f2["cvss_source"] == "CNA: chrome-cve-admin@google.com"
    with session_scope() as db:
        rec = db.query(VulnRecord).filter_by(vuln_id="CVE-2026-2004").one()
        assert rec.nvd_status == "Deferred" and rec.source == "nvd"
    detail = browser.get("/api/vulns/CVE-2026-2004").json()
    assert "has not analysed" in detail["enrichment_note"] and detail["open_findings"] == 0

    items = software(browser, agent.device_id)
    assert items["Google Chrome 124.0.6367.91"]["match_status"] == "matched"
    assert items["Spotify 1.2.40.599"]["match_status"] == "no_source"
    assert "curated list" in items["Spotify 1.2.40.599"]["match_reason"]
    assert items["Contoso Chrome Helper 1.0"]["match_status"] == "no_source"  # no name-similarity matching
    assert intel.count("services.nvd.nist.gov") == 1  # only curated products are looked up
    req = next(r for r in intel.calls if r.url.host == "services.nvd.nist.gov")
    assert req.url.params["virtualMatchString"] == "cpe:2.3:a:google:chrome" and "apiKey" not in req.headers

    # NVD product data is cached for 24 hours
    agent.scan(inventory(pkg("Google Chrome", "125.0.6422.60", "windows-registry")), scan_type="inventory")
    tick()
    assert intel.count("services.nvd.nist.gov") == 1
    assert vuln_findings(browser, agent.device_id, "open") == []

    summary = browser.get("/api/vulnerabilities/summary", params={"device_id": agent.device_id}).json()
    assert summary["nvd_not_enriched"] == 2


def test_nvd_rate_limit_defers_instead_of_failing(make_agent, browser, intel, monkeypatch):
    setup_nvd(intel)
    clock = {"t": 0.0}
    limiter = nvd.SlidingWindowLimiter(nvd.LIMIT_WITHOUT_KEY, nvd.WINDOW_SECONDS, clock=lambda: clock["t"],
                                       sleep=lambda s: clock.__setitem__("t", clock["t"] + s))
    monkeypatch.setattr(nvd, "_limiters", {False: limiter, True: limiter})
    for _ in range(5):  # the window is already used up by earlier requests
        limiter.acquire()
    agent = make_agent([inventory_check("win.software.inventory")], windows_host())
    agent.scan(inventory(pkg("Google Chrome", "124.0.6367.91", "windows-registry")), scan_type="inventory")
    tick()
    assert intel.count("services.nvd.nist.gov") == 0
    assert software(browser, agent.device_id)["Google Chrome 124.0.6367.91"]["match_status"] == "pending"
    status = browser.get("/api/intel/status").json()
    assert status["queue"] == {"waiting": 1, "retrying": 0, "last_error": None}
    nvd_status = next(s for s in status["sources"] if s["source"] == "nvd")
    assert nvd_status["rate_limit"] == "5 requests per 30 seconds" and nvd_status["api_key_configured"] is False

    clock["t"] += 31
    tick(timedelta(seconds=40), monkeypatch)
    assert intel.count("services.nvd.nist.gov") == 1
    assert len(vuln_findings(browser, agent.device_id)) == 2


def test_nvd_api_key_header(make_agent, browser, intel):
    setup_nvd(intel)
    assert browser.put("/api/secrets/nvd_api_key", json={"value": "nvd-test-key-123"}).status_code == 200
    agent = make_agent([inventory_check("win.software.inventory")], windows_host())
    agent.scan(inventory(pkg("Google Chrome", "124.0.6367.91", "windows-registry")), scan_type="inventory")
    tick()
    req = next(r for r in intel.calls if r.url.host == "services.nvd.nist.gov")
    assert req.headers["apiKey"] == "nvd-test-key-123"
    with session_scope() as db:
        logged = db.query(OutboundRequest).filter_by(integration="nvd").one()
        assert "nvd-test-key-123" not in logged.path + logged.payload_summary


# =========================================================================== summary and inventory routes


def test_summary_numbers(make_agent, browser, intel):
    setup_osv(intel)
    setup_msrc(intel)
    setup_nvd(intel)
    intel.kev.append({"cveID": "CVE-2026-1111", "dateAdded": "2026-10-20", "knownRansomwareCampaignUse": "Unknown"})
    linux = make_agent([inventory_check("test.inventory")], DEB)
    linux.scan(inventory(pkg("openssl", "3.0.11-1~deb12u2", "Debian:12"), pkg("bash", "5.2.15-2+b7", "Debian:12"),
                         pkg("jinja2", "3.1.4", "PyPI"), pkg("leftpad", "1.0.0", "cargo-thing")), scan_type="inventory")
    win = make_agent([inventory_check("win.os.inventory"), inventory_check("win.software.inventory")],
                     windows_host(hostname="WIN-PC", os_build="10.0.26100.6584"))
    win.scan(inventory(windows_os("10.0.26100.6584"), pkg("Google Chrome", "124.0.6367.91", "windows-registry"),
                       pkg("Spotify", "1.2.40.599", "windows-registry")), scan_type="inventory")
    tick()

    s = browser.get("/api/vulnerabilities/summary", params={"device_id": linux.device_id}).json()
    assert s["open_total"] == 2
    assert s["by_severity"] == {"critical": 0, "high": 1, "medium": 1, "low": 0, "info": 0}
    assert {c["key"]: c["count"] for c in s["by_ecosystem"]} == {"Debian:12": 1, "PyPI": 1}
    assert s["kev_count"] == 1 and s["with_fixed_version"] == 2 and s["by_source"] == {"osv": 2}
    assert s["items"] == {"matched": 3, "no_source": 1, "error": 0, "pending": 0}
    assert s["items_by_ecosystem"]["cargo-thing"]["no_source"] == 1
    assert s["top_affected_software"][0]["name"] == "openssl" and s["top_affected_software"][0]["kev"] is True
    assert s["nvd_not_enriched"] == 0 and s["last_matched_at"]
    sources = {x["source"]: x for x in s["sources"]}
    assert set(sources) == {"osv", "msrc", "nvd", "kev", "epss"}
    assert sources["osv"]["status"] == "ok" and sources["kev"]["status"] == "ok"

    w = browser.get("/api/vulnerabilities/summary", params={"device_id": win.device_id}).json()
    assert w["open_total"] == 3  # one KB + two Chrome CVEs
    assert w["by_source"] == {"msrc": 1, "nvd": 2}
    assert w["by_severity"]["critical"] == 1 and w["by_severity"]["high"] == 2
    assert w["kev_count"] == 1  # the KB contains a KEV CVE
    assert w["items"] == {"matched": 2, "no_source": 1, "error": 0, "pending": 0}
    assert w["nvd_not_enriched"] == 2

    everything = browser.get("/api/vulnerabilities/summary").json()
    assert everything["open_total"] == 5 and everything["device_id"] is None
    assert browser.get("/api/vulnerabilities/summary", params={"device_id": 9999}).status_code == 404

    # inventory filters
    r = browser.get("/api/software", params={"ecosystem": "Debian:12"}).json()
    assert r["total"] == 2 and {i["name"] for i in r["items"]} == {"openssl", "bash"}
    assert browser.get("/api/software", params={"q": "chrom"}).json()["total"] == 1
    assert browser.get("/api/software", params={"match_status": "no_source"}).json()["total"] == 2
    assert browser.get("/api/software", params={"match_status": "bogus"}).status_code == 422

    intel_status = browser.get("/api/intel/status").json()
    assert intel_status["kev_count"] == 2 and intel_status["msrc_documents"] == ["2026-Aug", "2026-Oct", "2026-Sep"]
    assert intel_status["outbound_enabled"] is True and intel_status["nvd_products_cached"] == 1


def test_routes_require_sign_in(anon):
    for url in ("/api/software", "/api/vulnerabilities/summary", "/api/intel/status", "/api/vulns/CVE-2026-1111"):
        assert anon.get(url).status_code == 401
    assert anon.post("/api/intel/sync", json={"source": "kev"}).status_code == 401


def test_queue_row_tracks_device_check(make_agent, browser, intel):
    agent = make_agent([inventory_check("test.inventory")], DEB)
    agent.scan(inventory(pkg("bash", "5.2.15-2+b7", "Debian:12")), scan_type="inventory")
    agent.scan(inventory(pkg("bash", "5.2.15-2+b8", "Debian:12")), scan_type="inventory")
    with session_scope() as db:
        q = db.get(IntelSync, vm.QUEUE)
        assert q is not None
        # two uploads before a tick: only the newest inventory run is queued for this check
        assert len(q.data["items"]) == 1 and q.data["items"][0]["ecosystems"] == ["Debian:12"]
        assert db.query(SoftwareRecord).filter_by(is_present=True).count() == 1
        assert db.query(FindingRecord).count() == 0


def test_nothing_leaves_the_machine_until_an_integration_is_enabled(make_agent, browser, monkeypatch):
    """Out of the box, an inventory scan must not send package names anywhere."""
    for name in ("osv", "nvd", "kev", "epss", "msrc"):
        monkeypatch.setitem(app_settings.DEFAULTS["integrations"], name, {"enabled": False})
    calls: list[str] = []
    http.set_transport(httpx.MockTransport(lambda req: calls.append(str(req.url)) or httpx.Response(500)))
    try:
        agent = make_agent([inventory_check("linux.packages")], host=linux_host())
        agent.scan(inventory(pkg("openssl", "3.0.15-1~deb12u1", "Debian:12")), scan_type="inventory")
        tick()
        tick()
    finally:
        http.set_transport(None)
    assert calls == []
    with session_scope() as db:
        assert db.query(OutboundRequest).count() == 0
