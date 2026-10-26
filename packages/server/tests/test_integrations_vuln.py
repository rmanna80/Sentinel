"""Unit tests for the vulnerability integrations: NVD configuration evaluation, version ordering,
the NVD rate limiter, OSV parsing, MSRC CVRF digests, KEV and EPSS clients.

Every fixture below is hand-written to match the documented response formats (OSV.dev API and
schema, NVD CVE API 2.0, MSRC CVRF API v3.0, CISA KEV JSON feed, FIRST EPSS API). None of them is a
recording of a live response. No test touches the network: a mock transport answers every request.
"""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest
from sentinel_server.integrations import epss, http, kev, msrc, nvd, osv
from sentinel_server.integrations.nvd import Installed, compare_generic, evaluate
from sentinel_server.integrations.osv import compare_dpkg


@pytest.fixture(autouse=True)
def _vulnerability_sources_enabled(monkeypatch):
    """Server integrations are off by default (local-first); these tests exercise them switched on."""
    from sentinel_server.services import app_settings as _settings

    for name in ("osv", "nvd", "kev", "epss", "msrc"):
        monkeypatch.setitem(_settings.DEFAULTS["integrations"], name, {"enabled": True})

# =========================================================================== helpers


@pytest.fixture
def transport():
    """Install a mock transport; tests register handlers by host."""
    routes: dict[str, Any] = {}
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        fn = routes.get(request.url.host)
        if fn is None:
            return httpx.Response(599, json={"error": f"no route for {request.url.host}"})
        return fn(request)

    http.set_transport(httpx.MockTransport(handler))
    yield routes, seen
    http.set_transport(None)


def cpe(vendor: str, product: str, version: str = "*", update: str = "*", sw_edition: str = "*",
        target_sw: str = "*", part: str = "a") -> str:
    return f"cpe:2.3:{part}:{vendor}:{product}:{version}:{update}:*:*:{sw_edition}:{target_sw}:*:*"


def match(criteria: str, vulnerable: bool = True, **bounds: str) -> dict[str, Any]:
    return {"vulnerable": vulnerable, "criteria": criteria, "matchCriteriaId": "00000000-0000-0000-0000-000000000000",
            **bounds}


def cve_record(configurations: list[dict[str, Any]], cve_id: str = "CVE-2026-0001", **extra: Any) -> dict[str, Any]:
    return {"id": cve_id, "vulnStatus": "Analyzed", "configurations": configurations, **extra}


def or_config(*matches: dict[str, Any]) -> dict[str, Any]:
    return {"nodes": [{"operator": "OR", "negate": False, "cpeMatch": list(matches)}]}


CHROME = Installed(cpes=frozenset({("google", "chrome")}), version="124.0.6367.91", windows_build=26100)


# =========================================================================== version ordering


@pytest.mark.parametrize(("a", "b", "expected"), [
    ("6.23", "6.23.0", 0),
    ("124.0.6367.91", "124.0.6367.207", -1),  # numeric, not lexical
    ("8.5.10", "8.5.6", 1),
    ("24.07", "24.7", 0),
    ("1.1.1w", "1.1.1", 1),  # trailing letter is a later OpenSSL release
    ("1.1.1w", "1.1.1x", -1),
    ("3.13.0b1", "3.13.0", -1),  # pre-release sorts first
    ("3.13.0rc1", "3.13.0b2", 1),
    ("1.0-rc1", "1.0", -1),
    ("2.45.2.windows.1", "2.45.2", 1),  # Git for Windows build suffix
    ("v1.2.3", "1.2.3", 0),
    ("abc", "1.0", None),  # nothing comparable
    (None, "1.0", None),
])
def test_compare_generic(a, b, expected):
    assert compare_generic(a, b) == expected


@pytest.mark.parametrize(("a", "b", "expected"), [
    ("3.0.11-1~deb12u2", "3.0.15-1~deb12u1", -1),
    ("1.0~rc1-1", "1.0-1", -1),  # tilde sorts before everything
    ("1:1.0-1", "2.0-1", 1),  # epoch wins
    ("2.36-9+deb12u7", "2.36-9+deb12u10", -1),
    ("1.2.3-1ubuntu0.1", "1.2.3-1", 1),
    ("1.0", "1.0", 0),
])
def test_compare_dpkg(a, b, expected):
    assert compare_dpkg(a, b) == expected


# =========================================================================== NVD configuration evaluation


def test_range_match_reports_fixed_version():
    rec = cve_record([or_config(match(cpe("google", "chrome"), versionEndExcluding="124.0.6367.201"))])
    v = evaluate(rec, CHROME)
    assert v.status == "affected" and v.match is not None and v.match.fixed_version == "124.0.6367.201"


def test_range_bounds_inclusive_and_exclusive():
    def verdict(**bounds: str) -> str:
        return evaluate(cve_record([or_config(match(cpe("google", "chrome"), **bounds))]), CHROME).status

    assert verdict(versionStartIncluding="124.0.6367.91", versionEndExcluding="125") == "affected"
    assert verdict(versionStartExcluding="124.0.6367.91", versionEndExcluding="125") == "not_affected"
    assert verdict(versionEndIncluding="124.0.6367.91") == "affected"
    assert verdict(versionEndExcluding="124.0.6367.91") == "not_affected"
    assert verdict(versionStartIncluding="125.0") == "not_affected"


def test_exact_version_criteria():
    exact = cve_record([or_config(match(cpe("google", "chrome", "124.0.6367.91")))])
    other = cve_record([or_config(match(cpe("google", "chrome", "124.0.6367.60")))])
    assert evaluate(exact, CHROME).status == "affected"
    assert evaluate(other, CHROME).status == "not_affected"


def test_name_similarity_never_matches():
    # a different product with a similar name: nothing to do with the installed app
    rec = cve_record([or_config(match(cpe("google", "chrome_os")), match(cpe("googlechrome", "chrome")))])
    assert evaluate(rec, CHROME).status == "not_affected"


def test_and_with_windows_platform_is_satisfied_on_windows():
    rec = cve_record([{"operator": "AND", "nodes": [
        {"operator": "OR", "negate": False, "cpeMatch": [match(cpe("docker", "desktop"), versionEndExcluding="4.29.0")]},
        {"operator": "OR", "negate": False, "cpeMatch": [
            match(cpe("apple", "macos", "-", part="o"), vulnerable=False),
            match(cpe("microsoft", "windows", "-", part="o"), vulnerable=False),
        ]},
    ]}])
    docker = Installed(cpes=frozenset({("docker", "desktop")}), version="4.28.0", windows_build=26100)
    v = evaluate(rec, docker)
    assert v.status == "affected" and v.match is not None and v.match.fixed_version == "4.29.0"
    assert evaluate(rec, Installed(cpes=docker.cpes, version="4.29.0")).status == "not_affected"


def test_and_with_specific_windows_release():
    def rec(release: str) -> dict[str, Any]:
        return cve_record([{"operator": "AND", "nodes": [
            {"operator": "OR", "cpeMatch": [match(cpe("google", "chrome"), versionEndExcluding="125")]},
            {"operator": "OR", "cpeMatch": [match(cpe("microsoft", release, "-", part="o"), vulnerable=False)]},
        ]}])

    assert evaluate(rec("windows_11_24h2"), CHROME).status == "affected"
    assert evaluate(rec("windows_10_22h2"), CHROME).status == "not_affected"
    # an OS we cannot decide (server edition) is unknown, so conservatively no finding
    assert evaluate(rec("windows_server_2022"), CHROME).status == "unknown"


def test_unresolvable_and_is_no_match():
    # vulnerable only together with another application we know nothing about
    rec = cve_record([{"operator": "AND", "nodes": [
        {"operator": "OR", "cpeMatch": [match(cpe("google", "chrome"), versionEndExcluding="125")]},
        {"operator": "OR", "cpeMatch": [match(cpe("somevendor", "plugin"), vulnerable=False)]},
    ]}])
    assert evaluate(rec, CHROME).status == "unknown"


def test_and_inside_one_node():
    rec = cve_record([{"nodes": [{"operator": "AND", "negate": False, "cpeMatch": [
        match(cpe("google", "chrome"), versionEndExcluding="125"),
        match(cpe("microsoft", "windows", "-", part="o"), vulnerable=False),
    ]}]}])
    assert evaluate(rec, CHROME).status == "affected"


def test_negated_node():
    # affected on every OS except Windows: negate excludes this device
    rec = cve_record([{"operator": "AND", "nodes": [
        {"operator": "OR", "cpeMatch": [match(cpe("google", "chrome"), versionEndExcluding="125")]},
        {"operator": "OR", "negate": True, "cpeMatch": [match(cpe("microsoft", "windows", "-", part="o"),
                                                              vulnerable=False)]},
    ]}])
    assert evaluate(rec, CHROME).status == "not_affected"
    # a negated node is never the vulnerable part on its own
    only_negated = cve_record([{"nodes": [{"operator": "OR", "negate": True,
                                           "cpeMatch": [match(cpe("google", "chrome", "1.0"))]}]}])
    assert evaluate(only_negated, CHROME).status == "not_affected"


def test_platform_specific_criteria():
    mac_only = cve_record([or_config(match(cpe("google", "chrome", target_sw="macos"), versionEndExcluding="125"))])
    win = cve_record([or_config(match(cpe("google", "chrome", target_sw="windows"), versionEndExcluding="125"))])
    assert evaluate(mac_only, CHROME).status == "not_affected"
    assert evaluate(win, CHROME).status == "affected"


def test_vulnerable_false_on_our_product_is_not_a_match():
    rec = cve_record([or_config(match(cpe("google", "chrome"), vulnerable=False, versionEndExcluding="125"))])
    assert evaluate(rec, CHROME).status == "not_affected"


def test_unenriched_cve_is_not_evaluated():
    rec = {"id": "CVE-2026-9999", "vulnStatus": "Deferred", "configurations": []}
    assert evaluate(rec, CHROME).status == "no_config"
    assert evaluate({"id": "CVE-2026-9998", "vulnStatus": "Received"}, CHROME).status == "no_config"


def test_java_update_component():
    jre = Installed(cpes=frozenset({("oracle", "jre")}), version="1.8.0", update="update451")
    exact = cve_record([or_config(match(cpe("oracle", "jre", "1.8.0", "update451")))])
    other = cve_record([or_config(match(cpe("oracle", "jre", "1.8.0", "update441")))])
    bare = cve_record([or_config(match(cpe("oracle", "jre"), versionEndIncluding="1.8.0"))])
    assert evaluate(exact, jre).status == "affected"
    assert evaluate(other, jre).status == "not_affected"
    assert evaluate(bare, jre).status == "unknown"  # 1.8.0 update N against a bare 1.8.0 bound: undecidable


def test_adobe_release_track():
    app = nvd.match_app("Adobe Acrobat Reader (64-bit)")
    assert app is not None
    inst = nvd.installed_for(app, "Adobe Acrobat Reader (64-bit)", "24.002.20759")
    assert inst is not None and inst.sw_edition == "continuous"
    rec = cve_record([or_config(
        match(cpe("adobe", "acrobat_reader_dc", sw_edition="continuous"), versionStartIncluding="15.008.20082",
              versionEndExcluding="24.002.21005"),
        match(cpe("adobe", "acrobat_reader", sw_edition="classic"), versionStartIncluding="20.001.3005",
              versionEndExcluding="20.005.30655"),
    )])
    v = evaluate(rec, inst)
    assert v.status == "affected" and v.match is not None and v.match.fixed_version == "24.002.21005"


@pytest.mark.parametrize(("display_name", "key"), [
    ("Google Chrome", "chrome"), ("Mozilla Firefox (x64 en-US)", "firefox"), ("Mozilla Firefox ESR (x64 en-US)",
                                                                             "firefox_esr"),
    ("7-Zip 24.08 (x64)", "7zip"), ("VLC media player", "vlc"), ("Git", "git"), ("Node.js", "nodejs"),
    ("Python 3.12.4 (64-bit)", "python"), ("Notepad++ (64-bit x64)", "notepadpp"), ("WinRAR 7.01 (64-bit)", "winrar"),
    ("PuTTY release 0.81 (64-bit)", "putty"), ("Wireshark 4.4.0 x64", "wireshark"), ("FileZilla 3.67.1", "filezilla"),
    ("Microsoft Visual Studio Code (User)", "vscode"), ("Docker Desktop", "docker_desktop"),
    ("Zoom Workplace (64-bit)", "zoom"), ("TeamViewer", "teamviewer"), ("Adobe Acrobat (64-bit)", "acrobat"),
    ("Java 8 Update 451 (64-bit)", "java_jre"), ("Java(TM) SE Development Kit 21.0.7 (64-bit)", "java_jdk"),
    ("OpenSSL 3.3.1 Light (64-bit)", "openssl"),
    # not curated: never matched by name similarity
    ("Microsoft Edge", None), ("Spotify", None), ("Python 3.12.4 Core Interpreter (64-bit)", None),
    ("Google Chrome Remote Desktop Host", None), ("FileZilla Server", None),
])
def test_curated_display_names(display_name, key):
    app = nvd.match_app(display_name)
    assert (app.key if app else None) == key


def test_curated_version_extraction():
    py = nvd.match_app("Python 3.12.4 (64-bit)")
    assert py is not None
    # the MSI DisplayVersion encodes the release level; the name carries the real version
    assert nvd.installed_for(py, "Python 3.12.4 (64-bit)", "3.12.4150.0").version == "3.12.4"  # type: ignore[union-attr]
    java = nvd.match_app("Java 8 Update 451 (64-bit)")
    inst = nvd.installed_for(java, "Java 8 Update 451 (64-bit)", "8.0.4510.10")  # type: ignore[arg-type]
    assert inst is not None and (inst.version, inst.update) == ("1.8.0", "update451")
    chrome = nvd.match_app("Google Chrome")
    assert nvd.installed_for(chrome, "Google Chrome", None) is None  # type: ignore[arg-type]


# =========================================================================== NVD scores


def _metric(version: str, kind: str, source: str, score: float, vector: str) -> dict[str, Any]:
    return {"source": source, "type": kind, "cvssData": {"version": version, "vectorString": vector, "baseScore": score}}


V98 = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
V78 = "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"


def test_score_prefers_nvd_primary():
    s = nvd.pick_score({"cvssMetricV31": [_metric("3.1", "Secondary", "chrome-cve-admin@google.com", 7.8, V78),
                                          _metric("3.1", "Primary", "nvd@nist.gov", 9.8, V98)]})
    assert (s.score, s.vector, s.source) == (9.8, V98, "NVD")


def test_score_falls_back_to_cna():
    s = nvd.pick_score({"cvssMetricV31": [_metric("3.1", "Secondary", "chrome-cve-admin@google.com", 7.8, V78)]})
    assert (s.score, s.source) == (7.8, "CNA: chrome-cve-admin@google.com")
    v4 = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
    s4 = nvd.pick_score({"cvssMetricV40": [_metric("4.0", "Secondary", "cna@example.org", 9.3, v4)]})
    assert s4.score == 9.3 and s4.source == "CNA: cna@example.org (CVSS 4.0)"
    assert nvd.pick_score({}).score is None


# =========================================================================== NVD rate limiting and paging


class FakeClock:
    def __init__(self) -> None:
        self.t = 1000.0
        self.sleeps: list[float] = []

    def time(self) -> float:
        return self.t

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.t += seconds


def test_rate_limiter_spacing_without_key():
    clock = FakeClock()
    lim = nvd.SlidingWindowLimiter(nvd.LIMIT_WITHOUT_KEY, nvd.WINDOW_SECONDS, clock=clock.time, sleep=clock.sleep)
    for _ in range(5):
        lim.acquire()
        clock.t += 1.0
    assert clock.sleeps == []
    # the sixth request inside the rolling 30 s window must wait until the first one ages out
    with pytest.raises(nvd.RateLimited) as exc:
        lim.acquire(max_wait=0)
    assert exc.value.wait == pytest.approx(30.5 - 5.0)
    lim.acquire(max_wait=60)
    assert clock.sleeps == [pytest.approx(25.5)]
    # never more than 5 in any 30 s window
    stamps = list(lim._hits)
    assert len([s for s in stamps if s > clock.t - 30]) <= 5


def test_rate_limiter_with_key_allows_fifty():
    clock = FakeClock()
    lim = nvd.SlidingWindowLimiter(nvd.LIMIT_WITH_KEY, nvd.WINDOW_SECONDS, clock=clock.time, sleep=clock.sleep)
    for _ in range(50):
        lim.acquire()
    with pytest.raises(nvd.RateLimited):
        lim.acquire()
    assert nvd.limiter(True).limit == 50 and nvd.limiter(False).limit == 5


def test_fetch_product_pages_and_sends_key(app, transport):
    routes, seen = transport
    total = 3

    def nvd_api(request: httpx.Request) -> httpx.Response:
        start = int(request.url.params["startIndex"])
        page = [{"cve": cve_record([], cve_id=f"CVE-2026-000{i}")} for i in range(start, min(start + 2, total))]
        return httpx.Response(200, json={"resultsPerPage": len(page), "startIndex": start, "totalResults": total,
                                         "format": "NVD_CVE", "version": "2.0", "vulnerabilities": page})

    routes["services.nvd.nist.gov"] = nvd_api
    clock = FakeClock()
    lim = nvd.SlidingWindowLimiter(50, 30, clock=clock.time, sleep=clock.sleep)
    out = nvd.fetch_product("google", "chrome", "secret-key", rate=lim)
    assert [r["id"] for r in out] == ["CVE-2026-0000", "CVE-2026-0001", "CVE-2026-0002"]
    assert len(seen) == 2
    first = seen[0]
    assert first.url.params["virtualMatchString"] == "cpe:2.3:a:google:chrome"
    assert first.url.params["resultsPerPage"] == "2000"
    assert first.headers["apiKey"] == "secret-key"

    from sentinel_server.db import session_scope
    from sentinel_server.models import OutboundRequest

    with session_scope() as db:
        logged = db.query(OutboundRequest).filter_by(integration="nvd").all()
        assert len(logged) == 2
        assert "secret-key" not in (logged[0].path + logged[0].payload_summary)
        assert logged[0].payload_summary == "product identifier cpe:2.3:a:google:chrome only (no device data)"


# =========================================================================== OSV


def test_osv_querybatch_follows_page_tokens(app, transport):
    routes, seen = transport

    def osv_api(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        results = []
        for q in body["queries"]:
            if q["package"]["name"] == "openssl" and "page_token" not in q:
                results.append({"vulns": [{"id": "DEBIAN-CVE-2026-0001", "modified": "2026-10-01T00:00:00Z"}],
                                "next_page_token": "tok-1"})
            elif q["package"]["name"] == "openssl":
                assert q["page_token"] == "tok-1"
                results.append({"vulns": [{"id": "DEBIAN-CVE-2026-0002", "modified": "2026-10-02T00:00:00Z"}]})
            else:
                results.append({})  # no vulnerabilities: an empty object
        return httpx.Response(200, json={"results": results})

    routes["api.osv.dev"] = osv_api
    out = osv.query_batch([osv.Query("openssl", "Debian:12", "3.0.11-1~deb12u2"),
                           osv.Query("bash", "Debian:12", "5.2.15-2+b7")])
    assert out[0] == [("DEBIAN-CVE-2026-0001", "2026-10-01T00:00:00Z"), ("DEBIAN-CVE-2026-0002", "2026-10-02T00:00:00Z")]
    assert out[1] == []
    first = json.loads(seen[0].content)
    assert first["queries"][0] == {"package": {"name": "openssl", "ecosystem": "Debian:12"},
                                   "version": "3.0.11-1~deb12u2"}
    assert len(json.loads(seen[1].content)["queries"]) == 1  # only the query that had a token is re-sent


def test_osv_errors_and_missing_records(app, transport):
    routes, _ = transport
    routes["api.osv.dev"] = lambda r: (httpx.Response(404, json={"code": 5, "message": "Bug not found."})
                                       if r.url.path.startswith("/v1/vulns/") else httpx.Response(200, json={"results": []}))
    assert osv.get_vuln("GHSA-xxxx-yyyy-zzzz") is None
    with pytest.raises(osv.OsvError):  # result count must match the query count
        osv.query_batch([osv.Query("requests", "PyPI", "2.31.0")])
    with pytest.raises(osv.OsvError):
        osv.get_vuln("../../etc/passwd")


DEBIAN_RECORD = {
    "id": "DEBIAN-CVE-2026-1111", "upstream": ["CVE-2026-1111"], "modified": "2026-10-01T00:00:00Z",
    "summary": "", "details": "A buffer overflow in X.509 parsing lets a malicious certificate crash the client.",
    "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"}],
    "affected": [
        {"package": {"name": "openssl", "ecosystem": "Debian:12"},
         "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "3.0.15-1~deb12u1"}]}],
         "ecosystem_specific": {"urgency": "medium"}},
        {"package": {"name": "openssl", "ecosystem": "Debian:13"},
         "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "3.5.1-1"}]}],
         "ecosystem_specific": {"urgency": "medium"}},
    ],
}


def test_osv_fixed_version_and_rating():
    assert osv.fixed_version(DEBIAN_RECORD, "openssl", "Debian:12", "3.0.11-1~deb12u2") == "3.0.15-1~deb12u1"
    assert osv.fixed_version(DEBIAN_RECORD, "openssl", "Debian:13", "3.5.0-1") == "3.5.1-1"
    r = osv.rating(DEBIAN_RECORD, "openssl", "Debian:12")
    assert (r.score, r.severity) == (7.5, "high") and r.source.startswith("OSV: CVSS 3.1")
    assert osv.cve_of(DEBIAN_RECORD) == "CVE-2026-1111"


def test_osv_multiple_ranges_pick_the_one_containing_the_version():
    rec = {"id": "PYSEC-2026-1", "affected": [{"package": {"name": "Jinja2", "ecosystem": "PyPI"}, "ranges": [
        {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.11.3"}, {"introduced": "3.0.0"},
                                         {"fixed": "3.1.5"}]}]}]}
    assert osv.fixed_version(rec, "jinja2", "PyPI", "3.1.4") == "3.1.5"  # name normalised
    assert osv.fixed_version(rec, "Jinja2", "PyPI", "2.10") == "2.11.3"


@pytest.mark.parametrize(("record", "severity", "source"), [
    ({"id": "UBUNTU-CVE-2026-2", "severity": [{"type": "Ubuntu", "score": "medium"}],
      "affected": [{"package": {"name": "curl", "ecosystem": "Ubuntu:24.04:LTS"}}]}, "medium", "OSV: Ubuntu priority"),
    ({"id": "DEBIAN-CVE-2026-3", "affected": [{"package": {"name": "curl", "ecosystem": "Ubuntu:24.04:LTS"},
                                               "ecosystem_specific": {"urgency": "high"}}]}, "high", "OSV: Debian urgency"),
    ({"id": "GHSA-aaaa-bbbb-cccc", "database_specific": {"severity": "MODERATE"},
      "affected": [{"package": {"name": "curl", "ecosystem": "Ubuntu:24.04:LTS"}}]}, "medium",
     "OSV: advisory severity rating"),
    ({"id": "DEBIAN-CVE-2026-4", "affected": [{"package": {"name": "curl", "ecosystem": "Ubuntu:24.04:LTS"},
                                               "ecosystem_specific": {"urgency": "not yet assigned"}}]}, None,
     "OSV: Debian urgency"),
    ({"id": "X-1", "affected": []}, None, "OSV: not rated by any source yet"),
])
def test_osv_ratings_without_cvss(record, severity, source):
    r = osv.rating(record, "curl", "Ubuntu:24.04:LTS")
    assert r.severity == severity and r.source == source and r.score is None


def test_osv_cvss4_vector_kept_but_not_scored():
    v4 = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
    rec = {"id": "GHSA-dddd-eeee-ffff", "severity": [{"type": "CVSS_V4", "score": v4}],
           "database_specific": {"severity": "CRITICAL"}, "affected": [{"package": {"name": "x", "ecosystem": "npm"}}]}
    r = osv.rating(rec, "x", "npm")
    assert r.score is None and r.vector == v4 and r.severity == "critical"


def test_osv_grouping_merges_aliases_and_drops_bundles():
    records = {
        "DSA-6000-1": {"id": "DSA-6000-1", "upstream": ["CVE-2026-1111", "CVE-2026-2222"]},
        "DEBIAN-CVE-2026-1111": {"id": "DEBIAN-CVE-2026-1111", "upstream": ["CVE-2026-1111"]},
        "GHSA-1111-2222-3333": {"id": "GHSA-1111-2222-3333", "aliases": ["CVE-2026-5555", "PYSEC-2026-9"]},
        "PYSEC-2026-9": {"id": "PYSEC-2026-9", "aliases": ["GHSA-1111-2222-3333", "CVE-2026-5555"]},
        "OLD-1": {"id": "OLD-1", "withdrawn": "2026-01-01T00:00:00Z"},
    }
    groups = osv.group_records(list(records), records)
    reps = {g.representative: sorted(g.ids) for g in groups}
    assert reps == {"DEBIAN-CVE-2026-1111": ["DEBIAN-CVE-2026-1111"],
                    "GHSA-1111-2222-3333": ["GHSA-1111-2222-3333", "PYSEC-2026-9"]}
    assert osv.group_cve([records["GHSA-1111-2222-3333"], records["PYSEC-2026-9"]]) == "CVE-2026-5555"


def test_osv_bundle_alone_is_kept():
    records = {"DSA-6000-1": {"id": "DSA-6000-1", "upstream": ["CVE-2026-1111"]}}
    [g] = osv.group_records(["DSA-6000-1"], records)
    assert g.representative == "DSA-6000-1"
    assert osv.group_cve([records["DSA-6000-1"]]) == "CVE-2026-1111"


# =========================================================================== MSRC

WIN11_X64 = "Windows 11 Version 24H2 for x64-based Systems"
WIN11_ARM = "Windows 11 Version 24H2 for ARM64-based Systems"
WIN10_X64 = "Windows 10 Version 22H2 for x64-based Systems"


def cvrf_document(month: str, kb: str, fixed_24h2: str, cves: list[tuple[str, float, bool]],
                  fixed_win10: str = "10.0.19045.6456") -> dict[str, Any]:
    """A CVRF JSON document shaped like MSRC's (hand-written; not a recording)."""
    vector = "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H/E:U/RL:O/RC:C"
    vulns = []
    for cve, score, exploited in cves:
        vulns.append({
            "Title": {"Value": f"Windows Component {cve[-4:]} Elevation of Privilege Vulnerability"},
            "CVE": cve,
            "Threats": [
                {"Type": 0, "Description": {"Value": "Elevation of Privilege"}, "ProductID": ["40001"]},
                {"Type": 1, "Description": {"Value": f"Publicly Disclosed:No;Exploited:{'Yes' if exploited else 'No'};"
                                                     "Latest Software Release:Exploitation Detected"}},
                {"Type": 3, "Description": {"Value": "Important"}, "ProductID": ["40001", "40002", "30001"]},
            ],
            "CVSSScoreSets": [{"BaseScore": score, "TemporalScore": score - 0.8, "Vector": vector,
                               "ProductID": ["40001", "40002", "30001"]}],
            "Remediations": [
                {"Description": {"Value": kb}, "URL": f"https://catalog.update.microsoft.com/v7/site/Search.aspx?q=KB{kb}",
                 "Supercedence": "", "ProductID": ["40001", "40002"], "Type": 2, "SubType": "Security Update",
                 "FixedBuild": fixed_24h2, "RestartRequired": {"Value": "Yes"}},
                {"Description": {"Value": str(int(kb) + 1)}, "ProductID": ["30001"], "Type": 2,
                 "SubType": "Security Update", "FixedBuild": fixed_win10},
                {"Description": {"Value": "Release Notes"}, "URL": "https://support.microsoft.com/help/x",
                 "ProductID": ["40001"], "Type": 5},
            ],
        })
    return {
        "DocumentTitle": {"Value": f"{month} Security Updates"},
        "DocumentType": {"Value": "Security Update"},
        "DocumentTracking": {"Identification": {"ID": {"Value": month}}},
        "ProductTree": {
            "Branch": [{"Items": [{"Type": 0, "Name": "Microsoft", "Items": [
                {"ProductID": "40001", "Value": WIN11_X64}, {"ProductID": "40002", "Value": WIN11_ARM}]}]}],
            "FullProductName": [{"ProductID": "40001", "Value": WIN11_X64}, {"ProductID": "40002", "Value": WIN11_ARM},
                                {"ProductID": "30001", "Value": WIN10_X64},
                                {"ProductID": "11111", "Value": "Microsoft Office 2019 for 64-bit editions"}],
        },
        "Vulnerability": vulns,
    }


@pytest.mark.parametrize(("build", "arch", "name"), [
    (26100, "AMD64", WIN11_X64), (26200, "AMD64", "Windows 11 Version 25H2 for x64-based Systems"),
    (22631, "ARM64", "Windows 11 Version 23H2 for ARM64-based Systems"),
    (22621, "AMD64", "Windows 11 Version 22H2 for x64-based Systems"), (19045, "AMD64", WIN10_X64),
    (19045, "x86", "Windows 10 Version 22H2 for 32-bit Systems"), (26100, "x86", None), (27900, "AMD64", None),
])
def test_msrc_product_names(build, arch, name):
    assert msrc.product_name(build, arch) == name


def test_msrc_digest_and_missing_kbs():
    doc = cvrf_document("2026-Oct", "5066835", "10.0.26100.6899",
                        [("CVE-2026-1001", 7.8, True), ("CVE-2026-1002", 8.8, False)])
    d = msrc.digest(doc, {"ID": "2026-Oct", "CurrentReleaseDate": "2026-10-14T07:00:00Z"})
    assert set(d["products"]) == {WIN11_X64, WIN11_ARM, WIN10_X64}  # Office is not a Windows client product
    entry = d["products"][WIN11_X64]["5066835"]
    assert entry["fixed_build"] == "10.0.26100.6899"
    assert entry["cves"]["CVE-2026-1001"]["exploited"] is True
    assert entry["cves"]["CVE-2026-1002"] == {"title": "Windows Component 1002 Elevation of Privilege Vulnerability",
                                              "score": 8.8, "vector": entry["cves"]["CVE-2026-1002"]["vector"],
                                              "severity": "Important", "exploited": False}
    assert "Release Notes" not in str(d["products"])  # known-issue remediations (type 5) are not KBs

    sep = msrc.digest(cvrf_document("2026-Sep", "5065426", "10.0.26100.6584", [("CVE-2026-0901", 9.8, False)]))
    digests = [d, sep]
    old = msrc.evaluate(digests, WIN11_X64, (10, 0, 26100, 4061))
    assert old["covered"] and [m["kb"] for m in old["missing"]] == ["5066835", "5065426"]
    assert old["latest_kb"] == "5066835"
    mid = msrc.evaluate(digests, WIN11_X64, (10, 0, 26100, 6584))
    assert [m["kb"] for m in mid["missing"]] == ["5066835"]
    current = msrc.evaluate(digests, WIN11_X64, (10, 0, 26100, 6899))
    assert current["covered"] and current["missing"] == []
    score, _, top = msrc.kb_score(old["missing"][0])
    assert (score, top) == (8.8, "CVE-2026-1002")
    assert msrc.kb_severity(old["missing"][0]) == ("high", "MSRC (CVSS 3.1)")


def test_msrc_unknown_product_is_not_covered():
    d = msrc.digest(cvrf_document("2026-Oct", "5066835", "10.0.26100.6899", [("CVE-2026-1001", 7.8, False)]))
    r = msrc.evaluate([d], "Windows 11 Version 25H2 for x64-based Systems", (10, 0, 26200, 100))
    assert r["covered"] is False and r["reason"] == msrc.NOT_COVERED


def test_msrc_fetch(app, transport):
    routes, _ = transport
    docs = {"2026-Oct": cvrf_document("2026-Oct", "5066835", "10.0.26100.6899", [("CVE-2026-1001", 7.8, False)])}

    def msrc_api(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/cvrf/v3.0/updates":
            return httpx.Response(200, json={"@odata.context": "https://api.msrc.microsoft.com/cvrf/v3.0/$metadata#updates",
                                             "value": [
                {"ID": "2026-Sep", "Alias": "2026-Sep", "DocumentTitle": "September 2026 Security Updates",
                 "InitialReleaseDate": "2026-09-09T07:00:00Z", "CurrentReleaseDate": "2026-09-20T07:00:00Z",
                 "CvrfUrl": "https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/2026-Sep"},
                {"ID": "2026-Oct", "Alias": "2026-Oct", "DocumentTitle": "October 2026 Security Updates",
                 "InitialReleaseDate": "2026-10-14T07:00:00Z", "CurrentReleaseDate": "2026-10-14T07:00:00Z",
                 "CvrfUrl": "https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/2026-Oct"},
                {"ID": "bogus", "CvrfUrl": "https://evil.example/cvrf/bogus"},
            ]})
        assert request.headers["Accept"] == "application/json"
        return httpx.Response(200, json=docs[request.url.path.rsplit("/", 1)[1]])

    routes["api.msrc.microsoft.com"] = msrc_api
    index = msrc.fetch_index()
    assert [e["ID"] for e in index] == ["2026-Oct", "2026-Sep"]  # newest first, malformed entries dropped
    assert msrc.fetch_document(index[0])["Vulnerability"][0]["CVE"] == "CVE-2026-1001"
    with pytest.raises(msrc.MsrcError):
        msrc.document_url({"ID": "x", "CvrfUrl": "https://evil.example/cvrf/x"})


# =========================================================================== KEV and EPSS


def test_kev_catalog(app, transport):
    routes, _ = transport
    routes["www.cisa.gov"] = lambda r: httpx.Response(200, json={
        "title": "CISA Catalog of Known Exploited Vulnerabilities", "catalogVersion": "2026.10.24",
        "dateReleased": "2026-10-24T17:00:00.000Z", "count": 2, "vulnerabilities": [
            {"cveID": "CVE-2026-1111", "vendorProject": "OpenSSL", "product": "OpenSSL", "vulnerabilityName": "x",
             "dateAdded": "2026-10-20", "shortDescription": "x", "requiredAction": "Apply updates.",
             "dueDate": "2026-11-10", "knownRansomwareCampaignUse": "Known", "notes": "", "cwes": ["CWE-787"]},
            {"cveID": "not-a-cve", "dateAdded": "2026-10-20"},
        ]})
    cat = kev.fetch_catalog()
    assert cat["cves"] == {"CVE-2026-1111": ["2026-10-20", "Known"]} and cat["catalogVersion"] == "2026.10.24"


def test_epss_scores_are_chunked_and_parsed(app, transport):
    routes, seen = transport

    def epss_api(request: httpx.Request) -> httpx.Response:
        cves = request.url.params["cve"].split(",")
        data = [{"cve": c, "epss": "0.912340000", "percentile": "0.998760000", "date": "2026-10-25"}
                for c in cves if c != "CVE-2026-0007"]
        return httpx.Response(200, json={"status": "OK", "status-code": 200, "version": "1.0", "total": len(data),
                                         "offset": 0, "limit": len(cves), "data": data})

    routes["api.first.org"] = epss_api
    wanted = [f"CVE-2026-{i:04d}" for i in range(150)] + ["junk"]
    out = epss.fetch_scores(wanted)
    assert len(seen) == 2 and all(len(r.url.params["cve"]) <= 2000 for r in seen)
    assert out["CVE-2026-0001"] == {"epss": 0.91234, "percentile": 0.99876, "date": "2026-10-25"}
    assert out["CVE-2026-0007"] is None and "junk" not in out
