"""OSV.dev: vulnerabilities for Debian, Ubuntu, PyPI and npm packages.

Two calls: ``POST /v1/querybatch`` (up to 1000 package versions per request; answers carry only
vulnerability ids and their ``modified`` time, and may continue with a per-query
``next_page_token``) and ``GET /v1/vulns/{id}`` for the full record. Distro version strings are
passed verbatim: OSV evaluates them with the distro's own version ordering, which handles backports.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import quote

from . import cvss
from .http import request
from .nvd import compare_generic

API = "https://api.osv.dev/v1"
BATCH_SIZE = 1000
MAX_PAGES = 100
_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:\-]{1,63}$")


class OsvError(Exception):
    pass


def supports(ecosystem: str) -> bool:
    return ecosystem in ("PyPI", "npm") or ecosystem.split(":", 1)[0] in ("Debian", "Ubuntu")


# =========================================================================== API calls


@dataclass(frozen=True)
class Query:
    name: str
    ecosystem: str
    version: str


def query_batch(queries: list[Query]) -> list[list[tuple[str, str | None]]]:
    """For each query, the (id, modified) pairs of vulnerabilities affecting that version."""
    results: list[list[tuple[str, str | None]]] = [[] for _ in queries]
    for start in range(0, len(queries), BATCH_SIZE):
        pending: list[tuple[int, str | None]] = [(i, None) for i in range(start, min(start + BATCH_SIZE, len(queries)))]
        pages = 0
        while pending:
            pages += 1
            if pages > MAX_PAGES:
                raise OsvError("OSV returned too many result pages; stopping")
            body = {"queries": [_query_json(queries[i], token) for i, token in pending]}
            ecosystems = sorted({queries[i].ecosystem for i, _ in pending})
            resp = request(
                "osv", "POST", f"{API}/querybatch",
                purpose="Look up known vulnerabilities for installed packages",
                payload_summary=f"package names and versions ({len(pending)} packages; {', '.join(ecosystems)})",
                json=body, timeout=60,
            )
            if resp.status_code != 200:
                raise OsvError(f"OSV querybatch returned HTTP {resp.status_code}")
            try:
                data = resp.json()
            except ValueError as exc:
                raise OsvError("OSV querybatch returned invalid JSON") from exc
            rows = data.get("results") if isinstance(data, dict) else None
            if not isinstance(rows, list) or len(rows) != len(pending):
                raise OsvError(f"OSV querybatch answered {len(rows) if isinstance(rows, list) else 'no'} results "
                               f"for {len(pending)} queries")
            nxt: list[tuple[int, str | None]] = []
            for (i, _), row in zip(pending, rows, strict=True):
                row = row or {}
                for v in row.get("vulns") or []:
                    if isinstance(v, dict) and isinstance(v.get("id"), str):
                        results[i].append((v["id"], v.get("modified")))
                token = row.get("next_page_token")
                if token:
                    nxt.append((i, str(token)))
            pending = nxt
    return results


def _query_json(q: Query, page_token: str | None) -> dict[str, Any]:
    body: dict[str, Any] = {"package": {"name": q.name, "ecosystem": q.ecosystem}, "version": q.version}
    if page_token:
        body["page_token"] = page_token
    return body


def get_vuln(vuln_id: str) -> dict[str, Any] | None:
    """The full OSV record, or None when OSV no longer has it (HTTP 404)."""
    if not _ID_RE.match(vuln_id):
        raise OsvError(f"refusing unexpected OSV id {vuln_id!r}")
    resp = request(
        "osv", "GET", f"{API}/vulns/{quote(vuln_id, safe='')}",
        purpose="Download details of a vulnerability that matched an installed package",
        payload_summary=f"vulnerability id {vuln_id} only", ok_statuses=(200, 404),
    )
    if resp.status_code == 404:
        return None
    if resp.status_code != 200:
        raise OsvError(f"OSV returned HTTP {resp.status_code} for {vuln_id}")
    try:
        data = resp.json()
    except ValueError as exc:
        raise OsvError(f"OSV returned invalid JSON for {vuln_id}") from exc
    if not isinstance(data, dict) or data.get("id") != vuln_id:
        raise OsvError(f"OSV returned an unexpected record for {vuln_id}")
    return data


# =========================================================================== version ordering


def _dpkg_order(c: str) -> int:
    if c.isdigit():
        return 0
    if c.isalpha():
        return ord(c)
    if c == "~":
        return -1
    return ord(c) + 256


def _verrevcmp(a: str, b: str) -> int:
    i = j = 0
    while i < len(a) or j < len(b):
        first_diff = 0
        while (i < len(a) and not a[i].isdigit()) or (j < len(b) and not b[j].isdigit()):
            ac = _dpkg_order(a[i]) if i < len(a) else 0
            bc = _dpkg_order(b[j]) if j < len(b) else 0
            if ac != bc:
                return -1 if ac < bc else 1
            i += 1
            j += 1
        while i < len(a) and a[i] == "0":
            i += 1
        while j < len(b) and b[j] == "0":
            j += 1
        while i < len(a) and a[i].isdigit() and j < len(b) and b[j].isdigit():
            if not first_diff:
                first_diff = ord(a[i]) - ord(b[j])
            i += 1
            j += 1
        if i < len(a) and a[i].isdigit():
            return 1
        if j < len(b) and b[j].isdigit():
            return -1
        if first_diff:
            return -1 if first_diff < 0 else 1
    return 0


def _split_dpkg(v: str) -> tuple[int, str, str]:
    epoch = 0
    if ":" in v:
        e, v = v.split(":", 1)
        epoch = int(e) if e.isdigit() else 0
    upstream, rev = (v.rsplit("-", 1) if "-" in v else (v, ""))
    return epoch, upstream, rev


def compare_dpkg(a: str | None, b: str | None) -> int | None:
    """Debian version ordering (epoch, upstream, revision; '~' sorts before everything)."""
    if not a or not b:
        return None
    ea, ua, ra = _split_dpkg(a.strip())
    eb, ub, rb = _split_dpkg(b.strip())
    if ea != eb:
        return -1 if ea < eb else 1
    return _verrevcmp(ua, ub) or _verrevcmp(ra, rb)


def comparator(ecosystem: str) -> Callable[[str | None, str | None], int | None]:
    if ecosystem.split(":", 1)[0] in ("Debian", "Ubuntu"):
        return compare_dpkg
    return compare_generic


def normalize_name(name: str, ecosystem: str) -> str:
    if ecosystem == "PyPI":
        return re.sub(r"[-_.]+", "-", name).lower()
    return name


# =========================================================================== record parsing


def matching_affected(record: dict[str, Any], name: str, ecosystem: str) -> list[dict[str, Any]]:
    want = normalize_name(name, ecosystem)
    out = []
    for aff in record.get("affected") or []:
        pkg = aff.get("package") or {}
        if pkg.get("ecosystem") == ecosystem and normalize_name(str(pkg.get("name", "")), ecosystem) == want:
            out.append(aff)
    return out


def fixed_version(record: dict[str, Any], name: str, ecosystem: str, installed: str) -> str | None:
    """The 'fixed' event of the range that contains the installed version, when it can be decided."""
    cmp = comparator(ecosystem)
    fixes: list[str] = []
    for aff in matching_affected(record, name, ecosystem):
        for rng in aff.get("ranges") or []:
            if rng.get("type") not in ("ECOSYSTEM", "SEMVER"):
                continue
            introduced: str | None = None
            for ev in rng.get("events") or []:
                if "introduced" in ev:
                    introduced = str(ev["introduced"])
                elif "fixed" in ev:
                    fix = str(ev["fixed"])
                    fixes.append(fix)
                    lower_ok = introduced in (None, "0") or (cmp(installed, introduced) or 0) >= 0
                    upper = cmp(installed, fix)
                    if lower_ok and upper is not None and upper < 0:
                        return fix
                    introduced = None
    distinct = sorted(set(fixes))
    if len(distinct) == 1:
        return distinct[0]
    newer = [f for f in distinct if (cmp(f, installed) or 0) > 0]
    if newer:
        best = newer[0]
        for f in newer[1:]:
            if (cmp(f, best) or 0) < 0:
                best = f
        return best
    return None


_UBUNTU_PRIORITY = {"critical": "critical", "high": "high", "medium": "medium", "low": "low", "negligible": "info"}
_DEBIAN_URGENCY = {"high": "high", "medium": "medium", "low": "low", "unimportant": "info"}
_GHSA_SEVERITY = {"critical": "critical", "high": "high", "moderate": "medium", "medium": "medium", "low": "low"}


@dataclass
class Rating:
    severity: str | None  # finding vocabulary, None when nothing rated it
    score: float | None
    vector: str | None
    source: str
    note: str | None = None
    rank: int = 99  # lower is better (more specific)


def _from_severity_list(entries: list[dict[str, Any]], record_id: str) -> list[Rating]:
    out: list[Rating] = []
    for entry in entries or []:
        typ, score = str(entry.get("type", "")), entry.get("score")
        if not isinstance(score, str) or not score:
            continue
        if typ == "CVSS_V3":
            try:
                base = cvss.base_score(score)
            except cvss.CvssError:
                continue
            version = cvss.vector_version(score) or "3"
            out.append(Rating(cvss.finding_severity(base, version), base, score, f"OSV: CVSS {version} ({record_id})",
                              rank=0))
        elif typ == "CVSS_V4":
            out.append(Rating(None, None, score, f"OSV: CVSS 4.0 vector only ({record_id})", rank=2))
        elif typ == "CVSS_V2":
            out.append(Rating(None, None, score, f"OSV: CVSS 2.0 vector only ({record_id})", rank=3))
        elif typ.lower() == "ubuntu":
            sev = _UBUNTU_PRIORITY.get(score.lower())
            if sev:
                out.append(Rating(sev, None, None, "OSV: Ubuntu priority", f"Ubuntu priority: {score.lower()}", rank=1))
    return out


def rating(record: dict[str, Any], name: str, ecosystem: str) -> Rating:
    """Best available severity: a CVSS 3.x vector, else the distro's or advisory's own rating."""
    rid = str(record.get("id", ""))
    candidates = _from_severity_list(record.get("severity") or [], rid)
    for aff in matching_affected(record, name, ecosystem):
        candidates += _from_severity_list(aff.get("severity") or [], rid)
        urgency = (aff.get("ecosystem_specific") or {}).get("urgency")
        if isinstance(urgency, str):
            sev = _DEBIAN_URGENCY.get(urgency.lower())
            note = f"Debian urgency: {urgency}"
            if urgency.lower() == "end-of-life":
                note = "Debian no longer provides security support for this package in this release"
            candidates.append(Rating(sev, None, None, "OSV: Debian urgency", note, rank=1 if sev else 50))
    ghsa = (record.get("database_specific") or {}).get("severity")
    if isinstance(ghsa, str) and ghsa.lower() in _GHSA_SEVERITY:
        candidates.append(Rating(_GHSA_SEVERITY[ghsa.lower()], None, None, "OSV: advisory severity rating",
                                 f"Advisory rating: {ghsa.lower()}", rank=1))
    return _combine(candidates)


def _combine(candidates: list[Rating]) -> Rating:
    """The most specific rating; a vector that cannot be scored here (CVSS 4.0, 2.0) is kept next to the
    qualitative rating that supplies the severity."""
    if not candidates:
        return Rating(None, None, None, "OSV: not rated by any source yet", rank=100)
    candidates = sorted(candidates, key=lambda r: r.rank)
    best = candidates[0]
    if best.score is not None:
        return best
    rated = next((r for r in candidates if r.severity is not None), None)
    vectored = next((r for r in candidates if r.vector), None)
    if rated is None:
        return best
    if vectored is None or vectored is rated:
        return rated
    return Rating(rated.severity, None, vectored.vector, f"{rated.source}; {vectored.source}", rated.note, rated.rank)


def best_rating(members: list[dict[str, Any]], name: str, ecosystem: str) -> Rating:
    """The most specific rating among records describing the same vulnerability (e.g. GHSA and PYSEC)."""
    return _combine([rating(m, name, ecosystem) for m in members])


def record_rating(record: dict[str, Any]) -> Rating | None:
    """Package-independent rating from the record's own top-level severity list."""
    ratings = sorted(_from_severity_list(record.get("severity") or [], str(record.get("id", ""))), key=lambda r: r.rank)
    return ratings[0] if ratings else None


def distro_end_of_life(members: list[dict[str, Any]], name: str, ecosystem: str) -> bool:
    """Debian marks packages it no longer supports in a release with urgency 'end-of-life'."""
    return any(str((aff.get("ecosystem_specific") or {}).get("urgency", "")).lower() == "end-of-life"
               for m in members for aff in matching_affected(m, name, ecosystem))


def distro_unimportant(members: list[dict[str, Any]], name: str, ecosystem: str) -> str | None:
    """Debian 'unimportant' or Ubuntu 'negligible': the distribution says it is not a real risk there."""
    for m in members:
        for aff in matching_affected(m, name, ecosystem):
            urgency = (aff.get("ecosystem_specific") or {}).get("urgency")
            if isinstance(urgency, str) and urgency.lower() == "unimportant":
                return "Debian rates it unimportant"
        if ecosystem.startswith("Ubuntu"):
            for s in m.get("severity") or []:
                if str(s.get("type", "")).lower() == "ubuntu" and str(s.get("score", "")).lower() == "negligible":
                    return "Ubuntu rates it negligible"
    return None


_CVE_IN = re.compile(r"CVE-\d{4}-\d{4,}")


def all_ids(record: dict[str, Any]) -> list[str]:
    ids = [str(record.get("id", ""))]
    for key in ("aliases", "upstream"):
        ids += [str(x) for x in record.get(key) or [] if isinstance(x, str)]
    return [i for i in dict.fromkeys(ids) if i]


def own_cves(record: dict[str, Any]) -> set[str]:
    """CVE ids the record itself stands for (its id or aliases), not the ones a bundle advisory lists upstream."""
    out = set()
    for i in [record.get("id"), *(record.get("aliases") or [])]:
        m = _CVE_IN.search(str(i or ""))
        if m:
            out.add(m.group(0))
    return out


def group_cve(members: list[dict[str, Any]]) -> str | None:
    owned = sorted(set().union(*(own_cves(m) for m in members))) if members else []
    if owned:
        return owned[0]
    upstream = sorted({m.group(0) for r in members for u in r.get("upstream") or []
                       if (m := _CVE_IN.search(str(u)))})
    return upstream[0] if len(upstream) == 1 else None


def cve_of(record: dict[str, Any]) -> str | None:
    return group_cve([record])


def references(record: dict[str, Any], limit: int = 15) -> list[str]:
    urls = [f"https://osv.dev/vulnerability/{record.get('id')}"]
    for ref in record.get("references") or []:
        url = ref.get("url") if isinstance(ref, dict) else None
        if isinstance(url, str) and url.startswith(("https://", "http://")):
            urls.append(url)
    return list(dict.fromkeys(urls))[:limit]


def slim(record: dict[str, Any]) -> dict[str, Any]:
    """The record without the (often huge) explicit version lists, for caching."""
    out = dict(record)
    out["affected"] = [{k: v for k, v in aff.items() if k != "versions"} for aff in record.get("affected") or []]
    return out


@dataclass
class Group:
    """OSV records that describe the same vulnerability for one package (aliases, advisories)."""

    representative: str
    ids: list[str] = field(default_factory=list)


_RANK_PREFIXES = ("DEBIAN-CVE-", "UBUNTU-CVE-", "GHSA-", "PYSEC-", "CVE-", "MAL-")


def _id_rank(vid: str) -> tuple[int, str]:
    for n, prefix in enumerate(_RANK_PREFIXES):
        if vid.startswith(prefix):
            return n, vid
    return len(_RANK_PREFIXES), vid


def group_records(ids: list[str], records: dict[str, dict[str, Any]]) -> list[Group]:
    """One group per real vulnerability.

    Records that are aliases of each other or stand for the same CVE are merged; bundle advisories
    (DSA, DLA, USN ...) are dropped when a per-CVE record for one of their upstream CVEs is present,
    so the same problem is not listed twice. Withdrawn records are ignored.
    """
    present = [i for i in dict.fromkeys(ids) if i in records and not records[i].get("withdrawn")]
    owns = {i: own_cves(records[i]) for i in present}
    covered: set[str] = set().union(*owns.values()) if owns else set()
    idset = set(present)
    kept = []
    for i in present:
        if not owns[i]:
            ups = [str(u) for u in records[i].get("upstream") or []]
            if any((u in idset and u != i) or ((m := _CVE_IN.search(u)) and m.group(0) in covered) for u in ups):
                continue
        kept.append(i)
    parent = {i: i for i in kept}

    def find(x: str) -> str:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a: str, b: str) -> None:
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[max(ra, rb)] = min(ra, rb)

    by_cve: dict[str, str] = {}
    for i in kept:
        for a in records[i].get("aliases") or []:
            if a in parent:
                union(i, a)
        for c in owns[i]:
            if c in by_cve:
                union(i, by_cve[c])
            else:
                by_cve[c] = i
    groups: dict[str, list[str]] = {}
    for i in kept:
        groups.setdefault(find(i), []).append(i)
    out = []
    for members in groups.values():
        members.sort(key=_id_rank)
        out.append(Group(representative=members[0], ids=members))
    out.sort(key=lambda g: _id_rank(g.representative))
    return out
