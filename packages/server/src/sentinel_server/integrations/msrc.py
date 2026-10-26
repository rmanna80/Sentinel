"""Microsoft Security Update Guide (CVRF API v3.0, no key needed) for Windows OS builds.

``GET /cvrf/v3.0/updates`` lists the monthly documents (``value[]`` with ``ID``, ``InitialReleaseDate``,
``CurrentReleaseDate``, ``CvrfUrl``); each CVRF document (``Accept: application/json``) carries a
``ProductTree`` (``FullProductName[]`` of ``{ProductID, Value}``) and ``Vulnerability[]`` whose
``Remediations`` of ``Type`` 2 ("Vendor Fix") give the KB number in ``Description.Value``, the
``ProductID`` list and, for Windows, the ``FixedBuild``. A device whose build is lower than the
FixedBuild for its product is missing that update.

Only the parts Sentinel uses are kept (a small digest per month), never the whole document.
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlsplit

from . import cvss
from .http import request

API = "https://api.msrc.microsoft.com/cvrf/v3.0"
MONTHS = 3
VENDOR_FIX = 2  # Remediations.Type
THREAT_EXPLOIT_STATUS = 1  # Threats.Type
THREAT_SEVERITY = 3  # Threats.Type
_MONTH_ID = re.compile(r"^\d{4}-[A-Z][a-z]{2}$")
_KB = re.compile(r"^(?:KB)?(\d{6,8})$", re.IGNORECASE)

# Windows client builds Microsoft's update guide names. Insider builds are excluded by the caller.
WINDOWS_RELEASES: dict[int, str] = {
    26200: "Windows 11 Version 25H2",
    26100: "Windows 11 Version 24H2",
    22631: "Windows 11 Version 23H2",
    22621: "Windows 11 Version 22H2",
    19045: "Windows 10 Version 22H2",
}
ARCH_SUFFIX: dict[str, str] = {
    "amd64": "for x64-based Systems",
    "x64": "for x64-based Systems",
    "x86_64": "for x64-based Systems",
    "arm64": "for ARM64-based Systems",
    "aarch64": "for ARM64-based Systems",
    "x86": "for 32-bit Systems",
}
SEVERITY_WORDS = {"critical": "critical", "important": "high", "moderate": "medium", "low": "low"}

NOT_COVERED = "Insider or unrecognized build; Microsoft's update guide does not cover it"


class MsrcError(Exception):
    pass


def parse_build(version: str | None) -> tuple[int, int, int, int] | None:
    """'10.0.26100.4061' -> (10, 0, 26100, 4061)."""
    if not version:
        return None
    m = re.match(r"^\s*(\d+)\.(\d+)\.(\d+)\.(\d+)", version)
    if not m:
        return None
    a, b, c, d = (int(x) for x in m.groups())
    return a, b, c, d


def product_name(build: int, arch: str | None) -> str | None:
    release = WINDOWS_RELEASES.get(build)
    suffix = ARCH_SUFFIX.get((arch or "").strip().lower())
    if not release or not suffix:
        return None
    if suffix == ARCH_SUFFIX["x86"] and release.startswith("Windows 11"):
        return None  # Windows 11 has no 32-bit edition
    return f"{release} {suffix}"


# =========================================================================== fetching


def fetch_index() -> list[dict[str, Any]]:
    """The monthly documents, newest first (by initial release date)."""
    resp = request("msrc", "GET", f"{API}/updates", purpose="List Microsoft's monthly security update documents",
                   payload_summary="none (public list request)", timeout=30)
    if resp.status_code != 200:
        raise MsrcError(f"MSRC update list returned HTTP {resp.status_code}")
    try:
        data = resp.json()
    except ValueError as exc:
        raise MsrcError("MSRC update list was not valid JSON") from exc
    rows = data.get("value") if isinstance(data, dict) else None
    if not isinstance(rows, list):
        raise MsrcError("MSRC update list has no 'value' array")
    docs = [r for r in rows if isinstance(r, dict) and _MONTH_ID.match(str(r.get("ID", "")))]
    docs.sort(key=lambda r: str(r.get("InitialReleaseDate") or ""), reverse=True)
    return docs


def document_url(entry: dict[str, Any]) -> str:
    url = str(entry.get("CvrfUrl") or f"{API}/cvrf/{entry.get('ID')}")
    parts = urlsplit(url)
    if parts.scheme != "https" or parts.hostname != "api.msrc.microsoft.com" or "/cvrf/" not in parts.path:
        raise MsrcError(f"unexpected CVRF document URL {url!r}")
    return url


def fetch_document(entry: dict[str, Any]) -> dict[str, Any]:
    url = document_url(entry)
    resp = request("msrc", "GET", url, purpose=f"Download Microsoft security update details for {entry.get('ID')}",
                   payload_summary="none (public document request)", headers={"Accept": "application/json"},
                   timeout=120)
    if resp.status_code != 200:
        raise MsrcError(f"MSRC document {entry.get('ID')} returned HTTP {resp.status_code}")
    try:
        doc = resp.json()
    except ValueError as exc:
        raise MsrcError(f"MSRC document {entry.get('ID')} was not valid JSON") from exc
    if not isinstance(doc, dict) or "Vulnerability" not in doc:
        raise MsrcError(f"MSRC document {entry.get('ID')} has no Vulnerability list")
    return doc


# =========================================================================== digest


def _value(x: Any) -> str | None:
    if isinstance(x, dict):
        x = x.get("Value")
    return str(x) if x is not None else None


def _ids(x: Any) -> list[str]:
    if x is None:
        return []
    if isinstance(x, list):
        return [str(i) for i in x]
    return [str(x)]


def _products(tree: dict[str, Any]) -> dict[str, str]:
    """ProductID -> name, from FullProductName and from the nested Branch items."""
    out: dict[str, str] = {}

    def walk(node: Any) -> None:
        if isinstance(node, list):
            for n in node:
                walk(n)
        elif isinstance(node, dict):
            pid, name = node.get("ProductID"), node.get("Value")
            if isinstance(pid, str | int) and isinstance(name, str):
                out.setdefault(str(pid), name)
            for key in ("Items", "Branch", "FullProductName"):
                if key in node:
                    walk(node[key])

    walk(tree.get("FullProductName"))
    walk(tree.get("Branch"))
    return out


def _windows_client(name: str) -> bool:
    return name.startswith(("Windows 10 ", "Windows 11 "))


def digest(doc: dict[str, Any], entry: dict[str, Any] | None = None) -> dict[str, Any]:
    """{id, title, current_release, products: {product name: {kb: {...}}}} for Windows client products."""
    tracking = doc.get("DocumentTracking") or {}
    doc_id = _value((tracking.get("Identification") or {}).get("ID")) or (entry or {}).get("ID")
    names = {pid: name for pid, name in _products(doc.get("ProductTree") or {}).items() if _windows_client(name)}
    products: dict[str, dict[str, Any]] = {name: {} for name in names.values()}
    for vuln in doc.get("Vulnerability") or []:
        cve = str(vuln.get("CVE") or "")
        if not cve:
            continue
        title = _value(vuln.get("Title")) or cve
        scores: dict[str, tuple[float | None, str | None]] = {}
        for s in vuln.get("CVSSScoreSets") or []:
            base = s.get("BaseScore")
            for pid in _ids(s.get("ProductID")):
                scores[pid] = (float(base) if isinstance(base, int | float) else None, s.get("Vector"))
        exploited_all = False
        exploited_for: set[str] = set()
        severity_for: dict[str, str] = {}
        for t in vuln.get("Threats") or []:
            desc = _value(t.get("Description")) or ""
            pids = _ids(t.get("ProductID"))
            if t.get("Type") == THREAT_EXPLOIT_STATUS and re.search(r"Exploited:\s*Yes", desc, re.IGNORECASE):
                if pids:
                    exploited_for.update(pids)
                else:
                    exploited_all = True
            elif t.get("Type") == THREAT_SEVERITY:
                for pid in pids:
                    severity_for[pid] = desc
        for rem in vuln.get("Remediations") or []:
            if rem.get("Type") != VENDOR_FIX:
                continue
            m = _KB.match((_value(rem.get("Description")) or "").strip())
            if not m:
                continue
            kb = m.group(1)
            for pid in _ids(rem.get("ProductID")):
                if pid not in names:
                    continue
                entry_kb = products[names[pid]].setdefault(kb, {
                    "kb": kb, "fixed_build": rem.get("FixedBuild"), "url": rem.get("URL"),
                    "subtype": rem.get("SubType"), "supersedes": rem.get("Supercedence"), "cves": {},
                })
                if not entry_kb.get("fixed_build") and rem.get("FixedBuild"):
                    entry_kb["fixed_build"] = rem.get("FixedBuild")
                score, vector = scores.get(pid, (None, None))
                entry_kb["cves"][cve] = {
                    "title": title, "score": score, "vector": vector,
                    "severity": severity_for.get(pid), "exploited": exploited_all or pid in exploited_for,
                }
    return {"id": doc_id, "title": _value(doc.get("DocumentTitle")),
            "current_release": (entry or {}).get("CurrentReleaseDate") or tracking.get("CurrentReleaseDate"),
            "products": {k: v for k, v in products.items() if v}, "product_names": sorted(products)}


# =========================================================================== matching


def _fixed_tuple(fixed: Any) -> tuple[int, int, int, int] | None:
    return parse_build(str(fixed)) if fixed else None


def evaluate(digests: list[dict[str, Any]], product: str, build: tuple[int, int, int, int]) -> dict[str, Any]:
    """Which KBs the device is missing.

    Returns {"covered": bool, "reason": str|None, "missing": [kb entries newest first], "latest_kb": str|None}.
    """
    known = any(product in (d.get("product_names") or []) or product in (d.get("products") or {}) for d in digests)
    if not known:
        return {"covered": False, "reason": NOT_COVERED, "missing": [], "latest_kb": None}
    merged: dict[str, dict[str, Any]] = {}
    order: list[str] = []
    for d in digests:  # newest document first
        for kb, info in ((d.get("products") or {}).get(product) or {}).items():
            if kb not in merged:
                merged[kb] = {**info, "cves": dict(info.get("cves") or {}), "document": d.get("id")}
                order.append(kb)
            else:
                merged[kb]["cves"].update(info.get("cves") or {})
    comparable = [kb for kb in order if (ft := _fixed_tuple(merged[kb].get("fixed_build"))) and ft[2] == build[2]
                  and "hotpatch" not in str(merged[kb].get("subtype") or "").lower()]
    if not comparable:
        return {"covered": False, "missing": [], "latest_kb": None,
                "reason": "Microsoft's data lists no fixed build numbers for this Windows version"}
    latest = max(comparable, key=lambda kb: _fixed_tuple(merged[kb]["fixed_build"]) or (0, 0, 0, 0))
    missing = []
    for kb in comparable:
        fixed = _fixed_tuple(merged[kb]["fixed_build"])
        assert fixed is not None
        if build[3] < fixed[3]:
            missing.append(merged[kb])
    missing.sort(key=lambda e: _fixed_tuple(e["fixed_build"]) or (0, 0, 0, 0), reverse=True)
    return {"covered": True, "reason": None, "missing": missing, "latest_kb": latest}


def kb_score(entry: dict[str, Any]) -> tuple[float | None, str | None, str | None]:
    """(max CVSS base score, its vector, the CVE it belongs to) among the KB's CVEs for this product."""
    best: tuple[float | None, str | None, str | None] = (None, None, None)
    for cve, info in sorted((entry.get("cves") or {}).items()):
        score = info.get("score")
        if score is None:
            continue
        if best[0] is None or score > best[0]:
            best = (float(score), info.get("vector"), cve)
    return best


def kb_severity(entry: dict[str, Any]) -> tuple[str | None, str]:
    """Finding severity and where it came from: CVSS first, Microsoft's own rating as fallback."""
    score, vector, _ = kb_score(entry)
    if score is not None:
        version = cvss.vector_version(vector) or "3.1"
        return cvss.finding_severity(score, version), f"MSRC (CVSS {version})"
    ranks = ["low", "medium", "high", "critical"]
    words = [SEVERITY_WORDS.get(str(i.get("severity") or "").lower()) for i in (entry.get("cves") or {}).values()]
    rated = [w for w in words if w]
    if rated:
        return max(rated, key=ranks.index), "MSRC severity rating"
    return None, "MSRC (not rated)"
