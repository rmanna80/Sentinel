"""CISA Known Exploited Vulnerabilities catalog (public JSON feed, refreshed daily)."""

from __future__ import annotations

import re
from typing import Any

from .http import request

URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
_CVE = re.compile(r"^CVE-\d{4}-\d{4,}$")


class KevError(Exception):
    pass


def fetch_catalog() -> dict[str, Any]:
    """{"catalogVersion", "dateReleased", "count", "cves": {CVE: [dateAdded, knownRansomwareCampaignUse]}}."""
    resp = request("kev", "GET", URL, purpose="Download CISA's list of vulnerabilities known to be exploited",
                   payload_summary="none (public file download)", timeout=60)
    if resp.status_code != 200:
        raise KevError(f"KEV feed returned HTTP {resp.status_code}")
    try:
        data = resp.json()
    except ValueError as exc:
        raise KevError("KEV feed was not valid JSON") from exc
    rows = data.get("vulnerabilities") if isinstance(data, dict) else None
    if not isinstance(rows, list):
        raise KevError("KEV feed has no 'vulnerabilities' list")
    cves: dict[str, list[str | None]] = {}
    for r in rows:
        if not isinstance(r, dict):
            continue
        cve = str(r.get("cveID") or "").strip().upper()
        if _CVE.match(cve):
            cves[cve] = [r.get("dateAdded"), r.get("knownRansomwareCampaignUse")]
    if rows and not cves:
        raise KevError("KEV feed entries had no recognizable cveID values")
    return {"catalogVersion": data.get("catalogVersion"), "dateReleased": data.get("dateReleased"),
            "count": len(cves), "cves": cves}
