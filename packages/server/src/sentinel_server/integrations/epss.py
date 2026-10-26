"""FIRST EPSS scores: the estimated probability that a CVE is exploited in the next 30 days."""

from __future__ import annotations

import re
from typing import Any

from .http import request

URL = "https://api.first.org/data/v1/epss"
CHUNK = 100  # the cve parameter is limited to 2000 characters; 100 ids stay well under it
_CVE = re.compile(r"^CVE-\d{4}-\d{4,}$")


class EpssError(Exception):
    pass


def _float(x: Any) -> float | None:
    try:
        return float(x)
    except (TypeError, ValueError):
        return None


def fetch_scores(cves: list[str]) -> dict[str, dict[str, Any] | None]:
    """{CVE: {"epss", "percentile", "date"}} for every requested CVE; None when EPSS has no score."""
    wanted = sorted({c.upper() for c in cves if _CVE.match(c.upper())})
    out: dict[str, dict[str, Any] | None] = {c: None for c in wanted}
    for i in range(0, len(wanted), CHUNK):
        chunk = wanted[i:i + CHUNK]
        resp = request("epss", "GET", URL, params={"cve": ",".join(chunk), "limit": len(chunk)},
                       purpose="Look up exploitation likelihood (EPSS) for vulnerabilities found on your devices",
                       payload_summary=f"CVE identifiers only ({len(chunk)} CVEs)", timeout=30)
        if resp.status_code != 200:
            raise EpssError(f"EPSS returned HTTP {resp.status_code}")
        try:
            data = resp.json()
        except ValueError as exc:
            raise EpssError("EPSS returned invalid JSON") from exc
        rows = data.get("data") if isinstance(data, dict) else None
        if not isinstance(rows, list):
            raise EpssError("EPSS response has no 'data' list")
        for r in rows:
            cve = str((r or {}).get("cve") or "").upper()
            if cve in out:
                epss, pct = _float(r.get("epss")), _float(r.get("percentile"))
                if epss is not None:
                    out[cve] = {"epss": epss, "percentile": pct, "date": r.get("date")}
    return out
