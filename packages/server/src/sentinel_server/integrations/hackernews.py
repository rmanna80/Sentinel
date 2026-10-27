"""Hacker News threat-intelligence source.

Reads public Hacker News search results (the Algolia HN Search API: no account, no key, nothing about
this machine is sent) for security-related stories. Returned items are turned into advisories a person
reads; they never become executable code.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import UTC, datetime

from . import http

# One search per term; results are merged and de-duplicated by story id. Kept short to stay well within
# the API's fair-use limits and to keep the Outbound data log readable.
SECURITY_QUERIES = ("vulnerability", "CVE", "exploit", "zero-day", "ransomware", "data breach", "RCE")
SEARCH_URL = "https://hn.algolia.com/api/v1/search"
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
_KEYWORDS = (
    "vulnerability", "exploit", "zero-day", "0-day", "ransomware", "breach", "backdoor", "malware",
    "rce", "remote code execution", "privilege escalation", "sql injection", "xss", "ssrf", "supply chain",
    "phishing", "patch", "advisory", "cve", "spyware", "rootkit", "ddos",
)


@dataclass
class HnItem:
    object_id: str
    title: str
    url: str | None
    points: int
    author: str | None
    created_at: datetime
    cve_ids: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)


def _parse_created(hit: dict) -> datetime:
    ts = hit.get("created_at_i")
    if isinstance(ts, (int, float)):
        return datetime.fromtimestamp(ts, tz=UTC)
    raw = str(hit.get("created_at", ""))
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return datetime.now(UTC)


def _item(hit: dict) -> HnItem | None:
    object_id = str(hit.get("objectID") or "")
    title = (hit.get("title") or hit.get("story_title") or "").strip()
    if not object_id or not title:
        return None
    blob = f"{title} {hit.get('url') or ''} {hit.get('story_text') or ''}"
    cves = sorted({m.group(0).upper() for m in _CVE_RE.finditer(blob)})
    low = blob.lower()
    tags = [kw for kw in _KEYWORDS if kw in low]
    return HnItem(
        object_id=object_id,
        title=title[:500],
        url=(hit.get("url") or f"https://news.ycombinator.com/item?id={object_id}")[:1024],
        points=int(hit.get("points") or 0),
        author=(hit.get("author") or None),
        created_at=_parse_created(hit),
        cve_ids=cves,
        tags=tags,
    )


def fetch(min_points: int = 20, since: datetime | None = None, queries: tuple[str, ...] = SECURITY_QUERIES) -> list[HnItem]:
    """Fetch recent security stories. Raises ``http.OutboundDisabled`` / ``http.OutboundError`` on failure.

    Only public story metadata is read; the request carries nothing identifying this machine.
    """
    numeric = [f"points>={max(0, min_points)}"]
    if since is not None:
        numeric.append(f"created_at_i>{int(since.timestamp())}")
    params_base = {"tags": "story", "hitsPerPage": "40", "numericFilters": ",".join(numeric)}
    by_id: dict[str, HnItem] = {}
    for query in queries:
        resp = http.request(
            "hackernews", "GET", SEARCH_URL,
            purpose="Search Hacker News for security stories",
            payload_summary=f"public search term {query!r} (nothing about this machine is sent)",
            params={**params_base, "query": query}, timeout=15.0,
        )
        if resp.status_code != 200:
            continue
        for hit in resp.json().get("hits", []):
            item = _item(hit)
            if item is not None:
                by_id.setdefault(item.object_id, item)
    return sorted(by_id.values(), key=lambda i: i.created_at, reverse=True)
