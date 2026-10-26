"""Pwned Passwords range API (k-anonymity): only the first 5 hex characters of a SHA-1 hash leave.

The browser hashes the password and compares suffixes itself; this module only relays the prefix.
The API is free, needs no key and has no rate limit. ``Add-Padding: true`` pads every answer to
800-1,000 rows so its size reveals nothing; padded rows have a count of 0 and are discarded here.

The outbound log records that a range lookup happened but never the prefix: a stored prefix next
to a timestamp would narrow down which password was checked.
"""

from __future__ import annotations

import logging
import re

from . import http

log = logging.getLogger(__name__)

INTEGRATION = "pwned_passwords"
RANGE_URL = "https://api.pwnedpasswords.com/range/{prefix}"
PAYLOAD_SUMMARY = "first 5 characters of a SHA-1 hash"
LOGGED_PATH = "/range/[prefix not stored]"

_PREFIX_RE = re.compile(r"[0-9A-Fa-f]{5}")
_SUFFIX_RE = re.compile(r"[0-9A-F]{35}")


class InvalidPrefix(ValueError):
    pass


def normalize_prefix(prefix: str) -> str:
    if not isinstance(prefix, str) or not _PREFIX_RE.fullmatch(prefix):
        raise InvalidPrefix("prefix must be exactly 5 hexadecimal characters")
    return prefix.upper()


def parse_range(text: str) -> list[dict[str, str | int]]:
    """``SUFFIX:COUNT`` lines -> suffix/count pairs, without padding rows or malformed lines."""
    out: list[dict[str, str | int]] = []
    for line in text.splitlines():
        suffix, sep, count = line.strip().partition(":")
        if not sep:
            continue
        suffix = suffix.strip().upper()
        if not _SUFFIX_RE.fullmatch(suffix):
            continue
        try:
            n = int(count.strip())
        except ValueError:
            continue
        if n <= 0:  # padding
            continue
        out.append({"suffix": suffix, "count": n})
    return out


def range_query(prefix: str) -> list[dict[str, str | int]]:
    """Raises ``InvalidPrefix``, ``http.OutboundDisabled`` or ``http.OutboundError``."""
    p = normalize_prefix(prefix)
    resp = http.request(INTEGRATION, "GET", RANGE_URL.format(prefix=p),
                        purpose="Pwned Passwords range lookup (k-anonymity)", payload_summary=PAYLOAD_SUMMARY,
                        headers={"Add-Padding": "true", "Accept": "text/plain"}, log_path=LOGGED_PATH)
    if resp.status_code != 200:
        raise http.OutboundError(f"Pwned Passwords returned HTTP {resp.status_code}", resp.status_code)
    return parse_range(resp.text)
