"""Have I Been Pwned API v3: breaches for one email address and for a verified domain.

What this client relies on (checked against https://haveibeenpwned.com/API/v3 in October 2026):

* the key goes in the ``hibp-api-key`` header; a user agent is mandatory (403 without one), and
  ``integrations.http.request`` always sends Sentinel's own;
* ``truncateResponse=false`` returns the full breach model instead of breach names only;
* ``404`` means the address (or domain) is not in any loaded breach; ``429`` carries ``retry-after``
  (seconds, rounded up); a domain search answers ``403`` until the domain is verified;
* Core tiers have no k-anonymity search, so the full address is sent. Core 1 allows 10 requests per
  minute, so calls are spaced at least ``MIN_INTERVAL_SECONDS`` apart across the whole process.
"""

from __future__ import annotations

import logging
import math
import threading
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote

import httpx

from . import http

log = logging.getLogger(__name__)

INTEGRATION = "hibp"
BASE_URL = "https://haveibeenpwned.com/api/v3"
MIN_INTERVAL_SECONDS = 6.5  # 10 requests per minute on Core 1, with a margin
ACCOUNT_PAYLOAD = "full email address (Core tiers have no k-anonymity search)"
DOMAIN_PAYLOAD = "domain name"
ATTRIBUTION = ("Breach data: Have I Been Pwned (https://haveibeenpwned.com), "
               "licensed under Creative Commons Attribution 4.0.")

_lock = threading.Lock()
_last_start: float | None = None
_blocked_until = 0.0
# Indirections so tests can drive the spacing logic without waiting.
_clock = time.monotonic
_sleep = time.sleep


@dataclass
class HibpResult:
    """``status`` is one of found | not_found | not_verified | unavailable | error."""

    status: str
    data: Any = None
    error: str | None = None
    status_code: int | None = None
    retry_after: int | None = None
    sent: bool = True  # False when nothing left the machine (local back-off, outbound disabled)


class _LocallyRateLimited(Exception):
    def __init__(self, seconds: int) -> None:
        super().__init__(seconds)
        self.seconds = seconds


def reset() -> None:
    """Forget spacing and back-off state (tests)."""
    global _last_start, _blocked_until
    with _lock:
        _last_start = None
        _blocked_until = 0.0


def _retry_after(resp: httpx.Response) -> int | None:
    raw = resp.headers.get("retry-after")
    if raw is None:
        return None
    try:
        return max(0, math.ceil(float(raw.strip())))
    except ValueError:
        return None


def mask_email(email: str) -> str:
    local, _, domain = email.partition("@")
    return f"{local[:1]}***@{domain}"


def _call(url: str, *, api_key: str, purpose: str, payload_summary: str,
          params: dict[str, str] | None = None, log_path: str | None = None) -> httpx.Response:
    """One HIBP request, never closer than ``MIN_INTERVAL_SECONDS`` to the previous one."""
    global _last_start, _blocked_until
    with _lock:
        t = _clock()
        if t < _blocked_until:
            raise _LocallyRateLimited(math.ceil(_blocked_until - t))
        if _last_start is not None:
            wait = MIN_INTERVAL_SECONDS - (t - _last_start)
            if wait > 0:
                _sleep(wait)
        _last_start = _clock()
        resp = http.request(INTEGRATION, "GET", url, purpose=purpose, payload_summary=payload_summary,
                            params=params, headers={"hibp-api-key": api_key}, ok_statuses=(200, 404),
                            log_path=log_path)
        if resp.status_code == 429:
            seconds = _retry_after(resp)
            if seconds:
                _blocked_until = _clock() + seconds
        return resp


def _common_error(resp: httpx.Response) -> HibpResult:
    code = resp.status_code
    if code == 400:
        return HibpResult("error", error="HIBP rejected the request as malformed (HTTP 400)", status_code=code)
    if code == 401:
        return HibpResult("error", error="API key rejected", status_code=code)
    if code == 429:
        seconds = _retry_after(resp)
        when = f"retry after {seconds} seconds" if seconds is not None else "retry later"
        return HibpResult("error", error=f"Rate limited by HIBP; {when}", status_code=code, retry_after=seconds)
    if code == 503:
        return HibpResult("error", error="HIBP is temporarily unavailable (HTTP 503)", status_code=code)
    return HibpResult("error", error=f"Unexpected response from HIBP (HTTP {code})", status_code=code)


def _send(url: str, *, api_key: str, purpose: str, payload_summary: str,
          params: dict[str, str] | None = None, log_path: str | None = None) -> httpx.Response | HibpResult:
    try:
        return _call(url, api_key=api_key, purpose=purpose, payload_summary=payload_summary, params=params,
                     log_path=log_path)
    except _LocallyRateLimited as exc:
        return HibpResult("error", error=f"Rate limited by HIBP; retry after {exc.seconds} seconds",
                          status_code=429, retry_after=exc.seconds, sent=False)
    except http.OutboundDisabled as exc:
        return HibpResult("unavailable", error=str(exc), sent=False)
    except http.OutboundError as exc:
        return HibpResult("error", error=f"Could not reach HIBP: {exc}", status_code=exc.status_code)


def breached_account(email: str, api_key: str) -> HibpResult:
    """All breaches (full model) for one address. Unverified breaches are included (the API default)."""
    path = "/api/v3/breachedaccount/{}?truncateResponse=false"
    # The outbound log records the masked address only; the full one is never written to it.
    sent = _send(f"{BASE_URL}/breachedaccount/{quote(email, safe='')}", api_key=api_key,
                 purpose="Breach lookup for a monitored email address", payload_summary=ACCOUNT_PAYLOAD,
                 params={"truncateResponse": "false"},
                 log_path=path.format(quote(mask_email(email), safe="*@")))
    if isinstance(sent, HibpResult):
        return sent
    resp = sent
    if resp.status_code == 404:
        return HibpResult("not_found", data=[], status_code=404)
    if resp.status_code == 200:
        try:
            data = resp.json()
        except ValueError:
            return HibpResult("error", error="HIBP returned a response that is not JSON", status_code=200)
        if not isinstance(data, list) or not all(isinstance(b, dict) for b in data):
            return HibpResult("error", error="HIBP returned an unexpected response shape", status_code=200)
        return HibpResult("found" if data else "not_found", data=data, status_code=200)
    if resp.status_code == 403:
        return HibpResult("error", error="HIBP refused the request (HTTP 403)", status_code=403)
    return _common_error(resp)


def breached_domain(domain: str, api_key: str) -> HibpResult:
    """Aliases on a verified domain mapped to the breach names they appear in."""
    url = f"{BASE_URL}/breacheddomain/{quote(domain, safe='')}"
    sent = _send(url, api_key=api_key, purpose="Breach lookup for a verified domain", payload_summary=DOMAIN_PAYLOAD)
    if isinstance(sent, HibpResult):
        return sent
    resp = sent
    if resp.status_code == 404:
        return HibpResult("not_found", data={}, status_code=404)
    if resp.status_code == 403:
        return HibpResult("not_verified", error="Domain not verified for this API key (HTTP 403)", status_code=403)
    if resp.status_code == 200:
        try:
            data = resp.json()
        except ValueError:
            return HibpResult("error", error="HIBP returned a response that is not JSON", status_code=200)
        if not isinstance(data, dict):
            return HibpResult("error", error="HIBP returned an unexpected response shape", status_code=200)
        aliases = {str(k): [str(n) for n in v] for k, v in data.items() if isinstance(v, list)}
        return HibpResult("found" if aliases else "not_found", data=aliases, status_code=200)
    return _common_error(resp)
