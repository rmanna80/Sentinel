"""The one way the server talks to the internet. Every request is logged for the Outbound data page."""

from __future__ import annotations

import logging
import time
from typing import Any
from urllib.parse import urlencode, urlsplit

import httpx

from .. import __version__
from ..config import get_settings
from ..db import session_scope
from ..models import OutboundRequest

log = logging.getLogger(__name__)

USER_AGENT = f"Sentinel-Security-Assistant/{__version__} (local-first; self-hosted)"
_SECRET_PARAM_NAMES = {"apikey", "api_key", "key", "token", "access_token"}

_transport: httpx.BaseTransport | None = None  # tests can install a mock transport


def set_transport(transport: httpx.BaseTransport | None) -> None:
    global _transport
    _transport = transport


class OutboundDisabled(Exception):
    pass


class OutboundError(Exception):
    def __init__(self, message: str, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code


def _loggable_path(url: str, params: dict[str, Any] | None) -> tuple[str, str]:
    parts = urlsplit(url)
    query = dict(params or {})
    clean = {k: ("[REDACTED]" if k.lower() in _SECRET_PARAM_NAMES else v) for k, v in query.items()}
    path = parts.path + (("?" + urlencode(clean, doseq=True)) if clean else "")
    return parts.hostname or "", path[:1024]


def _log(integration: str, method: str, host: str, path: str, purpose: str, payload_summary: str,
         status_code: int | None, duration_ms: int, error: str | None) -> None:
    try:
        with session_scope() as db:
            db.add(OutboundRequest(integration=integration, method=method, host=host, path=path, purpose=purpose[:300],
                                   payload_summary=payload_summary[:4000], status_code=status_code,
                                   duration_ms=duration_ms, error=error))
    except Exception:  # logging must never break the integration itself
        log.exception("could not record outbound request")


def request(
    integration: str,
    method: str,
    url: str,
    *,
    purpose: str,
    payload_summary: str,
    params: dict[str, Any] | None = None,
    headers: dict[str, str] | None = None,
    json: Any = None,
    timeout: float = 20.0,
    ok_statuses: tuple[int, ...] = (200,),
    log_path: str | None = None,
) -> httpx.Response:
    """Send one request. ``payload_summary`` says in plain words what leaves the machine.

    ``log_path`` replaces the recorded path when the real one contains personal data
    (for example an email address in a URL); the real value is then never written to the log.
    """
    settings = get_settings()
    if not settings.outbound_enabled:
        raise OutboundDisabled("Outbound connections are disabled in settings")
    if not url.startswith("https://") and not url.startswith("http://127.0.0.1"):
        raise OutboundError("integrations must use HTTPS")
    hdrs = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    hdrs.update(headers or {})
    host, path = _loggable_path(url, params)
    if log_path is not None:
        path = log_path[:1024]
    start = time.monotonic()
    status_code: int | None = None
    error: str | None = None
    try:
        with httpx.Client(timeout=timeout, transport=_transport, follow_redirects=False) as client:
            resp = client.request(method, url, params=params, headers=hdrs, json=json)
        status_code = resp.status_code
        if resp.status_code not in ok_statuses:
            error = f"HTTP {resp.status_code}"
        return resp
    except httpx.HTTPError as exc:
        error = f"{type(exc).__name__}: {exc}"[:500]
        raise OutboundError(f"{integration}: {error}") from exc
    finally:
        _log(integration, method, host, path, purpose, payload_summary, status_code,
             int((time.monotonic() - start) * 1000), error)
