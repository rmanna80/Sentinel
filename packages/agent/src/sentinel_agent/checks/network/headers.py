"""HTTP security headers of URLs the owner is authorized to test."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

import httpx
from pydantic import BaseModel, Field, field_validator
from sentinel_core.checks import Check, CheckContext, SkipCheck
from sentinel_core.models import CheckOutput, Platform, Severity

from ... import __version__
from ...safe_commands import CommandCancelled
from .._util import finding
from .scope import check_target

TIMEOUT = 10.0


class HeaderParams(BaseModel):
    urls: list[str] = Field(min_length=1, max_length=32)

    @field_validator("urls")
    @classmethod
    def _valid(cls, values: list[str]) -> list[str]:
        out = []
        for v in values:
            parts = urlsplit(v.strip())
            if parts.scheme not in ("http", "https") or not parts.hostname:
                raise ValueError(f"{v!r} is not an http(s) URL")
            if "@" in parts.netloc:  # any user info, even an empty one ("http://@host/")
                raise ValueError("URLs with credentials are not allowed")
            _ = parts.port  # raises ValueError for an invalid port
            check_target(parts.hostname)  # the agent's own limits, whatever the server sent
            out.append(v.strip())
        return out


@dataclass
class HttpResult:
    status: int | None = None
    headers: dict[str, str] = field(default_factory=dict)  # lower-case names
    error: str | None = None


def fetch_headers(url: str) -> HttpResult:
    """One GET without following redirects; the body is not downloaded. The only network I/O in this check."""
    try:
        ua = {"User-Agent": f"Sentinel-agent/{__version__} (security header check)"}
        with (httpx.Client(follow_redirects=False, timeout=TIMEOUT, verify=True, headers=ua) as client,
              client.stream("GET", url) as resp):
            return HttpResult(resp.status_code, {k.lower(): v for k, v in resp.headers.items()})
    except httpx.HTTPError as exc:
        return HttpResult(error=f"{type(exc).__name__}: {exc}"[:300])


def _csp_has_frame_ancestors(csp: str | None) -> bool:
    return bool(csp) and any(d.strip().lower().startswith("frame-ancestors") for d in csp.split(";"))  # type: ignore[union-attr]


class HttpHeaders(Check):
    id = "net.http_headers"
    version = "1"
    title = "Web pages send security headers"
    category = "network"
    platforms = frozenset({Platform.WINDOWS, Platform.LINUX})
    profiles = frozenset({"network"})
    timeout_seconds = 32 * TIMEOUT + 30
    data_collected = "For the URLs you entered: the HTTP status code and response headers (the page body is not read)"
    params_model = HeaderParams

    def run(self, ctx: CheckContext) -> CheckOutput:
        params = ctx.params
        assert isinstance(params, HeaderParams)
        urls = sorted(set(params.urls))
        results: dict[str, Any] = {}
        findings = []
        for url in urls:
            if ctx.cancelled():
                raise CommandCancelled("cancelled between URLs")
            r = fetch_headers(url)
            results[url] = {"status": r.status, "headers": r.headers, "error": r.error}
            if r.error is None:
                findings.extend(self._judge(url, r))
        failed = {u: v["error"] for u, v in results.items() if v["error"]}
        if failed:
            # Reporting the others alone would mark this URL's earlier findings as resolved.
            raise SkipCheck("Could not fetch " + "; ".join(f"{u} ({e[:150]})" for u, e in failed.items()))
        evidence = [ctx.evidence("command_output", "HTTP GET (no redirects followed)", {"urls": results})]
        return CheckOutput(evidence=evidence, findings=findings, reconcile_scope="headers:" + ",".join(urls))

    def _judge(self, url: str, r: HttpResult) -> list[Any]:
        h = r.headers
        https = url.lower().startswith("https://")
        redirect = r.status is not None and 300 <= r.status < 400
        location = h.get("location", "")
        out = []

        def missing(name: str, rule: str, why: str, fix: str, severity: Severity = Severity.LOW) -> None:
            out.append(finding(f"net.http_headers.{rule}", f"headers:{url}:{rule}", f"{url} does not send {name}",
                               severity, why, fix, category="network"))

        if not https:
            to_https = redirect and location.lower().startswith("https://")
            if not to_https:
                out.append(finding(
                    "net.http_headers.no_https_redirect", f"headers:{url}:https", f"{url} is served over plain HTTP",
                    Severity.MEDIUM,
                    "Anyone on the network path can read or change the page, including sign-in forms.",
                    "Serve the site over HTTPS and redirect every http:// request to https://.",
                    category="network",
                ))
            return out  # headers on a plain-HTTP response or redirect do not protect anyone
        if "strict-transport-security" not in h:
            missing("Strict-Transport-Security (HSTS)", "hsts",
                    "Browsers may still try plain HTTP first, which an attacker on the network can intercept.",
                    "Add `Strict-Transport-Security: max-age=31536000` once the whole site works over HTTPS.")
        if redirect:
            return out  # page-content headers matter on the page itself, not on a redirect
        csp = h.get("content-security-policy")
        if not csp:
            missing("Content-Security-Policy", "csp",
                    "Without a CSP, an injected script runs with the page's full rights.",
                    "Add a Content-Security-Policy that lists where scripts may load from (start with report-only).")
        if h.get("x-content-type-options", "").strip().lower() != "nosniff":
            missing("X-Content-Type-Options: nosniff", "nosniff",
                    "Browsers may guess a file's type and run an uploaded file as a script.",
                    "Add `X-Content-Type-Options: nosniff`.")
        if "x-frame-options" not in h and not _csp_has_frame_ancestors(csp):
            missing("X-Frame-Options or CSP frame-ancestors", "framing",
                    "Other sites can load this page in a hidden frame and trick users into clicking (clickjacking).",
                    "Add `X-Frame-Options: DENY` (or SAMEORIGIN), or `frame-ancestors 'self'` in the CSP.")
        if "referrer-policy" not in h:
            missing("Referrer-Policy", "referrer",
                    "Full page addresses, which can contain private details, may be sent to other sites.",
                    "Add `Referrer-Policy: strict-origin-when-cross-origin` (or stricter).")
        return out
