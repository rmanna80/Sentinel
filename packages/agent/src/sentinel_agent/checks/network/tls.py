"""TLS certificate and protocol of endpoints the owner is authorized to test.

Uses only Python's ssl module. A connection is first made with full verification; if verification fails the
certificate is read again over an unverified connection, only so its dates and names can be reported.
"""

from __future__ import annotations

import socket
import ssl
import warnings
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, Field, field_validator
from sentinel_core.checks import Check, CheckContext, SkipCheck
from sentinel_core.commands import CommandParamError, validate_target
from sentinel_core.models import CheckOutput, Platform, Severity, utcnow

from ...safe_commands import CommandCancelled
from .._util import finding
from .scope import check_target

TIMEOUT = 10.0
LEGACY_PROTOCOLS = ("TLSv1", "TLSv1.1", "SSLv3")


def split_endpoint(value: str) -> tuple[str, int]:
    """"host", "host:port" or "[v6]:port" (port defaults to 443) -> (validated host, port)."""
    v = value.strip()
    port = 443
    if v.startswith("["):
        host, _, rest = v[1:].partition("]")
        if rest:
            if not rest.startswith(":") or not rest[1:].isdigit():
                raise ValueError(f"invalid endpoint {value!r}")
            port = int(rest[1:])
    elif v.count(":") == 1:
        host, port_s = v.split(":")
        if not port_s.isdigit():
            raise ValueError(f"invalid port in {value!r}")
        port = int(port_s)
    else:
        host = v
    if not 0 < port <= 65535:
        raise ValueError(f"port out of range in {value!r}")
    if "/" in host:
        raise ValueError("ranges are not allowed here; give one host per endpoint")
    try:
        host = validate_target(host)
    except CommandParamError as exc:
        raise ValueError(f"{value!r}: {exc}") from exc
    return check_target(host), port


def endpoint_label(host: str, port: int) -> str:
    return f"[{host}]:{port}" if ":" in host else f"{host}:{port}"


class TlsParams(BaseModel):
    endpoints: list[str] = Field(min_length=1, max_length=32)

    @field_validator("endpoints")
    @classmethod
    def _valid(cls, values: list[str]) -> list[str]:
        return [endpoint_label(*split_endpoint(v)) for v in values]


# --------------------------------------------------------------------------- minimal X.509 (DER) reader

_NAME_OIDS = {"2.5.4.3": "CN", "2.5.4.10": "O", "2.5.4.11": "OU", "2.5.4.6": "C", "2.5.4.8": "ST", "2.5.4.7": "L"}


def _tlv(data: bytes, i: int) -> tuple[int, int, int]:
    """(tag, content start, content end) of the DER element at ``i``."""
    tag = data[i]
    length = data[i + 1]
    j = i + 2
    if length & 0x80:
        n = length & 0x7F
        length = int.from_bytes(data[j:j + n], "big")
        j += n
    if j + length > len(data):
        raise ValueError("truncated DER")
    return tag, j, j + length


def _children(data: bytes, start: int, end: int) -> list[tuple[int, int, int]]:
    out, i = [], start
    while i < end:
        tag, s, e = _tlv(data, i)
        out.append((tag, s, e))
        i = e
    return out


def _oid(raw: bytes) -> str:
    parts = [raw[0] // 40, raw[0] % 40]
    value = 0
    for b in raw[1:]:
        value = (value << 7) | (b & 0x7F)
        if not b & 0x80:
            parts.append(value)
            value = 0
    return ".".join(str(p) for p in parts)


def _time(tag: int, raw: bytes) -> datetime:
    text = raw.decode("ascii").rstrip("Z")
    if tag == 0x17:  # UTCTime YYMMDDHHMMSS
        year = int(text[:2])
        text = f"{1900 + year if year >= 50 else 2000 + year}{text[2:]}"
    return datetime.strptime(text[:14], "%Y%m%d%H%M%S").replace(tzinfo=UTC)


def _name(data: bytes, start: int, end: int) -> str:
    parts = []
    for _, s, e in _children(data, start, end):  # SET of AttributeTypeAndValue
        for _, s2, e2 in _children(data, s, e):
            (_, os_, oe), (_, vs, ve) = _children(data, s2, e2)[:2]
            key = _NAME_OIDS.get(_oid(data[os_:oe]))
            if key:
                parts.append(f"{key}={data[vs:ve].decode('utf-8', errors='replace')}")
    return ", ".join(parts)


def parse_certificate(der: bytes) -> dict[str, Any]:
    """not_before, not_after, subject, issuer and whether issuer == subject, from a DER certificate."""
    _, s, e = _tlv(der, 0)
    _, ts, te = _children(der, s, e)[0]
    fields = _children(der, ts, te)
    if fields[0][0] == 0xA0:  # explicit [0] version
        fields = fields[1:]
    _serial, _sig, issuer, validity, subject = fields[:5]
    nb, na = _children(der, validity[1], validity[2])[:2]
    return {
        "not_before": _time(nb[0], der[nb[1]:nb[2]]),
        "not_after": _time(na[0], der[na[1]:na[2]]),
        "issuer": _name(der, issuer[1], issuer[2]),
        "subject": _name(der, subject[1], subject[2]),
        "self_issued": der[issuer[1]:issuer[2]] == der[subject[1]:subject[2]],
    }


# --------------------------------------------------------------------------- network I/O (patched in tests)


@dataclass
class TlsProbe:
    verified: bool
    verify_error: str | None = None
    verify_code: int | None = None
    protocol: str | None = None
    cipher: str | None = None
    certificate: dict[str, Any] = field(default_factory=dict)
    error: str | None = None


def _handshake(host: str, port: int, context: ssl.SSLContext) -> tuple[bytes, str | None, str | None]:
    # Python sends no SNI for IP addresses but still needs server_hostname to match the certificate.
    with (socket.create_connection((host, port), timeout=TIMEOUT) as sock,
          context.wrap_socket(sock, server_hostname=host) as tls):
        der = tls.getpeercert(binary_form=True) or b""
        cipher = tls.cipher()
        return der, tls.version(), cipher[0] if cipher else None


def _legacy_allowed(context: ssl.SSLContext) -> ssl.SSLContext:
    """Also accept TLS 1.0/1.1 and weak ciphers, so an old server can be identified and reported."""
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)  # TLSv1 is deprecated; that is why we look for it
            context.minimum_version = ssl.TLSVersion.TLSv1
        context.set_ciphers("DEFAULT:@SECLEVEL=0")
    except (ValueError, ssl.SSLError):
        pass
    return context


def probe_tls(host: str, port: int) -> TlsProbe:
    """Connect, verify, and read the certificate. The only network I/O in this check."""
    reason: str | None = None
    code: int | None = None
    # 1) normal verification; 2) verification again with legacy protocols allowed (an old server is reported as
    # such, not as a certificate problem); 3) if the certificate does not verify, read it without verification.
    for context in (ssl.create_default_context(), _legacy_allowed(ssl.create_default_context())):
        try:
            der, proto, cipher = _handshake(host, port, context)
            return TlsProbe(True, protocol=proto, cipher=cipher, certificate=parse_certificate(der))
        except ssl.SSLCertVerificationError as exc:
            reason, code = exc.verify_message or str(exc), exc.verify_code
            break
        except ssl.SSLError as exc:
            reason = f"handshake failed: {exc.reason or exc}"
        except (OSError, ValueError) as exc:
            return TlsProbe(False, error=f"could not connect: {exc}")
    if code is None:
        return TlsProbe(False, error=f"TLS {reason or 'handshake failed'}")
    unverified = _legacy_allowed(ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT))
    unverified.check_hostname = False
    unverified.verify_mode = ssl.CERT_NONE
    try:
        der, proto, cipher = _handshake(host, port, unverified)
    except (OSError, ssl.SSLError, ValueError) as exc:
        return TlsProbe(False, verify_error=reason, verify_code=code, error=f"TLS handshake failed: {exc}")
    cert = parse_certificate(der) if der else {}
    return TlsProbe(False, verify_error=reason, verify_code=code, protocol=proto, cipher=cipher, certificate=cert)


# --------------------------------------------------------------------------- check

SELF_SIGNED_CODES = (18, 19)  # X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT, X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN
EXPIRED_CODE = 10  # X509_V_ERR_CERT_HAS_EXPIRED


class TlsCertificate(Check):
    id = "net.tls_certificate"
    version = "1"
    title = "TLS certificates are valid and not expiring"
    category = "network"
    platforms = frozenset({Platform.WINDOWS, Platform.LINUX})
    profiles = frozenset({"network"})
    timeout_seconds = 32 * 2 * TIMEOUT + 30
    data_collected = (
        "For the endpoints you entered: the TLS version and cipher negotiated, and the certificate's subject, "
        "issuer and validity dates"
    )
    params_model = TlsParams

    def run(self, ctx: CheckContext) -> CheckOutput:
        params = ctx.params
        assert isinstance(params, TlsParams)
        endpoints = sorted(set(params.endpoints))
        now = utcnow()
        results: dict[str, dict[str, Any]] = {}
        findings = []
        for ep in endpoints:
            if ctx.cancelled():
                raise CommandCancelled("cancelled between endpoints")
            host, port = split_endpoint(ep)
            probe = probe_tls(host, port)
            cert = probe.certificate
            days_left = (cert["not_after"] - now).total_seconds() / 86400 if cert.get("not_after") else None
            results[ep] = {
                "verified": probe.verified, "verify_error": probe.verify_error, "protocol": probe.protocol,
                "cipher": probe.cipher, "error": probe.error,
                "subject": cert.get("subject"), "issuer": cert.get("issuer"),
                "not_before": cert["not_before"].isoformat() if cert.get("not_before") else None,
                "not_after": cert["not_after"].isoformat() if cert.get("not_after") else None,
                "days_left": round(days_left, 1) if days_left is not None else None,
            }
            if probe.error and not cert:
                continue
            findings.extend(self._judge(ep, probe, cert, days_left))
        failed = {ep: r["error"] for ep, r in results.items() if r["error"] and not r["not_after"]}
        if failed:
            # Reporting the others alone would mark this endpoint's earlier findings as resolved.
            raise SkipCheck("Could not read a certificate from " + "; ".join(f"{ep} ({e[:120]})"
                                                                            for ep, e in failed.items()))
        evidence = [ctx.evidence("command_output", "TLS handshake (Python ssl)", {"endpoints": results})]
        return CheckOutput(evidence=evidence, findings=findings, reconcile_scope="tls:" + ",".join(endpoints))

    def _judge(self, ep: str, probe: TlsProbe, cert: dict[str, Any], days_left: float | None) -> list[Any]:
        out = []
        expired = days_left is not None and days_left < 0
        self_signed = probe.verify_code in SELF_SIGNED_CODES or (bool(cert.get("self_issued")) and not probe.verified)
        if expired:
            out.append(finding(
                "net.tls_certificate.expired", f"tls:{ep}:expiry", f"Certificate for {ep} has expired",
                Severity.CRITICAL,
                f"The certificate expired on {cert['not_after'].date().isoformat()}. Browsers and apps refuse the "
                "connection or show a warning that trains users to click through.",
                "Renew the certificate now (for Let's Encrypt, check that automatic renewal is running).",
                category="network",
            ))
        elif days_left is not None and days_left < 30:
            out.append(finding(
                "net.tls_certificate.expiring", f"tls:{ep}:expiry",
                f"Certificate for {ep} expires in {int(days_left)} days",
                Severity.HIGH if days_left < 14 else Severity.MEDIUM,
                f"The certificate expires on {cert['not_after'].date().isoformat()}; after that, connections fail.",
                "Renew it before it expires and make sure automatic renewal works.",
                category="network",
            ))
        if self_signed and not expired:
            out.append(finding(
                "net.tls_certificate.self_signed", f"tls:{ep}:trust", f"{ep} uses a self-signed certificate",
                Severity.MEDIUM,
                "Clients cannot tell this certificate apart from one an attacker made, so users must click "
                "through warnings, and a man-in-the-middle would look the same.",
                "Use a certificate from a public CA (for example Let's Encrypt), or for home-lab devices a private "
                "CA whose root you install on your own devices.",
                category="network",
            ))
        elif probe.verify_error and not expired and probe.verify_code != EXPIRED_CODE:
            out.append(finding(
                "net.tls_certificate.invalid", f"tls:{ep}:trust",
                f"Certificate does not validate: {probe.verify_error}"[:300],
                Severity.HIGH,
                f"Clients connecting to {ep} see a certificate error, so they cannot be sure who they are talking to.",
                "Fix the cause shown (wrong host name, missing intermediate certificate, or untrusted issuer) and "
                "re-run this check.",
                category="network",
            ))
        if probe.protocol in LEGACY_PROTOCOLS:
            out.append(finding(
                "net.tls_certificate.legacy_protocol", f"tls:{ep}:protocol",
                f"{ep} negotiated {probe.protocol}",
                Severity.HIGH,
                "TLS 1.0 and 1.1 have known weaknesses and are disabled in current browsers.",
                "Enable TLS 1.2 and 1.3 on the server and disable older versions.",
                category="network",
            ))
        return out
