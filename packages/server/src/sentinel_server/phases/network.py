"""Phase 5: network scope controls, scan previews and network scans run by an agent.

Nothing is scanned unless every target lies inside an enabled scope entry. Public addresses and
hostnames need a typed authorization sentence before they can enter the scope. The server never
resolves DNS: a hostname is in scope only if it is listed itself, and it is treated as public unless
it ends in a local-only suffix. The scan itself runs on the chosen device's agent.
"""

from __future__ import annotations

import ipaddress
import math
from datetime import datetime
from typing import Annotated, Any, Literal
from urllib.parse import urlsplit, urlunsplit

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from pydantic import BaseModel, ConfigDict, Field, StrictBool
from sentinel_core.commands import CommandParamError, validate_target
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import audit
from ..api.scans import queue_scan
from ..db import get_db
from ..deps import AuthContext, current_auth
from ..models import CheckRun, Device, EvidenceRecord, FindingRecord, Scan, ScopeEntry
from ..schemas import FindingOut, ScanOut
from ..services.findings import OPEN

router = APIRouter(prefix="/api/network", tags=["network"])

IPNet = ipaddress.IPv4Network | ipaddress.IPv6Network
IPAddr = ipaddress.IPv4Address | ipaddress.IPv6Address

LOCAL_SUFFIXES = (".local", ".lan", ".internal", ".home.arpa")
MIN_PREFIX = {4: 16, 6: 64}
MAX_TARGETS = 256
LARGE_RANGE = 256
SUMMARY_CHECKS = ("net.listening", "net.interfaces", "net.dns_config", "win.network_profile")

CHECK_IDS = {"discovery": "net.nmap_discovery", "tls": "net.tls_certificate", "headers": "net.http_headers"}
# The agent's own limits per scan (its params models reject anything larger); checked here first so the
# person gets a clear message instead of a skipped check.
AGENT_TARGET_LIMITS = {"discovery": 16, "tls": 32, "headers": 32}
NMAP_COMMAND = "nmap -sT -T3 --top-ports {n} -sV --version-light -oX - {target}"
ESTIMATE_NOTE = ("Rough estimate. Real duration depends on how many hosts answer, firewalls that drop packets "
                 "and the services found.")


def authorization_sentence(value: str) -> str:
    return f"I am authorized to test {value}"


# --------------------------------------------------------------------------- schemas


class ScopeCreate(BaseModel):
    kind: Literal["cidr", "host", "url"]
    value: str = Field(min_length=1, max_length=512)
    note: str | None = Field(default=None, max_length=300)
    confirm_public: str | None = Field(default=None, max_length=700)


class ScopeUpdate(BaseModel):
    enabled: bool | None = None
    note: str | None = Field(default=None, max_length=300)


class ScopeOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    kind: str
    value: str
    note: str | None
    is_public: bool
    authorization: str | None
    enabled: bool
    created_by: int | None
    created_at: datetime


class NetworkScanRequest(BaseModel):
    device_id: int
    kind: Literal["discovery", "tls", "headers"]
    targets: list[Annotated[str, Field(min_length=1, max_length=512)]] = Field(min_length=1, max_length=MAX_TARGETS)
    top_ports: int | None = Field(default=None, ge=10, le=1000)


class NetworkScanCreate(NetworkScanRequest):
    acknowledged: StrictBool = False  # JSON true only


class NetworkPreview(BaseModel):
    check_id: str
    params: dict[str, Any]
    commands: list[str]
    behavior: str
    warnings: list[str]
    estimated_seconds: int
    estimate_note: str


class EvidenceFact(BaseModel):
    kind: str
    source: str
    content: Any
    redacted: bool
    collected_at: datetime


class NetworkFact(BaseModel):
    check_id: str
    title: str
    status: str
    scan_id: int
    check_run_id: int
    finished_at: datetime | None
    evidence: list[EvidenceFact]


class NetworkSummary(BaseModel):
    device_id: int
    facts: dict[str, NetworkFact | None]
    findings: list[FindingOut]
    scans: list[ScanOut]


# --------------------------------------------------------------------------- parsing and scope logic


def _ip_is_public(obj: IPAddr | IPNet) -> bool:
    return not (obj.is_private or obj.is_loopback or obj.is_link_local)


def hostname_is_public(name: str) -> bool:
    n = name.rstrip(".").lower()
    if n == "localhost" or n.endswith(".localhost"):
        return False
    return not n.endswith(LOCAL_SUFFIXES)


def _host_is_public(host: str) -> bool:
    try:
        return _ip_is_public(ipaddress.ip_address(host))
    except ValueError:
        return hostname_is_public(host)


def parse_cidr(value: str) -> IPNet:
    try:
        net = ipaddress.ip_network(value.strip(), strict=False)
    except ValueError as exc:
        raise HTTPException(422, f"Not a valid CIDR range: {value!r}") from exc
    minimum = MIN_PREFIX[net.version]
    if net.prefixlen < minimum:
        raise HTTPException(422, f"Range too large: IPv{net.version} ranges must be /{minimum} or smaller "
                                 f"(prefix length {minimum} or longer)")
    return net


def parse_host(value: str) -> str:
    """An IP address or DNS hostname, normalized (no ranges)."""
    v = value.strip()
    if "/" in v:
        raise HTTPException(422, f"{value!r} is a range; add it as kind 'cidr'")
    try:
        return validate_target(v)
    except CommandParamError as exc:
        raise HTTPException(422, f"Not a valid IP address or hostname: {value!r}") from exc


def _url_host(host: str) -> str:
    return f"[{host}]" if ":" in host else host


def parse_url(value: str) -> tuple[str, str]:
    """Return (normalized URL, normalized host). Default ports and fragments are dropped."""
    v = value.strip()
    try:
        parts = urlsplit(v)
        port = parts.port
    except ValueError as exc:
        raise HTTPException(422, f"Not a valid URL: {value!r}") from exc
    scheme = parts.scheme.lower()
    if scheme not in ("http", "https") or not parts.hostname:
        raise HTTPException(422, f"URL must start with http:// or https:// and name a host: {value!r}")
    if parts.username is not None or parts.password is not None:
        raise HTTPException(422, "URLs with embedded credentials are not accepted")
    host = parse_host(parts.hostname)
    netloc = _url_host(host)
    if port is not None and port != {"http": 80, "https": 443}[scheme]:
        netloc += f":{port}"
    return urlunsplit((scheme, netloc, parts.path or "/", parts.query, "")), host


def parse_endpoint(value: str) -> tuple[str, str]:
    """``host:port`` (IPv6 as ``[addr]:port``; port defaults to 443) -> (normalized endpoint, host)."""
    v = value.strip()
    port_s: str | None = None
    if v.startswith("["):
        host_s, sep, rest = v[1:].partition("]")
        if not sep or (rest and not rest.startswith(":")):
            raise HTTPException(422, f"Not a valid host:port endpoint: {value!r}")
        port_s = rest[1:] if rest else None
    elif v.count(":") == 1:
        host_s, port_s = v.split(":")
    else:
        host_s = v  # a bare hostname, IPv4 or unbracketed IPv6 address
    host = parse_host(host_s)
    port = 443
    if port_s is not None:
        if not port_s.isdigit() or not 0 < int(port_s) <= 65535:
            raise HTTPException(422, f"Not a valid port in {value!r}")
        port = int(port_s)
    return f"{_url_host(host)}:{port}", host


def _normalize_scope_value(kind: str, value: str) -> tuple[str, bool]:
    if kind == "cidr":
        net = parse_cidr(value)
        return str(net), _ip_is_public(net)
    if kind == "host":
        host = parse_host(value)
        return host, _host_is_public(host)
    url, host = parse_url(value)
    return url, _host_is_public(host)


class Scope:
    """The enabled scope entries, pre-parsed for membership tests."""

    def __init__(self, entries: list[ScopeEntry]) -> None:
        self.nets: list[IPNet] = []
        self.host_ips: set[IPAddr] = set()
        self.hostnames: set[str] = set()
        self.urls: set[str] = set()
        for e in entries:
            try:
                if e.kind == "cidr":
                    self.nets.append(ipaddress.ip_network(e.value, strict=False))
                elif e.kind == "host":
                    try:
                        self.host_ips.add(ipaddress.ip_address(e.value))
                    except ValueError:
                        self.hostnames.add(e.value.rstrip(".").lower())
                elif e.kind == "url":
                    self.urls.add(parse_url(e.value)[0])
            except (ValueError, HTTPException):
                continue  # an entry that no longer parses grants nothing

    @classmethod
    def load(cls, db: Session) -> Scope:
        return cls(list(db.execute(select(ScopeEntry).where(ScopeEntry.enabled.is_(True))).scalars()))

    def has_host(self, host: str) -> bool:
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            return host.rstrip(".").lower() in self.hostnames
        return ip in self.host_ips or any(ip.version == n.version and ip in n for n in self.nets)

    def has_network(self, net: IPNet) -> bool:
        if net.num_addresses == 1 and net.network_address in self.host_ips:
            return True
        return any(net.version == n.version and net.subnet_of(n) for n in self.nets)  # type: ignore[arg-type]

    def has_url(self, url: str, host: str) -> bool:
        return url in self.urls or self.has_host(host)


class Plan:
    def __init__(self) -> None:
        self.values: list[str] = []
        self.out_of_scope: list[str] = []
        self.public: list[str] = []
        self.large_ranges: list[str] = []
        self.hostnames: list[str] = []
        self.addresses = 0


def plan_targets(kind: str, targets: list[str], scope: Scope) -> Plan:
    plan = Plan()
    for raw in targets:
        if kind == "discovery":
            v = raw.strip()
            if "/" in v:
                net = parse_cidr(v)
                value, in_scope, public = str(net), scope.has_network(net), _ip_is_public(net)
                count = net.num_addresses
                if count > LARGE_RANGE:
                    plan.large_ranges.append(f"{value} ({count} addresses)")
                version = net.version
            else:
                value = parse_host(v)
                in_scope, public, count = scope.has_host(value), _host_is_public(value), 1
                try:
                    version = ipaddress.ip_address(value).version
                except ValueError:
                    version = 4
                    plan.hostnames.append(value)
            if version == 6:
                raise HTTPException(422, f"IPv6 targets are not supported by network discovery: {value}")
            plan.addresses += count
        elif kind == "tls":
            value, host = parse_endpoint(raw)
            in_scope, public = scope.has_host(host), _host_is_public(host)
            if not _is_ip(host):
                plan.hostnames.append(host)
        else:
            value, host = parse_url(raw)
            in_scope, public = scope.has_url(value, host), _host_is_public(host)
            if not _is_ip(host):
                plan.hostnames.append(host)
        if value in plan.values:
            continue
        plan.values.append(value)
        if not in_scope:
            plan.out_of_scope.append(value)
        if public:
            plan.public.append(value)
    return plan


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _device(db: Session, device_id: int) -> Device:
    device = db.get(Device, device_id)
    if device is None or not device.is_active:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No such device")
    return device


def build_preview(db: Session, body: NetworkScanRequest) -> tuple[Device, NetworkPreview, Plan]:
    device = _device(db, body.device_id)
    plan = plan_targets(body.kind, body.targets, Scope.load(db))
    if plan.out_of_scope:
        raise HTTPException(422, "Outside the enabled scope: " + ", ".join(plan.out_of_scope)
                                 + ". Add them on the Scope page first.")
    check_id = CHECK_IDS[body.kind]
    limit = AGENT_TARGET_LIMITS[body.kind]
    if len(plan.values) > limit:
        raise HTTPException(422, f"At most {limit} targets per {body.kind} scan; split the list into several scans. "
                                 "A CIDR range counts as one target.")
    warnings: list[str] = []
    commands: list[str] = []
    n = len(plan.values)
    if body.kind == "discovery":
        top = body.top_ports or 100
        params: dict[str, Any] = {"targets": plan.values, "top_ports": top}
        commands = [NMAP_COMMAND.format(n=top, target=t) for t in plan.values]
        behavior = (f"TCP connect scan of the {top} most common ports with light version detection. It completes "
                    "TCP handshakes that the target can log, sends no exploits, runs no NSE scripts, does no OS "
                    "fingerprinting, and is not stealthy.")
        estimate = 10 + math.ceil(plan.addresses / 32) * (5 + math.ceil(top / 20))
    elif body.kind == "tls":
        params = {"endpoints": plan.values}
        behavior = ("Opens a TCP connection to each endpoint, completes a TLS handshake and records the certificate "
                    "the server presents. It sends no exploits or vulnerability probes; the target can log the "
                    "connection.")
        estimate = 3 + 5 * n
    else:
        params = {"urls": plan.values}
        behavior = ("Requests each URL and records the HTTP response status and headers. It submits no forms, sends "
                    "no exploit payloads and does not crawl; the target can log the request.")
        estimate = 3 + 5 * n
    if plan.public:
        warnings.append("Public targets: " + ", ".join(plan.public) + ". Scanning systems you are not authorized to "
                        "test may be illegal; their owners and network providers can see these connections.")
    if plan.large_ranges:
        warnings.append("Large ranges (more than 256 addresses): " + ", ".join(plan.large_ranges)
                        + ". The scan will take longer and generate more traffic.")
    if plan.hostnames:
        warnings.append("Hostnames are resolved by the device's agent at scan time, not by the server: "
                        + ", ".join(sorted(set(plan.hostnames)))
                        + ". Make sure they resolve to systems you are authorized to test.")
    warnings.append(f"The agent on {device.name} performs the scan from its own network position: results show what "
                    "that device can reach, and targets see connections from that device's address.")
    catalog = {c.get("id") for c in device.checks_catalog or []}
    if catalog and check_id not in catalog:
        warnings.append(f"This device's agent does not report the check {check_id}; the scan cannot start until it does.")
    preview = NetworkPreview(check_id=check_id, params=params, commands=commands, behavior=behavior,
                             warnings=warnings, estimated_seconds=estimate, estimate_note=ESTIMATE_NOTE)
    return device, preview, plan


# --------------------------------------------------------------------------- scope routes


def _scope_entry(db: Session, entry_id: int) -> ScopeEntry:
    entry = db.get(ScopeEntry, entry_id)
    if entry is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No such scope entry")
    return entry


@router.get("/scope", response_model=list[ScopeOut])
def list_scope(auth: AuthContext = Depends(current_auth), db: Session = Depends(get_db)) -> list[ScopeEntry]:
    return list(db.execute(select(ScopeEntry).order_by(ScopeEntry.created_at, ScopeEntry.id)).scalars())


@router.post("/scope", response_model=ScopeOut, status_code=201)
def add_scope(body: ScopeCreate, auth: AuthContext = Depends(current_auth), db: Session = Depends(get_db)) -> ScopeEntry:
    value, public = _normalize_scope_value(body.kind, body.value)
    authorization: str | None = None
    if public:
        accepted = {authorization_sentence(value), authorization_sentence(body.value.strip())}
        typed = body.confirm_public or ""
        if typed not in accepted:
            raise HTTPException(422, f"{value} is a public target. To add it, type exactly: "
                                     f"\"{authorization_sentence(value)}\"")
        authorization = typed
    if db.execute(select(ScopeEntry.id).where(ScopeEntry.value == value)).first() is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, f"{value} is already in the scope")
    note = body.note.strip() if body.note and body.note.strip() else None
    entry = ScopeEntry(kind=body.kind, value=value, note=note, is_public=public, authorization=authorization,
                       enabled=True, created_by=auth.user.id)
    db.add(entry)
    db.flush()
    audit.record(db, auth.actor, "network.scope_added", "scope", entry.id,
                 {"kind": entry.kind, "value": value, "is_public": public, "authorization": authorization})
    db.commit()
    return entry


@router.patch("/scope/{entry_id}", response_model=ScopeOut)
def update_scope(entry_id: int, body: ScopeUpdate, auth: AuthContext = Depends(current_auth),
                 db: Session = Depends(get_db)) -> ScopeEntry:
    entry = _scope_entry(db, entry_id)
    changes: dict[str, Any] = {}
    if body.enabled is not None and body.enabled != entry.enabled:
        changes["enabled"] = {"from": entry.enabled, "to": body.enabled}
        entry.enabled = body.enabled
    if "note" in body.model_fields_set:
        note = body.note.strip() if body.note and body.note.strip() else None
        if note != entry.note:
            changes["note"] = True
            entry.note = note
    if changes:
        audit.record(db, auth.actor, "network.scope_updated", "scope", entry.id, {"value": entry.value, **changes})
    db.commit()
    return entry


@router.delete("/scope/{entry_id}", status_code=204)
def delete_scope(entry_id: int, auth: AuthContext = Depends(current_auth), db: Session = Depends(get_db)) -> Response:
    entry = _scope_entry(db, entry_id)
    detail = {"kind": entry.kind, "value": entry.value, "is_public": entry.is_public}
    db.delete(entry)
    audit.record(db, auth.actor, "network.scope_deleted", "scope", entry_id, detail)
    db.commit()
    return Response(status_code=204)


# --------------------------------------------------------------------------- preview and scans


@router.post("/preview", response_model=NetworkPreview)
def preview_scan(body: NetworkScanRequest, auth: AuthContext = Depends(current_auth),
                 db: Session = Depends(get_db)) -> NetworkPreview:
    return build_preview(db, body)[1]


@router.post("/scans", response_model=ScanOut, status_code=201)
def create_network_scan(body: NetworkScanCreate, auth: AuthContext = Depends(current_auth),
                        db: Session = Depends(get_db)) -> Scan:
    if body.acknowledged is not True:
        raise HTTPException(422, "Review the preview and acknowledge what the scan will do before starting it")
    device, preview, plan = build_preview(db, body)
    catalog = {c.get("id") for c in device.checks_catalog or []}
    if catalog and preview.check_id not in catalog:
        raise HTTPException(422, f"This device's agent does not offer {preview.check_id}; update the agent or install "
                                 "the tool the check needs, then try again")
    scan = queue_scan(db, device=device, scan_type="network", actor=auth.actor, user_id=auth.user.id,
                      check_ids=[preview.check_id], params={preview.check_id: preview.params}, reason="network")
    audit.record(db, auth.actor, "network.scan_requested", "scan", scan.id,
                 {"device_id": device.id, "check_id": preview.check_id, "kind": body.kind, "targets": plan.values,
                  "public_targets": plan.public, "acknowledged": True})
    db.commit()
    return scan


# --------------------------------------------------------------------------- summary


def _latest_fact(db: Session, device_id: int, check_id: str) -> NetworkFact | None:
    run = db.execute(
        select(CheckRun).join(Scan, Scan.id == CheckRun.scan_id)
        .where(Scan.device_id == device_id, CheckRun.check_id == check_id, CheckRun.status.in_(("passed", "failed")))
        .order_by(CheckRun.finished_at.desc().nulls_last(), CheckRun.id.desc()).limit(1)
    ).scalar_one_or_none()
    if run is None:
        return None
    evidence = db.execute(select(EvidenceRecord).where(EvidenceRecord.check_run_id == run.id)
                          .order_by(EvidenceRecord.position, EvidenceRecord.id)).scalars()
    return NetworkFact(check_id=check_id, title=run.title, status=run.status, scan_id=run.scan_id, check_run_id=run.id,
                       finished_at=run.finished_at,
                       evidence=[EvidenceFact(kind=e.kind, source=e.source, content=e.content, redacted=e.redacted,
                                              collected_at=e.collected_at) for e in evidence])


@router.get("/summary", response_model=NetworkSummary)
def network_summary(device_id: int = Query(...), auth: AuthContext = Depends(current_auth),
                    db: Session = Depends(get_db)) -> NetworkSummary:
    device = db.get(Device, device_id)
    if device is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No such device")
    findings = db.execute(select(FindingRecord).where(FindingRecord.device_id == device.id,
                                                      FindingRecord.category == "network",
                                                      FindingRecord.status.in_(OPEN))
                          .order_by(FindingRecord.id)).scalars()
    scans = db.execute(select(Scan).where(Scan.device_id == device.id, Scan.scan_type == "network")
                       .order_by(Scan.requested_at.desc(), Scan.id.desc()).limit(10)).scalars()
    return NetworkSummary(device_id=device.id, facts={c: _latest_fact(db, device.id, c) for c in SUMMARY_CHECKS},
                          findings=[FindingOut.model_validate(f) for f in findings],
                          scans=[ScanOut.model_validate(s) for s in scans])
