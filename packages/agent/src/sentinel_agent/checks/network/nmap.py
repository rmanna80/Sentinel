"""Nmap TCP-connect discovery of hosts the owner is authorized to scan."""

from __future__ import annotations

from typing import Any

from defusedxml import ElementTree
from pydantic import BaseModel, Field, field_validator
from sentinel_core.checks import Check, CheckContext, SkipCheck
from sentinel_core.commands import CommandParamError, CommandSpec, ParamKind, validate_target
from sentinel_core.models import CheckOutput, Confidence, FindingKind, Platform, Severity

from ...safe_commands import CommandCancelled, CommandFailed, CommandNotFound
from .._util import finding
from .scope import check_target

NMAP_MISSING = "Nmap is not installed. Install it from nmap.org (Windows) or your package manager (Linux)."

# TCP connect scan only (-sT): no raw packets, no OS detection (-O), no scripts (-sC/--script).
NMAP_SCAN = CommandSpec(
    "nmap.discovery", "nmap",
    ("-sT", "-T3", "--top-ports", "{top}", "-sV", "--version-light", "-oX", "-", "{target}"),
    params={"top": ParamKind.INT, "target": ParamKind.TARGET},
    timeout=900,
)


class NmapParams(BaseModel):
    targets: list[str] = Field(min_length=1, max_length=16)
    top_ports: int = Field(default=100, ge=10, le=1000)

    @field_validator("targets")
    @classmethod
    def _valid(cls, values: list[str]) -> list[str]:
        out = []
        for v in values:
            try:
                target = validate_target(v)
            except CommandParamError as exc:
                raise ValueError(f"{v!r}: {exc}") from exc
            out.append(check_target(target))  # the agent's own limits, whatever the server sent
        return out


HIGH_SERVICES = {"telnet": "Telnet", "ftp": "FTP", "vnc": "VNC"}
MEDIUM_SERVICES = {
    "microsoft-ds": "SMB file sharing", "netbios-ssn": "NetBIOS/SMB", "smb": "SMB file sharing",
    "ms-wbt-server": "Remote Desktop", "rdp": "Remote Desktop", "wsman": "WinRM", "wsmans": "WinRM",
    "winrm": "WinRM", "mysql": "MySQL", "postgresql": "PostgreSQL", "redis": "Redis", "mongodb": "MongoDB",
    "mongod": "MongoDB", "elasticsearch": "Elasticsearch",
}
MEDIUM_PORTS = {445: "SMB file sharing", 139: "NetBIOS/SMB", 3389: "Remote Desktop", 5985: "WinRM", 5986: "WinRM",
                3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis", 27017: "MongoDB", 9200: "Elasticsearch"}
HIGH_PORTS = {23: "Telnet", 21: "FTP", 5900: "VNC"}


def parse_nmap_xml(xml: str) -> list[dict[str, Any]]:
    root = ElementTree.fromstring(xml)
    hosts = []
    for h in root.findall("host"):
        status = h.find("status")
        addrs = {a.get("addrtype"): a.get("addr") for a in h.findall("address")}
        names = [n.get("name") for n in h.findall("hostnames/hostname") if n.get("name")]
        ports = []
        for p in h.findall("ports/port"):
            state = p.find("state")
            svc = p.find("service")
            ports.append({
                "protocol": p.get("protocol"), "port": int(p.get("portid") or 0),
                "state": state.get("state") if state is not None else None,
                "service": svc.get("name") if svc is not None else None,
                "product": svc.get("product") if svc is not None else None,
                "version": svc.get("version") if svc is not None else None,
                "tunnel": svc.get("tunnel") if svc is not None else None,
            })
        hosts.append({
            "address": addrs.get("ipv4") or addrs.get("ipv6"), "mac": addrs.get("mac"),
            "vendor": next((a.get("vendor") for a in h.findall("address") if a.get("vendor")), None),
            "hostnames": names, "state": status.get("state") if status is not None else None, "ports": ports,
        })
    return hosts


GENERIC_NAMES = {"", "unknown", "http", "https", "ssl", "tcpwrapped"}
PRODUCT_HINTS = {"elasticsearch": "Elasticsearch", "redis": "Redis", "mongodb": "MongoDB", "mysql": "MySQL",
                 "mariadb": "MySQL", "postgresql": "PostgreSQL", "vnc": "VNC"}


def classify(port: dict[str, Any], https_on_host: bool) -> tuple[Severity, str, str]:
    """(severity, label, why)."""
    name = (port.get("service") or "").lower()
    product = (port.get("product") or "").lower()
    num = port["port"]
    tls = port.get("tunnel") == "ssl" or name in ("https", "ssl/http")
    hint = next((label for key, label in PRODUCT_HINTS.items() if key in product), None)
    if name in HIGH_SERVICES or (num in HIGH_PORTS and name in GENERIC_NAMES) or hint == "VNC":
        label = HIGH_SERVICES.get(name) or HIGH_PORTS.get(num) or "VNC"
        return Severity.HIGH, label, "sends credentials without encryption or gives remote control"
    if name in MEDIUM_SERVICES or (num in MEDIUM_PORTS and name in GENERIC_NAMES) or hint:
        label = MEDIUM_SERVICES.get(name) or MEDIUM_PORTS.get(num) or hint or name
        return Severity.MEDIUM, label, "is a sharing, remote-administration or database service attackers look for"
    if name.startswith("http") and not tls and not https_on_host:
        return Severity.LOW, "plain HTTP", "serves web pages without encryption and the host offers no HTTPS"
    return Severity.INFO, name or "unknown service", "is reachable from the network"


class NmapDiscovery(Check):
    id = "net.nmap_discovery"
    version = "1"
    title = "Network discovery (Nmap)"
    category = "network"
    platforms = frozenset({Platform.WINDOWS, Platform.LINUX})
    profiles = frozenset({"network"})
    timeout_seconds = 1800.0
    data_collected = (
        "For the targets you entered: which hosts answered, their open TCP ports, and the service name, product "
        "and version Nmap identified on each port"
    )
    commands = (NMAP_SCAN,)
    params_model = NmapParams

    def run(self, ctx: CheckContext) -> CheckOutput:
        params = ctx.params
        assert isinstance(params, NmapParams)
        targets = sorted(set(params.targets))
        results: dict[str, Any] = {}
        hosts: list[dict[str, Any]] = []
        for target in targets:
            if ctx.cancelled():
                raise CommandCancelled("cancelled between targets")
            try:
                result = ctx.run(NMAP_SCAN, top=params.top_ports, target=target)
            except CommandNotFound as exc:
                raise SkipCheck(NMAP_MISSING) from exc
            except CommandCancelled:
                raise
            except CommandFailed as exc:
                results[target] = {"error": str(exc)[:300]}
                continue
            try:
                found = parse_nmap_xml(result.stdout)
            except ElementTree.ParseError as exc:
                results[target] = {"error": f"Nmap output was not valid XML: {exc}"}
                continue
            results[target] = {"hosts_up": sum(1 for h in found if h["state"] == "up"),
                               "warnings": result.stderr.strip()[:300] or None}
            hosts.extend(found)
        failed = {t: r["error"] for t, r in results.items() if "error" in r}
        if failed:
            # Reporting the other targets alone would mark this target's earlier findings as resolved.
            raise SkipCheck("Nmap failed for " + "; ".join(f"{t}: {e[:120]}" for t, e in failed.items()))
        evidence = [ctx.evidence("command_output", f"nmap -sT -T3 --top-ports {params.top_ports} -sV --version-light", {
            "targets": targets, "per_target": results, "hosts": [h for h in hosts if h["state"] == "up"],
        })]
        findings = []
        seen: set[str] = set()
        for h in hosts:
            if h["state"] != "up" or not h["address"]:
                continue
            open_ports = [p for p in h["ports"] if p["state"] == "open"]
            https = any(p.get("tunnel") == "ssl" or (p.get("service") or "") == "https" for p in open_ports)
            for p in open_ports:
                key = f"{h['address']}:{p['protocol']}/{p['port']}"
                if key in seen:
                    continue
                seen.add(key)
                severity, label, why = classify(p, https)
                product = " ".join(x for x in (p.get("product"), p.get("version")) if x)
                informational = severity is Severity.INFO
                name = h["hostnames"][0] if h["hostnames"] else h["address"]
                findings.append(finding(
                    "net.nmap_discovery.open_port", key,
                    f"{label} open on {name} port {p['port']}/{p['protocol']}" + (f" ({product})" if product else ""),
                    severity,
                    f"Port {p['port']} on {h['address']} {why}. Anything on the scanned network can connect to it.",
                    "If the service is not needed, turn it off on that device. Otherwise restrict it with the "
                    "device's firewall, keep it updated and use strong authentication.",
                    kind=FindingKind.INFORMATIONAL if informational else FindingKind.VERIFIED,
                    confidence=Confidence.HIGH if not informational else Confidence.MEDIUM, category="network",
                ))
        return CheckOutput(evidence=evidence, findings=findings, reconcile_scope="nmap:" + ",".join(targets))
