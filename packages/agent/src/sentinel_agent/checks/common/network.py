"""Network exposure and activity checks that work on Windows and Linux."""

from __future__ import annotations

import ipaddress
import re
from collections import Counter
from typing import Any

from sentinel_core.checks import Check, CheckContext, SkipCheck
from sentinel_core.commands import powershell
from sentinel_core.models import CheckOutput, Confidence, FindingKind, Platform, Severity

from ...context import PathNotAllowed
from ...safe_commands import CommandFailed
from .._util import finding, ps_list

BOTH = frozenset({Platform.WINDOWS, Platform.LINUX})
PROCESS_NAME_NOTE = ("Process names can be missing for services owned by other users when the agent runs without "
                     "admin rights.")

# --------------------------------------------------------------------------- listening ports

RISKY_PORTS: dict[int, tuple[str, Severity, str]] = {
    23: ("Telnet", Severity.HIGH, "sends passwords and everything else unencrypted"),
    21: ("FTP", Severity.HIGH, "usually sends passwords unencrypted"),
    5900: ("VNC", Severity.HIGH, "gives remote control of the screen and is often weakly protected"),
    # Windows listens on 445/139 by default and its firewall blocks them on Public networks, so these are
    # LOW: worth knowing and closing if unused, but flagging every Windows PC as MEDIUM would teach people
    # to ignore the list.
    445: ("SMB file sharing", Severity.LOW, "has a long history of remotely exploitable bugs; Windows enables it by "
          "default and its firewall blocks it on Public networks"),
    139: ("NetBIOS session service", Severity.LOW, "is legacy file sharing that leaks machine and user names"),
    3389: ("Remote Desktop", Severity.MEDIUM, "is a frequent target of password guessing"),
    5985: ("WinRM (HTTP)", Severity.MEDIUM, "allows remote administration"),
    5986: ("WinRM (HTTPS)", Severity.MEDIUM, "allows remote administration"),
    3306: ("MySQL/MariaDB", Severity.MEDIUM, "is a database that rarely needs to be reachable from other machines"),
    5432: ("PostgreSQL", Severity.MEDIUM, "is a database that rarely needs to be reachable from other machines"),
    6379: ("Redis", Severity.MEDIUM, "has no password by default"),
    27017: ("MongoDB", Severity.MEDIUM, "is a database that rarely needs to be reachable from other machines"),
    9200: ("Elasticsearch", Severity.MEDIUM, "often has no authentication"),
    22: ("SSH", Severity.INFO, "is remote shell access"),
}


def _is_loopback(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip.split("%", 1)[0]).is_loopback
    except ValueError:
        return ip in ("localhost",)


class ListeningPorts(Check):
    id = "net.listening"
    version = "2"
    title = "No risky services are listening for network connections"
    category = "network"
    platforms = BOTH
    data_collected = "Local addresses, ports, process ids and process names of listening TCP and UDP sockets"

    def run(self, ctx: CheckContext) -> CheckOutput:
        sockets = ctx.system.listening_sockets()
        evidence = [ctx.evidence("metric", "listening sockets", {
            "sockets": sorted(sockets, key=lambda s: (s.get("proto", ""), s.get("port") or 0, s.get("ip", ""))),
            "note": PROCESS_NAME_NOTE,
        })]
        findings = []
        seen: set[str] = set()
        for s in sockets:
            port, ip = s.get("port"), str(s.get("ip") or "")
            if s.get("proto") != "tcp" or port not in RISKY_PORTS or _is_loopback(ip):
                continue
            key = f"tcp:{ip}:{port}"
            if key in seen:
                continue
            seen.add(key)
            service, severity, why = RISKY_PORTS[port]
            who = f" ({s['process']})" if s.get("process") else ""
            scope = {"0.0.0.0": "all IPv4 interfaces", "::": "all IPv6 interfaces", "": "all interfaces"}.get(ip, ip)  # noqa: S104
            informational = severity is Severity.INFO
            findings.append(finding(
                "net.listening.risky_port", key,
                f"{service} is listening on port {port} on {scope}{who}",
                severity,
                f"{service} {why}. Unless a firewall blocks the port, other devices that can reach this address can "
                "try to connect. (This check sees the listening socket, not the firewall rules.)",
                "If you do not use it, stop and disable the service. If you do, limit it with the firewall to the "
                "devices that need it."
                + (" Prefer key-based SSH sign-in and disable password authentication." if port == 22 else ""),
                kind=FindingKind.INFORMATIONAL if informational else FindingKind.VERIFIED,
                category="network",
            ))
        return CheckOutput(evidence=evidence, findings=findings)


# --------------------------------------------------------------------------- processes in odd places

_LINUX_TEMP = ("/tmp/", "/var/tmp/", "/dev/shm/")  # noqa: S108 - paths we look for, never write to
_WIN_MARKERS = (
    ("\\appdata\\local\\temp\\", "AppData\\Local\\Temp"),
    ("\\windows\\temp\\", "Windows\\Temp"),
    ("\\downloads\\", "Downloads"),
    ("\\users\\public\\", "Users\\Public"),
    ("\\temp\\", "a Temp folder"),
)


def odd_location(exe: str) -> str | None:
    if exe.startswith("/"):
        for prefix in _LINUX_TEMP:
            if exe.startswith(prefix):
                return prefix.rstrip("/")
        return None
    low = exe.replace("/", "\\").lower()
    for marker, label in _WIN_MARKERS:
        if marker in low:
            return label
    return None


class SuspiciousProcessLocations(Check):
    id = "proc.suspicious_locations"
    version = "1"
    title = "No programs are running from temporary or download folders"
    category = "threat"
    platforms = BOTH
    data_collected = "Process ids, names, program paths and owning user of running processes"

    def run(self, ctx: CheckContext) -> CheckOutput:
        procs = ctx.system.processes()
        flagged: list[dict[str, Any]] = []
        for p in procs:
            exe = str(p.get("exe") or "")
            where = odd_location(exe) if exe else None
            if where:
                flagged.append({**p, "location": where})
        evidence = [ctx.evidence("metric", "process list", {
            "processes_seen": len(procs),
            "without_path": sum(1 for p in procs if not p.get("exe")),
            "flagged": flagged,
            "note": "Program paths of other users' processes are hidden without admin rights, so those cannot be "
                    "checked in a standard scan.",
        })]
        findings = []
        seen: set[str] = set()
        for p in flagged:
            exe = str(p["exe"])
            if exe.lower() in seen:
                continue
            seen.add(exe.lower())
            findings.append(finding(
                "proc.suspicious_locations.running_from_temp", f"process:{exe.lower()}",
                f"{p.get('name') or exe} is running from {p['location']}",
                Severity.MEDIUM,
                f"The program {exe} is running from {p['location']}. Malware often runs from folders like this, "
                "but so do some installers and portable apps. This is not proof of malware.",
                "Check whether you started this program (for example an installer you just downloaded). If you do "
                "not recognise it, run a full antivirus scan. Sentinel never stops processes.",
                kind=FindingKind.HEURISTIC, confidence=Confidence.MEDIUM, category="threat",
            ))
        return CheckOutput(evidence=evidence, findings=findings)


# --------------------------------------------------------------------------- unusual outbound

UNUSUAL_REMOTE_PORTS = {
    4444: "a common default for remote-access tools such as Metasploit",
    1337: "a port often used by hacking tools",
    31337: "a port often used by backdoors",
    6667: "IRC, historically used to control botnets",
    6697: "IRC over TLS, historically used to control botnets",
    9001: "a common Tor relay port",
    9030: "a common Tor directory port",
    9050: "the Tor client (SOCKS) port",
    9150: "the Tor Browser (SOCKS) port",
    5555: "Android Debug Bridge and some remote-access tools",
}
MANY_CONNECTIONS = 50


class UnusualOutbound(Check):
    id = "net.unusual_outbound"
    version = "1"
    title = "No unusual outbound connections"
    category = "threat"
    platforms = BOTH
    data_collected = "Local and remote addresses, ports and process names of established TCP connections"

    def run(self, ctx: CheckContext) -> CheckOutput:
        conns = ctx.system.connections()
        per_process: Counter[str] = Counter()
        for c in conns:
            per_process[str(c.get("process") or f"pid {c.get('pid')}")] += 1
        evidence = [ctx.evidence("metric", "established connections", {
            "connections": conns,
            "per_process": dict(per_process.most_common()),
            "note": PROCESS_NAME_NOTE,
        })]
        findings = []
        seen: set[str] = set()
        for c in conns:
            rport = c.get("rport")
            if rport not in UNUSUAL_REMOTE_PORTS:
                continue
            raddr = str(c.get("raddr"))
            key = f"outbound:{c.get('process') or 'unknown'}:{raddr}:{rport}"
            if key in seen:
                continue
            seen.add(key)
            who = c.get("process") or f"process {c.get('pid')}"
            findings.append(finding(
                "net.unusual_outbound.port", key,
                f"{who} is connected to {raddr} on port {rport}",
                Severity.LOW,
                f"Port {rport} is {UNUSUAL_REMOTE_PORTS[rport]}. Legitimate software uses it too, so this is only a "
                "lead to check.",
                "If you do not recognise the program or the destination, look it up and run an antivirus scan.",
                kind=FindingKind.HEURISTIC, confidence=Confidence.LOW, category="threat",
            ))
        for proc, n in per_process.items():
            if n > MANY_CONNECTIONS:
                findings.append(finding(
                    "net.unusual_outbound.many_connections", f"outbound:{proc}:count",
                    f"{proc} has {n} open connections",
                    Severity.INFO,
                    "Browsers, sync clients and torrent clients often hold many connections; malware that scans "
                    "or sends spam does too.",
                    "Confirm the program is something you use.",
                    kind=FindingKind.INFORMATIONAL, confidence=Confidence.LOW, category="threat",
                ))
        return CheckOutput(evidence=evidence, findings=findings)


# --------------------------------------------------------------------------- DNS

DNS_SERVERS = powershell(
    "ps.dns_client_servers",
    "Get-DnsClientServerAddress -ErrorAction Stop | Select-Object InterfaceAlias, InterfaceIndex,"
    " @{n='AddressFamily';e={[string]$_.AddressFamily}}, @{n='ServerAddresses';e={,@($_.ServerAddresses)}}"
    " | ConvertTo-Json -Depth 3 -Compress",
)
_NAMESERVER = re.compile(r"^\s*nameserver\s+(\S+)", re.MULTILINE)


def _usable_v4(iface: dict[str, Any]) -> bool:
    for a in iface.get("addresses") or []:
        if a.get("family") != "ipv4":
            continue
        try:
            ip = ipaddress.ip_address(a.get("address", ""))
        except ValueError:
            continue
        if not (ip.is_loopback or ip.is_link_local):
            return True
    return False


class DnsConfiguration(Check):
    id = "net.dns_config"
    version = "1"
    title = "DNS servers are configured"
    category = "network"
    platforms = BOTH
    data_collected = "The DNS server addresses configured per network adapter (Windows) or in /etc/resolv.conf (Linux)"
    commands = (DNS_SERVERS,)

    def run(self, ctx: CheckContext) -> CheckOutput:
        if ctx.host.os_family is Platform.WINDOWS:
            return self._windows(ctx)
        return self._linux(ctx)

    def _windows(self, ctx: CheckContext) -> CheckOutput:
        try:
            rows = [r for r in ps_list(ctx.run_json(DNS_SERVERS)) if isinstance(r, dict)]
        except CommandFailed as exc:
            raise SkipCheck("DNS settings could not be read (Get-DnsClientServerAddress failed)") from exc
        ifaces = {i.get("name"): i for i in ctx.system.interfaces()}
        usable: dict[str, list[str]] = {}
        for alias in sorted({str(r.get("InterfaceAlias")) for r in rows}):
            iface = ifaces.get(alias)
            if iface and iface.get("is_up") and _usable_v4(iface):
                usable[alias] = [str(s) for r in rows if r.get("InterfaceAlias") == alias
                                 for s in ps_list(r.get("ServerAddresses"))]
        evidence = [ctx.evidence("command_output", "Get-DnsClientServerAddress", {
            "servers": rows,
            "up_interfaces_without_dns": sorted(a for a, s in usable.items() if not s),
            "note": "Adapters without DNS servers are normal for virtual switches (WSL, Hyper-V, VPN clients); "
                    "Windows resolves names through the adapters that have servers.",
        })]
        findings = []
        if usable and not any(usable.values()):
            findings.append(self._no_dns(", ".join(sorted(usable))))
        return CheckOutput(evidence=evidence, findings=findings)

    def _linux(self, ctx: CheckContext) -> CheckOutput:
        try:
            text = ctx.read_text("/etc/resolv.conf")
        except (OSError, PathNotAllowed) as exc:
            raise SkipCheck("/etc/resolv.conf could not be read") from exc
        servers = _NAMESERVER.findall(text)
        notes = []
        if "127.0.0.53" in servers:
            notes.append("127.0.0.53 is the local systemd-resolved stub; the real upstream servers are configured "
                         "in systemd-resolved (resolvectl status).")
        evidence = [ctx.evidence("file_metadata", "/etc/resolv.conf", {"nameservers": servers, "notes": notes})]
        findings = []
        if not servers and any(i.get("is_up") and _usable_v4(i) for i in ctx.system.interfaces()):
            findings.append(self._no_dns("/etc/resolv.conf"))
        return CheckOutput(evidence=evidence, findings=findings)

    @staticmethod
    def _no_dns(where: str) -> Any:
        return finding(
            "net.dns_config.no_servers", f"dns:{where}",
            f"No DNS servers are configured for {where}",
            Severity.LOW,
            "Name lookups may fail or fall back to whatever answers on the network.",
            "Let the adapter obtain DNS servers automatically (DHCP), or set the servers your router or provider "
            "recommends.",
            category="network",
        )


# --------------------------------------------------------------------------- interfaces


def _public_ipv4(address: str) -> bool:
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False
    return ip.version == 4 and ip.is_global


class NetworkInterfaces(Check):
    id = "net.interfaces"
    version = "1"
    title = "Network interfaces"
    category = "network"
    platforms = BOTH
    data_collected = "Name, up/down state, speed, MTU and addresses of each network interface"

    def run(self, ctx: CheckContext) -> CheckOutput:
        ifaces = ctx.system.interfaces()
        evidence = [ctx.evidence("metric", "network interfaces", ifaces)]
        findings = []
        for i in ifaces:
            if not i.get("is_up"):
                continue
            for a in i.get("addresses") or []:
                addr = str(a.get("address", ""))
                if a.get("family") == "ipv4" and _public_ipv4(addr):
                    findings.append(finding(
                        "net.interfaces.public_ipv4", f"iface:{i.get('name')}:{addr}",
                        f"{i.get('name')} has a public IPv4 address ({addr})",
                        Severity.INFO,
                        "This machine is directly on the internet rather than behind a home router's NAT, so its "
                        "firewall is the only thing between its services and everyone else.",
                        "Keep the firewall on and check the listening-ports results for anything you do not need.",
                        kind=FindingKind.INFORMATIONAL, category="network",
                    ))
        return CheckOutput(evidence=evidence, findings=findings)
