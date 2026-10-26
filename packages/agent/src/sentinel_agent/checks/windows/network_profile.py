"""Network profiles and the security of the connected Wi-Fi network."""

from __future__ import annotations

import re
from typing import Any

from sentinel_core.checks import Check, CheckContext
from sentinel_core.commands import CommandSpec, powershell
from sentinel_core.models import CheckOutput, Platform, Severity

from ...safe_commands import CommandFailed
from .._util import finding, ps_list

CONNECTION_PROFILES = powershell(
    "ps.net_connection_profiles",
    "Get-NetConnectionProfile -ErrorAction Stop | Select-Object Name, InterfaceAlias,"
    " @{n='NetworkCategory';e={[string]$_.NetworkCategory}},"
    " @{n='IPv4Connectivity';e={[string]$_.IPv4Connectivity}},"
    " @{n='IPv6Connectivity';e={[string]$_.IPv6Connectivity}}"
    " | ConvertTo-Json -Depth 3 -Compress",
)
# Exit code 1 when the WLAN AutoConfig service is absent/stopped, or when Windows 11 24H2+ denies WLAN
# details to apps without location permission. Both are treated as "no Wi-Fi details".
WLAN_INTERFACES = CommandSpec("netsh.wlan_interfaces", "netsh", ("wlan", "show", "interfaces"),
                              timeout=30, ok_exit_codes=(0, 1))

_KV = re.compile(r"^\s{2,}(?P<key>[A-Za-z][A-Za-z0-9 ()/-]*?)\s*:\s?(?P<value>.*?)\s*$")


def parse_wlan_interfaces(text: str) -> list[dict[str, str]]:
    """One dict per interface block. Labels are English; other languages yield no usable keys."""
    interfaces: list[dict[str, str]] = []
    current: dict[str, str] | None = None
    for line in text.splitlines():
        m = _KV.match(line)
        if not m:
            continue
        key, value = m.group("key"), m.group("value")
        if key == "Name":
            current = {}
            interfaces.append(current)
        if current is not None and key not in current:
            current[key] = value
    return interfaces


def wifi_weakness(auth: str, cipher: str) -> tuple[Severity, str] | None:
    a, c = auth.strip().lower(), cipher.strip().lower()
    if "wep" in c or a in ("shared", "wep"):
        return Severity.HIGH, "uses WEP encryption, which can be broken in minutes"
    if a == "open" and c in ("none", ""):
        return Severity.HIGH, "is open (no password and no encryption)"
    if "tkip" in c:
        return Severity.MEDIUM, "uses the outdated TKIP cipher"
    if a in ("wpa-personal", "wpa-psk"):
        return Severity.MEDIUM, "uses original WPA, which is outdated"
    return None


class NetworkProfile(Check):
    id = "win.network_profile"
    version = "1"
    title = "Connected networks are classified and secured"
    category = "network"
    platforms = frozenset({Platform.WINDOWS})
    timeout_seconds = 60.0
    data_collected = (
        "Name, adapter and Public/Private category of each connected network, and for Wi-Fi the network name "
        "(SSID), authentication and cipher of the connected access point"
    )
    commands = (CONNECTION_PROFILES, WLAN_INTERFACES)

    def run(self, ctx: CheckContext) -> CheckOutput:
        try:
            profiles: Any = [p for p in ps_list(ctx.run_json(CONNECTION_PROFILES)) if isinstance(p, dict)]
        except CommandFailed as exc:
            profiles = f"unavailable: {str(exc)[:200]}"
        wifi_note = None
        connected: list[dict[str, str]] = []
        try:
            result = ctx.run(WLAN_INTERFACES)
            interfaces = parse_wlan_interfaces(result.stdout)
            connected = [i for i in interfaces if i.get("State", "").lower() == "connected"]
            if result.exit_code != 0 or not interfaces:
                first = next((ln.strip() for ln in result.stdout.splitlines() if ln.strip()), "")
                wifi_note = f"No Wi-Fi details: {first[:200]}" if first else "No Wi-Fi interface reported."
        except CommandFailed as exc:
            wifi_note = f"No Wi-Fi details: {str(exc)[:200]}"
        evidence = [ctx.evidence("command_output", "Get-NetConnectionProfile; netsh wlan show interfaces", {
            "profiles": profiles,
            "wifi": [{k: i.get(k) for k in ("Name", "State", "SSID", "Authentication", "Cipher", "Radio type",
                                             "Profile")} for i in connected],
            "wifi_note": wifi_note,
        })]
        findings = []
        for i in connected:
            ssid = i.get("SSID") or "(hidden network)"
            weakness = wifi_weakness(i.get("Authentication", ""), i.get("Cipher", ""))
            if weakness is None:
                continue
            severity, why = weakness
            findings.append(finding(
                "win.network_profile.weak_wifi", f"wifi:{ssid}",
                f"Wi-Fi network \"{ssid}\" {why}",
                severity,
                "Other people in range can read or tamper with traffic that is not separately encrypted (HTTPS, "
                "VPN), and devices on the same network can reach this PC.",
                "If it is your network, switch the router to WPA2-Personal (AES) or WPA3-Personal. If it is not, "
                "use a VPN on it and keep the network set to Public in Settings > Network & internet.",
                category="network",
            ))
        return CheckOutput(evidence=evidence, findings=findings)
