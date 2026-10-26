"""Security (authentication and cipher) of the Wi-Fi network this PC is connected to.

``netsh wlan show interfaces`` is the only source. Its output is localized and it exits with code 1 for several
unrelated reasons (WLAN AutoConfig service stopped, Windows 11 24H2+ location permission off for desktop apps),
so anything other than recognizable English output is reported as a skip: a pass would mark an earlier weak-Wi-Fi
finding as verified resolved.
"""

from __future__ import annotations

import re

from sentinel_core.checks import Check, CheckContext, NotApplicable, SkipCheck
from sentinel_core.commands import CommandSpec
from sentinel_core.models import CheckOutput, Platform, Severity

from ...safe_commands import CommandCancelled, CommandFailed, CommandTimedOut
from .._util import finding

# Exit code 1 is accepted so its message can be shown in the skip reason; it is never read as "no Wi-Fi".
WLAN_INTERFACES = CommandSpec("netsh.wlan_interfaces", "netsh", ("wlan", "show", "interfaces"),
                              timeout=30, ok_exit_codes=(0, 1))

LIKELY_CAUSES = (
    "Likely causes: the WLAN AutoConfig service (wlansvc) is not running; this PC has no Wi-Fi adapter; Windows "
    "location access for desktop apps is off (Windows 11 24H2 and later need it for Wi-Fi details: Settings > "
    "Privacy & security > Location > Let desktop apps access your location); or Windows uses a display language "
    "other than English (Sentinel reads netsh's English output)."
)
EVIDENCE_FIELDS = ("Name", "State", "SSID", "Authentication", "Cipher", "Radio type", "Profile")

_KV = re.compile(r"^\s{2,}(?P<key>[A-Za-z][A-Za-z0-9 ()/-]*?)\s*:\s?(?P<value>.*?)\s*$")
_NO_INTERFACE = re.compile(r"(?im)^\s*There is no wireless interface on the system\.?\s*$")


def parse_wlan_interfaces(text: str) -> list[dict[str, str]]:
    """One dict per interface block (a block starts at a ``Name`` line). Labels are English; other languages
    yield no blocks or blocks without the English field names."""
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


def _first_line(text: str) -> str:
    return next((ln.strip() for ln in text.splitlines() if ln.strip()), "")[:200]


def _unknown(detail: str) -> SkipCheck:
    return SkipCheck(f"Wi-Fi security could not be determined ({detail}). {LIKELY_CAUSES}")


class WifiSecurity(Check):
    id = "win.wifi_security"
    version = "1"
    title = "The connected Wi-Fi network is secured"
    category = "network"
    platforms = frozenset({Platform.WINDOWS})
    timeout_seconds = 60.0
    data_collected = (
        "For each Wi-Fi adapter: its name and connection state, and for a connected network its name (SSID), "
        "authentication, cipher, radio type and profile name"
    )
    commands = (WLAN_INTERFACES,)

    def run(self, ctx: CheckContext) -> CheckOutput:
        try:
            result = ctx.run(WLAN_INTERFACES)
        except (CommandTimedOut, CommandCancelled):
            raise
        except CommandFailed as exc:
            raise _unknown(f"netsh failed: {str(exc)[:200]}") from exc
        if _NO_INTERFACE.search(result.stdout):
            raise NotApplicable("This PC has no Wi-Fi adapter (netsh reports no wireless interface)")
        first = _first_line(result.stdout) or "no output"
        if result.exit_code != 0:
            raise _unknown(f"netsh exited with code {result.exit_code}: {first}")
        interfaces = parse_wlan_interfaces(result.stdout)
        if not interfaces:
            raise _unknown(f"netsh output had no recognizable interface details: {first}")
        if any("State" not in i for i in interfaces):
            raise _unknown(f"netsh output had no recognizable English field names: {first}")
        connected = [i for i in interfaces if i["State"].strip().lower() == "connected"]
        for i in connected:
            if not i.get("Authentication") or not i.get("Cipher"):
                raise _unknown(f"no authentication or cipher shown for connected interface {i.get('Name') or '?'}")

        evidence = [ctx.evidence("command_output", "netsh wlan show interfaces", {
            "interfaces": [{k: i.get(k) for k in EVIDENCE_FIELDS} for i in interfaces],
            "connected": len(connected),
        })]
        findings = []
        for i in connected:
            ssid = i.get("SSID") or "(hidden network)"
            weakness = wifi_weakness(i["Authentication"], i["Cipher"])
            if weakness is None:
                continue
            severity, why = weakness
            findings.append(finding(
                "win.wifi_security.weak_wifi", f"wifi:{ssid}",
                f"Wi-Fi network \"{ssid}\" {why}",
                severity,
                "Other people in range can read or tamper with traffic that is not separately encrypted (HTTPS, "
                "VPN), and devices on the same network can reach this PC.",
                "If it is your network, switch the router to WPA2-Personal (AES) or WPA3-Personal. If it is not, "
                "use a VPN on it and keep the network set to Public in Settings > Network & internet.",
                category="network",
            ))
        return CheckOutput(evidence=evidence, findings=findings)
