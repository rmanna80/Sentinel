"""Windows Firewall profile state."""

from __future__ import annotations

from sentinel_core.checks import Check, CheckContext
from sentinel_core.commands import powershell
from sentinel_core.models import CheckOutput, Platform, Severity

from ...safe_commands import as_list
from .._util import finding

FIREWALL_PROFILES = powershell(
    "ps.firewall_profiles",
    "Get-NetFirewallProfile | Select-Object Name,"
    " @{n='Enabled';e={[string]$_.Enabled}},"
    " @{n='DefaultInboundAction';e={[string]$_.DefaultInboundAction}},"
    " @{n='DefaultOutboundAction';e={[string]$_.DefaultOutboundAction}}"
    " | ConvertTo-Json -Depth 3",
)


class FirewallProfiles(Check):
    id = "win.firewall.profiles"
    version = "1"
    title = "Windows Firewall is on for every profile"
    category = "configuration"
    platforms = frozenset({Platform.WINDOWS})
    data_collected = "On/off state and default inbound action of the Domain, Private and Public firewall profiles"
    commands = (FIREWALL_PROFILES,)

    def run(self, ctx: CheckContext) -> CheckOutput:
        # ConvertTo-Json emits enums as numbers, so the script casts them to strings first.
        rows = as_list(ctx.run_json(FIREWALL_PROFILES))
        evidence = [ctx.evidence("command_output", "Get-NetFirewallProfile", rows)]
        findings = []
        for p in rows:
            name = str(p.get("Name", "Unknown"))
            if str(p.get("Enabled")) != "True":
                findings.append(finding(
                    "win.firewall.profile_disabled", f"firewall:{name}",
                    f"Firewall is off for the {name} profile",
                    Severity.HIGH if name == "Public" else Severity.MEDIUM,
                    "Inbound connections on this type of network are not filtered.",
                    "Open Windows Security > Firewall & network protection and turn the "
                    f"{name} network firewall on.",
                    references=["https://learn.microsoft.com/windows/security/operating-system-security/network-security/windows-firewall/"],
                ))
            elif name == "Public" and str(p.get("DefaultInboundAction")) == "Allow":
                findings.append(finding(
                    "win.firewall.public_inbound_allow", f"firewall:{name}:inbound",
                    "Public firewall profile allows inbound connections by default",
                    Severity.HIGH,
                    "On public Wi-Fi, any service listening on this machine is reachable by others on that network.",
                    "Set the Public profile's default inbound action back to Block (the Windows default).",
                ))
        return CheckOutput(evidence=evidence, findings=findings)
