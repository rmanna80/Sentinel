"""Network profiles (Public/Private category) of the connected networks.

The security of the connected Wi-Fi network is a separate check, ``win.wifi_security`` (wifi.py), so a Wi-Fi
read that fails can be reported as skipped without hiding the profile information.
"""

from __future__ import annotations

from sentinel_core.checks import Check, CheckContext, SkipCheck
from sentinel_core.commands import powershell
from sentinel_core.models import CheckOutput, Platform

from ...safe_commands import CommandCancelled, CommandFailed, CommandTimedOut
from .._util import ps_list

CONNECTION_PROFILES = powershell(
    "ps.net_connection_profiles",
    "Get-NetConnectionProfile -ErrorAction Stop | Select-Object Name, InterfaceAlias,"
    " @{n='NetworkCategory';e={[string]$_.NetworkCategory}},"
    " @{n='IPv4Connectivity';e={[string]$_.IPv4Connectivity}},"
    " @{n='IPv6Connectivity';e={[string]$_.IPv6Connectivity}}"
    " | ConvertTo-Json -Depth 3 -Compress",
)


class NetworkProfile(Check):
    id = "win.network_profile"
    version = "2"
    title = "Connected networks are classified"
    category = "network"
    platforms = frozenset({Platform.WINDOWS})
    timeout_seconds = 60.0
    data_collected = "Name, adapter, Public/Private category and connectivity of each connected network"
    commands = (CONNECTION_PROFILES,)

    def run(self, ctx: CheckContext) -> CheckOutput:
        try:
            profiles = [p for p in ps_list(ctx.run_json(CONNECTION_PROFILES)) if isinstance(p, dict)]
        except (CommandTimedOut, CommandCancelled):
            raise
        except CommandFailed as exc:
            raise SkipCheck(f"Network profiles could not be read: {str(exc)[:200]}") from exc
        evidence = [ctx.evidence("command_output", "Get-NetConnectionProfile", {"profiles": profiles})]
        return CheckOutput(evidence=evidence)
