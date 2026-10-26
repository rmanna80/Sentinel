"""Remote Desktop host configuration."""

from __future__ import annotations

from sentinel_core.checks import Check, CheckContext, SkipCheck
from sentinel_core.models import CheckOutput, HostInfo, Platform, Severity

from .._util import as_int, finding, is_home_edition

TS_KEY = r"SYSTEM\CurrentControlSet\Control\Terminal Server"
RDP_TCP_KEY = TS_KEY + r"\WinStations\RDP-Tcp"


class RemoteDesktop(Check):
    id = "win.rdp"
    version = "1"
    title = "Remote Desktop is off or requires Network Level Authentication"
    category = "exposure"
    platforms = frozenset({Platform.WINDOWS})
    data_collected = (
        "Whether Remote Desktop connections are allowed (fDenyTSConnections), whether Network Level "
        "Authentication is required (UserAuthentication) and the listening port (PortNumber)"
    )

    def applicable(self, host: HostInfo) -> str | None:
        if is_home_edition(host.edition):
            return "Windows Home cannot host Remote Desktop connections"
        return None

    def run(self, ctx: CheckContext) -> CheckOutput:
        deny = ctx.read_registry("HKLM", TS_KEY, "fDenyTSConnections", view="64")
        nla = ctx.read_registry("HKLM", RDP_TCP_KEY, "UserAuthentication", view="64")
        port = ctx.read_registry("HKLM", RDP_TCP_KEY, "PortNumber", view="64")
        if deny is None:
            raise SkipCheck("The Remote Desktop setting (fDenyTSConnections) could not be read")
        values = {"fDenyTSConnections": deny, "UserAuthentication": nla, "PortNumber": port}
        evidence = [ctx.evidence("registry_value", f"HKLM\\{TS_KEY}", values)]
        findings = []
        if as_int(deny) == 0:
            port_text = f" on port {as_int(port)}" if as_int(port) else ""
            if as_int(nla) == 1:
                findings.append(finding(
                    "win.rdp.enabled_nla", "rdp:enabled",
                    f"Remote Desktop is on{port_text} (Network Level Authentication required)",
                    Severity.LOW,
                    "Anyone who can reach this port can try passwords. NLA makes them authenticate before a "
                    "session starts, which blocks many attacks, but weak passwords are still at risk.",
                    "Turn Remote Desktop off in Settings > System > Remote Desktop if you do not use it. If you do, "
                    "only allow it from your own network (or over a VPN) and use strong passwords.",
                ))
            else:
                findings.append(finding(
                    "win.rdp.no_nla", "rdp:enabled",
                    f"Remote Desktop is on{port_text} without Network Level Authentication",
                    Severity.HIGH,
                    "Connections reach the Windows sign-in screen before proving who they are, which exposes the "
                    "machine to password guessing and pre-authentication vulnerabilities.",
                    "In Settings > System > Remote Desktop > Advanced settings, turn on \"Require devices to use "
                    "Network Level Authentication to connect\", or turn Remote Desktop off.",
                ))
        return CheckOutput(evidence=evidence, findings=findings)
