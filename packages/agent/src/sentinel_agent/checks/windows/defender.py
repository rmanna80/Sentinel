"""Microsoft Defender Antivirus status."""

from __future__ import annotations

from sentinel_core.checks import Check, CheckContext, NotApplicable, SkipCheck
from sentinel_core.commands import powershell
from sentinel_core.models import CheckOutput, Platform, Severity

from ...safe_commands import CommandFailed, as_list
from .._util import as_int, finding

SIGNATURE_MAX_AGE_DAYS = 3

DEFENDER_STATUS = powershell(
    "ps.defender_status",
    "Get-MpComputerStatus -ErrorAction Stop | Select-Object AMServiceEnabled, AntivirusEnabled,"
    " RealTimeProtectionEnabled, IsTamperProtected, AntivirusSignatureAge,"
    " @{n='AntivirusSignatureLastUpdated';e={if ($_.AntivirusSignatureLastUpdated) {"
    "$_.AntivirusSignatureLastUpdated.ToUniversalTime().ToString('o')}}},"
    " @{n='AMRunningMode';e={[string]$_.AMRunningMode}}"
    " | ConvertTo-Json -Depth 3 -Compress",
)
# Security Center exists on client editions only; productState is a bit field (bits 12-13 = 0x1000 on, 0x2000 snoozed).
AV_PRODUCTS = powershell(
    "ps.securitycenter_av",
    "Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction Stop"
    " | Select-Object displayName, productState | ConvertTo-Json -Depth 3 -Compress",
)

PASSIVE_MODES = ("passive mode", "passive", "edr block mode", "sxs passive mode", "not running")


def _is_active(product_state: object) -> bool:
    state = as_int(product_state)
    if state is None:
        return False
    return (state >> 12) & 0xF == 1


def _is_microsoft_defender(name: object) -> bool:
    # Exact product names only: "Bitdefender" also contains "defender".
    return str(name or "").strip().lower().startswith(("windows defender", "microsoft defender"))


class DefenderStatus(Check):
    id = "win.defender.status"
    version = "1"
    title = "Microsoft Defender Antivirus is protecting this PC"
    category = "configuration"
    platforms = frozenset({Platform.WINDOWS})
    timeout_seconds = 60.0
    data_collected = (
        "Microsoft Defender's on/off states (service, antivirus, real-time protection, tamper protection), "
        "the age and date of its virus definitions, its running mode, and the names and state codes of "
        "antivirus products registered with Windows Security Center"
    )
    commands = (DEFENDER_STATUS, AV_PRODUCTS)

    def run(self, ctx: CheckContext) -> CheckOutput:
        try:
            products = [p for p in as_list(ctx.run_json(AV_PRODUCTS)) if isinstance(p, dict)]
            products_error = None
        except CommandFailed as exc:
            products, products_error = [], str(exc)[:200]
        others = [
            str(p.get("displayName")) for p in products
            if _is_active(p.get("productState")) and not _is_microsoft_defender(p.get("displayName"))
        ]
        try:
            status = ctx.run_json(DEFENDER_STATUS)
        except CommandFailed as exc:
            if others:
                raise NotApplicable(f"{others[0]} is the active antivirus; Microsoft Defender is not running") from exc
            raise SkipCheck("Microsoft Defender status could not be read (Get-MpComputerStatus failed)") from exc
        if not isinstance(status, dict):
            raise SkipCheck("Microsoft Defender status could not be read (unexpected output)")

        mode = str(status.get("AMRunningMode") or "")
        av_on = status.get("AntivirusEnabled") is True
        defender_passive = mode.lower() in PASSIVE_MODES or not av_on
        if others and defender_passive:
            raise NotApplicable(f"{others[0]} is the active antivirus, so Microsoft Defender runs in passive mode")

        evidence = [ctx.evidence("command_output", "Get-MpComputerStatus; root/SecurityCenter2 AntiVirusProduct", {
            "defender": status,
            "security_center_products": products,
            "security_center_error": products_error,
            "other_active_antivirus": others,
        })]
        findings = []
        if not av_on and not others:
            findings.append(finding(
                "win.defender.av_disabled", "defender:antivirus",
                "Antivirus protection is off and no other antivirus is active",
                Severity.CRITICAL,
                "Nothing on this PC is scanning files for malware.",
                "Open Windows Security > Virus & threat protection and turn protection on. If another antivirus "
                "was uninstalled, restart so Microsoft Defender can take over again.",
            ))
        elif status.get("RealTimeProtectionEnabled") is not True:
            findings.append(finding(
                "win.defender.realtime_off", "defender:realtime",
                "Real-time protection is off",
                Severity.HIGH,
                "Files are no longer scanned when they are downloaded or opened, so malware can run before any "
                "scheduled scan notices it.",
                "Open Windows Security > Virus & threat protection > Manage settings and turn Real-time "
                "protection on.",
            ))
        age = as_int(status.get("AntivirusSignatureAge"))
        if av_on and age is not None and age > SIGNATURE_MAX_AGE_DAYS:
            findings.append(finding(
                "win.defender.signatures_old", "defender:signatures",
                f"Virus definitions are {age} days old",
                Severity.MEDIUM,
                "Malware released since the last definition update may not be recognised.",
                "Open Windows Security > Virus & threat protection > Protection updates and select Check for "
                "updates. Make sure Windows Update is not paused.",
            ))
        if av_on and status.get("IsTamperProtected") is False:
            findings.append(finding(
                "win.defender.tamper_off", "defender:tamper",
                "Tamper Protection is off",
                Severity.MEDIUM,
                "Malware running with administrator rights can switch off Microsoft Defender's protections.",
                "Open Windows Security > Virus & threat protection > Manage settings and turn Tamper Protection on.",
            ))
        return CheckOutput(evidence=evidence, findings=findings)
