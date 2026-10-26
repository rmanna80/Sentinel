"""UEFI Secure Boot state."""

from __future__ import annotations

from sentinel_core.checks import Check, CheckContext, SkipCheck
from sentinel_core.commands import powershell
from sentinel_core.models import CheckOutput, Platform, Severity

from ...safe_commands import CommandFailed
from .._util import finding

# Confirm-SecureBootUEFI returns $true/$false on UEFI machines, throws PlatformNotSupportedException
# ("Cmdlet not supported on this platform") on legacy BIOS, and UnauthorizedAccessException without admin rights.
SECURE_BOOT = powershell(
    "ps.secure_boot",
    "$r = [ordered]@{state='unknown'; message=$null}; "
    "try { if (Confirm-SecureBootUEFI -ErrorAction Stop) { $r.state = 'on' } else { $r.state = 'off' } } "
    "catch { $e = $_.Exception; $r.message = [string]$e.Message; "
    "if ($e -is [System.PlatformNotSupportedException] -or $e.Message -like '*not supported on this platform*') "
    "{ $r.state = 'unsupported' } else { $r.state = 'inaccessible' } }; "
    "[pscustomobject]$r | ConvertTo-Json -Compress",
)


class SecureBoot(Check):
    id = "win.secureboot"
    version = "1"
    title = "Secure Boot is on"
    category = "configuration"
    platforms = frozenset({Platform.WINDOWS})
    requires_elevation = True
    data_collected = "Whether UEFI Secure Boot is on, off or unsupported (Confirm-SecureBootUEFI)"
    commands = (SECURE_BOOT,)

    def run(self, ctx: CheckContext) -> CheckOutput:
        try:
            data = ctx.run_json(SECURE_BOOT)
        except CommandFailed as exc:
            raise SkipCheck("Secure Boot state could not be read") from exc
        state = str((data or {}).get("state", "")).lower() if isinstance(data, dict) else ""
        message = data.get("message") if isinstance(data, dict) else None
        if state not in ("on", "off", "unsupported"):
            reason = f": {str(message)[:150]}" if message else ""
            raise SkipCheck(f"Secure Boot state could not be read{reason}")
        evidence = [ctx.evidence("command_output", "Confirm-SecureBootUEFI", {"state": state, "message": message})]
        findings = []
        if state == "off":
            findings.append(finding(
                "win.secureboot.off", "secureboot", "Secure Boot is off",
                Severity.MEDIUM,
                "Boot-level malware (bootkits) can load before Windows and hide from antivirus. Windows 11 expects "
                "Secure Boot to be on.",
                "Restart into the UEFI/BIOS setup (Settings > System > Recovery > Advanced startup > UEFI Firmware "
                "Settings) and enable Secure Boot. If you dual-boot Linux, make sure its boot loader is signed first.",
            ))
        elif state == "unsupported":
            findings.append(finding(
                "win.secureboot.unsupported", "secureboot",
                "This PC boots in legacy BIOS mode, so Secure Boot is unavailable",
                Severity.MEDIUM,
                "Without UEFI boot, Secure Boot cannot verify the boot loader, leaving room for bootkits.",
                "If the firmware supports UEFI, the disk can be converted from MBR to GPT with Microsoft's mbr2gpt tool "
                "and the firmware switched to UEFI mode. Back up first; this is an advanced change.",
            ))
        return CheckOutput(evidence=evidence, findings=findings)
