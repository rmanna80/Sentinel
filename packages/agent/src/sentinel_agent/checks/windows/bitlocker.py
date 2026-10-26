"""System drive encryption (BitLocker / Device encryption)."""

from __future__ import annotations

import re
from typing import Any

from sentinel_core.checks import Check, CheckContext, SkipCheck
from sentinel_core.commands import CommandSpec, powershell
from sentinel_core.models import CheckOutput, Platform, Severity

from ...safe_commands import CommandFailed
from .._util import finding, is_home_edition

BITLOCKER_VOLUME = powershell(
    "ps.bitlocker_volume",
    # The agent starts PowerShell with a minimal environment (no SystemDrive), so the drive comes from the API.
    "$sd = [IO.Path]::GetPathRoot([Environment]::SystemDirectory).TrimEnd('\\'); "
    "Get-BitLockerVolume -MountPoint $sd -ErrorAction Stop | Select-Object MountPoint,"
    " @{n='VolumeStatus';e={[string]$_.VolumeStatus}}, @{n='ProtectionStatus';e={[string]$_.ProtectionStatus}},"
    " EncryptionPercentage, @{n='EncryptionMethod';e={[string]$_.EncryptionMethod}},"
    " @{n='LockStatus';e={[string]$_.LockStatus}},"
    " @{n='KeyProtector';e={,@($_.KeyProtector | ForEach-Object { [string]$_.KeyProtectorType })}}"
    " | ConvertTo-Json -Depth 3 -Compress",
)
# manage-bde ships on Home too. Its labels are localized; only English output is parsed.
MANAGE_BDE = CommandSpec("manage-bde.status", "manage-bde", ("-status", "C:"), timeout=30)

_LINE = re.compile(r"^\s*(Conversion Status|Percentage Encrypted|Protection Status|Encryption Method|"
                   r"Lock Status|BitLocker Version)\s*:\s*(.+?)\s*$", re.MULTILINE)


def parse_manage_bde(text: str) -> dict[str, str] | None:
    fields = {m.group(1): m.group(2) for m in _LINE.finditer(text)}
    if "Conversion Status" not in fields or "Protection Status" not in fields:
        return None
    return fields


class BitLockerEncryption(Check):
    id = "win.bitlocker"
    version = "1"
    title = "The system drive is encrypted"
    category = "configuration"
    platforms = frozenset({Platform.WINDOWS})
    requires_elevation = True
    timeout_seconds = 60.0
    data_collected = (
        "Encryption status, percentage, method, protection status and key protector types of the system "
        "drive (from Get-BitLockerVolume, or manage-bde -status C: when the BitLocker module is unavailable)"
    )
    commands = (BITLOCKER_VOLUME, MANAGE_BDE)

    def _remediation(self, ctx: CheckContext) -> str:
        if is_home_edition(ctx.host.edition):
            return ("Windows Home: open Settings > Privacy & security > Device encryption and turn it on (it needs a "
                    "Microsoft account to store the recovery key, plus TPM and Modern Standby support). If that page "
                    "is missing, this hardware does not support Device encryption; full BitLocker needs Windows Pro.")
        return ("Open Control Panel > System and Security > BitLocker Drive Encryption and turn BitLocker on for "
                "the system drive. Save the recovery key somewhere other than this PC.")

    def run(self, ctx: CheckContext) -> CheckOutput:
        source, raw, attempts = None, None, {}
        status: dict[str, Any] | None = None
        try:
            data = ctx.run_json(BITLOCKER_VOLUME)
            if isinstance(data, dict) and data.get("VolumeStatus"):
                status = {
                    "encrypted": data.get("VolumeStatus") == "FullyEncrypted",
                    "in_progress": data.get("VolumeStatus") == "EncryptionInProgress",
                    "protection_on": data.get("ProtectionStatus") == "On",
                    "percentage": data.get("EncryptionPercentage"),
                }
                source, raw = "Get-BitLockerVolume", data
            else:
                attempts["Get-BitLockerVolume"] = "unexpected output"
        except CommandFailed as exc:
            attempts["Get-BitLockerVolume"] = str(exc)[:200]
        if status is None:
            try:
                text = ctx.run(MANAGE_BDE).stdout
            except CommandFailed as exc:
                attempts["manage-bde"] = str(exc)[:200]
                raise SkipCheck("Drive encryption status could not be read: the BitLocker PowerShell module is not "
                                "available and manage-bde failed") from exc
            fields = parse_manage_bde(text)
            if fields is None:
                raise SkipCheck("Drive encryption status could not be read: manage-bde output was not recognised "
                                "(only English output is understood)")
            conversion = fields["Conversion Status"].lower()
            pct = re.match(r"([\d.,]+)", fields.get("Percentage Encrypted", ""))
            status = {
                "encrypted": conversion == "fully encrypted" or conversion.startswith("used space only encrypted"),
                "in_progress": "in progress" in conversion,
                "protection_on": fields["Protection Status"].lower().startswith("protection on"),
                "percentage": float(pct.group(1).replace(",", ".")) if pct else None,
            }
            source, raw = "manage-bde -status C:", fields
        evidence = [ctx.evidence("command_output", source or "", {"status": raw, "interpreted": status,
                                                                    "earlier_attempts": attempts})]
        findings = []
        if not status["encrypted"] and not status["in_progress"]:
            findings.append(finding(
                "win.bitlocker.not_encrypted", "volume:system",
                "The system drive is not encrypted",
                Severity.HIGH,
                "If this PC is lost or stolen, anyone can remove the drive and read every file on it, including "
                "saved browser sessions and documents.",
                self._remediation(ctx),
            ))
        elif not status["protection_on"]:
            findings.append(finding(
                "win.bitlocker.protection_off", "volume:system",
                "Drive encryption is suspended (protection is off)",
                Severity.HIGH,
                "The drive is encrypted but the key is stored in the clear, so the data is not protected. This "
                "is normal briefly during some updates but should not last.",
                "Resume protection: Control Panel > BitLocker Drive Encryption > Resume protection, or on Windows "
                "Home check Settings > Privacy & security > Device encryption.",
            ))
        return CheckOutput(evidence=evidence, findings=findings)
