"""Small registry-based hardening checks: LSA protection and SmartScreen."""

from __future__ import annotations

from sentinel_core.checks import Check, CheckContext
from sentinel_core.models import CheckOutput, Platform, Severity

from .._util import as_int, finding

LSA_KEY = r"SYSTEM\CurrentControlSet\Control\Lsa"
EXPLORER_KEY = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer"
SMARTSCREEN_POLICY_KEY = r"SOFTWARE\Policies\Microsoft\Windows\System"


class LsaProtection(Check):
    id = "win.lsa_protection"
    version = "1"
    title = "LSA protection guards stored credentials"
    category = "configuration"
    platforms = frozenset({Platform.WINDOWS})
    data_collected = "The RunAsPPL, RunAsPPLBoot and LsaCfgFlags values of the LSA registry key"

    def run(self, ctx: CheckContext) -> CheckOutput:
        values = {n: ctx.read_registry("HKLM", LSA_KEY, n, view="64") for n in ("RunAsPPL", "RunAsPPLBoot", "LsaCfgFlags")}
        evidence = [ctx.evidence("registry_value", f"HKLM\\{LSA_KEY}", {
            **values,
            "meaning": "RunAsPPL 1 = on with UEFI lock, 2 = on without UEFI lock, absent or 0 = off. "
                       "LsaCfgFlags controls Credential Guard and is recorded for context only.",
        })]
        findings = []
        if as_int(values["RunAsPPL"]) not in (1, 2):
            findings.append(finding(
                "win.lsa_protection.off", "lsa:RunAsPPL",
                "Local Security Authority (LSA) protection is off",
                Severity.LOW,
                "Without LSA protection, a program running as administrator can read credentials held in memory "
                "by the LSA process (a common step in credential-theft tools).",
                "Open Windows Security > Device security > Core isolation details and turn on Local Security "
                "Authority protection, then restart. If a driver blocks it, update or remove that driver first.",
                references=["https://learn.microsoft.com/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection"],
            ))
        return CheckOutput(evidence=evidence, findings=findings)


class SmartScreen(Check):
    id = "win.smartscreen"
    version = "1"
    title = "SmartScreen checks downloaded apps"
    category = "configuration"
    platforms = frozenset({Platform.WINDOWS})
    data_collected = (
        "The SmartScreenEnabled value under Explorer settings and the EnableSmartScreen group policy value"
    )

    def run(self, ctx: CheckContext) -> CheckOutput:
        explorer = ctx.read_registry("HKLM", EXPLORER_KEY, "SmartScreenEnabled", view="64")
        policy = ctx.read_registry("HKLM", SMARTSCREEN_POLICY_KEY, "EnableSmartScreen", view="64")
        notes = []
        if explorer is None:
            notes.append("SmartScreenEnabled is absent, which means the Windows default (on).")
        if policy is None:
            notes.append("No EnableSmartScreen policy is set, so the user setting applies.")
        evidence = [ctx.evidence("registry_value", f"HKLM\\{EXPLORER_KEY}; HKLM\\{SMARTSCREEN_POLICY_KEY}", {
            "SmartScreenEnabled": explorer, "EnableSmartScreen_policy": policy, "notes": notes,
        })]
        off_by_setting = str(explorer).strip().lower() == "off"
        off_by_policy = as_int(policy) == 0
        findings = []
        if off_by_setting or off_by_policy:
            how = "by group policy" if off_by_policy else "in Windows settings"
            findings.append(finding(
                "win.smartscreen.off", "smartscreen:apps",
                f"SmartScreen for apps and files is turned off {how}",
                Severity.MEDIUM,
                "Windows no longer warns before running downloaded programs that are unknown or reported as "
                "malicious.",
                "Open Windows Security > App & browser control > Reputation-based protection and turn on "
                "\"Check apps and files\"."
                + (" The policy must be changed in the Local Group Policy Editor (or removed by whatever tool "
                   "set it)." if off_by_policy else ""),
            ))
        return CheckOutput(evidence=evidence, findings=findings)
