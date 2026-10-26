"""User Account Control configuration."""

from __future__ import annotations

from sentinel_core.checks import Check, CheckContext, SkipCheck
from sentinel_core.models import CheckOutput, Platform, Severity

from .._util import as_int, finding

UAC_KEY = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
PROMPT_BEHAVIOR = {
    0: "Elevate without prompting",
    1: "Prompt for credentials on the secure desktop",
    2: "Prompt for consent on the secure desktop",
    3: "Prompt for credentials",
    4: "Prompt for consent",
    5: "Prompt for consent for non-Windows binaries (default)",
}


class UacConfiguration(Check):
    id = "win.uac"
    version = "1"
    title = "User Account Control prompts before elevation"
    category = "configuration"
    platforms = frozenset({Platform.WINDOWS})
    data_collected = "EnableLUA, ConsentPromptBehaviorAdmin and PromptOnSecureDesktop registry values"

    def run(self, ctx: CheckContext) -> CheckOutput:
        values = {
            name: ctx.read_registry("HKLM", UAC_KEY, name, view="64")
            for name in ("EnableLUA", "ConsentPromptBehaviorAdmin", "PromptOnSecureDesktop")
        }
        if all(v is None for v in values.values()):
            raise SkipCheck("UAC policy registry key could not be read")
        evidence = [ctx.evidence("registry_value", f"HKLM\\{UAC_KEY}", values)]
        findings = []
        lua = as_int(values["EnableLUA"])
        behavior = as_int(values["ConsentPromptBehaviorAdmin"])
        if lua == 0:
            findings.append(finding(
                "win.uac.disabled", "uac:EnableLUA", "User Account Control is turned off",
                Severity.HIGH,
                "Every program runs with full administrator rights, so malware needs no prompt to change the system.",
                "Set EnableLUA to 1 (Control Panel > User Accounts > Change User Account Control settings), then restart.",
                references=["https://learn.microsoft.com/windows/security/application-security/application-control/user-account-control/"],
            ))
        elif behavior == 0:
            findings.append(finding(
                "win.uac.no_prompt", "uac:ConsentPromptBehaviorAdmin",
                "Administrators are elevated without any prompt",
                Severity.MEDIUM,
                "Programs started by an administrator can gain full rights silently.",
                "Move the UAC slider back to the default (\"Notify me only when apps try to make changes\").",
            ))
        if lua != 0 and as_int(values["PromptOnSecureDesktop"]) == 0:
            findings.append(finding(
                "win.uac.no_secure_desktop", "uac:PromptOnSecureDesktop",
                "UAC prompts are not shown on the secure desktop",
                Severity.LOW,
                "Other programs can interact with or imitate the elevation prompt.",
                "Use the default UAC level, which dims the screen for prompts.",
            ))
        return CheckOutput(evidence=evidence, findings=findings)
