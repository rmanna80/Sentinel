"""Local account password and lockout policy."""

from __future__ import annotations

import re

from sentinel_core.checks import Check, CheckContext, SkipCheck
from sentinel_core.commands import CommandSpec
from sentinel_core.models import CheckOutput, Confidence, FindingKind, Platform, Severity

from ...safe_commands import CommandFailed
from .._util import finding

NET_ACCOUNTS = CommandSpec("net.accounts", "net", ("accounts",), timeout=30)

_FIELD = re.compile(r"^(?P<label>[A-Za-z][^:]*?)(?:\?)?:\s+(?P<value>\S.*?)\s*$", re.MULTILINE)


def parse_net_accounts(text: str) -> dict[str, str]:
    return {m.group("label").strip(): m.group("value") for m in _FIELD.finditer(text)}


class PasswordPolicy(Check):
    id = "win.password_policy"
    version = "1"
    title = "Local accounts lock out after repeated wrong passwords"
    category = "configuration"
    platforms = frozenset({Platform.WINDOWS})
    data_collected = "The local password and lockout policy shown by `net accounts` (no account names or passwords)"
    commands = (NET_ACCOUNTS,)

    def run(self, ctx: CheckContext) -> CheckOutput:
        try:
            text = ctx.run(NET_ACCOUNTS).stdout
        except CommandFailed as exc:
            raise SkipCheck("The local password policy could not be read (net accounts failed)") from exc
        fields = parse_net_accounts(text)
        threshold = fields.get("Lockout threshold")
        min_length = fields.get("Minimum password length")
        if threshold is None or min_length is None:
            raise SkipCheck("net accounts output was not in English, so the policy could not be read reliably")
        evidence = [ctx.evidence("command_output", "net accounts", fields)]
        findings = []
        if threshold.strip().lower() == "never" or threshold.strip() == "0":
            findings.append(finding(
                "win.password_policy.no_lockout", "policy:lockout_threshold",
                "Local accounts never lock out after wrong passwords",
                Severity.LOW,
                "Someone at the keyboard, or reaching a network sign-in, can guess local account passwords "
                "without limit.",
                "Set a lockout threshold (Windows 11 now defaults to 10 attempts). On Pro: Local Security Policy > "
                "Account Lockout Policy. On Home, run `net accounts /lockoutthreshold:10` yourself in an "
                "administrator terminal.",
            ))
        findings.append(finding(
            "win.password_policy.microsoft_account_note", "policy:microsoft_account",
            "Microsoft-account sign-ins follow Microsoft's own password policy",
            Severity.INFO,
            "This local policy applies to local accounts. If you sign in with a Microsoft account, its password "
            "rules and lockout are set by Microsoft online; a PIN or Windows Hello sign-in has its own "
            "anti-hammering protection in the TPM.",
            "Protect the Microsoft account with a strong unique password and two-step verification.",
            kind=FindingKind.INFORMATIONAL, confidence=Confidence.HIGH,
        ))
        return CheckOutput(evidence=evidence, findings=findings)
