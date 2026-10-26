"""Linux host firewall and local accounts."""

from __future__ import annotations

import re

from sentinel_core.checks import Check, CheckContext, SkipCheck
from sentinel_core.commands import CommandSpec
from sentinel_core.models import CheckOutput, Platform, Severity

from ...context import PathNotAllowed
from ...safe_commands import CommandFailed, CommandNotFound
from .._util import finding

UFW_STATUS = CommandSpec("ufw.status", "ufw", ("status",), timeout=30)
NFT_RULESET = CommandSpec("nft.list_ruleset", "nft", ("list", "ruleset"), timeout=30)
_STATUS = re.compile(r"^Status:\s*(active|inactive)\b", re.MULTILINE | re.IGNORECASE)
_TABLE = re.compile(r"^table\s+(\S+)\s+(\S+)", re.MULTILINE)
_RULE_HINT = re.compile(r"\b(accept|drop|reject|jump|goto|policy drop)\b")

_FIREWALL_FIX = (
    "Turn on a host firewall yourself. The simplest is ufw: `sudo apt install ufw`, then `sudo ufw allow "
    "OpenSSH` (so you are not locked out), then `sudo ufw enable`."
)


class LinuxFirewall(Check):
    id = "linux.firewall"
    version = "1"
    title = "A host firewall is active"
    category = "configuration"
    platforms = frozenset({Platform.LINUX})
    requires_elevation = True
    data_collected = "Whether ufw is active (`ufw status`), or else the nftables ruleset (`nft list ruleset`)"
    commands = (UFW_STATUS, NFT_RULESET)

    def run(self, ctx: CheckContext) -> CheckOutput:
        ufw_state: str | None = None
        ufw_note = None
        try:
            m = _STATUS.search(ctx.run(UFW_STATUS).stdout)
            if m:
                ufw_state = m.group(1).lower()
            else:
                ufw_note = "ufw output not recognised"
        except CommandNotFound:
            ufw_note = "ufw is not installed"
        except CommandFailed as exc:
            ufw_note = f"ufw status failed: {(exc.stderr or str(exc)).strip()[:200]}"

        if ufw_state is not None:
            evidence = [ctx.evidence("command_output", "ufw status", {"ufw": ufw_state})]
            findings = []
            if ufw_state == "inactive":
                findings.append(finding(
                    "linux.firewall.inactive", "firewall:host", "The ufw firewall is installed but inactive",
                    Severity.MEDIUM,
                    "Every listening service is reachable by any device that can reach this machine.",
                    "Allow the services you need (at least `sudo ufw allow OpenSSH`), then run `sudo ufw enable`.",
                ))
            return CheckOutput(evidence=evidence, findings=findings)

        try:
            ruleset = ctx.run(NFT_RULESET).stdout
        except CommandNotFound as exc:
            raise SkipCheck(f"No firewall tool to inspect ({ufw_note}; nft is not installed either)") from exc
        except CommandFailed as exc:
            raise SkipCheck(f"The firewall state could not be read ({ufw_note}; nft failed: {str(exc)[:120]})") from exc
        tables = [f"{fam} {name}" for fam, name in _TABLE.findall(ruleset)]
        has_rules = bool(ruleset.strip()) and bool(_RULE_HINT.search(ruleset))
        evidence = [ctx.evidence("command_output", "nft list ruleset", {
            "ufw": ufw_note, "nft_tables": tables, "nft_has_rules": has_rules, "ruleset_bytes": len(ruleset),
            "note": "A non-empty nftables ruleset counts as configured. Rules added by Docker or similar tools "
                    "also count, even though they may not filter inbound traffic.",
        })]
        findings = []
        if not has_rules:
            findings.append(finding(
                "linux.firewall.inactive", "firewall:host", "No host firewall rules are configured",
                Severity.MEDIUM,
                "Every listening service is reachable by any device that can reach this machine.",
                _FIREWALL_FIX,
            ))
        return CheckOutput(evidence=evidence, findings=findings)


NO_LOGIN_SHELLS = ("/usr/sbin/nologin", "/sbin/nologin", "/bin/false", "/usr/bin/false", "/bin/sync", "")


class LinuxAccounts(Check):
    id = "linux.accounts"
    version = "1"
    title = "Only root has administrator user id 0"
    category = "configuration"
    platforms = frozenset({Platform.LINUX})
    data_collected = "User names, user ids and login shells from /etc/passwd (no password hashes; /etc/shadow is never read)"

    def run(self, ctx: CheckContext) -> CheckOutput:
        try:
            text = ctx.read_text("/etc/passwd")
        except (OSError, PathNotAllowed) as exc:
            raise SkipCheck("/etc/passwd could not be read") from exc
        accounts = []
        for line in text.splitlines():
            if not line.strip() or line.startswith(("#", "+", "-")):
                continue
            parts = line.split(":")
            if len(parts) < 7:
                continue
            accounts.append({"name": parts[0], "uid": parts[2], "gid": parts[3], "home": parts[5], "shell": parts[6]})
        if not accounts:
            raise SkipCheck("/etc/passwd had no readable entries")
        login = [a for a in accounts if a["shell"] not in NO_LOGIN_SHELLS]
        uid0 = [a for a in accounts if a["uid"] == "0" and a["name"] != "root"]
        evidence = [ctx.evidence("file_metadata", "/etc/passwd", {
            "accounts": len(accounts),
            "login_shell_accounts": [{k: a[k] for k in ("name", "uid", "shell")} for a in login],
            "uid0_accounts": [a["name"] for a in accounts if a["uid"] == "0"],
        })]
        findings = [finding(
            "linux.accounts.extra_uid0", f"account:{a['name']}",
            f"Account {a['name']} has user id 0 (full root rights)",
            Severity.HIGH,
            "Any account with user id 0 is root under another name. Attackers add such accounts as a hidden "
            "backdoor.",
            f"If you did not create {a['name']} on purpose, treat the machine as compromised. Otherwise give it its "
            "own user id and use sudo for administration.",
        ) for a in uid0]
        return CheckOutput(evidence=evidence, findings=findings)
