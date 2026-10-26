"""Pending APT updates, restart-required flag and automatic security updates (Debian, Ubuntu, Raspberry Pi OS)."""

from __future__ import annotations

import re

from sentinel_core.checks import Check, CheckContext, NotApplicable, SkipCheck
from sentinel_core.commands import CommandSpec
from sentinel_core.models import CheckOutput, Platform, Severity

from ...context import PathNotAllowed
from ...safe_commands import CommandFailed, CommandNotFound
from .._util import finding

# Reads APT's cached package lists; it does not refresh them (that would be `apt update`, a write).
APT_UPGRADABLE = CommandSpec("apt.list_upgradable", "apt", ("list", "--upgradable"), timeout=60)
REBOOT_REQUIRED = "/var/run/reboot-required"
REBOOT_PKGS = "/var/run/reboot-required.pkgs"
MANY_SECURITY_UPDATES = 20

# "openssl/bookworm-security 3.0.15-1~deb12u1 arm64 [upgradable from: 3.0.14-1~deb12u2]"
_LINE = re.compile(r"^(?P<pkg>[^\s/]+)/(?P<suites>\S+)\s+(?P<version>\S+)\s+(?P<arch>\S+)"
                   r"(?:\s+\[upgradable from:\s*(?P<old>[^\]]+)\])?")


def parse_apt_upgradable(text: str) -> list[dict[str, str | bool | None]]:
    out: list[dict[str, str | bool | None]] = []
    for line in text.splitlines():
        m = _LINE.match(line.strip())
        if not m:
            continue  # "Listing..." header and blank lines
        suites = m.group("suites")
        out.append({
            "package": m.group("pkg"), "suites": suites, "version": m.group("version"), "arch": m.group("arch"),
            "from": (m.group("old") or "").strip() or None,
            "security": any("-security" in s for s in suites.split(",")),
        })
    return out


class LinuxUpdates(Check):
    id = "linux.updates"
    version = "1"
    title = "Package updates are installed"
    category = "configuration"
    platforms = frozenset({Platform.LINUX})
    timeout_seconds = 90.0
    data_collected = (
        "Names, versions and source suites of packages with an available update (from APT's cached lists), "
        "and whether the system flags that a restart is required (with the packages that asked for it)"
    )
    commands = (APT_UPGRADABLE,)

    def run(self, ctx: CheckContext) -> CheckOutput:
        try:
            result = ctx.run(APT_UPGRADABLE)
        except CommandNotFound as exc:
            raise SkipCheck("APT is not installed, so pending updates cannot be listed (only Debian-based systems "
                            "are supported)") from exc
        except CommandFailed as exc:
            raise SkipCheck(f"apt list --upgradable failed: {str(exc)[:200]}") from exc
        updates = parse_apt_upgradable(result.stdout)
        security = [u for u in updates if u["security"]]
        reboot = ctx.path_exists(REBOOT_REQUIRED)
        reboot_pkgs: list[str] = []
        if reboot:
            try:
                reboot_pkgs = sorted({ln.strip() for ln in ctx.read_text(REBOOT_PKGS).splitlines() if ln.strip()})
            except (OSError, PathNotAllowed):
                reboot_pkgs = []
        evidence = [ctx.evidence("command_output", "apt list --upgradable", {
            "upgradable": updates,
            "security_updates": len(security),
            "other_updates": len(updates) - len(security),
            "reboot_required": reboot,
            "reboot_required_packages": reboot_pkgs,
            "note": "Based on APT's package lists as of the last `apt update` (run automatically by the daily "
                    "APT timer on most systems). Sentinel does not refresh them.",
        })]
        findings = []
        if security:
            names = ", ".join(sorted(str(u["package"]) for u in security)[:10])
            more = f" and {len(security) - 10} more" if len(security) > 10 else ""
            findings.append(finding(
                "linux.updates.security_pending", "apt:security",
                f"{len(security)} security update{'s' if len(security) != 1 else ''} not installed",
                Severity.HIGH if len(security) > MANY_SECURITY_UPDATES else Severity.MEDIUM,
                f"Fixes for published vulnerabilities are available but not installed: {names}{more}.",
                "Run `sudo apt update && sudo apt full-upgrade` yourself, then restart if asked. Consider enabling "
                "unattended-upgrades for security updates.",
            ))
        elif updates:
            findings.append(finding(
                "linux.updates.pending", "apt:other",
                f"{len(updates)} package update{'s' if len(updates) != 1 else ''} not installed",
                Severity.LOW,
                "Updates that are not marked as security fixes are available. Some still fix bugs that matter "
                "for security (for example on the Raspberry Pi archive, which has no separate security suite).",
                "Run `sudo apt update && sudo apt full-upgrade` yourself when convenient.",
            ))
        if reboot:
            pk = f" ({', '.join(reboot_pkgs[:8])}{'...' if len(reboot_pkgs) > 8 else ''})" if reboot_pkgs else ""
            findings.append(finding(
                "linux.updates.restart_required", "reboot-required",
                "A restart is required to finish installing updates",
                Severity.LOW,
                f"Updated components{pk} keep running their old, possibly vulnerable version until the system "
                "restarts.",
                "Restart the machine when convenient (`sudo reboot`).",
            ))
        return CheckOutput(evidence=evidence, findings=findings)


# --------------------------------------------------------------------------- unattended-upgrades

APT_CONF_DIR = "/etc/apt/apt.conf.d"
_UU = re.compile(r'^\s*APT::Periodic::Unattended-Upgrade\s+"(?P<v>[^"]*)"\s*;', re.MULTILINE | re.IGNORECASE)


class UnattendedUpgrades(Check):
    id = "linux.unattended_upgrades"
    version = "1"
    title = "Security updates install automatically"
    category = "configuration"
    platforms = frozenset({Platform.LINUX})
    data_collected = "The APT::Periodic::Unattended-Upgrade setting from the files in /etc/apt/apt.conf.d"

    def run(self, ctx: CheckContext) -> CheckOutput:
        try:
            names = ctx.list_dir(APT_CONF_DIR)
        except FileNotFoundError as exc:
            raise NotApplicable("APT is not used on this system") from exc
        except (OSError, PathNotAllowed) as exc:
            raise SkipCheck("/etc/apt/apt.conf.d could not be read") from exc
        # APT reads the directory in alphabetical order and a later assignment overrides an earlier one.
        effective, set_in = None, None
        for name in sorted(names):
            if name.startswith(".") or name.endswith((".dpkg-old", ".dpkg-dist", ".bak", "~")):
                continue
            try:
                text = ctx.read_text(f"{APT_CONF_DIR}/{name}")
            except (OSError, PathNotAllowed) as exc:
                # APT still reads it, and it may override the setting; the effective value is unknown.
                raise SkipCheck(f"{APT_CONF_DIR}/{name} could not be read") from exc
            for m in _UU.finditer(text):
                effective, set_in = m.group("v"), name
        evidence = [ctx.evidence("file_metadata", APT_CONF_DIR, {
            "Unattended-Upgrade": effective, "set_in": set_in,
            "unattended_upgrades_config_present": "50unattended-upgrades" in names,
        })]
        findings = []
        if effective is None or effective.strip() in ("", "0"):
            findings.append(finding(
                "linux.unattended_upgrades.off", "apt:unattended-upgrade",
                "Security updates are not installed automatically",
                Severity.LOW,
                "Security fixes wait until someone runs an upgrade by hand, which is easy to forget on a "
                "headless machine like a Raspberry Pi.",
                "Install and enable it yourself: `sudo apt install unattended-upgrades` then "
                "`sudo dpkg-reconfigure -plow unattended-upgrades` and answer Yes.",
            ))
        return CheckOutput(evidence=evidence, findings=findings)
