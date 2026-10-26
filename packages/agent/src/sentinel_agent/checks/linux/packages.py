"""Installed Linux packages, tagged with the OSV ecosystem used for vulnerability matching."""

from __future__ import annotations

import re

from sentinel_core.checks import Check, CheckContext, SkipCheck
from sentinel_core.commands import CommandSpec
from sentinel_core.models import CheckOutput, HostInfo, Platform, SoftwareItem

from ...safe_commands import CommandFailed, CommandNotFound

# These contain "${...}" and "%{...}" but no "{lowercase_name}" placeholder, so CommandSpec leaves them alone
# (verified in tests). They are passed as one argument each, never through a shell.
# source:Package / source:Version: Debian and Ubuntu advisories (and OSV) are keyed by SOURCE package,
# e.g. libssl3 is built from "openssl", and a binNMU version "5.2.15-2+b8" has source version "5.2.15-2".
DPKG_FORMAT = "-f=${Package}\\t${Version}\\t${db:Status-Abbrev}\\t${source:Package}\\t${source:Version}\\n"
RPM_FORMAT = "%{NAME}\\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}\\n"
DPKG_QUERY = CommandSpec("dpkg-query.installed", "dpkg-query", ("-W", DPKG_FORMAT), timeout=60)
RPM_QUERY = CommandSpec("rpm.installed", "rpm", ("-qa", "--qf", RPM_FORMAT), timeout=90)

# Raspberry Pi archive builds carry these markers in their version strings (for example "+rpt1" or "+rpi1").
_PI_VERSION = re.compile(r"[+~]rp[it]\d")


def ubuntu_ecosystem(version: str) -> str:
    """OSV: "Ubuntu:<YY.MM>" with a mandatory ":LTS" suffix for LTS releases (even years, April)."""
    m = re.match(r"^(\d{2})\.(\d{2})", version)
    if m and int(m.group(1)) % 2 == 0 and m.group(2) == "04":
        return f"Ubuntu:{m.group(1)}.{m.group(2)}:LTS"
    return f"Ubuntu:{version}"


def ecosystem_for(host: HostInfo) -> tuple[str, str | None]:
    """(OSV ecosystem string, note). Unknown distributions keep a descriptive ecosystem the server will not match."""
    distro = (host.distro_id or "").lower()
    version = (host.distro_version or "").strip()
    if distro in ("debian", "raspbian"):
        major = version.split(".", 1)[0] or "unknown"
        note = None
        if distro == "raspbian" or "rpi" in (host.os_build or "") or "raspberry" in host.os_name.lower():
            note = ("Raspberry Pi OS: packages from archive.raspberrypi.com are matched against Debian advisories, "
                    "so results for those packages are lower confidence.")
        return f"Debian:{major}", note
    if distro == "ubuntu":
        return ubuntu_ecosystem(version), None
    if distro in ("almalinux", "rocky"):
        name = "AlmaLinux" if distro == "almalinux" else "Rocky Linux"
        return f"{name}:{version.split('.', 1)[0]}", None
    return f"{distro or 'linux'}:{version or 'unknown'}", "No vulnerability source is known for this distribution."


def parse_dpkg(text: str) -> tuple[list[tuple[str, str, str, str]], int]:
    """Installed ("ii") packages as (binary, version, source, source_version), plus the count of other entries.

    Output without the source columns (older recordings) falls back to the binary name and version.
    """
    out, other = [], 0
    for line in text.splitlines():
        parts = line.split("\t")
        if len(parts) < 3 or not parts[0]:
            continue
        if parts[2].strip() != "ii":
            other += 1
            continue
        name, version = parts[0].strip(), parts[1].strip()
        source = parts[3].strip() if len(parts) > 3 and parts[3].strip() else name
        source_version = parts[4].strip() if len(parts) > 4 and parts[4].strip() else version
        out.append((name, version, source, source_version))
    return out, other


def parse_rpm(text: str) -> list[tuple[str, str]]:
    out = []
    for line in text.splitlines():
        parts = line.split("\t")
        if len(parts) == 2 and parts[0] and parts[0] != "gpg-pubkey":
            out.append((parts[0].strip(), parts[1].strip()))
    return out


class LinuxPackages(Check):
    id = "linux.packages"
    version = "2"
    title = "Installed packages"
    category = "inventory"
    platforms = frozenset({Platform.LINUX})
    profiles = frozenset({"inventory"})
    timeout_seconds = 120.0
    data_collected = ("Names and versions of installed packages from dpkg (or rpm); on Debian and Ubuntu, "
                      "listed by source package as security advisories are")
    commands = (DPKG_QUERY, RPM_QUERY)

    def run(self, ctx: CheckContext) -> CheckOutput:
        ecosystem, note = ecosystem_for(ctx.host)
        tool, other = "dpkg-query", 0
        binary_to_source: dict[str, str] = {}
        try:
            rows, other = parse_dpkg(ctx.run(DPKG_QUERY).stdout)
            pkgs = [(src, src_ver) for _, _, src, src_ver in rows]
            binary_to_source = {b: src for b, _, src, _ in rows if b != src}
        except CommandNotFound:
            tool = "rpm"
            try:
                pkgs = parse_rpm(ctx.run(RPM_QUERY).stdout)
            except CommandNotFound as exc:
                raise SkipCheck("Neither dpkg nor rpm is installed, so packages cannot be listed") from exc
            except CommandFailed as exc:
                raise SkipCheck(f"rpm -qa failed: {str(exc)[:200]}") from exc
        except CommandFailed as exc:
            raise SkipCheck(f"dpkg-query failed: {str(exc)[:200]}") from exc
        unique = sorted(set(pkgs))
        pi_built = sorted(n for n, v in unique if _PI_VERSION.search(v))
        evidence = [ctx.evidence("command_output", tool, {
            "ecosystem": ecosystem,
            "installed": len(unique),
            "listed_by": "source package" if tool == "dpkg-query" else "package",
            "binary_packages_mapped_to_source": dict(sorted(binary_to_source.items())[:300]),
            "not_installed_entries": other,
            "note": note,
            "raspberry_pi_archive_versions": pi_built[:200],
            "distro_id": ctx.host.distro_id,
            "distro_version": ctx.host.distro_version,
        })]
        software = [SoftwareItem(name=n, version=v, ecosystem=ecosystem, source=tool) for n, v in unique]
        return CheckOutput(evidence=evidence, software=software)
