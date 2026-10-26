"""Installed software and operating system inventory (Windows)."""

from __future__ import annotations

from typing import Any

from sentinel_core.checks import Check, CheckContext, SkipCheck
from sentinel_core.models import CheckOutput, Platform, SoftwareItem

from .._util import as_int

UNINSTALL_KEY = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
SOURCES = (("HKLM", "64", "registry:HKLM64"), ("HKLM", "32", "registry:HKLM32"), ("HKCU", None, "registry:HKCU"))


def _text(value: Any, limit: int) -> str | None:
    if value is None:
        return None
    s = str(value).strip()
    return s[:limit] or None


class WindowsSoftwareInventory(Check):
    id = "win.software.inventory"
    version = "1"
    title = "Installed programs"
    category = "inventory"
    platforms = frozenset({Platform.WINDOWS})
    profiles = frozenset({"inventory"})
    timeout_seconds = 120.0
    data_collected = (
        "Name, version, publisher and install date of programs listed in the Uninstall registry keys "
        "(machine-wide 64- and 32-bit, and the current user's)"
    )

    def run(self, ctx: CheckContext) -> CheckOutput:
        items: dict[tuple[str, str | None], SoftwareItem] = {}
        counts: dict[str, dict[str, int]] = {}
        for hive, view, source in SOURCES:
            subkeys = ctx.list_registry_subkeys(hive, UNINSTALL_KEY, view=view)
            stat = counts.setdefault(source, {"subkeys": len(subkeys), "listed": 0, "skipped": 0})
            for sub in subkeys:
                if ctx.cancelled():
                    break
                values = ctx.read_registry_values(hive, f"{UNINSTALL_KEY}\\{sub}", view=view) or {}
                name = _text(values.get("DisplayName"), 512)
                if not name or as_int(values.get("SystemComponent")) == 1 or values.get("ParentKeyName"):
                    stat["skipped"] += 1
                    continue
                version = _text(values.get("DisplayVersion"), 256)
                key = (name, version)
                if key in items:
                    stat["skipped"] += 1
                    continue
                stat["listed"] += 1
                items[key] = SoftwareItem(
                    name=name, version=version, publisher=_text(values.get("Publisher"), 512),
                    ecosystem="windows-registry", source=source, install_date=_text(values.get("InstallDate"), 32),
                )
        if not any(c["subkeys"] for c in counts.values()):
            raise SkipCheck("The Uninstall registry keys could not be read")
        evidence = [ctx.evidence("registry_value", f"HKLM/HKCU\\{UNINSTALL_KEY}", {
            "per_source": counts,
            "programs": len(items),
            "note": "Entries without a display name, Windows components (SystemComponent=1) and updates that "
                    "belong to another program (ParentKeyName) are skipped; duplicates by name and version are "
                    "listed once.",
        })]
        software = sorted(items.values(), key=lambda s: (s.name.lower(), s.version or ""))
        return CheckOutput(evidence=evidence, software=software)


class WindowsOsInventory(Check):
    id = "win.os.inventory"
    version = "1"
    title = "Windows version"
    category = "inventory"
    platforms = frozenset({Platform.WINDOWS})
    profiles = frozenset({"inventory"})
    data_collected = "Windows name, edition, version and build number (already known to the agent)"

    def run(self, ctx: CheckContext) -> CheckOutput:
        host = ctx.host
        if not host.os_build:
            raise SkipCheck("The Windows build number is unknown")
        evidence = [ctx.evidence("metric", "host", {
            "os_name": host.os_name, "edition": host.edition, "os_version": host.os_version,
            "os_build": host.os_build, "is_insider_build": host.is_insider_build,
        })]
        item = SoftwareItem(name="Microsoft Windows", version=host.os_build, ecosystem="windows-os",
                            publisher="Microsoft", source="host")
        return CheckOutput(evidence=evidence, software=[item])
