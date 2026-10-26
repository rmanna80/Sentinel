"""Describe the machine the agent runs on."""

from __future__ import annotations

import os
import platform
import socket
import sys

from sentinel_core.models import HostInfo, Platform

from . import __version__

_EDITIONS = {
    "core": "Home",
    "coren": "Home N",
    "coresinglelanguage": "Home Single Language",
    "corecountryspecific": "Home China",
    "professional": "Pro",
    "professionaln": "Pro N",
    "professionalworkstation": "Pro for Workstations",
    "professionaleducation": "Pro Education",
    "enterprise": "Enterprise",
    "enterprises": "Enterprise LTSC",
    "education": "Education",
    "serverstandard": "Server Standard",
    "serverdatacenter": "Server Datacenter",
}


def is_elevated() -> bool:
    if sys.platform == "win32":
        try:
            import ctypes

            return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
        except Exception:
            return False
    return hasattr(os, "geteuid") and os.geteuid() == 0


def _windows_host() -> HostInfo:
    import winreg

    def val(name: str) -> object | None:
        try:
            with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion", 0,
                winreg.KEY_READ | winreg.KEY_WOW64_64KEY,
            ) as k:
                return winreg.QueryValueEx(k, name)[0]
        except OSError:
            return None

    build = str(val("CurrentBuild") or platform.version().split(".")[-1])
    ubr = val("UBR")
    edition_id = str(val("EditionID") or "")
    display_version = val("DisplayVersion")
    insider = False
    try:
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\WindowsSelfHost\Applicability", 0,
            winreg.KEY_READ | winreg.KEY_WOW64_64KEY,
        ) as k:
            insider = bool(winreg.QueryValueEx(k, "BranchName")[0])
    except OSError:
        insider = False
    build_num = int(build) if build.isdigit() else 0
    # ProductName still says "Windows 10" on Windows 11, so the build number decides.
    name = "Windows 11" if build_num >= 22000 else "Windows 10" if build_num >= 10240 else "Windows"
    version = f"{display_version} " if display_version else ""
    return HostInfo(
        hostname=socket.gethostname(),
        os_family=Platform.WINDOWS,
        os_name=name,
        os_version=f"{version}(build {build}{'.' + str(ubr) if ubr is not None else ''})".strip(),
        os_build=f"10.0.{build}.{ubr}" if ubr is not None else f"10.0.{build}",
        edition=_EDITIONS.get(edition_id.lower(), edition_id or None),
        arch=platform.machine() or "unknown",
        agent_version=__version__,
        is_elevated=is_elevated(),
        is_insider_build=insider,
    )


def parse_os_release(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in text.splitlines():
        if "=" not in line or line.startswith("#"):
            continue
        k, v = line.split("=", 1)
        out[k.strip()] = v.strip().strip('"').strip("'")
    return out


def _linux_host() -> HostInfo:
    info: dict[str, str] = {}
    for path in ("/etc/os-release", "/usr/lib/os-release"):
        try:
            with open(path, encoding="utf-8") as fh:
                info = parse_os_release(fh.read())
                break
        except OSError:
            continue
    return HostInfo(
        hostname=socket.gethostname(),
        os_family=Platform.LINUX,
        os_name=info.get("PRETTY_NAME", "Linux"),
        os_version=info.get("VERSION_ID", platform.release()),
        os_build=platform.release(),
        edition=None,
        arch=platform.machine() or "unknown",
        agent_version=__version__,
        is_elevated=is_elevated(),
        distro_id=info.get("ID"),
        distro_version=info.get("VERSION_ID"),
    )


def current_host() -> HostInfo:
    if sys.platform == "win32":
        return _windows_host()
    if sys.platform.startswith("linux"):
        return _linux_host()
    return HostInfo(
        hostname=socket.gethostname(),
        os_family=Platform.MACOS if sys.platform == "darwin" else Platform.LINUX,
        os_name=platform.system(),
        os_version=platform.release(),
        arch=platform.machine() or "unknown",
        agent_version=__version__,
        is_elevated=is_elevated(),
    )
