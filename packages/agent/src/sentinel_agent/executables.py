"""Resolve logical executable names to absolute paths.

Checks never name a binary directly. They name a logical tool, and this module maps it to
a fixed absolute location, so a planted ``powershell.exe`` or ``ss`` earlier on ``PATH``
is never executed.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path


class ExecutableNotFound(Exception):
    pass


def _system32() -> Path:
    root = Path(os.environ.get("SystemRoot", r"C:\Windows"))
    # A 32-bit Python on 64-bit Windows is redirected away from System32; Sysnative reaches it.
    if sys.maxsize <= 2**32 and (root / "Sysnative").exists():
        return root / "Sysnative"
    return root / "System32"


def _windows_candidates(name: str) -> list[Path]:
    s32 = _system32()
    pf = Path(os.environ.get("ProgramFiles", r"C:\Program Files"))
    pf86 = Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"))
    table: dict[str, list[Path]] = {
        "powershell": [s32 / "WindowsPowerShell" / "v1.0" / "powershell.exe"],
        "wevtutil": [s32 / "wevtutil.exe"],
        "netsh": [s32 / "netsh.exe"],
        "net": [s32 / "net.exe"],
        "manage-bde": [s32 / "manage-bde.exe"],
        "nmap": [pf86 / "Nmap" / "nmap.exe", pf / "Nmap" / "nmap.exe"],
        "clamscan": [pf / "ClamAV" / "clamscan.exe", pf86 / "ClamAV" / "clamscan.exe"],
    }
    return table.get(name, [])


_LINUX_TOOLS = frozenset(
    {
        "journalctl", "dpkg-query", "rpm", "apt", "ss", "systemctl", "ufw", "nft", "sshd",
        "nmap", "clamscan", "lsblk", "findmnt", "ip", "resolvectl", "iptables", "getent",
        "last", "lastb", "who",
    }
)
_LINUX_DIRS = ("/usr/bin", "/usr/sbin", "/bin", "/sbin", "/usr/local/bin")


def resolve(name: str) -> str:
    if sys.platform == "win32":
        for candidate in _windows_candidates(name):
            if candidate.is_file():
                return str(candidate)
        raise ExecutableNotFound(f"{name} is not installed in its expected location")
    if name not in _LINUX_TOOLS:
        raise ExecutableNotFound(f"{name} is not an allowed tool")
    for d in _LINUX_DIRS:
        p = Path(d) / name
        if p.is_file() and os.access(p, os.X_OK):
            return str(p)
    raise ExecutableNotFound(f"{name} is not installed")


def is_available(name: str) -> bool:
    try:
        resolve(name)
        return True
    except ExecutableNotFound:
        return False
