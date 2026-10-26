"""Resolve logical executable names to absolute paths.

Checks never name a binary directly. They name a logical tool, and this module maps it to
a fixed absolute location, so a planted ``powershell.exe`` or ``ss`` earlier on ``PATH``
is never executed.

On Windows the Windows and Program Files folders come from the operating system
(GetSystemWindowsDirectoryW and SHGetKnownFolderPath), never from the SystemRoot / ProgramFiles
environment variables: a standard user can override those per user, which matters when the agent
runs elevated.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

# KNOWNFOLDERID values (shlobj_core.h / knownfolders.h)
FOLDERID_PROGRAM_FILES = "{905e63b6-c1bf-494e-b29c-65b732d3d21a}"
FOLDERID_PROGRAM_FILES_X86 = "{7C5A40EF-A0FB-4BFC-874A-C0F2E0B9FA8E}"
FOLDERID_PROGRAM_DATA = "{62AB5D82-FDC1-4DC3-A9DD-070D1D495D97}"
FOLDERID_STARTUP = "{B97D20BB-F46A-4C97-BA10-5E3608430854}"


class ExecutableNotFound(Exception):
    pass


# --------------------------------------------------------------------------- Windows folders (ctypes, Windows only)


def _system_windows_directory() -> str:
    """GetSystemWindowsDirectoryW (kernel32): the system's Windows folder, not affected by the environment."""
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)  # type: ignore[attr-defined]
    fn = kernel32.GetSystemWindowsDirectoryW
    fn.argtypes = [wintypes.LPWSTR, wintypes.UINT]
    fn.restype = wintypes.UINT
    buf = ctypes.create_unicode_buffer(32768)
    n = fn(buf, len(buf))
    if n == 0 or n >= len(buf):
        raise OSError(ctypes.get_last_error(), "GetSystemWindowsDirectoryW failed")  # type: ignore[attr-defined]
    return buf.value


def _known_folder_path(folder_id: str) -> str:
    """SHGetKnownFolderPath (shell32) for a KNOWNFOLDERID; the returned string is freed with CoTaskMemFree."""
    import ctypes
    import uuid
    from ctypes import wintypes

    class GUID(ctypes.Structure):
        _fields_ = [("Data1", wintypes.DWORD), ("Data2", wintypes.WORD), ("Data3", wintypes.WORD),
                    ("Data4", ctypes.c_ubyte * 8)]

    guid = GUID.from_buffer_copy(uuid.UUID(folder_id).bytes_le)
    shell32 = ctypes.WinDLL("shell32")  # type: ignore[attr-defined]
    ole32 = ctypes.WinDLL("ole32")  # type: ignore[attr-defined]
    get_path = shell32.SHGetKnownFolderPath
    get_path.argtypes = [ctypes.POINTER(GUID), wintypes.DWORD, wintypes.HANDLE, ctypes.POINTER(ctypes.c_void_p)]
    get_path.restype = ctypes.c_long  # HRESULT
    free = ole32.CoTaskMemFree
    free.argtypes = [ctypes.c_void_p]
    free.restype = None
    ptr = ctypes.c_void_p()
    hr = get_path(ctypes.byref(guid), 0, None, ctypes.byref(ptr))
    try:
        if hr != 0 or not ptr.value:
            raise OSError(f"SHGetKnownFolderPath {folder_id} failed (HRESULT {hr & 0xFFFFFFFF:#010x})")
        return ctypes.wstring_at(ptr.value)
    finally:
        free(ptr)  # required even when the call fails; freeing NULL is a no-op


def windows_directory() -> Path | None:
    """The Windows folder (normally C:\\Windows) as the OS reports it, or None if it cannot be determined."""
    try:
        value = _system_windows_directory()
    except OSError:
        return None
    return Path(value) if value else None


def known_folder(folder_id: str) -> Path | None:
    """A Windows known folder (Program Files, ProgramData, Startup ...) as the OS reports it, or None."""
    try:
        value = _known_folder_path(folder_id)
    except OSError:
        return None
    return Path(value) if value else None


# --------------------------------------------------------------------------- tool locations


def _system32() -> Path | None:
    root = windows_directory()
    if root is None:
        return None
    # A 32-bit Python on 64-bit Windows is redirected away from System32; Sysnative reaches it.
    if sys.maxsize <= 2**32 and (root / "Sysnative").exists():
        return root / "Sysnative"
    return root / "System32"


def _windows_candidates(name: str) -> list[Path]:
    s32 = _system32()
    pf = known_folder(FOLDERID_PROGRAM_FILES)
    pf86 = known_folder(FOLDERID_PROGRAM_FILES_X86)
    system: dict[str, list[str]] = {
        "powershell": ["WindowsPowerShell", "v1.0", "powershell.exe"],
        "wevtutil": ["wevtutil.exe"],
        "netsh": ["netsh.exe"],
        "net": ["net.exe"],
        "manage-bde": ["manage-bde.exe"],
    }
    if name in system:
        return [s32.joinpath(*system[name])] if s32 is not None else []
    program_files: dict[str, list[tuple[Path | None, str, str]]] = {
        "nmap": [(pf86, "Nmap", "nmap.exe"), (pf, "Nmap", "nmap.exe")],
        "clamscan": [(pf, "ClamAV", "clamscan.exe"), (pf86, "ClamAV", "clamscan.exe")],
    }
    return [base / folder / exe for base, folder, exe in program_files.get(name, []) if base is not None]


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
