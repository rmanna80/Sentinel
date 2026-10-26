"""Programs that start automatically at sign-in."""

from __future__ import annotations

import os
import re
from typing import Any

from sentinel_core.checks import Check, CheckContext
from sentinel_core.models import CheckOutput, Confidence, FindingKind, Platform, Severity

from ...context import PathNotAllowed
from .._util import finding, join_path, windows_temp_like

RUN_KEYS = (r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce")
LOCATIONS = (("HKLM", "64"), ("HKLM", "32"), ("HKCU", None))
STARTUP_SUBPATH = ("Microsoft", "Windows", "Start Menu", "Programs")

_POWERSHELL = re.compile(r"(?i)\b(powershell|pwsh)(\.exe)?\b")
_SCRIPT_HOST_URL = re.compile(r"(?i)\b(mshta|wscript|cscript)(\.exe)?\b.*\bhttps?://")
_MSHTA = re.compile(r"(?i)\bmshta(\.exe)?\b")


def _uses_encoded_command(command: str) -> bool:
    """powershell.exe accepts any prefix of -EncodedCommand (-e, -en, -enc ...) and the alias -ec."""
    if not _POWERSHELL.search(command):
        return False
    for token in command.split():
        if token[:1] in ("-", "/") and len(token) > 1:
            flag = token[1:].lower()
            if flag == "ec" or "encodedcommand".startswith(flag):
                return True
    return False


def suspicious_reason(command: str) -> str | None:
    """Why a startup command looks suspicious, or None. Heuristic only."""
    if _uses_encoded_command(command):
        return "runs an encoded PowerShell command, which hides what it does"
    if _SCRIPT_HOST_URL.search(command):
        return "runs a script host (mshta/wscript/cscript) against a web address"
    if _MSHTA.search(command):
        return "uses mshta, which is rarely needed by legitimate startup programs"
    where = windows_temp_like(command)
    if where:
        return f"starts a program from {where}, a folder installers do not normally run programs from"
    return None


def startup_folders() -> list[tuple[str, str]]:
    """The all-users and per-user Startup folders, taken from the environment at run time."""
    out = []
    program_data = os.environ.get("ProgramData")
    app_data = os.environ.get("APPDATA")
    if program_data:
        out.append(("all_users", join_path(program_data, *STARTUP_SUBPATH, "StartUp")))
    if app_data:
        out.append(("current_user", join_path(app_data, *STARTUP_SUBPATH, "Startup")))
    return out


class StartupPrograms(Check):
    id = "win.startup"
    version = "1"
    title = "Programs that start automatically look legitimate"
    category = "threat"
    platforms = frozenset({Platform.WINDOWS})
    data_collected = (
        "Names and command lines of programs registered under the Run and RunOnce registry keys (machine-wide, "
        "32- and 64-bit, and for the current user) and the file names in the two Startup folders"
    )

    def run(self, ctx: CheckContext) -> CheckOutput:
        entries: list[dict[str, Any]] = []
        for hive, view in LOCATIONS:
            for key in RUN_KEYS:
                values = ctx.read_registry_values(hive, key, view=view) or {}
                for name, command in values.items():
                    if not name and command in (None, ""):
                        continue
                    where = f"{hive}{view or ''}\\{key.rsplit(chr(92), 1)[-1]}"
                    entries.append({"location": where, "name": name or "(Default)", "command": str(command)})
        folder_errors: dict[str, str] = {}
        for scope, folder in startup_folders():
            try:
                names = ctx.list_dir(folder)
            except (PathNotAllowed, OSError) as exc:
                folder_errors[folder] = str(exc)[:200]
                continue
            for name in names:
                if name.lower() == "desktop.ini":
                    continue
                entries.append({"location": f"StartupFolder:{scope}", "name": name,
                                "command": join_path(folder, name)})

        evidence = [ctx.evidence("registry_value", "Run/RunOnce keys and Startup folders", {
            "entries": entries,
            "startup_folder_errors": folder_errors,
            "note": "A shortcut (.lnk) in a Startup folder is listed by name; its target is not read.",
        })]
        findings = []
        for e in entries:
            reason = suspicious_reason(e["command"])
            if reason is None:
                continue
            findings.append(finding(
                "win.startup.suspicious_entry", f"startup:{e['location']}:{e['name']}".lower(),
                f"Startup entry \"{e['name']}\" {reason.split(',')[0]}",
                Severity.MEDIUM,
                f"The entry {reason}. Malware commonly persists this way, but some legitimate updaters and "
                "installers do it too, so this is a lead to check, not proof of infection.",
                "Look up the program name and publisher. If you do not recognise it, disable it in Task Manager > "
                "Startup apps and run a full Microsoft Defender scan. Sentinel does not change startup entries.",
                kind=FindingKind.HEURISTIC, confidence=Confidence.MEDIUM, category="threat",
            ))
        return CheckOutput(evidence=evidence, findings=findings)
