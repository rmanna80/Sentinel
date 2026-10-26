"""The live CheckContext: the only door a check has to the machine."""

from __future__ import annotations

import os
import sys
import threading
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

from pydantic import BaseModel
from sentinel_core.checks import AgentState
from sentinel_core.commands import CommandSpec
from sentinel_core.models import Evidence, HostInfo, utcnow

from .probe import PsutilProbe
from .safe_commands import CommandResult, SafeCommandRunner, parse_json_output


class PathNotAllowed(Exception):
    pass


_LINUX_READ_ROOTS = ("/etc/", "/proc/", "/sys/", "/run/", "/var/run/", "/var/lib/dpkg/", "/usr/lib/os-release")
_DENY_SUFFIXES = ("_key", ".key", ".pem", "shadow", "gshadow", "shadow-", "gshadow-")


def _windows_read_roots() -> list[str]:
    roots = [
        os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "drivers", "etc"),
        os.path.join(os.environ.get("ProgramData", r"C:\ProgramData"), "Microsoft", "Windows", "Start Menu",
                     "Programs", "StartUp"),
        os.path.join(os.environ.get("APPDATA", ""), "Microsoft", "Windows", "Start Menu", "Programs", "Startup"),
    ]
    return [r for r in roots if r]


class Recorder:
    """Captures raw command output and registry reads so a live run can become test fixtures."""

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.commands: dict[str, dict[str, Any]] = {}
        self.registry: dict[str, Any] = {}
        self.files: dict[str, str] = {}

    def command(self, spec: CommandSpec, result: CommandResult) -> None:
        with self.lock:
            self.commands[spec.name] = {"exit_code": result.exit_code, "stdout": result.stdout}

    def registry_read(self, key: str, value: Any) -> None:
        with self.lock:
            self.registry[key] = value

    def file_read(self, path: str, text: str) -> None:
        with self.lock:
            self.files[path] = text


def registry_key(hive: str, path: str, name: str | None, view: str | None) -> str:
    return f"{hive}\\{path}::{name or ''}::{view or ''}"


class LiveContext:
    def __init__(
        self,
        host: HostInfo,
        runner: SafeCommandRunner,
        state: AgentState,
        config: Mapping[str, Any],
        cancelled: Callable[[], bool],
        params: BaseModel | None = None,
        recorder: Recorder | None = None,
    ) -> None:
        self.host = host
        self.params = params
        self.state = state
        self.config = config
        self._runner = runner
        self._cancelled = cancelled
        self._recorder = recorder
        self.system = PsutilProbe(recorder)

    # ------------------------------------------------------------------ commands
    def cancelled(self) -> bool:
        return self._cancelled()

    def run(self, spec: CommandSpec, **params: object) -> CommandResult:
        return self._runner.run(spec, **params)

    def run_json(self, spec: CommandSpec, **params: object) -> Any:
        return parse_json_output(spec.name, self.run(spec, **params).stdout)

    # ------------------------------------------------------------------ registry (read-only)
    def _open(self, hive: str, path: str, view: str | None) -> Any:
        import winreg

        roots = {"HKLM": winreg.HKEY_LOCAL_MACHINE, "HKCU": winreg.HKEY_CURRENT_USER, "HKU": winreg.HKEY_USERS}
        access = winreg.KEY_READ
        if view == "64":
            access |= winreg.KEY_WOW64_64KEY
        elif view == "32":
            access |= winreg.KEY_WOW64_32KEY
        return winreg.OpenKey(roots[hive], path, 0, access)

    def read_registry(self, hive: str, path: str, name: str, view: str | None = None) -> Any:
        if sys.platform != "win32":
            return None
        import winreg

        try:
            with self._open(hive, path, view) as key:
                value = winreg.QueryValueEx(key, name)[0]
        except OSError:
            value = None
        value = _registry_value(value)
        if self._recorder:
            self._recorder.registry_read(registry_key(hive, path, name, view), value)
        return value

    def read_registry_values(self, hive: str, path: str, view: str | None = None) -> dict[str, Any] | None:
        if sys.platform != "win32":
            return None
        import winreg

        try:
            with self._open(hive, path, view) as key:
                out: dict[str, Any] = {}
                i = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(key, i)
                    except OSError:
                        break
                    out[name] = _registry_value(value)
                    i += 1
        except OSError:
            out = None  # type: ignore[assignment]
        if self._recorder:
            self._recorder.registry_read(registry_key(hive, path, "*", view), out)
        return out

    def list_registry_subkeys(self, hive: str, path: str, view: str | None = None) -> list[str]:
        if sys.platform != "win32":
            return []
        import winreg

        names: list[str] = []
        try:
            with self._open(hive, path, view) as key:
                i = 0
                while True:
                    try:
                        names.append(winreg.EnumKey(key, i))
                    except OSError:
                        break
                    i += 1
        except OSError:
            names = []
        if self._recorder:
            self._recorder.registry_read(registry_key(hive, path, "<subkeys>", view), names)
        return names

    # ------------------------------------------------------------------ files (read-only, allowlisted)
    def _allowed(self, path: str) -> str:
        resolved = str(Path(path).resolve())
        lower = resolved.lower()
        if any(lower.endswith(s) for s in _DENY_SUFFIXES):
            raise PathNotAllowed(f"{path} is never read")
        extra = [*self.config.get("project_paths", []), *self.config.get("malware_scan_paths", [])]
        if sys.platform == "win32":
            roots = [str(Path(r).resolve()).lower() for r in [*_windows_read_roots(), *extra]]
            if any(lower == r or lower.startswith(r.rstrip("\\") + "\\") for r in roots):
                return resolved
        else:
            roots = [*_LINUX_READ_ROOTS, *[str(Path(p).resolve()).rstrip("/") + "/" for p in extra]]
            if any(resolved == r.rstrip("/") or resolved.startswith(r) for r in roots):
                return resolved
        raise PathNotAllowed(f"{path} is outside the folders checks may read")

    def read_text(self, path: str, max_bytes: int = 2_000_000) -> str:
        resolved = self._allowed(path)
        with open(resolved, "rb") as fh:
            data = fh.read(max_bytes + 1)
        if len(data) > max_bytes:
            data = data[:max_bytes]
        text = data.decode("utf-8", errors="replace")
        if self._recorder:
            self._recorder.file_read(path, text)
        return text

    def path_exists(self, path: str) -> bool:
        try:
            return os.path.exists(self._allowed(path))
        except PathNotAllowed:
            return False

    def list_dir(self, path: str) -> list[str]:
        resolved = self._allowed(path)
        try:
            names = sorted(os.listdir(resolved))
        except OSError:
            names = []
        if self._recorder:
            self._recorder.file_read(path + "::<listdir>", "\n".join(names))
        return names

    # ------------------------------------------------------------------ evidence
    def evidence(self, kind: str, source: str, content: Any) -> Evidence:
        return Evidence(kind=kind, source=source, content=content, collected_at=utcnow())


def _registry_value(value: Any) -> Any:
    if isinstance(value, bytes):
        return value.hex()
    return value
