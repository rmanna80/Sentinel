"""The only code in the agent that starts processes."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Any

from sentinel_core.commands import CommandSpec

from .executables import ExecutableNotFound, resolve


class CommandRefused(Exception):
    """The spec was not registered by any check, so it is never run."""


class CommandFailed(Exception):
    def __init__(self, message: str, exit_code: int | None = None, stderr: str = "") -> None:
        super().__init__(message)
        self.exit_code = exit_code
        self.stderr = stderr


class CommandNotFound(CommandFailed):
    """The program is not installed (or not in its expected, trusted location)."""


class CommandTimedOut(CommandFailed):
    pass


class CommandCancelled(CommandFailed):
    pass


@dataclass
class CommandResult:
    exit_code: int
    stdout: str
    stderr: str
    duration_ms: int


Recorder = Callable[[CommandSpec, CommandResult], None]


class SafeCommandRunner:
    """Runs registered command specs: argument lists only, absolute executables, hard timeouts."""

    def __init__(
        self,
        registered: Iterable[CommandSpec],
        cancelled: Callable[[], bool] = lambda: False,
        recorder: Recorder | None = None,
    ) -> None:
        self._registered: dict[str, CommandSpec] = {}
        for spec in registered:
            existing = self._registered.get(spec.name)
            if existing is not None and existing != spec:
                raise ValueError(f"two different commands registered under {spec.name!r}")
            self._registered[spec.name] = spec
        self._cancelled = cancelled
        self._recorder = recorder

    def is_registered(self, spec: CommandSpec) -> bool:
        return self._registered.get(spec.name) == spec

    def run(self, spec: CommandSpec, **params: object) -> CommandResult:
        if not self.is_registered(spec):
            raise CommandRefused(f"command {spec.name!r} is not registered")
        try:
            exe = resolve(spec.executable)
        except ExecutableNotFound as exc:
            raise CommandNotFound(str(exc)) from exc
        argv = [exe, *spec.render(params)]
        creationflags = 0
        if sys.platform == "win32":
            creationflags = subprocess.CREATE_NO_WINDOW  # type: ignore[attr-defined]
        env = _minimal_env()
        start = time.monotonic()
        proc = subprocess.Popen(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            creationflags=creationflags,
            shell=False,
        )
        deadline = start + spec.timeout
        while True:
            try:
                out_b, err_b = proc.communicate(timeout=0.5)
                break
            except subprocess.TimeoutExpired:
                if self._cancelled():
                    _kill(proc)
                    raise CommandCancelled(f"{spec.name} cancelled") from None
                if time.monotonic() > deadline:
                    _kill(proc)
                    raise CommandTimedOut(f"{spec.name} exceeded {spec.timeout:.0f}s") from None
        duration = int((time.monotonic() - start) * 1000)
        if len(out_b) > spec.max_output_bytes:
            raise CommandFailed(f"{spec.name} produced more than {spec.max_output_bytes} bytes")
        result = CommandResult(
            exit_code=proc.returncode,
            stdout=out_b.decode("utf-8", errors="replace"),
            stderr=err_b.decode("utf-8", errors="replace")[:4000],
            duration_ms=duration,
        )
        if self._recorder is not None:
            self._recorder(spec, result)
        if proc.returncode not in spec.ok_exit_codes:
            raise CommandFailed(
                f"{spec.name} exited with code {proc.returncode}",
                exit_code=proc.returncode,
                stderr=result.stderr,
            )
        return result

    def run_json(self, spec: CommandSpec, **params: object) -> Any:
        result = self.run(spec, **params)
        return parse_json_output(spec.name, result.stdout)


def parse_json_output(name: str, stdout: str) -> Any:
    text = stdout.strip().lstrip("﻿")
    if not text:
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise CommandFailed(f"{name} did not return valid JSON: {exc.msg}") from exc


def _kill(proc: subprocess.Popen[bytes]) -> None:
    try:
        proc.kill()
    finally:
        try:
            proc.communicate(timeout=5)
        except Exception:  # noqa: S110 - best effort cleanup after kill
            pass


def windows_module_path() -> str | None:
    """PowerShell module folders only administrators can write to.

    The inherited PSModulePath starts with the user's Documents\\WindowsPowerShell\\Modules, where a planted
    module named like a built-in one (BitLocker, Defender, NetSecurity...) would be auto-loaded in place of
    the real cmdlet, including in an elevated scan. So the agent never passes the inherited value on.
    """
    from .executables import FOLDERID_PROGRAM_FILES, known_folder, windows_directory

    windows, program_files = windows_directory(), known_folder(FOLDERID_PROGRAM_FILES)
    if windows is None or program_files is None:
        return None
    return ";".join([
        str(windows / "System32" / "WindowsPowerShell" / "v1.0" / "Modules"),
        str(program_files / "WindowsPowerShell" / "Modules"),
    ])


_KEEP_ENV = frozenset(k.upper() for k in (
    "SystemRoot", "windir", "ComSpec", "PATHEXT", "TEMP", "TMP", "USERPROFILE", "LOCALAPPDATA", "APPDATA",
    "ProgramData", "ProgramFiles", "ProgramFiles(x86)", "ProgramW6432", "ALLUSERSPROFILE", "USERNAME", "USERDOMAIN",
    "COMPUTERNAME", "HOME", "LANG", "LC_ALL", "NUMBER_OF_PROCESSORS", "PROCESSOR_ARCHITECTURE", "OS",
))


def _minimal_env() -> dict[str, str]:
    """The environment for child processes: a short allowlist, with security-relevant values pinned.

    Names are compared case-insensitively because Windows reports them in upper case.
    """
    env = {k.upper() if sys.platform == "win32" else k: v for k, v in os.environ.items() if k.upper() in _KEEP_ENV}
    if sys.platform == "win32":
        from .executables import windows_directory

        windows = windows_directory()
        if windows is not None:  # the real Windows folder from the OS, never a per-user override
            env["SYSTEMROOT"] = env["WINDIR"] = str(windows)
            system32 = windows / "System32"
            env["COMSPEC"] = str(system32 / "cmd.exe")
            env["PATH"] = ";".join(str(p) for p in (system32, windows, system32 / "Wbem",
                                                     system32 / "WindowsPowerShell" / "v1.0"))
        module_path = windows_module_path()
        if module_path:
            env["PSMODULEPATH"] = module_path
        return env
    env["PATH"] = "/usr/bin:/bin:/usr/sbin:/sbin"
    env.setdefault("LANG", "C.UTF-8")
    env["LC_ALL"] = "C.UTF-8"  # stable, parseable tool output
    env["SYSTEMD_PAGER"] = ""
    return env


def as_list(value: Any) -> list[Any]:
    """PowerShell's ConvertTo-Json returns a bare object for one item and null for none."""
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]
