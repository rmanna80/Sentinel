"""Fixture-driven CheckContext for tests and the clearly labeled demo mode.

A fixture file is JSON shaped like this::

    {
      "_fixture": "what this is and where it came from",
      "host": { ...HostInfo... },
      "commands": {"ps.firewall_profiles": {"exit_code": 0, "stdout": "[...]"}},
      "registry": {"HKLM\\\\SOFTWARE\\\\...::EnableLUA::": 1},
      "files": {"/etc/os-release": "ID=debian\\n"}
    }

Command entries may instead be {"error": "not_found" | "timeout" | "failed", "message": "..."}.
Fixture data is never treated as live data: scans run from fixtures are tagged ``fixture``.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

from pydantic import BaseModel
from sentinel_core.commands import CommandSpec
from sentinel_core.models import Evidence, HostInfo, Platform, utcnow

from .config import MemoryState
from .context import registry_key
from .probe import FixtureProbe
from .safe_commands import CommandFailed, CommandResult, CommandTimedOut, parse_json_output


def windows_host(**overrides: Any) -> HostInfo:
    base: dict[str, Any] = dict(
        hostname="TEST-PC", os_family=Platform.WINDOWS, os_name="Windows 11", os_version="24H2 (build 26100.4061)",
        os_build="10.0.26100.4061", edition="Pro", arch="AMD64", agent_version="0.1.0", is_elevated=False,
    )
    base.update(overrides)
    return HostInfo(**base)


def linux_host(**overrides: Any) -> HostInfo:
    base: dict[str, Any] = dict(
        hostname="pi5", os_family=Platform.LINUX, os_name="Debian GNU/Linux 12 (bookworm)", os_version="12",
        os_build="6.6.51+rpt-rpi-2712", arch="aarch64", agent_version="0.1.0", is_elevated=False,
        distro_id="debian", distro_version="12",
    )
    base.update(overrides)
    return HostInfo(**base)


class FixtureContext:
    def __init__(
        self,
        host: HostInfo,
        fixture: Mapping[str, Any] | None = None,
        params: BaseModel | None = None,
        config: Mapping[str, Any] | None = None,
        state: MemoryState | None = None,
        cancelled: Callable[[], bool] = lambda: False,
    ) -> None:
        fixture = fixture or {}
        self.host = host
        self.params = params
        self.config = dict(config or {})
        self.state = state or MemoryState()
        self._commands: dict[str, Any] = dict(fixture.get("commands", {}))
        self._registry: dict[str, Any] = dict(fixture.get("registry", {}))
        self._files: dict[str, str] = dict(fixture.get("files", {}))
        self._cancelled = cancelled
        self.calls: list[tuple[str, dict[str, object]]] = []
        system = dict(fixture.get("system", {}))
        system.update({k: v for k, v in self._files.items() if k.startswith("<system>::")})
        self.system = FixtureProbe(system)

    @classmethod
    def from_file(cls, path: str | Path, **kwargs: Any) -> FixtureContext:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        host = kwargs.pop("host", None) or HostInfo(**data["host"])
        return cls(host, data, **kwargs)

    def cancelled(self) -> bool:
        return self._cancelled()

    def run(self, spec: CommandSpec, **params: object) -> CommandResult:
        spec.render(params)  # same parameter validation as the live runner
        self.calls.append((spec.name, dict(params)))
        key = spec.name
        if params:
            keyed = spec.name + "|" + ",".join(f"{k}={params[k]}" for k in sorted(params))
            if keyed in self._commands:
                key = keyed
        entry = self._commands.get(key)
        if entry is None:
            raise CommandFailed(f"no fixture for command {spec.name}")
        error = entry.get("error")
        if error == "timeout":
            raise CommandTimedOut(entry.get("message", f"{spec.name} timed out"))
        if error:
            raise CommandFailed(entry.get("message", f"{spec.name} failed"), exit_code=entry.get("exit_code"))
        stdout = entry["stdout"] if "stdout" in entry else json.dumps(entry.get("json"))
        exit_code = int(entry.get("exit_code", 0))
        result = CommandResult(exit_code=exit_code, stdout=stdout, stderr=entry.get("stderr", ""), duration_ms=1)
        if exit_code not in spec.ok_exit_codes:
            raise CommandFailed(f"{spec.name} exited with code {exit_code}", exit_code=exit_code, stderr=result.stderr)
        return result

    def run_json(self, spec: CommandSpec, **params: object) -> Any:
        return parse_json_output(spec.name, self.run(spec, **params).stdout)

    def _reg(self, key: str) -> Any:
        if key in self._registry:
            return self._registry[key]
        base = key.rsplit("::", 1)[0] + "::"
        return self._registry.get(base)

    def read_registry(self, hive: str, path: str, name: str, view: str | None = None) -> Any:
        return self._reg(registry_key(hive, path, name, view))

    def read_registry_values(self, hive: str, path: str, view: str | None = None) -> dict[str, Any] | None:
        return self._reg(registry_key(hive, path, "*", view))

    def list_registry_subkeys(self, hive: str, path: str, view: str | None = None) -> list[str]:
        return list(self._reg(registry_key(hive, path, "<subkeys>", view)) or [])

    def read_text(self, path: str, max_bytes: int = 2_000_000) -> str:
        if path not in self._files:
            raise FileNotFoundError(path)
        return self._files[path][:max_bytes]

    def path_exists(self, path: str) -> bool:
        return path in self._files or (path + "::<listdir>") in self._files

    def list_dir(self, path: str) -> list[str]:
        raw = self._files.get(path + "::<listdir>", "")
        return [n for n in raw.split("\n") if n]

    def evidence(self, kind: str, source: str, content: Any) -> Evidence:
        return Evidence(kind=kind, source=source, content=content, collected_at=utcnow())


def ps_json(value: Any) -> dict[str, Any]:
    """Helper for fixtures: a PowerShell command entry returning ``value`` as JSON."""
    return {"exit_code": 0, "stdout": json.dumps(value)}


def reg(hive: str, path: str, name: str, view: str | None = None) -> str:
    return registry_key(hive, path, name, view)
