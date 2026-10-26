"""The contract every security check implements."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Mapping
from typing import Any, ClassVar, Protocol

from pydantic import BaseModel

from .commands import CommandSpec
from .models import CheckDescriptor, CheckOutput, Evidence, HostInfo, Platform


class SkipCheck(Exception):
    """Raise inside ``run`` when the check cannot be performed. The message is shown to the user."""


class NotApplicable(Exception):
    """Raise inside ``run`` when the check turns out not to apply to this host."""


class CommandResult(Protocol):
    exit_code: int
    stdout: str
    stderr: str


class AgentState(Protocol):
    """Small persistent key/value store on the agent, e.g. for log cursors."""

    def get(self, key: str, default: str | None = None) -> str | None: ...

    def set(self, key: str, value: str) -> None: ...


class SystemProbe(Protocol):
    """Read-only system telemetry (psutil on a live host, fixture data in tests and demo mode).

    Every method returns plain JSON-able data so it can be recorded and replayed.
    """

    def cpu_percent(self) -> float: ...

    def memory(self) -> dict[str, Any]: ...  # total, available, percent

    def disks(self) -> list[dict[str, Any]]: ...  # mountpoint, fstype, total, used, free, percent

    def boot_time(self) -> float: ...  # epoch seconds

    def listening_sockets(self) -> list[dict[str, Any]]: ...  # proto, ip, port, pid, process

    def connections(self) -> list[dict[str, Any]]: ...  # established: proto, laddr, raddr, rport, pid, process

    def interfaces(self) -> list[dict[str, Any]]: ...  # name, is_up, mtu, speed, addresses[{family,address,netmask}]

    def processes(self) -> list[dict[str, Any]]: ...  # pid, name, exe, username, create_time


class CheckContext(Protocol):
    """Everything a check may touch. There are no write operations on the host."""

    host: HostInfo
    params: BaseModel | None
    state: AgentState
    config: Mapping[str, Any]
    system: SystemProbe

    def cancelled(self) -> bool: ...

    def run(self, spec: CommandSpec, **params: object) -> CommandResult: ...

    def run_json(self, spec: CommandSpec, **params: object) -> Any: ...

    def read_registry(self, hive: str, path: str, name: str, view: str | None = None) -> Any:
        """Read one registry value (Windows only). Returns None when the key or value is absent.

        ``hive`` is "HKLM" or "HKCU"; ``view`` is "64", "32" or None for the default view.
        """
        ...

    def read_registry_values(self, hive: str, path: str, view: str | None = None) -> dict[str, Any] | None:
        """All values of one key as a dict, or None when the key is absent."""
        ...

    def list_registry_subkeys(self, hive: str, path: str, view: str | None = None) -> list[str]: ...

    def read_text(self, path: str, max_bytes: int = 2_000_000) -> str: ...

    def path_exists(self, path: str) -> bool: ...

    def list_dir(self, path: str) -> list[str]: ...

    def startup_folders(self) -> list[tuple[str, str]]:
        """Windows Startup folders as (scope, path): ("all_users", ...), ("current_user", ...).

        A live scan asks Windows; a fixture (test or demo) scan uses the fixture's folders, so a demo never
        reads the real machine's folders.
        """
        ...

    def evidence(self, kind: str, source: str, content: Any) -> Evidence: ...


class Check(ABC):
    id: ClassVar[str]
    version: ClassVar[str]
    title: ClassVar[str]
    category: ClassVar[str]  # configuration, diagnostics, exposure, vulnerability, logs, network, malware
    platforms: ClassVar[frozenset[Platform]]
    profiles: ClassVar[frozenset[str]] = frozenset({"posture"})
    requires_elevation: ClassVar[bool] = False
    timeout_seconds: ClassVar[float] = 30.0
    data_collected: ClassVar[str]
    commands: ClassVar[tuple[CommandSpec, ...]] = ()
    params_model: ClassVar[type[BaseModel] | None] = None

    def applicable(self, host: HostInfo) -> str | None:
        """Return a reason when the check does not apply beyond the platform test (e.g. Home edition)."""
        return None

    @abstractmethod
    def run(self, ctx: CheckContext) -> CheckOutput: ...

    @classmethod
    def descriptor(cls) -> CheckDescriptor:
        return CheckDescriptor(
            id=cls.id,
            version=cls.version,
            title=cls.title,
            category=cls.category,
            platforms=sorted(cls.platforms),
            profiles=sorted(cls.profiles),
            requires_elevation=cls.requires_elevation,
            timeout_seconds=cls.timeout_seconds,
            data_collected=cls.data_collected,
            params_schema=cls.params_model.model_json_schema() if cls.params_model else None,
        )
