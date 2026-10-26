"""Registered command specifications.

Every external program a check can run is declared as a frozen ``CommandSpec`` on the
check class. The agent's runner refuses any spec that was not registered at startup,
and substitutes parameters only after validating them against a strict kind. No
command ever goes through a shell, and no free-form user text reaches an argument.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from types import MappingProxyType


class ParamKind(StrEnum):
    INT = "int"  # non-negative integer; may be embedded inside an argument
    JOURNAL_CURSOR = "journal_cursor"  # systemd journal cursor; whole argument only
    TARGET = "target"  # IPv4/IPv6 address, CIDR or DNS hostname; whole argument only
    PORT_LIST = "port_list"  # "22,80,443" or "1-1024"; whole argument only
    PATH = "path"  # absolute path checked against the agent's allowlist; whole argument only


class CommandParamError(ValueError):
    """A parameter failed validation; the command is never started."""


_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*\.?$"
)
_CURSOR_RE = re.compile(r"^[A-Za-z0-9=;_\-]{1,600}$")
_PORT_LIST_RE = re.compile(r"^\d{1,5}(?:-\d{1,5})?(?:,\d{1,5}(?:-\d{1,5})?){0,63}$")
_PLACEHOLDER_RE = re.compile(r"\{([a-z_][a-z0-9_]*)\}")


def validate_param(kind: ParamKind, value: object) -> str:
    """Return the validated string form of ``value`` or raise ``CommandParamError``."""
    if kind is ParamKind.INT:
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise CommandParamError("expected a non-negative integer")
        return str(value)
    if not isinstance(value, str):
        raise CommandParamError(f"expected a string for {kind}")
    if value.startswith("-"):
        raise CommandParamError("parameters may not start with '-'")
    if kind is ParamKind.JOURNAL_CURSOR:
        if not _CURSOR_RE.match(value):
            raise CommandParamError("invalid journal cursor")
        return value
    if kind is ParamKind.TARGET:
        return validate_target(value)
    if kind is ParamKind.PORT_LIST:
        if not _PORT_LIST_RE.match(value):
            raise CommandParamError("invalid port list")
        for part in value.split(","):
            for p in part.split("-"):
                if not 0 < int(p) <= 65535:
                    raise CommandParamError("port out of range")
        return value
    if kind is ParamKind.PATH:
        # The agent applies the allowlist; here we only reject obviously unsafe forms.
        if "\x00" in value or not (value.startswith("/") or re.match(r"^[A-Za-z]:\\", value)):
            raise CommandParamError("path must be absolute")
        return value
    raise CommandParamError(f"unknown parameter kind {kind}")  # pragma: no cover


def validate_target(value: str) -> str:
    value = value.strip()
    try:
        if "/" in value:
            return str(ipaddress.ip_network(value, strict=False))
        return str(ipaddress.ip_address(value))
    except ValueError:
        pass
    if _HOSTNAME_RE.match(value):
        return value.rstrip(".").lower()
    raise CommandParamError("target must be an IP address, CIDR range or hostname")


@dataclass(frozen=True)
class CommandSpec:
    """A program invocation a check is allowed to make.

    ``executable`` is a logical name resolved by the agent to an absolute path
    (for example ``powershell`` -> ``C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe``),
    so a planted binary earlier on ``PATH`` is never used.
    """

    name: str
    executable: str
    args: tuple[str, ...]
    params: Mapping[str, ParamKind] = field(default_factory=lambda: MappingProxyType({}))
    timeout: float = 30.0
    max_output_bytes: int = 8_000_000
    ok_exit_codes: tuple[int, ...] = (0,)

    def __post_init__(self) -> None:
        used: set[str] = set()
        for arg in self.args:
            for name in _PLACEHOLDER_RE.findall(arg):
                if name not in self.params:
                    raise ValueError(f"{self.name}: placeholder {{{name}}} has no declared kind")
                kind = self.params[name]
                if kind is not ParamKind.INT and arg != "{" + name + "}":
                    raise ValueError(f"{self.name}: {kind} parameters must be a whole argument")
                used.add(name)
        unused = set(self.params) - used
        if unused:
            raise ValueError(f"{self.name}: declared but unused parameters {sorted(unused)}")
        object.__setattr__(self, "params", MappingProxyType(dict(self.params)))

    def render(self, values: Mapping[str, object] | None = None) -> list[str]:
        """Return the argument list with validated parameters substituted."""
        values = dict(values or {})
        missing = set(self.params) - set(values)
        extra = set(values) - set(self.params)
        if missing or extra:
            raise CommandParamError(f"{self.name}: missing {sorted(missing)} extra {sorted(extra)}")
        clean = {k: validate_param(self.params[k], v) for k, v in values.items()}
        out: list[str] = []
        for arg in self.args:
            out.append(_PLACEHOLDER_RE.sub(lambda m: clean[m.group(1)], arg) if "{" in arg else arg)
        return out


PS_PRELUDE = (
    "$ProgressPreference='SilentlyContinue'; "
    "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8; "
)


def powershell(name: str, script: str, timeout: float = 30.0, **kwargs: object) -> CommandSpec:
    """Build a Windows PowerShell spec. The script is a fixed constant; output should be JSON.

    The prelude forces UTF-8 output: Windows PowerShell 5.1 otherwise writes redirected
    output in the OEM code page, which corrupts non-English names.
    """
    return CommandSpec(
        name=name,
        executable="powershell",
        args=("-NoProfile", "-NonInteractive", "-Command", PS_PRELUDE + script),
        timeout=timeout,
        **kwargs,  # type: ignore[arg-type]
    )
