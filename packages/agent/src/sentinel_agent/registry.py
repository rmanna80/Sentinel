"""The allowlist of checks the agent can run."""

from __future__ import annotations

import re
from collections.abc import Iterable, Iterator

from sentinel_core.checks import Check
from sentinel_core.commands import CommandSpec
from sentinel_core.models import CheckDescriptor

_ID_RE = re.compile(r"^[a-z0-9]+(?:[._][a-z0-9_]+)+$")
_REQUIRED = ("id", "version", "title", "category", "platforms", "data_collected")


class CheckRegistry:
    def __init__(self, checks: Iterable[type[Check]]) -> None:
        self._checks: dict[str, Check] = {}
        for cls in checks:
            for attr in _REQUIRED:
                if not getattr(cls, attr, None):
                    raise ValueError(f"{cls.__name__} is missing {attr}")
            if not _ID_RE.match(cls.id):
                raise ValueError(f"{cls.__name__}: invalid check id {cls.id!r}")
            if cls.id in self._checks:
                raise ValueError(f"duplicate check id {cls.id}")
            self._checks[cls.id] = cls()

    def __iter__(self) -> Iterator[Check]:
        return iter(self._checks.values())

    def __contains__(self, check_id: object) -> bool:
        return check_id in self._checks

    def __len__(self) -> int:
        return len(self._checks)

    def get(self, check_id: str) -> Check | None:
        return self._checks.get(check_id)

    def descriptors(self) -> list[CheckDescriptor]:
        return [type(c).descriptor() for c in self._checks.values()]

    def command_specs(self) -> list[CommandSpec]:
        specs: list[CommandSpec] = []
        for check in self._checks.values():
            specs.extend(type(check).commands)
        return specs


def default_registry() -> CheckRegistry:
    from .checks import ALL_CHECKS

    return CheckRegistry(ALL_CHECKS)
