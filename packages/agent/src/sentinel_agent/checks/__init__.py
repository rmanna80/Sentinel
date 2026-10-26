"""Every check the agent can run. Adding a check means adding it to ALL_CHECKS."""

from __future__ import annotations

from sentinel_core.checks import Check

from .common.resources import ResourceDiagnostics
from .windows.firewall import FirewallProfiles
from .windows.uac import UacConfiguration

ALL_CHECKS: list[type[Check]] = [
    ResourceDiagnostics,
    FirewallProfiles,
    UacConfiguration,
]
