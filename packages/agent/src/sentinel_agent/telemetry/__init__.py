"""Sentinel X collectors: produce normalized telemetry events from this machine.

The engine in ``sentinel_detect`` consumes :class:`~sentinel_core.telemetry.TelemetryEvent`; this package is
where those events come from on a real host. Today the source is Sysmon (a hardened Event Tracing for Windows
consumer); the mapping from Sysmon's event schema to ours lives in :mod:`.sysmon`, and the live reader and the
offline-export reader live in :mod:`.collector`.
"""

from __future__ import annotations

from .collector import Collector, CollectorError, ExportCollector, SysmonCollector
from .sysmon import SYSMON_CHANNEL, SYSMON_IDS, map_sysmon, parse_sysmon_log

__all__ = [
    "SYSMON_CHANNEL",
    "SYSMON_IDS",
    "Collector",
    "CollectorError",
    "ExportCollector",
    "SysmonCollector",
    "map_sysmon",
    "parse_sysmon_log",
]
