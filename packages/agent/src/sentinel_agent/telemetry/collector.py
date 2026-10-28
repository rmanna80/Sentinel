"""Collectors: read telemetry from the machine and hand back normalized events.

A :class:`Collector` is anything that can produce a batch of :class:`TelemetryEvent`. Two concrete ones:

* :class:`SysmonCollector` reads the live Sysmon event-log channel through the agent's ordinary command
  runner — the exact same ``Get-WinEvent ... ToXml()`` mechanism the posture log checks already use, with a
  record-id cursor kept in agent state so each call returns only what is new. Because it goes through a
  ``CheckContext``, it is driven by a ``FixtureContext`` in tests: no Windows machine required to prove the
  read-parse-map path end to end.
* :class:`ExportCollector` reads a saved Sysmon log export (an XML file), for analysing captures after the
  fact or on another machine.

Collectors never execute anything from the events they read; they only normalize and return them.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Protocol
from xml.etree.ElementTree import ParseError

from sentinel_core.telemetry import TelemetryEvent

from ..checks._util import as_int, parse_iso, ps_list
from ..checks.windows.eventlogs import log_specs, parse_event_xml
from ..safe_commands import CommandFailed
from .sysmon import SYSMON_CHANNEL, SYSMON_IDS, map_sysmon, parse_sysmon_log

SYSMON_SINCE_CURSOR, SYSMON_FIRST_RUN = log_specs("sysmon", SYSMON_CHANNEL, SYSMON_IDS)
STATE_KEY = "cursor:telemetry:sysmon"


class CollectorError(Exception):
    """The telemetry source could not be read (Sysmon missing, access denied, unreadable output)."""


class _Context(Protocol):  # the slice of CheckContext a collector needs
    host: Any
    state: Any

    def run_json(self, spec: Any, **params: Any) -> Any: ...


class Collector(ABC):
    @abstractmethod
    def collect(self) -> list[TelemetryEvent]:
        """Return the telemetry events available since the last call (or all, for a one-shot source)."""


class SysmonCollector(Collector):
    commands = (SYSMON_SINCE_CURSOR, SYSMON_FIRST_RUN)

    def __init__(self, ctx: _Context, seq_start: int = 0) -> None:
        self.ctx = ctx
        self._seq = seq_start

    def collect(self) -> list[TelemetryEvent]:
        data = self._read()
        self._raise_for_error(data)
        rows = [r for r in ps_list(data.get("Events")) if isinstance(r, dict)]
        events: list[TelemetryEvent] = []
        max_record: int | None = None
        for row in rows:
            record, eid = as_int(row.get("RecordId")), as_int(row.get("Id"))
            if record is None or eid is None:
                continue
            max_record = record if max_record is None else max(max_record, record)
            try:
                system, fields = parse_event_xml(str(row.get("Xml") or ""))
            except ParseError:  # a malformed record is skipped, not fatal
                continue
            when = parse_iso(row.get("Time")) or parse_iso(system.get("TimeCreated"))
            if when is None:
                continue
            host = system.get("Computer") or getattr(self.ctx.host, "hostname", "")
            event = map_sysmon(eid, when, host, fields, self._seq)
            if event is not None:
                events.append(event)
                self._seq += 1
        if max_record is not None:
            self.ctx.state.set(STATE_KEY, str(max_record))
        return events

    def _read(self) -> dict[str, Any]:
        cursor = self.ctx.state.get(STATE_KEY)
        try:
            if cursor and cursor.isdigit():
                result = self.ctx.run_json(SYSMON_SINCE_CURSOR, cursor=int(cursor))
                newest = as_int(result.get("Newest")) if isinstance(result, dict) else None
                if newest is not None and newest < int(cursor):
                    # Record ids restart when a log is cleared; re-read the recent window instead of waiting.
                    return self.ctx.run_json(SYSMON_FIRST_RUN) or {}
                return result if isinstance(result, dict) else {}
            return self.ctx.run_json(SYSMON_FIRST_RUN) or {}
        except CommandFailed as exc:
            raise CollectorError(f"The Sysmon log could not be read: {str(exc)[:200]}") from exc

    @staticmethod
    def _raise_for_error(data: dict[str, Any]) -> None:
        if not isinstance(data, dict):
            raise CollectorError("The Sysmon log could not be read (unexpected output)")
        if not data.get("Error"):
            return
        error_id = str(data.get("ErrorId") or "")
        if "NoMatchingLogsFound" in error_id:
            raise CollectorError("Sysmon does not appear to be installed (its Operational log was not found). "
                                 "Install Sysmon with a config to enable behavioural telemetry.")
        if "UnauthorizedAccess" in error_id or "unauthorized" in str(data["Error"]).lower():
            raise CollectorError("Access to the Sysmon log was denied. Run with administrator rights.")
        raise CollectorError(f"The Sysmon log could not be read: {str(data['Error'])[:200]}")


class ExportCollector(Collector):
    """Read telemetry from a saved Sysmon log export (XML)."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def collect(self) -> list[TelemetryEvent]:
        return parse_sysmon_log(self.path.read_text(encoding="utf-8", errors="replace"))
