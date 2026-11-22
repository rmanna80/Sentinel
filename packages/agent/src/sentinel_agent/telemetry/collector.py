"""Collectors: read telemetry from the machine and hand back normalized events.

A :class:`Collector` is anything that can produce a batch of :class:`TelemetryEvent`. Two concrete ones:

* :class:`SysmonCollector` reads the live Sysmon event-log channel through the agent's ordinary command
  runner — the exact same ``Get-WinEvent ... ToXml()`` mechanism the posture log checks already use, with a
  record-id cursor kept in agent state so each call returns only what is new. Because it goes through a
  ``CheckContext``, it is driven by a ``FixtureContext`` in tests: no Windows machine required to prove the
  read-parse-map path end to end.
* :class:`ExportCollector` reads a saved Sysmon log export (an XML file), for analysing captures after the
  fact or on another machine.
* :class:`AuditdCollector` is the Linux counterpart: it reads kernel audit records from the systemd journal
  (which a member of the ``systemd-journal`` group can read without root), with a journal cursor in agent
  state. :class:`AuditExportCollector` reads a saved ``audit.log``.

Collectors never execute anything from the events they read; they only normalize and return them.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Protocol
from xml.etree.ElementTree import ParseError

from sentinel_core.commands import CommandSpec, ParamKind
from sentinel_core.telemetry import TelemetryEvent

from ..checks._util import as_int, parse_iso, ps_list
from ..checks.linux.authlog import parse_journal
from ..checks.windows.eventlogs import log_specs, parse_event_xml
from ..safe_commands import CommandFailed, CommandNotFound
from .auditd import AuditState, events_from_records, parse_audit_log, record_from_journal
from .sysmon import SYSMON_CHANNEL, SYSMON_IDS, map_sysmon, parse_sysmon_log

SYSMON_SINCE_CURSOR, SYSMON_FIRST_RUN = log_specs("sysmon", SYSMON_CHANNEL, SYSMON_IDS)
STATE_KEY = "cursor:telemetry:sysmon"


AUDIT_STATE_KEY = "cursor:telemetry:auditd"
AUDIT_MAX_ENTRIES = 20_000
_AUDIT_BASE = ("-o", "json", "--no-pager", "-n", str(AUDIT_MAX_ENTRIES), "_TRANSPORT=audit")
AUDIT_AFTER_CURSOR = CommandSpec("journalctl.audit_after_cursor", "journalctl",
                                 (*_AUDIT_BASE, "--after-cursor", "{cursor}"),
                                 params={"cursor": ParamKind.JOURNAL_CURSOR}, timeout=60)
AUDIT_FIRST_RUN = CommandSpec("journalctl.audit_first_run", "journalctl",
                              (*_AUDIT_BASE, "--since", "10 minutes ago"), timeout=60)


class CollectorError(Exception):
    """The telemetry source could not be read (Sysmon missing, access denied, unreadable output)."""


class _Context(Protocol):  # the slice of CheckContext a collector needs
    host: Any
    state: Any

    def run(self, spec: Any, **params: Any) -> Any: ...

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
            host = str(system.get("Computer") or getattr(self.ctx.host, "hostname", "") or "")
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


class AuditdCollector(Collector):
    """Read new kernel audit records from the systemd journal and translate them (Linux)."""

    commands = (AUDIT_AFTER_CURSOR, AUDIT_FIRST_RUN)

    def __init__(self, ctx: _Context, audit_state: AuditState | None = None) -> None:
        self.ctx = ctx
        self.audit_state = audit_state if audit_state is not None else AuditState()

    def collect(self) -> list[TelemetryEvent]:
        cursor = self.ctx.state.get(AUDIT_STATE_KEY)
        try:
            result = (self.ctx.run(AUDIT_AFTER_CURSOR, cursor=cursor) if cursor else self.ctx.run(AUDIT_FIRST_RUN))
            stdout, stderr = result.stdout, result.stderr or ""
        except CommandNotFound as exc:
            raise CollectorError("journalctl is not installed, so audit records cannot be read") from exc
        except CommandFailed as exc:
            if exc.exit_code == 1 and not (exc.stderr or "").strip():
                return []  # some journalctl versions exit 1 when nothing matches
            raise CollectorError(f"The audit journal could not be read: {str(exc)[:200]}") from exc
        entries = parse_journal(stdout)
        if not entries:
            low = stderr.lower()
            if "permission" in low or "not seeing messages" in low or "no journal files were opened" in low:
                raise CollectorError("The agent's account cannot read the system journal. Add it to the "
                                     "systemd-journal group (`sudo usermod -aG systemd-journal <user>`).")
            if not cursor:
                raise CollectorError(
                    "No audit records were found in the journal. Load the audit rules "
                    "(scripts/linux/sentinel-audit.rules) and make sure audit records reach the journal; "
                    "docs/operations.md has the steps.")
            return []
        records = [r for r in (record_from_journal(e) for e in entries) if r is not None]
        host = str(getattr(self.ctx.host, "hostname", "") or "")
        events = events_from_records(records, host, self.audit_state)
        last = next((str(e["__CURSOR"]) for e in reversed(entries) if e.get("__CURSOR")), None)
        if last:
            self.ctx.state.set(AUDIT_STATE_KEY, last)
        return events


class AuditExportCollector(Collector):
    """Read telemetry from a saved Linux ``audit.log`` (or ``ausearch --raw`` output)."""

    def __init__(self, path: str | Path, host: str = "") -> None:
        self.path = Path(path)
        self.host = host

    def collect(self) -> list[TelemetryEvent]:
        return parse_audit_log(self.path.read_text(encoding="utf-8", errors="replace"), self.host)

