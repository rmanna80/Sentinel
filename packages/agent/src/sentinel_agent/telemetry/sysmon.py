"""Map Sysmon events to Sentinel X telemetry events.

[Sysmon](https://learn.microsoft.com/sysinternals/downloads/sysmon) is a free Microsoft tool that is itself a
hardened Event Tracing for Windows (ETW) consumer. It writes clean, well-documented events — process creation
with full lineage, network connections, registry changes — to its own Windows event-log channel, and, most
usefully for us, it assigns every process a stable **ProcessGuid**, exactly the key our model is built around.

Rather than re-implement the fragile parts of raw ETW, Sentinel X stands on Sysmon: this module translates its
event schema into our normalized :class:`~sentinel_core.telemetry.TelemetryEvent`. That translation is the only
Windows-specific knowledge in the detection path, and it is pure and fully testable — give it the fields from a
Sysmon event and it hands back one of our events (or ``None`` for an event id we do not model yet).

The event ids we map:

===  =========================  ===================================
 ID  Sysmon event               our EventKind
===  =========================  ===================================
  1  Process create             process_create
  3  Network connect            network_connect
  5  Process terminate          process_exit
  7  Image loaded               image_load
 11  File create                file_write
 13  Registry value set         registry_set
===  =========================  ===================================
"""

from __future__ import annotations

import re
from datetime import datetime
from xml.etree.ElementTree import ParseError

from sentinel_core.telemetry import EventKind, TelemetryEvent

from ..checks._util import as_int, parse_iso

SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"
SYSMON_PROVIDER = "Microsoft-Windows-Sysmon"
SYSMON_IDS = (1, 3, 5, 7, 11, 13)

_REGISTRY_INT = re.compile(r"^[QD]WORD\s*\(0x([0-9a-fA-F]+)\)")  # "DWORD (0x00000001)" / "QWORD (0x...)"


def _cap(value: str | None, limit: int) -> str | None:
    if value is None:
        return None
    return value if len(value) <= limit else value[:limit]


def strip_guid(value: str | None) -> str:
    """Sysmon GUIDs are wrapped in braces (``{a1b2...}``); our model stores the bare value."""
    return (value or "").strip().strip("{}")


def parse_registry_value(details: str | None) -> int | None:
    """Pull the numeric value out of Sysmon's ``Details`` string for a registry set, when it is a DWORD/QWORD.

    Sysmon renders a value as e.g. ``DWORD (0x00000001)``; the detection rules care whether a Defender flag is
    1 or 0, so we recover the integer. String and binary values return ``None`` (kept raw in ``value_raw``).
    """
    if not details:
        return None
    match = _REGISTRY_INT.match(details.strip())
    return int(match.group(1), 16) if match else None


def map_sysmon(eid: int, when: datetime, host: str, data: dict[str, str], seq: int) -> TelemetryEvent | None:
    """Translate one Sysmon event's fields into a TelemetryEvent, or None for an id we do not model."""
    common = {"host": host[:256], "ts": when, "seq": seq}
    guid = strip_guid(data.get("ProcessGuid"))
    pid = as_int(data.get("ProcessId")) or 0
    image = _cap(data.get("Image"), 1024) or ""
    user = _cap(data.get("User"), 256)
    if not guid:
        return None  # every event we model is anchored to an acting process

    if eid == 1:  # ProcessCreate
        return TelemetryEvent(
            kind=EventKind.PROCESS_CREATE, process_guid=guid, pid=pid, image=image, user=user,
            command_line=_cap(data.get("CommandLine"), 8192),
            parent_guid=strip_guid(data.get("ParentProcessGuid")) or None,
            parent_pid=as_int(data.get("ParentProcessId")),
            parent_image=_cap(data.get("ParentImage"), 1024),
            details=_some({"hashes": data.get("Hashes"), "integrity_level": data.get("IntegrityLevel")}),
            **common,
        )
    if eid == 5:  # ProcessTerminate
        return TelemetryEvent(kind=EventKind.PROCESS_EXIT, process_guid=guid, pid=pid, image=image, user=user, **common)
    if eid == 3:  # NetworkConnect
        initiated = (data.get("Initiated") or "").strip().lower() == "true"
        return TelemetryEvent(
            kind=EventKind.NETWORK_CONNECT, process_guid=guid, pid=pid, image=image, user=user,
            dest_ip=_cap(data.get("DestinationIp"), 64), dest_port=as_int(data.get("DestinationPort")),
            protocol=(data.get("Protocol") or "").strip().lower() or None,
            direction="outbound" if initiated else "inbound",
            details=_some({"dest_hostname": data.get("DestinationHostname"), "source_ip": data.get("SourceIp")}),
            **common,
        )
    if eid == 13:  # RegistryEvent (value set)
        target = data.get("TargetObject") or ""
        path, _, value_name = target.rpartition("\\")
        numeric = parse_registry_value(data.get("Details"))
        details: dict[str, object] = {}
        if numeric is not None:
            details["value"] = numeric
        if data.get("Details"):
            details["value_raw"] = data["Details"]
        return TelemetryEvent(
            kind=EventKind.REGISTRY_SET, process_guid=guid, pid=pid, image=image, user=user,
            registry_path=_cap(path or target, 1024), registry_value=_cap(value_name or None, 256),
            details=details, **common,
        )
    if eid == 11:  # FileCreate
        return TelemetryEvent(kind=EventKind.FILE_WRITE, process_guid=guid, pid=pid, image=image, user=user,
                              file_path=_cap(data.get("TargetFilename"), 1024), **common)
    if eid == 7:  # ImageLoad
        return TelemetryEvent(kind=EventKind.IMAGE_LOAD, process_guid=guid, pid=pid, image=image, user=user,
                              file_path=_cap(data.get("ImageLoaded"), 1024),
                              details=_some({"signed": data.get("Signed"), "signature": data.get("Signature")}),
                              **common)
    return None


def _some(d: dict[str, str | None]) -> dict[str, object]:
    return {k: v for k, v in d.items() if v}


def parse_sysmon_log(xml_text: str) -> list[TelemetryEvent]:
    """Parse an exported Sysmon log (a stream of ``<Event>`` elements) into telemetry events.

    Accepts the output of ``wevtutil qe`` or ``Get-WinEvent | ForEach { $_.ToXml() }``, with or without an
    ``<Events>`` wrapper or XML declarations. Non-Sysmon events in the file are ignored.
    """
    from ..checks.windows.eventlogs import parse_event_xml

    events: list[TelemetryEvent] = []
    for chunk in re.findall(r"<Event\b.*?</Event>", xml_text, re.DOTALL):
        try:
            system, data = parse_event_xml(chunk)
        except ParseError:  # a malformed element is skipped, not fatal
            continue
        provider = system.get("Provider") or ""
        if "Sysmon" not in provider:
            continue
        eid = as_int(system.get("EventID"))
        when = parse_iso(system.get("TimeCreated"))
        if eid is None or when is None:
            continue
        event = map_sysmon(eid, when, system.get("Computer") or "", data, len(events))
        if event is not None:
            events.append(event)
    return events
