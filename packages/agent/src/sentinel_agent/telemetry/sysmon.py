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
  8  CreateRemoteThread         remote_thread
 10  Process access             process_access
 11  File create                file_write
 13  Registry value set         registry_set
 19  WMI event filter           wmi_subscription
 20  WMI event consumer         wmi_subscription
 21  WMI consumer-to-filter     wmi_subscription
 22  DNS query                  dns_query
 23  File delete (archived)     file_delete
 26  File delete (detected)     file_delete
===  =========================  ===================================

Events 8 and 10 describe one process acting on another, so Sysmon names the actor ``Source*`` and the victim
``Target*``; we keep the actor in the usual ``process_guid``/``image`` fields and the victim in
``target_guid``/``target_image``. WMI events (19-21) carry no process at all - WMI itself performs the
registration - so they are anchored to a fixed placeholder GUID and the interesting fields live in ``details``.
"""

from __future__ import annotations

import json
import re
from datetime import datetime
from xml.etree.ElementTree import ParseError

from sentinel_core.telemetry import EventKind, TelemetryEvent

from ..checks._util import as_int, parse_iso

SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"
SYSMON_PROVIDER = "Microsoft-Windows-Sysmon"
SYSMON_IDS = (1, 3, 5, 7, 8, 10, 11, 13, 19, 20, 21, 22, 23, 26)
WMI_PLACEHOLDER_GUID = "wmi-activity"  # WMI events name no acting process; see the module docstring
_WMI_STAGE = {19: "filter", 20: "consumer", 21: "binding"}

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
    if eid in (8, 10):
        return _map_cross_process(eid, data, common)
    if eid in _WMI_STAGE:
        return _map_wmi(eid, data, common)
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
            details=_some({
                "hashes": data.get("Hashes"), "integrity_level": data.get("IntegrityLevel"),
                # carried for imported Sigma rules, which often match on these
                "original_file_name": _cap(data.get("OriginalFileName"), 256),
                "parent_command_line": _cap(data.get("ParentCommandLine"), 8192),
                "current_directory": _cap(data.get("CurrentDirectory"), 1024),
                "description": _cap(data.get("Description"), 256), "product": _cap(data.get("Product"), 256),
                "company": _cap(data.get("Company"), 256),
            }),
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
    if eid in (23, 26):  # FileDelete (archived) / FileDeleteDetected
        return TelemetryEvent(kind=EventKind.FILE_DELETE, process_guid=guid, pid=pid, image=image, user=user,
                              file_path=_cap(data.get("TargetFilename"), 1024), **common)
    if eid == 22:  # DnsQuery
        return TelemetryEvent(
            kind=EventKind.DNS_QUERY, process_guid=guid, pid=pid, image=image, user=user,
            dns_query=_cap(data.get("QueryName"), 1024),
            details=_some({"query_status": data.get("QueryStatus"), "query_results": _cap(data.get("QueryResults"), 2048)}),
            **common,
        )
    if eid == 7:  # ImageLoad
        return TelemetryEvent(kind=EventKind.IMAGE_LOAD, process_guid=guid, pid=pid, image=image, user=user,
                              file_path=_cap(data.get("ImageLoaded"), 1024),
                              details=_some({"signed": data.get("Signed"), "signature": data.get("Signature")}),
                              **common)
    return None


def _first(data: dict[str, str], *names: str) -> str | None:
    """Sysmon spells some fields inconsistently across versions (``SourceProcessGUID`` vs ``...Guid``)."""
    for name in names:
        if data.get(name):
            return data[name]
    return None


def parse_access_mask(raw: str | None) -> int | None:
    """``GrantedAccess`` is rendered as hex (``0x1410``); recover the integer so rules can test its bits."""
    if not raw:
        return None
    try:
        return int(raw.strip(), 16)
    except ValueError:
        return None


def _map_cross_process(eid: int, data: dict[str, str], common: dict[str, object]) -> TelemetryEvent | None:
    guid = strip_guid(_first(data, "SourceProcessGuid", "SourceProcessGUID"))
    if not guid:
        return None
    target = {
        "target_image": _cap(data.get("TargetImage"), 1024),
        "target_guid": strip_guid(_first(data, "TargetProcessGuid", "TargetProcessGUID")) or None,
    }
    actor = {
        "process_guid": guid, "pid": as_int(data.get("SourceProcessId")) or 0,
        "image": _cap(data.get("SourceImage"), 1024) or "", "user": _cap(data.get("SourceUser"), 256),
    }
    if eid == 10:  # ProcessAccess
        details: dict[str, object] = _some({"call_trace": _cap(data.get("CallTrace"), 2048)})
        mask = parse_access_mask(data.get("GrantedAccess"))
        if mask is not None:
            details["granted_access"] = mask
        return TelemetryEvent(kind=EventKind.PROCESS_ACCESS, details=details, **actor, **target, **common)
    return TelemetryEvent(  # 8: CreateRemoteThread
        kind=EventKind.REMOTE_THREAD,
        details=_some({"start_module": data.get("StartModule"), "start_function": data.get("StartFunction"),
                       "start_address": data.get("StartAddress")}),
        **actor, **target, **common,
    )


def _map_wmi(eid: int, data: dict[str, str], common: dict[str, object]) -> TelemetryEvent:
    return TelemetryEvent(
        kind=EventKind.WMI_SUBSCRIPTION, process_guid=WMI_PLACEHOLDER_GUID, pid=0, image="",
        user=_cap(data.get("User"), 256),
        details=_some({
            "stage": _WMI_STAGE[eid], "operation": data.get("Operation"), "name": _cap(data.get("Name"), 512),
            "namespace": data.get("EventNamespace"), "query": _cap(data.get("Query"), 2048),
            "consumer_type": data.get("Type"), "destination": _cap(data.get("Destination"), 4096),
            "consumer": _cap(data.get("Consumer"), 512), "filter": _cap(data.get("Filter"), 512),
        }),
        **common,
    )


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


def _scalar(value: object) -> str | None:
    if value is None or isinstance(value, dict | list):
        return None
    return str(value).lower() if isinstance(value, bool) else str(value)


def map_evtx_json(record: dict[str, object], seq: int = 0) -> TelemetryEvent | None:
    """Translate one event in the JSON shape EVTX converters emit (``{"Event": {"System": .., "EventData": ..}}``).

    This is the format public attack datasets are usually published in (``evtx_dump --format json`` and
    similar), so it is the door through which recorded real-world telemetry reaches the lab.
    """
    event = record.get("Event")
    if not isinstance(event, dict):
        return None
    system, data = event.get("System"), event.get("EventData")
    if not isinstance(system, dict) or not isinstance(data, dict):
        return None
    provider = system.get("Provider")
    name = provider.get("#attributes", {}).get("Name", "") if isinstance(provider, dict) else ""
    if "Sysmon" not in str(name):
        return None
    eid = system.get("EventID")
    if isinstance(eid, dict):  # some converters wrap the id with its qualifiers
        eid = eid.get("#text")
    created = system.get("TimeCreated")
    stamp = created.get("#attributes", {}).get("SystemTime") if isinstance(created, dict) else None
    when = parse_iso(str(stamp)) if stamp else None
    number = as_int(str(eid)) if eid is not None else None
    if number is None or when is None:
        return None
    fields = {str(k): v for k, v in ((k, _scalar(v)) for k, v in data.items()) if v is not None}
    return map_sysmon(number, when, str(system.get("Computer") or ""), fields, seq)


def parse_evtx_json(text: str) -> list[TelemetryEvent]:
    """Parse a file of EVTX-as-JSON events: one object, a JSON array, or objects one after another (NDJSON)."""
    decoder, records, pos = json.JSONDecoder(), [], 0
    while pos < len(text):
        while pos < len(text) and text[pos] in " \t\r\n,":
            pos += 1
        if pos >= len(text):
            break
        try:
            value, pos = decoder.raw_decode(text, pos)
        except json.JSONDecodeError:
            break  # trailing garbage: keep what parsed
        records.extend(value if isinstance(value, list) else [value])
    events: list[TelemetryEvent] = []
    for record in records:
        if isinstance(record, dict):
            mapped = map_evtx_json(record, len(events))
            if mapped is not None:
                events.append(mapped)
    return events
