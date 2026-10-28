"""Mapping Sysmon events to telemetry events, and parsing an exported Sysmon log end to end."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from sentinel_agent.telemetry.sysmon import (
    SYSMON_CHANNEL,
    SYSMON_PROVIDER,
    map_sysmon,
    parse_registry_value,
    parse_sysmon_log,
    strip_guid,
)
from sentinel_agent.testing import win_event_xml
from sentinel_core.telemetry import EventKind
from sentinel_detect import Engine

WHEN = datetime(2026, 10, 28, 20, 0, 0, tzinfo=UTC)
PWSH = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
WINWORD = r"C:\Program Files\Microsoft Office\root\Office16\winword.exe"
SAMPLES = Path(__file__).resolve().parents[1] / "samples"


def test_strip_guid():
    assert strip_guid("{abc-123}") == "abc-123"
    assert strip_guid(None) == ""


def test_parse_registry_value():
    assert parse_registry_value("DWORD (0x00000001)") == 1
    assert parse_registry_value("QWORD (0x00000000000000ff)") == 255
    assert parse_registry_value("some string value") is None
    assert parse_registry_value(None) is None


def test_process_create_maps_lineage_and_strips_guids():
    event = map_sysmon(1, WHEN, "WKS-1", {
        "ProcessGuid": "{gP}", "ProcessId": "6100", "Image": PWSH, "CommandLine": "powershell -enc AAA",
        "User": "CORP\\sam", "ParentProcessGuid": "{gW}", "ParentProcessId": "6001", "ParentImage": WINWORD,
    }, seq=0)
    assert event is not None
    assert event.kind is EventKind.PROCESS_CREATE
    assert (event.process_guid, event.parent_guid) == ("gP", "gW")  # braces stripped
    assert event.pid == 6100 and event.parent_pid == 6001
    assert event.image == PWSH and event.parent_image == WINWORD
    assert event.command_line == "powershell -enc AAA" and event.user == "CORP\\sam"


def test_network_connect_direction_from_initiated():
    out = map_sysmon(3, WHEN, "H", {"ProcessGuid": "{g}", "ProcessId": "1", "Image": PWSH,
                                    "Protocol": "tcp", "Initiated": "true",
                                    "DestinationIp": "8.8.8.8", "DestinationPort": "443"}, seq=0)
    assert out.kind is EventKind.NETWORK_CONNECT and out.direction == "outbound"
    assert out.dest_ip == "8.8.8.8" and out.dest_port == 443 and out.protocol == "tcp"
    inbound = map_sysmon(3, WHEN, "H", {"ProcessGuid": "{g}", "ProcessId": "1", "Image": PWSH,
                                        "Initiated": "false", "DestinationIp": "8.8.8.8", "DestinationPort": "443"},
                         seq=1)
    assert inbound.direction == "inbound"


def test_registry_set_splits_target_and_parses_value():
    target = r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection\DisableRealtimeMonitoring"
    out = map_sysmon(13, WHEN, "H", {"ProcessGuid": "{g}", "ProcessId": "1", "Image": PWSH,
                                     "TargetObject": target, "Details": "DWORD (0x00000001)"}, seq=0)
    assert out.kind is EventKind.REGISTRY_SET
    assert out.registry_value == "DisableRealtimeMonitoring"
    assert out.registry_path.endswith(r"Windows Defender\Real-Time Protection")
    assert out.details["value"] == 1 and out.details["value_raw"] == "DWORD (0x00000001)"


def test_unmapped_event_id_and_missing_guid_return_none():
    assert map_sysmon(22, WHEN, "H", {"ProcessGuid": "{g}", "QueryName": "evil.com"}, seq=0) is None  # DNS: not modelled
    assert map_sysmon(1, WHEN, "H", {"ProcessId": "1", "Image": PWSH}, seq=0) is None  # no ProcessGuid


def test_overlong_command_line_is_truncated_not_rejected():
    out = map_sysmon(1, WHEN, "H", {"ProcessGuid": "{g}", "ProcessId": "1", "Image": PWSH,
                                    "CommandLine": "x" * 20000}, seq=0)
    assert out is not None and len(out.command_line) == 8192


def test_parse_sysmon_log_ignores_non_sysmon_events():
    sysmon = win_event_xml(1, 1, "2026-10-28T20:00:00.000Z",
                           {"ProcessGuid": "{g}", "ProcessId": "1", "Image": PWSH, "ParentImage": WINWORD},
                           channel=SYSMON_CHANNEL, provider=SYSMON_PROVIDER)
    security = win_event_xml(4624, 2, "2026-10-28T20:00:01.000Z", {"TargetUserName": "sam"})  # Security provider
    events = parse_sysmon_log(sysmon + "\n" + security)
    assert len(events) == 1 and events[0].kind is EventKind.PROCESS_CREATE


def test_shipped_sysmon_export_feeds_the_engine():
    events = parse_sysmon_log((SAMPLES / "sysmon_suspicious.xml").read_text(encoding="utf-8"))
    assert len(events) == 5
    rule_ids = {d.rule_id for d in Engine().feed_stream(events)}
    assert "intrusion.suspicious_exec_chain" in rule_ids
    assert "exec.office_spawns_interpreter" in rule_ids
