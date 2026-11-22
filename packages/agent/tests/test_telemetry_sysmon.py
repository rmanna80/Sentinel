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
    assert map_sysmon(17, WHEN, "H", {"ProcessGuid": "{g}", "PipeName": "\\x"}, seq=0) is None  # pipes: not modelled
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


def test_process_access_keeps_actor_and_target_apart():
    out = map_sysmon(10, WHEN, "H", {
        "SourceProcessGUID": "{src}", "SourceProcessId": "4242", "SourceImage": r"C:\Temp\x.exe",
        "TargetProcessGUID": "{tgt}", "TargetImage": r"C:\Windows\System32\lsass.exe",
        "GrantedAccess": "0x1410", "CallTrace": "ntdll.dll+9d4c4|UNKNOWN(0000)", "SourceUser": "WKS\\sam",
    }, seq=3)
    assert out.kind is EventKind.PROCESS_ACCESS
    assert (out.process_guid, out.pid, out.image, out.user) == ("src", 4242, r"C:\Temp\x.exe", "WKS\\sam")
    assert (out.target_guid, out.target_image) == ("tgt", r"C:\Windows\System32\lsass.exe")
    assert out.details["granted_access"] == 0x1410 and "ntdll" in out.details["call_trace"]


def test_remote_thread_accepts_either_guid_spelling():
    for key in ("SourceProcessGuid", "SourceProcessGUID"):
        out = map_sysmon(8, WHEN, "H", {key: "{src}", "SourceImage": PWSH, "TargetProcessGuid": "{t}",
                                        "TargetImage": r"C:\Windows\explorer.exe", "StartFunction": "LoadLibraryA"}, seq=0)
        assert out.kind is EventKind.REMOTE_THREAD and out.process_guid == "src" and out.target_guid == "t"
        assert out.details == {"start_function": "LoadLibraryA"}
    assert map_sysmon(8, WHEN, "H", {"SourceImage": PWSH}, seq=0) is None  # no acting process


def test_dns_query_and_file_delete():
    dns = map_sysmon(22, WHEN, "H", {"ProcessGuid": "{g}", "Image": PWSH, "QueryName": "c2.example.invalid",
                                     "QueryStatus": "0", "QueryResults": "198.51.100.7;"}, seq=0)
    assert dns.kind is EventKind.DNS_QUERY and dns.dns_query == "c2.example.invalid"
    assert dns.details == {"query_status": "0", "query_results": "198.51.100.7;"}
    for eid in (23, 26):
        gone = map_sysmon(eid, WHEN, "H", {"ProcessGuid": "{g}", "Image": PWSH, "TargetFilename": r"C:\d\a.docx"}, seq=0)
        assert gone.kind is EventKind.FILE_DELETE and gone.file_path == r"C:\d\a.docx"


def test_wmi_events_have_no_process_and_carry_their_stage():
    consumer = map_sysmon(20, WHEN, "H", {"Operation": "Created", "User": "WKS\\sam", "Name": "Upd",
                                          "Type": "Command Line", "Destination": "powershell -enc AAAA"}, seq=0)
    assert consumer.kind is EventKind.WMI_SUBSCRIPTION and consumer.process_guid == "wmi-activity"
    assert consumer.details["stage"] == "consumer" and consumer.details["consumer_type"] == "Command Line"
    assert map_sysmon(19, WHEN, "H", {"Name": "f", "Query": "select 1"}, seq=0).details["stage"] == "filter"
    assert map_sysmon(21, WHEN, "H", {"Consumer": "c", "Filter": "f"}, seq=0).details["stage"] == "binding"


def test_new_sysmon_events_drive_the_new_rules_end_to_end():
    lsass = win_event_xml(10, 1, "2026-10-28T20:00:00.000Z", {
        "SourceProcessGUID": "{aa}", "SourceProcessId": "9", "SourceImage": r"C:\Users\sam\AppData\Local\Temp\d.exe",
        "TargetProcessGUID": "{bb}", "TargetImage": r"C:\Windows\System32\lsass.exe", "GrantedAccess": "0x1410",
    }, channel=SYSMON_CHANNEL, provider=SYSMON_PROVIDER)
    wmi = win_event_xml(20, 2, "2026-10-28T20:00:01.000Z", {
        "Operation": "Created", "Name": "Upd", "Type": "Command Line", "Destination": "cmd /c a.exe",
    }, channel=SYSMON_CHANNEL, provider=SYSMON_PROVIDER)
    events = parse_sysmon_log(lsass + wmi)
    assert [e.kind for e in events] == [EventKind.PROCESS_ACCESS, EventKind.WMI_SUBSCRIPTION]
    assert {d.rule_id for d in Engine().feed_stream(events)} == {"cred.lsass_access", "persist.wmi_subscription"}


def _evtx_json(eid: int, data: dict) -> dict:
    return {"Event": {"System": {"Provider": {"#attributes": {"Name": "Microsoft-Windows-Sysmon"}}, "EventID": eid,
                                 "TimeCreated": {"#attributes": {"SystemTime": "2026-08-30T14:19:31.7888122Z"}},
                                 "Computer": "LabVm"},
                      "EventData": data}}


def test_evtx_json_events_map_like_xml_ones():
    import json

    from sentinel_agent.telemetry.sysmon import map_evtx_json, parse_evtx_json

    record = _evtx_json(1, {"ProcessGuid": "570E49AA-0000", "ProcessId": 8268, "Image": PWSH, "CommandLine": "p -enc A",
                            "OriginalFileName": "PowerShell.EXE", "ParentProcessGuid": "570E49AA-1111",
                            "ParentImage": WINWORD, "ParentCommandLine": "winword /n", "Nested": {"ignored": 1}})
    event = map_evtx_json(record)
    assert event.kind is EventKind.PROCESS_CREATE and event.pid == 8268 and event.host == "LabVm"
    assert event.details["original_file_name"] == "PowerShell.EXE"
    assert event.details["parent_command_line"] == "winword /n"

    other = {"Event": {"System": {"Provider": {"#attributes": {"Name": "Microsoft-Windows-Security-Auditing"}},
                                  "EventID": 4624}, "EventData": {}}}
    as_array = json.dumps([record, other])
    as_ndjson = json.dumps(record) + "\n" + json.dumps(other) + "\n" + json.dumps(_evtx_json(22, {
        "ProcessGuid": "g", "Image": PWSH, "QueryName": "a.invalid"}))
    assert len(parse_evtx_json(as_array)) == 1
    assert [e.kind for e in parse_evtx_json(as_ndjson)] == [EventKind.PROCESS_CREATE, EventKind.DNS_QUERY]
    assert parse_evtx_json(json.dumps(record) + "{broken") == parse_evtx_json(json.dumps(record))
    assert parse_evtx_json("") == [] and map_evtx_json({"Event": "nope"}) is None


def test_recordings_load_by_format(tmp_path):
    import json

    import pytest
    from sentinel_agent.telemetry.dataset import find_recordings, load_recording
    from sentinel_detect import StreamBuilder, dump_stream

    b = StreamBuilder()
    b.process_create("P", PWSH)
    (tmp_path / "a.jsonl").write_text(dump_stream(b.events), encoding="utf-8")
    (tmp_path / "b.json").write_text(json.dumps(_evtx_json(22, {"ProcessGuid": "g", "QueryName": "x.invalid"})), "utf-8")
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "c.xml").write_text((SAMPLES / "sysmon_suspicious.xml").read_text(encoding="utf-8"), "utf-8")
    (tmp_path / "d.evtx").write_bytes(b"ElfFile\x00")
    (tmp_path / "notes.txt").write_text("x", encoding="utf-8")

    found = find_recordings([tmp_path])
    assert [p.name for p in found] == ["a.jsonl", "b.json", "c.xml"]
    assert [len(load_recording(p)) > 0 for p in found] == [True, True, True]
    assert load_recording(tmp_path / "b.json")[0].kind is EventKind.DNS_QUERY
    with pytest.raises(ValueError, match="convert it"):
        load_recording(tmp_path / "d.evtx")
    with pytest.raises(ValueError, match="unrecognised"):
        load_recording(tmp_path / "notes.txt")
