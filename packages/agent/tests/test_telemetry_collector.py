"""SysmonCollector driven by a FixtureContext: read -> parse -> map -> (engine), no Windows needed.

The collector runs the same Get-WinEvent command the posture log checks use, so a fixture that supplies the
command's JSON output exercises the entire live path deterministically.
"""

from __future__ import annotations

import json

import pytest
from sentinel_agent.telemetry.collector import SysmonCollector
from sentinel_agent.telemetry.sysmon import SYSMON_CHANNEL, SYSMON_PROVIDER
from sentinel_agent.testing import FixtureContext, win_event_xml
from sentinel_core.telemetry import EventKind
from sentinel_detect import Engine

PWSH = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
WINWORD = r"C:\Program Files\Microsoft Office\root\Office16\winword.exe"
RUNDLL = r"C:\Windows\System32\rundll32.exe"
EXPLORER = r"C:\Windows\explorer.exe"
DEFENDER = r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"


def _row(rid: int, eid: int, secs: int, data: dict[str, str]) -> dict[str, str]:
    iso = f"2026-10-28T20:00:{secs:02d}.000Z"
    xml = win_event_xml(eid, rid, iso, data, channel=SYSMON_CHANNEL, provider=SYSMON_PROVIDER, computer="WKS-14")
    return {"RecordId": rid, "Id": eid, "Time": iso, "Xml": xml}


def _ctx(first_run: dict | None = None, since_cursor: dict | None = None) -> FixtureContext:
    commands: dict[str, dict] = {}
    if first_run is not None:
        commands["ps.winlog_sysmon_first_run"] = {"stdout": json.dumps(first_run)}
    if since_cursor is not None:
        commands["ps.winlog_sysmon_since_cursor"] = {"stdout": json.dumps(since_cursor)}
    from sentinel_agent.testing import windows_host
    return FixtureContext(windows_host(), {"commands": commands})


def test_collect_maps_rows_and_sets_cursor():
    rows = [
        _row(10, 1, 0, {"ProcessGuid": "{gP}", "ProcessId": "6100", "Image": PWSH, "ParentImage": EXPLORER,
                        "ParentProcessGuid": "{gE}", "CommandLine": "powershell"}),
        _row(11, 3, 1, {"ProcessGuid": "{gP}", "ProcessId": "6100", "Image": PWSH, "Initiated": "true",
                        "DestinationIp": "8.8.8.8", "DestinationPort": "443", "Protocol": "tcp"}),
    ]
    ctx = _ctx(first_run={"Newest": 11, "Events": rows})
    events = SysmonCollector(ctx).collect()
    assert [e.kind for e in events] == [EventKind.PROCESS_CREATE, EventKind.NETWORK_CONNECT]
    assert events[0].process_guid == "gP" and events[0].host == "WKS-14"
    assert ctx.state.get("cursor:telemetry:sysmon") == "11"  # cursor advanced to the highest record id


def test_second_collect_reads_incrementally_from_cursor():
    first = {"Newest": 10, "Events": [_row(10, 1, 0, {"ProcessGuid": "{g1}", "ProcessId": "1", "Image": PWSH,
                                                      "ParentImage": EXPLORER})]}
    later = {"Newest": 12, "Events": [_row(12, 1, 5, {"ProcessGuid": "{g2}", "ProcessId": "2", "Image": PWSH,
                                                      "ParentImage": EXPLORER})]}
    ctx = _ctx(first_run=first, since_cursor=later)
    first_batch = SysmonCollector(ctx).collect()
    assert [e.process_guid for e in first_batch] == ["g1"]
    # cursor is now 10; a second collect uses the since-cursor command and returns only the newer event
    second_batch = SysmonCollector(ctx).collect()
    assert [e.process_guid for e in second_batch] == ["g2"]
    assert ctx.state.get("cursor:telemetry:sysmon") == "12"


def test_sysmon_not_installed_raises_collector_error():
    from sentinel_agent.telemetry.collector import CollectorError
    ctx = _ctx(first_run={"Error": "No events were found.", "ErrorId": "NoMatchingLogsFound,Get-WinEvent"})
    with pytest.raises(CollectorError, match="Sysmon does not appear to be installed"):
        SysmonCollector(ctx).collect()


def test_collector_output_drives_the_engine():
    rows = [
        _row(1, 1, 0, {"ProcessGuid": "{gW}", "ProcessId": "6001", "Image": WINWORD, "ParentImage": EXPLORER,
                       "ParentProcessGuid": "{gE}"}),
        _row(2, 1, 1, {"ProcessGuid": "{gP}", "ProcessId": "6100", "Image": PWSH, "ParentImage": WINWORD,
                       "ParentProcessGuid": "{gW}", "CommandLine": "powershell -enc AAA"}),
        _row(3, 1, 2, {"ProcessGuid": "{gR}", "ProcessId": "6200", "Image": RUNDLL, "ParentImage": PWSH,
                       "ParentProcessGuid": "{gP}"}),
        _row(4, 3, 3, {"ProcessGuid": "{gR}", "ProcessId": "6200", "Image": RUNDLL, "Initiated": "true",
                       "DestinationIp": "45.142.212.61", "DestinationPort": "443", "Protocol": "tcp"}),
        _row(5, 13, 4, {"ProcessGuid": "{gP}", "ProcessId": "6100", "Image": PWSH,
                        "TargetObject": DEFENDER + r"\DisableRealtimeMonitoring", "Details": "DWORD (0x00000001)"}),
    ]
    events = SysmonCollector(_ctx(first_run={"Newest": 5, "Events": rows})).collect()
    rule_ids = {d.rule_id for d in Engine().feed_stream(events)}
    assert "intrusion.suspicious_exec_chain" in rule_ids
