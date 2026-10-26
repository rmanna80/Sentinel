"""Windows event logs and inventory against hand-written fixtures shaped like real output (not recordings)."""

import pytest
from sentinel_agent.checks.windows import eventlogs as el
from sentinel_agent.checks.windows import inventory as inv
from sentinel_agent.config import MemoryState
from sentinel_agent.testing import FixtureContext, ps_json, reg, win_event_xml, windows_host
from sentinel_core.checks import SkipCheck
from sentinel_core.models import Severity

HOST = windows_host(edition="Home", is_elevated=True, hostname="RYAN-PC")
T = "2026-10-24T03:12:{:02d}.0000000Z"


def row(event_id, record_id, data, **kw):
    time = T.format(record_id % 60)
    return {"RecordId": record_id, "Id": event_id, "Time": time, "Xml": win_event_xml(event_id, record_id, time, data, **kw)}


def logon(eid, rid, user="Ryan", ip="-", logon_type="2", **extra):
    return row(eid, rid, {"SubjectUserSid": "S-1-5-18", "SubjectUserName": "RYAN-PC$", "TargetUserName": user,
                          "TargetDomainName": "RYAN-PC", "Status": "0xc000006d", "SubStatus": "0xc000006a",
                          "LogonType": logon_type, "IpAddress": ip, "IpPort": "0", "WorkstationName": "RYAN-PC",
                          "ProcessName": "C:\\Windows\\System32\\svchost.exe", **extra})


def security_fixture(rows, newest=None, spec=el.SECURITY_FIRST_RUN):
    return {"commands": {spec.name: ps_json({"Newest": newest or max((r["RecordId"] for r in rows), default=1),
                                             "Events": rows})}}


# --------------------------------------------------------------------------- win.logs.security


def test_security_log_normalizes_logons_and_saves_cursor():
    rows = [
        logon(4625, 101, "administrator", "203.0.113.50", "3"),
        logon(4625, 102, "Ryan", "-", "2"),
        logon(4624, 103, "Ryan", "127.0.0.1", "2"),
        logon(4624, 104, "SYSTEM", "-", "5"),  # service logon: dropped
        row(4672, 105, {"SubjectUserSid": "S-1-5-18", "SubjectUserName": "SYSTEM", "PrivilegeList": "SeTcbPrivilege"}),
        row(4672, 106, {"SubjectUserSid": "S-1-5-21-1-2-3-1001", "SubjectUserName": "Ryan",
                        "PrivilegeList": "SeDebugPrivilege\n\t\t\tSeBackupPrivilege"}),
    ]
    state = MemoryState()
    out = el.WindowsSecurityLog().run(FixtureContext(HOST, security_fixture(rows), state=state))
    actions = [e.action for e in out.events]
    assert actions == ["logon_failed", "logon_failed", "logon_success", "special_privileges"]
    failed = out.events[0]
    assert (failed.source, failed.record_id, failed.event_id) == ("windows:Security", "101", "4625")
    assert failed.source_ip == "203.0.113.50" and failed.outcome == "failure" and failed.severity is Severity.LOW
    assert failed.data["Status"] == "0xc000006d" and failed.data["LogonType"] == "3"
    assert out.events[1].source_ip is None  # "-" means no address
    assert out.events[3].data["PrivilegeList"] == "SeDebugPrivilege SeBackupPrivilege"
    assert out.evidence[0].content["counts_by_event_id"] == {"4624": 2, "4625": 2, "4672": 2}
    assert state.get("cursor:windows:Security") == "106"
    assert out.findings == []


def test_security_log_account_and_tamper_events():
    rows = [
        row(4720, 201, {"TargetUserName": "support", "TargetSid": "S-1-5-21-1-2-3-1005", "SubjectUserName": "Ryan"}),
        row(4732, 202, {"MemberName": "-", "MemberSid": "S-1-5-21-1-2-3-1005", "TargetUserName": "Administrators",
                        "TargetSid": "S-1-5-32-544", "SubjectUserName": "Ryan"}),
        row(4732, 203, {"MemberSid": "S-1-5-21-1-2-3-1005", "TargetUserName": "Remote Desktop Users",
                        "TargetSid": "S-1-5-32-555", "SubjectUserName": "Ryan"}),
        row(4740, 204, {"TargetUserName": "Ryan", "TargetDomainName": "RYAN-PC"}),
        row(1102, 205, {"SubjectUserName": "Ryan", "SubjectDomainName": "RYAN-PC"}, provider="Microsoft-Windows-Eventlog",
            user_data="LogFileCleared"),
        row(4697, 206, {"SubjectUserName": "Ryan", "ServiceName": "updsvc",
                        "ServiceFileName": "C:\\Users\\Public\\updsvc.exe", "ServiceStartType": "2"}),
        row(4698, 207, {"SubjectUserName": "Ryan", "TaskName": "\\OneDrive Reporting Task"}),
    ]
    out = el.WindowsSecurityLog().run(FixtureContext(HOST, security_fixture(rows)))
    by = {e.record_id: e for e in out.events}
    assert by["201"].action == "account_created" and by["201"].severity is Severity.MEDIUM
    assert by["202"].action == "group_member_added" and by["202"].severity is Severity.HIGH
    assert by["202"].data["TargetSid"] == "S-1-5-32-544" and by["202"].data["MemberSid"] == "S-1-5-21-1-2-3-1005"
    assert by["203"].severity is Severity.INFO
    assert by["204"].action == "account_locked_out" and by["204"].severity is Severity.MEDIUM
    assert by["205"].action == "audit_log_cleared" and by["205"].category == "audit" and by["205"].user == "Ryan"
    assert by["206"].action == "service_installed" and by["206"].data["ServiceFileName"].endswith("updsvc.exe")
    assert by["207"].action == "scheduled_task_created" and by["207"].data["TaskName"] == "\\OneDrive Reporting Task"


def test_security_log_uses_cursor_and_no_matching_events_is_empty():
    # Get-WinEvent's NoMatchingEventsFound is caught inside the script, which then returns no events.
    fixture = {"commands": {el.SECURITY_SINCE_CURSOR.name + "|cursor=500": ps_json({"Newest": 512, "Events": []})}}
    state = MemoryState({"cursor:windows:Security": "500"})
    ctx = FixtureContext(HOST, fixture, state=state)
    out = el.WindowsSecurityLog().run(ctx)
    assert out.events == [] and ctx.calls == [(el.SECURITY_SINCE_CURSOR.name, {"cursor": 500})]
    assert state.get("cursor:windows:Security") == "500"
    assert "NoMatchingEventsFound" in el.SECURITY_FIRST_RUN.args[-1]


def test_security_log_restarted_after_clear_reads_last_week_again():
    fixture = {"commands": {
        el.SECURITY_SINCE_CURSOR.name: ps_json({"Newest": 40, "Events": []}),
        el.SECURITY_FIRST_RUN.name: ps_json({"Newest": 40, "Events": [logon(4625, 39, "Ryan")]}),
    }}
    state = MemoryState({"cursor:windows:Security": "90000"})
    out = el.WindowsSecurityLog().run(FixtureContext(HOST, fixture, state=state))
    assert [e.record_id for e in out.events] == ["39"] and state.get("cursor:windows:Security") == "39"


def test_security_log_access_denied_skips():
    fixture = {"commands": {el.SECURITY_FIRST_RUN.name: ps_json({
        "Events": [], "Error": "Attempted to perform an unauthorized operation.",
        "ErrorId": "System.UnauthorizedAccessException,Microsoft.PowerShell.Commands.GetWinEventCommand"})}}
    with pytest.raises(SkipCheck, match="denied"):
        el.WindowsSecurityLog().run(FixtureContext(HOST, fixture))


def test_log_specs_embed_cursor_as_int_only():
    rendered = el.SECURITY_SINCE_CURSOR.render({"cursor": 1234})[-1]
    assert "EventRecordID > 1234" in rendered and "EventID=4698" in rendered and "EventID=1102" in rendered
    assert "timediff(@SystemTime) <= 604800000" in el.SECURITY_FIRST_RUN.args[-1]
    with pytest.raises(ValueError):
        el.SECURITY_SINCE_CURSOR.render({"cursor": "1 or 1=1"})


# --------------------------------------------------------------------------- win.logs.system


def test_system_log_services_clears_and_watched_start_types():
    rows = [
        row(7045, 11, {"ServiceName": "Zoom Sharing Service",
                       "ImagePath": "\"C:\\Program Files\\Zoom\\bin\\CptService.exe\"",
                       "ServiceType": "user mode service", "StartType": "auto start", "AccountName": "LocalSystem"},
            channel="System", provider="Service Control Manager"),
        row(104, 12, {"SubjectUserName": "Ryan", "SubjectDomainName": "RYAN-PC", "Channel": "System"},
            channel="System", provider="Microsoft-Windows-Eventlog", user_data="LogFileCleared"),
        row(6008, 13, ["3:41:12 AM", "10/23/2026", "", "", "", "", ""], channel="System", provider="EventLog"),
        row(7040, 14, {"param1": "Windows Update", "param2": "demand start", "param3": "disabled", "param4": "wuauserv"},
            channel="System", provider="Service Control Manager"),
        row(7040, 15, {"param1": "Background Intelligent Transfer Service", "param2": "auto start",
                       "param3": "demand start", "param4": "BITS"}, channel="System", provider="Service Control Manager"),
    ]
    fixture = {"commands": {el.SYSTEM_FIRST_RUN.name: ps_json({"Newest": 15, "Events": rows})}}
    state = MemoryState()
    out = el.WindowsSystemLog().run(FixtureContext(windows_host(), fixture, state=state))
    assert [(e.action, e.severity) for e in out.events] == [
        ("service_installed", Severity.MEDIUM), ("log_cleared", Severity.HIGH),
        ("unexpected_shutdown", Severity.LOW), ("service_start_type_changed", Severity.MEDIUM)]
    assert out.events[0].data["ImagePath"].endswith("CptService.exe\"")
    assert out.events[1].data["Channel"] == "System"
    assert out.events[3].data["NewStartType"] == "disabled"
    assert state.get("cursor:windows:System") == "15"


def test_system_log_empty_week_passes():
    fixture = {"commands": {el.SYSTEM_FIRST_RUN.name: ps_json({"Newest": 900, "Events": []})}}
    out = el.WindowsSystemLog().run(FixtureContext(windows_host(), fixture))
    assert out.events == [] and out.evidence[0].content["events_read"] == 0


# --------------------------------------------------------------------------- win.logs.defender

DEF = {"channel": "Microsoft-Windows-Windows Defender/Operational", "provider": "Microsoft-Windows-Windows Defender"}


def test_defender_log_detection_and_protection_changes():
    rows = [
        row(1116, 301, {"Threat Name": "Trojan:Win32/Wacatac.B!ml", "Severity Name": "Severe",
                        "Path": "file:_C:\\Users\\Ryan\\Downloads\\crack.exe", "Detection User": "RYAN-PC\\Ryan",
                        "Process Name": "C:\\Windows\\explorer.exe"}, **DEF),
        row(1117, 302, {"Threat Name": "Trojan:Win32/Wacatac.B!ml", "Action Name": "Quarantine",
                        "Detection User": "RYAN-PC\\Ryan"}, **DEF),
        row(5001, 303, {"Product Name": "Microsoft Defender Antivirus"}, **DEF),
        row(5007, 304, {"Old Value": "HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths\\C:\\x = 0x0",
                        "New Value": ""}, **DEF),
    ]
    fixture = {"commands": {el.DEFENDER_FIRST_RUN.name: ps_json({"Newest": 304, "Events": rows})}}
    out = el.WindowsDefenderLog().run(FixtureContext(windows_host(), fixture))
    assert [(e.action, e.severity) for e in out.events] == [
        ("malware_detected", Severity.HIGH), ("malware_action_taken", Severity.MEDIUM),
        ("realtime_protection_disabled", Severity.HIGH), ("defender_config_changed", Severity.LOW)]
    assert out.events[0].data["ThreatName"] == "Trojan:Win32/Wacatac.B!ml"
    assert out.events[0].data["SeverityName"] == "Severe"


def test_defender_log_access_denied_skips():
    fixture = {"commands": {el.DEFENDER_FIRST_RUN.name: ps_json({
        "Events": [], "Error": "Attempted to perform an unauthorized operation.",
        "ErrorId": "System.UnauthorizedAccessException,Microsoft.PowerShell.Commands.GetWinEventCommand"})}}
    with pytest.raises(SkipCheck, match="denied"):
        el.WindowsDefenderLog().run(FixtureContext(windows_host(), fixture))


# --------------------------------------------------------------------------- inventory


def _uninstall(entries_by_source):
    registry = {}
    views = {"registry:HKLM64": ("HKLM", "64"), "registry:HKLM32": ("HKLM", "32"), "registry:HKCU": ("HKCU", None)}
    for source, entries in entries_by_source.items():
        hive, view = views[source]
        registry[reg(hive, inv.UNINSTALL_KEY, "<subkeys>", view)] = list(entries)
        for key, values in entries.items():
            registry[reg(hive, f"{inv.UNINSTALL_KEY}\\{key}", "*", view)] = values
    return {"registry": registry}


def test_software_inventory_filters_and_dedupes():
    fixture = _uninstall({
        "registry:HKLM64": {
            "Git_is1": {"DisplayName": "Git", "DisplayVersion": "2.43.0", "Publisher": "The Git Development Community",
                        "InstallDate": "20240112"},
            "7-Zip": {"DisplayName": "7-Zip 19.00 (x64)", "DisplayVersion": "19.00", "Publisher": "Igor Pavlov"},
            "{KB-Update}": {"DisplayName": "Security Update for X", "ParentKeyName": "OfficeProduct"},
            "{Component}": {"DisplayName": "Microsoft VC++ Minimum Runtime", "SystemComponent": 1},
            "Empty": {"UninstallString": "x"},
        },
        "registry:HKLM32": {"Git_is1": {"DisplayName": "Git", "DisplayVersion": "2.43.0"}},
        "registry:HKCU": {"Discord": {"DisplayName": "Discord", "DisplayVersion": "1.0.9213", "Publisher": "Discord Inc."}},
    })
    out = inv.WindowsSoftwareInventory().run(FixtureContext(windows_host(), fixture))
    got = {(s.name, s.version, s.source) for s in out.software}
    assert got == {("Git", "2.43.0", "registry:HKLM64"), ("7-Zip 19.00 (x64)", "19.00", "registry:HKLM64"),
                   ("Discord", "1.0.9213", "registry:HKCU")}
    assert {s.ecosystem for s in out.software} == {"windows-registry"}
    assert out.findings == []
    assert next(s for s in out.software if s.name == "Git").install_date == "20240112"


def test_software_inventory_unreadable_registry_skips():
    with pytest.raises(SkipCheck):
        inv.WindowsSoftwareInventory().run(FixtureContext(windows_host(), {}))


def test_os_inventory_item_and_insider_evidence():
    host = windows_host(edition="Home", os_build="10.0.26300.7171", is_insider_build=True)
    out = inv.WindowsOsInventory().run(FixtureContext(host, {}))
    item = out.software[0]
    assert (item.name, item.version, item.ecosystem, item.publisher, item.source) == (
        "Microsoft Windows", "10.0.26300.7171", "windows-os", "Microsoft", "host")
    assert out.evidence[0].content["is_insider_build"] is True
    assert out.findings == []


def test_os_inventory_without_build_skips():
    with pytest.raises(SkipCheck):
        inv.WindowsOsInventory().run(FixtureContext(windows_host(os_build=None), {}))
