"""Windows event log collection (Security, System, Microsoft Defender).

Each check reads only the event ids it normalizes, oldest first, starting after the last record id it
saw (kept in agent state). The first run reads the last 7 days. Raw event XML is parsed with defusedxml.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable
from datetime import datetime
from typing import Any, ClassVar

from defusedxml import ElementTree
from sentinel_core.checks import Check, CheckContext, SkipCheck
from sentinel_core.commands import CommandSpec, ParamKind, powershell
from sentinel_core.models import CheckOutput, LogEvent, Platform, Severity

from ...safe_commands import CommandFailed
from .._util import as_int, parse_iso, ps_list

EVENT_NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"
MAX_EVENTS = 2000
FIRST_RUN_WINDOW_MS = 7 * 24 * 3600 * 1000
ADMINISTRATORS_SID = "S-1-5-32-544"
SERVICE_SIDS = {"S-1-5-18", "S-1-5-19", "S-1-5-20"}  # SYSTEM, LOCAL SERVICE, NETWORK SERVICE (names are localized)
SERVICE_NAMES = {"system", "local service", "network service"}


def _xpath(ids: Iterable[int], extra: str) -> str:
    return "*[System[(" + " or ".join(f"EventID={i}" for i in ids) + f") and {extra}]]"


def _script(log_name: str, xpath: str) -> str:
    # Single-quoted PowerShell strings: nothing inside is expanded. Get-WinEvent throws
    # NoMatchingEventsFound when nothing matches, which is an empty result, not an error.
    return (
        "$r = [ordered]@{Newest=$null; Events=@()}; "
        f"try {{ $r.Newest = (Get-WinEvent -LogName '{log_name}' -MaxEvents 1 -ErrorAction Stop).RecordId }} catch {{ }}; "
        f"try {{ $r.Events = @(Get-WinEvent -LogName '{log_name}' -FilterXPath '{xpath}' -MaxEvents {MAX_EVENTS} "
        "-Oldest -ErrorAction Stop | ForEach-Object { [pscustomobject]@{RecordId=$_.RecordId; Id=$_.Id; "
        "Time=$_.TimeCreated.ToUniversalTime().ToString('o'); Xml=$_.ToXml()} }) } "
        "catch { if ([string]$_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') { "
        "$r.Error = [string]$_.Exception.Message; $r.ErrorId = [string]$_.FullyQualifiedErrorId } }; "
        "[pscustomobject]$r | ConvertTo-Json -Depth 4 -Compress"
    )


def log_specs(prefix: str, log_name: str, ids: tuple[int, ...]) -> tuple[CommandSpec, CommandSpec]:
    """(after-cursor spec, first-run spec). Built once at import time from constants."""
    since_cursor = powershell(f"ps.winlog_{prefix}_since_cursor",
                              _script(log_name, _xpath(ids, "EventRecordID > {cursor}")),
                              timeout=150, params={"cursor": ParamKind.INT})
    first_run = powershell(f"ps.winlog_{prefix}_first_run",
                           _script(log_name, _xpath(ids, f"TimeCreated[timediff(@SystemTime) <= {FIRST_RUN_WINDOW_MS}]")),
                           timeout=150)
    return since_cursor, first_run


def parse_event_xml(xml: str) -> tuple[dict[str, Any], dict[str, str]]:
    """Return (system fields, data fields). Named <Data> and <UserData> children are keyed by name;
    unnamed <Data> elements become param1, param2, ..."""
    root = ElementTree.fromstring(xml)
    system: dict[str, Any] = {}
    sys_el = root.find(f"{EVENT_NS}System")
    if sys_el is not None:
        for child in sys_el:
            tag = child.tag.replace(EVENT_NS, "")
            if tag == "TimeCreated":
                system["TimeCreated"] = child.get("SystemTime")
            elif tag == "Provider":
                system["Provider"] = child.get("Name")
            elif tag == "Security":
                system["UserID"] = child.get("UserID")
            elif tag == "Execution":
                system["ProcessID"] = child.get("ProcessID")
            else:
                system[tag] = (child.text or "").strip()
    data: dict[str, str] = {}
    event_data = root.find(f"{EVENT_NS}EventData")
    if event_data is not None:
        unnamed = 0
        for d in event_data.findall(f"{EVENT_NS}Data"):
            name = d.get("Name")
            if not name:
                unnamed += 1
                name = f"param{unnamed}"
            data[name] = (d.text or "").strip()
    user_data = root.find(f"{EVENT_NS}UserData")
    if user_data is not None:
        for wrapper in user_data:
            for child in wrapper:
                data[child.tag.rsplit("}", 1)[-1]] = (child.text or "").strip()
    return system, data


def clean(value: str | None) -> str | None:
    if value is None:
        return None
    value = value.strip()
    return None if value in ("", "-") else value


class WindowsLogCheck(Check):
    """Shared cursor handling; subclasses set the channel and implement ``normalize``."""

    platforms = frozenset({Platform.WINDOWS})
    profiles = frozenset({"logs"})
    category = "logs"
    timeout_seconds = 180.0
    log_name: ClassVar[str]
    source: ClassVar[str]
    state_key: ClassVar[str]
    since_cursor_spec: ClassVar[CommandSpec]
    first_run_spec: ClassVar[CommandSpec]

    def normalize(self, event_id: int, when: datetime, record_id: str, system: dict[str, Any],
                  data: dict[str, str]) -> LogEvent | None:
        raise NotImplementedError

    def _read(self, ctx: CheckContext) -> tuple[dict[str, Any], str]:
        cursor = ctx.state.get(self.state_key)
        try:
            if cursor and cursor.isdigit():
                result = ctx.run_json(self.since_cursor_spec, cursor=int(cursor))
                newest = as_int(result.get("Newest")) if isinstance(result, dict) else None
                if newest is None or newest >= int(cursor):
                    return (result if isinstance(result, dict) else {}), f"records after {cursor}"
                # Record ids restart when a log is cleared; start over rather than wait past the old cursor.
                return ctx.run_json(self.first_run_spec) or {}, f"last 7 days (log restarted below record {cursor})"
            return ctx.run_json(self.first_run_spec) or {}, "last 7 days (first collection)"
        except CommandFailed as exc:
            raise SkipCheck(f"The {self.log_name} log could not be read: {str(exc)[:200]}") from exc

    def run(self, ctx: CheckContext) -> CheckOutput:
        data, window = self._read(ctx)
        if not isinstance(data, dict):
            raise SkipCheck(f"The {self.log_name} log could not be read (unexpected output)")
        error_id = str(data.get("ErrorId") or "")
        if data.get("Error"):
            if "UnauthorizedAccess" in error_id or "unauthorized" in str(data["Error"]).lower():
                raise SkipCheck(f"Access to the {self.log_name} log was denied. Run an elevated scan to include it.")
            if "NoMatchingLogsFound" in error_id:
                raise SkipCheck(f"The {self.log_name} log does not exist on this PC")
            raise SkipCheck(f"The {self.log_name} log could not be read: {str(data['Error'])[:200]}")

        rows = [r for r in ps_list(data.get("Events")) if isinstance(r, dict)]
        events: list[LogEvent] = []
        seen: Counter[str] = Counter()
        kept: Counter[str] = Counter()
        unparsed = 0
        max_record: int | None = None
        for row in rows:
            record = as_int(row.get("RecordId"))
            event_id = as_int(row.get("Id"))
            if record is None or event_id is None:
                unparsed += 1
                continue
            max_record = record if max_record is None else max(max_record, record)
            seen[str(event_id)] += 1
            try:
                system, fields = parse_event_xml(str(row.get("Xml") or ""))
            except ElementTree.ParseError:
                unparsed += 1
                continue
            when = parse_iso(row.get("Time")) or parse_iso(system.get("TimeCreated"))
            if when is None:
                unparsed += 1
                continue
            event = self.normalize(event_id, when, str(record), system, fields)
            if event is not None:
                events.append(event)
                kept[event.action] += 1
        evidence = [ctx.evidence("metric", f"Get-WinEvent -LogName '{self.log_name}'", {
            "window": window,
            "events_read": len(rows),
            "counts_by_event_id": dict(sorted(seen.items())),
            "kept_by_action": dict(sorted(kept.items())),
            "unparsed": unparsed,
            "more_pending": len(rows) >= MAX_EVENTS,
            "newest_record_in_log": data.get("Newest"),
        })]
        output = CheckOutput(evidence=evidence, events=events)
        if max_record is not None:
            ctx.state.set(self.state_key, str(max_record))
        return output

    def event(self, event_id: int, when: datetime, record_id: str, *, category: str, action: str, message: str,
              severity: Severity = Severity.INFO, outcome: str | None = None, user: str | None = None,
              source_ip: str | None = None, process: str | None = None, data: dict[str, Any] | None = None) -> LogEvent:
        return LogEvent(
            source=self.source, record_id=record_id, event_id=str(event_id), occurred_at=when, category=category,
            action=action, outcome=outcome, severity=severity, user=(user or None) and user[:256],
            source_ip=clean(source_ip), process=(process or None) and process[:1024], message=message[:2000],
            data={k: v for k, v in (data or {}).items() if v not in (None, "")},
        )


# --------------------------------------------------------------------------- Security

SECURITY_IDS = (4624, 4625, 4648, 4672, 4720, 4722, 4724, 4728, 4732, 4756, 4740, 1102, 4697, 4698)
SECURITY_SINCE_CURSOR, SECURITY_FIRST_RUN = log_specs("security", "Security", SECURITY_IDS)
KEPT_LOGON_TYPES = {"2", "3", "7", "10", "11"}
LOGON_TYPE_NAMES = {"2": "interactive", "3": "network", "7": "unlock", "10": "remote desktop", "11": "cached"}


def _ip_suffix(ip: str | None) -> str:
    ip = clean(ip)
    return f" from {ip}" if ip else ""


class WindowsSecurityLog(WindowsLogCheck):
    id = "win.logs.security"
    version = "1"
    title = "Windows Security log: sign-ins and account changes"
    requires_elevation = True
    data_collected = (
        "Security log events for sign-ins (successful, failed, explicit credentials, admin privileges), account "
        "creation, enabling, password resets, group membership changes, lockouts, service and scheduled-task "
        "installs, and audit log clearing: time, account names, source IP, logon type and the program involved"
    )
    log_name = "Security"
    source = "windows:Security"
    state_key = "cursor:windows:Security"
    since_cursor_spec = SECURITY_SINCE_CURSOR
    first_run_spec = SECURITY_FIRST_RUN
    commands = (SECURITY_SINCE_CURSOR, SECURITY_FIRST_RUN)

    def normalize(self, eid: int, when: datetime, rid: str, system: dict[str, Any], d: dict[str, str]) -> LogEvent | None:
        target, subject = clean(d.get("TargetUserName")), clean(d.get("SubjectUserName"))
        ip, process = clean(d.get("IpAddress")), clean(d.get("ProcessName"))
        if eid == 4624:
            lt = d.get("LogonType", "")
            if lt not in KEPT_LOGON_TYPES:
                return None
            return self.event(eid, when, rid, category="authentication", action="logon_success", outcome="success",
                              user=target, source_ip=ip, process=process,
                              message=f"Successful {LOGON_TYPE_NAMES.get(lt, 'type ' + lt)} sign-in for "
                                      f"{target}{_ip_suffix(ip)}",
                              data={"LogonType": lt, "TargetUserName": target,
                                    "TargetDomainName": clean(d.get("TargetDomainName")), "IpAddress": ip,
                                    "WorkstationName": clean(d.get("WorkstationName")),
                                    "AuthenticationPackageName": clean(d.get("AuthenticationPackageName"))})
        if eid == 4625:
            lt = d.get("LogonType", "")
            return self.event(eid, when, rid, category="authentication", action="logon_failed", outcome="failure",
                              severity=Severity.LOW, user=target, source_ip=ip, process=process,
                              message=f"Failed {LOGON_TYPE_NAMES.get(lt, 'type ' + lt)} sign-in for {target}"
                                      f"{_ip_suffix(ip)} (status {d.get('Status', '?')}, "
                                      f"sub-status {d.get('SubStatus', '?')})",
                              data={"TargetUserName": target, "IpAddress": ip, "Status": d.get("Status"),
                                    "SubStatus": d.get("SubStatus"), "LogonType": lt,
                                    "WorkstationName": clean(d.get("WorkstationName"))})
        if eid == 4648:
            return self.event(eid, when, rid, category="authentication", action="explicit_credentials",
                              user=subject, source_ip=ip, process=process,
                              message=f"{subject} used the credentials of {target} explicitly"
                                      f"{' for ' + d['TargetServerName'] if clean(d.get('TargetServerName')) else ''}",
                              data={"SubjectUserName": subject, "TargetUserName": target,
                                    "TargetServerName": clean(d.get("TargetServerName"))})
        if eid == 4672:
            sid = d.get("SubjectUserSid", "")
            if sid in SERVICE_SIDS or (subject or "").lower() in SERVICE_NAMES or (subject or "").endswith("$"):
                return None
            return self.event(eid, when, rid, category="authentication", action="special_privileges", user=subject,
                              message=f"{subject} signed in with administrator-level privileges",
                              data={"SubjectUserName": subject, "SubjectUserSid": sid,
                                    "PrivilegeList": " ".join((d.get("PrivilegeList") or "").split())})
        if eid in (4720, 4722, 4724):
            action, sev, verb = {4720: ("account_created", Severity.MEDIUM, "created account"),
                                 4722: ("account_enabled", Severity.INFO, "enabled account"),
                                 4724: ("password_reset", Severity.INFO, "reset the password of")}[eid]
            return self.event(eid, when, rid, category="account_management", action=action, severity=sev, user=target,
                              message=f"{subject} {verb} {target}",
                              data={"TargetUserName": target, "TargetSid": d.get("TargetSid"), "SubjectUserName": subject})
        if eid in (4728, 4732, 4756):
            group_sid = d.get("TargetSid", "")
            member = clean(d.get("MemberName")) or d.get("MemberSid")
            admin = group_sid == ADMINISTRATORS_SID
            return self.event(eid, when, rid, category="account_management", action="group_member_added",
                              severity=Severity.HIGH if admin else Severity.INFO, user=member,
                              message=f"{subject} added {member} to group {target}"
                                      + (" (local Administrators)" if admin else ""),
                              data={"TargetSid": group_sid, "GroupName": target, "MemberSid": d.get("MemberSid"),
                                    "MemberName": clean(d.get("MemberName")), "SubjectUserName": subject})
        if eid == 4740:
            return self.event(eid, when, rid, category="account_management", action="account_locked_out",
                              severity=Severity.MEDIUM, user=target,
                              message=f"Account {target} was locked out after repeated failed sign-ins",
                              data={"TargetUserName": target, "CallerComputerName": clean(d.get("TargetDomainName"))})
        if eid == 1102:
            return self.event(eid, when, rid, category="audit", action="audit_log_cleared", severity=Severity.HIGH,
                              user=subject,
                              message=f"The Security audit log was cleared by {subject or 'an unknown account'}",
                              data={"SubjectUserName": subject, "SubjectDomainName": clean(d.get("SubjectDomainName"))})
        if eid == 4697:
            return self.event(eid, when, rid, category="service", action="service_installed", severity=Severity.MEDIUM,
                              user=subject, process=clean(d.get("ServiceFileName")),
                              message=f"Service {d.get('ServiceName')} was installed by {subject}",
                              data={"ServiceName": d.get("ServiceName"), "ServiceFileName": d.get("ServiceFileName"),
                                    "ServiceStartType": d.get("ServiceStartType"),
                                    "ServiceAccount": d.get("ServiceAccount")})
        if eid == 4698:
            return self.event(eid, when, rid, category="service", action="scheduled_task_created", user=subject,
                              message=f"Scheduled task {d.get('TaskName')} was created by {subject}",
                              data={"TaskName": d.get("TaskName"), "SubjectUserName": subject})
        return None


# --------------------------------------------------------------------------- System

SYSTEM_IDS = (7045, 104, 6008, 7040)
SYSTEM_SINCE_CURSOR, SYSTEM_FIRST_RUN = log_specs("system", "System", SYSTEM_IDS)
WATCHED_SERVICES = {"windefend": "Microsoft Defender Antivirus", "wuauserv": "Windows Update",
                    "mpssvc": "Windows Defender Firewall"}
WATCHED_DISPLAY_NAMES = {"microsoft defender antivirus service", "windows defender antivirus service", "windows update",
                         "windows defender firewall", "windows firewall"}


class WindowsSystemLog(WindowsLogCheck):
    id = "win.logs.system"
    version = "1"
    title = "Windows System log: new services, log clearing and crashes"
    data_collected = (
        "System log events for new services (name, program path, start type, account), log clearing, unexpected "
        "shutdowns, and start-type changes of Microsoft Defender, Windows Update and the firewall service"
    )
    log_name = "System"
    source = "windows:System"
    state_key = "cursor:windows:System"
    since_cursor_spec = SYSTEM_SINCE_CURSOR
    first_run_spec = SYSTEM_FIRST_RUN
    commands = (SYSTEM_SINCE_CURSOR, SYSTEM_FIRST_RUN)

    def normalize(self, eid: int, when: datetime, rid: str, system: dict[str, Any], d: dict[str, str]) -> LogEvent | None:
        if eid == 7045:
            return self.event(eid, when, rid, category="service", action="service_installed", severity=Severity.MEDIUM,
                              user=clean(d.get("AccountName")), process=clean(d.get("ImagePath")),
                              message=f"Service {d.get('ServiceName')} was installed ({d.get('ImagePath')})",
                              data={k: d.get(k) for k in ("ServiceName", "ImagePath", "StartType", "AccountName",
                                                          "ServiceType")})
        if eid == 104:
            channel = d.get("Channel") or "an event"
            who = clean(d.get("SubjectUserName"))
            return self.event(eid, when, rid, category="audit", action="log_cleared", severity=Severity.HIGH, user=who,
                              message=f"The {channel} log was cleared by {who or 'an unknown account'}",
                              data={"Channel": d.get("Channel"), "SubjectUserName": clean(d.get("SubjectUserName")),
                                    "SubjectDomainName": clean(d.get("SubjectDomainName"))})
        if eid == 6008:
            return self.event(eid, when, rid, category="system", action="unexpected_shutdown", severity=Severity.LOW,
                              message="The previous shutdown was unexpected (power loss, crash or forced power-off)",
                              data={"param1": d.get("param1"), "param2": d.get("param2")})
        if eid == 7040:
            key = (d.get("param4") or "").lower()
            display = (d.get("param1") or "").lower()
            if key not in WATCHED_SERVICES and display not in WATCHED_DISPLAY_NAMES:
                return None
            return self.event(eid, when, rid, category="service", action="service_start_type_changed",
                              severity=Severity.MEDIUM,
                              message=f"Start type of {d.get('param1')} changed from {d.get('param2')} to {d.get('param3')}",
                              data={"ServiceName": d.get("param4"), "DisplayName": d.get("param1"),
                                    "OldStartType": d.get("param2"), "NewStartType": d.get("param3")})
        return None


# --------------------------------------------------------------------------- Microsoft Defender

DEFENDER_LOG = "Microsoft-Windows-Windows Defender/Operational"
DEFENDER_IDS = (1116, 1006, 1015, 1117, 5001, 5007)
DEFENDER_SINCE_CURSOR, DEFENDER_FIRST_RUN = log_specs("defender", DEFENDER_LOG, DEFENDER_IDS)


class WindowsDefenderLog(WindowsLogCheck):
    id = "win.logs.defender"
    version = "1"
    title = "Microsoft Defender log: detections and protection changes"
    data_collected = (
        "Microsoft Defender events for malware detections (threat name, file path, severity), actions taken, "
        "real-time protection being turned off and configuration changes"
    )
    log_name = DEFENDER_LOG
    source = "windows:Defender"
    state_key = "cursor:windows:Defender"
    since_cursor_spec = DEFENDER_SINCE_CURSOR
    first_run_spec = DEFENDER_FIRST_RUN
    commands = (DEFENDER_SINCE_CURSOR, DEFENDER_FIRST_RUN)

    def normalize(self, eid: int, when: datetime, rid: str, system: dict[str, Any], d: dict[str, str]) -> LogEvent | None:
        threat, path = d.get("Threat Name"), clean(d.get("Path"))
        details = {"ThreatName": threat, "Path": path, "SeverityName": d.get("Severity Name"),
                   "ActionName": d.get("Action Name"), "ProcessName": clean(d.get("Process Name")),
                   "DetectionUser": clean(d.get("Detection User"))}
        if eid in (1116, 1006, 1015):
            return self.event(eid, when, rid, category="malware", action="malware_detected", severity=Severity.HIGH,
                              user=details["DetectionUser"], process=details["ProcessName"],
                              message=f"Microsoft Defender detected {threat or 'malware'}" + (f" in {path}" if path else ""),
                              data=details)
        if eid == 1117:
            return self.event(eid, when, rid, category="malware", action="malware_action_taken", severity=Severity.MEDIUM,
                              user=details["DetectionUser"],
                              message=f"Microsoft Defender took action ({d.get('Action Name') or 'unknown'}) "
                                      f"against {threat or 'malware'}",
                              data=details)
        if eid == 5001:
            return self.event(eid, when, rid, category="malware", action="realtime_protection_disabled",
                              severity=Severity.HIGH, message="Microsoft Defender real-time protection was turned off")
        if eid == 5007:
            return self.event(eid, when, rid, category="malware", action="defender_config_changed", severity=Severity.LOW,
                              message="Microsoft Defender configuration changed",
                              data={"OldValue": d.get("Old Value"), "NewValue": d.get("New Value")})
        return None
