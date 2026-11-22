"""Map Linux audit records to Sentinel X telemetry events.

Sysmon is to Windows what the kernel audit subsystem is to Linux: a supported way to be told about process
executions, network connections and file changes as they happen. Once a few audit rules are loaded
(``scripts/linux/sentinel-audit.rules``), the kernel emits records like these for every program that starts::

    type=SYSCALL msg=audit(1731975000.123:4567): arch=c000003e syscall=59 success=yes exit=0 ppid=1000 pid=1001
        auid=1000 uid=1000 comm="curl" exe="/usr/bin/curl" key="sentinel_exec"
    type=EXECVE msg=audit(1731975000.123:4567): argc=3 a0="curl" a1="-s" a2="http://198.51.100.7/x"
    type=CWD msg=audit(1731975000.123:4567): cwd="/home/sam"

Several records share one ``audit(time:serial)`` stamp and together describe one event. This module groups
them and translates each group into the same :class:`~sentinel_core.telemetry.TelemetryEvent` the Windows
collector produces, so the engine and its rules do not care which operating system an event came from:

==================================  ================  ==========================================
 records in the group               our EventKind     what it needs loaded
==================================  ================  ==========================================
 SYSCALL + EXECVE                   process_create    an ``execve`` rule
 SYSCALL(connect) + SOCKADDR        network_connect   a ``connect`` rule
 SYSCALL + PATH nametype=CREATE     file_write        a watch on the folder
 SYSCALL + PATH nametype=DELETE     file_delete       a watch on the folder
==================================  ================  ==========================================

Two things differ from Windows and are handled here rather than in the rules. Linux has no process GUID, and
PIDs are reused, so a process is identified as ``lx:<pid>:<serial of its exec>``; an :class:`AuditState` kept
across batches remembers which identity each live PID has. And a value with spaces or odd bytes is written by
the kernel as bare hexadecimal (``a2=2F746D702F6120622E7368``), which is decoded back to text.

The parser is pure: text in, events out. It accepts the raw ``audit.log`` format and journal entries (which is
how the agent reads audit records without root), and never executes anything it reads.
"""

from __future__ import annotations

import ipaddress
import re
import shlex
from collections import OrderedDict
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from sentinel_core.telemetry import EventKind, TelemetryEvent

_HEADER = re.compile(r"type=(?P<type>[A-Z_0-9]+)\s+msg=audit\((?P<secs>\d+)\.(?P<ms>\d+):(?P<serial>\d+)\):\s*(?P<body>.*)")
_FIELD = re.compile(r'(?P<key>[A-Za-z_][\w\[\]]*)=(?:"(?P<quoted>[^"]*)"|(?P<bare>\S*))')
_HEX = re.compile(r"^(?:[0-9A-Fa-f]{2})+$")

# connect(2) by architecture, as the kernel numbers it. execve is recognised by its EXECVE record instead.
_CONNECT = {"c000003e": 42, "c00000b7": 203, "40000028": 283, "40000003": 362}
MAX_TRACKED_PIDS = 50_000


@dataclass
class AuditRecord:
    type: str
    when: datetime
    serial: int
    fields: dict[str, str]
    encoded: frozenset[str] = frozenset()  # fields the kernel wrote as bare (unquoted) values


@dataclass
class AuditState:
    """Which process identity each PID currently has, and its executable. Kept across batches."""

    guids: OrderedDict[int, str] = field(default_factory=OrderedDict)
    images: dict[int, str] = field(default_factory=dict)
    seq: int = 0

    def identity(self, pid: int) -> str:
        return self.guids.get(pid) or f"lx:{pid}:0"  # a process that started before we were listening

    def started(self, pid: int, serial: int, image: str) -> str:
        guid = f"lx:{pid}:{serial}"
        self.guids.pop(pid, None)
        self.guids[pid] = guid
        self.images[pid] = image
        while len(self.guids) > MAX_TRACKED_PIDS:
            old, _ = self.guids.popitem(last=False)
            self.images.pop(old, None)
        return guid

    def next_seq(self) -> int:
        self.seq += 1
        return self.seq - 1


# --------------------------------------------------------------------------- reading records


def _fields(body: str) -> tuple[dict[str, str], frozenset[str]]:
    out: dict[str, str] = {}
    bare: set[str] = set()
    for m in _FIELD.finditer(body):
        key = m.group("key")
        if m.group("quoted") is not None:
            out[key] = m.group("quoted")
        else:
            out[key] = m.group("bare") or ""
            bare.add(key)
    return out, frozenset(bare)


def decode(value: str | None, was_bare: bool) -> str | None:
    """Undo the kernel's hex encoding of an untrusted string. Quoted values are already plain text."""
    if value is None or value == "(null)":
        return None
    if was_bare and len(value) >= 2 and _HEX.match(value):
        try:
            return bytes.fromhex(value).replace(b"\x00", b" ").decode("utf-8", errors="replace").strip()
        except ValueError:
            return value
    return value


def parse_line(line: str) -> AuditRecord | None:
    """One raw audit record (``type=... msg=audit(...): ...``), wherever it sits in the line."""
    m = _HEADER.search(line)
    if m is None:
        return None
    fields, bare = _fields(m.group("body"))
    when = datetime.fromtimestamp(int(m.group("secs")) + int(m.group("ms")[:3].ljust(3, "0")) / 1000, tz=UTC)
    return AuditRecord(m.group("type"), when, int(m.group("serial")), fields, bare)


def record_from_journal(entry: dict[str, Any]) -> AuditRecord | None:
    """One journal entry carrying an audit record.

    journald stores audit records either as the raw line (when forwarded by auditd's syslog plugin) or split
    into fields, with the type in ``_AUDIT_TYPE_NAME``, the serial in ``_AUDIT_ID`` and the record body, led by
    its type name, in ``MESSAGE``. Both shapes are accepted.
    """
    message = entry.get("MESSAGE")
    if isinstance(message, list):  # journalctl emits non-UTF-8 messages as a byte array
        try:
            message = bytes(int(b) & 0xFF for b in message).decode("utf-8", errors="replace")
        except (TypeError, ValueError):
            return None
    if not isinstance(message, str):
        return None
    raw = parse_line(message)
    if raw is not None:
        return raw
    kind = str(entry.get("_AUDIT_TYPE_NAME") or message.split(" ", 1)[0])
    try:
        serial = int(entry["_AUDIT_ID"])
        micros = int(entry.get("_SOURCE_REALTIME_TIMESTAMP") or entry["__REALTIME_TIMESTAMP"])
        when = datetime.fromtimestamp(micros / 1_000_000, tz=UTC)
    except (KeyError, TypeError, ValueError, OverflowError, OSError):
        return None
    body = message[len(kind):].lstrip() if message.startswith(kind) else message
    fields, bare = _fields(body)
    return AuditRecord(kind, when, serial, fields, bare) if kind.isupper() else None


# --------------------------------------------------------------------------- records -> events


def _int(value: str | None) -> int | None:
    try:
        return int(value) if value is not None else None
    except ValueError:
        return None


def _command_line(execve: AuditRecord) -> str | None:
    args: dict[int, str] = {}
    for key, value in execve.fields.items():
        m = re.fullmatch(r"a(\d+)(?:\[(\d+)\])?", key)
        if m is None:
            continue
        text = decode(value, key in execve.encoded) or ""
        index = int(m.group(1))
        args[index] = args.get(index, "") + text  # long arguments arrive in numbered pieces
    if not args:
        return None
    return " ".join(shlex.quote(args[i]) if args[i] else "''" for i in sorted(args))[:8192]


def parse_sockaddr(saddr: str | None) -> tuple[str, int] | None:
    """``saddr`` is a hex dump of the kernel's socket address. Returns (ip, port) for IPv4/IPv6, else None."""
    if not saddr or not _HEX.match(saddr):
        return None
    raw = bytes.fromhex(saddr)
    if len(raw) < 8:
        return None
    family = int.from_bytes(raw[0:2], "little")
    port = int.from_bytes(raw[2:4], "big")
    if family == 2:  # AF_INET
        return str(ipaddress.IPv4Address(raw[4:8])), port
    if family == 10 and len(raw) >= 24:  # AF_INET6
        return str(ipaddress.IPv6Address(raw[8:24])), port
    return None


def _user(syscall: AuditRecord) -> str | None:
    uid = syscall.fields.get("uid")
    return f"uid={uid}" if uid is not None else None


def events_from_group(records: list[AuditRecord], host: str, state: AuditState) -> list[TelemetryEvent]:
    """Translate the records of one audit event (same serial) into zero or more telemetry events."""
    by_type: dict[str, list[AuditRecord]] = {}
    for record in records:
        by_type.setdefault(record.type, []).append(record)
    syscall = next(iter(by_type.get("SYSCALL", [])), None)
    if syscall is None:
        return []
    f = syscall.fields
    pid = _int(f.get("pid"))
    if pid is None:
        return []
    exe = decode(f.get("exe"), "exe" in syscall.encoded) or ""
    common: dict[str, Any] = {"host": host[:256], "ts": syscall.when, "pid": pid, "user": _user(syscall)}
    details = {k: v for k, v in {"audit_key": f.get("key"), "auid": f.get("auid"), "comm": f.get("comm")}.items()
               if v and v != "(null)"}
    cwd = next((decode(r.fields.get("cwd"), "cwd" in r.encoded) for r in by_type.get("CWD", [])), None)

    execve = next(iter(by_type.get("EXECVE", [])), None)
    if execve is not None:
        if f.get("success") != "yes":
            return []
        ppid = _int(f.get("ppid"))
        parent_guid = state.identity(ppid) if ppid is not None else None
        parent_image = state.images.get(ppid) if ppid is not None else None
        guid = state.started(pid, syscall.serial, exe)
        if cwd:
            details["current_directory"] = cwd
        return [TelemetryEvent(
            kind=EventKind.PROCESS_CREATE, seq=state.next_seq(), process_guid=guid, image=exe[:1024],
            command_line=_command_line(execve), parent_pid=ppid, parent_guid=parent_guid,
            parent_image=parent_image, details=details, **common,
        )]

    guid = state.identity(pid)
    events: list[TelemetryEvent] = []
    sockaddr = next(iter(by_type.get("SOCKADDR", [])), None)
    if sockaddr is not None and _int(f.get("syscall")) == _CONNECT.get(f.get("arch", "")):
        dest = parse_sockaddr(sockaddr.fields.get("saddr"))
        # A non-blocking connect reports EINPROGRESS (-115); the attempt was still made.
        if dest is not None and (f.get("success") == "yes" or f.get("exit") == "-115"):
            events.append(TelemetryEvent(
                kind=EventKind.NETWORK_CONNECT, seq=state.next_seq(), process_guid=guid, image=exe[:1024],
                dest_ip=dest[0], dest_port=dest[1], direction="outbound", details=details, **common,
            ))
    if f.get("success") == "yes":
        for path in by_type.get("PATH", []):
            nametype = path.fields.get("nametype")
            if nametype not in ("CREATE", "DELETE"):
                continue
            name = decode(path.fields.get("name"), "name" in path.encoded)
            if not name:
                continue
            if not name.startswith("/") and cwd:
                name = f"{cwd.rstrip('/')}/{name}"
            events.append(TelemetryEvent(
                kind=EventKind.FILE_WRITE if nametype == "CREATE" else EventKind.FILE_DELETE,
                seq=state.next_seq(), process_guid=guid, image=exe[:1024], file_path=name[:1024],
                details=details, **common,
            ))
    return events


def events_from_records(records: Iterable[AuditRecord], host: str, state: AuditState | None = None) -> list[TelemetryEvent]:
    """Group records by audit event and translate each group, in the order the events occurred."""
    state = state if state is not None else AuditState()
    groups: OrderedDict[tuple[datetime, int], list[AuditRecord]] = OrderedDict()
    for record in records:
        groups.setdefault((record.when, record.serial), []).append(record)
    events: list[TelemetryEvent] = []
    for key in sorted(groups, key=lambda k: (k[0], k[1])):
        events.extend(events_from_group(groups[key], host, state))
    return events


def parse_audit_log(text: str, host: str = "", state: AuditState | None = None) -> list[TelemetryEvent]:
    """Parse a saved ``audit.log`` (or ``ausearch --raw`` output) into telemetry events."""
    records = [r for r in (parse_line(line) for line in text.splitlines()) if r is not None]
    node = next((m.group(1) for m in (re.match(r"node=(\S+)\s", line) for line in text.splitlines()[:50]) if m), "")
    return events_from_records(records, host or node, state)
