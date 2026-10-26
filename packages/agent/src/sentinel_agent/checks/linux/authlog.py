"""SSH and sudo events from the systemd journal."""

from __future__ import annotations

import json
import re
from collections import Counter
from datetime import UTC, datetime
from typing import Any

from sentinel_core.checks import Check, CheckContext, SkipCheck
from sentinel_core.commands import CommandParamError, CommandSpec, ParamKind
from sentinel_core.models import CheckOutput, LogEvent, Platform, Severity

from ...safe_commands import CommandFailed, CommandNotFound

SOURCE = "linux:journal"
STATE_KEY = "cursor:linux:journal-auth"
MAX_ENTRIES = 5000
# OpenSSH 9.8+ (Debian 13, Ubuntu 24.10+) logs authentication from "sshd-session" instead of "sshd".
MATCHES = ("_COMM=sshd", "+", "_COMM=sshd-session", "+", "_COMM=sudo")
BASE = ("-o", "json", "--no-pager", "-n", str(MAX_ENTRIES))
JOURNAL_AFTER_CURSOR = CommandSpec("journalctl.auth_after_cursor", "journalctl",
                                   (*BASE, "--after-cursor", "{cursor}", *MATCHES),
                                   params={"cursor": ParamKind.JOURNAL_CURSOR}, timeout=60)
JOURNAL_FIRST_RUN = CommandSpec("journalctl.auth_first_run", "journalctl",
                                (*BASE, "--since", "7 days ago", *MATCHES), timeout=60)

PERMISSION_HINT = (
    "The agent's account cannot read the system journal. Add it to the adm or systemd-journal group "
    "(`sudo usermod -aG systemd-journal <user>`, then sign in again) or run an elevated scan."
)
_PERMISSION_MARKERS = ("insufficient permissions", "not seeing messages from other users", "permission denied",
                       "no journal files were opened")

_FAILED = re.compile(r"^Failed (?P<method>password|keyboard-interactive/pam) for (?P<invalid>invalid user )?"
                     r"(?P<user>.*?) from (?P<ip>[0-9A-Fa-f.:]+) port (?P<port>\d+)")
_ACCEPTED = re.compile(r"^Accepted (?P<method>password|publickey|keyboard-interactive/pam) for (?P<user>\S+) from "
                       r"(?P<ip>[0-9A-Fa-f.:]+) port (?P<port>\d+)")
_INVALID = re.compile(r"^Invalid user (?P<user>.*?) from (?P<ip>[0-9A-Fa-f.:]+)(?: port (?P<port>\d+))?")
_SUDO_PAM_FAIL = re.compile(r"pam_unix\(sudo(?:-i)?:auth\): authentication failure;.*?\buser=(?P<user>\S*)")
_SUDO_LINE = re.compile(r"^\s*(?P<user>\S+) : (?P<rest>.*)$")
_SUDO_TRIES = re.compile(r"(?P<n>\d+) incorrect password attempts?")
_KV = re.compile(r"(TTY|PWD|USER|COMMAND)=(.*?)(?: ; |$)")


def _message(entry: dict[str, Any]) -> str:
    msg = entry.get("MESSAGE")
    if isinstance(msg, list):  # journalctl emits non-UTF-8 messages as a byte array
        try:
            return bytes(int(b) & 0xFF for b in msg).decode("utf-8", errors="replace")
        except (TypeError, ValueError):
            return ""
    return str(msg or "")


def _when(entry: dict[str, Any]) -> datetime | None:
    try:
        return datetime.fromtimestamp(int(entry["__REALTIME_TIMESTAMP"]) / 1_000_000, tz=UTC)
    except (KeyError, TypeError, ValueError, OverflowError, OSError):
        return None


def parse_journal(text: str) -> list[dict[str, Any]]:
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(entry, dict):
            out.append(entry)
    return out


def _ev(entry: dict[str, Any], when: datetime, *, category: str, action: str, message: str,
        severity: Severity = Severity.INFO, outcome: str | None = None, user: str | None = None,
        ip: str | None = None, data: dict[str, Any] | None = None) -> LogEvent:
    return LogEvent(
        source=SOURCE, record_id=str(entry["__CURSOR"])[:600], event_id=None, occurred_at=when, category=category,
        action=action, outcome=outcome, severity=severity, user=(user or None) and user[:256], source_ip=ip,
        process=str(entry.get("_COMM") or entry.get("SYSLOG_IDENTIFIER") or "") or None, message=message[:2000],
        data={k: v for k, v in (data or {}).items() if v not in (None, "")},
    )


def normalize(entry: dict[str, Any], skip_invalid_user_pids: set[str]) -> LogEvent | None:
    when = _when(entry)
    if when is None or not entry.get("__CURSOR"):
        return None
    msg = _message(entry).strip()
    comm = str(entry.get("_COMM") or entry.get("SYSLOG_IDENTIFIER") or "")
    pid = str(entry.get("_PID") or "")
    if comm.startswith("sshd"):
        if m := _FAILED.match(msg):
            invalid = bool(m.group("invalid"))
            return _ev(entry, when, category="authentication", action="ssh_failed", outcome="failure",
                       severity=Severity.LOW, user=m.group("user"), ip=m.group("ip"),
                       message=f"Failed SSH {m.group('method')} sign-in for {'unknown user ' if invalid else ''}"
                               f"{m.group('user')} from {m.group('ip')}",
                       data={"method": m.group("method"), "invalid_user": invalid, "port": m.group("port")})
        if m := _ACCEPTED.match(msg):
            return _ev(entry, when, category="authentication", action="ssh_success", outcome="success",
                       user=m.group("user"), ip=m.group("ip"),
                       message=f"SSH sign-in for {m.group('user')} from {m.group('ip')} ({m.group('method')})",
                       data={"method": m.group("method"), "port": m.group("port")})
        if m := _INVALID.match(msg):
            if pid and pid in skip_invalid_user_pids:
                return None  # the same connection also logged "Failed password for invalid user"; count it once
            return _ev(entry, when, category="authentication", action="ssh_failed", outcome="failure",
                       severity=Severity.LOW, user=m.group("user"), ip=m.group("ip"),
                       message=f"SSH connection for unknown user {m.group('user')} from {m.group('ip')}",
                       data={"invalid_user": True, "port": m.group("port"), "reason": "invalid user"})
        return None
    if comm == "sudo":
        if m := _SUDO_PAM_FAIL.search(msg):
            user = m.group("user") or None
            return _ev(entry, when, category="authentication", action="sudo_failed", outcome="failure",
                       severity=Severity.MEDIUM, user=user, message=f"sudo password check failed for {user}",
                       data={"reason": "authentication failure"})
        if m := _SUDO_LINE.match(msg):
            user, rest = m.group("user"), m.group("rest")
            fields = dict(_KV.findall(rest))
            if t := _SUDO_TRIES.search(rest):
                return _ev(entry, when, category="authentication", action="sudo_failed", outcome="failure",
                           severity=Severity.MEDIUM, user=user,
                           message=f"{user} entered a wrong sudo password {t.group('n')} times",
                           data={"attempts": int(t.group("n")), "run_as": fields.get("USER"),
                                 "command": fields.get("COMMAND")})
            if "NOT in sudoers" in rest or "not allowed to execute" in rest:
                return _ev(entry, when, category="authentication", action="sudo_failed", outcome="failure",
                           severity=Severity.MEDIUM, user=user, message=f"{user} is not allowed to use sudo",
                           data={"reason": "not permitted", "command": fields.get("COMMAND")})
            if "COMMAND" in fields:
                return _ev(entry, when, category="privilege", action="sudo_command", outcome="success", user=user,
                           message=f"{user} ran a command as {fields.get('USER', 'root')} with sudo",
                           data={"run_as": fields.get("USER"), "command": fields.get("COMMAND"),
                                 "cwd": fields.get("PWD"), "tty": fields.get("TTY")})
    return None


def _permission_problem(text: str) -> bool:
    low = text.lower()
    return any(m in low for m in _PERMISSION_MARKERS)


class LinuxAuthLog(Check):
    id = "linux.logs.auth"
    version = "1"
    title = "SSH and sudo activity from the system journal"
    category = "logs"
    platforms = frozenset({Platform.LINUX})
    profiles = frozenset({"logs"})
    timeout_seconds = 120.0
    data_collected = (
        "Journal entries from sshd and sudo: time, account name, source IP, sign-in method, and the commands "
        "run with sudo"
    )
    commands = (JOURNAL_AFTER_CURSOR, JOURNAL_FIRST_RUN)

    def _read(self, ctx: CheckContext) -> tuple[str, str, str]:
        cursor = ctx.state.get(STATE_KEY)
        if cursor:
            try:
                r = ctx.run(JOURNAL_AFTER_CURSOR, cursor=cursor)
                return r.stdout, r.stderr, "entries after the saved cursor"
            except CommandParamError:
                pass  # a corrupted cursor in local state: start over
            except CommandNotFound:
                raise
            except CommandFailed as exc:
                if _permission_problem(exc.stderr or str(exc)):
                    raise
                # The cursor points into a journal file that has since been rotated away.
        window = "last 7 days" + (" (saved cursor was no longer valid)" if cursor else "")
        try:
            r = ctx.run(JOURNAL_FIRST_RUN)
        except CommandNotFound:
            raise
        except CommandFailed as exc:
            if exc.exit_code == 1 and not (exc.stderr or "").strip():
                return "", "", window  # some journalctl versions exit 1 when nothing matches
            raise
        return r.stdout, r.stderr, window

    def run(self, ctx: CheckContext) -> CheckOutput:
        try:
            stdout, stderr, window = self._read(ctx)
        except CommandNotFound as exc:
            raise SkipCheck("journalctl is not installed, so SSH and sudo activity cannot be read") from exc
        except CommandFailed as exc:
            if _permission_problem(exc.stderr or str(exc)):
                raise SkipCheck(PERMISSION_HINT) from exc
            raise SkipCheck(f"journalctl failed: {str(exc)[:200]}") from exc
        entries = parse_journal(stdout)
        if not entries and _permission_problem(stderr):
            raise SkipCheck(PERMISSION_HINT)
        partial_view = _permission_problem(stderr)

        invalid_pids = {str(e.get("_PID")) for e in entries
                        if _FAILED.match(_message(e).strip() or "") and "invalid user" in _message(e) and e.get("_PID")}
        events: list[LogEvent] = []
        counts: Counter[str] = Counter()
        for e in entries:
            ev = normalize(e, invalid_pids)
            if ev is not None:
                events.append(ev)
                counts[ev.action] += 1
        evidence = [ctx.evidence("metric", "journalctl " + " ".join(MATCHES), {
            "window": window,
            "entries_read": len(entries),
            "counts_by_action": dict(sorted(counts.items())),
            "more_pending": len(entries) >= MAX_ENTRIES,
            "note": ("journalctl -n returns the newest entries, so if more than "
                     f"{MAX_ENTRIES} arrived since the last scan the oldest of them are not collected.")
                    if len(entries) >= MAX_ENTRIES else None,
            "partial_view": "Only this user's own entries were visible. " + PERMISSION_HINT if partial_view else None,
        })]
        output = CheckOutput(evidence=evidence, events=events)
        last_cursor = next((str(e["__CURSOR"]) for e in reversed(entries) if e.get("__CURSOR")), None)
        if last_cursor:
            ctx.state.set(STATE_KEY, last_cursor)
        return output
