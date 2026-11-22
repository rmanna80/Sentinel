"""Tradecraft rules: well-known attacker techniques that show up as one recognisable action.

The rules in :mod:`.rules` are about *lineage* - who spawned what. The rules here are about *what was done*:
dumping credentials out of LSASS, registering a scheduled task, abusing a signed Windows binary to fetch or
run code, destroying the backups a victim would restore from, and encrypting files in bulk. Most are
contextual (one event, judged with the process tree); ``MassFileEncryption`` is a second worked example of a
stateful rule, counting events per process inside a sliding window.

Every rule here is a heuristic with a stated reason for firing and a stated way to be wrong. None of them
proves compromise: backup software deletes shadow copies, administrators create scheduled tasks, and security
tools read LSASS. The rules narrow each behaviour to the variants ordinary use rarely produces, and the
suppression list is the place to record the exceptions your own environment needs.
"""

from __future__ import annotations

import re
from collections import Counter, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from sentinel_core.models import Confidence, Severity
from sentinel_core.telemetry import Detection, EventKind, TelemetryEvent

from .process_tree import ProcessTree, _basename
from .rules import (
    LOLBINS,
    SUSPICIOUS_PATH_MARKERS,
    Emit,
    Rule,
    _in_suspicious_path,
    _is_interpreter,
    _is_office,
    _norm,
)

# --------------------------------------------------------------------------- helpers

_ENV_STAGING = ("%temp%", "%tmp%", "%appdata%", "%localappdata%", "%public%", "%programdata%")
_URL = re.compile(r"\b(?:https?|ftp)://", re.IGNORECASE)
_SCRIPT_PROTOCOL = re.compile(r"\b(?:javascript|vbscript):", re.IGNORECASE)
# PowerShell flags that hide what is being run: -enc/-encodedcommand, -w hidden, and download cradles.
_OBFUSCATED_SHELL = re.compile(
    r"(?:\s-e(?:nc|ncodedcommand|c)?\s+[A-Za-z0-9+/=]{16,})|(?:-w(?:indowstyle)?\s+hid)|downloadstring|"
    r"downloadfile|invoke-webrequest|\biwr\b|\biex\b|invoke-expression|frombase64string",
    re.IGNORECASE,
)


def _cmd(event: TelemetryEvent) -> str:
    return (event.command_line or "").lower()


def _mentions_staging_path(text: str) -> bool:
    n = _norm(text)
    return any(marker in n for marker in SUSPICIOUS_PATH_MARKERS) or any(v in n for v in _ENV_STAGING)


def _has_flag(cmd: str, *names: str) -> bool:
    """True when the command line carries one of ``names`` as a ``/flag`` or ``-flag`` (Windows accepts both)."""
    return any(re.search(rf"(?:^|\s)[/-]{re.escape(name)}\b", cmd) for name in names)


def _is_create(event: TelemetryEvent, *basenames: str) -> bool:
    return event.kind is EventKind.PROCESS_CREATE and _basename(event.image) in basenames


# --------------------------------------------------------------------------- credential access

# Handle rights that let a process read another's memory. PROCESS_VM_READ is the one credential dumpers need;
# the common benign LSASS access (0x1000, PROCESS_QUERY_LIMITED_INFORMATION) does not include it.
PROCESS_VM_READ = 0x0010

# Windows components that legitimately read LSASS memory. Matched on full path, never on name alone, so a
# copy of "svchost.exe" dropped in a temp folder is not trusted.
_TRUSTED_LSASS_READERS = (
    "c:/windows/system32/svchost.exe", "c:/windows/system32/csrss.exe", "c:/windows/system32/wininit.exe",
    "c:/windows/system32/services.exe", "c:/windows/system32/lsass.exe", "c:/windows/system32/winlogon.exe",
    "c:/windows/system32/smss.exe", "c:/windows/system32/wbem/wmiprvse.exe", "c:/windows/system32/werfault.exe",
    "c:/windows/system32/taskmgr.exe", "c:/windows/system32/lsm.exe",
)
_TRUSTED_LSASS_PREFIXES = (
    "c:/programdata/microsoft/windows defender/", "c:/program files/windows defender/",
    "c:/program files/windows defender advanced threat protection/",
)


def _trusted_lsass_reader(image: str | None) -> bool:
    n = _norm(image)
    return n in _TRUSTED_LSASS_READERS or n.startswith(_TRUSTED_LSASS_PREFIXES)


def _dump_command(cmd: str) -> str | None:
    if "comsvcs" in cmd and "minidump" in cmd:
        return "rundll32 was used to call comsvcs.dll's MiniDump export, a built-in way to dump a process"
    if "procdump" in cmd and "lsass" in cmd:
        return "ProcDump was pointed at lsass.exe"
    if "sekurlsa" in cmd or "lsadump::" in cmd:
        return "the command line contains Mimikatz credential-dumping module names"
    return None


class LsassAccess(Rule):
    """A process reading the memory of LSASS, where Windows keeps logon credentials."""

    id = "cred.lsass_access"
    title = "LSASS memory accessed by an unexpected process"
    severity = Severity.HIGH
    confidence = Confidence.MEDIUM
    technique_ids = ("T1003.001",)

    def observe(self, event: TelemetryEvent, tree: ProcessTree, emit: Emit) -> None:
        if event.kind is EventKind.PROCESS_CREATE:
            how = _dump_command(_cmd(event))
            if how is None:
                return
            emit(self._detect(
                tree=tree, events=[event], primary_guid=event.process_guid,
                summary=f"{_basename(event.image)} ran a credential-dumping command",
                explanation=(
                    f"{how}. Command line:\n    {event.command_line}\n"
                    "LSASS holds password hashes and Kerberos tickets for everyone logged on; dumping it is how "
                    "an attacker turns one compromised machine into access to others."
                ),
                dedup_key=f"{self.id}:cmd:{event.process_guid}", confidence=Confidence.HIGH,
            ))
            return
        if event.kind is not EventKind.PROCESS_ACCESS or _basename(event.target_image) != "lsass.exe":
            return
        mask = event.details.get("granted_access")
        if isinstance(mask, int) and not mask & PROCESS_VM_READ:
            return  # no memory-read right: a status query, not a dump
        node = tree.get(event.process_guid)
        image = event.image or (node.image if node else "")
        if _trusted_lsass_reader(image):
            return
        shown = f"0x{mask:x}" if isinstance(mask, int) else "not captured"
        emit(self._detect(
            tree=tree, events=[event], primary_guid=event.process_guid,
            summary=f"{_basename(image) or 'a process'} opened LSASS with memory-read access",
            explanation=(
                f"{_basename(image) or 'A process'} ({image or 'unknown image'}) opened a handle to lsass.exe "
                f"with access rights {shown}, which include reading its memory. LSASS holds logon credentials; "
                "reading its memory is how credential dumpers work. Windows components and antivirus that "
                "normally do this are excluded by full path. Third-party security or monitoring tools can also "
                "trigger this; if this one is expected, add a suppression for its path."
            ),
            dedup_key=f"{self.id}:{event.process_guid}",
        ))


# --------------------------------------------------------------------------- persistence


def _task_action(cmd: str) -> str:
    """The program a ``schtasks /create`` will run (the ``/tr`` argument), or '' when absent."""
    match = re.search(r"[/-]tr\s+(\"[^\"]*\"|'[^']*'|\S+)", cmd)
    return match.group(1).strip("\"'") if match else ""


class ScheduledTaskPersistence(Rule):
    """A scheduled task created by an unusual author, or one that runs something from a staging location."""

    id = "persist.scheduled_task"
    title = "Suspicious scheduled task created"
    severity = Severity.HIGH
    confidence = Confidence.MEDIUM
    technique_ids = ("T1053.005",)

    def observe(self, event: TelemetryEvent, tree: ProcessTree, emit: Emit) -> None:
        if not _is_create(event, "schtasks.exe"):
            return
        cmd = _cmd(event)
        if not _has_flag(cmd, "create"):
            return
        reason = self._reason(event, cmd, tree)
        if reason is None:
            return  # administrators and installers create tasks all the time; only unusual ones are flagged
        emit(self._detect(
            tree=tree, events=[event], primary_guid=event.process_guid,
            summary=f"schtasks created a task: {reason}",
            explanation=(
                f"A scheduled task was created with:\n    {event.command_line}\n"
                f"It was flagged because {reason}. A scheduled task runs again on a timer or at logon, so it "
                "is a common way for malware to survive a reboot or to run with higher privileges."
            ),
            dedup_key=f"{self.id}:{event.process_guid}",
        ))

    @staticmethod
    def _reason(event: TelemetryEvent, cmd: str, tree: ProcessTree) -> str | None:
        action = _task_action(cmd)
        if action:
            if _mentions_staging_path(action):
                return "the task runs a program from a user-writable location"
            if _OBFUSCATED_SHELL.search(action) or _URL.search(action) or _SCRIPT_PROTOCOL.search(action):
                return "the task runs an encoded, hidden or download-and-run command"
            if _basename(action.split(" ")[0]) in LOLBINS:
                return f"the task runs {_basename(action.split(' ')[0])}, a living-off-the-land binary"
        for node in tree.ancestry(event.process_guid)[1:]:
            if _is_office(node.image):
                return f"it was created from a process tree that starts in an Office application ({node.image_name})"
            if _basename(node.image) in LOLBINS:
                return f"it was created under {node.image_name}, a living-off-the-land binary"
            if _in_suspicious_path(node.image):
                return "it was created by a program running from a user-writable location"
        if _is_office(event.parent_image) or _in_suspicious_path(event.parent_image):
            return "it was created by an Office application or a program in a user-writable location"
        return None


class WmiPersistence(Rule):
    """A WMI event consumer that runs a command or script - a quiet, fileless way to persist."""

    id = "persist.wmi_subscription"
    title = "WMI event consumer registered that runs code"
    severity = Severity.HIGH
    confidence = Confidence.MEDIUM
    technique_ids = ("T1546.003",)

    def observe(self, event: TelemetryEvent, tree: ProcessTree, emit: Emit) -> None:
        if event.kind is not EventKind.WMI_SUBSCRIPTION or event.details.get("stage") != "consumer":
            return
        consumer_type = str(event.details.get("consumer_type") or "").lower()
        if "command" not in consumer_type and "script" not in consumer_type:
            return  # log-file and event-log consumers do not run code
        name = str(event.details.get("name") or "(unnamed)")
        destination = str(event.details.get("destination") or "(not captured)")
        emit(self._detect(
            tree=tree, events=[event], primary_guid=event.process_guid,
            summary=f"WMI consumer '{name}' runs a {consumer_type or 'command'}",
            explanation=(
                f"A permanent WMI event consumer named '{name}' was registered"
                f"{f' by {event.user}' if event.user else ''}. When its trigger fires it runs:\n"
                f"    {destination}\n"
                "WMI subscriptions live in the WMI repository rather than in a file or a Run key, so they "
                "survive reboots and are missed by most startup-entry reviews. Management software such as "
                "SCCM registers legitimate ones; an unfamiliar name or command deserves a look."
            ),
            dedup_key=f"{self.id}:{name.lower()}",
        ))


# --------------------------------------------------------------------------- defence evasion / execution


@dataclass(frozen=True)
class _LolbinHit:
    what: str
    techniques: tuple[str, ...]


def _lolbin_hit(event: TelemetryEvent) -> _LolbinHit | None:
    name, cmd = _basename(event.image), _cmd(event)
    has_url = bool(_URL.search(cmd))
    if name == "certutil.exe":
        if _has_flag(cmd, "urlcache", "verifyctl") and has_url:
            return _LolbinHit("certutil was used to download a file from the internet", ("T1105", "T1218"))
        if _has_flag(cmd, "decode", "decodehex"):
            return _LolbinHit("certutil was used to decode an encoded file into its original form", ("T1140",))
    elif name == "mshta.exe":
        if has_url or _SCRIPT_PROTOCOL.search(cmd):
            return _LolbinHit("mshta was given a remote address or inline script to execute", ("T1218.005",))
    elif name == "bitsadmin.exe":
        if _has_flag(cmd, "transfer", "addfile") and has_url:
            return _LolbinHit("bitsadmin was used to download a file through a BITS job", ("T1197", "T1105"))
    elif name == "rundll32.exe":
        if _SCRIPT_PROTOCOL.search(cmd):
            return _LolbinHit("rundll32 was given inline script to execute", ("T1218.011",))
        if _mentions_staging_path(cmd):
            return _LolbinHit("rundll32 loaded a DLL from a user-writable location", ("T1218.011",))
    elif name == "regsvr32.exe" and ((_has_flag(cmd, "i") and has_url) or ("scrobj.dll" in cmd and has_url)):
        return _LolbinHit("regsvr32 was pointed at a remote scriptlet", ("T1218.010",))
    return None


class LolbinAbuse(Rule):
    """A signed Windows binary used the way attackers use it: to fetch, decode or run code."""

    id = "exec.lolbin_abuse"
    title = "Windows binary used to download or run code"
    severity = Severity.HIGH
    confidence = Confidence.MEDIUM
    technique_ids = ("T1218", "T1105")

    def observe(self, event: TelemetryEvent, tree: ProcessTree, emit: Emit) -> None:
        if event.kind is not EventKind.PROCESS_CREATE:
            return
        hit = _lolbin_hit(event)
        if hit is None:
            return
        emit(self._detect(
            tree=tree, events=[event], primary_guid=event.process_guid,
            summary=hit.what,
            explanation=(
                f"{hit.what[0].upper()}{hit.what[1:]}:\n    {event.command_line}\n"
                f"{_basename(event.image)} ships with Windows and is trusted by most allowlists, which is "
                "exactly why attackers use it instead of bringing their own tool. This particular use is rare "
                "in normal administration; check where the file came from and what ran next."
            ),
            dedup_key=f"{self.id}:{event.process_guid}", technique_ids=hit.techniques,
        ))


class RemoteThreadInjection(Rule):
    """A script host, Office application or staged binary starting a thread inside another process."""

    id = "inject.remote_thread"
    title = "Thread created in another process by an unusual source"
    severity = Severity.HIGH
    confidence = Confidence.MEDIUM
    technique_ids = ("T1055",)

    def observe(self, event: TelemetryEvent, tree: ProcessTree, emit: Emit) -> None:
        if event.kind is not EventKind.REMOTE_THREAD:
            return
        if event.target_guid and event.target_guid == event.process_guid:
            return
        source = event.image
        if not (_is_interpreter(source) or _is_office(source) or _basename(source) in LOLBINS
                or _in_suspicious_path(source)):
            return  # debuggers, antivirus and Windows itself create remote threads constantly
        emit(self._detect(
            tree=tree, events=[event], primary_guid=event.process_guid,
            summary=f"{_basename(source)} started a thread inside {_basename(event.target_image) or 'another process'}",
            explanation=(
                f"{_basename(source)} ({source}) created a thread in {event.target_image or 'another process'}. "
                "Running code inside a different process is how malware hides behind a trusted name. This was "
                "flagged because the source is a script host, an Office application, a living-off-the-land "
                "binary or a program in a user-writable location - none of which normally do this."
            ),
            dedup_key=f"{self.id}:{event.process_guid}:{_norm(event.target_image)}",
        ))


# --------------------------------------------------------------------------- impact


def _recovery_inhibition(event: TelemetryEvent) -> str | None:
    if event.kind is not EventKind.PROCESS_CREATE:
        return None
    name, cmd = _basename(event.image), _cmd(event)
    if name == "vssadmin.exe":
        if "delete" in cmd and "shadows" in cmd:
            return "Volume shadow copies were deleted with vssadmin"
        if "resize" in cmd and "shadowstorage" in cmd:
            return "Shadow-copy storage was resized with vssadmin, which discards existing copies"
    elif name == "wmic.exe" and "shadowcopy" in cmd and "delete" in cmd:
        return "Volume shadow copies were deleted with wmic"
    elif name == "wbadmin.exe" and "delete" in cmd and any(w in cmd for w in ("catalog", "systemstatebackup", "backup")):
        return "Windows backups or the backup catalog were deleted with wbadmin"
    elif name == "bcdedit.exe":
        if "recoveryenabled" in cmd and re.search(r"\bno\b", cmd):
            return "Windows automatic recovery was switched off with bcdedit"
        if "bootstatuspolicy" in cmd and "ignoreallfailures" in cmd:
            return "Windows was told to ignore boot failures with bcdedit"
    elif _is_interpreter(event.image) and "win32_shadowcopy" in cmd and any(
            w in cmd for w in ("delete", "remove-wmiobject", "remove-ciminstance")):
        return "Volume shadow copies were deleted through WMI from a script"
    return None


class RecoveryInhibited(Rule):
    """Deleting shadow copies or backups, or disabling recovery: the step ransomware takes before encrypting."""

    id = "impact.recovery_inhibited"
    title = "Backups or recovery options destroyed"
    severity = Severity.HIGH
    confidence = Confidence.HIGH
    technique_ids = ("T1490",)

    def observe(self, event: TelemetryEvent, tree: ProcessTree, emit: Emit) -> None:
        what = _recovery_inhibition(event)
        if what is None:
            return
        emit(self._detect(
            tree=tree, events=[event], primary_guid=event.process_guid,
            summary=what,
            explanation=(
                f"{what}:\n    {event.command_line}\n"
                "Shadow copies and backups are what you restore from after files are encrypted or destroyed, "
                "so ransomware removes them first. Backup software and disk clean-up occasionally do the same; "
                "if nobody here ran this on purpose, treat it as urgent and check for file encryption."
            ),
            dedup_key=f"{self.id}:{event.process_guid}",
        ))


# File types people keep their work in. A new file named "<document>.<something else>" is the footprint of a
# program writing an encrypted copy next to (or in place of) the original.
_DOCUMENT_EXTENSIONS = frozenset({
    "doc", "docx", "xls", "xlsx", "ppt", "pptx", "pdf", "txt", "rtf", "odt", "ods", "csv", "jpg", "jpeg", "png",
    "gif", "bmp", "tif", "tiff", "psd", "mp3", "mp4", "mov", "avi", "zip", "7z", "rar", "sql", "mdb", "accdb",
    "pst", "ost", "kdbx", "db", "sqlite", "json", "xml", "py", "js", "ts", "cs", "java", "cpp", "c", "h",
})
# Second extensions that ordinary software appends: downloads in progress, backups, signatures, compression.
_BENIGN_SUFFIXES = frozenset({
    "tmp", "temp", "bak", "old", "orig", "crdownload", "part", "partial", "download", "lnk", "gz", "bz2", "xz",
    "zst", "zip", "7z", "sig", "asc", "sha256", "md5", "lock", "swp", "log", "map", "min", "d",
}) | _DOCUMENT_EXTENSIONS
_RANSOM_NOTE = re.compile(
    r"(?:readme|read_me|how[_ -]?to[_ -]?(?:decrypt|recover|restore)|decrypt[_ -]?(?:instructions|files)|"
    r"recover[_ -]?(?:files|your)|restore[_ -]?(?:files|your)|your[_ -]?files)[^/]*\.(?:txt|html?|hta)$",
    re.IGNORECASE,
)


def encrypted_suffix(path: str | None) -> str | None:
    """The extension appended to a document name (``report.docx.locked`` -> ``locked``), or None."""
    name = _norm(path).rsplit("/", 1)[-1]
    parts = name.split(".")
    if len(parts) < 3 or parts[-2] not in _DOCUMENT_EXTENSIONS:
        return None
    suffix = parts[-1]
    return None if (not suffix or suffix in _BENIGN_SUFFIXES or len(suffix) > 16) else suffix


@dataclass
class _WriteBurst:
    hits: deque[tuple[datetime, str, TelemetryEvent]] = field(default_factory=deque)  # (ts, suffix, event)
    notes: int = 0
    fired_at: datetime | None = None


class MassFileEncryption(Rule):
    """One process writing many "document + new extension" files in a short window: bulk encryption.

    This is the second stateful rule. Where ``SuspiciousExecChain`` ties different kinds of event together by
    lineage, this one counts one kind of event per process inside a sliding window and fires when the count
    crosses a threshold *and* the files share one appended extension. The shared extension is what separates
    ransomware from a program that merely writes a lot of files.

    Limit worth knowing: it sees only what Sysmon logs. File-create events are recorded for the paths and
    extensions the Sysmon configuration includes, and ransomware that overwrites files in place without
    renaming them produces no "document + new extension" names at all.
    """

    id = "impact.mass_file_encryption"
    title = "Many files rewritten with a new extension by one process"
    severity = Severity.CRITICAL
    confidence = Confidence.MEDIUM
    technique_ids = ("T1486",)

    def __init__(self, threshold: int = 20, window: timedelta = timedelta(seconds=60),
                 same_suffix_share: float = 0.8, max_tracked: int = 2_000) -> None:
        self.threshold = threshold
        self.window = window
        self.same_suffix_share = same_suffix_share
        self.max_tracked = max_tracked
        self._bursts: dict[str, _WriteBurst] = {}

    def observe(self, event: TelemetryEvent, tree: ProcessTree, emit: Emit) -> None:
        if event.kind is EventKind.PROCESS_EXIT:
            self._bursts.pop(event.process_guid, None)
            return
        if event.kind is not EventKind.FILE_WRITE:
            return
        suffix = encrypted_suffix(event.file_path)
        is_note = bool(_RANSOM_NOTE.search(_norm(event.file_path)))
        if suffix is None and not is_note:
            return
        burst = self._bursts.setdefault(event.process_guid, _WriteBurst())
        if is_note and suffix is None:
            burst.notes += 1
            return
        assert suffix is not None
        burst.hits.append((event.ts, suffix, event))
        cutoff = event.ts - self.window
        while burst.hits and burst.hits[0][0] < cutoff:
            burst.hits.popleft()
        self._bound()
        if len(burst.hits) < self.threshold:
            return
        if burst.fired_at is not None and event.ts - burst.fired_at < self.window:
            return
        top_suffix, top_count = Counter(s for _, s, _ in burst.hits).most_common(1)[0]
        if top_count / len(burst.hits) < self.same_suffix_share:
            return
        burst.fired_at = event.ts
        emit(self._emit_for(event, burst, top_suffix, tree))

    def _emit_for(self, event: TelemetryEvent, burst: _WriteBurst, suffix: str,
                  tree: ProcessTree) -> Detection:
        node = tree.get(event.process_guid)
        image = event.image or (node.image if node else "")
        matching = [e for _, s, e in burst.hits if s == suffix]
        folders = {_norm(e.file_path).rsplit("/", 1)[0] for e in matching}
        seconds = max(1, int((matching[-1].ts - matching[0].ts).total_seconds()))
        sample = "\n".join(f"    {e.file_path}" for e in matching[:5])
        note = (f" It also wrote {burst.notes} file(s) named like a ransom note." if burst.notes else "")
        evidence = [*matching[:8], *matching[-2:]] if len(matching) > 10 else matching
        return self._detect(
            tree=tree, events=evidence, primary_guid=event.process_guid,
            summary=(f"{_basename(image) or 'a process'} wrote {len(matching)} files ending in .{suffix} "
                     f"in {seconds}s"),
            explanation=(
                f"{_basename(image) or 'A process'} ({image or 'unknown image'}) wrote {len(matching)} files "
                f"across {len(folders)} folder(s) in about {seconds} seconds, each named like an existing "
                f"document with '.{suffix}' appended:\n{sample}\n"
                f"Writing an encrypted copy of each document under a new extension is the footprint of "
                f"ransomware.{note} Archive, sync and conversion tools can also produce bursts like this; "
                "if this program is one of those, add a suppression for its path. Otherwise disconnect the "
                "machine from the network and check whether the original files still open."
            ),
            dedup_key=f"{self.id}:{event.process_guid}",
        )

    def _bound(self) -> None:
        while len(self._bursts) > self.max_tracked:
            del self._bursts[next(iter(self._bursts))]


def tradecraft_rules() -> list[Rule]:
    return [
        LsassAccess(), ScheduledTaskPersistence(), WmiPersistence(), LolbinAbuse(),
        RemoteThreadInjection(), RecoveryInhibited(), MassFileEncryption(),
    ]
