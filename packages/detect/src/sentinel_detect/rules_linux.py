"""Linux rules: the same ideas as the Windows rules, in the shapes they take on a Linux host.

The engine does not know which operating system an event came from; these rules simply key on Linux paths and
program names, so they stay silent on Windows telemetry and the Windows rules stay silent on Linux telemetry.
They read what ``sentinel_agent.telemetry.auditd`` produces from kernel audit records.

As everywhere in Sentinel X, each rule is a heuristic with a stated reason. Administrators pipe installers
into a shell, package managers write service files, and deployment tools run from temporary folders. The rules
narrow each behaviour to the variant that ordinary use produces least, and suppression is where the
exceptions for your own machines belong.
"""

from __future__ import annotations

import re

from sentinel_core.models import Confidence, Severity
from sentinel_core.telemetry import EventKind, TelemetryEvent

from .process_tree import ProcessTree, _basename
from .rules import Emit, Rule

SHELLS = frozenset({"sh", "bash", "dash", "zsh", "ksh", "ash", "busybox"})
_STAGING_PREFIXES = ("/tmp/", "/var/tmp/", "/dev/shm/", "/run/shm/")
# Programs that legitimately write service files, cron jobs and startup scripts.
_PACKAGE_MANAGERS = frozenset({
    "dpkg", "apt", "apt-get", "aptitude", "unattended-upgrade", "unattended-upgrades", "rpm", "dnf", "yum",
    "pacman", "zypper", "snapd", "snap", "systemd", "systemctl", "packagekitd", "flatpak", "ansible-playbook",
    "puppet", "chef-client", "salt-minion", "cloud-init", "update-rc.d", "crontab", "cron", "anacron",
})
# Dedicated web servers only: general-purpose runtimes (node, java, python) spawn shells too often to be a signal.
_WEB_SERVERS = frozenset({
    "nginx", "apache2", "httpd", "lighttpd", "caddy", "php-fpm", "php-cgi", "uwsgi", "gunicorn", "tomcat",
})


def _cmd(event: TelemetryEvent) -> str:
    return event.command_line or ""


def _is_linux_exec(event: TelemetryEvent) -> bool:
    return event.kind is EventKind.PROCESS_CREATE and event.image.startswith("/")


def _in_staging(path: str | None) -> bool:
    return bool(path) and str(path).startswith(_STAGING_PREFIXES)


# --------------------------------------------------------------------------- execution

_PIPE_TO_SHELL = re.compile(
    r"\b(?:curl|wget|fetch)\b[^|;&]*\|\s*(?:sudo\s+)?(?:ba|da|z|k)?sh\b", re.IGNORECASE)
_REVERSE_SHELL = re.compile(
    r"/dev/(?:tcp|udp)/\d|"                                  # bash -i >& /dev/tcp/1.2.3.4/4444
    r"\b(?:nc|ncat|netcat)\b[^|;&]*\s-(?:\w*e|c)\s|"           # nc -e /bin/sh
    r"\bsocat\b[^|;&]*\bexec:|"                                # socat tcp:... exec:sh
    r"\bmkfifo\b[^|;&]*[;&|].*\b(?:nc|ncat|netcat|telnet)\b|"  # mkfifo /tmp/f; ... | nc
    r"\bsocket\b.*\b(?:dup2|subprocess|pty\.spawn|/bin/(?:ba)?sh)\b|"  # python/perl one-liners
    r"\bbase64\s+(?:-d|--decode)\b[^|;&]*\|\s*(?:ba|da|z)?sh\b",
    re.IGNORECASE | re.DOTALL)


class LinuxShellDownloadOrReverse(Rule):
    """A shell fed straight from the network, or wired to a network socket."""

    id = "linux.exec.remote_shell"
    title = "Shell connected to the network (download-and-run or reverse shell)"
    severity = Severity.HIGH
    confidence = Confidence.MEDIUM
    technique_ids = ("T1059.004", "T1105")

    def observe(self, event: TelemetryEvent, tree: ProcessTree, emit: Emit) -> None:
        if not _is_linux_exec(event):
            return
        cmd = _cmd(event)
        if _REVERSE_SHELL.search(cmd):
            what = "a shell's input and output were connected to a network socket (a reverse shell)"
            confidence, techniques = Confidence.HIGH, ("T1059.004", "T1071")
        elif _PIPE_TO_SHELL.search(cmd):
            what = "a file was downloaded and piped straight into a shell"
            confidence, techniques = Confidence.MEDIUM, ("T1059.004", "T1105")
        else:
            return
        emit(self._detect(
            tree=tree, events=[event], primary_guid=event.process_guid,
            summary=f"{_basename(event.image)}: {what}",
            explanation=(
                f"{what[0].upper()}{what[1:]}:\n    {cmd}\n"
                "A reverse shell hands an outside machine a command prompt on this one. Piping a download "
                "into a shell runs code nobody has looked at; installers do it too, so check the address."
            ),
            dedup_key=f"{self.id}:{event.process_guid}", confidence=confidence, technique_ids=techniques,
        ))


class LinuxExecFromStaging(Rule):
    """A program executed from a world-writable temporary folder."""

    id = "linux.exec.from_tmp"
    title = "Program run from a temporary folder"
    severity = Severity.MEDIUM
    confidence = Confidence.LOW
    technique_ids = ("T1059.004",)

    def observe(self, event: TelemetryEvent, tree: ProcessTree, emit: Emit) -> None:
        if not _is_linux_exec(event) or not _in_staging(event.image):
            return
        emit(self._detect(
            tree=tree, events=[event], primary_guid=event.process_guid,
            summary=f"{event.image} was executed",
            explanation=(
                f"{event.image} was run"
                f"{f' by {_basename(event.parent_image)}' if event.parent_image else ''}:\n    {_cmd(event)}\n"
                "/tmp, /var/tmp and /dev/shm are writable by every account and are where downloaded tools "
                "are usually dropped. Build systems and some installers also run from there, which is why "
                "this is low confidence on its own; it matters more next to other detections."
            ),
            dedup_key=f"{self.id}:{event.image}",
        ))


class LinuxWebServerShell(Rule):
    """A web server process starting a shell: how a web shell or command injection looks from the kernel."""

    id = "linux.exec.web_server_shell"
    title = "Web server started a shell"
    severity = Severity.HIGH
    confidence = Confidence.MEDIUM
    technique_ids = ("T1505.003", "T1059.004")

    def observe(self, event: TelemetryEvent, tree: ProcessTree, emit: Emit) -> None:
        if not _is_linux_exec(event) or _basename(event.image) not in SHELLS:
            return
        parent = _basename(event.parent_image)
        if parent not in _WEB_SERVERS:
            return
        emit(self._detect(
            tree=tree, events=[event], primary_guid=event.process_guid,
            summary=f"{parent} started {_basename(event.image)}",
            explanation=(
                f"The web server process {parent} ({event.parent_image}) started a shell:\n    {_cmd(event)}\n"
                "Web servers serve pages; they rarely need a shell. This is what a web shell, or a command "
                "injection flaw being exploited, looks like. Some applications do shell out on purpose "
                "(image conversion, backups); the command above shows which this is."
            ),
            dedup_key=f"{self.id}:{event.process_guid}",
        ))


# --------------------------------------------------------------------------- persistence

_PERSISTENCE_PATHS: tuple[tuple[re.Pattern[str], str, tuple[str, ...]], ...] = (
    (re.compile(r"^(?:/etc/cron\.(?:d|hourly|daily|weekly|monthly)/|/etc/crontab$|/var/spool/cron/)"),
     "a scheduled (cron) job", ("T1053.003",)),
    (re.compile(r"^(?:/etc|/usr/lib|/lib)/systemd/system/.+\.(?:service|timer|socket)$|/\.config/systemd/user/"),
     "a systemd unit", ("T1543.002",)),
    (re.compile(r"/\.ssh/authorized_keys2?$"), "an SSH authorized_keys file", ("T1098.004",)),
    (re.compile(r"^/etc/ld\.so\.preload$"), "the dynamic loader's preload list", ("T1574.006",)),
    (re.compile(r"^(?:/etc/rc\.local$|/etc/profile\.d/|/etc/init\.d/)"), "a startup script", ("T1037.004",)),
)


def _persistence_target(path: str | None) -> tuple[str, tuple[str, ...]] | None:
    if not path:
        return None
    for pattern, what, techniques in _PERSISTENCE_PATHS:
        if pattern.search(path):
            return what, techniques
    return None


class LinuxPersistence(Rule):
    """A file created in a place that makes something run again, by a program that is not a package manager."""

    id = "linux.persist.startup_location"
    title = "Persistence location written by an unexpected program"
    severity = Severity.HIGH
    confidence = Confidence.MEDIUM
    technique_ids = ("T1053.003", "T1543.002")

    def observe(self, event: TelemetryEvent, tree: ProcessTree, emit: Emit) -> None:
        if event.kind is not EventKind.FILE_WRITE:
            return
        target = _persistence_target(event.file_path)
        if target is None:
            return
        node = tree.get(event.process_guid)
        image = event.image or (node.image if node else "")
        if _basename(image) in _PACKAGE_MANAGERS:
            return
        what, techniques = target
        emit(self._detect(
            tree=tree, events=[event], primary_guid=event.process_guid,
            summary=f"{_basename(image) or 'a process'} created {event.file_path}",
            explanation=(
                f"{_basename(image) or 'A process'} ({image or 'unknown program'}) created {what}:\n"
                f"    {event.file_path}\n"
                "A file here makes a program run again at boot, at login or on a schedule, so it is a common "
                "way for an intruder to keep access. Package managers and configuration tools are excluded; "
                "an editor or shell writing here is normal when you did it yourself."
            ),
            dedup_key=f"{self.id}:{event.file_path}", technique_ids=techniques,
        ))


# --------------------------------------------------------------------------- defence evasion

# (programs that can do it, what the command line looks like, what happened, techniques). A pattern is only
# tried when the program being run is one of the named ones or a shell, so the same words inside an unrelated
# program's arguments (a commit message, a search string) are never read as the action itself.
_TAMPER: tuple[tuple[frozenset[str], re.Pattern[str], str, tuple[str, ...]], ...] = (
    (frozenset({"auditctl"}), re.compile(r"\bauditctl\b.*\s-(?:e\s+0|D)\b"),
     "kernel auditing was switched off or its rules were deleted", ("T1562.001",)),
    (frozenset({"systemctl", "service"}),
     re.compile(r"\b(?:stop|disable|mask)\b.*\b(?:auditd|apparmor|ufw|firewalld|falco|clamav\S*)"),
     "a security service was stopped or disabled", ("T1562.001",)),
    (frozenset({"ufw", "iptables", "ip6tables", "nft"}),
     re.compile(r"\bufw\s+disable\b|\bip6?tables\b.*\s-F\b|\bnft\s+flush\s+ruleset\b"),
     "the firewall was switched off", ("T1562.004",)),
    (frozenset({"setenforce", "aa-disable", "aa-teardown"}), re.compile(r"\bsetenforce\s+0\b|\baa-(?:disable|teardown)\b"),
     "mandatory access control was switched off", ("T1562.001",)),
    (frozenset(), re.compile(r"\bhistory\s+-c\b|\bunset\s+HISTFILE\b|HISTFILE=/dev/null|HISTSIZE=0\b"),
     "shell history was cleared or disabled", ("T1070.003",)),  # shell built-ins: only ever seen inside `sh -c`
    (frozenset({"rm", "shred", "truncate", "unlink"}), re.compile(r"\.(?:bash|zsh)_history\b"),
     "shell history was deleted", ("T1070.003",)),
    (frozenset({"rm", "shred", "truncate", "unlink"}),
     re.compile(r"/var/log/(?:auth\.log|secure|audit/|syslog|wtmp|btmp|lastlog)"), "system logs were deleted",
     ("T1070.002",)),
    (frozenset({"journalctl"}), re.compile(r"--vacuum-(?:time|size)=\s*1[smhkKM]?\b"), "the system journal was emptied",
     ("T1070.002",)),
)


class LinuxDefenseTamper(Rule):
    """A command that blinds logging or drops defences."""

    id = "linux.defense.tamper"
    title = "Logging or security controls disabled"
    severity = Severity.HIGH
    confidence = Confidence.MEDIUM
    technique_ids = ("T1562.001", "T1070")

    def observe(self, event: TelemetryEvent, tree: ProcessTree, emit: Emit) -> None:
        if not _is_linux_exec(event):
            return
        cmd = _cmd(event)
        program = _basename(event.image)
        for programs, pattern, what, techniques in _TAMPER:
            if (program in programs or program in SHELLS) and pattern.search(cmd):
                emit(self._detect(
                    tree=tree, events=[event], primary_guid=event.process_guid,
                    summary=what[0].upper() + what[1:],
                    explanation=(
                        f"{what[0].upper()}{what[1:]}:\n    {cmd}\n"
                        "Removing logs or switching off auditing and firewalls is what an intruder does to "
                        "avoid being seen; it is also ordinary maintenance. If nobody here ran this, look at "
                        "what the same account did just before."
                    ),
                    dedup_key=f"{self.id}:{event.process_guid}", technique_ids=techniques,
                ))
                return


def linux_rules() -> list[Rule]:
    return [LinuxShellDownloadOrReverse(), LinuxExecFromStaging(), LinuxWebServerShell(), LinuxPersistence(),
            LinuxDefenseTamper()]
