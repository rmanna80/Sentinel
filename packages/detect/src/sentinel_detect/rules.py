"""Detection rules: the logic that turns a stream of events into a conclusion.

Two shapes of rule live here, and the difference is the whole point of the project:

* A **contextual** rule looks at one event in the light of the process tree. "A Word document just launched
  PowerShell" is one process-creation event plus one question about its parent. It needs memory of what
  spawned what, but not memory of *time*.
* A **sequence** rule watches for several events that only mean something together and only within a window.
  "An unusually-spawned interpreter reached the internet and then switched off Defender" is three events,
  possibly seconds or minutes apart, correlated by lineage. This is the hard, interesting case, and
  ``SuspiciousExecChain`` below is the worked example of it.

Every rule maps itself to MITRE ATT&CK techniques and, when it fires, hands back the exact events it saw so
the conclusion can be audited. Adding a rule is meant to be cheap; the machinery that makes sequence rules
tractable (the process tree, the windowed state, lineage attribution) is the reusable part.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta

from sentinel_core.models import Confidence, FindingKind, Severity
from sentinel_core.telemetry import Detection, EventKind, TelemetryEvent

from . import attack
from .process_tree import ProcessTree, _basename

Emit = Callable[[Detection], None]

# --------------------------------------------------------------------------- vocabulary

INTERPRETERS = frozenset({
    "powershell.exe", "pwsh.exe", "powershell_ise.exe", "cmd.exe",
    "wscript.exe", "cscript.exe", "mshta.exe",
})
# "Living off the land" binaries an attacker uses to launch code while looking like Windows itself.
LOLBINS = frozenset({"mshta.exe", "wscript.exe", "cscript.exe", "rundll32.exe", "regsvr32.exe", "msbuild.exe"})
OFFICE_APPS = frozenset({
    "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe",
    "msaccess.exe", "mspub.exe", "onenote.exe", "visio.exe",
})
# Substrings (normalised, forward-slash, lower-case) that mark a user-writable staging location.
SUSPICIOUS_PATH_MARKERS = (
    "/appdata/local/temp/", "/windows/temp/", "/temp/", "/downloads/",
    "/users/public/", "/$recycle.bin/", "/perflogs/",
)


def _norm(path: str | None) -> str:
    return (path or "").replace("\\", "/").lower()


def _is_interpreter(image: str | None) -> bool:
    return _basename(image) in INTERPRETERS


def _is_office(image: str | None) -> bool:
    return _basename(image) in OFFICE_APPS


def _in_suspicious_path(image: str | None) -> bool:
    n = _norm(image)
    return any(marker in n for marker in SUSPICIOUS_PATH_MARKERS)


def _is_external_ip(ip: str | None) -> bool:
    """True only for a routable public address. Loopback/private/link-local and unparseable values are not."""
    if not ip:
        return False
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def _is_outbound_external(event: TelemetryEvent) -> bool:
    return (
        event.kind is EventKind.NETWORK_CONNECT
        and (event.direction or "outbound") == "outbound"
        and _is_external_ip(event.dest_ip)
    )


# Autorun locations. A write here means "run this again automatically" — persistence.
_AUTORUN_MARKERS = ("/currentversion/run", "/currentversion/runonce", "/currentversion/policies/explorer/run")
_WINLOGON_MARKER = "/currentversion/winlogon"
_WINLOGON_VALUES = frozenset({"shell", "userinit"})


def _is_autorun(event: TelemetryEvent) -> bool:
    if event.kind is not EventKind.REGISTRY_SET:
        return False
    path = _norm(event.registry_path)
    if any(marker in path for marker in _AUTORUN_MARKERS):
        return True
    return _WINLOGON_MARKER in path and (event.registry_value or "").lower() in _WINLOGON_VALUES


# Security-tooling settings whose modification means "defences are being weakened".
def _tamper_kind(event: TelemetryEvent) -> str | None:
    if event.kind is not EventKind.REGISTRY_SET:
        return None
    path = _norm(event.registry_path)
    value = (event.registry_value or "").lower()
    raw = event.details.get("value")
    if "/windows defender" in path or "/microsoft/windows defender" in path:
        disable_flags = {"disableantispyware", "disableantivirus", "disablerealtimemonitoring",
                         "disablebehaviormonitoring", "disableioavprotection", "disableonaccessprotection"}
        if value in disable_flags and _enabled(raw):  # the flag is being turned ON (i.e. protection OFF)
            return "Microsoft Defender was switched off via the registry"
        if value == "tamperprotection" and _disabled(raw):
            return "Defender tamper protection was switched off"
    # The firewall policy lives under two paths: the GPO ...\WindowsFirewall\... and the service's
    # ...\SharedAccess\Parameters\FirewallPolicy\... — accept either.
    if ("/windowsfirewall/" in path or "/firewallpolicy/" in path) and value == "enablefirewall" and _disabled(raw):
        return "the Windows Firewall was switched off for a profile"
    return None


def _enabled(raw: object) -> bool:
    # A "Disable*" flag set to 1 (or set at all, if the collector didn't capture the value) disables protection.
    return raw is None or _as_int(raw) != 0


def _disabled(raw: object) -> bool:
    # An "Enable*"/"TamperProtection" value of 0 disables protection; absence is treated as suspicious too.
    return raw is None or _as_int(raw) == 0


def _as_int(raw: object) -> int | None:
    try:
        return int(raw)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None


# --------------------------------------------------------------------------- rule base


class Rule:
    id: str = ""
    title: str = ""
    severity: Severity = Severity.MEDIUM
    confidence: Confidence = Confidence.MEDIUM
    technique_ids: tuple[str, ...] = ()

    def observe(self, event: TelemetryEvent, tree: ProcessTree, emit: Emit) -> None:
        raise NotImplementedError

    def _detect(
        self, *, tree: ProcessTree, events: list[TelemetryEvent], primary_guid: str,
        summary: str, explanation: str, dedup_key: str,
        severity: Severity | None = None, confidence: Confidence | None = None,
    ) -> Detection:
        times = [e.ts for e in events]
        guids: list[str] = []
        for g in [primary_guid, *(e.process_guid for e in events)]:
            if g and g not in guids:
                guids.append(g)
        host = next((e.host for e in events if e.host), "")
        return Detection(
            rule_id=self.id, title=self.title, summary=summary, explanation=explanation,
            severity=severity or self.severity, confidence=confidence or self.confidence,
            kind=FindingKind.HEURISTIC, technique_ids=list(self.technique_ids),
            technique_names=attack.names(list(self.technique_ids)), host=host,
            first_ts=min(times), last_ts=max(times), dedup_key=dedup_key,
            process_guids=guids[:50], events=events, process_tree=tree.snapshot(primary_guid),
        )


# --------------------------------------------------------------------------- contextual rules


class OfficeSpawnsInterpreter(Rule):
    """A document-handling application that launches a script interpreter — the classic macro/phish execution."""

    id = "exec.office_spawns_interpreter"
    title = "Office application launched a script interpreter"
    severity = Severity.HIGH
    confidence = Confidence.HIGH
    technique_ids = ("T1566", "T1204.002", "T1059")

    def observe(self, event: TelemetryEvent, tree: ProcessTree, emit: Emit) -> None:
        if event.kind is not EventKind.PROCESS_CREATE or not _is_interpreter(event.image):
            return
        if not _is_office(event.parent_image):
            return
        parent, child = _basename(event.parent_image), _basename(event.image)
        summary = f"{parent} spawned {child}"
        explanation = (
            f"{parent} ({event.parent_image}) created {child} ({event.image}). Office applications open "
            "documents, not shells; this pattern is how a malicious macro or opened attachment starts running "
            "code. Command line observed:\n"
            f"    {event.command_line or '(none captured)'}"
        )
        emit(self._detect(
            tree=tree, events=[event], primary_guid=event.process_guid, summary=summary,
            explanation=explanation, dedup_key=f"{self.id}:{event.process_guid}",
        ))


class AutorunPersistence(Rule):
    """A write to an autorun location by a process that has no business configuring startup."""

    id = "persist.autorun_registry"
    title = "Autorun entry created by an unusual process"
    severity = Severity.MEDIUM
    confidence = Confidence.MEDIUM
    technique_ids = ("T1547.001",)

    def observe(self, event: TelemetryEvent, tree: ProcessTree, emit: Emit) -> None:
        if not _is_autorun(event):
            return
        node = tree.get(event.process_guid)
        image = node.image if node else event.image
        parent_is_interpreter = bool(node and _is_interpreter(node.parent_image))
        unusual = _is_interpreter(image) or _in_suspicious_path(image) or parent_is_interpreter
        if not unusual:
            return  # legitimate installers and policy write autoruns constantly; only flag suspicious authors
        where = f"{event.registry_path}\\{event.registry_value}" if event.registry_value else event.registry_path
        summary = f"{_basename(image)} created an autorun entry"
        explanation = (
            f"{_basename(image)} ({image}) wrote an autorun value at:\n    {where}\n"
            "An autorun entry makes something run again on every boot or logon — a common way for malware to "
            "survive a reboot. This was flagged because the writing process is an interpreter, lives in a "
            "user-writable location, or was itself launched by one."
        )
        emit(self._detect(
            tree=tree, events=[event], primary_guid=event.process_guid, summary=summary,
            explanation=explanation, dedup_key=f"{self.id}:{event.process_guid}:{_norm(event.registry_path)}",
        ))


class DefenseTamper(Rule):
    """A registry change that weakens security tooling (Defender, the firewall)."""

    id = "defense.security_tooling_disabled"
    title = "Security tooling disabled via the registry"
    severity = Severity.HIGH
    confidence = Confidence.MEDIUM
    technique_ids = ("T1562.001", "T1112")

    def observe(self, event: TelemetryEvent, tree: ProcessTree, emit: Emit) -> None:
        kind = _tamper_kind(event)
        if kind is None:
            return
        node = tree.get(event.process_guid)
        image = node.image if node else event.image
        summary = f"{_basename(image) or 'a process'} weakened security settings"
        explanation = (
            f"{kind}. The change was made by {_basename(image)} ({image}) at:\n"
            f"    {event.registry_path}\\{event.registry_value}\n"
            "Legitimate changes to these settings normally come from Windows servicing or managed policy; a "
            "change from an ordinary process is a common step once an attacker has a foothold."
        )
        emit(self._detect(
            tree=tree, events=[event], primary_guid=event.process_guid, summary=summary,
            explanation=explanation, dedup_key=f"{self.id}:{event.process_guid}:{_norm(event.registry_path)}",
        ))


# --------------------------------------------------------------------------- sequence rule


@dataclass
class _Chain:
    guid: str
    start_ts: datetime
    spawn: TelemetryEvent
    parent_desc: str
    network: TelemetryEvent | None = None
    tamper: TelemetryEvent | None = None
    fired: bool = False


class SuspiciousExecChain(Rule):
    """The worked example of correlation: an unusually-spawned interpreter that then reaches out and tampers.

    Three stages, in any order within a time window, tied together by process lineage:

    1. an interpreter is created by an *unusual* parent (an Office app, a living-off-the-land binary, or a
       process running from a user-writable location);
    2. that interpreter, or any descendant of it, opens an outbound connection to a public address;
    3. that interpreter, or any descendant, modifies an autorun or security setting.

    No single stage is damning — admins spawn shells, shells talk to the internet, settings get changed. The
    three together, from one lineage, inside a few minutes, is a pattern that ordinary administration almost
    never produces, which is exactly why the correlation is worth more than any one of its parts.
    """

    id = "intrusion.suspicious_exec_chain"
    title = "Suspicious execution chain: unusual spawn, outbound connection, and system change"
    severity = Severity.CRITICAL
    confidence = Confidence.MEDIUM
    technique_ids = ("T1059", "T1071", "T1562.001", "T1547.001")

    def __init__(self, window: timedelta = timedelta(minutes=10), max_chains: int = 10_000) -> None:
        self.window = window
        self.max_chains = max_chains
        self._chains: dict[str, _Chain] = {}

    def observe(self, event: TelemetryEvent, tree: ProcessTree, emit: Emit) -> None:
        self._expire(event.ts)
        if event.kind is EventKind.PROCESS_CREATE and _is_interpreter(event.image):
            desc = self._unusual_parent(event)
            if desc is not None:
                self._chains[event.process_guid] = _Chain(
                    guid=event.process_guid, start_ts=event.ts, spawn=event, parent_desc=desc,
                )
                self._bound()
        elif event.kind is EventKind.NETWORK_CONNECT and _is_outbound_external(event):
            chain = self._chain_for(event, tree)
            if chain is not None and chain.network is None:
                chain.network = event
        elif _is_autorun(event) or _tamper_kind(event) is not None:
            chain = self._chain_for(event, tree)
            if chain is not None and chain.tamper is None:
                chain.tamper = event

        chain = self._chains.get(self._nearest_tracked(event, tree) or event.process_guid)
        if chain and not chain.fired and chain.network is not None and chain.tamper is not None:
            chain.fired = True
            emit(self._emit_for(chain, tree))

    def _unusual_parent(self, event: TelemetryEvent) -> str | None:
        parent = _basename(event.parent_image)
        if parent in OFFICE_APPS:
            return f"an Office application ({parent})"
        if parent in LOLBINS:
            return f"{parent}, a living-off-the-land binary"
        if _in_suspicious_path(event.parent_image):
            return "a process running from a user-writable location"
        if _in_suspicious_path(event.image):
            return "an interpreter copied into a user-writable location"
        return None

    def _nearest_tracked(self, event: TelemetryEvent, tree: ProcessTree) -> str | None:
        for node in tree.ancestry(event.process_guid):
            if node.process_guid in self._chains:
                return node.process_guid
        return event.process_guid if event.process_guid in self._chains else None

    def _chain_for(self, event: TelemetryEvent, tree: ProcessTree) -> _Chain | None:
        guid = self._nearest_tracked(event, tree)
        return self._chains.get(guid) if guid else None

    def _emit_for(self, chain: _Chain, tree: ProcessTree) -> Detection:
        spawn, net, tamper = chain.spawn, chain.network, chain.tamper
        assert net is not None and tamper is not None  # guarded by the caller
        dest = f"{net.dest_ip}:{net.dest_port}" if net.dest_port else str(net.dest_ip)
        setting = f"{tamper.registry_path}\\{tamper.registry_value}" if tamper.registry_value else tamper.registry_path
        summary = (
            f"{_basename(spawn.image)} spawned by {chain.parent_desc.split(' (')[0]}, "
            f"connected to {dest}, then changed {_basename_reg(setting)}"
        )
        explanation = (
            "Three events from one process lineage, within the correlation window, form a pattern ordinary "
            "administration almost never produces:\n\n"
            f"  1. Execution — {_basename(spawn.image)} ({spawn.image}) was launched by {chain.parent_desc}.\n"
            f"       command line: {spawn.command_line or '(none captured)'}\n"
            f"  2. Command & control — a descendant opened an outbound connection to {dest} "
            f"({net.protocol or 'tcp'}).\n"
            f"  3. System change — a descendant modified {setting}.\n\n"
            "Each step alone is weak evidence. Together, from the same lineage and inside the window, they "
            "describe code that was run unusually, reached the internet, and then changed the system to keep "
            "its footing. This merits investigation; no action has been taken automatically."
        )
        return self._detect(
            tree=tree, events=[spawn, net, tamper], primary_guid=chain.guid, summary=summary,
            explanation=explanation, dedup_key=f"{self.id}:{chain.guid}",
        )

    def _expire(self, now: datetime) -> None:
        cutoff = now - self.window
        for guid in [g for g, c in self._chains.items() if c.start_ts < cutoff]:
            del self._chains[guid]

    def _bound(self) -> None:
        while len(self._chains) > self.max_chains:
            oldest = min(self._chains, key=lambda g: self._chains[g].start_ts)
            del self._chains[oldest]


def _basename_reg(path: str | None) -> str:
    """Last segment of a registry path, for a compact summary (``...\\Run\\Updater`` -> ``Updater``)."""
    if not path:
        return "a setting"
    return path.replace("/", "\\").rsplit("\\", 1)[-1]


# --------------------------------------------------------------------------- registry


def default_rules() -> list[Rule]:
    """The rules the engine runs by default. Order is irrelevant; each keeps its own state."""
    return [
        OfficeSpawnsInterpreter(),
        AutorunPersistence(),
        DefenseTamper(),
        SuspiciousExecChain(),
    ]
