"""Phase 2: log-based detection rules, alerts, incidents and IOC hash matching.

This is where SOC-style triage of Windows and Linux logs lives. Every rule is defined in code below,
in plain terms, and is readable through ``GET /api/rules`` (thresholds, windows, investigation steps and
remediation advice). Rules only read stored log events and write alerts and incidents. Nothing here, or
anywhere else in Sentinel, ever runs an action on a host: remediation is advice text for a person.

How alerts are built
--------------------
* The ``events_ingested`` hook runs inside the agent's upload request, so it is database only and quick.
  Threshold rules count the device's stored events in the time window (not only the new batch), so a
  burst split across several uploads is still seen as one burst.
* ``dedupe_key`` is the SHA-256 of rule id, device id, entity and the window bucket of the burst's first
  event. A burst that grows is found again by time overlap and its alert is updated (event count, last
  event time, evidence) instead of creating a second alert.
* Alert evidence holds event ids, counts, first/last times and sample messages copied from the stored
  log events. Raw evidence stays in ``log_events``; alerts never contain AI-generated text.

Correlation
-----------
After an alert is created or updated it joins an open incident on the same device whose alerts' event
times lie within +/- 2 hours of the alert's events and that shares an entity (an account or a source IP).
Otherwise, when another open alert on the device within 2 hours shares an entity, a new incident is
opened. The ``+/- 2 h`` is measured on event times (when it happened on the host), not on upload times,
because a daily log scan uploads a whole day of events at once.

IOC hashes
----------
Sentinel ships no hash feed. Matching only uses SHA-256 values the user imports through ``/api/iocs``.
The background ``tick`` looks for those values inside evidence and log event data collected in the last
2 days.
"""

from __future__ import annotations

import bisect
import hashlib
import logging
import re
from collections import Counter, defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from pydantic import BaseModel, ConfigDict, Field, StrictBool
from sqlalchemy import and_, func, or_, select
from sqlalchemy.orm import Session

from .. import audit
from ..db import get_db
from ..deps import AuthContext, current_auth
from ..models import (
    Alert,
    AlertEventLink,
    AuditEntry,
    CheckRun,
    Device,
    EvidenceRecord,
    Incident,
    IocHash,
    LogEventRecord,
    RuleState,
    Scan,
    now,
)
from ..services import hooks
from ..services.notify import notify
from .logs import LogEventOut

log = logging.getLogger(__name__)

router = APIRouter(prefix="/api", tags=["detection"])

FAILED_LOGON = ("logon_failed", "ssh_failed")
SUCCESS_LOGON = ("logon_success", "ssh_success")
OPEN_ALERT = ("new", "acknowledged", "investigating")
OPEN_INCIDENT = ("open", "investigating")
ADMINISTRATORS_SID = "S-1-5-32-544"
NO_IP = ("", "-", "::", "0.0.0.0")  # noqa: S104 - a value seen in logs, not a bind address
# Built-in principals that appear in many unrelated events; they never link alerts together.
SYSTEM_PRINCIPALS = {"", "-", "system", "local service", "localservice", "network service", "networkservice",
                     "anonymous logon", "anonymous"}
SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
CORRELATION_WINDOW = timedelta(hours=2)
MAX_EVIDENCE_IDS = 500
MAX_ENTITIES = 50
IOC_LOOKBACK = timedelta(days=2)
IOC_CHUNK = 200
IOC_MAX_CHUNKS = 10
HEX64 = re.compile(r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{64}(?![0-9A-Fa-f])")
IOC_NOTE = ("Sentinel ships no hash feed. Matching only uses SHA-256 hashes you import here; they are compared "
            "with hashes found in evidence and log data collected in the last 2 days.")

USER_WRITABLE = ("\\users\\", "\\appdata\\", "\\temp\\", "\\users\\public\\")
# PowerShell accepts -e, -ec and any prefix of -EncodedCommand from -en on, with "-" or "/".
ENCODED_PS = re.compile(r"\b(?:powershell|pwsh)(?:\.exe)?\b.*?(?<![^\s\"'])[-/](?:e|ec|en[a-z]*)(?=[\s\"']|$)",
                        re.IGNORECASE | re.DOTALL)
CMD_C = re.compile(r"\bcmd(?:\.exe)?\"?\s+/[ck]\b", re.IGNORECASE)


# =========================================================================== rules


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    description: str
    severity: str
    confidence: str
    kind: Literal["heuristic", "verified"]
    investigation_steps: tuple[str, ...]
    remediation: str
    window_minutes: int | None = 60  # None: one alert per entity, whenever it happens
    threshold: int | None = None
    event_actions: tuple[str, ...] = field(default_factory=tuple)


RULE_LIST: tuple[Rule, ...] = (
    Rule(
        id="det.bruteforce",
        title="Possible brute-force sign-in attempts",
        description=("Ten or more failed sign-ins (Windows logon failures or SSH failures) from one source IP "
                     "address within 60 minutes. When the events carry no IP address, failures against one "
                     "account are counted instead."),
        severity="high", confidence="medium", kind="heuristic", window_minutes=60, threshold=10,
        event_actions=FAILED_LOGON,
        investigation_steps=(
            "Check whether the source address is one of your own devices or services. A saved, outdated password "
            "(mapped drive, phone mail app, scheduled task) produces the same pattern.",
            "Look at which accounts were tried: many different names suggests password spraying, one name a "
            "guessed or stale password.",
            "Search the logs for a successful sign-in from the same address, or for the same account, after the "
            "failures.",
            "If the address is outside your network, check whether Remote Desktop or SSH is reachable from the "
            "internet (router port forwarding).",
        ),
        remediation=("If the source is not yours: block the address at the router or firewall, stop exposing "
                     "Remote Desktop/SSH to the internet (use a VPN), use long unique passwords and keep an account "
                     "lockout policy on. If the source is your own device, update the password saved there. "
                     "Sentinel does not block anything itself."),
    ),
    Rule(
        id="det.bruteforce_success",
        title="Successful sign-in after repeated failures",
        description=("Five or more failed sign-ins followed by a successful sign-in for the same account or from "
                     "the same IP address within 30 minutes. It can be a person who mistyped a password, or a "
                     "guessed password."),
        severity="critical", confidence="medium", kind="heuristic", window_minutes=30, threshold=5,
        event_actions=FAILED_LOGON + SUCCESS_LOGON,
        investigation_steps=(
            "Ask the account owner whether they signed in at that time, from that address.",
            "Check the source address and logon details of the successful sign-in in the linked events.",
            "Review what the account did afterwards: new accounts, group changes, services or scheduled tasks "
            "created, cleared logs.",
            "Check the other alerts in the same incident.",
        ),
        remediation=("If the sign-in was not expected: change the account's password from a clean device, sign the "
                     "account out everywhere, review and remove accounts, services or scheduled tasks it created, "
                     "and disconnect the device from the network if you suspect remote control. If it was the "
                     "owner, mark the alert as a false positive."),
    ),
    Rule(
        id="det.audit_log_cleared",
        title="Event log cleared",
        description=("A Windows event log was cleared. Attackers clear logs to hide what they did; administrators "
                     "rarely need to."),
        severity="high", confidence="high", kind="verified", window_minutes=60,
        event_actions=("audit_log_cleared", "log_cleared"),
        investigation_steps=(
            "Check which account cleared the log and whether that person did it on purpose.",
            "Look at the events just before the clear in other logs that were not cleared.",
            "Check for other alerts on this device around the same time.",
        ),
        remediation=("If nobody you know cleared the log, treat the device as possibly compromised: change the "
                     "passwords of accounts used on it, review new accounts, services and scheduled tasks, and "
                     "consider a larger Security log size so history is kept longer."),
    ),
    Rule(
        id="det.admin_group_add",
        title="Account added to the local Administrators group",
        description=("An account was added to the built-in Administrators group (S-1-5-32-544), which gives it "
                     "full control of the device."),
        severity="high", confidence="high", kind="verified", window_minutes=24 * 60,
        event_actions=("group_member_added",),
        investigation_steps=(
            "Identify the added account (member SID or name) and the account that added it.",
            "Confirm with the person responsible whether the change was planned.",
            "Check whether the added account was created recently or signed in from an unusual address.",
        ),
        remediation=("If the change was not planned, remove the account from Administrators (Computer Management > "
                     "Local Users and Groups) and change the password of the account that made the change. "
                     "Sentinel does not change group membership itself."),
    ),
    Rule(
        id="det.new_local_account",
        title="New local account created",
        description="A new local user account was created on the device.",
        severity="medium", confidence="high", kind="verified", window_minutes=24 * 60,
        event_actions=("account_created",),
        investigation_steps=(
            "Check the new account's name and which account created it.",
            "Confirm it was created on purpose (a new person, or software that creates its own account).",
            "Check whether it was also added to Administrators or used to sign in.",
        ),
        remediation=("If the account is unexpected, disable it first (this keeps evidence), then find out how it "
                     "was created. Delete it once you are sure it is not needed."),
    ),
    Rule(
        id="det.suspicious_service",
        title="Service installed from a suspicious location",
        description=("A new service was installed whose program runs from a user-writable folder (\\Users\\, "
                     "\\AppData\\, \\Temp\\, \\Users\\Public\\) or starts PowerShell with an encoded command or "
                     "cmd /c. Software normally installs services under Program Files or Windows."),
        severity="high", confidence="medium", kind="heuristic", window_minutes=24 * 60,
        event_actions=("service_installed",),
        investigation_steps=(
            "Read the service's program path in the event and check whether the file still exists.",
            "Check the file's publisher signature and hash (Get-AuthenticodeSignature, Get-FileHash).",
            "Decode an encoded PowerShell command to read what it does, without running it.",
            "Check which account installed it and what else happened on the device at that time.",
        ),
        remediation=("If you do not recognize the service, stop and disable it (services.msc), keep a copy of the "
                     "file for analysis, run a full antivirus scan, and remove the service once you have what you "
                     "need. Sentinel never stops or removes services itself."),
    ),
    Rule(
        id="det.service_installed",
        title="New service installed",
        description="A new Windows service was installed. This is usually software installation or an update.",
        severity="low", confidence="high", kind="verified", window_minutes=24 * 60,
        event_actions=("service_installed",),
        investigation_steps=(
            "Check that the service name and program path belong to software you installed.",
            "Compare the install time with your own software installs and updates.",
        ),
        remediation="No action is needed if you recognize the software. Otherwise disable the service and look into "
                    "the program it runs.",
    ),
    Rule(
        id="det.malware_detected",
        title="Defender reported a detection",
        description="Microsoft Defender reported detecting malware or potentially unwanted software.",
        severity="high", confidence="high", kind="verified", window_minutes=24 * 60,
        event_actions=("malware_detected",),
        investigation_steps=(
            "Read the threat name and file path in the event.",
            "Check Defender's protection history for the action taken (quarantined, removed, or failed).",
            "Find out how the file arrived (download, email attachment, USB drive).",
            "Run a full scan.",
        ),
        remediation=("Let Defender quarantine or remove the item and run a full scan. If the action failed or the "
                     "threat returns, disconnect the device and run Microsoft Defender Offline. Change passwords used "
                     "on the device if the threat steals passwords."),
    ),
    Rule(
        id="det.realtime_protection_disabled",
        title="Defender real-time protection turned off",
        description="Microsoft Defender reported that real-time protection was turned off.",
        severity="high", confidence="high", kind="verified", window_minutes=60,
        event_actions=("realtime_protection_disabled",),
        investigation_steps=(
            "Check whether someone turned it off on purpose or another antivirus product took over.",
            "Check whether it has been turned back on.",
            "Look for malware detections or new services around the same time.",
        ),
        remediation=("Turn real-time protection back on in Windows Security > Virus & threat protection and enable "
                     "Tamper Protection so programs cannot turn it off."),
    ),
    Rule(
        id="det.account_lockout",
        title="Account locked out",
        description="An account was locked out after too many failed sign-in attempts.",
        severity="medium", confidence="high", kind="verified", window_minutes=60,
        event_actions=("account_locked_out",),
        investigation_steps=(
            "Check which account was locked and where the failures came from (failed sign-in events and "
            "brute-force alerts).",
            "Ask the owner whether they mistyped the password or recently changed it on another device.",
        ),
        remediation=("If the failures were not the owner's, block the source and keep the lockout policy on. "
                     "Otherwise update the stored password on the device that keeps retrying."),
    ),
    Rule(
        id="det.sudo_failures",
        title="Repeated sudo authentication failures",
        description="Three or more failed sudo attempts by one user within 10 minutes.",
        severity="medium", confidence="medium", kind="heuristic", window_minutes=10, threshold=3,
        event_actions=("sudo_failed",),
        investigation_steps=(
            "Check which user ran sudo and which commands were attempted (linked events).",
            "Ask the user whether it was them.",
            "Look for SSH sign-ins for the same user just before.",
        ),
        remediation=("If it was not the user, change their password, check ~/.ssh/authorized_keys for unknown keys "
                     "and review recent sign-ins. Sentinel does not change accounts itself."),
    ),
    Rule(
        id="det.ioc_hash_match",
        title="File hash matched a hash you imported",
        description=("A SHA-256 hash in collected evidence or log data matched a hash you imported as an indicator "
                     "of compromise. Sentinel ships no hash feed: it only matches hashes you added yourself."),
        severity="high", confidence="high", kind="verified", window_minutes=None,
        investigation_steps=(
            "Check the label and source you gave the hash when you imported it.",
            "Open the matching evidence or log event to see the file path.",
            "Confirm the hash on the device (Get-FileHash or sha256sum).",
        ),
        remediation=("If the file is malicious, quarantine it with your antivirus, run a full scan and find out how "
                     "it arrived. Sentinel does not delete or quarantine files itself."),
    ),
)
RULES: dict[str, Rule] = {r.id: r for r in RULE_LIST}


def enabled_rule_ids(db: Session) -> set[str]:
    disabled = set(db.execute(select(RuleState.rule_id).where(RuleState.enabled.is_(False))).scalars())
    return set(RULES) - disabled


# =========================================================================== small helpers


def _norm_user(value: str | None) -> str | None:
    if value is None:
        return None
    v = value.strip().lower()
    return v if v and v != "-" else None


def _norm_ip(value: str | None) -> str | None:
    if value is None:
        return None
    v = value.strip()
    return None if v.lower() in NO_IP else v


def _correlatable_user(user: str) -> bool:
    short = user.rsplit("\\", 1)[-1]
    return not (short in SYSTEM_PRINCIPALS or short.endswith("$") or short.startswith(("dwm-", "umfd-")))


def _data(ev: LogEventRecord, *names: str) -> str | None:
    data = ev.data or {}
    for n in names:
        v = data.get(n)
        if v not in (None, "", "-"):
            return str(v)
    return None


def _dedupe_key(rule_id: str, device_id: int, entity: str | None, bucket: int) -> str:
    raw = f"{rule_id}|{device_id}|{entity or ''}|{bucket}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _bucket(t: datetime, window: timedelta | None) -> int:
    if window is None:
        return 0
    return int(t.timestamp() // window.total_seconds())


def _clusters(rows: list[LogEventRecord], gap: timedelta) -> list[list[LogEventRecord]]:
    """Split time-sorted events where two neighbours are further apart than ``gap``."""
    out: list[list[LogEventRecord]] = []
    for ev in rows:
        if out and ev.occurred_at - out[-1][-1].occurred_at <= gap:
            out[-1].append(ev)
        else:
            out.append([ev])
    return out


def _bursts(rows: list[LogEventRecord], threshold: int, window: timedelta) -> list[list[LogEventRecord]]:
    """Events that belong to some ``window``-long span holding at least ``threshold`` events, as clusters."""
    rows = sorted(rows, key=lambda e: (e.occurred_at, e.id))
    marked = [False] * len(rows)
    start = 0
    last_marked = -1
    for j, ev in enumerate(rows):
        while ev.occurred_at - rows[start].occurred_at > window:
            start += 1
        if j - start + 1 >= threshold:
            for k in range(max(start, last_marked + 1), j + 1):
                marked[k] = True
            last_marked = j
    return _clusters([r for r, m in zip(rows, marked, strict=True) if m], window)


def is_suspicious_service_path(path: str | None) -> bool:
    if not path:
        return False
    p = path.replace("/", "\\").lower()
    if any(part in p for part in USER_WRITABLE):
        return True
    return bool(ENCODED_PS.search(path) or CMD_C.search(path))


def _fmt(t: datetime | None) -> str:
    return t.strftime("%Y-%m-%d %H:%M UTC") if t else "unknown time"


# =========================================================================== alert upsert


def _find_existing(db: Session, rule: Rule, device_id: int, entity: str | None, first: datetime,
                   last: datetime) -> Alert | None:
    q = select(Alert).where(Alert.rule_id == rule.id, Alert.device_id == device_id,
                            Alert.entity == entity if entity is not None else Alert.entity.is_(None))
    if rule.window_minutes is not None:
        window = timedelta(minutes=rule.window_minutes)
        q = q.where(Alert.last_event_at >= first - window, Alert.first_event_at <= last + window)
    return db.execute(q.order_by(Alert.last_event_at.desc(), Alert.id.desc()).limit(1)).scalar_one_or_none()


def _linked_ids(db: Session, alert_id: int) -> set[int]:
    return set(db.execute(select(AlertEventLink.log_event_id).where(AlertEventLink.alert_id == alert_id)).scalars())


def _refresh_alert(db: Session, alert: Alert, rule: Rule, device: Device, entity_kind: str,
                   details: list[str], evidence_matches: list[dict[str, Any]] | None) -> None:
    """Recompute counts, times, evidence and description from the linked events (and evidence matches)."""
    linked = (select(LogEventRecord).join(AlertEventLink, AlertEventLink.log_event_id == LogEventRecord.id)
              .where(AlertEventLink.alert_id == alert.id))
    n_events, first, last = db.execute(
        select(func.count(LogEventRecord.id), func.min(LogEventRecord.occurred_at),
               func.max(LogEventRecord.occurred_at))
        .join(AlertEventLink, AlertEventLink.log_event_id == LogEventRecord.id)
        .where(AlertEventLink.alert_id == alert.id)
    ).one()
    by_action = {a: n for a, n in db.execute(
        select(LogEventRecord.action, func.count())
        .join(AlertEventLink, AlertEventLink.log_event_id == LogEventRecord.id)
        .where(AlertEventLink.alert_id == alert.id).group_by(LogEventRecord.action)
    ).all()}
    ids = list(db.execute(linked.with_only_columns(LogEventRecord.id)
                          .order_by(LogEventRecord.occurred_at, LogEventRecord.id).limit(MAX_EVIDENCE_IDS)).scalars())
    head = list(db.execute(linked.order_by(LogEventRecord.occurred_at, LogEventRecord.id).limit(5)).scalars())
    tail = list(db.execute(linked.order_by(LogEventRecord.occurred_at.desc(), LogEventRecord.id.desc())
                           .limit(5)).scalars())
    samples_by_id = {e.id: e for e in head + tail}
    samples = [{"id": e.id, "occurred_at": e.occurred_at.isoformat(), "action": e.action, "user": e.user,
                "source_ip": e.source_ip, "message": e.message[:500]}
               for e in sorted(samples_by_id.values(), key=lambda e: (e.occurred_at, e.id))]
    users_raw = db.execute(linked.with_only_columns(func.lower(LogEventRecord.user)).distinct()
                           .limit(MAX_ENTITIES * 2)).scalars()
    ips_raw = db.execute(linked.with_only_columns(LogEventRecord.source_ip).distinct()
                         .limit(MAX_ENTITIES * 2)).scalars()
    users = sorted({u for raw in users_raw if (u := _norm_user(raw))})[:MAX_ENTITIES]
    ips = sorted({ip for raw in ips_raw if (ip := _norm_ip(raw))})[:MAX_ENTITIES]

    previous = alert.evidence or {}
    matches = list(previous.get("evidence_matches") or [])
    seen = {m["evidence_id"] for m in matches}
    for m in evidence_matches or []:
        if m["evidence_id"] not in seen:
            matches.append(m)
            seen.add(m["evidence_id"])
    match_times = [datetime.fromisoformat(m["collected_at"]) for m in matches]
    times = [t for t in (first, last) if t is not None] + match_times

    entities = {f"user:{u}" for u in users if _correlatable_user(u)} | {f"ip:{ip}" for ip in ips}
    if alert.entity and (entity_kind == "ip" or (entity_kind == "user" and _correlatable_user(alert.entity))):
        entities.add(f"{entity_kind}:{alert.entity}")

    alert.event_count = int(n_events) + len(matches)
    if times:
        alert.first_event_at = min(times)
        alert.last_event_at = max(times)
    evidence: dict[str, Any] = {
        "rule_id": rule.id,
        "entity": alert.entity,
        "entity_kind": entity_kind,
        "event_ids": ids,
        "event_ids_truncated": int(n_events) > len(ids),
        "event_count": int(n_events),
        "counts_by_action": by_action,
        "first_event_at": alert.first_event_at.isoformat(),
        "last_event_at": alert.last_event_at.isoformat(),
        "users": users,
        "source_ips": ips,
        "entities": sorted(entities),
        "samples": samples,
        "details": details or list(previous.get("details") or []),
    }
    if rule.threshold is not None:
        evidence["threshold"] = rule.threshold
        evidence["window_minutes"] = rule.window_minutes
    if matches:
        evidence["evidence_matches"] = matches
    for key in ("ioc_sha256", "ioc_label", "ioc_source", "reopened_at"):
        if key in previous:
            evidence[key] = previous[key]
    alert.evidence = evidence

    lines = [rule.description, "",
             f"Observed on {device.name}: {alert.event_count} matching item(s) between "
             f"{_fmt(alert.first_event_at)} and {_fmt(alert.last_event_at)}."]
    if by_action:
        lines.append("Events: " + ", ".join(f"{a} x{n}" for a, n in sorted(by_action.items())) + ".")
    if users:
        lines.append("Accounts: " + ", ".join(users[:10]) + (" and more" if len(users) > 10 else "") + ".")
    if ips:
        lines.append("Source addresses: " + ", ".join(ips[:10]) + (" and more" if len(ips) > 10 else "") + ".")
    lines.extend(evidence["details"])
    alert.description = "\n".join(lines)


def upsert_alert(
    db: Session,
    rule: Rule,
    device: Device,
    *,
    entity: str | None,
    entity_kind: str,
    title: str,
    events: list[LogEventRecord],
    details: list[str] | None = None,
    evidence_matches: list[dict[str, Any]] | None = None,
    extra_evidence: dict[str, Any] | None = None,
) -> Alert | None:
    """Create or update the alert for one burst of ``rule`` on ``device`` about ``entity``."""
    times = [e.occurred_at for e in events] + [datetime.fromisoformat(m["collected_at"])
                                               for m in evidence_matches or []]
    if not times:
        return None
    first, last = min(times), max(times)
    window = timedelta(minutes=rule.window_minutes) if rule.window_minutes is not None else None
    key = _dedupe_key(rule.id, device.id, entity, _bucket(first, window))
    alert = _find_existing(db, rule, device.id, entity, first, last)
    if alert is None:
        alert = db.execute(select(Alert).where(Alert.dedupe_key == key)).scalar_one_or_none()
    created = False
    if alert is None:
        alert = Alert(device_id=device.id, rule_id=rule.id, dedupe_key=key, title=title[:300],
                      description=rule.description, severity=rule.severity, confidence=rule.confidence,
                      kind=rule.kind, status="new", entity=entity, first_event_at=first, last_event_at=last,
                      event_count=0, evidence=dict(extra_evidence or {}),
                      investigation_steps=list(rule.investigation_steps), remediation=rule.remediation)
        db.add(alert)
        db.flush()
        created = True

    already = _linked_ids(db, alert.id)
    new_events = [e for e in events if e.id not in already]
    known_matches = {m["evidence_id"] for m in (alert.evidence or {}).get("evidence_matches") or []}
    new_matches = [m for m in evidence_matches or [] if m["evidence_id"] not in known_matches]
    if not created and not new_events and not new_matches:
        return alert  # nothing new for this alert
    for e in new_events:
        db.add(AlertEventLink(alert_id=alert.id, log_event_id=e.id))
    db.flush()

    reopened = False
    if not created and alert.status == "resolved":
        # Activity continued after someone resolved it: bring it back rather than hide it.
        alert.status = "new"
        reopened = True
        alert.evidence = {**(alert.evidence or {}), "reopened_at": now().isoformat()}
    if extra_evidence:
        alert.evidence = {**(alert.evidence or {}), **extra_evidence}
    _refresh_alert(db, alert, rule, device, entity_kind, details or [], evidence_matches)
    db.flush()

    if created or reopened:
        n = notify(db, severity=alert.severity, kind="alert", title=f"{alert.title} on {device.name}",
                   body=alert.description[:1000], link=f"/threats/alerts/{alert.id}",
                   dedupe_key=f"alert:{alert.id}" if created else f"alert:{alert.id}:reopened:{alert.event_count}")
        if n is not None:
            alert.notified = True
    correlate(db, alert, device)
    return alert


# =========================================================================== correlation


def alert_entities(alert: Alert) -> set[str]:
    return set((alert.evidence or {}).get("entities") or [])


def _user_wrote_summary(db: Session, incident: Incident) -> bool:
    entries = db.execute(select(AuditEntry).where(
        AuditEntry.action == "incident.updated", AuditEntry.target_type == "incident",
        AuditEntry.target_id == str(incident.id)).order_by(AuditEntry.id.desc())).scalars()
    for e in entries:
        if "summary" in (e.detail or {}).get("fields", []):
            return bool(e.detail.get("summary_set"))
    return False


def _entity_label(entity: str) -> str:
    kind, _, value = entity.partition(":")
    return f"{'account' if kind == 'user' else 'IP'} {value}"


def refresh_incident(db: Session, incident: Incident) -> None:
    """Severity, entities, title and the automatic summary follow the incident's alerts."""
    alerts = list(db.execute(select(Alert).where(Alert.incident_id == incident.id)
                             .order_by(Alert.first_event_at, Alert.id)).scalars())
    device = db.get(Device, incident.device_id)
    device_name = device.name if device else f"device {incident.device_id}"
    incident.updated_at = now()
    if not alerts:
        return
    counted = [a for a in alerts if a.status != "false_positive"] or alerts
    incident.severity = max((a.severity for a in counted), key=lambda s: SEV_RANK.get(s, 0))
    counts: Counter[str] = Counter()
    for a in alerts:
        counts.update(alert_entities(a))
    shared = sorted((e for e, n in counts.items() if n >= 2), key=lambda e: (-counts[e], e))
    incident.entities = sorted(counts, key=lambda e: (-counts[e], e))[:MAX_ENTITIES]
    shared_users = [e for e in shared if e.startswith("user:")]
    if shared_users:
        incident.title = f"Possible account compromise: {shared_users[0].partition(':')[2]}"[:300]
    else:
        incident.title = f"{len(alerts)} related alerts on {device_name}"[:300]
    if not _user_wrote_summary(db, incident):
        first = min(a.first_event_at for a in alerts)
        last = max(a.last_event_at for a in alerts)
        parts = [f"{len(alerts)} alerts on {device_name} between {_fmt(first)} and {_fmt(last)}."]
        if shared:
            parts.append("Shared: " + ", ".join(_entity_label(e) for e in shared[:5]) + ".")
        parts.append("Alerts: " + "; ".join(
            f"{a.title} ({a.severity}, {a.event_count} item(s), {a.status})" for a in alerts) + ".")
        parts.append("Generated from the linked alerts; nothing was changed on the device.")
        incident.summary = " ".join(parts)


def correlate(db: Session, alert: Alert, device: Device) -> Incident | None:
    if alert.status not in OPEN_ALERT:
        if alert.incident_id is not None and (inc := db.get(Incident, alert.incident_id)) is not None:
            refresh_incident(db, inc)
        return None
    if alert.incident_id is not None:
        inc = db.get(Incident, alert.incident_id)
        if inc is not None:
            refresh_incident(db, inc)
        return inc
    ents = alert_entities(alert)
    if not ents:
        return None
    lo, hi = alert.first_event_at - CORRELATION_WINDOW, alert.last_event_at + CORRELATION_WINDOW
    candidates = db.execute(select(Incident).where(Incident.device_id == device.id,
                                                   Incident.status.in_(OPEN_INCIDENT))
                            .order_by(Incident.opened_at.desc(), Incident.id.desc())).scalars().all()
    for inc in candidates:
        span_first, span_last = db.execute(select(func.min(Alert.first_event_at), func.max(Alert.last_event_at))
                                           .where(Alert.incident_id == inc.id)).one()
        if span_first is None or span_last < lo or span_first > hi:
            continue
        if set(inc.entities or []) & ents:
            alert.incident_id = inc.id
            db.flush()
            refresh_incident(db, inc)
            return inc
    related = [a for a in db.execute(select(Alert).where(
        Alert.device_id == device.id, Alert.id != alert.id, Alert.status.in_(OPEN_ALERT),
        Alert.incident_id.is_(None), Alert.last_event_at >= lo, Alert.first_event_at <= hi)).scalars()
        if alert_entities(a) & ents]
    if not related:
        return None
    t = now()
    inc = Incident(device_id=device.id, title="Related alerts", severity=alert.severity, status="open",
                   entities=[], opened_at=t, updated_at=t)
    db.add(inc)
    db.flush()
    for a in [alert, *related]:
        a.incident_id = inc.id
    db.flush()
    refresh_incident(db, inc)
    audit.record(db, "system", "incident.opened", "incident", inc.id,
                 {"device_id": device.id, "alerts": sorted(a.id for a in [alert, *related])})
    return inc


# =========================================================================== evaluators (hook)


def _entity_clause(kind: str, value: str, *, require_no_ip: bool = False) -> Any:
    if kind == "ip":
        return LogEventRecord.source_ip == value
    clause = func.lower(LogEventRecord.user) == value
    if require_no_ip:
        clause = and_(clause, or_(LogEventRecord.source_ip.is_(None), LogEventRecord.source_ip.in_(NO_IP)))
    return clause


def _window_rows(db: Session, device_id: int, actions: Iterable[str], clause: Any, lo: datetime,
                 hi: datetime) -> list[LogEventRecord]:
    return list(db.execute(select(LogEventRecord).where(
        LogEventRecord.device_id == device_id, LogEventRecord.action.in_(list(actions)), clause,
        LogEventRecord.occurred_at >= lo, LogEventRecord.occurred_at <= hi,
    ).order_by(LogEventRecord.occurred_at, LogEventRecord.id)).scalars())


def _counts_by_entity(db: Session, device_id: int, actions: Iterable[str], kind: str, lo: datetime, hi: datetime,
                      *, require_no_ip: bool = False) -> dict[str, int]:
    """One grouped count per entity over [lo, hi]: a cheap prefilter before loading any window."""
    col = LogEventRecord.source_ip if kind == "ip" else func.lower(LogEventRecord.user)
    q = select(col, func.count()).where(LogEventRecord.device_id == device_id,
                                        LogEventRecord.action.in_(list(actions)),
                                        LogEventRecord.occurred_at >= lo, LogEventRecord.occurred_at <= hi)
    if require_no_ip:
        q = q.where(or_(LogEventRecord.source_ip.is_(None), LogEventRecord.source_ip.in_(NO_IP)))
    return {k: n for k, n in db.execute(q.group_by(col)).all() if k is not None}


def _threshold_rule(db: Session, rule: Rule, device: Device, batch: list[LogEventRecord],
                    entity_of: Any, title_of: Any) -> None:
    assert rule.threshold is not None and rule.window_minutes is not None
    window = timedelta(minutes=rule.window_minutes)
    groups: dict[tuple[str, str], list[LogEventRecord]] = defaultdict(list)
    for ev in batch:
        if ev.action in rule.event_actions and (key := entity_of(ev)) is not None:
            groups[key].append(ev)
    if not groups:
        return
    span_lo = min(e.occurred_at for evs in groups.values() for e in evs) - window
    span_hi = max(e.occurred_at for evs in groups.values() for e in evs) + window
    counts = {kind: _counts_by_entity(db, device.id, rule.event_actions, kind, span_lo, span_hi,
                                      require_no_ip=(rule.id == "det.bruteforce" and kind == "user"))
              for kind in {k for k, _ in groups}}
    for (kind, value), new in sorted(groups.items()):
        if counts[kind].get(value, 0) < rule.threshold:
            continue  # cannot reach the threshold anywhere in this batch's time span
        new_ids = {e.id for e in new}
        lo = min(e.occurred_at for e in new) - window
        hi = max(e.occurred_at for e in new) + window
        clause = _entity_clause(kind, value, require_no_ip=(rule.id == "det.bruteforce" and kind == "user"))
        rows = _window_rows(db, device.id, rule.event_actions, clause, lo, hi)
        for burst in _bursts(rows, rule.threshold, window):
            if new_ids & {e.id for e in burst}:
                upsert_alert(db, rule, device, entity=value, entity_kind=kind, title=title_of(kind, value),
                             events=burst)


def _bruteforce_entity(ev: LogEventRecord) -> tuple[str, str] | None:
    if (ip := _norm_ip(ev.source_ip)) is not None:
        return ("ip", ip)
    if (user := _norm_user(ev.user)) is not None:
        return ("user", user)
    return None


def _eval_bruteforce(db: Session, device: Device, events: list[LogEventRecord]) -> None:
    _threshold_rule(db, RULES["det.bruteforce"], device, events, _bruteforce_entity,
                    lambda kind, v: f"Possible brute force from {v}" if kind == "ip"
                    else f"Possible brute force against account {v}")


def _eval_sudo(db: Session, device: Device, events: list[LogEventRecord]) -> None:
    def entity(ev: LogEventRecord) -> tuple[str, str] | None:
        user = _norm_user(ev.user)
        return ("user", user) if user else None

    _threshold_rule(db, RULES["det.sudo_failures"], device, events, entity,
                    lambda _kind, v: f"Repeated sudo failures by {v}")


def _eval_bruteforce_success(db: Session, device: Device, events: list[LogEventRecord]) -> None:
    rule = RULES["det.bruteforce_success"]
    assert rule.threshold is not None and rule.window_minutes is not None
    window = timedelta(minutes=rule.window_minutes)
    batch = [e for e in events if e.action in rule.event_actions]
    if not batch:
        return
    new_ids = {e.id for e in batch}
    lo = min(e.occurred_at for e in batch) - window
    hi = max(e.occurred_at for e in batch) + window
    users = sorted({u for e in batch if (u := _norm_user(e.user))})
    ips = sorted({ip for e in batch if (ip := _norm_ip(e.source_ip))})
    claimed: dict[int, str] = {}  # success event id -> entity whose alert holds it
    for kind, values in (("user", users), ("ip", ips)):
        if not values:
            continue
        fail_counts = _counts_by_entity(db, device.id, FAILED_LOGON, kind, lo, hi)
        for value in values:
            if fail_counts.get(value, 0) < rule.threshold:
                continue  # the common case (SYSTEM, machine accounts): no need to load their sign-ins
            clause = _entity_clause(kind, value)
            rows = _window_rows(db, device.id, rule.event_actions, clause, lo, hi)
            failures = [e for e in rows if e.action in FAILED_LOGON]
            fail_times = [f.occurred_at for f in failures]
            candidates: list[tuple[LogEventRecord, int, int]] = []
            for s in rows:
                if s.action not in SUCCESS_LOGON:
                    continue
                start = bisect.bisect_left(fail_times, s.occurred_at - window)
                end = bisect.bisect_right(fail_times, s.occurred_at)
                if end - start >= rule.threshold:
                    candidates.append((s, start, end))
            if not candidates:
                continue
            for link_event_id, entity in db.execute(
                select(AlertEventLink.log_event_id, Alert.entity).join(Alert, Alert.id == AlertEventLink.alert_id)
                .where(Alert.rule_id == rule.id, Alert.device_id == device.id,
                       AlertEventLink.log_event_id.in_([s.id for s, _, _ in candidates]))
            ).all():
                claimed.setdefault(link_event_id, entity or "")
            groups: list[list[LogEventRecord]] = []
            for s, start, end in candidates:
                if claimed.get(s.id, value) != value:
                    continue  # this sign-in already belongs to the alert for the account (or address)
                groups.append([*failures[start:end], s])
                claimed[s.id] = value
            merged: list[dict[int, LogEventRecord]] = []
            for g in groups:  # groups are in success-time order; overlapping ones form one burst
                if merged and g[0].occurred_at <= max(e.occurred_at for e in merged[-1].values()) + window:
                    merged[-1].update({e.id: e for e in g})
                else:
                    merged.append({e.id: e for e in g})
            for by_id in merged:
                cluster = list(by_id.values())
                if not new_ids & {e.id for e in cluster}:
                    continue
                n_fail = sum(1 for e in cluster if e.action in FAILED_LOGON)
                title = (f"Sign-in as {value} after {n_fail} failures" if kind == "user"
                         else f"Successful sign-in from {value} after {n_fail} failures")
                upsert_alert(db, rule, device, entity=value, entity_kind=kind, title=title,
                             events=sorted(cluster, key=lambda e: (e.occurred_at, e.id)))


def _classify(ev: LogEventRecord) -> tuple[str, str | None, str, str, list[str]] | None:
    """Single-event rules: (rule id, entity, entity kind, title, details) or None."""
    a = ev.action
    user = _norm_user(ev.user)
    if a in ("audit_log_cleared", "log_cleared"):
        channel = _data(ev, "Channel", "channel") or ev.source.partition(":")[2] or ev.source
        title = f"{channel} log cleared" + (f" by {user}" if user else "")
        return "det.audit_log_cleared", user, "user", title, [f"Log: {channel}."]
    if a == "group_member_added":
        group_sid = (_data(ev, "TargetSid") or "").upper()
        if group_sid != ADMINISTRATORS_SID:
            return None
        member = _data(ev, "MemberName", "MemberSid") or "unknown account"
        member_sid = _data(ev, "MemberSid")
        title = f"{member} added to Administrators"
        details = [f"Member: {member}" + (f" ({member_sid})" if member_sid and member_sid != member else "") + "."]
        if user:
            details.append(f"Changed by: {user}.")
        kind = "user" if not member.upper().startswith("S-1-") else "sid"
        return "det.admin_group_add", member.lower() if kind == "user" else member, kind, title, details
    if a == "account_created":
        target = _norm_user(_data(ev, "TargetUserName", "SamAccountName")) or user or "unknown account"
        details = [f"New account: {target}."] + ([f"Created by: {user}."] if user and user != target else [])
        return "det.new_local_account", target, "user", f"New local account: {target}", details
    if a == "service_installed":
        path = _data(ev, "ImagePath", "ServiceFileName") or ""
        name = _data(ev, "ServiceName") or "unknown service"
        details = [f"Service: {name}.", f"Program: {path or 'not recorded'}."]
        if is_suspicious_service_path(path):
            return "det.suspicious_service", name, "service", f"Suspicious service installed: {name}", details
        return "det.service_installed", name, "service", f"New service installed: {name}", details
    if a == "malware_detected":
        threat = _data(ev, "Threat Name", "ThreatName") or "unnamed threat"
        threat_path = _data(ev, "Path")
        details = [f"Threat: {threat}."] + ([f"Path: {threat_path}."] if threat_path else [])
        return "det.malware_detected", threat, "threat", f"Defender reported {threat}", details
    if a == "realtime_protection_disabled":
        return ("det.realtime_protection_disabled", None, "none", RULES["det.realtime_protection_disabled"].title,
                [])
    if a == "account_locked_out":
        target = _norm_user(_data(ev, "TargetUserName")) or user or "unknown account"
        return "det.account_lockout", target, "user", f"Account locked out: {target}", [f"Account: {target}."]
    return None


def _eval_single(db: Session, device: Device, events: list[LogEventRecord], enabled: set[str]) -> None:
    groups: dict[tuple[str, str | None, str], list[tuple[LogEventRecord, str, list[str]]]] = defaultdict(list)
    for ev in events:
        hit = _classify(ev)
        if hit is None or hit[0] not in enabled:
            continue
        rule_id, entity, kind, title, details = hit
        groups[(rule_id, entity, kind)].append((ev, title, details))
    for (rule_id, entity, kind), items in groups.items():
        rule = RULES[rule_id]
        items.sort(key=lambda it: (it[0].occurred_at, it[0].id))
        gap = timedelta(minutes=rule.window_minutes or 0) if rule.window_minutes else timedelta.max
        for cluster in _clusters([it[0] for it in items], gap):
            last = next(it for it in reversed(items) if it[0].id == cluster[-1].id)
            upsert_alert(db, rule, device, entity=entity, entity_kind=kind, title=last[1], events=cluster,
                         details=last[2])


def on_events_ingested(db: Session, device: Device, scan: Scan | None, events: list[LogEventRecord]) -> None:
    """Hook: evaluate rules for a freshly stored batch. Database only; no commit."""
    if not events:
        return
    enabled = enabled_rule_ids(db)
    steps: list[tuple[str, Any]] = [
        ("det.bruteforce", lambda: _eval_bruteforce(db, device, events)),
        ("det.bruteforce_success", lambda: _eval_bruteforce_success(db, device, events)),
        ("det.sudo_failures", lambda: _eval_sudo(db, device, events)),
        ("single-event rules", lambda: _eval_single(db, device, events, enabled)),
    ]
    for name, step in steps:
        if name in RULES and name not in enabled:
            continue
        try:
            with db.begin_nested():
                step()
        except Exception:
            log.exception("detection step %s failed for device %s", name, device.id)


def register_hooks() -> None:
    hooks.register("events_ingested", on_events_ingested)


# =========================================================================== IOC matching (tick)

# How far the IOC matcher has read, per database, so each tick only walks new rows. A change in the
# imported hash set resets it, so new hashes are compared with the whole 2-day lookback.
_ioc_progress: dict[str, dict[str, Any]] = {}


def _db_key(db: Session) -> str:
    return str(getattr(db.get_bind(), "url", "default"))


def find_hashes(value: Any, out: set[str] | None = None, depth: int = 0) -> set[str]:
    """Every 64-hex-character string anywhere inside a JSON value, lower-cased."""
    out = set() if out is None else out
    if depth > 32:
        return out
    if isinstance(value, str):
        if len(value) >= 64:
            out.update(m.lower() for m in HEX64.findall(value))
    elif isinstance(value, dict):
        for k, v in value.items():
            find_hashes(k, out, depth + 1)
            find_hashes(v, out, depth + 1)
    elif isinstance(value, list | tuple):
        for v in value:
            find_hashes(v, out, depth + 1)
    return out


def _ioc_alert(db: Session, ioc: IocHash, device: Device, events: list[LogEventRecord],
               matches: list[dict[str, Any]]) -> Alert | None:
    label = f": {ioc.label}" if ioc.label else ""
    places = sorted({m["source"] for m in matches} | {e.source for e in events})
    details = [f"Hash: {ioc.sha256}.", f"Imported indicator{label or ''} (source: {ioc.source}).",
               "Found in: " + ", ".join(places[:10]) + "."]
    return upsert_alert(db, RULES["det.ioc_hash_match"], device, entity=ioc.sha256, entity_kind="hash",
                        title=f"File hash matched imported indicator{label}"[:300], events=events, details=details,
                        evidence_matches=matches,
                        extra_evidence={"ioc_sha256": ioc.sha256, "ioc_label": ioc.label, "ioc_source": ioc.source})


def match_iocs(db: Session, now_: datetime | None = None) -> int:
    """Compare imported hashes with evidence and log data from the last 2 days. Returns alerts touched."""
    t = now_ or now()
    iocs = {h.sha256: h for h in db.execute(select(IocHash)).scalars()}
    state = _ioc_progress.setdefault(_db_key(db), {"signature": None, "evidence_id": 0, "log_id": 0})
    if not iocs or "det.ioc_hash_match" not in enabled_rule_ids(db):
        return 0
    signature = hashlib.sha256("".join(sorted(iocs)).encode()).hexdigest()
    if signature != state["signature"]:  # new or removed hashes: look at the whole lookback window again
        state.update(signature=signature, evidence_id=0, log_id=0)
    since = t - IOC_LOOKBACK
    hits_events: dict[tuple[int, str], list[LogEventRecord]] = defaultdict(list)
    hits_evidence: dict[tuple[int, str], list[dict[str, Any]]] = defaultdict(list)

    for _ in range(IOC_MAX_CHUNKS):
        rows = db.execute(
            select(EvidenceRecord, Scan.device_id, CheckRun.check_id)
            .join(CheckRun, CheckRun.id == EvidenceRecord.check_run_id).join(Scan, Scan.id == CheckRun.scan_id)
            .where(EvidenceRecord.id > state["evidence_id"], EvidenceRecord.collected_at >= since)
            .order_by(EvidenceRecord.id).limit(IOC_CHUNK)
        ).all()
        for ev, device_id, check_id in rows:
            for h in find_hashes(ev.content) & iocs.keys():
                hits_evidence[(device_id, h)].append({
                    "evidence_id": ev.id, "check_run_id": ev.check_run_id, "check_id": check_id,
                    "source": ev.source, "kind": ev.kind, "collected_at": ev.collected_at.isoformat()})
        if rows:
            state["evidence_id"] = rows[-1][0].id
        if len(rows) < IOC_CHUNK:
            break

    for _ in range(IOC_MAX_CHUNKS):
        events = list(db.execute(
            select(LogEventRecord).where(LogEventRecord.id > state["log_id"], LogEventRecord.ingested_at >= since)
            .order_by(LogEventRecord.id).limit(IOC_CHUNK)).scalars())
        for le in events:
            for h in find_hashes(le.data) & iocs.keys():
                hits_events[(le.device_id, h)].append(le)
        if events:
            state["log_id"] = events[-1].id
        if len(events) < IOC_CHUNK:
            break

    touched = 0
    for key in sorted(set(hits_events) | set(hits_evidence)):
        device_id, h = key
        device = db.get(Device, device_id)
        if device is None:
            continue
        if _ioc_alert(db, iocs[h], device, hits_events.get(key, []), hits_evidence.get(key, [])) is not None:
            touched += 1
    return touched


def tick(db: Session) -> None:
    match_iocs(db)


# =========================================================================== API schemas


class AlertOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    device_id: int
    device_name: str | None = None
    rule_id: str
    title: str
    severity: str
    confidence: str
    kind: str
    status: str
    entity: str | None
    first_event_at: datetime
    last_event_at: datetime
    detected_at: datetime
    event_count: int
    incident_id: int | None
    notified: bool


class IncidentOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    device_id: int
    device_name: str | None = None
    title: str
    severity: str
    status: str
    entities: list[str]
    opened_at: datetime
    updated_at: datetime
    closed_at: datetime | None
    summary: str | None
    alert_count: int = 0


class AlertDetail(AlertOut):
    description: str
    evidence: dict[str, Any]
    investigation_steps: list[str]
    remediation: str
    notes: str | None
    events: list[LogEventOut]
    events_total: int
    incident: IncidentOut | None


class IncidentDetail(IncidentOut):
    alerts: list[AlertOut]


class AlertPage(BaseModel):
    items: list[AlertOut]
    total: int


class IncidentPage(BaseModel):
    items: list[IncidentOut]
    total: int


class AlertUpdate(BaseModel):
    status: Literal["new", "acknowledged", "investigating", "resolved", "false_positive"] | None = None
    notes: str | None = Field(default=None, max_length=8000)


class IncidentUpdate(BaseModel):
    status: Literal["open", "investigating", "closed"] | None = None
    summary: str | None = Field(default=None, max_length=8000)


class RuleOut(BaseModel):
    id: str
    title: str
    description: str
    severity: str
    confidence: str
    kind: str
    enabled: bool
    threshold: int | None
    window_minutes: int | None
    event_actions: list[str]
    investigation_steps: list[str]
    remediation: str
    alert_count: int
    open_alert_count: int


class RuleUpdate(BaseModel):
    enabled: StrictBool


class IocIn(BaseModel):
    sha256: str = Field(pattern=r"^[0-9A-Fa-f]{64}$")
    label: str | None = Field(default=None, max_length=255)


class IocOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    sha256: str
    label: str | None
    source: str
    added_at: datetime


class IocList(BaseModel):
    items: list[IocOut]
    total: int
    note: str


class IocImportResult(BaseModel):
    added: int
    updated: int
    total: int
    note: str


# =========================================================================== routes: alerts


def _device_names(db: Session, ids: Iterable[int]) -> dict[int, str]:
    ids = set(ids)
    if not ids:
        return {}
    return {d.id: d.name for d in db.execute(select(Device).where(Device.id.in_(ids))).scalars()}


def _alert_out(a: Alert, names: dict[int, str]) -> AlertOut:
    out = AlertOut.model_validate(a)
    out.device_name = names.get(a.device_id)
    return out


def _incident_out(db: Session, inc: Incident, names: dict[int, str]) -> IncidentOut:
    out = IncidentOut.model_validate(inc)
    out.device_name = names.get(inc.device_id)
    out.alert_count = db.execute(select(func.count(Alert.id)).where(Alert.incident_id == inc.id)).scalar_one()
    return out


@router.get("/alerts", response_model=AlertPage)
def list_alerts(
    status_filter: list[str] | None = Query(None, alias="status", description="One or more statuses, or 'open'"),
    severity: list[str] | None = Query(None),
    device_id: int | None = None,
    rule_id: str | None = Query(None, max_length=128),
    incident_id: int | None = None,
    since: datetime | None = Query(None, description="Detected or active since"),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    auth: AuthContext = Depends(current_auth),
    db: Session = Depends(get_db),
) -> AlertPage:
    q = select(Alert)
    if status_filter:
        wanted = set(status_filter)
        if "open" in wanted:
            wanted = (wanted - {"open"}) | set(OPEN_ALERT)
        q = q.where(Alert.status.in_(sorted(wanted)))
    if severity:
        q = q.where(Alert.severity.in_(severity))
    if device_id is not None:
        q = q.where(Alert.device_id == device_id)
    if rule_id:
        q = q.where(Alert.rule_id == rule_id)
    if incident_id is not None:
        q = q.where(Alert.incident_id == incident_id)
    if since is not None:
        q = q.where(or_(Alert.detected_at >= since, Alert.last_event_at >= since))
    total = db.execute(select(func.count()).select_from(q.subquery())).scalar_one()
    rows = db.execute(q.order_by(Alert.detected_at.desc(), Alert.id.desc()).limit(limit).offset(offset)).scalars().all()
    names = _device_names(db, (a.device_id for a in rows))
    return AlertPage(items=[_alert_out(a, names) for a in rows], total=total)


def _get_alert(db: Session, alert_id: int) -> Alert:
    a = db.get(Alert, alert_id)
    if a is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No such alert")
    return a


def _alert_detail(db: Session, a: Alert) -> AlertDetail:
    names = _device_names(db, [a.device_id])
    base = _alert_out(a, names).model_dump()
    events_q = (select(LogEventRecord).join(AlertEventLink, AlertEventLink.log_event_id == LogEventRecord.id)
                .where(AlertEventLink.alert_id == a.id))
    total = db.execute(select(func.count()).select_from(events_q.subquery())).scalar_one()
    events = db.execute(events_q.order_by(LogEventRecord.occurred_at, LogEventRecord.id).limit(500)).scalars().all()
    inc = db.get(Incident, a.incident_id) if a.incident_id is not None else None
    return AlertDetail(**base, description=a.description, evidence=a.evidence or {},
                       investigation_steps=list(a.investigation_steps or []), remediation=a.remediation,
                       notes=a.notes, events=[LogEventOut.model_validate(e) for e in events], events_total=total,
                       incident=_incident_out(db, inc, names) if inc else None)


@router.get("/alerts/{alert_id}", response_model=AlertDetail)
def get_alert(alert_id: int, auth: AuthContext = Depends(current_auth), db: Session = Depends(get_db)) -> AlertDetail:
    return _alert_detail(db, _get_alert(db, alert_id))


@router.patch("/alerts/{alert_id}", response_model=AlertDetail)
def update_alert(alert_id: int, body: AlertUpdate, auth: AuthContext = Depends(current_auth),
                 db: Session = Depends(get_db)) -> AlertDetail:
    a = _get_alert(db, alert_id)
    fields = body.model_fields_set
    before = a.status
    if "status" in fields and body.status is not None:
        a.status = body.status
    if "notes" in fields:
        a.notes = body.notes
    audit.record(db, auth.actor, "alert.updated", "alert", a.id,
                 {"from": before, "to": a.status, "notes_changed": "notes" in fields})
    if a.incident_id is not None and (inc := db.get(Incident, a.incident_id)) is not None:
        refresh_incident(db, inc)
    db.commit()
    return _alert_detail(db, a)


# =========================================================================== routes: incidents


@router.get("/incidents", response_model=IncidentPage)
def list_incidents(
    status_filter: list[str] | None = Query(None, alias="status", description="One or more statuses, or 'open'"),
    device_id: int | None = None,
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    auth: AuthContext = Depends(current_auth),
    db: Session = Depends(get_db),
) -> IncidentPage:
    q = select(Incident)
    if status_filter:
        wanted = set(status_filter)
        if "open" in wanted:
            wanted = (wanted - {"open"}) | set(OPEN_INCIDENT)
        q = q.where(Incident.status.in_(sorted(wanted)))
    if device_id is not None:
        q = q.where(Incident.device_id == device_id)
    total = db.execute(select(func.count()).select_from(q.subquery())).scalar_one()
    rows = db.execute(q.order_by(Incident.updated_at.desc(), Incident.id.desc()).limit(limit)
                      .offset(offset)).scalars().all()
    names = _device_names(db, (i.device_id for i in rows))
    return IncidentPage(items=[_incident_out(db, i, names) for i in rows], total=total)


def _get_incident(db: Session, incident_id: int) -> Incident:
    inc = db.get(Incident, incident_id)
    if inc is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No such incident")
    return inc


def _incident_detail(db: Session, inc: Incident) -> IncidentDetail:
    alerts = db.execute(select(Alert).where(Alert.incident_id == inc.id)
                        .order_by(Alert.first_event_at, Alert.id)).scalars().all()
    names = _device_names(db, [inc.device_id])
    return IncidentDetail(**_incident_out(db, inc, names).model_dump(),
                          alerts=[_alert_out(a, names) for a in alerts])


@router.get("/incidents/{incident_id}", response_model=IncidentDetail)
def get_incident(incident_id: int, auth: AuthContext = Depends(current_auth),
                 db: Session = Depends(get_db)) -> IncidentDetail:
    return _incident_detail(db, _get_incident(db, incident_id))


@router.patch("/incidents/{incident_id}", response_model=IncidentDetail)
def update_incident(incident_id: int, body: IncidentUpdate, auth: AuthContext = Depends(current_auth),
                    db: Session = Depends(get_db)) -> IncidentDetail:
    inc = _get_incident(db, incident_id)
    fields = sorted(body.model_fields_set)
    before = inc.status
    if "status" in fields and body.status is not None and body.status != inc.status:
        inc.status = body.status
        inc.closed_at = now() if body.status == "closed" else None
    summary_set = bool(body.summary and body.summary.strip())
    if "summary" in fields and summary_set:
        inc.summary = body.summary
    inc.updated_at = now()
    audit.record(db, auth.actor, "incident.updated", "incident", inc.id,
                 {"fields": fields, "from": before, "to": inc.status, "summary_set": summary_set})
    if "summary" in fields and not summary_set:
        refresh_incident(db, inc)  # an empty summary goes back to the generated one
    db.commit()
    return _incident_detail(db, inc)


# =========================================================================== routes: rules


@router.get("/rules", response_model=list[RuleOut])
def list_rules(auth: AuthContext = Depends(current_auth), db: Session = Depends(get_db)) -> list[RuleOut]:
    enabled = enabled_rule_ids(db)
    totals = {r: n for r, n in db.execute(select(Alert.rule_id, func.count()).group_by(Alert.rule_id)).all()}
    opens = {r: n for r, n in db.execute(select(Alert.rule_id, func.count()).where(Alert.status.in_(OPEN_ALERT))
                                         .group_by(Alert.rule_id)).all()}
    return [RuleOut(id=r.id, title=r.title, description=r.description, severity=r.severity,
                    confidence=r.confidence, kind=r.kind, enabled=r.id in enabled, threshold=r.threshold,
                    window_minutes=r.window_minutes, event_actions=list(r.event_actions),
                    investigation_steps=list(r.investigation_steps), remediation=r.remediation,
                    alert_count=totals.get(r.id, 0), open_alert_count=opens.get(r.id, 0)) for r in RULE_LIST]


@router.patch("/rules/{rule_id}", response_model=RuleOut)
def update_rule(rule_id: str, body: RuleUpdate, auth: AuthContext = Depends(current_auth),
                db: Session = Depends(get_db)) -> RuleOut:
    if rule_id not in RULES:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No such rule")
    state = db.get(RuleState, rule_id)
    if state is None:
        state = RuleState(rule_id=rule_id, enabled=body.enabled)
        db.add(state)
    else:
        state.enabled = body.enabled
    audit.record(db, auth.actor, "rule.updated", "rule", rule_id, {"enabled": body.enabled})
    db.commit()
    return next(r for r in list_rules(auth, db) if r.id == rule_id)


# =========================================================================== routes: IOC hashes


@router.get("/iocs", response_model=IocList)
def list_iocs(auth: AuthContext = Depends(current_auth), db: Session = Depends(get_db)) -> IocList:
    rows = db.execute(select(IocHash).order_by(IocHash.added_at.desc(), IocHash.sha256)).scalars().all()
    return IocList(items=[IocOut.model_validate(r) for r in rows], total=len(rows), note=IOC_NOTE)


@router.post("/iocs", response_model=IocImportResult)
def import_iocs(body: list[IocIn], auth: AuthContext = Depends(current_auth),
                db: Session = Depends(get_db)) -> IocImportResult:
    """Import SHA-256 indicators. Sentinel ships no feed; only hashes imported here are ever matched."""
    if len(body) > 10000:
        raise HTTPException(422, "Import at most 10000 hashes at a time")
    added = updated = 0
    seen: set[str] = set()
    for item in body:
        sha = item.sha256.lower()
        if sha in seen:
            continue
        seen.add(sha)
        row = db.get(IocHash, sha)
        if row is None:
            db.add(IocHash(sha256=sha, label=item.label, source=f"imported by {auth.user.username}"))
            added += 1
        elif item.label is not None and item.label != row.label:
            row.label = item.label
            updated += 1
    audit.record(db, auth.actor, "ioc.imported", "ioc", None, {"added": added, "updated": updated})
    db.commit()
    total = db.execute(select(func.count()).select_from(IocHash)).scalar_one()
    return IocImportResult(added=added, updated=updated, total=total, note=IOC_NOTE)


@router.delete("/iocs/{sha256}", status_code=204)
def delete_ioc(sha256: str, auth: AuthContext = Depends(current_auth), db: Session = Depends(get_db)) -> Response:
    if not re.fullmatch(r"[0-9A-Fa-f]{64}", sha256):
        raise HTTPException(422, "Expected a SHA-256 hash (64 hexadecimal characters)")
    row = db.get(IocHash, sha256.lower())
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No such hash")
    db.delete(row)
    audit.record(db, auth.actor, "ioc.deleted", "ioc", sha256.lower())
    db.commit()
    return Response(status_code=204)
