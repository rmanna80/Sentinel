"""Operating-system telemetry events and the detections correlated from them.

These models are the contract for Sentinel X, the behavioural-detection layer. An endpoint collector
(Event Tracing for Windows today) produces a stream of :class:`TelemetryEvent`; the detection engine in
``sentinel_detect`` correlates that stream and emits :class:`Detection` objects. Only detections — with the
handful of events that triggered them carried along as evidence — are shipped to the server. The raw event
firehose never leaves the endpoint.

A :class:`TelemetryEvent` is deliberately a single flat model with one ``kind`` discriminator and a wide set
of mostly-optional fields, rather than a class per event type. It mirrors the existing :class:`LogEvent`: it
serialises trivially, survives a new collector adding a field, and is cheap to store. ``details`` is the
escape hatch for anything a specific collector wants to carry that has no first-class field yet.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

from .models import Confidence, FindingKind, Severity

# --------------------------------------------------------------------------- events


class EventKind(StrEnum):
    PROCESS_CREATE = "process_create"
    PROCESS_EXIT = "process_exit"
    NETWORK_CONNECT = "network_connect"
    FILE_WRITE = "file_write"
    FILE_DELETE = "file_delete"
    REGISTRY_SET = "registry_set"
    IMAGE_LOAD = "image_load"


# A process is identified by its GUID, not its PID. Windows reuses PIDs within seconds; a GUID (the agent's
# boot id + PID + creation time, Sysmon-style) is unique for the life of the machine. Every correlation keys
# off the GUID so that a short-lived malicious process can never be confused with whatever reuses its PID.
class TelemetryEvent(BaseModel):
    kind: EventKind
    ts: datetime  # when the event occurred, from the collector; the engine's only clock
    host: str = Field(max_length=256)
    seq: int = Field(ge=0)  # monotonic within one stream; orders events that share a timestamp

    # the process that performed the action (for process_create, the process that was created)
    pid: int = Field(ge=0)
    process_guid: str = Field(min_length=1, max_length=128)
    image: str = Field(default="", max_length=1024)  # full path of the acting process's executable
    user: str | None = Field(default=None, max_length=256)

    # process_create / process_exit
    command_line: str | None = Field(default=None, max_length=8192)
    parent_pid: int | None = Field(default=None, ge=0)
    parent_guid: str | None = Field(default=None, max_length=128)
    parent_image: str | None = Field(default=None, max_length=1024)
    exit_code: int | None = None

    # network_connect
    dest_ip: str | None = Field(default=None, max_length=64)
    dest_port: int | None = Field(default=None, ge=0, le=65535)
    protocol: str | None = Field(default=None, max_length=8)  # tcp | udp
    direction: str | None = Field(default=None, max_length=8)  # outbound | inbound

    # file_write / file_delete / image_load
    file_path: str | None = Field(default=None, max_length=1024)

    # registry_set
    registry_path: str | None = Field(default=None, max_length=1024)  # full key path
    registry_value: str | None = Field(default=None, max_length=256)  # value name within the key

    details: dict[str, Any] = Field(default_factory=dict)  # collector extras: hashes, new value data, ...


# --------------------------------------------------------------------------- detections


class ProcessSnapshot(BaseModel):
    """A point-in-time view of one process, used to carry a detection's process-tree context."""

    process_guid: str = Field(max_length=128)
    pid: int = Field(ge=0)
    image: str = Field(default="", max_length=1024)
    command_line: str | None = Field(default=None, max_length=8192)
    user: str | None = Field(default=None, max_length=256)
    parent_guid: str | None = Field(default=None, max_length=128)


class Detection(BaseModel):
    """A behaviour the engine concluded is worth investigating, with the evidence that led to it.

    A detection is a conclusion, not an alarm bell on a single event: the ``events`` list holds the actual
    telemetry that triggered it and ``process_tree`` the ancestry that puts it in context, so the reasoning
    can always be re-examined. Nothing here is ever executed; remediation, if any, is for a human to decide.
    """

    rule_id: str = Field(pattern=r"^[a-z0-9_.\-]+$", max_length=128)
    title: str = Field(max_length=300)
    summary: str = Field(max_length=1000)  # the one-line "what happened"
    explanation: str = Field(max_length=8000)  # the narrative: why this sequence merits investigation
    severity: Severity
    confidence: Confidence
    kind: FindingKind = FindingKind.HEURISTIC
    technique_ids: list[str] = Field(default_factory=list, max_length=20)  # MITRE ATT&CK, e.g. "T1059.001"
    technique_names: list[str] = Field(default_factory=list, max_length=20)
    host: str = Field(max_length=256)
    first_ts: datetime  # earliest triggering event
    last_ts: datetime  # latest triggering event (when the detection fired)
    dedup_key: str = Field(max_length=512)  # stable across repeats of the same behaviour, for throttling
    process_guids: list[str] = Field(default_factory=list, max_length=50)
    events: list[TelemetryEvent] = Field(default_factory=list)  # verbatim evidence
    process_tree: list[ProcessSnapshot] = Field(default_factory=list)  # ancestry context
