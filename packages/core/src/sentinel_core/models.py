"""Pydantic models shared by the agent and the server."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

# --------------------------------------------------------------------------- enums


class Platform(StrEnum):
    WINDOWS = "windows"
    LINUX = "linux"
    MACOS = "macos"


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


SEVERITY_RANK: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class Confidence(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class FindingKind(StrEnum):
    VERIFIED = "verified"  # directly observed state, e.g. a firewall profile reported as off
    HEURISTIC = "heuristic"  # suspicious, not proof of a problem
    INFORMATIONAL = "informational"  # context only, never deducts from the score


class CheckStatus(StrEnum):
    PASSED = "passed"
    FAILED = "failed"
    SKIPPED = "skipped"
    NOT_APPLICABLE = "not_applicable"
    ERROR = "error"
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"


COMPLETED_CHECK_STATUSES = frozenset({CheckStatus.PASSED, CheckStatus.FAILED})


class PlanStatus(StrEnum):
    PLANNED = "planned"
    SKIPPED = "skipped"
    NOT_APPLICABLE = "not_applicable"


class ScanStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    PARTIAL = "partial"
    FAILED = "failed"
    CANCELLED = "cancelled"


class DataMode(StrEnum):
    LIVE = "live"
    FIXTURE = "fixture"


class FindingStatus(StrEnum):
    NEW = "new"
    CONFIRMED = "confirmed"
    IN_PROGRESS = "in_progress"
    ACCEPTED_RISK = "accepted_risk"
    RESOLVED = "resolved"  # only ever set by a passing re-run, never by a user
    REOPENED = "reopened"


OPEN_FINDING_STATUSES = frozenset(
    {
        FindingStatus.NEW,
        FindingStatus.CONFIRMED,
        FindingStatus.IN_PROGRESS,
        FindingStatus.ACCEPTED_RISK,
        FindingStatus.REOPENED,
    }
)


class ScanType(StrEnum):
    FULL = "full"  # posture + inventory + logs
    POSTURE = "posture"
    INVENTORY = "inventory"
    LOGS = "logs"
    NETWORK = "network"  # needs targets; never part of a full scan
    MALWARE = "malware"  # needs configured paths; never part of a full scan
    CUSTOM = "custom"  # explicit check ids


SCAN_TYPE_PROFILES: dict[ScanType, frozenset[str]] = {
    ScanType.FULL: frozenset({"posture", "inventory", "logs"}),
    ScanType.POSTURE: frozenset({"posture"}),
    ScanType.INVENTORY: frozenset({"inventory"}),
    ScanType.LOGS: frozenset({"logs"}),
    ScanType.NETWORK: frozenset({"network"}),
    ScanType.MALWARE: frozenset({"malware"}),
    ScanType.CUSTOM: frozenset(),
}


def utcnow() -> datetime:
    return datetime.now(UTC)


# --------------------------------------------------------------------------- check output


class Evidence(BaseModel):
    """What a check actually observed. Stored verbatim (after redaction) as proof."""

    kind: str = Field(max_length=64)  # "command_output", "registry_value", "metric", "file_metadata"
    source: str = Field(max_length=300)  # the command, registry path or API that produced it
    content: Any
    collected_at: datetime


class Finding(BaseModel):
    rule_id: str = Field(pattern=r"^[a-z0-9_.\-]+$", max_length=128)
    subject_key: str = Field(min_length=1, max_length=512)  # feeds the fingerprint
    title: str = Field(max_length=300)
    severity: Severity
    confidence: Confidence
    kind: FindingKind
    impact: str = Field(max_length=4000)
    remediation: str = Field(max_length=8000)  # explained to the user, never executed
    references: list[str] = Field(default_factory=list, max_length=50)
    evidence_refs: list[int] = Field(default_factory=list)
    category: str | None = None  # overrides the check category when set
    # vulnerability fields, filled by the server-side matcher
    vuln_id: str | None = None
    cve_id: str | None = None
    cvss_score: float | None = None
    cvss_vector: str | None = None
    cvss_source: str | None = None
    affected_software: str | None = None
    fixed_version: str | None = None


class LogEvent(BaseModel):
    """A normalized operating-system or application log event."""

    source: str = Field(max_length=128)  # "windows:Security", "linux:journal"
    record_id: str = Field(max_length=600)  # channel record id or journal cursor
    event_id: str | None = Field(default=None, max_length=32)
    occurred_at: datetime
    category: str = Field(max_length=64)  # authentication, account_management, service, audit, malware ...
    action: str = Field(max_length=64)  # logon_failed, logon_success, user_created, log_cleared ...
    outcome: str | None = Field(default=None, max_length=16)  # success | failure
    severity: Severity = Severity.INFO
    user: str | None = Field(default=None, max_length=256)
    source_ip: str | None = Field(default=None, max_length=64)
    process: str | None = Field(default=None, max_length=1024)
    message: str = Field(max_length=2000)
    data: dict[str, Any] = Field(default_factory=dict)


class SoftwareItem(BaseModel):
    name: str = Field(max_length=512)
    version: str | None = Field(default=None, max_length=256)
    publisher: str | None = Field(default=None, max_length=512)
    # "windows-registry", "Debian:12", "Ubuntu:24.04:LTS", "PyPI", "npm", "os"
    ecosystem: str = Field(max_length=64)
    source: str = Field(max_length=256)  # where it was read from
    location: str | None = Field(default=None, max_length=1024)  # project path for dependencies
    install_date: str | None = Field(default=None, max_length=32)


class MetricSample(BaseModel):
    metric: str = Field(max_length=64)
    value: float
    ts: datetime


class CheckOutput(BaseModel):
    evidence: list[Evidence] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    events: list[LogEvent] = Field(default_factory=list)
    software: list[SoftwareItem] = Field(default_factory=list)
    metrics: list[MetricSample] = Field(default_factory=list)
    # Findings are reconciled (resolved when absent) only within this scope, e.g. one network target.
    reconcile_scope: str = ""


# --------------------------------------------------------------------------- agent <-> server


class HostInfo(BaseModel):
    hostname: str
    os_family: Platform
    os_name: str
    os_version: str
    os_build: str | None = None
    edition: str | None = None  # "Home", "Pro", "Enterprise" on Windows
    arch: str
    agent_version: str
    is_elevated: bool = False
    distro_id: str | None = None  # Linux: "debian", "ubuntu", "raspbian"
    distro_version: str | None = None  # Linux: "12", "24.04"
    is_insider_build: bool = False


class CheckDescriptor(BaseModel):
    id: str
    version: str
    title: str
    category: str
    platforms: list[Platform]
    profiles: list[str]
    requires_elevation: bool
    timeout_seconds: float
    data_collected: str
    params_schema: dict[str, Any] | None = None


class PlannedCheck(BaseModel):
    check_id: str
    check_version: str
    title: str
    category: str
    status: PlanStatus
    reason: str | None = None
    data_collected: str
    requires_elevation: bool


class ScanPlan(BaseModel):
    host: HostInfo
    checks: list[PlannedCheck]
    data_mode: DataMode = DataMode.LIVE  # fixture when the agent answers from a fixture file (demo mode)


class CheckRunResult(BaseModel):
    model_config = ConfigDict(use_enum_values=False)

    check_id: str
    check_version: str
    status: CheckStatus
    skip_reason: str | None = None
    error_message: str | None = None
    started_at: datetime
    finished_at: datetime
    duration_ms: int
    ran_elevated: bool
    output: CheckOutput | None = None


class AgentJob(BaseModel):
    scan_id: int
    scan_type: ScanType
    check_ids: list[str] | None = None  # None: every applicable check for the scan type
    params: dict[str, dict[str, Any]] = Field(default_factory=dict)  # per check id
    data_mode: DataMode = DataMode.LIVE


class HeartbeatResponse(BaseModel):
    cancel: bool = False


class EnrollRequest(BaseModel):
    code: str = Field(min_length=6, max_length=64)
    host: HostInfo


class EnrollResponse(BaseModel):
    device_id: int
    device_token: str


class AgentHello(BaseModel):
    host: HostInfo
    checks: list[CheckDescriptor]


class ScanCompletion(BaseModel):
    status: ScanStatus
    error: str | None = None
