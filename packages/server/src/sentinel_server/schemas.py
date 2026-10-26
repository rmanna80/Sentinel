"""API request and response models for the Phase 1 surface (users, devices, scans, findings)."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Generic, Literal, TypeVar

from pydantic import BaseModel, ConfigDict, Field

T = TypeVar("T")


class Page(BaseModel, Generic[T]):
    items: list[T]
    total: int


class ORM(BaseModel):
    model_config = ConfigDict(from_attributes=True)


# --------------------------------------------------------------------------- auth


class AuthState(BaseModel):
    needs_setup: bool
    signed_in: bool
    username: str | None = None
    csrf_token: str | None = None
    mode: str


class SetupRequest(BaseModel):
    setup_token: str = Field(min_length=8, max_length=128)
    username: str = Field(min_length=3, max_length=64, pattern=r"^[A-Za-z0-9_.\-]+$")
    password: str = Field(min_length=1, max_length=256)


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)


class ChangePasswordRequest(BaseModel):
    current_password: str = Field(max_length=256)
    new_password: str = Field(max_length=256)


# --------------------------------------------------------------------------- devices


class DeviceOut(ORM):
    id: int
    name: str
    hostname: str
    os_family: str
    os_name: str
    os_version: str
    os_build: str | None
    edition: str | None
    arch: str
    distro_id: str | None
    distro_version: str | None
    is_insider_build: bool
    agent_version: str
    agent_elevated: bool
    enrolled_at: datetime
    last_seen_at: datetime | None
    is_active: bool


class DeviceSummary(DeviceOut):
    online: bool
    score: int | None
    raw_score: int
    coverage: float | None
    incomplete: bool
    open_findings: int
    threat_level: str
    counts: dict[str, int]
    latest_metrics: dict[str, float]


class DeviceUpdate(BaseModel):
    name: str = Field(min_length=1, max_length=255)


class EnrollmentCodeOut(BaseModel):
    code: str
    expires_at: datetime
    command: str


# --------------------------------------------------------------------------- scans


ScanTypeLit = Literal["full", "posture", "inventory", "logs", "network", "malware", "custom"]


class ScanCreate(BaseModel):
    device_id: int
    scan_type: ScanTypeLit = "full"
    check_ids: list[str] | None = Field(default=None, max_length=200)
    params: dict[str, dict[str, Any]] = Field(default_factory=dict)
    elevated: bool = False


class CheckRunOut(ORM):
    id: int
    check_id: str
    check_version: str
    title: str
    category: str
    status: str
    skip_reason: str | None
    error_message: str | None
    requires_elevation: bool
    ran_elevated: bool
    data_collected: str
    started_at: datetime | None
    finished_at: datetime | None
    duration_ms: int | None
    finding_count: int


class ScanOut(ORM):
    id: int
    device_id: int
    scan_type: str
    status: str
    data_mode: str
    elevated: bool
    reason: str | None
    requested_at: datetime
    started_at: datetime | None
    completed_at: datetime | None
    cancel_requested: bool
    error: str | None
    score: int | None
    coverage: float | None
    summary: dict[str, Any]
    check_ids: list[str] | None


class ScanDetail(ScanOut):
    check_runs: list[CheckRunOut]
    host_snapshot: dict[str, Any] | None
    progress: dict[str, int]


class ScanDiff(BaseModel):
    base_scan_id: int
    scan_id: int
    new: list[FindingOut]
    resolved: list[FindingOut]
    unchanged: list[FindingOut]


class CheckCatalogEntry(BaseModel):
    id: str
    version: str
    title: str
    category: str
    platforms: list[str]
    profiles: list[str]
    requires_elevation: bool
    data_collected: str
    params_schema: dict[str, Any] | None = None
    device_ids: list[int]


# --------------------------------------------------------------------------- findings


class FindingOut(ORM):
    id: int
    device_id: int
    rule_id: str
    check_id: str
    source: str
    scope: str
    subject_key: str
    title: str
    category: str
    severity: str
    confidence: str
    finding_kind: str
    status: str
    impact: str
    remediation: str
    references: list[str]
    first_seen_at: datetime
    last_seen_at: datetime
    first_seen_scan_id: int | None
    last_seen_scan_id: int | None
    verified_resolved_at: datetime | None
    reopened_count: int
    owner: str | None
    target_date: str | None
    vuln_id: str | None
    cve_id: str | None
    cvss_score: float | None
    cvss_vector: str | None
    cvss_source: str | None
    epss: float | None
    kev: bool
    affected_software: str | None
    fixed_version: str | None


class EvidenceOut(ORM):
    id: int
    check_run_id: int
    kind: str
    source: str
    content: Any
    content_sha256: str
    size_bytes: int
    redacted: bool
    collected_at: datetime


class FindingEventOut(ORM):
    id: int
    actor: str
    from_status: str | None
    to_status: str | None
    note: str | None
    changes: dict[str, Any]
    created_at: datetime


class ObservationOut(BaseModel):
    scan_id: int
    check_run_id: int
    observed_at: datetime
    evidence: list[EvidenceOut]


class TaskOut(ORM):
    id: int
    finding_id: int
    title: str
    owner: str | None
    due_date: str | None
    status: str
    notes: str | None
    created_at: datetime
    completed_at: datetime | None


class FindingDetail(FindingOut):
    device_name: str
    events: list[FindingEventOut]
    observations: list[ObservationOut]
    tasks: list[TaskOut]
    allowed_statuses: list[str]


class FindingUpdate(BaseModel):
    status: Literal["new", "confirmed", "in_progress", "accepted_risk", "resolved", "reopened"] | None = None
    note: str | None = Field(default=None, max_length=4000)
    owner: str | None = Field(default=None, max_length=128)
    target_date: str | None = Field(default=None, pattern=r"^\d{4}-\d{2}-\d{2}$")


class TaskCreate(BaseModel):
    title: str = Field(min_length=1, max_length=300)
    owner: str | None = Field(default=None, max_length=128)
    due_date: str | None = Field(default=None, pattern=r"^\d{4}-\d{2}-\d{2}$")
    notes: str | None = Field(default=None, max_length=4000)


class TaskUpdate(BaseModel):
    title: str | None = Field(default=None, min_length=1, max_length=300)
    owner: str | None = Field(default=None, max_length=128)
    due_date: str | None = Field(default=None, pattern=r"^\d{4}-\d{2}-\d{2}$")
    status: Literal["open", "done"] | None = None
    notes: str | None = Field(default=None, max_length=4000)


# --------------------------------------------------------------------------- dashboard & misc


class MetricPoint(BaseModel):
    ts: datetime
    value: float


class MetricSeries(BaseModel):
    metric: str
    points: list[MetricPoint]


class AuditOut(ORM):
    id: int
    ts: datetime
    actor: str
    action: str
    target_type: str | None
    target_id: str | None
    detail: dict[str, Any]
    hash: str


class AuditVerify(BaseModel):
    intact: bool
    first_bad_id: int | None
    entries: int


ScanDiff.model_rebuild()
