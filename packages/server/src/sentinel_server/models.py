"""Database tables for every phase."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    TypeDecorator,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .db import Base


def now() -> datetime:
    return datetime.now(UTC)


class UTCDateTime(TypeDecorator[datetime]):
    """Stores naive UTC (SQLite has no time zones) and always returns aware UTC datetimes."""

    impl = DateTime
    cache_ok = True

    def process_bind_param(self, value: datetime | None, dialect: Any) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None:
            return value
        return value.astimezone(UTC).replace(tzinfo=None)

    def process_result_value(self, value: datetime | None, dialect: Any) -> datetime | None:
        if value is None:
            return None
        return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


# =========================================================================== Phase 1: identity


class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=now)
    last_login_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    failed_logins: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(UTCDateTime)


class UserSession(Base):
    __tablename__ = "sessions"
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    csrf_token: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=now)
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime)
    last_seen_at: Mapped[datetime] = mapped_column(UTCDateTime, default=now)
    user_agent: Mapped[str | None] = mapped_column(String(300))
    user: Mapped[User] = relationship()


class EnrollmentCode(Base):
    __tablename__ = "enrollment_codes"
    id: Mapped[int] = mapped_column(primary_key=True)
    code_hash: Mapped[str] = mapped_column(String(64), unique=True)
    created_by: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=now)
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime)
    used_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    device_id: Mapped[int | None] = mapped_column(ForeignKey("devices.id", ondelete="SET NULL"))


class Device(Base):
    __tablename__ = "devices"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(255))
    hostname: Mapped[str] = mapped_column(String(255))
    os_family: Mapped[str] = mapped_column(String(16))
    os_name: Mapped[str] = mapped_column(String(255))
    os_version: Mapped[str] = mapped_column(String(255))
    os_build: Mapped[str | None] = mapped_column(String(64))
    edition: Mapped[str | None] = mapped_column(String(64))
    arch: Mapped[str] = mapped_column(String(32))
    distro_id: Mapped[str | None] = mapped_column(String(64))
    distro_version: Mapped[str | None] = mapped_column(String(64))
    is_insider_build: Mapped[bool] = mapped_column(Boolean, default=False)
    agent_version: Mapped[str] = mapped_column(String(32))
    agent_elevated: Mapped[bool] = mapped_column(Boolean, default=False)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    enrolled_at: Mapped[datetime] = mapped_column(UTCDateTime, default=now)
    last_seen_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    checks_catalog: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)


# =========================================================================== Phase 1: scans & findings


class Scan(Base):
    __tablename__ = "scans"
    id: Mapped[int] = mapped_column(primary_key=True)
    device_id: Mapped[int] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"), index=True)
    scan_type: Mapped[str] = mapped_column(String(16))
    status: Mapped[str] = mapped_column(String(16), default="queued", index=True)
    data_mode: Mapped[str] = mapped_column(String(16), default="live")
    elevated: Mapped[bool] = mapped_column(Boolean, default=False)
    check_ids: Mapped[list[str] | None] = mapped_column(JSON)
    params: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    requested_by: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    schedule_id: Mapped[int | None] = mapped_column(ForeignKey("schedules.id", ondelete="SET NULL"))
    reason: Mapped[str | None] = mapped_column(String(64))  # manual, scheduled, verify, demo
    requested_at: Mapped[datetime] = mapped_column(UTCDateTime, default=now, index=True)
    claimed_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    lease_expires_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    started_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    completed_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    cancel_requested: Mapped[bool] = mapped_column(Boolean, default=False)
    error: Mapped[str | None] = mapped_column(Text)
    agent_version: Mapped[str | None] = mapped_column(String(32))
    host_snapshot: Mapped[dict[str, Any] | None] = mapped_column(JSON)
    score: Mapped[int | None] = mapped_column(Integer)
    coverage: Mapped[float | None] = mapped_column(Float)
    summary: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    device: Mapped[Device] = relationship()
    check_runs: Mapped[list[CheckRun]] = relationship(back_populates="scan", cascade="all, delete-orphan")


class CheckRun(Base):
    __tablename__ = "check_runs"
    __table_args__ = (UniqueConstraint("scan_id", "check_id"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    check_id: Mapped[str] = mapped_column(String(128), index=True)
    check_version: Mapped[str] = mapped_column(String(16))
    title: Mapped[str] = mapped_column(String(300))
    category: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(16))  # planned + CheckStatus values
    skip_reason: Mapped[str | None] = mapped_column(Text)
    error_message: Mapped[str | None] = mapped_column(Text)
    requires_elevation: Mapped[bool] = mapped_column(Boolean, default=False)
    ran_elevated: Mapped[bool] = mapped_column(Boolean, default=False)
    data_collected: Mapped[str] = mapped_column(Text, default="")
    started_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    finished_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    duration_ms: Mapped[int | None] = mapped_column(Integer)
    finding_count: Mapped[int] = mapped_column(Integer, default=0)
    scan: Mapped[Scan] = relationship(back_populates="check_runs")
    evidence: Mapped[list[EvidenceRecord]] = relationship(back_populates="check_run", cascade="all, delete-orphan")


class EvidenceRecord(Base):
    __tablename__ = "evidence"
    id: Mapped[int] = mapped_column(primary_key=True)
    check_run_id: Mapped[int] = mapped_column(ForeignKey("check_runs.id", ondelete="CASCADE"), index=True)
    position: Mapped[int] = mapped_column(Integer, default=0)
    kind: Mapped[str] = mapped_column(String(64))
    source: Mapped[str] = mapped_column(String(300))
    content: Mapped[Any] = mapped_column(JSON)
    content_sha256: Mapped[str] = mapped_column(String(64))
    size_bytes: Mapped[int] = mapped_column(Integer)
    redacted: Mapped[bool] = mapped_column(Boolean, default=False)
    collected_at: Mapped[datetime] = mapped_column(UTCDateTime)
    check_run: Mapped[CheckRun] = relationship(back_populates="evidence")


class FindingRecord(Base):
    __tablename__ = "findings"
    __table_args__ = (
        UniqueConstraint("device_id", "fingerprint"),
        Index("ix_findings_open", "device_id", "status"),
    )
    id: Mapped[int] = mapped_column(primary_key=True)
    device_id: Mapped[int] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"), index=True)
    fingerprint: Mapped[str] = mapped_column(String(64))
    rule_id: Mapped[str] = mapped_column(String(128), index=True)
    check_id: Mapped[str] = mapped_column(String(128), index=True)
    source: Mapped[str] = mapped_column(String(32), default="agent")  # agent | vuln_matcher
    scope: Mapped[str] = mapped_column(String(255), default="")
    subject_key: Mapped[str] = mapped_column(String(512))
    title: Mapped[str] = mapped_column(String(300))
    category: Mapped[str] = mapped_column(String(64))
    severity: Mapped[str] = mapped_column(String(16), index=True)
    confidence: Mapped[str] = mapped_column(String(16))
    finding_kind: Mapped[str] = mapped_column(String(16))
    status: Mapped[str] = mapped_column(String(16), default="new")
    impact: Mapped[str] = mapped_column(Text)
    remediation: Mapped[str] = mapped_column(Text)
    references: Mapped[list[str]] = mapped_column(JSON, default=list)
    first_seen_scan_id: Mapped[int | None] = mapped_column(ForeignKey("scans.id", ondelete="SET NULL"))
    last_seen_scan_id: Mapped[int | None] = mapped_column(ForeignKey("scans.id", ondelete="SET NULL"))
    first_seen_at: Mapped[datetime] = mapped_column(UTCDateTime, default=now)
    last_seen_at: Mapped[datetime] = mapped_column(UTCDateTime, default=now)
    verified_resolved_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    resolved_by_check_run_id: Mapped[int | None] = mapped_column(ForeignKey("check_runs.id", ondelete="SET NULL"))
    reopened_count: Mapped[int] = mapped_column(Integer, default=0)
    owner: Mapped[str | None] = mapped_column(String(128))
    target_date: Mapped[str | None] = mapped_column(String(10))  # YYYY-MM-DD
    acknowledged_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    notified: Mapped[bool] = mapped_column(Boolean, default=False)
    # vulnerability details (Phase 3)
    vuln_id: Mapped[str | None] = mapped_column(String(64), index=True)
    cve_id: Mapped[str | None] = mapped_column(String(32), index=True)
    cvss_score: Mapped[float | None] = mapped_column(Float)
    cvss_vector: Mapped[str | None] = mapped_column(String(200))
    cvss_source: Mapped[str | None] = mapped_column(String(128))
    epss: Mapped[float | None] = mapped_column(Float)
    kev: Mapped[bool] = mapped_column(Boolean, default=False)
    affected_software: Mapped[str | None] = mapped_column(String(512))
    fixed_version: Mapped[str | None] = mapped_column(String(256))
    device: Mapped[Device] = relationship()


class FindingObservation(Base):
    __tablename__ = "finding_observations"
    id: Mapped[int] = mapped_column(primary_key=True)
    finding_id: Mapped[int] = mapped_column(ForeignKey("findings.id", ondelete="CASCADE"), index=True)
    check_run_id: Mapped[int] = mapped_column(ForeignKey("check_runs.id", ondelete="CASCADE"), index=True)
    evidence_ids: Mapped[list[int]] = mapped_column(JSON, default=list)
    observed_at: Mapped[datetime] = mapped_column(UTCDateTime, default=now)


class FindingEvent(Base):
    __tablename__ = "finding_events"
    id: Mapped[int] = mapped_column(primary_key=True)
    finding_id: Mapped[int] = mapped_column(ForeignKey("findings.id", ondelete="CASCADE"), index=True)
    actor: Mapped[str] = mapped_column(String(64))  # "user:<name>" or "system"
    from_status: Mapped[str | None] = mapped_column(String(16))
    to_status: Mapped[str | None] = mapped_column(String(16))
    note: Mapped[str | None] = mapped_column(Text)
    changes: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=now)


class RemediationTask(Base):
    __tablename__ = "remediation_tasks"
    id: Mapped[int] = mapped_column(primary_key=True)
    finding_id: Mapped[int] = mapped_column(ForeignKey("findings.id", ondelete="CASCADE"), index=True)
    title: Mapped[str] = mapped_column(String(300))
    owner: Mapped[str | None] = mapped_column(String(128))
    due_date: Mapped[str | None] = mapped_column(String(10))
    status: Mapped[str] = mapped_column(String(16), default="open")  # open | done
    notes: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=now)
    completed_at: Mapped[datetime | None] = mapped_column(UTCDateTime)


class MetricSampleRecord(Base):
    __tablename__ = "metric_samples"
    __table_args__ = (Index("ix_metrics_device_metric_ts", "device_id", "metric", "ts"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    device_id: Mapped[int] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"))
    ts: Mapped[datetime] = mapped_column(UTCDateTime)
    metric: Mapped[str] = mapped_column(String(128))
    value: Mapped[float] = mapped_column(Float)


class AuditEntry(Base):
    """Rows are written unsealed (seq NULL, empty hashes) and sealed in commit order right after commit."""

    __tablename__ = "audit_log"
    id: Mapped[int] = mapped_column(primary_key=True)
    seq: Mapped[int | None] = mapped_column(Integer, unique=True)
    ts: Mapped[datetime] = mapped_column(UTCDateTime, default=now, index=True)
    actor: Mapped[str] = mapped_column(String(128))
    action: Mapped[str] = mapped_column(String(64), index=True)
    target_type: Mapped[str | None] = mapped_column(String(64))
    target_id: Mapped[str | None] = mapped_column(String(64))
    detail: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    prev_hash: Mapped[str] = mapped_column(String(64))
    hash: Mapped[str] = mapped_column(String(64))


class AppSetting(Base):
    __tablename__ = "app_settings"
    key: Mapped[str] = mapped_column(String(128), primary_key=True)
    value: Mapped[Any] = mapped_column(JSON)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime, default=now, onupdate=now)


# =========================================================================== Phase 2: logs, detection, schedules


class LogEventRecord(Base):
    __tablename__ = "log_events"
    __table_args__ = (
        UniqueConstraint("device_id", "source", "record_id"),
        Index("ix_log_events_device_time", "device_id", "occurred_at"),
    )
    id: Mapped[int] = mapped_column(primary_key=True)
    device_id: Mapped[int] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"))
    source: Mapped[str] = mapped_column(String(128))
    record_id: Mapped[str] = mapped_column(String(600))
    event_id: Mapped[str | None] = mapped_column(String(32), index=True)
    occurred_at: Mapped[datetime] = mapped_column(UTCDateTime)
    category: Mapped[str] = mapped_column(String(64), index=True)
    action: Mapped[str] = mapped_column(String(64), index=True)
    outcome: Mapped[str | None] = mapped_column(String(16))
    severity: Mapped[str] = mapped_column(String(16), default="info")
    user: Mapped[str | None] = mapped_column(String(256))
    source_ip: Mapped[str | None] = mapped_column(String(64))
    process: Mapped[str | None] = mapped_column(String(1024))
    message: Mapped[str] = mapped_column(Text)
    data: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    ingested_at: Mapped[datetime] = mapped_column(UTCDateTime, default=now)
    scan_id: Mapped[int | None] = mapped_column(ForeignKey("scans.id", ondelete="SET NULL"))


class Incident(Base):
    __tablename__ = "incidents"
    id: Mapped[int] = mapped_column(primary_key=True)
    device_id: Mapped[int] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"), index=True)
    title: Mapped[str] = mapped_column(String(300))
    severity: Mapped[str] = mapped_column(String(16))
    status: Mapped[str] = mapped_column(String(16), default="open")  # open | investigating | closed
    entities: Mapped[list[str]] = mapped_column(JSON, default=list)
    opened_at: Mapped[datetime] = mapped_column(UTCDateTime, default=now)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime, default=now)
    closed_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    summary: Mapped[str | None] = mapped_column(Text)


class Alert(Base):
    __tablename__ = "alerts"
    id: Mapped[int] = mapped_column(primary_key=True)
    device_id: Mapped[int] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"), index=True)
    rule_id: Mapped[str] = mapped_column(String(128), index=True)
    dedupe_key: Mapped[str] = mapped_column(String(128), unique=True)
    title: Mapped[str] = mapped_column(String(300))
    description: Mapped[str] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(String(16), index=True)
    confidence: Mapped[str] = mapped_column(String(16))
    kind: Mapped[str] = mapped_column(String(16))  # heuristic | verified
    status: Mapped[str] = mapped_column(String(24), default="new")  # new|acknowledged|investigating|resolved|false_positive
    entity: Mapped[str | None] = mapped_column(String(256))
    first_event_at: Mapped[datetime] = mapped_column(UTCDateTime)
    last_event_at: Mapped[datetime] = mapped_column(UTCDateTime)
    detected_at: Mapped[datetime] = mapped_column(UTCDateTime, default=now, index=True)
    event_count: Mapped[int] = mapped_column(Integer, default=0)
    evidence: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    investigation_steps: Mapped[list[str]] = mapped_column(JSON, default=list)
    remediation: Mapped[str] = mapped_column(Text, default="")
    incident_id: Mapped[int | None] = mapped_column(ForeignKey("incidents.id", ondelete="SET NULL"), index=True)
    notified: Mapped[bool] = mapped_column(Boolean, default=False)
    notes: Mapped[str | None] = mapped_column(Text)


class AlertEventLink(Base):
    __tablename__ = "alert_events"
    alert_id: Mapped[int] = mapped_column(ForeignKey("alerts.id", ondelete="CASCADE"), primary_key=True)
    log_event_id: Mapped[int] = mapped_column(ForeignKey("log_events.id", ondelete="CASCADE"), primary_key=True)


class RuleState(Base):
    __tablename__ = "rule_states"
    rule_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)


class IocHash(Base):
    __tablename__ = "ioc_hashes"
    sha256: Mapped[str] = mapped_column(String(64), primary_key=True)
    label: Mapped[str | None] = mapped_column(String(255))
    source: Mapped[str] = mapped_column(String(255))
    added_at: Mapped[datetime] = mapped_column(UTCDateTime, default=now)


class Schedule(Base):
    __tablename__ = "schedules"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(128))
    device_id: Mapped[int] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"))
    scan_type: Mapped[str] = mapped_column(String(16))
    frequency: Mapped[str] = mapped_column(String(16))  # hourly | daily | weekly | monthly
    time_of_day: Mapped[str] = mapped_column(String(5), default="09:00")  # HH:MM local
    day_of_week: Mapped[int | None] = mapped_column(Integer)  # 0 = Monday
    day_of_month: Mapped[int | None] = mapped_column(Integer)  # 1..28
    timezone: Mapped[str] = mapped_column(String(64), default="UTC")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    next_run_at: Mapped[datetime | None] = mapped_column(UTCDateTime, index=True)
    last_run_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    last_scan_id: Mapped[int | None] = mapped_column(Integer)
    consecutive_failures: Mapped[int] = mapped_column(Integer, default=0)
    created_by: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=now)


class Notification(Base):
    __tablename__ = "notifications"
    id: Mapped[int] = mapped_column(primary_key=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=now, index=True)
    severity: Mapped[str] = mapped_column(String(16))
    kind: Mapped[str] = mapped_column(String(32))  # finding | alert | scan_failed | schedule_missed | system
    title: Mapped[str] = mapped_column(String(300))
    body: Mapped[str] = mapped_column(Text, default="")
    link: Mapped[str | None] = mapped_column(String(300))
    dedupe_key: Mapped[str | None] = mapped_column(String(160), unique=True)
    read_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    emailed_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    suppressed_reason: Mapped[str | None] = mapped_column(String(64))


# =========================================================================== Phase 3: inventory & vulnerabilities


class SoftwareRecord(Base):
    __tablename__ = "software"
    __table_args__ = (UniqueConstraint("device_id", "ecosystem", "name", "version", "location"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    device_id: Mapped[int] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(512))
    version: Mapped[str | None] = mapped_column(String(256))
    publisher: Mapped[str | None] = mapped_column(String(512))
    ecosystem: Mapped[str] = mapped_column(String(64))
    source: Mapped[str] = mapped_column(String(256))
    location: Mapped[str] = mapped_column(String(1024), default="")
    install_date: Mapped[str | None] = mapped_column(String(32))
    first_seen_at: Mapped[datetime] = mapped_column(UTCDateTime, default=now)
    last_seen_at: Mapped[datetime] = mapped_column(UTCDateTime, default=now)
    last_scan_id: Mapped[int | None] = mapped_column(Integer)
    is_present: Mapped[bool] = mapped_column(Boolean, default=True)
    match_status: Mapped[str] = mapped_column(String(32), default="pending")  # matched|no_source|pending|error
    match_source: Mapped[str | None] = mapped_column(String(32))


class VulnRecord(Base):
    __tablename__ = "vuln_records"
    id: Mapped[int] = mapped_column(primary_key=True)
    vuln_id: Mapped[str] = mapped_column(String(64), unique=True)  # OSV id, CVE id or MSRC id
    source: Mapped[str] = mapped_column(String(16))  # osv | nvd | msrc
    aliases: Mapped[list[str]] = mapped_column(JSON, default=list)
    cve_id: Mapped[str | None] = mapped_column(String(32), index=True)
    summary: Mapped[str | None] = mapped_column(Text)
    details: Mapped[str | None] = mapped_column(Text)
    cvss_score: Mapped[float | None] = mapped_column(Float)
    cvss_vector: Mapped[str | None] = mapped_column(String(200))
    cvss_source: Mapped[str | None] = mapped_column(String(128))
    severity: Mapped[str | None] = mapped_column(String(16))
    published: Mapped[str | None] = mapped_column(String(40))
    modified: Mapped[str | None] = mapped_column(String(40))
    references: Mapped[list[str]] = mapped_column(JSON, default=list)
    nvd_status: Mapped[str | None] = mapped_column(String(64))
    kev: Mapped[bool] = mapped_column(Boolean, default=False)
    kev_date_added: Mapped[str | None] = mapped_column(String(16))
    kev_ransomware: Mapped[str | None] = mapped_column(String(16))
    epss: Mapped[float | None] = mapped_column(Float)
    epss_percentile: Mapped[float | None] = mapped_column(Float)
    raw: Mapped[dict[str, Any] | None] = mapped_column(JSON)
    fetched_at: Mapped[datetime] = mapped_column(UTCDateTime, default=now)


class IntelSync(Base):
    __tablename__ = "intel_sync"
    source: Mapped[str] = mapped_column(String(32), primary_key=True)  # kev | epss | msrc | nvd | osv
    last_synced_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    status: Mapped[str] = mapped_column(String(16), default="never")
    detail: Mapped[str | None] = mapped_column(Text)
    data: Mapped[dict[str, Any] | None] = mapped_column(JSON)


class OutboundRequest(Base):
    __tablename__ = "outbound_requests"
    id: Mapped[int] = mapped_column(primary_key=True)
    ts: Mapped[datetime] = mapped_column(UTCDateTime, default=now, index=True)
    integration: Mapped[str] = mapped_column(String(32), index=True)
    method: Mapped[str] = mapped_column(String(8))
    host: Mapped[str] = mapped_column(String(255))
    path: Mapped[str] = mapped_column(String(1024))  # query string stripped of secrets
    purpose: Mapped[str] = mapped_column(String(300))
    payload_summary: Mapped[str] = mapped_column(Text, default="")
    status_code: Mapped[int | None] = mapped_column(Integer)
    duration_ms: Mapped[int | None] = mapped_column(Integer)
    error: Mapped[str | None] = mapped_column(Text)


# =========================================================================== Phase 4: email exposure


class EmailIdentity(Base):
    __tablename__ = "email_identities"
    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str] = mapped_column(String(320), unique=True)
    label: Mapped[str | None] = mapped_column(String(128))
    ownership_confirmed: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=now)
    last_checked_at: Mapped[datetime | None] = mapped_column(UTCDateTime)


class EmailCheck(Base):
    __tablename__ = "email_checks"
    id: Mapped[int] = mapped_column(primary_key=True)
    identity_id: Mapped[int] = mapped_column(ForeignKey("email_identities.id", ondelete="CASCADE"), index=True)
    checked_at: Mapped[datetime] = mapped_column(UTCDateTime, default=now)
    status: Mapped[str] = mapped_column(String(16))  # found | not_found | unavailable | error
    breach_count: Mapped[int] = mapped_column(Integer, default=0)
    breaches: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    source: Mapped[str] = mapped_column(String(32), default="hibp")
    error: Mapped[str | None] = mapped_column(Text)


class DomainCheck(Base):
    __tablename__ = "domain_checks"
    id: Mapped[int] = mapped_column(primary_key=True)
    domain: Mapped[str] = mapped_column(String(255), index=True)
    checked_at: Mapped[datetime] = mapped_column(UTCDateTime, default=now)
    status: Mapped[str] = mapped_column(String(16))
    result: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    error: Mapped[str | None] = mapped_column(Text)


# =========================================================================== Phase 5: network scope


class ScopeEntry(Base):
    __tablename__ = "scan_scopes"
    id: Mapped[int] = mapped_column(primary_key=True)
    kind: Mapped[str] = mapped_column(String(8))  # cidr | host | url
    value: Mapped[str] = mapped_column(String(512), unique=True)
    note: Mapped[str | None] = mapped_column(String(300))
    is_public: Mapped[bool] = mapped_column(Boolean, default=False)
    authorization: Mapped[str | None] = mapped_column(Text)  # the typed confirmation for public targets
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_by: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=now)


# =========================================================================== Phase 6: assistant & reports


class AssistantConversation(Base):
    __tablename__ = "assistant_conversations"
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    title: Mapped[str] = mapped_column(String(200), default="New conversation")
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=now)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime, default=now)


class AssistantMessage(Base):
    __tablename__ = "assistant_messages"
    id: Mapped[int] = mapped_column(primary_key=True)
    conversation_id: Mapped[int] = mapped_column(
        ForeignKey("assistant_conversations.id", ondelete="CASCADE"), index=True)
    role: Mapped[str] = mapped_column(String(16))  # user | assistant | tool
    content: Mapped[str] = mapped_column(Text)
    tool_calls: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    citations: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    model: Mapped[str | None] = mapped_column(String(128))
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=now)


class Report(Base):
    __tablename__ = "reports"
    id: Mapped[int] = mapped_column(primary_key=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=now)
    created_by: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    kind: Mapped[str] = mapped_column(String(8))  # pdf | csv | json
    title: Mapped[str] = mapped_column(String(200))
    scope: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    file_name: Mapped[str] = mapped_column(String(128))  # generated server-side, never from input
    sha256: Mapped[str] = mapped_column(String(64))
    size_bytes: Mapped[int] = mapped_column(Integer)


# =========================================================================== Threat-intelligence advisory feed


class Advisory(Base):
    """A security news/advisory item (Hacker News, CISA KEV ...) matched against this install's inventory.

    Advisories are information for a person to read. They never become executable code: ``suggested_coverage``
    is plain text for a human to review, and nothing here is ever run.
    """

    __tablename__ = "advisories"
    __table_args__ = (UniqueConstraint("source", "external_id"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    source: Mapped[str] = mapped_column(String(32), index=True)  # hackernews | kev | manual
    external_id: Mapped[str] = mapped_column(String(128))
    title: Mapped[str] = mapped_column(String(500))
    url: Mapped[str | None] = mapped_column(String(1024))
    summary: Mapped[str] = mapped_column(Text, default="")
    author: Mapped[str | None] = mapped_column(String(128))
    score: Mapped[int | None] = mapped_column(Integer)  # HN points, when applicable
    tags: Mapped[list[str]] = mapped_column(JSON, default=list)  # security keywords found
    cve_ids: Mapped[list[str]] = mapped_column(JSON, default=list)
    matched: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    match_detail: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)  # software/finding names it touched
    severity_hint: Mapped[str] = mapped_column(String(16), default="info")
    suggested_coverage: Mapped[str | None] = mapped_column(Text)  # human-reviewed note; NEVER executed
    status: Mapped[str] = mapped_column(String(16), default="new", index=True)  # new|read|pinned|dismissed
    published_at: Mapped[datetime | None] = mapped_column(UTCDateTime, index=True)
    fetched_at: Mapped[datetime] = mapped_column(UTCDateTime, default=now)
    read_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    notified: Mapped[bool] = mapped_column(Boolean, default=False)


# =========================================================================== Field data (uploaded sensor captures)


class FieldCapture(Base):
    """A file of data the user captured with their own equipment (e.g. a passive Wi-Fi survey) and uploaded."""

    __tablename__ = "field_captures"
    id: Mapped[int] = mapped_column(primary_key=True)
    kind: Mapped[str] = mapped_column(String(32), index=True)  # wifi_survey | rf_survey | host_report | generic
    source_label: Mapped[str] = mapped_column(String(128), default="")  # e.g. "Alfa AWUS036ACHM", "Raspberry Pi 5"
    notes: Mapped[str] = mapped_column(Text, default="")
    uploaded_by: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    uploaded_at: Mapped[datetime] = mapped_column(UTCDateTime, default=now, index=True)
    original_format: Mapped[str] = mapped_column(String(32), default="json")  # airodump_csv | json
    sha256: Mapped[str] = mapped_column(String(64))
    size_bytes: Mapped[int] = mapped_column(Integer, default=0)
    record_count: Mapped[int] = mapped_column(Integer, default=0)
    summary: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)


class FieldObservation(Base):
    """One parsed record from a capture (e.g. an access point seen in a Wi-Fi survey)."""

    __tablename__ = "field_observations"
    __table_args__ = (Index("ix_field_obs_capture", "capture_id", "kind"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    capture_id: Mapped[int] = mapped_column(ForeignKey("field_captures.id", ondelete="CASCADE"), index=True)
    kind: Mapped[str] = mapped_column(String(32))  # access_point | rf_signal | host | generic
    key: Mapped[str] = mapped_column(String(256), default="")  # bssid, device id ...
    label: Mapped[str] = mapped_column(String(256), default="")  # ssid, friendly name
    data: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    classification: Mapped[str] = mapped_column(String(24), default="unknown")  # own|known|unknown|rogue_suspect|weak_own
    severity: Mapped[str] = mapped_column(String(16), default="info")
    note: Mapped[str] = mapped_column(Text, default="")
