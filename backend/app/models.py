"""Normalized data model for Sentinel DAST.

UUIDs are stored as string(36) and JSON columns are used so the model is portable
between PostgreSQL (production) and SQLite (tests).
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import (JSON, Boolean, DateTime, Float, ForeignKey, Integer,
                        String, Text)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .db import Base


def uid() -> str:
    return str(uuid.uuid4())


def now() -> datetime:
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------- organizations
class Organization(Base):
    __tablename__ = "organizations"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    name: Mapped[str] = mapped_column(String(200), unique=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class User(Base):
    __tablename__ = "users"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(300))
    role: Mapped[str] = mapped_column(String(20), default="viewer")  # admin|analyst|viewer
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


# ---------------------------------------------------------------- applications
class Application(Base):
    __tablename__ = "applications"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    name: Mapped[str] = mapped_column(String(200))
    base_url: Mapped[str] = mapped_column(String(500))
    environment: Mapped[str] = mapped_column(String(20))  # development|qa|uat|staging|production
    description: Mapped[str] = mapped_column(Text, default="")
    allowed_hosts: Mapped[list] = mapped_column(JSON, default=list)  # approved hostname/origin allowlist
    included_paths: Mapped[list] = mapped_column(JSON, default=list)
    excluded_paths: Mapped[list] = mapped_column(JSON, default=list)
    approved_origins: Mapped[list] = mapped_column(JSON, default=list)
    created_by: Mapped[str | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)

    scans: Mapped[list["Scan"]] = relationship(back_populates="application")


class AuthorizationRecord(Base):
    __tablename__ = "authorization_records"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    application_id: Mapped[str] = mapped_column(ForeignKey("applications.id"), index=True)
    authorized_by: Mapped[str] = mapped_column(String(200))  # authorizer name/contact
    authorization_reference: Mapped[str] = mapped_column(String(200), default="")
    confirmation_text: Mapped[str] = mapped_column(Text)  # verbatim authorization statement
    environment_designation: Mapped[str] = mapped_column(String(20))
    created_by: Mapped[str | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


# ---------------------------------------------------------------- scans
class ScanConfig(Base):
    __tablename__ = "scan_configs"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    application_id: Mapped[str] = mapped_column(ForeignKey("applications.id"), index=True)
    profile: Mapped[str] = mapped_column(String(20))  # passive|baseline|standard|comprehensive
    # Authentication configuration (encrypted at rest via crypto.encrypt_secret)
    auth_type: Mapped[str] = mapped_column(String(20), default="anonymous")
    auth_config_encrypted: Mapped[str | None] = mapped_column(Text, nullable=True)
    max_depth: Mapped[int] = mapped_column(Integer, default=3)
    max_urls: Mapped[int] = mapped_column(Integer, default=200)
    max_requests: Mapped[int] = mapped_column(Integer, default=500)
    max_duration_seconds: Mapped[int] = mapped_column(Integer, default=1800)
    rate_limit_rps: Mapped[float] = mapped_column(Float, default=1.0)
    concurrency_limit: Mapped[int] = mapped_column(Integer, default=2)
    allowed_methods: Mapped[list] = mapped_column(JSON, default=lambda: ["GET", "HEAD"])
    render_js: Mapped[bool] = mapped_column(Boolean, default=False)
    openapi_spec: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    sitemap_url: Mapped[str | None] = mapped_column(String(500), nullable=True)
    proxy_url: Mapped[str | None] = mapped_column(String(500), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class Scan(Base):
    __tablename__ = "scans"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    application_id: Mapped[str] = mapped_column(ForeignKey("applications.id"), index=True)
    config_id: Mapped[str] = mapped_column(ForeignKey("scan_configs.id"))
    status: Mapped[str] = mapped_column(String(20), default="pending")
    phase: Mapped[str] = mapped_column(String(30), default="queued")
    parent_scan_id: Mapped[str | None] = mapped_column(String(36), nullable=True)  # retest link
    is_retest: Mapped[bool] = mapped_column(Boolean, default=False)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    requests_sent: Mapped[int] = mapped_column(Integer, default=0)
    endpoints_discovered: Mapped[int] = mapped_column(Integer, default=0)
    tests_run: Mapped[int] = mapped_column(Integer, default=0)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    progress: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)

    application: Mapped[Application] = relationship(back_populates="scans")


class Endpoint(Base):
    __tablename__ = "endpoints"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    application_id: Mapped[str] = mapped_column(ForeignKey("applications.id"), index=True)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id"), index=True)
    url: Mapped[str] = mapped_column(String(1000))
    method: Mapped[str] = mapped_column(String(10), default="GET")
    parameters: Mapped[list] = mapped_column(JSON, default=list)  # [{name, source, type}]
    auth_required: Mapped[bool] = mapped_column(Boolean, default=False)
    observed_role: Mapped[str | None] = mapped_column(String(80), nullable=True)
    content_type: Mapped[str | None] = mapped_column(String(200), nullable=True)
    status_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    technologies: Mapped[list] = mapped_column(JSON, default=list)
    workflow: Mapped[str | None] = mapped_column(String(200), nullable=True)
    discovered_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class HttpExchange(Base):
    __tablename__ = "http_exchanges"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id"), index=True)
    endpoint_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    method: Mapped[str] = mapped_column(String(10))
    url: Mapped[str] = mapped_column(String(1000))
    status_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    request_headers: Mapped[dict] = mapped_column(JSON, default=dict)
    request_body: Mapped[str | None] = mapped_column(Text, nullable=True)
    response_headers: Mapped[dict] = mapped_column(JSON, default=dict)
    response_body: Mapped[str] = mapped_column(Text, default="")
    duration_ms: Mapped[int] = mapped_column(Integer, default=0)
    is_attack_request: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class TestExecution(Base):
    __tablename__ = "test_executions"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id"), index=True)
    module_id: Mapped[str] = mapped_column(String(100))
    endpoint_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    status: Mapped[str] = mapped_column(String(20))  # ran|skipped|failed|inconclusive|finding
    detail: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


# ---------------------------------------------------------------- findings
class Finding(Base):
    __tablename__ = "findings"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    application_id: Mapped[str] = mapped_column(ForeignKey("applications.id"), index=True)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id"), index=True)
    finding_key: Mapped[str] = mapped_column(String(64), index=True)  # dedup key
    title: Mapped[str] = mapped_column(String(300))
    module_id: Mapped[str] = mapped_column(String(100))
    owasp_category: Mapped[str] = mapped_column(String(80))
    cwe_ids: Mapped[list] = mapped_column(JSON, default=list)
    severity: Mapped[str] = mapped_column(String(20))  # critical|high|medium|low|informational
    confidence: Mapped[str] = mapped_column(String(20), default="tentative")
    verification_status: Mapped[str] = mapped_column(String(30), default="suspected")
    url: Mapped[str] = mapped_column(String(1000))
    method: Mapped[str] = mapped_column(String(10), default="GET")
    parameter: Mapped[str | None] = mapped_column(String(200), nullable=True)
    role: Mapped[str | None] = mapped_column(String(80), nullable=True)
    description: Mapped[str] = mapped_column(Text, default="")
    preconditions: Mapped[str] = mapped_column(Text, default="")
    reproduction_steps: Mapped[list] = mapped_column(JSON, default=list)
    impact: Mapped[str] = mapped_column(Text, default="")
    root_cause_hypothesis: Mapped[str] = mapped_column(Text, default="")
    remediation: Mapped[str] = mapped_column(Text, default="")
    references: Mapped[list] = mapped_column(JSON, default=list)
    cvss_vector: Mapped[str | None] = mapped_column(String(100), nullable=True)
    cvss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    status: Mapped[str] = mapped_column(String(30), default="open")  # open|confirmed|fixed|false_positive|risk_accepted
    retest_status: Mapped[str] = mapped_column(String(30), default="not_retested")
    override_rationale: Mapped[str | None] = mapped_column(Text, nullable=True)
    owner_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    ticket_reference: Mapped[str | None] = mapped_column(String(100), nullable=True)
    first_detected: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    last_detected: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class Evidence(Base):
    __tablename__ = "evidence"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    finding_id: Mapped[str] = mapped_column(ForeignKey("findings.id"), index=True)
    kind: Mapped[str] = mapped_column(String(30), default="http_exchange")  # http_exchange|browser|diff
    redacted_request: Mapped[dict] = mapped_column(JSON, default=dict)
    redacted_response: Mapped[dict] = mapped_column(JSON, default=dict)
    notes: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class Report(Base):
    __tablename__ = "reports"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    scan_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    application_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    kind: Mapped[str] = mapped_column(String(20))  # executive|technical|portfolio
    format: Mapped[str] = mapped_column(String(10))  # html|json
    storage_path: Mapped[str] = mapped_column(String(1000))
    generated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class AuditEvent(Base):
    __tablename__ = "audit_events"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    organization_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    user_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    user_email: Mapped[str | None] = mapped_column(String(255), nullable=True)
    action: Mapped[str] = mapped_column(String(100))
    target_type: Mapped[str | None] = mapped_column(String(50), nullable=True)
    target_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    detail: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)