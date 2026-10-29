"""Pydantic API schemas (requests and responses)."""
from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field, field_validator

VALID_ENVIRONMENTS = {"development", "qa", "uat", "staging", "production"}
VALID_PROFILES = {"passive", "baseline", "standard", "comprehensive"}
VALID_AUTH_TYPES = {"anonymous", "form", "cookie", "bearer"}
VALID_SCAN_METHODS = {"GET", "HEAD", "POST", "PUT", "PATCH", "OPTIONS"}


class RegisterIn(BaseModel):
    email: str = Field(..., max_length=255)
    password: str = Field(..., min_length=10, max_length=200)
    organization_name: str = Field(..., max_length=200)
    # The first user in a new organization becomes its admin.
    @field_validator("password")
    @classmethod
    def strong_password(cls, v: str) -> str:
        if v.lower() in ("password", "12345678", "qwertyuiop") or len(set(v)) < 4:
            raise ValueError("Password too weak")
        return v


class LoginIn(BaseModel):
    email: str
    password: str


class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"
    role: str
    organization_id: str


class UserOut(BaseModel):
    id: str
    email: str
    role: str
    organization_id: str
    model_config = {"from_attributes": True}


class ApplicationIn(BaseModel):
    name: str = Field(..., max_length=200)
    base_url: str = Field(..., max_length=500)
    environment: str
    description: str = ""
    allowed_hosts: list[str] = []
    included_paths: list[str] = []
    excluded_paths: list[str] = []
    approved_origins: list[str] = []
    authorization: "AuthorizationIn"

    @field_validator("environment")
    @classmethod
    def env_valid(cls, v: str) -> str:
        if v not in VALID_ENVIRONMENTS:
            raise ValueError(f"environment must be one of {sorted(VALID_ENVIRONMENTS)}")
        return v


class AuthorizationIn(BaseModel):
    authorized_by: str = Field(..., max_length=200)
    authorization_reference: str = ""
    confirmation_text: str = Field(..., min_length=20)


class ApplicationOut(BaseModel):
    id: str
    name: str
    base_url: str
    environment: str
    description: str
    allowed_hosts: list
    included_paths: list
    excluded_paths: list
    approved_origins: list
    created_at: datetime
    model_config = {"from_attributes": True}


class ScanConfigIn(BaseModel):
    profile: str
    auth_type: str = "anonymous"
    auth_config: dict | None = None  # encrypted at rest, never logged
    max_depth: int = 3
    max_urls: int = 200
    max_requests: int = 500
    max_duration_seconds: int = 1800
    rate_limit_rps: float = 1.0
    concurrency_limit: int = 2
    allowed_methods: list[str] = ["GET", "HEAD"]
    render_js: bool = False
    openapi_spec: dict | None = None
    sitemap_url: str | None = None
    proxy_url: str | None = None

    @field_validator("profile")
    @classmethod
    def profile_valid(cls, v: str) -> str:
        if v not in VALID_PROFILES:
            raise ValueError(f"profile must be one of {sorted(VALID_PROFILES)}")
        return v

    @field_validator("auth_type")
    @classmethod
    def auth_valid(cls, v: str) -> str:
        if v not in VALID_AUTH_TYPES:
            raise ValueError(f"auth_type must be one of {sorted(VALID_AUTH_TYPES)}")
        return v


class ScanCreateIn(BaseModel):
    config: ScanConfigIn
    authorization_confirmation: str  # must match the stored authorization statement
    retest_of: str | None = None


class ScanOut(BaseModel):
    id: str
    application_id: str
    config_id: str
    status: str
    phase: str
    is_retest: bool
    parent_scan_id: str | None
    requests_sent: int
    endpoints_discovered: int
    tests_run: int
    error_message: str | None
    progress: dict
    started_at: datetime | None
    finished_at: datetime | None
    created_at: datetime
    model_config = {"from_attributes": True}


class FindingOut(BaseModel):
    id: str
    application_id: str
    scan_id: str
    title: str
    module_id: str
    owasp_category: str
    cwe_ids: list
    severity: str
    confidence: str
    verification_status: str
    url: str
    method: str
    parameter: str | None
    role: str | None
    description: str
    preconditions: str
    reproduction_steps: list
    impact: str
    root_cause_hypothesis: str
    remediation: str
    references: list
    cvss_vector: str | None
    cvss_score: float | None
    status: str
    retest_status: str
    override_rationale: str | None
    ticket_reference: str | None
    first_detected: datetime
    last_detected: datetime
    model_config = {"from_attributes": True}


class FindingUpdateIn(BaseModel):
    status: str | None = None
    severity: str | None = None
    verification_status: str | None = None
    override_rationale: str = Field(..., min_length=10)  # mandatory rationale for overrides
    ticket_reference: str | None = None
    owner_id: str | None = None


class ReportRequestIn(BaseModel):
    kind: str = "technical"  # executive|technical|portfolio
    format: str = "html"  # html|json
    scan_id: str | None = None
    application_id: str | None = None


ApplicationIn.model_rebuild()