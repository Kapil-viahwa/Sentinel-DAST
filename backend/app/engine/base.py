"""Plugin framework for test modules.

Each module declares its identifier, OWASP Top 10:2025 category, CWE mappings,
safety level, minimum scan profile, applicability rules and its run() logic.
Modules must be non-destructive: destructive payload classes are intentionally
absent from this framework.
"""
from __future__ import annotations

import abc
from dataclasses import dataclass, field
from enum import Enum

from .transport import Exchange, SafeHttpClient


class Severity(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    informational = "informational"


SEVERITY_RANK = {s.value: i for i, s in enumerate(Severity)}


class VerificationStatus(str, Enum):
    suspected = "suspected"
    evidence_observed = "evidence_observed"
    validated = "validated"
    inconclusive = "inconclusive"
    false_positive = "false_positive"
    requires_manual_review = "requires_manual_review"


PROFILES = {"passive": 0, "baseline": 1, "standard": 2, "comprehensive": 3}
SAFETY_LEVELS = {"passive": 0, "safe": 1, "moderate": 2, "high": 3}


@dataclass
class FindingDraft:
    module_id: str
    title: str
    owasp_category: str
    cwe_ids: list = field(default_factory=list)
    severity: str = "medium"
    confidence: str = "tentative"  # certain|firm|tentative
    verification_status: str = VerificationStatus.suspected.value
    url: str = ""
    method: str = "GET"
    parameter: str | None = None
    role: str | None = None
    description: str = ""
    preconditions: str = ""
    reproduction_steps: list = field(default_factory=list)
    impact: str = ""
    root_cause_hypothesis: str = ""
    remediation: str = ""
    references: list = field(default_factory=list)
    cvss_vector: str | None = None
    cvss_score: float | None = None
    evidence: dict = field(default_factory=dict)


@dataclass
class EndpointContext:
    url: str
    method: str = "GET"
    parameters: list = field(default_factory=list)  # [{name, source, type}]
    content_type: str | None = None
    has_session: bool = False
    role: str | None = None
    technologies: list = field(default_factory=list)
    baseline: Exchange | None = None
    other_sessions: list = field(default_factory=list)  # [{role, client}] for differential modules
    auth_probe_url: str | None = None
    policy: object | None = None   # ScopePolicy, for modules that need auxiliary clients
    controls: object | None = None  # runtime Controls

    @property
    def query_params(self) -> list[str]:
        return [p["name"] for p in self.parameters if p.get("source") == "query"]


class TestModule(abc.ABC):
    id: str = "module"
    title: str = "Module"
    owasp_category: str = "A00:2025 — Uncategorized"
    cwe_ids: list = []
    safety: str = "safe"  # passive|safe|moderate|high
    min_profile: str = "baseline"
    supported_methods: tuple = ("GET",)

    def applies(self, ctx: EndpointContext) -> bool:  # noqa: B027
        return True

    @abc.abstractmethod
    def run(self, client: SafeHttpClient, ctx: EndpointContext) -> list[FindingDraft]:
        ...


def module_enabled_for_profile(module: TestModule, profile: str) -> bool:
    return SAFETY_LEVELS[module.safety] <= SAFETY_LEVELS[
        {"passive": "passive", "baseline": "safe", "standard": "moderate", "comprehensive": "high"}[profile]
    ] and PROFILES[profile] >= PROFILES[module.min_profile]