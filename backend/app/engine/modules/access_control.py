"""Cross-role differential access-control checks (A01:2025).

Compares the same endpoint across provisioned role sessions. Status-code-only
conclusions are explicitly rejected: content similarity is the signal, and
results are flagged for manual review.
"""
from __future__ import annotations

from ..base import EndpointContext, FindingDraft, TestModule, VerificationStatus
from ..differential import body_similarity


class RoleDifferentialModule(TestModule):
    id = "access_control.role_differential"
    title = "Authorization differential across roles"
    owasp_category = "A01:2025 — Broken Access Control"
    cwe_ids = ["CWE-285", "CWE-639"]
    safety = "safe"
    min_profile = "standard"

    def applies(self, ctx: EndpointContext) -> bool:
        return ctx.method == "GET" and bool(ctx.other_sessions) and ctx.baseline is not None

    def run(self, client, ctx: EndpointContext) -> list[FindingDraft]:
        drafts = []
        baseline = ctx.baseline
        if baseline.status_code != 200 or len(baseline.response_body or "") < 100:
            return []
        for other in ctx.other_sessions[:2]:
            other_client = other.get("client")
            other_role = other.get("role", "other")
            if other_client is None or other_role == ctx.role:
                continue
            try:
                resp = other_client.get(ctx.url)
            except Exception:
                continue
            sim = body_similarity(baseline.response_body, resp.response_body)
            if resp.status_code == 200 and sim > 0.9:
                drafts.append(FindingDraft(
                    module_id=self.id,
                    title=f"Cross-role access: '{other_role}' session received '{ctx.role}' content",
                    owasp_category=self.owasp_category, cwe_ids=self.cwe_ids,
                    severity="high", confidence="firm",
                    verification_status=VerificationStatus.requires_manual_review.value,
                    role=ctx.role,
                    description=f"Responses for the same endpoint across roles are ~{sim:.0%} similar, indicating possible missing server-side authorization (horizontal or vertical privilege boundary not enforced).",
                    preconditions="Two provisioned test accounts with different roles and isolated test data.",
                    reproduction_steps=[
                        f"1. Request GET {ctx.url} as role '{ctx.role}'.",
                        f"2. Request the same URL as role '{other_role}'.",
                        "3. Compare content: near-identical bodies across roles indicate an authorization boundary gap.",
                    ],
                    impact="Privilege escalation between roles/tenants; unauthorized data access.",
                    root_cause_hypothesis="Authorization enforced by visibility rather than server-side checks.",
                    remediation="Enforce server-side, object-level and role-level authorization on every request; test with cross-role assertions in CI.",
                    references=["https://owasp.org/Top10/A01_2021-Broken_Access_Control/"],
                    evidence={"type": "role_differential", "url": ctx.url,
                              "role_a": ctx.role, "role_b": other_role,
                              "similarity": sim, "status_b": resp.status_code,
                              "requires_manual_review": True},
                    url=ctx.url, method="GET",
                ))
        return drafts