"""Engine unit tests: dedup, differential analysis, profile gating, passive checks."""
from __future__ import annotations

from app.engine.base import EndpointContext, module_enabled_for_profile
from app.engine.dedup import finding_key, should_upgrade_severity
from app.engine.differential import body_similarity, normalize, responses_differ
from app.engine.modules.active import ACTIVE_MODULES, SQLInjectionModule
from app.engine.passive import run_passive_checks
from app.engine.transport import Exchange


def _exchange(url="https://app.example.com/", body="<html>ok</html>", status=200, headers=None):
    return Exchange(
        method="GET", url=url, status_code=status, request_headers={},
        request_body=None, response_headers=headers or {}, response_body=body,
        duration_ms=5,
    )


def test_dedup_key_stable_across_ids():
    a = finding_key("A05:2025 — Injection", "active.sqli",
                    "https://app.example.com/users/42/profile", "GET", "q")
    b = finding_key("A05:2025 — Injection", "active.sqli",
                    "https://app.example.com/users/43/profile", "GET", "q")
    assert a == b  # same root cause, same resource shape


def test_dedup_key_differs_for_distinct_causes():
    a = finding_key("A05:2025 — Injection", "active.sqli",
                    "https://app.example.com/search", "GET", "q")
    b = finding_key("A05:2025 — Injection", "active.sqli",
                    "https://app.example.com/search", "GET", "page")
    c = finding_key("A01:2025 — Broken Access Control", "active.sqli",
                    "https://app.example.com/search", "GET", "q")
    assert len({a, b, c}) == 3


def test_severity_upgrade_only():
    assert should_upgrade_severity("medium", "high")
    assert not should_upgrade_severity("high", "medium")


def test_similarity_ignores_noise():
    a = "Report generated at 2024-01-01T12:00:00Z token=aaaabbbbccccdddd for user 123"
    b = "Report generated at 2025-06-06T23:59:59Z token=ddddccccbbbbaaaa for user 456"
    assert normalize(a) == normalize(b)
    assert body_similarity(a, b) == 1.0


def test_responses_differ():
    assert not responses_differ(200, "<html>same</html>", 200, "<html>same</html>")
    assert responses_differ(200, "<html>one</html>", 403, "<html>two</html>")
    assert responses_differ(200, "Admin dashboard with widgets", 200, "Access denied")


def test_profile_gating():
    sqli = SQLInjectionModule()
    assert module_enabled_for_profile(sqli, "baseline")
    assert module_enabled_for_profile(sqli, "standard")
    cors = next(m for m in ACTIVE_MODULES if m.id == "active.cors_reflection")
    assert not module_enabled_for_profile(cors, "baseline")  # standard only
    assert module_enabled_for_profile(cors, "standard")


def test_passive_findings_on_unhardened_response():
    exchange = _exchange(headers={"server": "nginx/1.19", "x-powered-by": "Express"})
    ctx = EndpointContext(url="https://app.example.com/")
    drafts = run_passive_checks(exchange, ctx)
    module_ids = {d.module_id for d in drafts}
    assert "passive.csp_missing" in module_ids
    assert "passive.xcto_missing" in module_ids
    assert "passive.server_disclosure" in module_ids
    assert all(d.severity in ("medium", "low", "informational") for d in drafts)


def test_passive_no_findings_on_hardened_response():
    headers = {
        "content-security-policy": "default-src 'self'",
        "x-content-type-options": "nosniff",
        "x-frame-options": "DENY",
    }
    exchange = _exchange(headers=headers)
    drafts = run_passive_checks(exchange, EndpointContext(url="http://app.example.com/"))
    # HTTP target: HSTS/mixed-content checks are skipped; nothing should fire here
    assert drafts == []
