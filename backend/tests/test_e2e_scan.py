"""End-to-end tests: the scanner runs real tests against the isolated demo
target, with scope enforcement, cancellation, retesting and reporting verified."""
from __future__ import annotations

import uuid

import pytest

from .conftest import REDIS_AVAILABLE, scan_config

AUTH_CONF = ("Authorized internal test: this synthetic demo target may be scanned by "
             "the security team for platform evaluation.")


def _register_app(client, headers, demo_server, *, excluded=None):
    r = client.post("/api/applications", headers=headers, json={
        "name": f"E2E-{uuid.uuid4().hex[:8]}", "base_url": demo_server,
        "environment": "development", "description": "",
        "allowed_hosts": [], "included_paths": [], "excluded_paths": excluded or [],
        "approved_origins": [],
        "authorization": {"authorized_by": "Security Lead", "authorization_reference": "TCK-E2E",
                          "confirmation_text": AUTH_CONF}})
    assert r.status_code == 201, r.text
    return r.json()["id"]


def _launch(client, headers, app_id, **cfg_overrides):
    r = client.post(f"/api/scans?application_id={app_id}", headers=headers,
                    json={"config": scan_config(**cfg_overrides),
                          "authorization_confirmation": AUTH_CONF})
    assert r.status_code == 201, r.text
    return r.json()["id"]


def test_full_scan_finds_real_vulnerabilities(client, auth_headers, demo_server, no_enqueue):
    from app.engine.pipeline import run_scan

    app_id = _register_app(client, auth_headers, demo_server)
    scan_id = _launch(client, auth_headers, app_id)
    run_scan(scan_id)

    scan = client.get(f"/api/scans/{scan_id}", headers=auth_headers).json()
    assert scan["status"] == "completed", scan["error_message"]
    assert scan["requests_sent"] > 0
    assert scan["endpoints_discovered"] > 5
    assert scan["tests_run"] > 0

    findings = client.get(f"/api/findings?application_id={app_id}",
                          headers=auth_headers).json()
    titles = " || ".join(f["title"] for f in findings)
    assert len(findings) > 5

    # real detections against the vulnerable demo target
    assert "Missing Content-Security-Policy header" in titles
    assert "Reflected XSS" in titles
    assert "SQL error disclosure" in titles
    assert "Path traversal" in titles and "/etc/passwd" in titles
    assert ".git repository" in titles
    assert ".env configuration file" in titles
    assert "Open redirect" in titles
    assert "Directory listing exposed" in titles
    assert "CORS policy reflects arbitrary origin" in titles

    # findings carry verification status, evidence and OWASP/CWE mapping
    for f in findings:
        assert f["owasp_category"].startswith("A")
        assert f["verification_status"] in ("suspected", "evidence_observed", "validated")
        ev = client.get(f"/api/findings/{f['id']}/evidence", headers=auth_headers).json()
        assert ev["evidence"], f"finding {f['title']} lacks evidence"

    # reflection alone must never be claimed as validated execution
    xss = next(f for f in findings if "Reflected XSS" in f["title"])
    assert xss["verification_status"] in ("evidence_observed", "suspected")

    # secrets are not present in evidence payloads
    body = client.get(f"/api/findings/{xss['id']}/evidence", headers=auth_headers).text
    assert "demo-session-token" not in body

    # reports generated from actual findings
    reports = client.get("/api/reports", headers=auth_headers).json()["reports"]
    assert {r["kind"] for r in reports} >= {"technical", "executive"}
    dl = client.get(f"/api/reports/{reports[0]['id']}/download", headers=auth_headers)
    assert dl.status_code == 200


def test_retest_reconciles_findings(client, auth_headers, demo_server, no_enqueue):
    from app.engine.pipeline import run_scan

    app_id = _register_app(client, auth_headers, demo_server)
    first = _launch(client, auth_headers, app_id, profile="passive")
    run_scan(first)

    count_before = len(client.get(f"/api/findings?application_id={app_id}",
                                  headers=auth_headers).json())

    retest_id = None
    r = client.post(f"/api/scans?application_id={app_id}", headers=auth_headers,
                    json={"config": scan_config(profile="passive", retest_of=first),
                          "authorization_confirmation": AUTH_CONF})
    assert r.status_code == 201
    retest_id = r.json()["id"]
    run_scan(retest_id)

    retest = client.get(f"/api/scans/{retest_id}", headers=auth_headers).json()
    assert retest["endpoints_discovered"] > 0
    endpoints = client.get(f"/api/scans/{retest_id}/endpoints", headers=auth_headers).json()
    assert endpoints["total"] > 0

    # dedup: a second scan of the same target must not duplicate findings
    count_after = len(client.get(f"/api/findings?application_id={app_id}",
                                 headers=auth_headers).json())
    assert count_after == count_before

    # parent findings were reconciled by the retest
    from app.db import SessionLocal
    from app.models import Finding
    db = SessionLocal()
    reproduced = db.query(Finding).filter_by(scan_id=first).all()
    db.close()
    assert reproduced, "expected findings on the first scan"
    assert any(f.retest_status == "reproduced" for f in reproduced)


def test_excluded_paths_are_not_crawled(client, auth_headers, demo_server, no_enqueue):
    from app.engine.pipeline import run_scan

    app_id = _register_app(client, auth_headers, demo_server, excluded=["/admin"])
    scan_id = _launch(client, auth_headers, app_id, profile="passive", max_urls=30)
    run_scan(scan_id)

    scan = client.get(f"/api/scans/{scan_id}", headers=auth_headers).json()
    assert scan["status"] == "completed"
    eps = client.get(f"/api/scans/{scan_id}/endpoints?limit=200",
                     headers=auth_headers).json()["endpoints"]
    assert eps, "expected discovered endpoints"
    assert all("/admin" not in e["url"] for e in eps)


def test_request_budget_stops_scan_gracefully(client, auth_headers, demo_server, no_enqueue):
    from app.engine.pipeline import run_scan

    app_id = _register_app(client, auth_headers, demo_server)
    scan_id = _launch(client, auth_headers, app_id, profile="baseline", max_requests=10)
    run_scan(scan_id)

    scan = client.get(f"/api/scans/{scan_id}", headers=auth_headers).json()
    assert scan["status"] == "completed"  # budget exhaustion is graceful, not failure
    assert scan["requests_sent"] <= 10 + 2  # small recording tolerance


def test_redirect_scope_escape_is_recorded_not_followed(client, auth_headers, demo_server):
    from app.engine.transport import Controls, SafeHttpClient
    from app.scope_guard import ScopePolicy

    policy = ScopePolicy(base_url=demo_server, allowed_hosts=[], allow_private_targets=True)
    client_http = SafeHttpClient(policy, max_requests=5, rate_limit_rps=50,
                                 controls=Controls())
    exchange = client_http.get(f"{demo_server}/profile?next=https://evil.example.test/")
    client_http.close()

    # the attacker redirect is visible as evidence…
    assert exchange.status_code in (301, 302, 303, 307, 308)
    assert "evil.example.test" in exchange.response_headers.get("location", "")
    # …but it was never followed
    assert client_http.requests_sent == 1


@pytest.mark.skipif(not REDIS_AVAILABLE, reason="cancellation requires Redis coordination")
def test_scan_cancellation(client, auth_headers, demo_server, no_enqueue):
    from app.engine.pipeline import run_scan

    app_id = _register_app(client, auth_headers, demo_server)
    scan_id = _launch(client, auth_headers, app_id, profile="baseline")

    r = client.post(f"/api/scans/{scan_id}/cancel", headers=auth_headers)
    assert r.status_code == 200

    run_scan(scan_id)
    scan = client.get(f"/api/scans/{scan_id}", headers=auth_headers).json()
    assert scan["status"] == "cancelled"


def test_dashboard_reflects_persisted_results(client, auth_headers, demo_server, no_enqueue):
    from app.engine.pipeline import run_scan

    app_id = _register_app(client, auth_headers, demo_server)
    scan_id = _launch(client, auth_headers, app_id, profile="passive")
    run_scan(scan_id)

    dash = client.get("/api/dashboard", headers=auth_headers).json()
    assert dash["empty"] is False
    assert dash["applications"] >= 1
    assert dash["scans"]["completed"] >= 1
    assert dash["findings"]["total"] > 0
    assert dash["endpoints"] > 0