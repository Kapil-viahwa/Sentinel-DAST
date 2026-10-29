"""API boundary tests: auth, tenant isolation, scan authorization, roles."""
from __future__ import annotations

import uuid

import pytest

from .conftest import REDIS_AVAILABLE, scan_config


def test_register_login_me(client):
    email = f"user-{uuid.uuid4().hex[:8]}@example.test"
    r = client.post("/api/auth/register", json={
        "email": email, "password": "correct-horse-battery",
        "organization_name": f"Org-{uuid.uuid4().hex[:8]}"})
    assert r.status_code == 201
    r = client.post("/api/auth/login", json={"email": email, "password": "correct-horse-battery"})
    assert r.status_code == 200
    token = r.json()["access_token"]
    r = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200
    assert r.json()["role"] == "admin"  # first user of an org is its admin


def test_endpoints_require_authentication(client):
    assert client.get("/api/applications").status_code == 401
    assert client.get("/api/findings").status_code == 401
    assert client.get("/api/dashboard").status_code == 401


def test_weak_password_rejected(client):
    r = client.post("/api/auth/register", json={
        "email": f"x-{uuid.uuid4().hex[:6]}@example.test", "password": "aaaaaaaaaa",
        "organization_name": f"Org-{uuid.uuid4().hex[:6]}"})
    assert r.status_code == 422  # too few distinct characters


def test_tenant_isolation(client, auth_headers, demo_server):
    conf = "Authorized internal test: this synthetic demo target may be scanned by the security team."
    r = client.post("/api/applications", headers=auth_headers, json={
        "name": "Tenant A App", "base_url": demo_server, "environment": "qa",
        "description": "", "allowed_hosts": [], "included_paths": [], "excluded_paths": [],
        "approved_origins": [],
        "authorization": {"authorized_by": "Security Lead", "authorization_reference": "TCK-1",
                          "confirmation_text": conf}})
    assert r.status_code == 201
    app_id = r.json()["id"]

    # a second organization sees neither the app nor any of its data
    other_email = f"other-{uuid.uuid4().hex[:8]}@example.test"
    other_org = f"Other-Org-{uuid.uuid4().hex[:8]}"
    client.post("/api/auth/register", json={
        "email": other_email, "password": "correct-horse-battery",
        "organization_name": other_org})
    r = client.post("/api/auth/login", json={"email": other_email,
                                             "password": "correct-horse-battery"})
    other = {"Authorization": f"Bearer {r.json()['access_token']}"}

    assert client.get(f"/api/applications/{app_id}", headers=other).status_code == 404
    assert client.get(f"/api/applications/{app_id}/authorizations", headers=other).status_code == 404
    assert client.post(f"/api/scans?application_id={app_id}", headers=other,
                       json={"config": scan_config(), "authorization_confirmation": conf}).status_code == 404
    app_list = client.get("/api/applications", headers=other).json()
    assert all(a["id"] != app_id for a in app_list)


def test_application_registration_validates_scope(client, auth_headers):
    r = client.post("/api/applications", headers=auth_headers, json={
        "name": "Bad scheme", "base_url": "ftp://example.com", "environment": "qa",
        "description": "", "allowed_hosts": [], "included_paths": [], "excluded_paths": [],
        "approved_origins": [],
        "authorization": {"authorized_by": "x", "authorization_reference": "",
                          "confirmation_text": "authorization statement goes here"}})
    assert r.status_code == 400
    assert "Scope validation failed" in r.json()["detail"]


def test_scan_requires_matching_authorization(client, auth_headers, demo_server, no_enqueue):
    conf = "Authorized internal test: this synthetic demo target may be scanned by the security team."
    r = client.post("/api/applications", headers=auth_headers, json={
        "name": "Auth-match app", "base_url": demo_server, "environment": "qa",
        "description": "", "allowed_hosts": [], "included_paths": [], "excluded_paths": [],
        "approved_origins": [],
        "authorization": {"authorized_by": "Security Lead", "authorization_reference": "TCK-2",
                          "confirmation_text": conf}})
    app_id = r.json()["id"]

    # wrong confirmation text is refused (403, not 4xx-validation) — scans are gated on authorization
    r = client.post(f"/api/scans?application_id={app_id}", headers=auth_headers,
                    json={"config": scan_config(), "authorization_confirmation": "just scan it please"})
    assert r.status_code == 403

    # exact match proceeds
    r = client.post(f"/api/scans?application_id={app_id}", headers=auth_headers,
                    json={"config": scan_config(), "authorization_confirmation": conf})
    assert r.status_code == 201
    assert r.json()["status"] in ("pending", "queued")


def test_viewer_role_cannot_create_scans(client):
    from app.auth import hash_password
    from app.db import SessionLocal
    from app.models import Organization, User

    email = f"viewer-{uuid.uuid4().hex[:8]}@example.test"
    db = SessionLocal()
    org = Organization(name=f"Viewer-Org-{uuid.uuid4().hex[:8]}")
    db.add(org)
    db.flush()
    db.add(User(email=email, password_hash=hash_password("correct-horse-battery"),
                role="viewer", organization_id=org.id))
    db.commit()
    db.close()

    r = client.post("/api/auth/login", json={"email": email, "password": "correct-horse-battery"})
    token = r.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # viewer can read, but cannot create applications/scans or use admin controls
    assert client.get("/api/applications", headers=headers).status_code == 200
    r = client.post("/api/applications", headers=headers, json={
        "name": "x", "base_url": "ftp://example.com", "environment": "qa", "description": "",
        "allowed_hosts": [], "included_paths": [], "excluded_paths": [], "approved_origins": [],
        "authorization": {"authorized_by": "x", "authorization_reference": "",
                          "confirmation_text": "some authorization statement"}})
    assert r.status_code == 403
    if REDIS_AVAILABLE:
        assert client.post("/api/admin/kill-switch?enabled=true", headers=headers).status_code == 403


def test_scan_bounds_enforced_server_side(client, auth_headers, demo_server, no_enqueue):
    conf = "Authorized internal test: this synthetic demo target may be scanned by the security team."
    r = client.post("/api/applications", headers=auth_headers, json={
        "name": "Bounds app", "base_url": demo_server, "environment": "qa",
        "description": "", "allowed_hosts": [], "included_paths": [], "excluded_paths": [],
        "approved_origins": [],
        "authorization": {"authorized_by": "Security Lead", "authorization_reference": "",
                          "confirmation_text": conf}})
    app_id = r.json()["id"]
    r = client.post(f"/api/scans?application_id={app_id}", headers=auth_headers, json={
        "config": scan_config(rate_limit_rps=999, max_requests=999999, max_depth=99),
        "authorization_confirmation": conf})
    assert r.status_code == 201
    # bounds are clamped, not trusted from the client — verify via the created config
    scan_id = r.json()["id"]
    scan = client.get(f"/api/scans/{scan_id}", headers=auth_headers).json()
    from app.db import SessionLocal
    from app.models import ScanConfig
    db = SessionLocal()
    cfg = db.get(ScanConfig, scan["config_id"])
    db.close()
    assert cfg is not None
    assert cfg.rate_limit_rps <= 10.0
    assert cfg.max_requests <= 5000
    assert cfg.max_depth <= 8