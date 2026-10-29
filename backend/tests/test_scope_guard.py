"""Security-boundary tests: scope guard must refuse unsafe targets."""
from __future__ import annotations

import pytest

from app.scope_guard import ScopePolicy, ScopeViolation, _address_forbidden, validate_url


def test_metadata_ip_always_forbidden():
    assert _address_forbidden("169.254.169.254", allow_private=False)
    assert _address_forbidden("169.254.169.254", allow_private=True)


def test_private_addresses_forbidden_by_default():
    for ip in ("10.1.2.3", "192.168.0.10", "172.16.5.5", "127.0.0.1", "::1", "fe80::1"):
        assert _address_forbidden(ip, allow_private=False), ip


def test_public_ip_allowed():
    assert not _address_forbidden("93.184.216.34", allow_private=False)


def test_private_allowed_only_in_lab_mode():
    assert not _address_forbidden("10.1.2.3", allow_private=True)


def test_url_scheme_restricted():
    policy = ScopePolicy(base_url="https://example.com")
    with pytest.raises(ScopeViolation):
        validate_url("ftp://example.com/file", policy)
    with pytest.raises(ScopeViolation):
        validate_url("file:///etc/passwd", policy)


def test_loopback_blocked_unless_lab():
    loopback = "http://127.0.0.1:8123/"
    default = ScopePolicy(base_url=loopback, allow_private_targets=False)
    with pytest.raises(ScopeViolation):
        validate_url(loopback, default)
    lab = ScopePolicy(base_url=loopback, allow_private_targets=True)
    assert validate_url(loopback, lab).host == "127.0.0.1"


def test_host_allowlist_enforced():
    policy = ScopePolicy(base_url="https://app.example.com", allowed_hosts=["api.example.com"])
    with pytest.raises(ScopeViolation):
        validate_url("https://evil.example.com/x", policy)
    with pytest.raises(ScopeViolation):
        validate_url("https://api.other.org/x", policy)
    assert validate_url("https://api.example.com/x", policy).host == "api.example.com"


def test_wildcard_host():
    policy = ScopePolicy(base_url="https://app.example.com", allowed_hosts=["*.example.com"])
    assert validate_url("https://api.example.com/x", policy).host == "api.example.com"
    with pytest.raises(ScopeViolation):
        validate_url("https://api.evilexample.com/x", policy)


def test_path_include_exclude():
    policy = ScopePolicy(base_url="https://app.example.com", included_paths=["/app"])
    assert validate_url("https://app.example.com/app/page", policy).path == "/app/page"
    with pytest.raises(ScopeViolation):
        validate_url("https://app.example.com/other", policy)

    policy = ScopePolicy(base_url="https://app.example.com", excluded_paths=["/admin"])
    with pytest.raises(ScopeViolation):
        validate_url("https://app.example.com/admin/users", policy)
    assert validate_url("https://app.example.com/public", policy)


def test_dns_failure_raises_scope_violation():
    policy = ScopePolicy(base_url="https://nonexistent-sentinel-test.invalid")
    with pytest.raises(ScopeViolation):
        validate_url("https://nonexistent-sentinel-test.invalid/", policy)


def test_redirect_escape_blocked(monkeypatch):
    """Redirects to unauthorized hosts are refused (never followed)."""
    from app.scope_guard import validate_redirect

    policy = ScopePolicy(base_url="https://app.example.com")
    with pytest.raises(ScopeViolation):
        validate_redirect("https://app.example.com/login", "https://evil.example.com/steal", policy)
    # relative redirects within scope resolve fine
    assert validate_redirect("https://app.example.com/login", "/dashboard", policy).path == "/dashboard"