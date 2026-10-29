"""Secret redaction must never leak credentials into evidence or reports."""
from __future__ import annotations

from app.redaction import redact_all, redact_body, redact_headers, redact_url_params


def test_authorization_and_cookie_headers_redacted():
    out = redact_headers({
        "Authorization": "Bearer super-secret-token",
        "Cookie": "sessionid=abc123",
        "Set-Cookie": "sessionid=xyz; HttpOnly",
        "Content-Type": "text/html",
        "X-Custom": "keep-me",
    })
    assert out["Authorization"] == "[REDACTED]"
    assert out["Cookie"] == "[REDACTED]"
    assert out["Set-Cookie"] == "[REDACTED]"
    assert out["Content-Type"] == "text/html"
    assert out["X-Custom"] == "keep-me"


def test_sensitive_url_params_redacted():
    url = redact_url_params("https://app.example.com/cb?code=abc123&state=xyz")
    assert "code=[REDACTED]" in url
    assert "state=xyz" in url


def test_token_like_params_redacted():
    url = redact_url_params("https://app.example.com/reset?token=secret123&next=/app")
    assert "secret123" not in url
    assert "next=/app" in url


def test_body_secrets_redacted():
    body = redact_body('{"password": "hunter2000", "username": "kim", "api_key": "AKIA..."}}')
    assert "hunter2000" not in body
    assert "AKIA..." not in body
    assert "kim" in body


def test_redact_all_shape():
    out = redact_all({"Cookie": "a=b"}, "<html>ok</html>", "https://x.example.com/?token=t")
    assert out["headers"]["Cookie"] == "[REDACTED]"
    assert "[REDACTED]" in out["url"]
    assert out["body"] == "<html>ok</html>"