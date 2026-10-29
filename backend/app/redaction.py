"""Secret redaction for logs, evidence, API responses and reports."""
from __future__ import annotations

import re

SENSITIVE_HEADERS = {"authorization", "cookie", "set-cookie", "x-api-key", "proxy-authorization"}
SENSITIVE_PARAMS = {
    "token", "access_token", "refresh_token", "id_token", "password", "passwd", "secret",
    "api_key", "apikey", "session", "sessionid", "auth", "credential", "credentials",
    "authorization", "bearer", "code", "client_secret", "private_key", "sid", "jwt",
}
SENSITIVE_BODY_KEYS = SENSITIVE_PARAMS | {"pwd", "pass", "otp", "pin", "cookie"}

_REDACTED = "[REDACTED]"


def redact_headers(headers: dict) -> dict:
    out = {}
    for k, v in (headers or {}).items():
        if str(k).lower() in SENSITIVE_HEADERS:
            out[k] = _REDACTED
        else:
            out[k] = v
    return out


def redact_url_params(url: str) -> str:
    def _sub(match: re.Match) -> str:
        key = match.group(1).lower()
        return f"{key}={_REDACTED}" if key in SENSITIVE_PARAMS else match.group(0)

    return re.sub(r"([A-Za-z0-9_.-]+)=([^&\s\"']*)", _sub, url)


def redact_body(body: str | None) -> str:
    """Redact token-shaped query values and key=value secrets inside text bodies."""
    if not body:
        return ""
    text = redact_url_params(body)
    text = re.sub(
        r"([\"']?)(password|passwd|secret|token|api_key|apikey|sessionid|auth)[\"']?\s*[:=]\s*[\"']?[^\"',;&\s}]+",
        lambda m: f"{m.group(1)}{m.group(2)}{_REDACTED}",
        text,
        flags=re.IGNORECASE,
    )
    return text


def redact_json(obj):
    """Recursively redact sensitive keys in parsed JSON structures."""
    if isinstance(obj, dict):
        return {
            k: (_REDACTED if str(k).lower() in SENSITIVE_BODY_KEYS else redact_json(v))
            for k, v in obj.items()
        }
    if isinstance(obj, list):
        return [redact_json(v) for v in obj]
    return obj


def redact_all(headers: dict | None, body: str | None, url: str | None = "") -> dict:
    return {
        "headers": redact_headers(headers or {}),
        "body": redact_body(body),
        "url": redact_url_params(url or ""),
    }