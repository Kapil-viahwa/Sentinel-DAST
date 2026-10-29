"""Authentication and session management for scans.

Supported: anonymous, bearer-token, cookie-header, form login. Multi-role
configurations produce one isolated session per role. Credentials are supplied
from encrypted scan configuration and are never logged (transport redaction is
applied before persistence).
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field

from ..scope_guard import ScopePolicy, ScopeViolation
from .transport import Controls, SafeHttpClient

logger = logging.getLogger("sentinel.authn")


@dataclass
class SessionContext:
    role: str
    kind: str
    headers: dict = field(default_factory=dict)
    cookies: dict = field(default_factory=dict)


@dataclass
class Session:
    context: SessionContext
    client: SafeHttpClient


def _client_for(policy: ScopePolicy, transport_cfg: dict, controls: Controls,
                ctx: SessionContext) -> SafeHttpClient:
    return SafeHttpClient(
        policy,
        max_requests=transport_cfg.get("max_requests", 500),
        rate_limit_rps=transport_cfg.get("rate_limit_rps", 1.0),
        controls=controls,
        default_headers=ctx.headers,
        cookies=ctx.cookies,
    )


def build_sessions(
    policy: ScopePolicy,
    auth_type: str,
    auth_config: dict,
    transport_cfg: dict,
    controls: Controls,
) -> list[Session]:
    sessions: list[Session] = []
    role_configs = auth_config.get("roles") or [auth_config]

    if auth_type == "anonymous":
        for cfg in role_configs:
            ctx = SessionContext(role=cfg.get("role", "anonymous"), kind="anonymous")
            sessions.append(Session(ctx, _client_for(policy, transport_cfg, controls, ctx)))
        return sessions

    if auth_type == "bearer":
        for cfg in role_configs:
            token = cfg.get("token", "")
            ctx = SessionContext(
                role=cfg.get("role", "authenticated"),
                kind="bearer",
                headers={"Authorization": f"Bearer {token}"} if token else {},
            )
            sessions.append(Session(ctx, _client_for(policy, transport_cfg, controls, ctx)))
        return sessions

    if auth_type == "cookie":
        for cfg in role_configs:
            cookie_header = cfg.get("cookie_header", "")
            cookies = {}
            for part in cookie_header.split(";"):
                if "=" in part:
                    k, _, v = part.partition("=")
                    cookies[k.strip()] = v.strip()
            ctx = SessionContext(role=cfg.get("role", "authenticated"), kind="cookie", cookies=cookies)
            sessions.append(Session(ctx, _client_for(policy, transport_cfg, controls, ctx)))
        return sessions

    if auth_type == "form":
        for cfg in role_configs:
            login_url = cfg.get("login_url", "")
            username = cfg.get("username", "")
            password = cfg.get("password", "")
            ctx = SessionContext(role=cfg.get("role", "authenticated"), kind="form")
            client = _client_for(policy, transport_cfg, controls, ctx)
            fields = {cfg.get("username_field", "username"): username,
                      cfg.get("password_field", "password"): password}
            fields.update(cfg.get("extra_fields") or {})
            try:
                client.post(login_url, data=fields)
                logger.info("form login attempted for role=%s at %s", ctx.role, login_url)
            except (ScopeViolation, Exception) as exc:
                logger.warning("form login failed for role=%s: %s", ctx.role, exc)
            sessions.append(Session(ctx, client))
        return sessions

    raise ValueError(f"Unsupported auth_type: {auth_type}")


def session_expired(client: SafeHttpClient, probe_url: str) -> bool:
    """Best-effort expiration probe: 401/403 or a redirect toward a login page."""
    try:
        exchange = client.get(probe_url)
    except Exception:
        return True
    if exchange.status_code in (401, 403):
        return True
    for hop in exchange.redirect_chain:
        if any(word in hop.lower() for word in ("login", "signin", "session", "oauth")):
            return True
    return False