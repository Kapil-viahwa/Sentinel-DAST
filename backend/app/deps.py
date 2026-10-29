"""FastAPI dependencies: authentication, roles, tenant scoping, audit."""
from __future__ import annotations

import time

import redis as redis_lib
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from . import models
from .auth import decode_token
from .config import settings
from .db import get_db

_bearer = HTTPBearer(auto_error=False)

_redis_pool = None


def _redis() -> redis_lib.Redis:
    global _redis_pool
    if _redis_pool is None:
        _redis_pool = redis_lib.Redis.from_url(settings.redis_url, decode_responses=True)
    return _redis_pool


def get_redis() -> redis_lib.Redis:
    return _redis()


def get_current_user(
    cred: HTTPAuthorizationCredentials | None = Depends(_bearer),
    db: Session = Depends(get_db),
) -> models.User:
    if cred is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Authentication required")
    try:
        payload = decode_token(cred.credentials)
    except Exception:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid or expired token")
    user = db.get(models.User, payload.get("sub"))
    if user is None or not user.is_active:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Unknown user")
    return user


def require_role(*roles: str):
    def checker(user: models.User = Depends(get_current_user)) -> models.User:
        if user.role not in roles:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Insufficient permissions")
        return user
    return checker


def record_audit(
    db: Session,
    user: models.User | None,
    action: str,
    target_type: str | None = None,
    target_id: str | None = None,
    detail: dict | None = None,
) -> None:
    db.add(models.AuditEvent(
        organization_id=getattr(user, "organization_id", None),
        user_id=getattr(user, "id", None),
        user_email=getattr(user, "email", None),
        action=action,
        target_type=target_type,
        target_id=target_id,
        detail=detail or {},
    ))


def check_login_rate_limit(request: Request) -> None:
    """Simple Redis-backed rate limit: 10 login attempts / 5 min / IP.
    Fails open (without limiting) when Redis is unavailable."""
    try:
        ip = request.client.host if request.client else "unknown"
        key = f"ratelimit:login:{ip}"
        r = get_redis()
        count = r.incr(key)
        if count == 1:
            r.expire(key, 300)
        if count > 10:
            raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Too many login attempts")
    except HTTPException:
        raise
    except Exception:
        return


def kill_switch_enabled() -> bool:
    try:
        return get_redis().get("sentinel:killswitch") == "1"
    except Exception:
        return False


def scan_cancel_requested(scan_id: str) -> bool:
    try:
        return get_redis().get(f"sentinel:scan:{scan_id}:cancel") == "1"
    except Exception:
        return False


def scan_pause_requested(scan_id: str) -> bool:
    try:
        return get_redis().get(f"sentinel:scan:{scan_id}:pause") == "1"
    except Exception:
        return False


_ = time  # imported intentionally for future timing instrumentation