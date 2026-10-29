"""Scan API: creation (with server-side scope + safety validation), lifecycle
controls (cancel/pause/resume, global kill switch), inventory, evidence and SSE
live status."""
from __future__ import annotations

import json
import time

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from .. import models
from ..auth import decode_token
from ..config import settings
from ..db import SessionLocal, get_db
from ..deps import (get_current_user, get_redis, record_audit, require_role,
                    scan_cancel_requested, scan_pause_requested)
from ..schemas import ApplicationOut, ScanCreateIn, ScanOut, UserOut
from ..scope_guard import ScopePolicy, ScopeViolation, validate_scope_policy
from ..services.orchestrator import enqueue_scan
from .applications import _get_app_or_404

router = APIRouter(prefix="/api/scans", tags=["scans"])
admin_router = APIRouter(prefix="/api/admin", tags=["admin"])

TERMINAL_STATUSES = {"completed", "failed", "cancelled"}


def _get_scan_or_404(db: Session, user: models.User, scan_id: str) -> models.Scan:
    scan = db.get(models.Scan, scan_id)
    if scan is None or scan.organization_id != user.organization_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Scan not found")
    return scan


@router.post("", response_model=ScanOut, status_code=status.HTTP_201_CREATED)
def create_scan(
    application_id: str,
    payload: ScanCreateIn,
    user: models.User = Depends(require_role("admin", "analyst")),
    db: Session = Depends(get_db),
) -> models.Scan:
    app = _get_app_or_404(db, user, application_id)
    config_in = payload.config

    # Authorization must match the recorded statement, verbatim.
    auth_record = (db.query(models.AuthorizationRecord)
                   .filter_by(application_id=app.id)
                   .order_by(models.AuthorizationRecord.created_at.desc())
                   .first())
    if auth_record is None or payload.authorization_confirmation != auth_record.confirmation_text:
        raise HTTPException(status.HTTP_403_FORBIDDEN,
                            "Scan creation requires confirmation text matching the recorded authorization")

    # Server-side safety bounds.
    config_in.rate_limit_rps = min(config_in.rate_limit_rps, settings.max_rate_limit_rps)
    config_in.max_requests = min(config_in.max_requests, settings.max_max_requests)
    config_in.max_depth = min(config_in.max_depth, settings.max_max_depth)
    config_in.max_urls = min(config_in.max_urls, settings.max_max_urls)
    config_in.max_duration_seconds = min(config_in.max_duration_seconds,
                                         settings.max_scan_duration_seconds)
    config_in.allowed_methods = [m.upper() for m in config_in.allowed_methods
                                 if m.upper() in {"GET", "HEAD", "POST", "PUT", "PATCH", "OPTIONS"}]

    # Scope must validate before anything is queued.
    policy = ScopePolicy.from_application(app, settings.allow_private_targets)
    try:
        validate_scope_policy(policy)
    except ScopeViolation as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"Scope validation failed: {exc}")

    # Retest linkage.
    parent_scan_id = None
    is_retest = False
    if payload.retest_of:
        parent = db.get(models.Scan, payload.retest_of)
        if parent is None or parent.organization_id != user.organization_id \
                or parent.application_id != app.id:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "retest_of scan not found for this application")
        parent_scan_id = parent.id
        is_retest = True

    config = models.ScanConfig(
        application_id=app.id,
        profile=config_in.profile,
        auth_type=config_in.auth_type,
        auth_config_encrypted=(_encrypt_auth_config(config_in.auth_config)
                               if config_in.auth_config else None),
        max_depth=config_in.max_depth,
        max_urls=config_in.max_urls,
        max_requests=config_in.max_requests,
        max_duration_seconds=config_in.max_duration_seconds,
        rate_limit_rps=config_in.rate_limit_rps,
        concurrency_limit=config_in.concurrency_limit,
        allowed_methods=config_in.allowed_methods,
        render_js=config_in.render_js,
        openapi_spec=config_in.openapi_spec,
        sitemap_url=config_in.sitemap_url,
        proxy_url=config_in.proxy_url,
    )
    db.add(config)
    db.flush()
    scan = models.Scan(
        organization_id=user.organization_id,
        application_id=app.id,
        config_id=config.id,
        status="pending",
        is_retest=is_retest,
        parent_scan_id=parent_scan_id,
    )
    db.add(scan)
    record_audit(db, user, "scan.create", "scan", scan.id,
                 {"application": app.name, "profile": config.profile, "queue": None})
    db.commit()
    db.refresh(scan)
    queue = enqueue_scan(scan.id)
    record_audit(db, user, "scan.enqueue", "scan", scan.id, {"queue": queue})
    db.commit()
    return scan


def _encrypt_auth_config(auth_config: dict | None) -> str | None:
    if not auth_config:
        return None
    from ..crypto import encrypt_secret
    return encrypt_secret(json.dumps(auth_config))


@router.get("", response_model=list[ScanOut])
def list_scans(
    application_id: str | None = None,
    status_filter: str | None = Query(default=None, alias="status"),
    skip: int = 0, limit: int = 50,
    user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> list[models.Scan]:
    limit = min(limit, 100)
    q = db.query(models.Scan).filter_by(organization_id=user.organization_id)
    if application_id:
        q = q.filter_by(application_id=application_id)
    if status_filter:
        q = q.filter_by(status=status_filter)
    return q.order_by(models.Scan.created_at.desc()).offset(skip).limit(limit).all()


@router.get("/{scan_id}", response_model=ScanOut)
def get_scan(scan_id: str, user: models.User = Depends(get_current_user),
             db: Session = Depends(get_db)) -> models.Scan:
    return _get_scan_or_404(db, user, scan_id)


@router.post("/{scan_id}/cancel", response_model=ScanOut)
def cancel_scan(scan_id: str, user: models.User = Depends(require_role("admin", "analyst")),
                db: Session = Depends(get_db)) -> models.Scan:
    scan = _get_scan_or_404(db, user, scan_id)
    if scan.status in TERMINAL_STATUSES:
        return scan
    try:
        get_redis().set(f"sentinel:scan:{scan.id}:cancel", "1")
        signal = "redis"
    except Exception:
        signal = "unavailable"
    # A scan that has not started (pending/queued) may have no worker holding it —
    # e.g. its task already failed in an earlier worker. Cancel it directly; the
    # redis flag above also covers any late task redelivery (acks_late), and the
    # pipeline refuses to run scans that are no longer pending/queued.
    if scan.status in ("pending", "queued"):
        scan.status = "cancelled"
        scan.phase = "done"
        scan.finished_at = models.now()
    scan.progress = dict(scan.progress or {}) | {"cancel_signal": signal}
    record_audit(db, user, "scan.cancel", "scan", scan.id, {"signal": signal})
    db.commit()
    db.refresh(scan)
    return scan


@router.post("/{scan_id}/pause", response_model=ScanOut)
def pause_scan(scan_id: str, user: models.User = Depends(require_role("admin", "analyst")),
               db: Session = Depends(get_db)) -> models.Scan:
    scan = _get_scan_or_404(db, user, scan_id)
    get_redis().set(f"sentinel:scan:{scan.id}:pause", "1")
    record_audit(db, user, "scan.pause", "scan", scan.id)
    db.commit()
    db.refresh(scan)
    return scan


@router.post("/{scan_id}/resume", response_model=ScanOut)
def resume_scan(scan_id: str, user: models.User = Depends(require_role("admin", "analyst")),
                db: Session = Depends(get_db)) -> models.Scan:
    scan = _get_scan_or_404(db, user, scan_id)
    get_redis().delete(f"sentinel:scan:{scan.id}:pause")
    record_audit(db, user, "scan.resume", "scan", scan.id)
    db.commit()
    db.refresh(scan)
    return scan


@router.get("/{scan_id}/endpoints")
def scan_endpoints(scan_id: str, skip: int = 0, limit: int = 100,
                   user: models.User = Depends(get_current_user),
                   db: Session = Depends(get_db)) -> dict:
    scan = _get_scan_or_404(db, user, scan_id)
    limit = min(limit, 200)
    total = db.query(models.Endpoint).filter_by(scan_id=scan.id).count()
    rows = (db.query(models.Endpoint).filter_by(scan_id=scan.id)
            .order_by(models.Endpoint.discovered_at).offset(skip).limit(limit).all())
    return {"total": total, "endpoints": [
        {"id": e.id, "url": e.url, "method": e.method, "parameters": e.parameters,
         "status_code": e.status_code, "content_type": e.content_type}
        for e in rows
    ]}


@router.get("/{scan_id}/exchanges")
def scan_exchanges(scan_id: str, skip: int = 0, limit: int = 50, attack_only: bool = False,
                   user: models.User = Depends(get_current_user),
                   db: Session = Depends(get_db)) -> dict:
    scan = _get_scan_or_404(db, user, scan_id)
    limit = min(limit, 200)
    q = db.query(models.HttpExchange).filter_by(scan_id=scan.id)
    if attack_only:
        q = q.filter_by(is_attack_request=True)
    total = q.count()
    rows = q.order_by(models.HttpExchange.created_at).offset(skip).limit(limit).all()
    return {"total": total, "exchanges": [
        {"id": x.id, "method": x.method, "url": x.url, "status_code": x.status_code,
         "request_headers": x.request_headers, "request_body": x.request_body,
         "response_headers": x.response_headers, "response_body": x.response_body,
         "duration_ms": x.duration_ms, "is_attack_request": x.is_attack_request}
        for x in rows
    ]}


@router.get("/{scan_id}/executions")
def scan_executions(scan_id: str, skip: int = 0, limit: int = 100,
                    user: models.User = Depends(get_current_user),
                    db: Session = Depends(get_db)) -> dict:
    scan = _get_scan_or_404(db, user, scan_id)
    limit = min(limit, 500)
    total = db.query(models.TestExecution).filter_by(scan_id=scan.id).count()
    rows = (db.query(models.TestExecution).filter_by(scan_id=scan.id)
            .order_by(models.TestExecution.created_at).offset(skip).limit(limit).all())
    return {"total": total, "executions": [
        {"id": t.id, "module_id": t.module_id, "status": t.status, "detail": t.detail}
        for t in rows
    ]}


@router.get("/{scan_id}/stream")
def stream_scan(scan_id: str, token: str, db: Session = Depends(get_db)) -> StreamingResponse:
    """SSE live scan status. Token is passed as a query parameter because
    EventSource cannot set headers."""
    try:
        payload = decode_token(token)
    except Exception:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid token")
    from .. import models
    user = db.get(models.User, payload.get("sub"))
    scan = db.get(models.Scan, scan_id)
    if user is None or scan is None or scan.organization_id != user.organization_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Scan not found")

    def event_stream():
        for _ in range(1800):  # hard cap ~1h of streaming
            s = SessionLocal()
            try:
                current = s.get(models.Scan, scan_id)
                if current is None:
                    return
                data = {"status": current.status, "phase": current.phase,
                        "requests_sent": current.requests_sent,
                        "endpoints_discovered": current.endpoints_discovered,
                        "tests_run": current.tests_run,
                        "progress": current.progress or {},
                        "error_message": current.error_message}
                yield f"data: {json.dumps(data)}\n\n"
                if current.status in TERMINAL_STATUSES:
                    return
            finally:
                s.close()
            time.sleep(2.0)

    return StreamingResponse(event_stream(), media_type="text/event-stream")


@admin_router.post("/kill-switch")
def kill_switch(enabled: bool, user: models.User = Depends(require_role("admin")),
                db: Session = Depends(get_db)) -> dict:
    redis = get_redis()
    if enabled:
        redis.set("sentinel:killswitch", "1")
    else:
        redis.delete("sentinel:killswitch")
    record_audit(db, user, "admin.kill_switch", "platform", None, {"enabled": enabled})
    db.commit()
    return {"kill_switch": enabled}