"""Application registration and scope management.

The base URL and approved hosts are validated server-side with the same scope
guard the scan transport uses, so an invalid or unsafe target cannot even be
registered.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from .. import models
from ..config import settings
from ..db import get_db
from ..deps import get_current_user, record_audit, require_role
from ..schemas import ApplicationIn, ApplicationOut, AuthorizationIn
from ..scope_guard import ScopePolicy, ScopeViolation, validate_url

router = APIRouter(prefix="/api/applications", tags=["applications"])


def _get_app_or_404(db: Session, user: models.User, app_id: str) -> models.Application:
    app = db.get(models.Application, app_id)
    if app is None or app.organization_id != user.organization_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Application not found")
    return app


def _validate_scope(base_url: str, allowed_hosts: list[str]) -> None:
    policy = ScopePolicy(base_url=base_url, allowed_hosts=allowed_hosts,
                         allow_private_targets=settings.allow_private_targets)
    try:
        validate_url(base_url, policy)
    except ScopeViolation as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"Scope validation failed: {exc}")


@router.post("", response_model=ApplicationOut, status_code=status.HTTP_201_CREATED)
def register_application(
    payload: ApplicationIn,
    user: models.User = Depends(require_role("admin", "analyst")),
    db: Session = Depends(get_db),
) -> models.Application:
    _validate_scope(payload.base_url, payload.allowed_hosts)
    app = models.Application(
        organization_id=user.organization_id,
        name=payload.name,
        base_url=payload.base_url.rstrip("/"),
        environment=payload.environment,
        description=payload.description,
        allowed_hosts=payload.allowed_hosts,
        included_paths=payload.included_paths,
        excluded_paths=payload.excluded_paths,
        approved_origins=payload.approved_origins,
        created_by=user.id,
    )
    db.add(app)
    db.flush()
    db.add(models.AuthorizationRecord(
        application_id=app.id,
        authorized_by=payload.authorization.authorized_by,
        authorization_reference=payload.authorization.authorization_reference,
        confirmation_text=payload.authorization.confirmation_text,
        environment_designation=payload.environment,
        created_by=user.id,
    ))
    record_audit(db, user, "application.register", "application", app.id,
                 {"name": app.name, "base_url": app.base_url, "environment": app.environment})
    db.commit()
    db.refresh(app)
    return app


@router.get("", response_model=list[ApplicationOut])
def list_applications(
    skip: int = 0, limit: int = 50,
    user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> list[models.Application]:
    limit = min(limit, 100)
    return (db.query(models.Application)
            .filter_by(organization_id=user.organization_id)
            .order_by(models.Application.created_at.desc())
            .offset(skip).limit(limit).all())


@router.get("/{app_id}", response_model=ApplicationOut)
def get_application(
    app_id: str,
    user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> models.Application:
    return _get_app_or_404(db, user, app_id)


@router.get("/{app_id}/authorizations")
def list_authorizations(
    app_id: str,
    user: models.User = Depends(require_role("admin", "analyst")),
    db: Session = Depends(get_db),
) -> dict:
    app = _get_app_or_404(db, user, app_id)
    records = db.query(models.AuthorizationRecord).filter_by(application_id=app.id).all()
    return {"authorizations": [
        {"id": r.id, "authorized_by": r.authorized_by,
         "authorization_reference": r.authorization_reference,
         "environment_designation": r.environment_designation,
         "created_at": r.created_at}
        for r in records
    ]}


@router.post("/{app_id}/authorizations", status_code=status.HTTP_201_CREATED)
def add_authorization(
    app_id: str,
    payload: AuthorizationIn,
    user: models.User = Depends(require_role("admin", "analyst")),
    db: Session = Depends(get_db),
) -> dict:
    app = _get_app_or_404(db, user, app_id)
    record = models.AuthorizationRecord(
        application_id=app.id,
        authorized_by=payload.authorized_by,
        authorization_reference=payload.authorization_reference,
        confirmation_text=payload.confirmation_text,
        environment_designation=app.environment,
        created_by=user.id,
    )
    db.add(record)
    record_audit(db, user, "authorization.add", "application", app.id)
    db.commit()
    db.refresh(record)
    return {"id": record.id, "authorized_by": record.authorized_by}