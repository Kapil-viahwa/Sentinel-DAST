"""Authentication API: registration (first user of an organization is its admin),
rate-limited login, current user."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from .. import models
from ..auth import create_access_token, hash_password, verify_password
from ..db import get_db
from ..deps import check_login_rate_limit, get_current_user, record_audit
from ..schemas import LoginIn, RegisterIn, TokenOut, UserOut

router = APIRouter(prefix="/api/auth", tags=["auth"])


@router.post("/register", response_model=UserOut, status_code=status.HTTP_201_CREATED)
def register(payload: RegisterIn, db: Session = Depends(get_db)) -> models.User:
    email = payload.email.strip().lower()
    if db.query(models.User).filter_by(email=email).first():
        raise HTTPException(status.HTTP_409_CONFLICT, "Email already registered")
    if db.query(models.Organization).filter_by(name=payload.organization_name).first():
        raise HTTPException(status.HTTP_409_CONFLICT,
                            "Organization name already exists — ask an admin to invite you")
    org = models.Organization(name=payload.organization_name)
    db.add(org)
    db.flush()
    user = models.User(
        email=email,
        password_hash=hash_password(payload.password),
        role="admin",
        organization_id=org.id,
    )
    db.add(user)
    record_audit(db, user, "auth.register", "user", user.id, {"organization": org.name})
    db.commit()
    db.refresh(user)
    return user


@router.post("/login", response_model=TokenOut)
def login(payload: LoginIn, request: Request, db: Session = Depends(get_db)) -> TokenOut:
    check_login_rate_limit(request)
    user = db.query(models.User).filter_by(email=payload.email.strip().lower()).first()
    if user is None or not user.is_active or not verify_password(payload.password, user.password_hash):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid email or password")
    record_audit(db, user, "auth.login", "user", user.id)
    db.commit()
    return TokenOut(
        access_token=create_access_token(user.id, user.organization_id, user.role),
        role=user.role,
        organization_id=user.organization_id,
    )


@router.get("/me", response_model=UserOut)
def me(user: models.User = Depends(get_current_user)) -> models.User:
    return user