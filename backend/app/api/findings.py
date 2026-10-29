"""Finding management: retrieval, analyst overrides (with mandatory rationale +
audit trail), evidence retrieval."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from .. import models
from ..db import get_db
from ..deps import get_current_user, record_audit, require_role
from ..schemas import FindingOut, FindingUpdateIn

router = APIRouter(prefix="/api/findings", tags=["findings"])


def _get_finding_or_404(db: Session, user: models.User, finding_id: str) -> models.Finding:
    finding = db.get(models.Finding, finding_id)
    if finding is None or finding.organization_id != user.organization_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Finding not found")
    return finding


@router.get("", response_model=list[FindingOut])
def list_findings(
    application_id: str | None = None,
    scan_id: str | None = None,
    severity: str | None = None,
    status_filter: str | None = Query(default=None, alias="status"),
    owasp: str | None = None,
    q: str | None = None,
    skip: int = 0,
    limit: int = 50,
    user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> list[models.Finding]:
    limit = min(limit, 100)
    query = db.query(models.Finding).filter_by(organization_id=user.organization_id)
    if application_id:
        query = query.filter_by(application_id=application_id)
    if scan_id:
        query = query.filter_by(scan_id=scan_id)
    if severity:
        query = query.filter_by(severity=severity)
    if status_filter:
        query = query.filter_by(status=status_filter)
    if owasp:
        query = query.filter(models.Finding.owasp_category.contains(owasp))
    if q:
        query = query.filter(models.Finding.title.ilike(f"%{q}%"))
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
    rows = query.order_by(models.Finding.last_detected.desc()).offset(skip).limit(limit).all()
    return sorted(rows, key=lambda f: order.get(f.severity, 9))


@router.get("/{finding_id}", response_model=FindingOut)
def get_finding(finding_id: str, user: models.User = Depends(get_current_user),
                db: Session = Depends(get_db)) -> models.Finding:
    return _get_finding_or_404(db, user, finding_id)


@router.patch("/{finding_id}", response_model=FindingOut)
def update_finding(
    finding_id: str,
    payload: FindingUpdateIn,
    user: models.User = Depends(require_role("admin", "analyst")),
    db: Session = Depends(get_db),
) -> models.Finding:
    finding = _get_finding_or_404(db, user, finding_id)
    allowed_statuses = {"open", "confirmed", "fixed", "false_positive", "risk_accepted"}
    allowed_severities = {"critical", "high", "medium", "low", "informational"}
    allowed_verification = {"suspected", "evidence_observed", "validated",
                            "inconclusive", "false_positive", "requires_manual_review"}

    changes: dict = {}
    if payload.status is not None:
        if payload.status not in allowed_statuses:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid status")
        if finding.status != payload.status:
            changes["status"] = {"from": finding.status, "to": payload.status}
            finding.status = payload.status
    if payload.severity is not None:
        if payload.severity not in allowed_severities:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid severity")
        if finding.severity != payload.severity:
            changes["severity"] = {"from": finding.severity, "to": payload.severity}
            finding.severity = payload.severity
    if payload.verification_status is not None:
        if payload.verification_status not in allowed_verification:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid verification status")
        if finding.verification_status != payload.verification_status:
            changes["verification_status"] = {"from": finding.verification_status,
                                              "to": payload.verification_status}
            finding.verification_status = payload.verification_status
    if payload.ticket_reference is not None:
        finding.ticket_reference = payload.ticket_reference
    if payload.owner_id is not None:
        finding.owner_id = payload.owner_id

    if changes:  # overrides always carry the rationale and an audit record
        finding.override_rationale = payload.override_rationale
        record_audit(db, user, "finding.override", "finding", finding.id,
                     {"changes": changes, "rationale": payload.override_rationale})
    db.commit()
    db.refresh(finding)
    return finding


@router.get("/{finding_id}/evidence")
def finding_evidence(finding_id: str, user: models.User = Depends(get_current_user),
                     db: Session = Depends(get_db)) -> dict:
    finding = _get_finding_or_404(db, user, finding_id)
    rows = db.query(models.Evidence).filter_by(finding_id=finding.id).all()
    return {"evidence": [
        {"id": e.id, "kind": e.kind, "redacted_request": e.redacted_request,
         "redacted_response": e.redacted_response, "notes": e.notes,
         "created_at": e.created_at}
        for e in rows
    ]}


@router.get("/{finding_id}/audit")
def finding_audit(finding_id: str, user: models.User = Depends(require_role("admin", "analyst")),
                  db: Session = Depends(get_db)) -> dict:
    finding = _get_finding_or_404(db, user, finding_id)
    rows = (db.query(models.AuditEvent)
            .filter_by(target_type="finding", target_id=finding.id)
            .order_by(models.AuditEvent.created_at.desc()).limit(100).all())
    return {"audit": [
        {"action": a.action, "user_email": a.user_email, "detail": a.detail,
         "created_at": a.created_at}
        for a in rows
    ]}