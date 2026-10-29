"""Enterprise dashboard aggregations — computed from persisted data only.
Empty deployments get honest zero-value payloads."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from .. import models
from ..db import get_db
from ..deps import get_current_user

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])


@router.get("")
def dashboard(user: models.User = Depends(get_current_user), db: Session = Depends(get_db)) -> dict:
    org = user.organization_id
    now = datetime.now(timezone.utc)

    apps = db.query(models.Application).filter_by(organization_id=org).count()
    scans = db.query(models.Scan).filter_by(organization_id=org)
    active_scans = scans.filter(models.Scan.status.in_(["pending", "queued", "running"])).count()
    completed_scans = scans.filter(models.Scan.status.in_(["completed", "failed", "cancelled"])).count()
    endpoints = db.query(models.Endpoint).filter_by(organization_id=org).count()

    findings = db.query(models.Finding).filter_by(organization_id=org).all()
    severity = {s: sum(1 for f in findings if f.severity == s)
                for s in ("critical", "high", "medium", "low", "informational")}
    owasp: dict = {}
    for f in findings:
        owasp[f.owasp_category] = owasp.get(f.owasp_category, 0) + 1
    confirmed = sum(1 for f in findings if f.verification_status in ("validated", "evidence_observed"))
    suspected = sum(1 for f in findings if f.verification_status in ("suspected", "requires_manual_review"))
    false_positives = sum(1 for f in findings if f.status == "false_positive")
    open_count = sum(1 for f in findings if f.status in ("open", "confirmed"))
    closed_count = sum(1 for f in findings if f.status in ("fixed", "risk_accepted"))
    fp_rate = round(false_positives / len(findings), 3) if findings else 0.0

    # vulnerability aging buckets for open findings
    aging = {"0-7d": 0, "8-30d": 0, "31-90d": 0, "90d+": 0}
    for f in findings:
        if f.status in ("open", "confirmed"):
            age = (now - f.first_detected).days
            if age <= 7:
                aging["0-7d"] += 1
            elif age <= 30:
                aging["8-30d"] += 1
            elif age <= 90:
                aging["31-90d"] += 1
            else:
                aging["90d+"] += 1

    # average time to remediate (fixed findings)
    fixed = [f for f in findings if f.status == "fixed"]
    avg_ttr = None
    if fixed:
        deltas = [(f.last_detected - f.first_detected).total_seconds() / 86400 for f in fixed
                  if f.last_detected and f.first_detected]
        avg_ttr = round(sum(deltas) / len(deltas), 1) if deltas else None

    recent_scans = (db.query(models.Scan).filter_by(organization_id=org)
                    .order_by(models.Scan.created_at.desc()).limit(8).all())

    # recurring findings: applications where a finding root cause appears in >1 scan
    keys_by_app: dict = {}
    for f in findings:
        keys_by_app.setdefault(f.application_id, {}).setdefault(f.finding_key, set()).add(f.scan_id)
    apps_with_recurring = sum(
        1 for key_map in keys_by_app.values()
        if any(len(scan_ids) > 1 for scan_ids in key_map.values())
    )

    return {
        "applications": apps,
        "scans": {"active": active_scans, "completed": completed_scans, "total": scan_total},
        "endpoints": endpoints,
        "findings": {
            "total": len(findings),
            "by_severity": severity,
            "by_owasp": owasp,
            "confirmed": confirmed,
            "suspected": suspected,
            "open": open_count,
            "closed": closed_count,
            "false_positive_rate": fp_rate,
            "aging": aging,
            "average_time_to_remediate_days": avg_ttr,
        },
        "recurring_applications": apps_with_recurring,
        "recent_scans": [
            {"id": s.id, "application_id": s.application_id, "status": s.status,
             "phase": s.phase, "requests_sent": s.requests_sent,
             "endpoints_discovered": s.endpoints_discovered,
             "created_at": s.created_at.isoformat()}
            for s in recent_scans
        ],
        "empty": apps == 0 and len(findings) == 0,
    }