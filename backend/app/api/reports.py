"""Report API: generation, listing, authorized download."""
from __future__ import annotations

import os

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from .. import models
from ..db import get_db
from ..deps import get_current_user, record_audit, require_role
from ..schemas import ReportRequestIn
from ..services.reporting import generate_scan_reports, portfolio_report_data

router = APIRouter(prefix="/api/reports", tags=["reports"])


@router.post("/generate")
def generate_report(
    payload: ReportRequestIn,
    user: models.User = Depends(require_role("admin", "analyst")),
    db: Session = Depends(get_db),
) -> dict:
    if payload.format not in ("html", "json"):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "format must be html or json")

    if payload.kind == "portfolio":
        data = portfolio_report_data(user.organization_id)
        import json
        report = models.Report(organization_id=user.organization_id, kind="portfolio",
                               format=payload.format, storage_path="")
        db.add(report)
        db.flush()
        from ..services.reporting import _storage_path
        path = _storage_path(user.organization_id, report.id, payload.format)
        with open(path, "w", encoding="utf-8") as fh:
            if payload.format == "json":
                import json as _json
                fh.write(_json.dumps(data, indent=2, default=str))
            else:
                fh.write(f"<html><body><h1>Portfolio report</h1><pre>{_json.dumps(data, indent=2)}</pre></body></html>")
        report.storage_path = path
        record_audit(db, user, "report.generate", "report", report.id, {"kind": "portfolio"})
        db.commit()
        db.refresh(report)
        return {"id": report.id, "kind": report.kind, "format": report.format}

    if not payload.scan_id:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "scan_id required for scan reports")
    scan = db.get(models.Scan, payload.scan_id)
    if scan is None or scan.organization_id != user.organization_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Scan not found")

    reports = generate_scan_reports(payload.scan_id)
    selected = [r for r in reports if r.format == payload.format and r.kind == payload.kind]
    if not selected:
        selected = [r for r in reports if r.format == payload.format]
    if not selected:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Requested report kind/format is not generated for scans")
    record_audit(db, user, "report.generate", "report", selected[0].id,
                 {"kind": selected[0].kind, "format": selected[0].format})
    return {"id": selected[0].id, "kind": selected[0].kind, "format": selected[0].format,
            "generated": len(reports)}


@router.get("")
def list_reports(user: models.User = Depends(get_current_user),
                 db: Session = Depends(get_db)) -> dict:
    rows = (db.query(models.Report).filter_by(organization_id=user.organization_id)
            .order_by(models.Report.generated_at.desc()).limit(200).all())
    return {"reports": [
        {"id": r.id, "kind": r.kind, "format": r.format, "scan_id": r.scan_id,
         "application_id": r.application_id, "generated_at": r.generated_at}
        for r in rows
    ]}


@router.get("/{report_id}/download")
def download_report(report_id: str, user: models.User = Depends(get_current_user),
                    db: Session = Depends(get_db)) -> FileResponse:
    report = db.get(models.Report, report_id)
    if report is None or report.organization_id != user.organization_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Report not found")
    if not os.path.exists(report.storage_path):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Report artifact missing")
    media = "application/json" if report.format == "json" else "text/html"
    return FileResponse(report.storage_path, media_type=media,
                        filename=f"sentinel-{report.kind}-{report.id}.{report.format}")