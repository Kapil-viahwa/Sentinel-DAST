"""Health checks and integration status (honest states only)."""
from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.orm import Session

from ..deps import get_db, get_redis
from ..engine.crawler import playwright_available
from ..engine.integrations.zap import ZapAdapter

router = APIRouter(prefix="/api/health", tags=["health"])


@router.get("")
def health() -> dict:
    return {"status": "ok", "service": "sentinel-dast-backend"}


@router.get("/ready")
def ready(db: Session = Depends(get_db)) -> dict:
    components = {"database": "ok", "redis": "ok"}
    overall = "ok"
    try:
        db.execute(text("SELECT 1"))
    except Exception as exc:
        components["database"] = f"error: {type(exc).__name__}"
        overall = "degraded"
    try:
        get_redis().ping()
    except Exception as exc:
        components["redis"] = f"error: {type(exc).__name__}"
        overall = "degraded"
    return {"status": overall, "components": components}


@router.get("/integrations")
def integrations() -> dict:
    zap = ZapAdapter.from_env()
    return {
        "integrations": [
            zap.status(),
            {
                "engine": "playwright-browser-crawler",
                "available": playwright_available(),
                "state": "configured" if playwright_available() else "unconfigured",
                "reason": None if playwright_available()
                else "Install `playwright` and run `playwright install chromium` to enable "
                     "browser crawling and DOM XSS execution checks.",
            },
        ]
    }