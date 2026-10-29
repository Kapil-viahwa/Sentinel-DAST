"""Sentinel DAST backend application."""
from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .config import settings
from .db import init_db
from .api import applications, auth, dashboard, findings, health, reports, scans

app = FastAPI(
    title="Sentinel DAST",
    description="Evidence-driven DAST platform for authorized web application assessments. "
                "All scanning requires an approved scope and an explicit authorization record.",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in settings.cors_origins.split(",") if o.strip()],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)

app.include_router(health.router)
app.include_router(auth.router)
app.include_router(applications.router)
app.include_router(scans.router)
app.include_router(findings.router)
app.include_router(reports.router)
app.include_router(dashboard.router)


@app.on_event("startup")
def startup() -> None:
    init_db()