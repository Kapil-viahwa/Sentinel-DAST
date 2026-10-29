"""Celery worker for scan execution.

Queues and coordination state live in Redis:
- `sentinel:killswitch`        global kill switch ("1" = stop everything)
- `sentinel:scan:{id}:cancel`  per-scan cancel flag
- `sentinel:scan:{id}:pause`   per-scan pause flag (checked between requests)
"""
from __future__ import annotations

from celery import Celery

from ..config import settings

celery_app = Celery(
    "sentinel",
    broker=settings.redis_url,
    backend=settings.redis_url,
)

celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    task_acks_late=True,
    worker_prefetch_multiplier=1,
    # Hard backstops; the pipeline enforces its own deadline gracefully first.
    task_soft_time_limit=settings.max_scan_duration_seconds + 300,
    task_time_limit=settings.max_scan_duration_seconds + 600,
)


@celery_app.task(name="sentinel.run_scan", bind=True, max_retries=0)
def run_scan_task(self, scan_id: str):
    from .pipeline import run_scan
    run_scan(scan_id)
    return {"scan_id": scan_id, "status": "processed"}