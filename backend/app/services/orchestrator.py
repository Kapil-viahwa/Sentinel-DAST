"""Scan orchestration: enqueue to Celery when the broker is reachable, otherwise
fall back to a background thread so environments without a worker still run.
The fallback is honest: callers receive which path was used."""
from __future__ import annotations

import threading

from ..deps import get_redis
from ..engine.pipeline import run_scan


def enqueue_scan(scan_id: str) -> str:
    try:
        get_redis().ping()
    except Exception:
        threading.Thread(target=run_scan, args=(scan_id,), daemon=True).start()
        return "thread"

    try:
        from ..engine.worker import celery_app
        celery_app.send_task("sentinel.run_scan", args=[scan_id])
        return "celery"
    except Exception:
        threading.Thread(target=run_scan, args=(scan_id,), daemon=True).start()
        return "thread"