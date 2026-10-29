"""Shared pytest fixtures.

Configuration is patched BEFORE any app import so engines and sessions bind to
the temporary SQLite database.
"""
from __future__ import annotations

import os
import pathlib
import tempfile
import threading
import time

import pytest

sys_path = str(pathlib.Path(__file__).resolve().parents[1])
if sys_path not in __import__("sys").path:
    __import__("sys").path.insert(0, sys_path)

_tmpdir = tempfile.mkdtemp(prefix="sentinel-test-")
os.environ["SECRET_KEY"] = "test-secret-key-not-for-production"
os.environ["ALLOW_PRIVATE_TARGETS"] = "true"  # demo target runs on loopback

from app import config  # noqa: E402

config.settings.database_url = f"sqlite:///{_tmpdir}/sentinel-test.db"
config.settings.allow_private_targets = True
config.settings.object_storage_dir = os.path.join(_tmpdir, "reports")

import app.db as app_db  # noqa: E402

app_db.init_db()

import redis as redis_lib  # noqa: E402

try:
    redis_lib.Redis.from_url(config.settings.redis_url).ping()
    REDIS_AVAILABLE = True
except Exception:
    REDIS_AVAILABLE = False

import uvicorn  # noqa: E402


@pytest.fixture()
def client():
    from fastapi.testclient import TestClient

    from app.main import app

    with TestClient(app) as c:
        yield c


@pytest.fixture()
def no_enqueue(monkeypatch):
    """Deterministic tests: API-created scans are not auto-started."""
    from app.api import scans as scans_api

    monkeypatch.setattr(scans_api, "enqueue_scan", lambda scan_id: "disabled-in-tests")


@pytest.fixture(scope="session")
def demo_server():
    """Runs the intentionally vulnerable demo target on loopback."""
    from demo.app import app as demo_app

    config = uvicorn.Config(demo_app, host="127.0.0.1", port=8123, log_level="warning")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.time() + 10
    while not server.started and time.time() < deadline:
        time.sleep(0.1)
    yield "http://127.0.0.1:8123"
    server.should_exit = True
    thread.join(timeout=5)


@pytest.fixture()
def auth_headers(client):
    """Registers (or logs in) a user and returns bearer headers."""
    import uuid

    email = f"analyst-{uuid.uuid4().hex[:8]}@example.test"
    payload = {"email": email, "password": "correct-horse-battery",
               "organization_name": f"Org-{uuid.uuid4().hex[:8]}"}
    r = client.post("/api/auth/register", json=payload)
    if r.status_code == 409:  # org/email race on reruns — fall back to login
        r = client.post("/api/auth/login", json={"email": email, "password": payload["password"]})
    token = r.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


def scan_config(**overrides):
    base = {
        "profile": "standard",
        "auth_type": "anonymous",
        "auth_config": None,
        "max_depth": 2,
        "max_urls": 15,
        "max_requests": 600,
        "max_duration_seconds": 600,
        "rate_limit_rps": 10,
        "concurrency_limit": 2,
        "allowed_methods": ["GET", "HEAD"],
        "render_js": False,
        "openapi_spec": None,
        "sitemap_url": None,
        "proxy_url": None,
    }
    base.update(overrides)
    return base
