from unittest.mock import Mock


def test_enqueue_scan_uses_worker_queue(monkeypatch):
    from app.engine import worker
    from app.services import orchestrator

    send_task = Mock()
    redis_client = Mock()
    monkeypatch.setattr(orchestrator, "get_redis", lambda: redis_client)
    monkeypatch.setattr(worker.celery_app, "send_task", send_task)

    assert orchestrator.enqueue_scan("scan-123") == "celery"
    send_task.assert_called_once_with("sentinel.run_scan", args=["scan-123"], queue="scans")
