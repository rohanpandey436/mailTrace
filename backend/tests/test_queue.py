"""The Celery queue: eager execution, the job endpoints and, when a broker is configured, a worker that consumes from it.  The broker test is skipped without"""
from __future__ import annotations

import os
import time
import uuid
from dataclasses import replace

import pytest
from fastapi.testclient import TestClient

from app import tasks
from app.main import create_app

REDIS_URL = os.environ.get("MAILTRACE_REDIS_URL", "").strip()
# CI sets this to 0 and starts a separate worker process.
QUEUE_WORKERS = int(os.environ.get("MAILTRACE_QUEUE_WORKERS", "1"))
requires_broker = pytest.mark.skipif(not REDIS_URL, reason="no MAILTRACE_REDIS_URL; eager mode covers the rest")


@pytest.fixture
def client(cfg):
    app = create_app(cfg)
    with TestClient(app) as test_client:
        yield test_client


def _submit(client, sample, *names):
    files = [("files", (name, sample(key), "message/rfc822")) for key, name in names]
    response = client.post("/api/analyze/async", files=files)
    assert response.status_code == 202, response.text
    return response.json()


def test_eager_mode_is_the_default(cfg):
    """With no broker configured, tasks must run in-process rather than block."""
    assert not cfg.redis_url
    # Built from cfg: CI configures the module-level application with a broker.
    configured = tasks.build_celery(cfg)
    assert configured.conf.task_always_eager is True
    # Without this every eager job stays PENDING.
    assert configured.conf.task_store_eager_result is True
    assert "eager" in tasks.queue_status(cfg)


def test_reconfiguring_moves_the_live_connections(cfg):
    """configure() must move the live backend and producer pool, not just the settings."""
    tasks.configure(cfg)
    assert type(tasks.celery_app.backend).__name__ == "CacheBackend"
    # Publishing creates the producer pool.
    tasks.enqueue(b"From: a@b\r\nSubject: warm\r\n\r\nx\r\n", "warm.eml", "analyst")
    assert tasks.celery_app.amqp.producer_pool.connections.connection.as_uri().startswith("memory://")

    with_broker = replace(cfg, redis_url="redis://127.0.0.1:6379/0")
    tasks.configure(with_broker)
    try:
        assert type(tasks.celery_app.backend).__name__ == "RedisBackend"
        assert tasks.celery_app.conf.task_always_eager is False
        assert tasks.celery_app.amqp.producer_pool.connections.connection.as_uri().startswith("redis://")
    finally:
        tasks.configure(cfg)
    assert type(tasks.celery_app.backend).__name__ == "CacheBackend"
    assert tasks.celery_app.conf.task_always_eager is True


def test_async_upload_returns_jobs_that_resolve(client, sample):
    body = _submit(client, sample, ("phishing", "phishing.eml"), ("legit", "legit.eml"))
    assert len(body["jobs"]) == 2
    assert "eager" in body["queue"]

    by_name = {job["filename"]: job for job in body["jobs"]}
    assert set(by_name) == {"phishing.eml", "legit.eml"}

    for job in body["jobs"]:
        polled = client.get(f"/api/jobs/{job['job_id']}")
        assert polled.status_code == 200, polled.text
        state = polled.json()
        assert state["state"] == "SUCCESS", state
        assert state["result"]["email_id"]

    # Cases from the queue are readable exactly like synchronous ones.
    listing = client.get("/api/emails").json()
    assert listing["total"] == 2
    verdicts = {item["filename"]: item["category"] for item in listing["items"]}
    assert verdicts["phishing.eml"] == "Phishing"

    # The job's email_id is the case id.
    email_id = client.get(f"/api/jobs/{by_name['phishing.eml']['job_id']}").json()["result"]["email_id"]
    detail = client.get(f"/api/emails/{email_id}")
    assert detail.status_code == 200
    assert detail.json()["verdict"]["category"] == "Phishing"


def test_batch_polling_matches_single_polling(client, sample):
    body = _submit(client, sample, ("phishing", "a.eml"), ("bec", "b.eml"), ("fraud", "c.eml"))
    ids = [job["job_id"] for job in body["jobs"]]

    batch = client.get("/api/jobs", params={"ids": ",".join(ids)})
    assert batch.status_code == 200, batch.text
    batched = {entry["job_id"]: entry["state"] for entry in batch.json()}
    assert len(batched) == 3

    for job_id in ids:
        single = client.get(f"/api/jobs/{job_id}").json()
        assert single["state"] == batched[job_id]


def test_async_upload_enforces_the_same_limits_as_the_sync_endpoint(client, cfg, sample):
    """A payload the worker could never handle is refused before it is queued."""
    empty = client.post("/api/analyze/async", files=[("files", ("empty.eml", b"", "message/rfc822"))])
    assert empty.status_code == 400

    oversized = b"x" * (cfg.max_upload_bytes + 1)
    too_big = client.post("/api/analyze/async", files=[("files", ("big.eml", oversized, "message/rfc822"))])
    assert too_big.status_code == 413

    # Nothing was accepted, so nothing was analysed.
    assert client.get("/api/emails").json()["total"] == 0


def test_unknown_and_malformed_job_ids(client):
    """A well-formed id nobody issued is PENDING; anything else is a 422."""
    unknown = client.get("/api/jobs/00000000-0000-4000-8000-000000000000")
    assert unknown.status_code == 200
    assert unknown.json()["state"] == "PENDING"

    for bad in ("../../etc/passwd", "not-a-uuid", "*"):
        assert client.get(f"/api/jobs/{bad}").status_code in (404, 422)

    assert client.get("/api/jobs", params={"ids": ""}).status_code == 422
    assert client.get("/api/jobs", params={"ids": ",".join(["00000000-0000-4000-8000-000000000000"] * 101)}).status_code == 422


def test_an_unreachable_broker_is_refused_rather_than_waited_on(cfg, sample):
    """A dead Redis must fail the upload quickly with a 503, not hang on retries."""
    # Port 1: refused immediately. queue_workers=0 avoids leaving a worker thread retrying.
    broken = replace(cfg, redis_url="redis://127.0.0.1:1/0", queue_workers=0)
    app = create_app(broken)
    started = time.monotonic()
    with TestClient(app) as client:
        response = client.post(
            "/api/analyze/async",
            files=[("files", ("x.eml", sample("legit"), "message/rfc822"))],
        )
    elapsed = time.monotonic() - started

    assert response.status_code == 503, response.text
    assert "queue is unreachable" in response.text
    assert elapsed < 30, f"took {elapsed:.1f}s; the retry policy is not bounded"
    tasks.configure(cfg)  # leave the module pointed back at the default


def test_health_reports_how_tasks_execute(client):
    health = client.get("/api/health").json()
    assert health.get("queue")


def test_task_result_carries_no_message_content(client, sample):
    """The result backend must never hold message content, only an id and a verdict."""
    body = _submit(client, sample, ("phishing", "phishing.eml"))
    result = client.get(f"/api/jobs/{body['jobs'][0]['job_id']}").json()["result"]
    assert set(result) == {
        "email_id", "filename", "category", "risk_score", "severity", "processing_ms", "alert_id",
    }
    serialised = repr(result)
    assert "sbi-kyc-update" not in serialised
    assert "@" not in serialised.replace("phishing.eml", "")


@requires_broker
def test_a_real_worker_consumes_from_the_broker(sample):
    """Publish here, consume in a Celery worker, read the case back."""
    from app.config import Settings

    cfg = Settings.from_env()
    assert cfg.redis_url == REDIS_URL
    assert cfg.queue_workers == QUEUE_WORKERS
    cfg.ensure_dirs()
    app = create_app(cfg)
    with TestClient(app) as client:
        assert "redis" in client.get("/api/health").json()["queue"]
        # The database is shared with the worker and may not be empty.
        filename = f"phishing-{uuid.uuid4().hex[:8]}.eml"
        response = client.post(
            "/api/analyze/async",
            files=[("files", (filename, sample("phishing"), "message/rfc822"))],
        )
        assert response.status_code == 202, response.text
        job_id = response.json()["jobs"][0]["job_id"]

        # PENDING at first is the point: with a broker the work has not run yet.
        deadline = time.monotonic() + 60
        state = "PENDING"
        while time.monotonic() < deadline:
            state = client.get(f"/api/jobs/{job_id}").json()["state"]
            if state in ("SUCCESS", "FAILURE"):
                break
            time.sleep(0.5)
        assert state == "SUCCESS", f"job never completed (last state {state})"

        listing = client.get("/api/emails").json()
        ours = [item for item in listing["items"] if item["filename"] == filename]
        assert ours, f"{filename} is not in the case list: {listing}"
        assert ours[0]["category"] == "Phishing"
