"""
The Celery queue: eager execution, the HTTP job endpoints, and - when a broker
is reachable - a worker that really consumes from it.

The eager tests run everywhere and are the ones that matter for correctness,
because eager execution is what a deployment without ``MAILTRACE_REDIS_URL``
does. The broker test is skipped unless one is configured, which is how CI
reaches it: the ``queue`` job starts a Redis service and sets that variable.
"""
from __future__ import annotations

import os
import time

import pytest
from fastapi.testclient import TestClient

from app import tasks
from app.main import create_app

REDIS_URL = os.environ.get("MAILTRACE_REDIS_URL", "").strip()
# CI sets this to 0 and starts a separate `celery worker` process, so the broker
# test proves an out-of-process consumer rather than a thread of its own making.
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
    # Built from cfg rather than read off the module-level application, whose
    # broker CI does configure - the claim here is about the default, not about
    # whatever this process happens to be pointed at.
    configured = tasks.build_celery(cfg)
    assert configured.conf.task_always_eager is True
    # The one setting that makes eager results pollable; without it every job
    # would answer PENDING forever. Asserted because it is easy to lose.
    assert configured.conf.task_store_eager_result is True
    assert "eager" in tasks.queue_status(cfg)


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

    # The queue is not a separate universe: the cases it produced are the same
    # cases the synchronous endpoint would have written, readable the same way.
    listing = client.get("/api/emails").json()
    assert listing["total"] == 2
    verdicts = {item["filename"]: item["category"] for item in listing["items"]}
    assert verdicts["phishing.eml"] == "Phishing"

    # The id the job reported is the id the case has, so a client can go
    # straight from a finished job to the full analysis.
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


def test_health_reports_how_tasks_execute(client):
    health = client.get("/api/health").json()
    assert health.get("queue")


def test_task_result_carries_no_message_content(client, sample):
    """What lands in the result backend must not be the email itself.

    In a real deployment the backend is Redis, which is neither the evidence
    store nor covered by the PII-masking policy, so the task returns an
    identifier and a verdict and nothing that could quote the message.
    """
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
    """End to end against Redis: publish here, consume in a Celery worker.

    Skipped without a broker. When it does run it is the only test that proves
    the distributed path, and MAILTRACE_QUEUE_WORKERS decides how much it
    proves: at 0 nothing in this process can run the task, so the job can only
    finish if the separate worker CI starts picked it up.

    Settings come from the environment rather than the ``cfg`` fixture,
    deliberately: the worker is a different process reading the same variables,
    so this is what makes the two agree on one database to write the case into.
    """
    from app.config import Settings

    cfg = Settings.from_env()
    assert cfg.redis_url == REDIS_URL
    assert cfg.queue_workers == QUEUE_WORKERS
    cfg.ensure_dirs()
    app = create_app(cfg)
    with TestClient(app) as client:
        assert "redis" in client.get("/api/health").json()["queue"]
        response = client.post(
            "/api/analyze/async",
            files=[("files", ("phishing.eml", sample("phishing"), "message/rfc822"))],
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
        assert listing["total"] == 1
        assert listing["items"][0]["category"] == "Phishing"
