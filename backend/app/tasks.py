"""
Celery task queue for out-of-band analysis.

Analysing a message is CPU-bound and, with ``MAILTRACE_ENABLE_NETWORK=true``,
also waits on WHOIS, DNS, GeoIP and blocklist lookups.  A single upload is
fast enough to answer inline, which is what ``POST /api/analyze`` does; a
mailbox export of several hundred messages is not, and holding an HTTP
connection open for it is the wrong shape.  ``POST /api/analyze/async``
enqueues one task per message and answers immediately with job ids the client
polls.

Three deployment shapes, all of them real, chosen by configuration alone:

``MAILTRACE_REDIS_URL`` unset
    Celery runs in eager mode: ``apply_async`` executes the task inline and
    stores the result in a process-local cache backend.  The job endpoints
    behave identically, so the frontend has one code path.  This is what the
    test suite and a plain ``pip install -r requirements.txt`` deployment use.

``MAILTRACE_REDIS_URL`` set, ``MAILTRACE_QUEUE_WORKERS`` > 0 (the default)
    Redis is the broker and the result backend, and this process also runs a
    Celery worker in a thread.  One container, a genuine queue: work is
    durable across a request, survives a client disconnect, and is rate-limited
    by worker concurrency rather than by however many uploads arrive at once.
    This is the shape the free tier can afford, since a separate Render
    Background Worker is a paid service.

``MAILTRACE_REDIS_URL`` set, ``MAILTRACE_QUEUE_WORKERS=0``
    Producer only.  Workers run elsewhere - ``deploy/docker-compose.yml``
    starts one, and ``celery -A app.tasks worker`` is the manual form.  This is
    the shape that scales horizontally.

One caveat is worth stating plainly: an alert raised inside an *external*
worker is written to the database but cannot reach the browsers subscribed to
this process's ``/api/alerts/stream``, because that stream is fed by an
in-process broadcaster.  Those alerts appear on the next poll of
``/api/alerts`` rather than instantly.  With the embedded worker - the default
whenever a broker is configured - the worker shares the process and the
broadcaster, so live alerts are unaffected.
"""
from __future__ import annotations

import base64
import logging
import threading
from typing import TYPE_CHECKING, Any

from celery import Celery
from celery.result import AsyncResult

from .config import Settings
from .config import settings as default_settings

if TYPE_CHECKING:
    from .database.case_manager import Store

log = logging.getLogger("mailtrace.tasks")

#: Task name, spelled explicitly rather than derived from the module path, so a
#: worker started as ``celery -A app.tasks`` and one started as
#: ``celery -A backend.app.tasks`` agree on what to consume.
ANALYZE_TASK = "mailtrace.analyze_message"

#: Queue name.  Named rather than default so an operator can run workers
#: dedicated to analysis alongside workers for anything added later.
QUEUE_NAME = "mailtrace.analysis"

#: In eager mode results live in a process-local dict rather than in Redis.
#: Celery's own name for that backend.
_MEMORY_BACKEND = "cache+memory://"
_MEMORY_BROKER = "memory://"

# The Store the task should use.  The web process binds its own during startup
# so that eager and embedded-worker execution share one database handle - which
# matters for MAILTRACE_ZERO_PERSISTENCE, where a second Store object would be
# a second, separate in-memory database rather than the same one.  An external
# worker process binds nothing and opens its own; see _task_store.
_bound_store: Store | None = None
_bound_settings: Settings | None = None
_own_store: Store | None = None
_store_lock = threading.Lock()

_embedded_worker: threading.Thread | None = None


def build_celery(cfg: Settings | None = None) -> Celery:
    """Configure the Celery application for ``cfg``."""
    cfg = cfg or default_settings
    broker = cfg.redis_url.strip()
    app = Celery(
        "mailtrace",
        broker=broker or _MEMORY_BROKER,
        backend=broker or _MEMORY_BACKEND,
    )
    app.conf.update(
        task_default_queue=QUEUE_NAME,
        task_serializer="json",
        result_serializer="json",
        # Never unpickle: a broker that an attacker can write to would
        # otherwise be remote code execution in the worker.
        accept_content=["json"],
        result_accept_content=["json"],
        timezone="UTC",
        enable_utc=True,
        # Distinguishes "queued behind other work" from "being analysed now",
        # which is the difference the progress bar shows.
        task_track_started=True,
        result_expires=cfg.queue_result_ttl,
        # One message at a time per worker process.  Analysis is CPU-bound and
        # already parallel across processes; prefetching would only make one
        # worker sit on messages another could be running.
        worker_prefetch_multiplier=1,
        task_acks_late=True,
        # A message whose worker died is redelivered rather than lost.
        task_reject_on_worker_lost=True,
        broker_connection_retry_on_startup=True,
        # Celery's logging configuration otherwise replaces uvicorn's.
        worker_hijack_root_logger=False,
        task_always_eager=not broker,
        # Eager mode must report a failed task the same way the broker does -
        # as a FAILURE state to poll for - not by raising into the HTTP handler.
        task_eager_propagates=False,
        # ...and must write its results to the backend, which eager mode does
        # not do by default. Without this the job endpoints would answer
        # PENDING forever for work that had already finished, and the frontend
        # would need to know which mode it was talking to.
        task_store_eager_result=True,
    )
    return app


celery_app = build_celery()


def configure(cfg: Settings) -> None:
    """Point the Celery application at ``cfg``'s broker.

    The module-level application is built from the environment at import time,
    because ``celery -A app.tasks worker`` has to work with no application
    factory in sight.  ``create_app`` calls this so that an injected
    ``Settings`` wins instead - which is what the test suite relies on, and
    what makes ``create_app(Settings(redis_url=...))`` mean anything.

    Updated in place rather than rebuilt: the task is registered against this
    application object, and replacing it would leave that registration behind.
    """
    broker = cfg.redis_url.strip()
    celery_app.conf.broker_url = broker or _MEMORY_BROKER
    celery_app.conf.result_backend = broker or _MEMORY_BACKEND
    celery_app.conf.task_always_eager = not broker
    celery_app.conf.result_expires = cfg.queue_result_ttl


def bind_store(store: Store, cfg: Settings) -> None:
    """Give in-process tasks the web application's own Store and settings."""
    global _bound_store, _bound_settings
    _bound_store = store
    _bound_settings = cfg


def unbind_store() -> None:
    """Release the bound Store, and close one this module opened itself."""
    global _bound_store, _bound_settings, _own_store
    _bound_store = None
    _bound_settings = None
    with _store_lock:
        own, _own_store = _own_store, None
    if own is not None:
        own.close()


def _task_settings() -> Settings:
    return _bound_settings or default_settings


def _task_store() -> Store:
    """The Store to analyse into: the bound one, or this process's own."""
    if _bound_store is not None:
        return _bound_store
    global _own_store
    with _store_lock:
        if _own_store is None:
            from .database.case_manager import Store as StoreClass

            cfg = _task_settings()
            cfg.ensure_dirs()
            _own_store = StoreClass(cfg.db_path, cfg.evidence_dir, database_url=cfg.database_url)
            log.info("celery worker opened its own store at %s", cfg.db_path)
        return _own_store


# Celery ships no type information for its decorator, so under strict mode it
# would erase the signature of whatever it wraps. Ignored here rather than
# loosening the settings for the module, so the body stays fully checked.
@celery_app.task(name=ANALYZE_TASK, bind=True, queue=QUEUE_NAME)  # type: ignore[untyped-decorator]
def analyze_message(self: Any, raw_b64: str, filename: str, actor: str) -> dict[str, Any]:
    """Analyse one message and persist the case.

    ``raw_b64`` because the JSON serializer cannot carry bytes, and JSON is the
    only content type this application accepts from the broker.

    The return value is deliberately a summary rather than the full
    ``AnalysisResult``: the case is in the database by the time this returns,
    so a client that wants the detail fetches ``/api/emails/{id}`` and gets it
    through the same masking and serialisation as every other read.  Putting a
    complete result in the broker would also mean unmasked PII sitting in
    Redis for ``result_expires`` seconds.
    """
    from .api.alerts import maybe_alert
    from .core import pipeline

    store = _task_store()
    cfg = _task_settings()
    result = pipeline.analyze_bytes(base64.b64decode(raw_b64), filename, store, cfg, actor)
    alert = maybe_alert(result, store, cfg)
    return {
        "email_id": result.id,
        "filename": result.filename,
        "category": result.verdict.category.value,
        "risk_score": result.verdict.risk_score,
        "severity": result.verdict.severity.value,
        "processing_ms": result.processing_ms,
        "alert_id": alert.id if alert is not None else None,
    }


def enqueue(raw: bytes, filename: str, actor: str) -> str:
    """Queue one message for analysis; returns the job id to poll."""
    payload = base64.b64encode(raw).decode("ascii")
    return str(analyze_message.apply_async(args=[payload, filename, actor], queue=QUEUE_NAME).id)


def job_state(job_id: str) -> dict[str, Any]:
    """Poll one job.

    ``state`` is Celery's own vocabulary - PENDING, STARTED, SUCCESS, FAILURE,
    RETRY, REVOKED - passed through rather than translated, because PENDING
    genuinely means "this broker has never heard of that id", which covers both
    "not started yet" and "wrong id".  There is no way to tell those apart, and
    inventing a friendlier word would hide that.
    """
    async_result = AsyncResult(job_id, app=celery_app)
    state = str(async_result.state)
    payload: dict[str, Any] = {"job_id": job_id, "state": state}
    if state == "SUCCESS":
        value = async_result.result
        if isinstance(value, dict):
            payload["result"] = value
    elif state == "FAILURE":
        # str() of the exception, never the traceback: it can quote message
        # content, and this is served over the API.
        payload["error"] = f"{type(async_result.result).__name__}: {async_result.result}"
    return payload


def start_embedded_worker(cfg: Settings) -> bool:
    """Run a Celery worker inside this process; True when one was started.

    ``WorkController`` rather than ``celery_app.Worker``: the latter is the CLI
    application and installs process-wide signal handlers, which fails outside
    the main thread.  The controller is the same worker without that.

    Nothing here is required for correctness - it is a deployment convenience
    for the single-container case - so a failure to start is logged and the
    service continues with whatever workers exist elsewhere.
    """
    global _embedded_worker
    if not cfg.redis_url.strip() or cfg.queue_workers <= 0:
        return False
    if _embedded_worker is not None and _embedded_worker.is_alive():
        return True

    def run() -> None:
        try:
            controller = celery_app.WorkController(
                pool_cls="solo" if cfg.queue_workers == 1 else "threads",
                concurrency=cfg.queue_workers,
                queues=[QUEUE_NAME],
                without_gossip=True,
                without_mingle=True,
                without_heartbeat=False,
                quiet=True,
            )
            controller.start()
        # A worker that cannot start must not take the API down with it: the
        # service still analyses synchronously, which is what it does with no
        # broker configured at all.
        except Exception as exc:
            log.warning("embedded Celery worker stopped: %s", exc, exc_info=True)

    _embedded_worker = threading.Thread(target=run, name="mt-celery-worker", daemon=True)
    _embedded_worker.start()
    log.info("embedded Celery worker started (%d slot(s), queue %s)", cfg.queue_workers, QUEUE_NAME)
    return True


def queue_status(cfg: Settings | None = None) -> str:
    """One line for ``/api/health`` describing how tasks actually execute."""
    cfg = cfg or _task_settings()
    if not cfg.redis_url.strip():
        return "eager (no broker configured; tasks run in the request process)"
    embedded = _embedded_worker is not None and _embedded_worker.is_alive()
    if embedded:
        return f"redis, {cfg.queue_workers} embedded worker slot(s)"
    if cfg.queue_workers > 0:
        return "redis, embedded worker configured but not running"
    return "redis, external workers only"
