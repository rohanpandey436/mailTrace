"""Celery task queue for bulk analysis."""
from __future__ import annotations

import base64
import logging
import threading
from typing import TYPE_CHECKING, Any

from celery import Celery, shared_task
from celery.result import AsyncResult

from .config import Settings
from .config import settings as default_settings

if TYPE_CHECKING:
    from .database.case_manager import Store

log = logging.getLogger("mailtrace.tasks")

#: Explicit so workers started as ``app.tasks`` and ``backend.app.tasks`` agree.
ANALYZE_TASK = "mailtrace.analyze_message"

#: Named, so workers can be dedicated to it.
QUEUE_NAME = "mailtrace.analysis"

#: Eager mode keeps results in a process-local dict.
_MEMORY_BACKEND = "cache+memory://"
_MEMORY_BROKER = "memory://"

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
        # JSON only: unpickling broker messages would be remote code execution.
        accept_content=["json"],
        result_accept_content=["json"],
        timezone="UTC",
        enable_utc=True,
        # STARTED separates "queued" from "running" for the progress bar.
        task_track_started=True,
        result_expires=cfg.queue_result_ttl,
        # Analysis is CPU-bound; prefetching only parks messages on a busy worker.
        worker_prefetch_multiplier=1,
        task_acks_late=True,
        # A message whose worker died is redelivered rather than lost.
        task_reject_on_worker_lost=True,
        broker_connection_retry_on_startup=True,
        # Bounded publish retries; the default retries for minutes and hangs the request.
        task_publish_retry_policy={
            "max_retries": 2,
            "interval_start": 0.0,
            "interval_step": 0.2,
            "interval_max": 0.5,
        },
        # socket_timeout is left unset: it would also cut the worker's blocking read.
        broker_transport_options={"socket_connect_timeout": 5.0},
        result_backend_transport_options={
            "socket_connect_timeout": 5.0,
            "retry_policy": {
                "max_retries": 2,
                "interval_start": 0.0,
                "interval_step": 0.2,
                "interval_max": 0.5,
            },
        },
        # Celery's logging configuration otherwise replaces uvicorn's.
        worker_hijack_root_logger=False,
        task_always_eager=not broker,
        # A failed eager task must surface as FAILURE, not raise into the handler.
        task_eager_propagates=False,
        # Eager results are not stored by default; without this every job stays PENDING.
        task_store_eager_result=True,
    )
    return app


celery_app = build_celery()


def configure(cfg: Settings) -> None:
    """Point the queue at ``cfg`` by building a new Celery application."""
    global celery_app
    previous = celery_app
    celery_app = build_celery(cfg)
    # So the shared_task proxy and AsyncResult resolve to the new application.
    celery_app.set_default()
    if previous is not None:
        previous.close()


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


@shared_task(name=ANALYZE_TASK, bind=True, queue=QUEUE_NAME)  # type: ignore[untyped-decorator]
def analyze_message(self: Any, raw_b64: str, filename: str, actor: str) -> dict[str, Any]:
    """Analyse one message and persist the case."""
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


class QueueUnavailable(RuntimeError):
    """The broker could not be reached, so nothing was queued."""


def enqueue(raw: bytes, filename: str, actor: str) -> str:
    """Queue one message; returns the job id."""
    from kombu.exceptions import OperationalError

    payload = base64.b64encode(raw).decode("ascii")
    try:
        result = analyze_message.apply_async(args=[payload, filename, actor], queue=QUEUE_NAME)
    except (OperationalError, RuntimeError) as exc:
        log.warning("could not queue %s: %s: %s", filename, type(exc).__name__, exc)
        raise QueueUnavailable(f"{type(exc).__name__}: {exc}") from exc
    return str(result.id)


def job_state(job_id: str) -> dict[str, Any]:
    """Poll one job."""
    async_result = AsyncResult(job_id, app=celery_app)
    state = str(async_result.state)
    payload: dict[str, Any] = {"job_id": job_id, "state": state}
    if state == "SUCCESS":
        value = async_result.result
        if isinstance(value, dict):
            payload["result"] = value
    elif state == "FAILURE":
        # str(), never the traceback: it can quote message content.
        payload["error"] = f"{type(async_result.result).__name__}: {async_result.result}"
    return payload


def start_embedded_worker(cfg: Settings) -> bool:
    """Run a Celery worker thread in this process; True when one was started."""
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
        # A worker that cannot start must not take the API down.
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
