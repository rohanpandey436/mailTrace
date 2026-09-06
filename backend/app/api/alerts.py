"""Alert listing, acknowledgement, outbound webhooks and the live feed, which is served over both Server-Sent Events and a WebSocket."""
from __future__ import annotations

import asyncio
import json
import logging
import threading
import time
import uuid
from collections.abc import AsyncIterator
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Query, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import StreamingResponse
from pydantic import JsonValue
from starlette.types import Message

from ..config import Settings
from ..core.errors import NotFound
from ..database.case_manager import Store
from ..schemas import ENGINE_VERSION, Acknowledged, Alert, AnalysisResult
from .deps import MaskDep, StoreDep, mask_alert

log = logging.getLogger("mailtrace.api.alerts")

HEARTBEAT_SECONDS = 15.0
POLL_SECONDS = 1.0
SSE_HEADERS = {"Cache-Control": "no-cache", "X-Accel-Buffering": "no"}

# Stage 5B: outbound webhook alert streams.
WEBHOOK_EVENT = "mailtrace.alert"
WEBHOOK_TIMEOUT = 3.0          # seconds per POST: connect, write, read
WEBHOOK_WORKERS = 4            # hard ceiling on webhook threads
WEBHOOK_MAX_INFLIGHT = 64      # queued + running deliveries before shedding load
WEBHOOK_USER_AGENT = f"MailTrace/{ENGINE_VERSION}"


class Broadcaster:
    """Fan-out of alerts to live subscribers; ``publish`` is safe from any thread."""

    def __init__(self) -> None:
        self._loop: asyncio.AbstractEventLoop | None = None
        self._queues: set[asyncio.Queue[Alert]] = set()
        self._lock = threading.Lock()

    def bind(self, loop: asyncio.AbstractEventLoop) -> None:
        """Remember the event loop that owns the subscriber queues (called at startup)."""
        self._loop = loop

    def subscribe(self) -> asyncio.Queue[Alert]:
        queue: asyncio.Queue[Alert] = asyncio.Queue()
        with self._lock:
            self._queues.add(queue)
        return queue

    def unsubscribe(self, queue: asyncio.Queue[Alert]) -> None:
        with self._lock:
            self._queues.discard(queue)

    def subscriber_count(self) -> int:
        """Live SSE + WebSocket subscribers; a leak shows up here as a number that never falls."""
        with self._lock:
            return len(self._queues)

    def publish(self, alert: Alert) -> None:
        """Deliver ``alert`` to every subscriber; dropped silently when no loop is bound."""
        loop = self._loop
        if loop is None or loop.is_closed():
            return
        with self._lock:
            queues = list(self._queues)
        for queue in queues:
            try:
                loop.call_soon_threadsafe(queue.put_nowait, alert)
            except RuntimeError:  # loop closed between the check and the call
                return


broadcaster = Broadcaster()
router = APIRouter(prefix="/api/alerts", tags=["alerts"])


# Outbound webhooks
_webhook_lock = threading.Lock()
_webhook_pool: ThreadPoolExecutor | None = None
_webhook_inflight = 0


def case_url(email_id: str, settings: Settings) -> str:
    """Deep link to the case in the dashboard (the UI routes on ``#/email/<id>``)."""
    host = (settings.host or "127.0.0.1").strip()
    if host in {"0.0.0.0", "::", "[::]", ""}:
        host = "127.0.0.1"  # a wildcard bind is not an address anyone can click
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"  # bare IPv6 literal
    return f"http://{host}:{settings.port}/#/email/{email_id}"


def webhook_payload(alert: Alert, settings: Settings) -> dict[str, JsonValue]:
    """The alert as JSON, plus the ``event`` type and a link back to the case."""
    payload: dict[str, JsonValue] = json.loads(alert.model_dump_json())
    payload["event"] = WEBHOOK_EVENT
    payload["url"] = case_url(alert.email_id, settings)
    return payload


def deliver_webhooks(alert: Alert, settings: Settings) -> None:
    """POST ``alert`` to every configured webhook URL.  Blocking; never raises."""
    urls = [url for url in (settings.webhook_urls or []) if url]
    if not urls:
        return
    try:
        import httpx
    except ImportError:  # pragma: no cover - httpx is a hard dependency of the API
        log.warning("httpx is not installed; %d alert webhook(s) not delivered", len(urls))
        return
    payload = webhook_payload(alert, settings)
    headers = {"User-Agent": WEBHOOK_USER_AGENT, "X-MailTrace-Event": WEBHOOK_EVENT}
    try:
        with httpx.Client(timeout=WEBHOOK_TIMEOUT, follow_redirects=True) as client:
            for url in urls:
                try:
                    response = client.post(url, json=payload, headers=headers)
                except (httpx.HTTPError, httpx.InvalidURL) as exc:  # a dead endpoint is not our problem
                    log.warning("alert webhook %s failed for alert %s: %s", url, alert.id, exc)
                    continue
                if response.status_code >= 400:
                    log.warning("alert webhook %s returned HTTP %d for alert %s", url, response.status_code, alert.id)
                else:
                    log.info("alert %s delivered to webhook %s (HTTP %d)", alert.id, url, response.status_code)
    except Exception:  # alerting must never break analysis
        log.warning("alert webhook delivery for alert %s failed", alert.id, exc_info=True)


def dispatch_webhooks(alert: Alert, settings: Settings) -> None:
    """Hand the delivery to a background thread and return immediately."""
    global _webhook_pool, _webhook_inflight

    if not [url for url in (settings.webhook_urls or []) if url]:
        return
    with _webhook_lock:
        if _webhook_inflight >= WEBHOOK_MAX_INFLIGHT:
            log.warning(
                "alert webhook backlog is full (%d outstanding); dropping delivery for alert %s",
                _webhook_inflight, alert.id,
            )
            return
        if _webhook_pool is None:
            _webhook_pool = ThreadPoolExecutor(max_workers=WEBHOOK_WORKERS, thread_name_prefix="mt-webhook")
        pool = _webhook_pool
        _webhook_inflight += 1

    def run() -> None:
        global _webhook_inflight
        try:
            deliver_webhooks(alert, settings)
        finally:
            with _webhook_lock:
                _webhook_inflight -= 1

    try:
        pool.submit(run)
    except RuntimeError:  # pool shut down between the submit and the check (app stopping)
        with _webhook_lock:
            _webhook_inflight -= 1
        log.warning("alert webhook pool is shut down; alert %s not delivered", alert.id)


def shutdown_webhooks(wait: bool = False) -> None:
    """Release the webhook pool at shutdown; a later alert lazily creates a new one."""
    global _webhook_pool
    with _webhook_lock:
        pool, _webhook_pool = _webhook_pool, None
    if pool is not None:
        pool.shutdown(wait=wait, cancel_futures=not wait)


def maybe_alert(result: AnalysisResult, store: Store, settings: Settings) -> Alert | None:
    """Create, persist, broadcast and webhook an alert when the verdict reaches the threshold."""
    verdict = result.verdict
    if verdict.risk_score < settings.alert_threshold:
        return None
    sender = result.email.sender.address or result.email.sender.raw
    subject = " ".join(result.email.subject.split()) or "(no subject)"
    alert = Alert(
        id="alr-" + uuid.uuid4().hex[:8],
        created_at=datetime.now(UTC),
        email_id=result.id,
        subject=result.email.subject,
        sender=sender,
        category=verdict.category,
        risk_score=verdict.risk_score,
        severity=verdict.severity,
        message=(
            f"{verdict.category.value} ({verdict.severity.value}, risk {verdict.risk_score}/100) "
            f"from {sender or 'unknown sender'}: {subject}"
        ),
    )
    store.create_alert(alert)
    broadcaster.publish(alert)          # browsers watching /api/alerts/stream
    dispatch_webhooks(alert, settings)  # SIEM / Slack / any external system
    log.info("alert %s raised for email %s (%s, risk %d)", alert.id, result.id, verdict.category.value, verdict.risk_score)
    return alert


@router.get("")
def list_alerts(
    store: StoreDep,
    mask: MaskDep,
    limit: Annotated[int, Query(ge=1, le=500)] = 50,
    unacknowledged_only: Annotated[bool, Query()] = False,
) -> list[Alert]:
    alerts = store.list_alerts(limit=limit, unacknowledged_only=unacknowledged_only)
    return [mask_alert(alert) for alert in alerts] if mask else alerts


@router.get("/stream")
async def stream_alerts(request: Request, mask: MaskDep) -> StreamingResponse:
    """SSE feed: ``event: alert`` per new alert, ``: ping`` heartbeat every 15 s."""
    queue = broadcaster.subscribe()

    async def events() -> AsyncIterator[str]:
        last_write = time.monotonic()
        try:
            yield ": connected\n\n"
            while not await request.is_disconnected():
                try:
                    alert = await asyncio.wait_for(queue.get(), timeout=POLL_SECONDS)
                except TimeoutError:
                    if time.monotonic() - last_write < HEARTBEAT_SECONDS:
                        continue
                    chunk = ": ping\n\n"
                else:
                    payload = (mask_alert(alert) if mask else alert).model_dump_json()
                    chunk = f"event: alert\ndata: {payload}\n\n"
                yield chunk
                last_write = time.monotonic()
        finally:
            broadcaster.unsubscribe(queue)

    return StreamingResponse(events(), media_type="text/event-stream", headers=dict(SSE_HEADERS))


def _ws_mask(websocket: WebSocket) -> bool:
    """Resolve ``?mask=`` for a WebSocket the way ``mask_param`` does for HTTP."""
    raw = websocket.query_params.get("mask")
    if raw is None:
        settings = getattr(getattr(websocket.app, "state", None), "settings", None)
        return bool(getattr(settings, "pii_mask_default", False))
    return raw.strip().lower() in {"1", "true", "yes", "on"}


@router.websocket("/ws")
async def alerts_websocket(websocket: WebSocket) -> None:
    """Live alert feed over a WebSocket: one text frame of Alert JSON per alert."""
    mask = _ws_mask(websocket)
    await websocket.accept()
    queue = broadcaster.subscribe()
    alert_task: asyncio.Task[Alert] | None = None
    receive_task: asyncio.Task[Message] | None = None
    try:
        alert_task = asyncio.create_task(queue.get())
        receive_task = asyncio.create_task(websocket.receive())
        while True:
            done, _ = await asyncio.wait({alert_task, receive_task}, return_when=asyncio.FIRST_COMPLETED)
            if receive_task in done:
                if receive_task.result().get("type") == "websocket.disconnect":
                    break
                receive_task = asyncio.create_task(websocket.receive())
            if alert_task in done:
                alert = alert_task.result()
                alert_task = asyncio.create_task(queue.get())
                await websocket.send_text((mask_alert(alert) if mask else alert).model_dump_json())
    except WebSocketDisconnect:
        log.debug("alert websocket closed by the client")
    except RuntimeError:  # send/receive after the transport is already gone
        log.debug("alert websocket transport closed mid-send", exc_info=True)
    except Exception:  # a broken client must not surface as a 500
        log.warning("alert websocket failed", exc_info=True)
    finally:
        for task in (alert_task, receive_task):
            if task is not None:
                task.cancel()
        broadcaster.unsubscribe(queue)


@router.post("/{alert_id}/ack")
def acknowledge_alert(alert_id: str, store: StoreDep) -> Acknowledged:
    if not store.acknowledge_alert(alert_id):
        raise NotFound(f"alert {alert_id} not found")
    return Acknowledged()
