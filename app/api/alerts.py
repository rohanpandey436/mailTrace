"""
Alert listing, acknowledgement and the live Server-Sent-Events stream.

``Broadcaster`` is a tiny in-process fan-out: every SSE client owns an
``asyncio.Queue``; ``publish`` may be called from worker threads (the analysis
pipeline runs in a thread pool) and hops onto the event loop captured at
startup with ``call_soon_threadsafe``.  ``maybe_alert`` is the single place
that turns a finished analysis into a persisted, broadcast alert once the
verdict crosses the configured risk threshold.
"""
from __future__ import annotations

import asyncio
import logging
import threading
import time
import uuid
from datetime import datetime, timezone
from typing import Any, AsyncIterator, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import StreamingResponse

from ..config import Settings
from ..db import Store
from ..schemas import Alert, AnalysisResult
from .deps import get_store, mask_alert, mask_param

log = logging.getLogger("mailtrace.api.alerts")

HEARTBEAT_SECONDS = 15.0
POLL_SECONDS = 1.0
SSE_HEADERS = {"Cache-Control": "no-cache", "X-Accel-Buffering": "no"}


class Broadcaster:
    """Fan-out of alerts to SSE subscribers; ``publish`` is safe from any thread."""

    def __init__(self) -> None:
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._queues: set[asyncio.Queue] = set()
        self._lock = threading.Lock()

    def bind(self, loop: asyncio.AbstractEventLoop) -> None:
        """Remember the event loop that owns the subscriber queues (called at startup)."""
        self._loop = loop

    def subscribe(self) -> asyncio.Queue:
        queue: asyncio.Queue = asyncio.Queue()
        with self._lock:
            self._queues.add(queue)
        return queue

    def unsubscribe(self, queue: asyncio.Queue) -> None:
        with self._lock:
            self._queues.discard(queue)

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


def maybe_alert(result: AnalysisResult, store: Store, settings: Settings) -> Optional[Alert]:
    """Create, persist and broadcast an alert when the verdict reaches the threshold."""
    verdict = result.verdict
    if verdict.risk_score < settings.alert_threshold:
        return None
    sender = result.email.sender.address or result.email.sender.raw
    subject = " ".join(result.email.subject.split()) or "(no subject)"
    alert = Alert(
        id="alr-" + uuid.uuid4().hex[:8],
        created_at=datetime.now(timezone.utc),
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
    broadcaster.publish(alert)
    log.info("alert %s raised for email %s (%s, risk %d)", alert.id, result.id, verdict.category.value, verdict.risk_score)
    return alert


@router.get("")
def list_alerts(
    limit: int = Query(50, ge=1, le=500),
    unacknowledged_only: bool = Query(False),
    mask: bool = Depends(mask_param),
    store: Store = Depends(get_store),
) -> list[Alert]:
    alerts = store.list_alerts(limit=limit, unacknowledged_only=unacknowledged_only)
    return [mask_alert(alert) for alert in alerts] if mask else alerts


@router.get("/stream")
async def stream_alerts(request: Request, mask: bool = Depends(mask_param)) -> StreamingResponse:
    """SSE feed: ``event: alert`` per new alert, ``: ping`` heartbeat every 15 s.

    The queue is polled in short slices so a vanished client is noticed within
    a second and the stream ends cleanly instead of failing on its next write.
    """
    queue = broadcaster.subscribe()

    async def events() -> AsyncIterator[str]:
        last_write = time.monotonic()
        try:
            yield ": connected\n\n"
            while not await request.is_disconnected():
                try:
                    alert = await asyncio.wait_for(queue.get(), timeout=POLL_SECONDS)
                except asyncio.TimeoutError:
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


@router.post("/{alert_id}/ack")
def acknowledge_alert(alert_id: str, store: Store = Depends(get_store)) -> dict[str, Any]:
    if not store.acknowledge_alert(alert_id):
        raise HTTPException(status_code=404, detail=f"alert {alert_id} not found")
    return {"ok": True}
