from __future__ import annotations

import calendar
import logging
import threading
from collections.abc import Callable
from datetime import UTC, datetime

import httpx

from .config import Settings

log = logging.getLogger("mailtrace.keepawake")

PING_TIMEOUT_SECONDS = 20.0


def _fetch(url: str) -> int:
    return httpx.get(url, timeout=PING_TIMEOUT_SECONDS, follow_redirects=True).status_code


def _utc_now() -> datetime:
    return datetime.now(UTC)


def resting(moment: datetime, rest_days: int) -> bool:
    if rest_days <= 0:
        return False
    last_day = calendar.monthrange(moment.year, moment.month)[1]
    return moment.day > last_day - rest_days


class KeepAwake:

    def __init__(
        self,
        url: str,
        *,
        seconds: float,
        rest_days: int,
        fetch: Callable[[str], int] = _fetch,
        now: Callable[[], datetime] = _utc_now,
    ) -> None:
        self.target = f"{url.rstrip('/')}/api/health"
        self._seconds = seconds
        self._rest_days = rest_days
        self._fetch = fetch
        self._now = now
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._last = "no ping sent yet"

    @classmethod
    def from_settings(cls, cfg: Settings) -> KeepAwake | None:
        if not cfg.keepawake_url:
            return None
        return cls(cfg.keepawake_url, seconds=cfg.keepawake_seconds, rest_days=cfg.keepawake_rest_days)

    def tick(self) -> None:
        moment = self._now()
        if resting(moment, self._rest_days):
            self._last = "resting until the 1st to stay inside the free monthly hours"
            return
        stamp = moment.strftime("%Y-%m-%d %H:%M UTC")
        try:
            status = self._fetch(self.target)
        except Exception as exc:
            self._last = f"last ping failed at {stamp} ({type(exc).__name__})"
            log.warning("keep-awake ping to %s failed: %s", self.target, exc)
            return
        self._last = f"last ping answered {status} at {stamp}"

    def _run(self) -> None:
        while not self._stop.wait(self._seconds):
            self.tick()

    def start(self) -> None:
        if self._thread is not None:
            return
        self._thread = threading.Thread(target=self._run, name="mt-keep-awake", daemon=True)
        self._thread.start()
        log.info("keep-awake requests %s every %d s", self.target, int(self._seconds))

    def stop(self) -> None:
        self._stop.set()

    def summary(self) -> str:
        return f"every {int(self._seconds)} s; {self._last}"
