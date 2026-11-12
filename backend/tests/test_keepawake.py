from __future__ import annotations

import threading
from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.keepawake import KeepAwake, resting
from app.main import create_app

NOON = datetime(2026, 11, 12, 10, 0, tzinfo=UTC)


def _keeper(calls: list[str], moment: datetime, rest_days: int = 3) -> KeepAwake:
    def fetch(url: str) -> int:
        calls.append(url)
        return 200

    return KeepAwake("https://mailtrace.test/", seconds=600, rest_days=rest_days, fetch=fetch, now=lambda: moment)


def test_a_tick_requests_the_public_health_address() -> None:
    calls: list[str] = []
    keeper = _keeper(calls, NOON)

    keeper.tick()

    assert calls == ["https://mailtrace.test/api/health"]
    assert keeper.summary() == "every 600 s; last ping answered 200 at 2026-11-12 10:00 UTC"


@pytest.mark.parametrize(
    ("moment", "expected"),
    [
        (datetime(2026, 11, 27, 23, 59, tzinfo=UTC), False),
        (datetime(2026, 11, 28, tzinfo=UTC), True),
        (datetime(2026, 11, 30, 23, 59, tzinfo=UTC), True),
        (datetime(2026, 12, 1, tzinfo=UTC), False),
        (datetime(2026, 12, 28, tzinfo=UTC), False),
        (datetime(2026, 12, 29, tzinfo=UTC), True),
        (datetime(2027, 2, 25, tzinfo=UTC), False),
        (datetime(2027, 2, 26, tzinfo=UTC), True),
    ],
)
def test_the_last_three_days_of_a_month_are_rest_days(moment: datetime, expected: bool) -> None:
    assert resting(moment, 3) is expected


def test_no_request_is_sent_on_a_rest_day() -> None:
    calls: list[str] = []
    keeper = _keeper(calls, datetime(2026, 11, 29, 9, 0, tzinfo=UTC))

    keeper.tick()

    assert calls == []
    assert keeper.summary() == "every 600 s; resting until the 1st to stay inside the free monthly hours"


def test_rest_days_can_be_switched_off() -> None:
    calls: list[str] = []
    keeper = _keeper(calls, datetime(2026, 11, 30, 9, 0, tzinfo=UTC), rest_days=0)

    keeper.tick()

    assert len(calls) == 1


def test_a_failed_request_is_reported_and_does_not_raise() -> None:
    def fetch(url: str) -> int:
        raise ConnectionError("no route")

    keeper = KeepAwake("https://mailtrace.test", seconds=600, rest_days=3, fetch=fetch, now=lambda: NOON)

    keeper.tick()

    assert keeper.summary() == "every 600 s; last ping failed at 2026-11-12 10:00 UTC (ConnectionError)"


def test_the_background_thread_keeps_requesting_until_stopped() -> None:
    twice = threading.Event()
    calls: list[str] = []

    def fetch(url: str) -> int:
        calls.append(url)
        if len(calls) >= 2:
            twice.set()
        return 200

    keeper = KeepAwake("https://mailtrace.test", seconds=0.01, rest_days=0, fetch=fetch)
    keeper.start()
    try:
        assert twice.wait(5)
    finally:
        keeper.stop()


def test_it_stays_off_without_a_public_address(cfg: Settings) -> None:
    assert KeepAwake.from_settings(cfg) is None
    with TestClient(create_app(cfg)) as client:
        assert client.get("/api/health").json()["keep_awake"] == "off"


def test_health_reports_the_keeper_when_an_address_is_set(cfg: Settings) -> None:
    cfg.keepawake_url = "https://mailtrace.test"
    with TestClient(create_app(cfg)) as client:
        assert client.get("/api/health").json()["keep_awake"] == "every 600 s; no ping sent yet"


def test_it_is_off_until_an_address_is_set(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("MAILTRACE_KEEPAWAKE_URL", raising=False)
    monkeypatch.setenv("RENDER_EXTERNAL_URL", "https://mailtrace.onrender.test")
    assert Settings.from_env().keepawake_url == ""

    monkeypatch.setenv("MAILTRACE_KEEPAWAKE_URL", "https://mailtrace.onrender.test/")
    assert Settings.from_env().keepawake_url == "https://mailtrace.onrender.test"

    monkeypatch.setenv("MAILTRACE_KEEPAWAKE_URL", "off")
    assert Settings.from_env().keepawake_url == ""


def test_the_dashboard_is_always_revalidated(cfg: Settings) -> None:
    with TestClient(create_app(cfg)) as client:
        assert client.get("/").headers["cache-control"] == "no-cache"
        assert client.get("/js/main.js").headers["cache-control"] == "no-cache"
