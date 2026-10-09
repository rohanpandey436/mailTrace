from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.database.case_manager import Store
from app.main import create_app


def test_queries_recover_after_the_connection_is_lost(store: Store) -> None:
    before = store.stats().total_emails
    store._live.close()

    assert store.stats().total_emails == before
    assert store.ping() == ""


def test_ping_reports_a_database_that_stays_down(store: Store, monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse() -> object:
        raise RuntimeError("database unreachable")

    monkeypatch.setattr(store._dialect, "connect", refuse)
    monkeypatch.setattr(store._dialect, "is_broken", lambda conn: True)

    note = store.ping()

    assert note.startswith("RuntimeError: database unreachable")


def test_health_shows_the_database_note(cfg: Settings, monkeypatch: pytest.MonkeyPatch) -> None:
    app = create_app(cfg)
    with TestClient(app) as client:
        store = app.state.store
        assert client.get("/api/health").json()["database_note"] == store.backend_note
        monkeypatch.setattr(store, "ping", lambda: "OperationalError: the connection is closed")

        health = client.get("/api/health").json()

    assert health["database_note"] == "OperationalError: the connection is closed"
