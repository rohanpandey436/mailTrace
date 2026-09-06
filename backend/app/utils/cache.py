"""Read-through cache shared by every enrichment engine."""
from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from pydantic import JsonValue

if TYPE_CHECKING:  # pragma: no cover
    from ..database.case_manager import Store

log = logging.getLogger("mailtrace.cache")


def cache_get(store: Store | None, key: str) -> JsonValue | None:
    """The cached value for ``key``; None when there is no store, no entry or no answer."""
    if store is None:
        return None
    try:
        return store.cache_get(key)
    except Exception:  # see the module docstring
        log.debug("cache read failed for %s", key, exc_info=True)
        return None


def cache_set(store: Store | None, key: str, value: object, ttl_seconds: int) -> None:
    """Remember ``value`` under ``key`` for ``ttl_seconds``; silently a no-op without a store."""
    if store is None:
        return
    try:
        store.cache_set(key, value, int(ttl_seconds))
    except Exception:  # see the module docstring
        log.debug("cache write failed for %s", key, exc_info=True)
