"""
Read-through cache shared by every enrichment engine.

GeoIP, DNS, WHOIS, blocklist and VirusTotal answers are cached in the
``Store`` so a second message from the same server costs no second round
trip.  The cache is an optimisation and nothing more: when there is no store
(a bare ``analyze_bytes`` call from a test or a CLI), when the entry is
missing, or when the database itself is unavailable, the engines simply do
the lookup.  That is why the two helpers here never raise.  The store may be
SQLite or PostgreSQL, whose error hierarchies differ and neither of which is
allowed to interrupt an analysis, so the guard is deliberately broad and
lives in exactly one place.
"""
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
