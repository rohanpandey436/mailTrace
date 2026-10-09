from __future__ import annotations

import logging
import threading
import time
from collections import OrderedDict
from typing import Protocol

from pydantic import JsonValue

log = logging.getLogger("mailtrace.cache")


class CacheBackend(Protocol):

    def cache_get(self, key: str) -> JsonValue | None: ...

    def cache_set(self, key: str, value: object, ttl_seconds: int) -> None: ...


class MemoryCache:

    def __init__(self, max_entries: int = 2048) -> None:
        self._max_entries = max(1, int(max_entries))
        self._entries: OrderedDict[str, tuple[float, JsonValue]] = OrderedDict()
        self._lock = threading.Lock()

    def __len__(self) -> int:
        with self._lock:
            return len(self._entries)

    def cache_get(self, key: str) -> JsonValue | None:
        with self._lock:
            entry = self._entries.get(key)
            if entry is None:
                return None
            expires_at, value = entry
            if expires_at < time.time():
                del self._entries[key]
                return None
            self._entries.move_to_end(key)
            return value

    def cache_set(self, key: str, value: object, ttl_seconds: int) -> None:
        from pydantic import TypeAdapter

        try:
            stored: JsonValue = TypeAdapter(JsonValue).validate_python(value)
        except ValueError:
            return
        with self._lock:
            self._entries[key] = (time.time() + float(ttl_seconds), stored)
            self._entries.move_to_end(key)
            while len(self._entries) > self._max_entries:
                self._entries.popitem(last=False)

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()


def cache_get(store: CacheBackend | None, key: str) -> JsonValue | None:
    if store is None:
        return None
    try:
        return store.cache_get(key)
    except Exception:
        log.debug("cache read failed for %s", key, exc_info=True)
        return None


def cache_set(store: CacheBackend | None, key: str, value: object, ttl_seconds: int) -> None:
    if store is None:
        return
    try:
        store.cache_set(key, value, int(ttl_seconds))
    except Exception:
        log.debug("cache write failed for %s", key, exc_info=True)
