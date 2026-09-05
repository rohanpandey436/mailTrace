"""
Reverse DNS: the three outcomes, and what each is allowed to cache.

This exists because the distinction is invisible until you measure it. A PTR
lookup has three results, not two: a name, "there is no PTR", and "the resolver
never answered". Collapsing the last two into "" meant a timeout was treated as
a fact that could not be cached, so every message from an address without a PTR
paid the full lookup timeout again - measured at four seconds per analysis on
the deployed service, for a supplementary signal.
"""
from __future__ import annotations

import socket
import time

import pytest

from app.core import geoip_mapper
from app.database.case_manager import Store

NO_PTR_IP = "45.148.10.72"


@pytest.fixture
def net_cfg(cfg):
    """The offline test settings, with network enabled for these two functions.

    Nothing here reaches the network: socket.gethostbyaddr is always replaced.
    The flag only gets past the guard at the top of reverse_dns.
    """
    cfg.enable_network = True
    return cfg


def test_a_name_is_returned_lowercase(net_cfg, monkeypatch):
    monkeypatch.setattr(socket, "gethostbyaddr", lambda ip: ("DNS.Google.", [], [ip]))
    assert geoip_mapper.reverse_dns("8.8.8.8", net_cfg) == "dns.google"


def test_no_ptr_is_an_answer_not_a_failure(net_cfg, monkeypatch):
    """The resolver saying "no PTR" is a fact, reported as ""."""

    def no_ptr(ip: str) -> tuple[str, list[str], list[str]]:
        raise socket.herror(11004, "host not found")

    monkeypatch.setattr(socket, "gethostbyaddr", no_ptr)
    assert geoip_mapper.reverse_dns(NO_PTR_IP, net_cfg) == ""


def test_a_timeout_is_not_an_answer(net_cfg, monkeypatch):
    """A resolver that never replies must be reported as None, not as ""."""

    def hang(ip: str) -> tuple[str, list[str], list[str]]:
        time.sleep(30)
        raise AssertionError("should have been abandoned long before this")

    monkeypatch.setattr(socket, "gethostbyaddr", hang)
    started = time.monotonic()
    assert geoip_mapper.reverse_dns(NO_PTR_IP, net_cfg) is None
    elapsed = time.monotonic() - started
    # Capped independently of lookup_timeout, which the fixture leaves higher.
    assert elapsed < 3, f"waited {elapsed:.1f}s; the PTR cap is {geoip_mapper._RDNS_TIMEOUT_SECONDS}s"


def test_the_ptr_cap_ignores_a_larger_lookup_budget(net_cfg):
    """A generous global budget must not become a generous PTR wait."""
    net_cfg.lookup_timeout = 30.0
    assert geoip_mapper._rdns_timeout(net_cfg) == geoip_mapper._RDNS_TIMEOUT_SECONDS
    # ...but a stricter global budget still wins.
    net_cfg.lookup_timeout = 0.4
    assert geoip_mapper._rdns_timeout(net_cfg) == pytest.approx(0.4)


def test_no_ptr_is_cached_so_it_is_looked_up_once(net_cfg, tmp_path, monkeypatch):
    """The whole point: a second message from the same origin must not re-stall."""
    store = Store(tmp_path / "cache.db", tmp_path / "evidence")
    calls = []

    def no_ptr(ip: str) -> tuple[str, list[str], list[str]]:
        calls.append(ip)
        raise socket.herror(11004, "host not found")

    monkeypatch.setattr(socket, "gethostbyaddr", no_ptr)
    try:
        assert geoip_mapper._cached_reverse_dns(NO_PTR_IP, net_cfg, store) == ""
        assert geoip_mapper._cached_reverse_dns(NO_PTR_IP, net_cfg, store) == ""
        assert geoip_mapper._cached_reverse_dns(NO_PTR_IP, net_cfg, store) == ""
    finally:
        store.close()
    assert calls == [NO_PTR_IP], f"the resolver was consulted {len(calls)} times, expected once"


def test_a_timeout_is_cached_only_briefly(net_cfg, tmp_path, monkeypatch):
    """A timeout still gets remembered, or a burst of mail re-stalls on each message.

    It is remembered for minutes rather than hours, because it records "we could
    not find out" and not "there is no PTR".
    """
    store = Store(tmp_path / "cache.db", tmp_path / "evidence")
    written: list[tuple[str, object, int]] = []
    real_cache_set = geoip_mapper.cache_set

    def record(target_store: object, key: str, value: object, ttl: int) -> None:
        written.append((key, value, ttl))
        real_cache_set(target_store, key, value, ttl)  # type: ignore[arg-type]

    monkeypatch.setattr(geoip_mapper, "cache_set", record)
    monkeypatch.setattr(geoip_mapper, "reverse_dns", lambda ip, cfg: None)
    try:
        assert geoip_mapper._cached_reverse_dns(NO_PTR_IP, net_cfg, store) == ""
        assert geoip_mapper._cached_reverse_dns(NO_PTR_IP, net_cfg, store) == ""
    finally:
        store.close()

    assert len(written) == 1, "the timeout should have been cached once, then read back"
    key, value, ttl = written[0]
    assert key == f"rdns:{NO_PTR_IP}"
    assert value == ""
    assert ttl == geoip_mapper._RDNS_TIMEOUT_TTL_SECONDS
    assert ttl < net_cfg.cache_ttl_seconds, "a timeout must expire sooner than a real answer"
