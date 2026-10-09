from __future__ import annotations

import ipaddress
import logging
import re
import threading

from fastapi import APIRouter, HTTPException
from fastapi.concurrency import run_in_threadpool

from ..config import Settings
from ..core import domain_intel, geoip_mapper, threat_intel
from ..core.link_analyzer import registrable_domain
from ..schemas import (
    DomainIntel,
    DomainTarget,
    GeoInfo,
    IntelLookupRequest,
    IntelLookupResponse,
    IntelMatchRequest,
    IntelMatchResponse,
)
from ..utils.cache import MemoryCache
from .deps import SettingsDep, StoreDep

log = logging.getLogger("mailtrace.api.intel")

router = APIRouter(prefix="/api/intel", tags=["intel"])

_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z0-9-]{2,63}$")
_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
_SIMHASH_RE = re.compile(r"^[0-9a-f]{16}$")

_cache_lock = threading.Lock()
_cache: MemoryCache | None = None


def lookup_cache(settings: Settings) -> MemoryCache:
    global _cache
    with _cache_lock:
        if _cache is None:
            _cache = MemoryCache(settings.intel_cache_entries)
        return _cache


def reset_cache() -> None:
    global _cache
    with _cache_lock:
        _cache = None


def _too_many(name: str, count: int, limit: int) -> HTTPException:
    return HTTPException(status_code=413, detail=f"{count} {name} in one request; the limit is {limit}")


def _domain_targets(items: list[DomainTarget], settings: Settings) -> list[tuple[str, str]]:
    if len(items) > settings.intel_max_domains:
        raise _too_many("domains", len(items), settings.intel_max_domains)
    targets: list[tuple[str, str]] = []
    seen: set[str] = set()
    for item in items:
        name = item.domain.strip().lower().rstrip(".")
        if not _DOMAIN_RE.match(name):
            raise HTTPException(status_code=422, detail=f"'{item.domain[:80]}' is not a domain name")
        domain = registrable_domain(name) or name
        if domain in seen:
            continue
        seen.add(domain)
        targets.append((domain, item.role))
    return targets


def _address(value: str) -> str:
    text = value.strip().strip("[]")
    try:
        return str(ipaddress.ip_address(text))
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=f"'{value[:80]}' is not an IP address") from exc


def _addresses(items: list[str], origin: str, settings: Settings) -> tuple[list[str], str]:
    if len(items) > settings.intel_max_ips:
        raise _too_many("IP addresses", len(items), settings.intel_max_ips)
    addresses = list(dict.fromkeys(_address(item) for item in items if item.strip()))
    return addresses, _address(origin) if origin.strip() else ""


def _lookup(
    targets: list[tuple[str, str]], addresses: list[str], origin: str, settings: Settings
) -> tuple[list[DomainIntel], list[GeoInfo]]:
    cache = lookup_cache(settings)
    domains = domain_intel.analyze_domains(targets, settings, cache)
    geos = geoip_mapper.enrich_addresses(addresses, origin, settings, cache)
    return domains, geos


@router.post("/lookup")
async def lookup(request: IntelLookupRequest, settings: SettingsDep) -> IntelLookupResponse:
    targets = _domain_targets(request.domains, settings)
    addresses, origin = _addresses(request.ips, request.origin_ip, settings)
    domains, geos = await run_in_threadpool(_lookup, targets, addresses, origin, settings)
    return IntelLookupResponse(domains=domains, ips=geos, network=settings.enable_network)


@router.post("/match")
async def match(request: IntelMatchRequest, store: StoreDep, settings: SettingsDep) -> IntelMatchResponse:
    if len(request.fingerprints) > settings.intel_max_fingerprints:
        raise _too_many("fingerprints", len(request.fingerprints), settings.intel_max_fingerprints)
    digests: list[str] = []
    for item in request.fingerprints:
        digest = item.strip().lower()
        if not _DIGEST_RE.match(digest):
            raise HTTPException(status_code=422, detail="every fingerprint must be a SHA-256 digest in hex")
        digests.append(digest)
    simhash = request.simhash.strip().lower()
    if simhash and not _SIMHASH_RE.match(simhash):
        raise HTTPException(status_code=422, detail="simhash must be 16 hex characters")
    incidents, campaigns = await run_in_threadpool(
        threat_intel.match_digests, store, digests, simhash, request.body_length, settings
    )
    return IntelMatchResponse(
        incidents=incidents,
        campaigns=campaigns,
        worst_risk=max((incident.risk_score for incident in incidents), default=0),
    )
