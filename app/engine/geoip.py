"""
IP geolocation and infrastructure intelligence.

Approach
--------
MailTrace ships no local GeoIP database (nothing to license, download or keep
current).  Every public IP in the Received chain is resolved through the free
ip-api.com JSON endpoint and enriched with reverse DNS, the Tor bulk exit list,
DNS blocklists (DNSBL) and, when a key is configured, AbuseIPDB.  Lookups are
cached through the Store (``geo:<ip>``, ``rdns:<ip>``, ``dnsbl:<ip>``,
``abuse:<ip>``, ``tor:list``), bounded by ``cfg.lookup_timeout`` and never
raise into the pipeline; with ``cfg.enable_network`` off every function still
returns complete objects tagged ``source="offline"``.

``analyze_infrastructure`` enriches the originating IP fully (DNSBL and
AbuseIPDB included) and the remaining public hops lightly, writes each GeoInfo
into ``hop.geo`` in place, then derives the infrastructure flags (Tor exit,
VPN/proxy, hosting provider, blocklists, suspected open relay, botnet-style
delivery), a 0..1 score and analyst-readable findings.
"""
from __future__ import annotations

import ipaddress
import logging
import math
import re
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import TYPE_CHECKING, Any, Optional

import httpx

from ..config import Settings
from ..schemas import Finding, GeoInfo, HeaderAnalysis, Hop, InfraAnalysis, Severity
from .knowledge import DNSBL_ZONES

if TYPE_CHECKING:  # pragma: no cover
    from ..db import Store

log = logging.getLogger("mailtrace.geoip")

MODULE = "geoip"
IP_API_URL = (
    "http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,regionName,"
    "city,lat,lon,isp,org,as,reverse,mobile,proxy,hosting,query"
)
TOR_EXIT_LIST_URL = "https://check.torproject.org/torbulkexitlist"
ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
HTTP_HEADERS: dict[str, str] = {"User-Agent": "MailTrace/1.0"}
TOR_LIST_TTL_SECONDS = 3600
TOR_RETRY_SECONDS = 300  # back-off before re-trying a failed exit-list download

# GeoInfo.source values proving the lookup layer actually answered for the IP.
_RESOLVED_SOURCES = {"ip-api", "cache"}

# RFC 6598 shared address space (CGNAT) is not covered by ipaddress.is_private.
_SHARED_ADDRESS_SPACE = ipaddress.ip_network("100.64.0.0/10")
# A DNSBL listing always answers inside 127.0.0.0/8; Spamhaus reserves
# 127.255.255.0/24 for error codes (blocked resolver, query limit exceeded).
_DNSBL_ANSWER_SPACE = ipaddress.ip_network("127.0.0.0/8")
_DNSBL_ERROR_SPACE = ipaddress.ip_network("127.255.255.0/24")

_AS_RE = re.compile(r"^(AS\d+)\s*(.*)$", re.IGNORECASE)
_TOR_RDNS_RE = re.compile(r"tor-?exit|torexit|tor-?node|torservers|torproject", re.IGNORECASE)
_VPN_RE = re.compile(
    r"nordvpn|expressvpn|mullvad|protonvpn|surfshark|privateinternetaccess|private internet access|"
    r"cyberghost|ipvanish|windscribe|torguard|vpn|proxy",
    re.IGNORECASE,
)
_HOSTING_RE = re.compile(
    r"digitalocean|amazon|\baws\b|google cloud|microsoft azure|\bazure\b|\bovh|hetzner|linode|vultr|"
    r"contabo|choopa|leaseweb|\bm247\b|hostinger|godaddy|namecheap|cloudflare|hosting|datacent|"
    r"data center|\bvps\b|colocation",
    re.IGNORECASE,
)
_TLS_HINT_RE = re.compile(r"\bTLS|\bSSL|version=TLS|cipher=", re.IGNORECASE)
_AUTH_HINT_RE = re.compile(r"\bESMTPS?A\b|authenticat", re.IGNORECASE)
# Dynamic / residential PTR naming (deliberately excludes "static").
_RESIDENTIAL_RDNS_RE = re.compile(
    r"dsl|dyn|pool|ppp|cable|dhcp|broadband|customer|cust-|res-|resid|dialup|dial-up|fib(?:er|re)|mobile|wireless",
    re.IGNORECASE,
)
# Auto-generated PTR names that carry no operator identity.
_GENERIC_RDNS_RE = re.compile(
    r"(?:^|[.-])(?:ip|host|static|node|vps|srv|server|vm|ec2)-?\d|"
    r"unknown|no-?rdns|unassigned|localhost|in-addr\.arpa",
    re.IGNORECASE,
)
_RESIDENTIAL_ISP_RE = re.compile(
    r"broadband|telecom|telekom|cable|\bdsl\b|fib(?:er|re)|wireless|mobile|cellular|\bisp\b|residential|"
    r"infocomm|\bjio\b|airtel|bsnl|vodafone|\bmtn\b|comcast|charter|spectrum|\bcox\b|frontier|centurylink|"
    r"virgin media|telenor|\borange\b|telefonica|beeline|rostelecom",
    re.IGNORECASE,
)
# Major mail services whose egress ranges ip-api labels "hosting".  A match needs
# BOTH the ASN owner (isp/org) and the PTR suffix; an attacker on rented
# infrastructure cannot forge the two together.
_MAIL_SERVICE_EGRESS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("google", ("google.com", "googlemail.com")),
    ("microsoft", ("outlook.com", "hotmail.com")),
    ("yahoo", ("yahoo.com", "yahoodns.net")),
    ("amazon", ("amazonses.com",)),
    ("sendgrid", ("sendgrid.net",)),
    ("mailgun", ("mailgun.org", "mailgun.net")),
    ("zoho", ("zoho.com", "zohomail.com")),
    ("proton", ("protonmail.ch", "proton.me")),
    ("apple", ("icloud.com", "apple.com")),
    ("mimecast", ("mimecast.com",)),
    ("proofpoint", ("pphosted.com", "ppe-hosted.com")),
)

_TOR_LOCK = threading.Lock()
_tor_memo: tuple[float, set[str]] = (0.0, set())  # (monotonic expiry, exit IPs)


# --------------------------------------------------------------------------- #
# Small utilities
# --------------------------------------------------------------------------- #
def _parse_ip(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """Parse an IP literal as written in headers ('[1.2.3.4]', '[IPv6:::1]');
    IPv4-mapped IPv6 collapses to the IPv4 address.  None when not an address."""
    text = (value or "").strip().strip("[]")
    if text.lower().startswith("ipv6:"):
        text = text[5:]
    try:
        addr = ipaddress.ip_address(text)
    except ValueError:
        return None
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        return addr.ipv4_mapped
    return addr


def _normalize_ip(value: str) -> str:
    addr = _parse_ip(value)
    return str(addr) if addr is not None else ""


def _timeout(cfg: Settings) -> float:
    return cfg.lookup_timeout if cfg.lookup_timeout > 0 else 3.0


def _clamp(value: float) -> float:
    if math.isnan(value):
        return 0.0
    return max(0.0, min(1.0, value))


def _text(value: Any) -> str:
    return "" if value is None else str(value).strip()


def _number(value: Any) -> Optional[float]:
    if value is None or isinstance(value, bool):
        return None
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return number if math.isfinite(number) else None


def _cache_get(store: Optional["Store"], key: str) -> Any:
    if store is None:
        return None
    try:
        return store.cache_get(key)
    except Exception:  # noqa: BLE001 - a cache problem must never block enrichment
        log.debug("cache read failed for %s", key, exc_info=True)
        return None


def _cache_set(store: Optional["Store"], key: str, value: Any, ttl_seconds: int) -> None:
    if store is None:
        return
    try:
        store.cache_set(key, value, int(ttl_seconds))
    except Exception:  # noqa: BLE001
        log.debug("cache write failed for %s", key, exc_info=True)


def _http_get(
    url: str,
    cfg: Settings,
    params: Optional[dict[str, str]] = None,
    headers: Optional[dict[str, str]] = None,
) -> Optional[httpx.Response]:
    """One bounded GET; None on any transport error."""
    merged = dict(HTTP_HEADERS)
    if headers:
        merged.update(headers)
    try:
        with httpx.Client(timeout=_timeout(cfg), headers=merged, follow_redirects=True) as client:
            return client.get(url, params=params)
    except Exception:  # noqa: BLE001 - timeouts, DNS failures, TLS errors, ...
        log.debug("GET %s failed", url, exc_info=True)
        return None


def _private_geo(ip: str) -> GeoInfo:
    return GeoInfo(ip=ip, is_private=True, source="private")


def _registrable(host: str) -> str:
    """Registrable domain of a host name; '' for empty, 'unknown' and IP literals."""
    text = host.strip().strip("[]").rstrip(".").lower()
    if not text or text == "unknown" or _parse_ip(text) is not None:
        return ""
    try:
        from .urls import registrable_domain  # sibling module; degrade to a heuristic if unavailable

        return registrable_domain(text)
    except Exception:  # noqa: BLE001
        return ".".join(text.split(".")[-2:])


# --------------------------------------------------------------------------- #
# Public lookups
# --------------------------------------------------------------------------- #
def is_public_ip(ip: str) -> bool:
    """True for globally routable unicast addresses (IPv4 or IPv6)."""
    addr = _parse_ip(ip)
    if addr is None or addr in _SHARED_ADDRESS_SPACE:
        return False
    return not (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_reserved
        or addr.is_unspecified
    )


def reverse_dns(ip: str, cfg: Settings) -> str:
    """Reverse (PTR) name of an IP, lowercase; '' when there is none or on failure.

    ``socket.gethostbyaddr`` has no timeout of its own, so it runs on a worker
    thread whose result we stop waiting for after ``cfg.lookup_timeout``.  A
    stalled resolver thread may linger briefly but never blocks the pipeline.
    """
    ip = _normalize_ip(ip)
    if not ip or not cfg.enable_network:
        return ""
    executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="mt-rdns")
    try:
        host = executor.submit(socket.gethostbyaddr, ip).result(timeout=_timeout(cfg))[0]
    except Exception:  # noqa: BLE001 - herror/gaierror (no PTR), timeout, resolver errors
        log.debug("reverse DNS for %s failed or timed out", ip)
        return ""
    finally:
        executor.shutdown(wait=False)
    host = host.strip().rstrip(".").lower()
    return "" if host == ip else host


def _split_as(value: Any) -> tuple[str, str]:
    """'AS15169 Google LLC' -> ('AS15169', 'Google LLC')."""
    text = _text(value)
    match = _AS_RE.match(text)
    if match is None:
        return "", text
    return match.group(1).upper(), match.group(2).strip()


def _geo_from_ip_api(ip: str, payload: dict[str, Any]) -> GeoInfo:
    asn, as_org = _split_as(payload.get("as"))
    return GeoInfo(
        ip=ip,
        country=_text(payload.get("country")),
        country_code=_text(payload.get("countryCode")).upper(),
        region=_text(payload.get("regionName")),
        city=_text(payload.get("city")),
        lat=_number(payload.get("lat")),
        lon=_number(payload.get("lon")),
        isp=_text(payload.get("isp")),
        org=_text(payload.get("org")) or as_org,
        asn=asn,
        reverse_dns=_text(payload.get("reverse")).rstrip(".").lower(),
        is_proxy=bool(payload.get("proxy", False)),
        is_hosting=bool(payload.get("hosting", False)),
        is_mobile=bool(payload.get("mobile", False)),
        source="ip-api",
    )


def geolocate(ip: str, cfg: Settings, store: Optional["Store"]) -> GeoInfo:
    """Geolocate one IP through ip-api.com (cached as ``geo:<ip>``).

    Private addresses yield ``source="private"``, offline mode ``"offline"``,
    any failure (transport error, HTTP 429 rate limit, ``status != success``)
    ``"unavailable"``; a cache hit is tagged ``"cache"``.
    """
    normalized = _normalize_ip(ip)
    if not normalized:
        return GeoInfo(ip=_text(ip), source="unavailable")
    ip = normalized
    if not is_public_ip(ip):
        return _private_geo(ip)
    if not cfg.enable_network:
        return GeoInfo(ip=ip, source="offline")

    key = f"geo:{ip}"
    cached = _cache_get(store, key)
    if isinstance(cached, dict):
        try:
            geo = GeoInfo.model_validate(cached)
        except Exception:  # noqa: BLE001 - corrupt cache entry: fall through to a live lookup
            log.debug("ignoring malformed cache entry %s", key)
        else:
            geo.source = "cache"
            return geo

    response = _http_get(IP_API_URL.format(ip=ip), cfg)
    if response is None:
        return GeoInfo(ip=ip, source="unavailable")
    if response.status_code != 200:
        log.warning("ip-api returned HTTP %s for %s", response.status_code, ip)
        return GeoInfo(ip=ip, source="unavailable")
    try:
        payload = response.json()
    except Exception:  # noqa: BLE001
        log.debug("ip-api returned a non-JSON body for %s", ip)
        return GeoInfo(ip=ip, source="unavailable")
    if not isinstance(payload, dict) or payload.get("status") != "success":
        log.debug("ip-api could not geolocate %s: %r", ip, payload)
        return GeoInfo(ip=ip, source="unavailable")

    geo = _geo_from_ip_api(ip, payload)
    _cache_set(store, key, geo.model_dump(mode="json"), cfg.cache_ttl_seconds)
    return geo


def _download_tor_exit_list(cfg: Settings) -> set[str]:
    response = _http_get(TOR_EXIT_LIST_URL, cfg)
    if response is None or response.status_code != 200:
        return set()
    exits: set[str] = set()
    for line in response.text.splitlines():
        ip = _normalize_ip(line.split("#", 1)[0])
        if ip:
            exits.add(ip)
    log.info("loaded %d Tor exit addresses", len(exits))
    return exits


def tor_exit_ips(cfg: Settings, store: Optional["Store"]) -> set[str]:
    """Current Tor exit addresses: module memo -> Store cache (``tor:list``, 1 h)
    -> download.  Empty offline or when the list cannot be fetched (retried
    after a short back-off).  Callers must not mutate the returned set."""
    global _tor_memo
    if not cfg.enable_network:
        return set()
    with _TOR_LOCK:  # one download even when several IPs are enriched concurrently
        expires, exits = _tor_memo
        now = time.monotonic()
        if now < expires:
            return exits
        cached = _cache_get(store, "tor:list")
        if isinstance(cached, list) and cached:
            exits = {str(item) for item in cached}
            _tor_memo = (now + TOR_LIST_TTL_SECONDS, exits)
            return exits
        exits = _download_tor_exit_list(cfg)
        if exits:
            _cache_set(store, "tor:list", sorted(exits), TOR_LIST_TTL_SECONDS)
            _tor_memo = (now + TOR_LIST_TTL_SECONDS, exits)
        else:
            _tor_memo = (now + TOR_RETRY_SECONDS, set())
        return exits


def _dnsbl_hit(answer_text: str) -> bool:
    addr = _parse_ip(answer_text)
    return addr is not None and addr in _DNSBL_ANSWER_SPACE and addr not in _DNSBL_ERROR_SPACE


def dnsbl_check(ip: str, cfg: Settings, store: Optional["Store"]) -> list[str]:
    """Zones of knowledge.DNSBL_ZONES that list this IPv4 address (cached as
    ``dnsbl:<ip>``).  NXDOMAIN means "not listed"; any other DNS problem is
    treated the same way."""
    ip = _normalize_ip(ip)
    if not ip or ":" in ip or not is_public_ip(ip) or not cfg.enable_network or not DNSBL_ZONES:
        return []
    key = f"dnsbl:{ip}"
    cached = _cache_get(store, key)
    if isinstance(cached, list):
        return [str(zone) for zone in cached]
    try:
        import dns.resolver  # dnspython; lazy so a missing package only disables DNSBL checks

        resolver = dns.resolver.Resolver(configure=True)
    except Exception:  # noqa: BLE001 - ImportError or no usable resolver configuration
        log.debug("DNSBL checks unavailable", exc_info=True)
        return []
    lifetime = _timeout(cfg)
    resolver.timeout = lifetime
    resolver.lifetime = lifetime
    reversed_octets = ".".join(reversed(ip.split(".")))

    def listed_in(zone: str) -> bool:
        try:
            answer = resolver.resolve(f"{reversed_octets}.{zone}", "A", lifetime=lifetime)
        except Exception:  # noqa: BLE001 - NXDOMAIN (not listed), timeout, SERVFAIL, ...
            return False
        return any(_dnsbl_hit(rdata.to_text()) for rdata in answer)

    with ThreadPoolExecutor(max_workers=len(DNSBL_ZONES), thread_name_prefix="mt-dnsbl") as pool:
        hits = list(pool.map(listed_in, DNSBL_ZONES))
    listed = [zone for zone, hit in zip(DNSBL_ZONES, hits) if hit]
    _cache_set(store, key, listed, cfg.cache_ttl_seconds)
    return listed


def abuseipdb_check(ip: str, cfg: Settings, store: Optional["Store"]) -> Optional[int]:
    """AbuseIPDB abuse-confidence score (0-100) when ``cfg.abuseipdb_key`` is
    set (cached as ``abuse:<ip>``); None otherwise or on any failure."""
    ip = _normalize_ip(ip)
    if not ip or not cfg.abuseipdb_key or not cfg.enable_network or not is_public_ip(ip):
        return None
    key = f"abuse:{ip}"
    cached = _cache_get(store, key)
    if isinstance(cached, int) and not isinstance(cached, bool):
        return cached
    response = _http_get(
        ABUSEIPDB_URL,
        cfg,
        params={"ipAddress": ip, "maxAgeInDays": "90"},
        headers={"Key": cfg.abuseipdb_key, "Accept": "application/json"},
    )
    if response is None or response.status_code != 200:
        return None
    try:
        score = int(response.json()["data"]["abuseConfidenceScore"])
    except Exception:  # noqa: BLE001 - non-JSON body or unexpected shape
        return None
    score = max(0, min(100, score))
    _cache_set(store, key, score, cfg.cache_ttl_seconds)
    return score


def _cached_reverse_dns(ip: str, cfg: Settings, store: Optional["Store"]) -> str:
    """PTR name through the Store cache.  Only real names are cached: an empty
    result may be a resolver timeout rather than a missing PTR."""
    key = f"rdns:{ip}"
    cached = _cache_get(store, key)
    if isinstance(cached, str) and cached:
        return cached
    host = reverse_dns(ip, cfg)
    if host:
        _cache_set(store, key, host, cfg.cache_ttl_seconds)
    return host


def enrich_ip(ip: str, cfg: Settings, store: Optional["Store"], full: bool) -> GeoInfo:
    """geolocate + reverse DNS + Tor check; ``full`` adds DNSBL and AbuseIPDB
    (used for the originating IP only).  Private IPs come back untouched."""
    geo = geolocate(ip, cfg, store)
    if geo.is_private or not is_public_ip(geo.ip):
        return geo
    if not geo.reverse_dns and cfg.enable_network:  # ip-api's "reverse" field saves the PTR lookup
        geo.reverse_dns = _cached_reverse_dns(geo.ip, cfg, store)
    geo.is_tor_exit = geo.ip in tor_exit_ips(cfg, store) or bool(_TOR_RDNS_RE.search(geo.reverse_dns))
    if full:
        geo.blacklists = dnsbl_check(geo.ip, cfg, store)
        geo.abuse_confidence = abuseipdb_check(geo.ip, cfg, store)
    return geo


# --------------------------------------------------------------------------- #
# Infrastructure analysis
# --------------------------------------------------------------------------- #
def _public_ips_in_order(header_analysis: HeaderAnalysis, origin: str) -> list[str]:
    """Unique public IPs worth enriching: origin first, then the hops in
    chronological order, then X-Originating-IP."""
    candidates = [origin, *(hop.from_ip for hop in header_analysis.hops), header_analysis.x_originating_ip]
    ordered: list[str] = []
    for candidate in candidates:
        ip = _normalize_ip(candidate)
        if ip and is_public_ip(ip) and ip not in ordered:
            ordered.append(ip)
    return ordered


def _enrich_many(targets: list[str], origin: str, cfg: Settings, store: Optional["Store"]) -> dict[str, GeoInfo]:
    if not targets:
        return {}
    results: dict[str, GeoInfo] = {}
    with ThreadPoolExecutor(max_workers=min(4, len(targets)), thread_name_prefix="mt-geoip") as pool:
        futures = {ip: pool.submit(enrich_ip, ip, cfg, store, ip == origin) for ip in targets}
        for ip, future in futures.items():
            try:
                results[ip] = future.result()
            except Exception:  # noqa: BLE001 - one failed lookup must not sink the others
                log.exception("enrichment of %s failed", ip)
                results[ip] = GeoInfo(ip=ip, source="unavailable")
    return results


def _provider_text(geo: GeoInfo) -> str:
    return f"{geo.isp} {geo.org} {geo.reverse_dns}"


def _is_mail_service_egress(geo: GeoInfo) -> bool:
    owner = f"{geo.isp} {geo.org}".lower()
    rdns = geo.reverse_dns.lower()
    for keyword, suffixes in _MAIL_SERVICE_EGRESS:
        if keyword in owner and any(rdns == suffix or rdns.endswith("." + suffix) for suffix in suffixes):
            return True
    return False


def _plain_smtp_hop(hop: Hop) -> bool:
    """Handed over as plain (E)SMTP: no TLS and no SMTP AUTH."""
    if "no_tls" in hop.anomalies:
        return True
    tokens = hop.protocol.upper().split()
    protocol = tokens[0] if tokens else ""
    return protocol in {"SMTP", "ESMTP"} and not _TLS_HINT_RE.search(hop.raw) and not _AUTH_HINT_RE.search(hop.raw)


def _generic_rdns(rdns: str, ip: str) -> bool:
    """Auto-generated PTR (embeds the address, 'host-12', 'static-...') or a residential pool name."""
    name = rdns.lower()
    octets = ip.split(".")
    if len(octets) == 4:
        forms = ("-".join(octets), ".".join(octets), "-".join(reversed(octets)), ".".join(reversed(octets)))
        if any(form in name for form in forms):
            return True
    return bool(_RESIDENTIAL_RDNS_RE.search(name) or _GENERIC_RDNS_RE.search(name))


def _anonymous_host(geo: GeoInfo) -> bool:
    """No usable reverse DNS.  A missing PTR only counts once ip-api actually
    answered for this IP, so an offline run or a resolver timeout is never
    mistaken for anonymity."""
    if geo.reverse_dns:
        return _generic_rdns(geo.reverse_dns, geo.ip)
    return geo.source in _RESOLVED_SOURCES


def _open_relay_hops(hops: list[Hop]) -> list[Hop]:
    """Public, non-internal hops that accepted the message over plain SMTP from
    a host in another domain that is anonymous or blocklisted."""
    suspects: list[Hop] = []
    for hop in hops:
        geo = hop.geo
        if geo is None or geo.is_private or hop.is_internal or not _plain_smtp_hop(hop):
            continue
        by_domain = _registrable(hop.by_host)
        if not by_domain or _registrable(hop.from_host) == by_domain:
            continue
        if geo.blacklists or _anonymous_host(geo):
            suspects.append(hop)
    return suspects


def _residential_origin(geo: GeoInfo) -> bool:
    if geo.is_hosting:
        return False
    return bool(
        geo.is_mobile
        or _RESIDENTIAL_ISP_RE.search(f"{geo.isp} {geo.org}")
        or _RESIDENTIAL_RDNS_RE.search(geo.reverse_dns)
    )


def _delivered_direct_to_mx(hops: list[Hop], origin_index: Optional[int]) -> bool:
    """From the origin hop onward every receiving server is on the recipient
    side (internal, or in the final MX's registrable domain): the sender spoke
    to the destination MX itself instead of submitting through a mail provider."""
    if origin_index is None or not 0 <= origin_index < len(hops):
        return False
    origin_hop = hops[origin_index]
    if _AUTH_HINT_RE.search(origin_hop.raw) or _AUTH_HINT_RE.search(origin_hop.protocol):
        return False  # authenticated submission = a real account at a mail provider
    final_domain = _registrable(hops[-1].by_host)
    for hop in hops[origin_index:]:
        by_domain = _registrable(hop.by_host)
        if not (hop.is_internal or (by_domain and by_domain == final_domain)):
            return False
    return True


def _botnet_indicators(header_analysis: HeaderAnalysis, origin_geo: Optional[GeoInfo]) -> list[str]:
    if origin_geo is None or origin_geo.is_private:
        return []
    hops = header_analysis.hops
    index = header_analysis.originating_hop_index
    origin_hop = hops[index] if index is not None and 0 <= index < len(hops) else None
    rdns = origin_geo.reverse_dns
    dynamic_rdns = bool(rdns and _RESIDENTIAL_RDNS_RE.search(rdns))
    indicators: list[str] = []
    if dynamic_rdns and origin_geo.blacklists:
        zones = ", ".join(origin_geo.blacklists)
        indicators.append(
            f"Origin reverse DNS '{rdns}' looks like a dynamic/residential address and the IP is listed on {zones}."
        )
    if dynamic_rdns and origin_hop is not None and _plain_smtp_hop(origin_hop):
        indicators.append(
            f"Origin reverse DNS '{rdns}' looks like a dynamic/residential address and the message was handed "
            "over without TLS or authentication."
        )
    if _residential_origin(origin_geo) and _delivered_direct_to_mx(hops, index):
        provider = origin_geo.isp or origin_geo.org or "a consumer ISP"
        indicators.append(
            f"Origin {origin_geo.ip} sits on a residential/mobile network ({provider}) and delivered the message "
            "straight to the recipient's mail server, bypassing any mail provider."
        )
    return indicators


# --------------------------------------------------------------------------- #
# Findings
# --------------------------------------------------------------------------- #
def _finding(fid: str, severity: Severity, title: str, detail: str, evidence: dict[str, Any]) -> Finding:
    return Finding(id=fid, module=MODULE, severity=severity, title=title, detail=detail, evidence=evidence)


def _geo_evidence(geo: GeoInfo) -> dict[str, Any]:
    return {
        "ip": geo.ip,
        "city": geo.city,
        "region": geo.region,
        "country": geo.country,
        "country_code": geo.country_code,
        "isp": geo.isp,
        "org": geo.org,
        "asn": geo.asn,
        "reverse_dns": geo.reverse_dns,
        "lat": geo.lat,
        "lon": geo.lon,
        "source": geo.source,
    }


def _origin_finding(geo: GeoInfo) -> Finding:
    place = ", ".join(part for part in (geo.city, geo.region, geo.country) if part) or "an unknown location"
    provider = geo.isp or geo.org or "an unknown network"
    asn = f" ({geo.asn})" if geo.asn else ""
    detail = f"The originating IP {geo.ip} is located in {place} and announced by {provider}{asn}."
    if geo.reverse_dns:
        detail += f" Reverse DNS: {geo.reverse_dns}."
    return _finding("origin_geolocated", Severity.INFO, "Origin IP geolocated", detail, _geo_evidence(geo))


def _geo_unavailable_finding(origin: str, origin_geo: Optional[GeoInfo], hops: list[Hop]) -> Finding:
    if not origin:
        detail = (
            "No public originating IP could be identified from the Received chain, so the sender could not be "
            "geolocated."
            if hops
            else "The message carries no Received headers, so there is no routing information to geolocate."
        )
    elif origin_geo is None:
        detail = (
            f"The originating IP {origin} was not geolocated because geolocation lookups are disabled "
            "(max_geo_lookups)."
        )
    elif origin_geo.is_private:
        detail = f"The originating IP {origin} is a private/internal address and has no public geolocation."
    elif origin_geo.source == "offline":
        detail = f"Network enrichment is disabled, so the originating IP {origin} was not geolocated."
    else:
        detail = f"The geolocation service could not resolve {origin} (timeout, rate limit or lookup failure)."
    evidence = {
        "originating_ip": origin,
        "source": origin_geo.source if origin_geo is not None else "",
        "hops": len(hops),
    }
    return _finding("geo_unavailable", Severity.INFO, "Origin geolocation unavailable", detail, evidence)


def _relay_finding(relay_hops: list[Hop]) -> Finding:
    evidence = [
        {
            "hop": hop.index,
            "from_ip": hop.from_ip,
            "from_host": hop.from_host,
            "by_host": hop.by_host,
            "protocol": hop.protocol,
            "reverse_dns": hop.geo.reverse_dns if hop.geo is not None else "",
            "blacklists": hop.geo.blacklists if hop.geo is not None else [],
        }
        for hop in relay_hops
    ]
    first = evidence[0]
    identity = first["reverse_dns"] or "a host without reverse DNS"
    detail = (
        f"Hop {first['hop']} ({first['by_host']}) accepted the message over plain, unauthenticated SMTP from "
        f"{first['from_ip']} ({identity}), which suggests an open relay or an abused mail server."
    )
    return _finding(
        "open_relay_suspected",
        Severity.HIGH,
        "Unauthenticated relay accepted mail from an anonymous host",
        detail,
        {"hops": evidence},
    )


def _trail_finding(hops: list[Hop]) -> Optional[Finding]:
    trail: list[dict[str, Any]] = []
    for hop in hops:
        geo = hop.geo
        if geo is not None and geo.country_code:
            trail.append({"hop": hop.index, "ip": geo.ip, "country_code": geo.country_code, "city": geo.city})
    if not trail:
        return None
    codes = [str(step["country_code"]) for step in trail]
    countries = list(dict.fromkeys(codes))
    path = " → ".join(codes)
    if len(countries) > 1:
        detail = (
            f"The message passed through {len(trail)} geolocated relay(s) across {len(countries)} countries "
            f"({path}); multi-country routing is worth checking against the claimed sender location."
        )
    else:
        detail = f"All {len(trail)} geolocated relay(s) are in {countries[0]} ({path})."
    return _finding(
        "hop_geo_trail", Severity.INFO, "Geographic routing trail", detail, {"trail": trail, "countries": countries}
    )


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #
def analyze_infrastructure(header_analysis: HeaderAnalysis, cfg: Settings, store: Optional["Store"]) -> InfraAnalysis:
    """Enrich the public IPs of the Received chain (``hop.geo`` is set in
    place), then derive infrastructure flags, score and findings."""
    hops = header_analysis.hops
    origin = _normalize_ip(header_analysis.originating_ip)
    public_ips = _public_ips_in_order(header_analysis, origin)
    enriched = _enrich_many(public_ips[: max(0, cfg.max_geo_lookups)], origin, cfg, store)

    for hop in hops:
        ip = _normalize_ip(hop.from_ip)
        if ip in enriched:
            hop.geo = enriched[ip]
        elif ip and not is_public_ip(ip):
            hop.geo = _private_geo(ip)
        # a public hop beyond the lookup budget keeps geo=None

    origin_geo: Optional[GeoInfo] = None
    if origin in enriched:
        origin_geo = enriched[origin]
    elif origin and not is_public_ip(origin):
        origin_geo = _private_geo(origin)

    # Flags -----------------------------------------------------------------
    tor_exit = origin_geo is not None and origin_geo.is_tor_exit
    vpn_match = _VPN_RE.search(_provider_text(origin_geo)) if origin_geo is not None else None
    # ip-api marks the egress ranges of the big mail providers as proxies, which
    # would label every genuine Gmail or Microsoft 365 message a VPN. Only trust
    # the proxy flag when the address is not a recognised mail-service egress.
    vpn_or_proxy = (
        origin_geo is not None
        and not _is_mail_service_egress(origin_geo)
        and (origin_geo.is_proxy or vpn_match is not None)
    )
    hosting_match = _HOSTING_RE.search(_provider_text(origin_geo)) if origin_geo is not None else None
    hosting_provider = (
        origin_geo is not None
        and not _is_mail_service_egress(origin_geo)
        and (origin_geo.is_hosting or hosting_match is not None)
    )
    listed = {geo.ip: geo.blacklists for geo in enriched.values() if geo.blacklists}
    abuse = origin_geo.abuse_confidence if origin_geo is not None else None
    abuse_high = abuse is not None and abuse >= 50
    blacklisted = bool(listed) or abuse_high
    relay_hops = _open_relay_hops(hops)
    botnet = _botnet_indicators(header_analysis, origin_geo)
    private_only = (origin_geo is not None and origin_geo.is_private) or (bool(hops) and not public_ips)

    # Score: the strongest signal plus 0.1 for every additional one ---------
    signals: list[float] = []
    if tor_exit:
        signals.append(0.9)
    if blacklisted:
        signals.append(0.9 if abuse is not None and abuse >= 80 else 0.8)
    if vpn_or_proxy:
        signals.append(0.5)
    if hosting_provider:
        signals.append(0.35)
    if relay_hops:
        signals.append(0.5)
    if botnet:
        signals.append(0.6)
    if private_only:
        signals.append(0.1)
    score = _clamp(max(signals) + 0.1 * (len(signals) - 1)) if signals else 0.0

    # Findings --------------------------------------------------------------
    findings: list[Finding] = []
    if origin_geo is not None:
        provider = origin_geo.isp or origin_geo.org or "unknown provider"
        if tor_exit:
            rdns_hit = _TOR_RDNS_RE.search(origin_geo.reverse_dns) is not None
            matched_by = "reverse DNS pattern" if rdns_hit else "Tor bulk exit list"
            findings.append(
                _finding(
                    "tor_exit_node",
                    Severity.CRITICAL,
                    "Origin IP is a Tor exit node",
                    f"The originating IP {origin_geo.ip} is a Tor exit node, which anonymises the real sender and is "
                    "almost never used for legitimate business email.",
                    {"ip": origin_geo.ip, "reverse_dns": origin_geo.reverse_dns, "matched_by": matched_by},
                )
            )
        if abuse_high:
            findings.append(
                _finding(
                    "abuseipdb_high",
                    Severity.HIGH,
                    "AbuseIPDB reports abuse from the origin IP",
                    f"AbuseIPDB gives {origin_geo.ip} an abuse confidence of {abuse}% from reports in the "
                    "last 90 days.",
                    {"ip": origin_geo.ip, "abuse_confidence": abuse},
                )
            )
        if vpn_or_proxy:
            findings.append(
                _finding(
                    "vpn_or_proxy_origin",
                    Severity.MEDIUM,
                    "Origin IP is a VPN or proxy egress",
                    f"{origin_geo.ip} ({provider}) is a VPN/proxy endpoint, so the real location of the sender "
                    "is hidden.",
                    {
                        "ip": origin_geo.ip,
                        "isp": origin_geo.isp,
                        "org": origin_geo.org,
                        "ip_api_proxy": origin_geo.is_proxy,
                        "matched": vpn_match.group(0) if vpn_match is not None else "",
                    },
                )
            )
        if hosting_provider:
            findings.append(
                _finding(
                    "hosting_provider_origin",
                    Severity.MEDIUM,
                    "Origin IP belongs to a hosting provider",
                    f"{origin_geo.ip} is allocated to a hosting/cloud provider ({provider}) rather than a mail service "
                    "or consumer ISP, a pattern typical of attacker-controlled infrastructure.",
                    {
                        "ip": origin_geo.ip,
                        "isp": origin_geo.isp,
                        "org": origin_geo.org,
                        "asn": origin_geo.asn,
                        "ip_api_hosting": origin_geo.is_hosting,
                        "matched": hosting_match.group(0) if hosting_match is not None else "",
                    },
                )
            )
    if listed:
        zones = sorted({zone for zone_list in listed.values() for zone in zone_list})
        zone_text = ", ".join(zones)
        ip_text = ", ".join(listed)
        findings.append(
            _finding(
                "ip_blacklisted",
                Severity.HIGH,
                "Origin IP listed on DNS blocklists",
                f"{ip_text} is listed on {len(zones)} DNS blocklist(s): {zone_text}. Listed addresses are known "
                "sources of spam or malware.",
                {"listed": listed},
            )
        )
    if relay_hops:
        findings.append(_relay_finding(relay_hops))
    if botnet:
        findings.append(
            _finding(
                "botnet_indicator",
                Severity.HIGH,
                "Botnet-style delivery indicators",
                " ".join(botnet[:2]),
                {"indicators": botnet, "origin_ip": origin_geo.ip if origin_geo is not None else ""},
            )
        )
    if origin_geo is not None and origin_geo.source in _RESOLVED_SOURCES:
        findings.append(_origin_finding(origin_geo))
    else:
        findings.append(_geo_unavailable_finding(origin, origin_geo, hops))
    trail = _trail_finding(hops)
    if trail is not None:
        findings.append(trail)

    return InfraAnalysis(
        origin_geo=origin_geo,
        tor_exit=tor_exit,
        vpn_or_proxy=vpn_or_proxy,
        hosting_provider=hosting_provider,
        blacklisted=blacklisted,
        open_relay_suspected=bool(relay_hops),
        botnet_indicators=botnet,
        score=score,
        findings=findings,
    )
