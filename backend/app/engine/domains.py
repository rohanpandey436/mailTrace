"""
Domain intelligence: registration age, DNS posture, hosting fingerprint,
reputation feeds and lookalike detection for every domain an email touches.

Approach
--------
* ``collect_domains`` decides *which* domains matter (sender, Reply-To,
  Return-Path, Message-ID, then link hosts by risk) and caps the lookups.
* ``whois_lookup`` speaks the WHOIS protocol directly over port 43 (registry
  table with an IANA referral fallback) and parses the half-dozen date and
  registrar spellings registries use.
* ``dns_lookup`` gathers A / MX / NS / SPF / DMARC with dnspython.
* ``domain_reputation`` queries URLhaus and applies local tags (disposable
  provider, abuse-prone TLD).
* ``analyze_domain`` fuses those into a ``DomainIntel`` with findings.

Every network call is optional (``cfg.enable_network``), bounded by
``cfg.lookup_timeout``, cached through the store when one is supplied and
wrapped so a failure yields a partial record instead of an exception.
"""
from __future__ import annotations

import ipaddress
import logging
import re
import socket
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Optional

from ..config import Settings
from ..schemas import DomainIntel, Finding, HeaderAnalysis, ParsedEmail, Severity, UrlAnalysis
from .knowledge import COMMON_URL_HOSTS, DISPOSABLE_DOMAINS, FREEMAIL_DOMAINS, SUSPICIOUS_TLDS
from .urls import is_lookalike, registrable_domain

if TYPE_CHECKING:  # pragma: no cover
    from ..db import Store

log = logging.getLogger("mailtrace.domains")

_WHOIS_SERVERS: dict[str, str] = {
    "com": "whois.verisign-grs.com", "net": "whois.verisign-grs.com", "cc": "ccwhois.verisign-grs.com",
    "tv": "whois.nic.tv", "org": "whois.pir.org", "in": "whois.registry.in", "io": "whois.nic.io",
    "info": "whois.nic.info", "biz": "whois.nic.biz", "xyz": "whois.nic.xyz", "top": "whois.nic.top",
    "icu": "whois.nic.icu", "online": "whois.nic.online", "site": "whois.nic.site", "uk": "whois.nic.uk",
    "de": "whois.denic.de", "ru": "whois.tcinet.ru", "me": "whois.nic.me", "co": "whois.nic.co",
    "us": "whois.nic.us", "app": "whois.nic.google", "dev": "whois.nic.google", "shop": "whois.nic.shop",
    "store": "whois.nic.store", "club": "whois.nic.club", "live": "whois.nic.live", "tech": "whois.nic.tech",
    "buzz": "whois.nic.buzz", "cloud": "whois.nic.cloud", "link": "whois.nic.link", "click": "whois.nic.click",
    "sbi": "whois.nic.sbi", "bank": "whois.nic.bank", "ai": "whois.nic.ai", "eu": "whois.eu",
    "nl": "whois.domain-registry.nl", "fr": "whois.nic.fr", "au": "whois.auda.org.au", "ca": "whois.cira.ca",
    "sg": "whois.sgnic.sg", "ae": "whois.aeda.net.ae", "pk": "whois.pknic.net.pk", "lk": "whois.nic.lk",
}
_BANK_BRANDS: frozenset[str] = frozenset({
    "sbi", "onlinesbi", "hdfc", "hdfcbank", "icici", "icicibank", "axisbank", "kotak", "pnb", "bankofbaroda",
    "canarabank", "paytm", "phonepe", "npci", "rbi", "chase", "wellsfargo", "bankofamerica", "hsbc", "citibank",
    "coinbase", "binance", "paypal",
})
_TZ_SUFFIX_RE = re.compile(r"(?:Z|UTC|GMT|[+-]\d{2}:?\d{2})$", re.IGNORECASE)
_DATE_FORMATS = (
    "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d", "%d-%b-%Y",
    "%d-%b-%Y %H:%M:%S", "%Y.%m.%d", "%Y.%m.%d %H:%M:%S", "%Y%m%d", "%d.%m.%Y", "%Y/%m/%d",
    "%b %d %Y", "%d %b %Y", "%Y-%m-%dT%H:%M:%S%z",
)
_CREATED_RE = re.compile(
    r"^\s*(?:Creation Date|Created On|Created Date|Registered on|Registered|created|Registration Time|"
    r"Creation date|Domain Registration Date|Registration Date|Domain Create Date)\s*:\s*(.+?)\s*$",
    re.IGNORECASE | re.MULTILINE,
)
_EXPIRES_RE = re.compile(
    r"^\s*(?:Registry Expiry Date|Expiration Date|Expiry date|Expiry Date|paid-till|expires|Expiration Time|"
    r"Domain Expiration Date|Registrar Registration Expiration Date)\s*:\s*(.+?)\s*$",
    re.IGNORECASE | re.MULTILINE,
)
_REGISTRAR_RE = re.compile(r"^\s*(?:Sponsoring )?Registrar(?: Name)?\s*:\s*(.+?)\s*$", re.IGNORECASE | re.MULTILINE)
_COUNTRY_RE = re.compile(r"^\s*Registrant Country\s*:\s*(.+?)\s*$", re.IGNORECASE | re.MULTILINE)
_NS_RE = re.compile(r"^\s*(?:Name Server|nserver)\s*:\s*(\S+)", re.IGNORECASE | re.MULTILINE)
_REFER_RE = re.compile(r"^\s*(?:whois|refer)\s*:\s*(\S+)", re.IGNORECASE | re.MULTILINE)
_WHOIS_MAX_BYTES = 64 * 1024


# --------------------------------------------------------------------------- #
# Small helpers
# --------------------------------------------------------------------------- #
def _timeout(cfg: Settings) -> float:
    try:
        return max(0.5, float(cfg.lookup_timeout))
    except (TypeError, ValueError):
        return 3.0


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _cache_get(store: Optional["Store"], key: str) -> Any:
    if store is None:
        return None
    try:
        return store.cache_get(key)
    except Exception:  # noqa: BLE001
        return None


def _cache_set(store: Optional["Store"], key: str, value: Any, ttl: int) -> None:
    if store is None:
        return
    try:
        store.cache_set(key, value, ttl)
    except Exception:  # noqa: BLE001
        log.debug("cache_set failed for %s", key, exc_info=True)


def _parse_whois_date(value: str) -> Optional[datetime]:
    text = (value or "").strip()
    if not text:
        return None
    text = text.split("(")[0].strip()
    text = _TZ_SUFFIX_RE.sub("", text).strip()
    for fmt in _DATE_FORMATS:
        try:
            parsed = datetime.strptime(text, fmt)
        except ValueError:
            continue
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    match = re.match(r"^(\d{4})-(\d{2})-(\d{2})", text)
    if match:
        try:
            return datetime(int(match.group(1)), int(match.group(2)), int(match.group(3)), tzinfo=timezone.utc)
        except ValueError:
            return None
    return None


def _from_iso(value: Any) -> Optional[datetime]:
    if not value or not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


# --------------------------------------------------------------------------- #
# WHOIS
# --------------------------------------------------------------------------- #
def _whois_query(server: str, query: str, timeout: float) -> str:
    chunks: list[bytes] = []
    total = 0
    with socket.create_connection((server, 43), timeout=timeout) as sock:
        sock.settimeout(timeout)
        sock.sendall((query + "\r\n").encode("utf-8", errors="ignore"))
        while total < _WHOIS_MAX_BYTES:
            chunk = sock.recv(4096)
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
    return b"".join(chunks).decode("utf-8", errors="replace")


def _whois_server_for(domain: str, cfg: Settings, store: Optional["Store"]) -> str:
    labels = domain.split(".")
    tld = labels[-1]
    if len(labels) >= 3 and ".".join(labels[-2:]) in _WHOIS_SERVERS:
        return _WHOIS_SERVERS[".".join(labels[-2:])]
    if tld in _WHOIS_SERVERS:
        return _WHOIS_SERVERS[tld]
    cache_key = f"whois_server:{tld}"
    cached = _cache_get(store, cache_key)
    if isinstance(cached, str) and cached:
        return cached
    try:
        response = _whois_query("whois.iana.org", tld, _timeout(cfg))
    except (OSError, ValueError):
        return ""
    match = _REFER_RE.search(response)
    server = match.group(1).strip().lower() if match else ""
    if server:
        _cache_set(store, cache_key, server, 7 * 24 * 3600)
    return server


def whois_lookup(domain: str, cfg: Settings, store: Optional["Store"]) -> dict:
    """Registration facts for ``domain`` as a JSON-safe dict; ``{}`` on failure."""
    if not cfg.enable_network or not domain or _is_ip(domain):
        return {}
    cache_key = f"whois:{domain}"
    cached = _cache_get(store, cache_key)
    if isinstance(cached, dict):
        return dict(cached, cached=True)
    server = _whois_server_for(domain, cfg, store)
    if not server:
        return {}
    query = f"={domain}" if server.endswith("verisign-grs.com") else domain
    try:
        text = _whois_query(server, query, _timeout(cfg))
    except (OSError, ValueError) as exc:
        log.debug("whois %s via %s failed: %s", domain, server, exc)
        return {}
    created = _CREATED_RE.search(text)
    expires = _EXPIRES_RE.search(text)
    registrar = _REGISTRAR_RE.search(text)
    country = _COUNTRY_RE.search(text)
    lowered = text.lower()
    if not created and ("no match" in lowered or "not found" in lowered or "no data found" in lowered):
        result = {"registered": False, "server": server}
        _cache_set(store, cache_key, result, cfg.cache_ttl_seconds)
        return result
    created_dt = _parse_whois_date(created.group(1)) if created else None
    expires_dt = _parse_whois_date(expires.group(1)) if expires else None
    result = {
        "registered": True,
        "server": server,
        "created": created_dt.isoformat() if created_dt else "",
        "expires": expires_dt.isoformat() if expires_dt else "",
        "registrar": registrar.group(1).strip()[:120] if registrar else "",
        "registrant_country": country.group(1).strip()[:60] if country else "",
        "name_servers": sorted({m.group(1).strip().lower().rstrip(".") for m in _NS_RE.finditer(text)})[:8],
    }
    _cache_set(store, cache_key, result, cfg.cache_ttl_seconds)
    return result


# --------------------------------------------------------------------------- #
# DNS
# --------------------------------------------------------------------------- #
def dns_lookup(domain: str, cfg: Settings, store: Optional["Store"]) -> dict:
    """A / MX / NS / SPF / DMARC records; ``{}`` when offline or unavailable."""
    if not cfg.enable_network or not domain or _is_ip(domain):
        return {}
    cache_key = f"dns:{domain}"
    cached = _cache_get(store, cache_key)
    if isinstance(cached, dict):
        return dict(cached, cached=True)
    try:
        import dns.exception
        import dns.resolver
    except ImportError:
        log.warning("dnspython not installed; DNS intelligence disabled")
        return {}
    resolver = dns.resolver.Resolver(configure=True)
    resolver.timeout = _timeout(cfg)
    resolver.lifetime = _timeout(cfg)
    result: dict[str, Any] = {"a": [], "mx": [], "ns": [], "txt_spf": "", "dmarc": "", "nxdomain": False, "queried": True}

    def query(name: str, rtype: str) -> list:
        try:
            return list(resolver.resolve(name, rtype))
        except dns.resolver.NXDOMAIN:
            if rtype == "A" and name == domain:
                result["nxdomain"] = True
            return []
        except (dns.exception.DNSException, OSError, ValueError):
            return []

    result["a"] = [r.address for r in query(domain, "A")][:8]
    mx_records = query(domain, "MX")
    result["mx"] = [
        r.exchange.to_text().rstrip(".").lower()
        for r in sorted(mx_records, key=lambda r: getattr(r, "preference", 0))
    ][:8]
    result["ns"] = [r.target.to_text().rstrip(".").lower() for r in query(domain, "NS")][:8]
    for record in query(domain, "TXT"):
        try:
            text = "".join(s.decode("utf-8", errors="replace") if isinstance(s, bytes) else str(s) for s in record.strings)
        except Exception:  # noqa: BLE001
            text = record.to_text().strip('"')
        if text.lower().startswith("v=spf1"):
            result["txt_spf"] = text[:500]
            break
    for record in query(f"_dmarc.{domain}", "TXT"):
        try:
            text = "".join(s.decode("utf-8", errors="replace") if isinstance(s, bytes) else str(s) for s in record.strings)
        except Exception:  # noqa: BLE001
            text = record.to_text().strip('"')
        if text.lower().startswith("v=dmarc1"):
            result["dmarc"] = text[:500]
            break
    _cache_set(store, cache_key, result, cfg.cache_ttl_seconds)
    return result


# --------------------------------------------------------------------------- #
# Reputation
# --------------------------------------------------------------------------- #
def domain_reputation(domain: str, cfg: Settings, store: Optional["Store"]) -> list[str]:
    """Feeds/tags that flag the domain: 'urlhaus', 'disposable', 'suspicious_tld'."""
    tags: list[str] = []
    if not domain:
        return tags
    if domain in DISPOSABLE_DOMAINS:
        tags.append("disposable")
    tld = domain.rsplit(".", 1)[-1]
    if tld in SUSPICIOUS_TLDS and domain not in FREEMAIL_DOMAINS:
        tags.append("suspicious_tld")
    # URLhaus began requiring an Auth-Key in 2025 and answers 401 without one.
    # Skipping the call when no key is configured keeps the local tags above and
    # saves a doomed round trip per domain on every analysis.
    if not cfg.enable_network or _is_ip(domain) or not cfg.urlhaus_key:
        return tags
    cache_key = f"rep:{domain}"
    cached = _cache_get(store, cache_key)
    if isinstance(cached, list):
        return tags + [t for t in cached if t not in tags]
    remote: list[str] = []
    try:
        import httpx

        headers = {"User-Agent": "MailTrace/1.0", "Auth-Key": cfg.urlhaus_key}
        with httpx.Client(timeout=_timeout(cfg), headers=headers) as client:
            response = client.post("https://urlhaus-api.abuse.ch/v1/host/", data={"host": domain})
        if response.status_code == 401:
            log.warning("URLhaus rejected the configured MAILTRACE_URLHAUS_KEY")
        elif response.status_code == 200:
            payload = response.json()
            if payload.get("query_status") == "ok" and payload.get("urls"):
                remote.append("urlhaus")
        _cache_set(store, cache_key, remote, cfg.cache_ttl_seconds)
    except Exception as exc:  # noqa: BLE001
        log.debug("urlhaus lookup failed for %s: %s", domain, exc)
    return tags + [t for t in remote if t not in tags]


# --------------------------------------------------------------------------- #
# Per-domain analysis
# --------------------------------------------------------------------------- #
def _finding(fid: str, severity: Severity, title: str, detail: str, evidence: dict) -> Finding:
    return Finding(id=fid, module="domains", severity=severity, title=title, detail=detail, evidence=evidence)


def analyze_domain(domain: str, role: str, cfg: Settings, store: Optional["Store"]) -> DomainIntel:
    domain = (domain or "").strip().lower().rstrip(".")
    intel = DomainIntel(domain=domain, role=role or "")
    if not domain:
        return intel
    intel.is_free_mail = domain in FREEMAIL_DOMAINS
    intel.is_disposable = domain in DISPOSABLE_DOMAINS
    org_domains = {registrable_domain(d) for d in cfg.org_domains if d}
    lookalike_of, technique = is_lookalike(domain, cfg)
    intel.lookalike_of, intel.lookalike_technique = lookalike_of, technique
    intel.source = "live" if cfg.enable_network else "offline"

    whois: dict = {}
    dns: dict = {}
    if cfg.enable_network and not _is_ip(domain):
        whois = whois_lookup(domain, cfg, store)
        dns = dns_lookup(domain, cfg, store)
        if whois.get("cached") and dns.get("cached"):
            intel.source = "cache"
    intel.reputation = domain_reputation(domain, cfg, store)

    if whois:
        intel.registrar = whois.get("registrar", "") or ""
        intel.registrant_country = whois.get("registrant_country", "") or ""
        intel.name_servers = list(whois.get("name_servers", []) or [])
        intel.created = _from_iso(whois.get("created"))
        intel.expires = _from_iso(whois.get("expires"))
        if intel.created is not None:
            intel.age_days = max(0, (datetime.now(timezone.utc) - intel.created).days)
    if dns:
        intel.a_records = list(dns.get("a", []) or [])
        intel.mx = list(dns.get("mx", []) or [])
        if not intel.name_servers:
            intel.name_servers = list(dns.get("ns", []) or [])
        intel.spf_record = dns.get("txt_spf", "") or ""
        intel.dmarc_record = dns.get("dmarc", "") or ""
        intel.has_mx = bool(intel.mx)
        intel.resolves = bool(intel.a_records or intel.mx)
        fingerprint: list[str] = []
        if intel.a_records:
            fingerprint.append("A: " + ", ".join(intel.a_records[:3]))
        if intel.name_servers:
            fingerprint.append("NS: " + ", ".join(intel.name_servers[:2]))
        if intel.mx:
            fingerprint.append("MX: " + ", ".join(intel.mx[:2]))
        intel.hosting_fingerprint = " | ".join(fingerprint)

    findings: list[Finding] = []
    label = {"sender": "Sender", "reply_to": "Reply-To", "return_path": "Return-Path", "url": "Link", "message_id": "Message-ID"}.get(role, "Domain")
    if intel.age_days is not None and not intel.is_free_mail:
        if intel.age_days < 30:
            sev: Optional[Severity] = Severity.HIGH
        elif intel.age_days < 90:
            sev = Severity.MEDIUM
        elif intel.age_days < 365:
            sev = Severity.LOW
        else:
            sev = None
        if sev is not None:
            findings.append(_finding(
                "newly_registered_domain", sev, f"Recently registered domain ({label.lower()})",
                f"{domain} was registered {intel.age_days} day(s) ago"
                + (f" via {intel.registrar}" if intel.registrar else "") + "; attack domains are typically days or weeks old.",
                {"domain": domain, "age_days": intel.age_days, "created": intel.created.isoformat() if intel.created else "", "registrar": intel.registrar},
            ))
    if lookalike_of:
        critical = lookalike_of in org_domains or lookalike_of in _BANK_BRANDS
        findings.append(_finding(
            "lookalike_domain", Severity.CRITICAL if critical else Severity.HIGH, f"Lookalike {label.lower()} domain",
            f"{domain} imitates {lookalike_of} using the {technique.replace('_', ' ')} technique.",
            {"domain": domain, "imitates": lookalike_of, "technique": technique, "role": role},
        ))
    if dns.get("queried") and role in ("sender", "reply_to") and not intel.is_free_mail:
        if dns.get("nxdomain") or (not intel.a_records and not intel.mx):
            if role == "sender":
                findings.append(_finding(
                    "domain_unresolvable", Severity.HIGH, "Sender domain does not resolve",
                    f"{domain} has no A or MX records: replies cannot reach it and the address is effectively fictitious.",
                    {"domain": domain, "nxdomain": bool(dns.get("nxdomain"))},
                ))
        elif not intel.has_mx:
            findings.append(_finding(
                "no_mx_record", Severity.MEDIUM, f"No mail server for {label.lower()} domain",
                f"{domain} publishes no MX record, so it is not set up to receive mail despite sending it.",
                {"domain": domain, "a_records": intel.a_records},
            ))
        if not intel.spf_record:
            findings.append(_finding(
                "no_spf_record", Severity.LOW, "No SPF record",
                f"{domain} publishes no SPF policy; anyone can send mail claiming this domain.",
                {"domain": domain},
            ))
        if not intel.dmarc_record:
            findings.append(_finding(
                "no_dmarc_record", Severity.LOW, "No DMARC record",
                f"{domain} publishes no DMARC policy; receivers cannot reject spoofed mail for it.",
                {"domain": domain},
            ))
    if role == "sender" and intel.is_free_mail:
        findings.append(_finding(
            "free_mail_sender", Severity.LOW, "Free-mail sender",
            f"The sender uses a free public mailbox provider ({domain}); business or institutional mail rarely does.",
            {"domain": domain},
        ))
    if intel.is_disposable:
        findings.append(_finding(
            "disposable_domain", Severity.HIGH, f"Disposable {label.lower()} domain",
            f"{domain} is a throwaway/temporary mailbox provider.",
            {"domain": domain},
        ))
    feeds = [t for t in intel.reputation if t not in ("disposable", "suspicious_tld")]
    if feeds:
        findings.append(_finding(
            "domain_blocklisted", Severity.CRITICAL, f"{label} domain on threat feed",
            f"{domain} is listed by {', '.join(feeds)} as hosting malicious content.",
            {"domain": domain, "feeds": feeds},
        ))
    if cfg.enable_network and not whois and not intel.is_free_mail and not _is_ip(domain):
        findings.append(_finding(
            "whois_unavailable", Severity.INFO, "WHOIS unavailable",
            f"Registration data for {domain} could not be retrieved (registry unreachable or rate-limited).",
            {"domain": domain},
        ))
    summary_bits = [f"role {role or 'n/a'}"]
    if intel.age_days is not None:
        summary_bits.append(f"age {intel.age_days}d")
    if intel.registrar:
        summary_bits.append(f"registrar {intel.registrar}")
    summary_bits.append(f"MX {'yes' if intel.has_mx else 'no'}" if dns else "DNS not queried")
    if intel.reputation:
        summary_bits.append("tags " + ", ".join(intel.reputation))
    findings.append(_finding(
        "domain_intel", Severity.INFO, f"Domain intelligence: {domain}",
        "; ".join(summary_bits) + ".",
        {"domain": domain, "role": role, "age_days": intel.age_days, "mx": intel.mx, "a_records": intel.a_records,
         "reputation": intel.reputation, "source": intel.source},
    ))
    intel.findings = findings
    return intel


# --------------------------------------------------------------------------- #
# Target selection and batch execution
# --------------------------------------------------------------------------- #
def collect_domains(
    parsed: ParsedEmail, header_analysis: HeaderAnalysis, url_analysis: UrlAnalysis, cfg: Settings
) -> list[tuple[str, str]]:
    """Ordered unique ``(registrable_domain, role)`` pairs, capped by config."""
    common = {registrable_domain(h) for h in COMMON_URL_HOSTS} | set(COMMON_URL_HOSTS)
    seen: set[str] = set()
    targets: list[tuple[str, str]] = []

    def add(host: str, role: str) -> None:
        rd = registrable_domain(host)
        if not rd or rd in seen or _is_ip(rd) or "." not in rd:
            return
        if role == "url" and rd in common:
            return
        seen.add(rd)
        targets.append((rd, role))

    add(parsed.sender.domain, "sender")
    for reply in parsed.reply_to:
        add(reply.domain, "reply_to")
    add(parsed.return_path.domain, "return_path")
    add(header_analysis.message_id_domain, "message_id")
    ranked = sorted(url_analysis.urls, key=lambda u: -{"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}[u.risk.value])
    for url in ranked:
        add(url.registrable_domain or url.host, "url")
    limit = max(1, int(cfg.max_domain_lookups or 6))
    return targets[:limit]


def analyze_domains(targets: list[tuple[str, str]], cfg: Settings, store: Optional["Store"]) -> list[DomainIntel]:
    """Analyse every target concurrently, preserving order; never raises."""
    if not targets:
        return []

    def run(target: tuple[str, str]) -> DomainIntel:
        domain, role = target
        try:
            return analyze_domain(domain, role, cfg, store)
        except Exception:  # noqa: BLE001
            log.exception("domain analysis failed for %s", domain)
            return DomainIntel(domain=domain, role=role, source="unavailable")

    with ThreadPoolExecutor(max_workers=min(6, len(targets)), thread_name_prefix="mt-domain") as pool:
        return list(pool.map(run, targets))
