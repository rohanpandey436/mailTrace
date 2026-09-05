"""
SPF / DKIM / DMARC evaluation.

Approach
--------
* ``Authentication-Results`` (and ``ARC-Authentication-Results`` /
  ``Received-SPF``) headers written by the receiving server are parsed first;
  they reflect what the boundary MTA observed on the pristine message.
* When network enrichment is enabled the verdicts are re-derived live:
  - SPF: a simplified RFC 7208 evaluator (``all``, ``ip4``, ``ip6``, ``a``,
    ``mx``, ``include``, ``redirect=``; ``exists``/``ptr``/macros are treated
    as no-match) run against the address that connected to the receiving
    organisation's boundary and the Return-Path domain, with the 10-lookup
    limit and include/redirect loop protection.
  - DKIM: ``dkimpy`` verification of the raw message with a dnspython-backed
    key lookup bounded by ``cfg.lookup_timeout``.
  - DMARC: the ``_dmarc`` TXT record of the From domain (``p=`` policy).
* Merge policy: a conclusive live result wins; an inconclusive one falls back
  to Authentication-Results.  The single exception is a live DKIM *fail* that
  contradicts a receiver-recorded DKIM *pass* for the same signing domain:
  exported evidence is frequently re-encoded after delivery, so the receiver's
  verdict is kept and the discrepancy is noted.
* Relaxed alignment compares registrable domains; DMARC is computed from the
  aligned results when no Authentication-Results verdict exists.

Every network call is guarded by ``cfg.enable_network``, bounded by
``cfg.lookup_timeout`` and can never raise to the caller.
"""
from __future__ import annotations

import ipaddress
import logging
import re
from email import policy as email_policy
from email.parser import BytesParser
from typing import Any, Optional

from ..config import Settings
from ..schemas import AuthResult, Finding, HeaderAnalysis, HeaderField, Hop, ParsedEmail, Severity
from .header_analyzer import is_private_ip
from .knowledge import BRANDS
from .link_analyzer import registrable_domain

log = logging.getLogger("mailtrace.auth")

MODULE = "auth"

_CONCLUSIVE = frozenset({"pass", "fail", "softfail", "neutral"})
_RESULT_ALIASES: dict[str, str] = {"hardfail": "fail", "bestguesspass": "neutral", "policy": "none"}
_BRAND_DOMAINS: frozenset[str] = frozenset(d.lower() for domains in BRANDS.values() for d in domains)
_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)[a-z0-9_-]+(?:\.[a-z0-9_-]+)+$")
_AR_METHOD_RE = re.compile(r"^\s*([a-z0-9_-]+)\s*=\s*([a-z]+)", re.IGNORECASE)
_AR_PROPERTY_RE = re.compile(
    r"\b(smtp\.mailfrom|smtp\.helo|header\.from|header\.d|header\.i|header\.s)\s*=\s*(\"[^\"]*\"|\S+)",
    re.IGNORECASE,
)
_DMARC_POLICY_RE = re.compile(r"\bp\s*=\s*([a-z]+)", re.IGNORECASE)
_RECEIVED_SPF_PROPERTY_RE = re.compile(r"\b(envelope-from|identity|helo|client-ip)\s*=\s*(\"[^\"]*\"|\S+)", re.IGNORECASE)
_RECEIVED_SPF_DOMAIN_RE = re.compile(r"domain of (?:\S+@)?([A-Za-z0-9.-]+)", re.IGNORECASE)
_SPF_QUALIFIERS: dict[str, str] = {"+": "pass", "-": "fail", "~": "softfail", "?": "neutral"}
_SPF_LOOKUP_LIMIT = 10
_SPF_MX_LIMIT = 10
_SPF_NESTING_LIMIT = 10


# --------------------------------------------------------------------------- #
# Small text helpers
# --------------------------------------------------------------------------- #
def _strip_comments(text: str) -> str:
    """Remove (possibly nested) parenthesised comments and collapse whitespace."""
    kept: list[str] = []
    depth = 0
    for ch in text:
        if ch == "(":
            depth += 1
        elif ch == ")":
            if depth > 0:
                depth -= 1
        elif depth == 0:
            kept.append(ch)
    return " ".join("".join(kept).split())


def _split_top_level(text: str, separator: str = ";") -> list[str]:
    """Split on ``separator`` occurrences that are outside parenthesised comments."""
    parts: list[str] = []
    depth = 0
    start = 0
    for position, ch in enumerate(text):
        if ch == "(":
            depth += 1
        elif ch == ")":
            if depth > 0:
                depth -= 1
        elif ch == separator and depth == 0:
            parts.append(text[start:position])
            start = position + 1
    parts.append(text[start:])
    return [p.strip() for p in parts if p.strip()]


def _unquote(value: str) -> str:
    return value.strip().strip('"').strip("<>").strip()


def _domain_part(value: str) -> str:
    """Domain of an address or bare domain property value, lower-cased."""
    value = _unquote(value)
    if "@" in value:
        value = value.rsplit("@", 1)[1]
    return value.lower().rstrip(".")


def _normalise_result(value: str) -> str:
    result = value.strip().lower()
    return _RESULT_ALIASES.get(result, result)


def _host_in(host: str, domains: list[str]) -> bool:
    host = (host or "").lower().rstrip(".")
    if not host:
        return False
    for raw in domains:
        domain = (raw or "").lower().strip().rstrip(".")
        if domain and (host == domain or host.endswith("." + domain)):
            return True
    return False


def _is_public(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip.strip())
    except ValueError:
        return False
    return not is_private_ip(ip)


def _aligned(domain: str, sender_rd: str) -> Optional[bool]:
    if not domain or not sender_rd:
        return None
    return registrable_domain(domain) == sender_rd


def _cache_get(store: Any, key: str) -> Any:
    if store is None:
        return None
    try:
        return store.cache_get(key)
    except Exception:  # noqa: BLE001 - cache problems must not affect analysis
        return None


def _cache_set(store: Any, key: str, value: Any, ttl: int) -> None:
    if store is None:
        return
    try:
        store.cache_set(key, value, ttl)
    except Exception:  # noqa: BLE001
        log.debug("cache_set failed for %s", key)


# --------------------------------------------------------------------------- #
# Header parsing
# --------------------------------------------------------------------------- #
def parse_authentication_results(headers: list[HeaderField]) -> dict[str, Any]:
    """Extract receiver verdicts from Authentication-Results, ARC-Authentication-
    Results and Received-SPF headers.

    Returns ``{'spf': (result, domain), 'dkim': (result, domain, selector),
    'dmarc': (result, policy)}``; absent methods carry empty strings.  The
    topmost header (added by the final receiver) wins; among several DKIM
    verdicts in one header a ``pass`` is preferred."""
    spf: tuple[str, str] = ("", "")
    dkim: tuple[str, str, str] = ("", "", "")
    dmarc: tuple[str, str] = ("", "")
    for field in headers:
        if field.name.lower() not in ("authentication-results", "arc-authentication-results"):
            continue
        dkim_here: list[tuple[str, str, str]] = []
        for segment in _split_top_level(" ".join(field.value.split())):
            match = _AR_METHOD_RE.match(_strip_comments(segment))
            if not match:
                continue
            method, result = match.group(1).lower(), _normalise_result(match.group(2))
            props = {key.lower(): _unquote(value) for key, value in _AR_PROPERTY_RE.findall(segment)}
            if method == "spf" and not spf[0]:
                domain = _domain_part(props.get("smtp.mailfrom", "")) or _domain_part(props.get("smtp.helo", ""))
                spf = (result, domain)
            elif method == "dkim":
                domain = _domain_part(props.get("header.d", "")) or _domain_part(props.get("header.i", ""))
                dkim_here.append((result, domain, props.get("header.s", "").lower()))
            elif method == "dmarc" and not dmarc[0]:
                policy_match = _DMARC_POLICY_RE.search(segment)
                dmarc = (result, policy_match.group(1).lower() if policy_match else "")
        if dkim_here and not dkim[0]:
            dkim = next((entry for entry in dkim_here if entry[0] == "pass"), dkim_here[0])
    if not spf[0]:
        for field in headers:
            if field.name.lower() != "received-spf":
                continue
            text = " ".join(field.value.split())
            match = re.match(r"\s*([A-Za-z]+)", text)
            if not match:
                continue
            props = {key.lower(): _unquote(value) for key, value in _RECEIVED_SPF_PROPERTY_RE.findall(text)}
            domain = _domain_part(props.get("envelope-from", ""))
            if not domain:
                domain_match = _RECEIVED_SPF_DOMAIN_RE.search(text)
                domain = domain_match.group(1).lower().rstrip(".") if domain_match else ""
            if not domain:
                domain = _domain_part(props.get("helo", ""))
            spf = (_normalise_result(match.group(1)), domain)
            break
    return {"spf": spf, "dkim": dkim, "dmarc": dmarc}


def _parse_tags(value: str) -> dict[str, str]:
    """DKIM tag=value list; whitespace inside values (folded b=/h=) is removed."""
    tags: dict[str, str] = {}
    for part in value.split(";"):
        if "=" not in part:
            continue
        key, _, tag_value = part.partition("=")
        key = key.strip().lower()
        if key and key not in tags:
            tags[key] = "".join(tag_value.split())
    return tags


def parse_dkim_signature(headers: list[HeaderField]) -> dict[str, str]:
    """``{'d', 's', 'a', 'h'}`` of the first DKIM-Signature header, ``{}`` if none."""
    for field in headers:
        if field.name.lower() != "dkim-signature":
            continue
        tags = _parse_tags(field.value)
        return {
            "d": tags.get("d", "").lower().rstrip("."),
            "s": tags.get("s", ""),
            "a": tags.get("a", "").lower(),
            "h": tags.get("h", "").lower(),
        }
    return {}


# --------------------------------------------------------------------------- #
# Live SPF (simplified RFC 7208)
# --------------------------------------------------------------------------- #
class _SpfPermError(Exception):
    """Record is unusable (syntax, loops, lookup limit)."""


class _SpfTempError(Exception):
    """DNS failed transiently."""


class _SpfEvaluator:
    """``check_host`` for one client address; DNS is bounded by the caller's resolver."""

    def __init__(
        self,
        addr: ipaddress.IPv4Address | ipaddress.IPv6Address,
        resolver: Any,
        no_record_errors: tuple[type[BaseException], ...],
        cfg: Settings,
        store: Any,
        notes: list[str],
    ) -> None:
        self.addr = addr
        self.resolver = resolver
        self.no_record_errors = no_record_errors
        self.cfg = cfg
        self.store = store
        self.notes = notes
        self.lookups = 0
        self.stack: list[str] = []

    # -- DNS ---------------------------------------------------------------
    def _count(self, what: str) -> None:
        self.lookups += 1
        if self.lookups > _SPF_LOOKUP_LIMIT:
            raise _SpfPermError(f"more than {_SPF_LOOKUP_LIMIT} DNS-querying terms ({what})")

    def _query(self, name: str, rdtype: str) -> list[str]:
        """Resolve ``name``; [] when the name/record does not exist."""
        try:
            answers = self.resolver.resolve(name, rdtype)
        except self.no_record_errors:
            return []
        except Exception as exc:  # noqa: BLE001 - timeouts, SERVFAIL, resolver errors
            raise _SpfTempError(f"{rdtype} lookup of {name} failed: {exc.__class__.__name__}") from exc
        if rdtype == "TXT":
            return [b"".join(rdata.strings).decode("utf-8", errors="replace") for rdata in answers]
        if rdtype == "MX":
            return [str(rdata.exchange).rstrip(".") for rdata in answers]
        return [str(rdata.address) for rdata in answers]

    def _spf_record(self, domain: str) -> tuple[str, str]:
        """(record, status) with status ``ok`` | ``none`` | ``permerror``."""
        cache_key = f"spf:{domain}"
        cached = _cache_get(self.store, cache_key)
        if isinstance(cached, dict):
            return str(cached.get("record", "")), str(cached.get("status", "none"))
        records = [
            text for text in self._query(domain, "TXT")
            if text.lower() == "v=spf1" or text.lower().startswith("v=spf1 ")
        ]
        if not records:
            result = ("", "none")
        elif len(records) > 1:
            result = ("", "permerror")
        else:
            result = (records[0].strip(), "ok")
        _cache_set(self.store, cache_key, {"record": result[0], "status": result[1]}, self.cfg.cache_ttl_seconds)
        return result

    # -- Evaluation ----------------------------------------------------------
    def check_host(self, domain: str) -> str:
        domain = domain.lower().rstrip(".")
        if domain in self.stack:
            raise _SpfPermError(f"include/redirect loop at {domain}")
        if len(self.stack) >= _SPF_NESTING_LIMIT:
            raise _SpfPermError("include/redirect nesting too deep")
        self.stack.append(domain)
        try:
            record, status = self._spf_record(domain)
            if status == "none":
                self.notes.append(f"{domain}: no SPF record")
                return "none"
            if status != "ok":
                self.notes.append(f"{domain}: multiple SPF records")
                return "permerror"
            self.notes.append(f"{domain}: {record}")
            redirect = ""
            for term in record.split()[1:]:
                if term.lower().startswith("redirect="):
                    redirect = term[len("redirect="):]
                    continue
                if "=" in term:
                    continue  # exp= and unknown modifiers carry no policy
                qualifier = "+"
                if term[0] in _SPF_QUALIFIERS:
                    qualifier, term = term[0], term[1:]
                if term and self._match(term, domain):
                    result = _SPF_QUALIFIERS[qualifier]
                    self.notes.append(f"{domain}: matched {qualifier}{term} -> {result}")
                    return result
            if redirect:
                self._count("redirect")
                result = self.check_host(redirect)
                return "permerror" if result == "none" else result
            self.notes.append(f"{domain}: no mechanism matched -> neutral")
            return "neutral"
        finally:
            self.stack.pop()

    def _match(self, term: str, domain: str) -> bool:
        lowered = term.lower()
        if lowered.startswith(("ip4:", "ip6:")):
            return self._match_network(term.partition(":")[2], lowered[:3])
        spec, _, cidr = term.partition("/")
        name, _, argument = spec.partition(":")
        name = name.lower()
        target = (argument or domain).lower().rstrip(".")
        if name == "all":
            return True
        if "%" in target:
            self.notes.append(f"{term}: macros are not supported, treated as no match")
            return False
        if name == "a":
            self._count("a")
            return self._matches_hosts([target], cidr)
        if name == "mx":
            self._count("mx")
            return self._matches_hosts(self._query(target, "MX")[:_SPF_MX_LIMIT], cidr)
        if name == "include":
            self._count("include")
            result = self.check_host(target)
            if result == "pass":
                return True
            if result in ("fail", "softfail", "neutral"):
                return False
            if result == "temperror":
                raise _SpfTempError(f"include:{target} returned temperror")
            raise _SpfPermError(f"include:{target} returned {result}")
        if name in ("exists", "ptr"):
            self.notes.append(f"{name} mechanism ignored (treated as no match)")
            return False
        self.notes.append(f"unknown mechanism '{name}' ignored")
        return False

    def _match_network(self, argument: str, name: str) -> bool:
        try:
            network = ipaddress.ip_network(argument.strip(), strict=False)
        except ValueError:
            self.notes.append(f"{name}:{argument}: invalid network ignored")
            return False
        return network.version == self.addr.version and self.addr in network

    def _prefix_length(self, cidr: str) -> Optional[int]:
        """Prefix length for this address family from ``24``, ``24//64`` or ``/64``."""
        if not cidr:
            return None
        v4_part, _, v6_part = cidr.partition("/")
        chosen = v4_part if self.addr.version == 4 else v6_part.lstrip("/")
        if not chosen.isdigit():
            return None
        length = int(chosen)
        return length if 0 <= length <= self.addr.max_prefixlen else None

    def _matches_hosts(self, hosts: list[str], cidr: str) -> bool:
        rdtype = "A" if self.addr.version == 4 else "AAAA"
        prefix = self._prefix_length(cidr)
        for host in hosts:
            if not host:
                continue
            for address in self._query(host, rdtype):
                try:
                    candidate = ipaddress.ip_address(address)
                except ValueError:
                    continue
                if candidate.version != self.addr.version:
                    continue
                if prefix is None:
                    if candidate == self.addr:
                        return True
                elif self.addr in ipaddress.ip_network(f"{candidate}/{prefix}", strict=False):
                    return True
        return False


def live_spf(ip: str, domain: str, cfg: Settings, store: Any = None) -> tuple[str, list[str]]:
    """Evaluate SPF for ``ip`` sending on behalf of ``domain``.

    Returns ``(result, notes)`` with result in pass | fail | softfail | neutral
    | none | temperror | permerror | unverifiable.  Never raises."""
    domain = (domain or "").strip().lower().rstrip(".")
    if not cfg.enable_network:
        return "unverifiable", ["network enrichment disabled; SPF not evaluated"]
    if not domain or not _DOMAIN_RE.match(domain):
        return "unverifiable", [f"no usable domain for SPF evaluation ({domain or 'empty'})"]
    try:
        addr = ipaddress.ip_address((ip or "").strip())
    except ValueError:
        return "unverifiable", [f"no usable client address for SPF evaluation ({ip or 'empty'})"]
    if is_private_ip(str(addr)):
        return "unverifiable", [f"{addr} is a private address; SPF cannot be evaluated for it"]
    try:
        import dns.resolver
    except Exception as exc:  # noqa: BLE001 - optional dependency
        return "unverifiable", [f"dnspython unavailable: {exc.__class__.__name__}"]

    notes: list[str] = []
    evaluator: Optional[_SpfEvaluator] = None
    try:
        resolver = dns.resolver.Resolver(configure=True)
        resolver.timeout = cfg.lookup_timeout
        resolver.lifetime = cfg.lookup_timeout
        evaluator = _SpfEvaluator(
            addr, resolver, (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer), cfg, store, notes
        )
        result = evaluator.check_host(domain)
    except _SpfPermError as exc:
        notes.append(f"permerror: {exc}")
        result = "permerror"
    except _SpfTempError as exc:
        notes.append(f"temperror: {exc}")
        result = "temperror"
    except Exception as exc:  # noqa: BLE001 - resolver configuration or unexpected DNS failures
        log.debug("SPF evaluation for %s/%s failed: %s", ip, domain, exc)
        notes.append(f"temperror: {exc.__class__.__name__}")
        result = "temperror"
    lookups = evaluator.lookups if evaluator is not None else 0
    notes.append(f"SPF {result} for {addr} on behalf of {domain} ({lookups} DNS-querying terms)")
    return result, notes


# --------------------------------------------------------------------------- #
# Live DKIM
# --------------------------------------------------------------------------- #
def live_dkim(raw: bytes, cfg: Settings) -> tuple[str, str, str, list[str]]:
    """Verify the first DKIM signature of ``raw`` with dkimpy.

    Returns ``(result, d_domain, selector, notes)`` with result pass | fail |
    unverifiable (no signature, no key, DNS error, library missing) | none
    when no DKIM-Signature exists.  Never raises."""
    notes: list[str] = []
    try:
        message = BytesParser(policy=email_policy.compat32).parsebytes(raw, headersonly=True)
        fields = [HeaderField(name=str(name), value=str(value)) for name, value in message.items()]
    except Exception as exc:  # noqa: BLE001 - unparseable input
        return "unverifiable", "", "", [f"could not parse message headers: {exc.__class__.__name__}"]
    signature = parse_dkim_signature(fields)
    if not signature:
        return "none", "", "", ["no DKIM-Signature header"]
    d_domain, selector = signature["d"], signature["s"]
    if not cfg.enable_network:
        return "unverifiable", d_domain, selector, ["network enrichment disabled; signature not verified"]
    try:
        import dkim
        import dns.resolver
    except Exception as exc:  # noqa: BLE001 - optional dependencies
        return "unverifiable", d_domain, selector, [f"DKIM library unavailable: {exc.__class__.__name__}"]

    key_found = False

    def dnsfunc(name: Any, timeout: float = cfg.lookup_timeout) -> Optional[bytes]:
        """dkimpy key lookup honouring cfg.lookup_timeout instead of dkimpy's default."""
        nonlocal key_found
        label = name.decode("ascii", errors="ignore") if isinstance(name, bytes) else str(name)
        try:
            resolver = dns.resolver.Resolver(configure=True)
            resolver.timeout = cfg.lookup_timeout
            resolver.lifetime = cfg.lookup_timeout
            answers = resolver.resolve(label, "TXT")
        except Exception as exc:  # noqa: BLE001 - NXDOMAIN, timeout, resolver errors
            notes.append(f"key lookup {label} failed: {exc.__class__.__name__}")
            return None
        for rdata in answers:
            key_found = True
            return b"".join(rdata.strings)
        return None

    try:
        verified = bool(dkim.verify(raw, dnsfunc=dnsfunc))
    except Exception as exc:  # noqa: BLE001 - dkim.DKIMException and friends
        notes.append(f"verification error: {exc.__class__.__name__}: {exc}")
        return "unverifiable", d_domain, selector, notes
    if verified:
        notes.append(f"signature d={d_domain} s={selector} verified against the published key")
        return "pass", d_domain, selector, notes
    if key_found:
        notes.append(f"signature d={d_domain} s={selector} does not verify against the published key")
        return "fail", d_domain, selector, notes
    notes.append(f"public key {selector}._domainkey.{d_domain} not available")
    return "unverifiable", d_domain, selector, notes


# --------------------------------------------------------------------------- #
# Live DMARC
# --------------------------------------------------------------------------- #
def live_dmarc(domain: str, cfg: Settings, store: Any = None) -> tuple[str, str]:
    """``(policy, record)`` of the DMARC record for ``domain`` (falling back to
    its registrable domain); ``('', '')`` offline, on failure or when absent."""
    domain = (domain or "").strip().lower().rstrip(".")
    if not cfg.enable_network or not domain or not _DOMAIN_RE.match(domain):
        return "", ""
    cache_key = f"dmarc:{domain}"
    cached = _cache_get(store, cache_key)
    if isinstance(cached, dict):
        return str(cached.get("policy", "")), str(cached.get("record", ""))
    candidates = [domain]
    organisational = registrable_domain(domain)
    if organisational and organisational != domain:
        candidates.append(organisational)
    record = ""
    try:
        import dns.resolver

        resolver = dns.resolver.Resolver(configure=True)
        resolver.timeout = cfg.lookup_timeout
        resolver.lifetime = cfg.lookup_timeout
        for name in candidates:
            try:
                answers = resolver.resolve(f"_dmarc.{name}", "TXT")
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                continue
            for rdata in answers:
                text = b"".join(rdata.strings).decode("utf-8", errors="replace").strip()
                if text.lower().startswith("v=dmarc1"):
                    record = text
                    break
            if record:
                break
    except Exception as exc:  # noqa: BLE001 - timeouts, resolver errors, missing library
        log.debug("DMARC lookup for %s failed: %s", domain, exc)
        return "", ""
    policy_match = re.search(r"(?:^|;)\s*p\s*=\s*([a-z]+)", record, re.IGNORECASE)
    policy = policy_match.group(1).lower() if policy_match else ""
    _cache_set(store, cache_key, {"policy": policy, "record": record}, cfg.cache_ttl_seconds)
    return policy, record


# --------------------------------------------------------------------------- #
# Evaluation
# --------------------------------------------------------------------------- #
def _boundary_hop(header_analysis: HeaderAnalysis, cfg: Settings) -> Optional[Hop]:
    """Latest hop whose source is a public, non-organisation, non-trusted
    address: the connection the receiving boundary evaluated SPF against."""
    for hop in reversed(header_analysis.hops):
        if (
            hop.from_ip and not hop.is_private_ip
            and not _host_in(hop.from_host, cfg.org_domains)
            and not _host_in(hop.from_host, cfg.trusted_relays)
        ):
            return hop
    return None


def _finding(fid: str, severity: Severity, title: str, detail: str, **evidence: Any) -> Finding:
    return Finding(id=fid, module=MODULE, severity=severity, title=title, detail=detail, evidence=dict(evidence))


def evaluate_auth(
    parsed: ParsedEmail,
    header_analysis: HeaderAnalysis,
    cfg: Settings,
    raw: bytes | None = None,
) -> tuple[AuthResult, list[Finding]]:
    """Combine receiver-recorded and live SPF/DKIM/DMARC verdicts into an
    AuthResult plus findings.  Never raises."""
    notes: list[str] = []
    recorded = parse_authentication_results(parsed.headers)
    ar_spf, ar_spf_domain = recorded["spf"]
    ar_dkim, ar_dkim_domain, ar_dkim_selector = recorded["dkim"]
    ar_dmarc, ar_dmarc_policy = recorded["dmarc"]
    signature = parse_dkim_signature(parsed.headers)
    has_recorded = bool(ar_spf or ar_dkim or ar_dmarc)

    sender_domain = (parsed.sender.domain or "").lower().rstrip(".")
    sender_rd = registrable_domain(sender_domain) if sender_domain else ""
    boundary = _boundary_hop(header_analysis, cfg)
    boundary_ip = boundary.from_ip if boundary else (
        header_analysis.originating_ip if _is_public(header_analysis.originating_ip) else ""
    )
    helo_domain = boundary.from_host if boundary else ""
    spf_domain = (parsed.return_path.domain or "").lower().rstrip(".") or ar_spf_domain or helo_domain

    if not cfg.enable_network:
        notes.append("network enrichment disabled: verdicts derived from Authentication-Results headers only")

    # SPF -------------------------------------------------------------------
    live_spf_result = ""
    if cfg.enable_network and spf_domain and boundary_ip:
        live_spf_result, spf_notes = live_spf(boundary_ip, spf_domain, cfg)
        notes.extend(f"spf: {line}" for line in spf_notes)
    if live_spf_result in _CONCLUSIVE:
        spf, spf_source = live_spf_result, "live"
    elif ar_spf:
        spf, spf_source = ar_spf, "authentication-results"
        if live_spf_result:
            notes.append(f"spf: live evaluation returned {live_spf_result}; using the receiver's verdict")
    elif live_spf_result == "none":
        spf, spf_source = "none", "live"
    elif live_spf_result:
        spf, spf_source = "unverifiable", "live"
    else:
        # No receiver verdict and no live evaluation: there is no SPF evidence
        # at all, which the merge policy reports as "none".
        spf, spf_source = "none", ("offline" if not cfg.enable_network else "none")
    spf_aligned = _aligned(spf_domain, sender_rd)

    # DKIM ------------------------------------------------------------------
    sig_domain = signature.get("d", "")
    sig_selector = signature.get("s", "")
    live_dkim_result = ""
    if raw is not None and cfg.enable_network and signature:
        live_dkim_result, live_d, live_s, dkim_notes = live_dkim(raw, cfg)
        sig_domain = live_d or sig_domain
        sig_selector = live_s or sig_selector
        notes.extend(f"dkim: {line}" for line in dkim_notes)
    dkim_domain = sig_domain or ar_dkim_domain
    dkim_selector = sig_selector or ar_dkim_selector
    if live_dkim_result == "pass":
        dkim, dkim_source = "pass", "live"
    elif live_dkim_result == "fail":
        same_signer = not ar_dkim_domain or not dkim_domain or registrable_domain(ar_dkim_domain) == registrable_domain(dkim_domain)
        if ar_dkim == "pass" and same_signer:
            dkim, dkim_source = "pass", "authentication-results"
            notes.append(
                "dkim: live re-verification failed but the receiving server recorded dkim=pass; the exported "
                "copy was probably re-encoded after delivery, so the receiver's verdict is kept"
            )
        else:
            dkim, dkim_source = "fail", "live"
    elif ar_dkim:
        dkim, dkim_source = ar_dkim, "authentication-results"
    elif signature:
        dkim = "unverifiable"
        dkim_source = "offline" if not cfg.enable_network else ("live" if live_dkim_result else "none")
    else:
        dkim, dkim_source = "none", "none"
    dkim_aligned = _aligned(dkim_domain, sender_rd)

    # DMARC -----------------------------------------------------------------
    live_policy, live_record = "", ""
    if cfg.enable_network and sender_domain:
        live_policy, live_record = live_dmarc(sender_domain, cfg, None)
        notes.append(f"dmarc: {live_record}" if live_record else f"dmarc: no record for {sender_domain}")
    if ar_dmarc:
        dmarc, dmarc_source = ar_dmarc, "authentication-results"
    elif (spf == "pass" and spf_aligned is True) or (dkim == "pass" and dkim_aligned is True):
        dmarc, dmarc_source = "pass", "computed"
    elif live_record:
        dmarc, dmarc_source = "fail", "live"
    elif cfg.enable_network and sender_domain:
        dmarc, dmarc_source = "none", "live"
    else:
        dmarc, dmarc_source = "none", ("offline" if not cfg.enable_network else "none")
    dmarc_policy = live_policy or ar_dmarc_policy

    notes.append(f"summary: spf={spf} ({spf_source}), dkim={dkim} ({dkim_source}), dmarc={dmarc} ({dmarc_source})")
    result = AuthResult(
        spf=spf,
        spf_domain=spf_domain,
        spf_source=spf_source,
        dkim=dkim,
        dkim_domain=dkim_domain,
        dkim_selector=dkim_selector,
        dkim_source=dkim_source,
        dmarc=dmarc,
        dmarc_policy=dmarc_policy,
        dmarc_source=dmarc_source,
        spf_aligned=spf_aligned,
        dkim_aligned=dkim_aligned,
        notes=notes,
    )

    # Findings --------------------------------------------------------------
    findings: list[Finding] = []
    spf_where = f"{boundary_ip} " if boundary_ip else ""
    if spf == "pass":
        findings.append(_finding(
            "spf_pass", Severity.INFO, "SPF pass",
            f"The sending server {spf_where}is authorised by the SPF policy of {spf_domain} (source: {spf_source}).",
            result=spf, domain=spf_domain, ip=boundary_ip, source=spf_source,
        ))
    elif spf == "fail":
        findings.append(_finding(
            "spf_fail", Severity.HIGH, "SPF fail",
            f"The sending server {spf_where}is not authorised by the SPF policy of {spf_domain}; the envelope "
            f"sender is forged or the message was relayed through unauthorised infrastructure.",
            result=spf, domain=spf_domain, ip=boundary_ip, source=spf_source,
        ))
    elif spf == "softfail":
        findings.append(_finding(
            "spf_softfail", Severity.MEDIUM, "SPF softfail",
            f"{spf_domain} marks the sending server {spf_where}as probably not authorised (~all); "
            f"treat the envelope sender as unproven.",
            result=spf, domain=spf_domain, ip=boundary_ip, source=spf_source,
        ))
    elif spf in ("none", "neutral"):
        if spf == "neutral":
            spf_detail = f"The SPF policy of {spf_domain} is neutral for the sending server {spf_where}and provides no assurance."
        elif spf_source in ("none", "offline"):
            spf_detail = (
                f"No SPF verdict is available for {spf_domain or 'the sender domain'}: the message carries no "
                f"receiver verdict and no live evaluation was performed (source: {spf_source})."
            )
        else:
            spf_detail = f"{spf_domain or 'The sender domain'} publishes no SPF record, so anyone can send on its behalf."
        findings.append(_finding(
            "spf_none", Severity.LOW, "No usable SPF policy", spf_detail,
            result=spf, domain=spf_domain, ip=boundary_ip, source=spf_source,
        ))
    else:
        findings.append(_finding(
            "spf_unverifiable", Severity.LOW, "SPF could not be verified",
            f"No SPF verdict could be established for {spf_domain or 'the sender'} ({spf}; source: {spf_source}).",
            result=spf, domain=spf_domain, ip=boundary_ip, source=spf_source,
        ))

    if dkim == "pass":
        findings.append(_finding(
            "dkim_pass", Severity.INFO, "DKIM pass",
            f"The message carries a valid DKIM signature by {dkim_domain or 'the signing domain'} "
            f"(selector {dkim_selector or '?'}; source: {dkim_source}).",
            result=dkim, domain=dkim_domain, selector=dkim_selector, source=dkim_source,
        ))
    elif dkim == "fail":
        findings.append(_finding(
            "dkim_fail", Severity.HIGH, "DKIM signature invalid",
            f"The DKIM signature by {dkim_domain or 'the signing domain'} does not verify; the message was "
            f"altered in transit or the signature was fabricated.",
            result=dkim, domain=dkim_domain, selector=dkim_selector, source=dkim_source,
        ))
    elif dkim == "none":
        findings.append(_finding(
            "dkim_missing", Severity.LOW, "No DKIM signature",
            "The message is not DKIM-signed, so its content and headers are not cryptographically bound "
            "to any domain.",
            result=dkim, source=dkim_source,
        ))
    else:
        findings.append(_finding(
            "dkim_unverifiable", Severity.LOW, "DKIM could not be verified",
            f"A DKIM signature by {dkim_domain or 'an unknown domain'} exists but no verdict could be "
            f"established ({dkim}; source: {dkim_source}).",
            result=dkim, domain=dkim_domain, selector=dkim_selector, source=dkim_source,
        ))

    org_domains = {d.lower().strip() for d in cfg.org_domains} | {registrable_domain(d) for d in cfg.org_domains if d}
    protected_sender = bool(sender_rd) and (sender_rd in org_domains or sender_rd in _BRAND_DOMAINS)
    if dmarc == "pass":
        findings.append(_finding(
            "dmarc_pass", Severity.INFO, "DMARC pass",
            f"The visible sender domain {sender_rd or sender_domain} is covered by an aligned SPF or DKIM "
            f"pass (source: {dmarc_source}).",
            result=dmarc, policy=dmarc_policy, domain=sender_rd, source=dmarc_source,
        ))
    elif dmarc == "fail":
        findings.append(_finding(
            "dmarc_fail",
            Severity.CRITICAL if dmarc_policy == "reject" and protected_sender else Severity.HIGH,
            "DMARC fail",
            f"Neither SPF nor DKIM passes in alignment with the visible sender domain {sender_rd or sender_domain}"
            + (f", whose published policy is p={dmarc_policy}" if dmarc_policy else "")
            + "; the From address is not authenticated.",
            result=dmarc, policy=dmarc_policy, domain=sender_rd, source=dmarc_source,
            protected_domain=protected_sender,
        ))
    else:
        findings.append(_finding(
            "dmarc_no_record", Severity.LOW, "No DMARC verdict",
            f"No DMARC policy or verdict is available for {sender_rd or sender_domain or 'the sender domain'} "
            f"(source: {dmarc_source}); the From address is unprotected against spoofing.",
            result=dmarc, policy=dmarc_policy, domain=sender_rd, source=dmarc_source,
        ))

    if spf == "pass" and spf_aligned is False:
        findings.append(_finding(
            "spf_misaligned", Severity.MEDIUM, "SPF passes for a different domain",
            f"SPF authorises {spf_domain}, not the visible sender domain {sender_rd}; the sender controls "
            f"the envelope domain but not necessarily the From identity.",
            spf_domain=spf_domain, sender_domain=sender_rd,
        ))
    if dkim == "pass" and dkim_aligned is False:
        findings.append(_finding(
            "dkim_misaligned", Severity.MEDIUM, "DKIM signed by a different domain",
            f"The DKIM signature belongs to {dkim_domain}, not the visible sender domain {sender_rd}; "
            f"a third party vouches for the message, not the claimed sender.",
            dkim_domain=dkim_domain, sender_domain=sender_rd,
        ))
    if not has_recorded and not signature and spf_source in ("none", "offline"):
        findings.append(_finding(
            "auth_all_missing", Severity.MEDIUM, "No authentication evidence",
            "The message carries no Authentication-Results, Received-SPF or DKIM-Signature headers and no "
            "live verdict could be obtained; the sender identity is entirely unverified.",
            network=cfg.enable_network,
        ))
    return result, findings
