"""
Received-chain reconstruction and header-forgery analysis.

Approach
--------
* Every ``Received`` header is split into its top-level clauses (``from``,
  ``by``, ``via``, ``with``, ``id``, ``for``) using a parenthesis-depth scan,
  so keywords that occur inside comments such as ``(envelope-from <x>)`` or
  cipher names like ``TLS_ECDHE_RSA_WITH_AES_256`` never derail the parse.
* The connecting address of a hop is taken from the receiver-written comment
  literal first (``(host [1.2.3.4])``), then from a bare address literal
  (``from [10.0.0.5]``), then from any address in the clause (Exchange /
  Microsoft 365 write ``(2603:10b6::12)`` without brackets).  This ordering
  makes Gmail, Microsoft 365, Postfix, Exim, Sendmail, qmail, Amazon SES and
  Zimbra formats yield the same answer.
* Hops are re-ordered chronologically (index 0 = earliest) and annotated with
  timing, privacy, TLS, HELO/rDNS and ordering anomalies.
* Origin selection walks upward from the earliest hop to the first public,
  non-trusted address; ``X-Originating-IP`` style headers are the fallback.
* Identity checks compare the registrable domains of From / Reply-To /
  Return-Path / Message-ID and look for brand or executive impersonation in
  the display name.

Everything in this module is offline and deterministic.
"""
from __future__ import annotations

import ipaddress
import logging
import re
from collections.abc import Iterable
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from typing import Any

from ..config import Settings
from ..schemas import Finding, HeaderAnalysis, Hop, ParsedEmail, Severity
from .knowledge import BRANDS, EXEC_TITLES, FREEMAIL_DOMAINS
from .link_analyzer import registrable_domain

log = logging.getLogger("mailtrace.headers")

MODULE = "headers"

# Top-level clause keywords of a Received header (RFC 5321 section 4.4).
_CLAUSE_RE = re.compile(r"(?<!\S)(from|by|via|with|id|for)(?!\S)", re.IGNORECASE)
_BRACKET_IP_RE = re.compile(r"\[(?:IPv6:)?([0-9A-Fa-f.:]+)\]")
_HELO_RE = re.compile(r"\b(?:helo|ehlo|lhlo)[=\s]+\[?([^\s\]\)]+)", re.IGNORECASE)
# "(rdns-name [ip])" as written by Postfix, Sendmail and Gmail ("name. [ip]").
_RDNS_RE = re.compile(r"\(\s*([A-Za-z0-9][A-Za-z0-9._-]*?)\.?\s+\[(?:IPv6:)?[0-9A-Fa-f.:]+\]")
_IPV4_RE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?!\w|\.\w)")
_IPV6_RE = re.compile(
    r"(?<![\w:.])(?:[0-9A-Fa-f]{0,4}:){2,7}(?:[0-9A-Fa-f]{0,4}|\d{1,3}(?:\.\d{1,3}){3})(?![\w:]|\.\w)"
)
_IPV6_PREFIX_RE = re.compile(r"IPv6:", re.IGNORECASE)
_TLS_RE = re.compile(
    r"\bTLS(?:v?\d|_|\b)|\bSSL\b|\bSTARTTLS\b|Google Transport Security|cipher=", re.IGNORECASE
)
_AUTH_RE = re.compile(r"\b(?:UTF8)?E?SMTPS?A\b|\bauthenticated\b", re.IGNORECASE)
_SMTP_PROTOCOL_RE = re.compile(r"^(?:UTF8)?[EL]?SMTPS?A?$", re.IGNORECASE)
_PLAINTEXT_PROTOCOL_RE = re.compile(r"^(?:UTF8)?E?SMTPA?$", re.IGNORECASE)
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})")
_BULK_MAILER_RE = re.compile(
    r"phpmailer|swift ?mailer|python|go-http|gophish|nodemailer|sendblaster|mass ?mail|"
    r"\bbulk\b|powershell|\bcurl\b|atomic ?mail|turbo-?mailer|advanced mass sender|libwww|\bperl\b",
    re.IGNORECASE,
)
_CGNAT_NETWORK = ipaddress.ip_network("100.64.0.0/10")
_CLIENT_IP_HEADERS = frozenset({"x-originating-ip", "x-sender-ip", "x-client-ip"})
# Anomalies below the origin hop that make the chain less trustworthy.
_CHAIN_DOUBT = frozenset(
    {"negative_delay", "large_delay", "missing_timestamp", "unparseable", "forged_received_order"}
)
# Providers whose Message-ID / Return-Path domains legitimately differ from the From domain.
_RELAY_PROVIDER_DOMAINS: frozenset[str] = frozenset(
    FREEMAIL_DOMAINS
    | {
        "google.com", "outlook.com", "office365.com", "microsoft.com", "microsoftonline.com",
        "amazonses.com", "sendgrid.net", "mailgun.org", "mandrillapp.com", "sparkpostmail.com",
        "mcsv.net", "mailchimp.com", "exacttarget.com", "salesforce.com", "zendesk.com",
        "hubspot.com", "constantcontact.com", "postmarkapp.com", "sendinblue.com", "brevo.com",
        "mailjet.com",
    }
)
# Multi-word brand names that map onto knowledge.BRANDS keys.
_BRAND_ALIASES: dict[str, str] = {
    "state bank of india": "sbi", "reserve bank of india": "rbi", "hdfc bank": "hdfc",
    "icici bank": "icici", "axis bank": "axisbank", "kotak mahindra": "kotak",
    "punjab national bank": "pnb", "bank of baroda": "bankofbaroda", "canara bank": "canarabank",
    "income tax department": "incometax", "income tax": "incometax", "bank of america": "bankofamerica",
    "wells fargo": "wellsfargo", "jp morgan chase": "chase", "blue dart": "bluedart",
    "office 365": "office365", "one drive": "onedrive", "share point": "sharepoint",
    "pay pal": "paypal", "phone pe": "phonepe", "docu sign": "docusign", "we transfer": "wetransfer",
}
_ALIAS_PHRASES: tuple[str, ...] = tuple(sorted(_BRAND_ALIASES, key=len, reverse=True))
_BRAND_KEYS: tuple[str, ...] = tuple(sorted(BRANDS, key=len, reverse=True))


# --------------------------------------------------------------------------- #
# Low-level text helpers
# --------------------------------------------------------------------------- #
def _depth_map(text: str) -> list[int]:
    """Parenthesis nesting depth *before* each character of ``text``."""
    depths: list[int] = []
    depth = 0
    for ch in text:
        depths.append(depth)
        if ch == "(":
            depth += 1
        elif ch == ")" and depth > 0:
            depth -= 1
    return depths


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


def _first_token(text: str) -> str:
    parts = text.split()
    return parts[0] if parts else ""


def _valid_ip(value: str) -> str:
    """Canonical text form of ``value`` when it is an IP address, else ''."""
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError:
        return ""


def _word_match(phrase: str, text: str) -> bool:
    """True when ``phrase`` occurs in ``text`` delimited by non-alphanumerics."""
    return re.search(r"(?<![a-z0-9])" + re.escape(phrase) + r"(?![a-z0-9])", text) is not None


def _host_matches(host: str, domains: Iterable[str]) -> bool:
    """True when ``host`` equals or is a subdomain of any entry in ``domains``."""
    host = (host or "").lower().rstrip(".")
    if not host:
        return False
    for raw in domains:
        domain = (raw or "").lower().strip().rstrip(".")
        if domain and (host == domain or host.endswith("." + domain)):
            return True
    return False


def _is_internal_host(host: str, cfg: Settings) -> bool:
    return _host_matches(host, cfg.org_domains) or _host_matches(host, cfg.trusted_relays)


# --------------------------------------------------------------------------- #
# Public helpers
# --------------------------------------------------------------------------- #
def is_private_ip(ip: str) -> bool:
    """RFC 1918, loopback, link-local, CGNAT (100.64/10), ULA, site-local,
    multicast, reserved and unspecified addresses.  IPv4-mapped and 6to4
    addresses are judged by their embedded IPv4 address.  Unparseable input
    is not private."""
    try:
        addr = ipaddress.ip_address(ip.strip())
    except ValueError:
        return False
    if isinstance(addr, ipaddress.IPv6Address):
        mapped = addr.ipv4_mapped
        if mapped is not None:
            return is_private_ip(str(mapped))
        embedded = addr.sixtofour
        if embedded is not None:
            return is_private_ip(str(embedded))
        return bool(
            addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_site_local
            or addr.is_multicast or addr.is_reserved or addr.is_unspecified
        )
    return bool(
        addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_multicast
        or addr.is_reserved or addr.is_unspecified or addr in _CGNAT_NETWORK
    )


def _is_public_ip(ip: str) -> bool:
    return bool(ip) and bool(_valid_ip(ip)) and not is_private_ip(ip)


def extract_ips(text: str) -> list[str]:
    """Every IPv4/IPv6 literal in ``text`` (public and private) in order of
    appearance, without duplicates.  Candidates are validated with
    ``ipaddress`` so timestamps, MAC addresses and version strings drop out."""
    if not text:
        return []
    text = _IPV6_PREFIX_RE.sub("", text)
    found: list[tuple[int, str]] = []
    v6_spans: list[tuple[int, int]] = []
    for match in _IPV6_RE.finditer(text):
        ip = _valid_ip(match.group(0))
        if ip:
            found.append((match.start(), ip))
            v6_spans.append(match.span())
    for match in _IPV4_RE.finditer(text):
        if any(start <= match.start() < end for start, end in v6_spans):
            continue  # dotted-quad tail of an IPv4-mapped IPv6 literal
        ip = _valid_ip(match.group(0))
        if ip:
            found.append((match.start(), ip))
    result: list[str] = []
    for _, ip in sorted(found, key=lambda item: item[0]):
        if ip not in result:
            result.append(ip)
    return result


# --------------------------------------------------------------------------- #
# Received header parsing
# --------------------------------------------------------------------------- #
def _split_clauses(body: str) -> dict[str, str]:
    """Map each top-level clause keyword to its raw value (first occurrence
    wins).  Keywords inside parenthesised comments are ignored."""
    depths = _depth_map(body)
    matches = [m for m in _CLAUSE_RE.finditer(body) if depths[m.start()] == 0]
    clauses: dict[str, str] = {}
    for position, match in enumerate(matches):
        end = matches[position + 1].start() if position + 1 < len(matches) else len(body)
        key = match.group(1).lower()
        if key not in clauses:
            clauses[key] = body[match.end():end].strip()
    return clauses


def _parse_from_clause(clause: str) -> tuple[str, str, str]:
    """Return (helo_or_host, connecting_ip, reverse_dns_name) for a ``from`` clause."""
    clause = clause.strip()
    if not clause:
        return "", "", ""
    token = _IPV6_PREFIX_RE.sub("", re.split(r"[\s(]", clause, maxsplit=1)[0].strip("[]")).rstrip(".").lower()
    if not token or token == "unknown" or _valid_ip(token):
        # The HELO name lives in a comment: "(helo=x)", "(EHLO x)", "(LHLO x)".
        helo = _HELO_RE.search(clause)
        from_host = helo.group(1).rstrip(".").lower() if helo else ""
        if _valid_ip(from_host):
            from_host = ""
    else:
        from_host = token
    depths = _depth_map(clause)
    comment_literal = ""
    bare_literal = ""
    for match in _BRACKET_IP_RE.finditer(clause):
        ip = _valid_ip(match.group(1))
        if not ip:
            continue
        if depths[match.start()] > 0:
            comment_literal = comment_literal or ip
        else:
            bare_literal = bare_literal or ip
    # The receiver-written comment literal is authoritative; a bare literal is
    # the client's own HELO claim; anything else is a last resort.
    from_ip = comment_literal or bare_literal
    if not from_ip:
        candidates = extract_ips(clause)
        from_ip = candidates[0] if candidates else ""
    rdns = ""
    rdns_match = _RDNS_RE.search(clause)
    if rdns_match:
        name = rdns_match.group(1).lower()
        if name != "unknown" and not _valid_ip(name):
            rdns = name
    return from_host, from_ip, rdns


def _protocol_from(with_text: str) -> str:
    if not with_text:
        return ""
    if with_text.lower().startswith("microsoft smtp server"):
        return "Microsoft SMTP Server"
    token = _first_token(with_text).strip(";,")
    return token.upper() if _SMTP_PROTOCOL_RE.match(token) else token


def _parse_timestamp(value: str) -> datetime | None:
    text = _strip_comments(value)
    if not text:
        return None
    try:
        parsed = parsedate_to_datetime(text)
    except (TypeError, ValueError, IndexError, OverflowError):  # malformed dates are data, not errors
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _parse_received_full(value: str) -> dict[str, Any]:
    """Tolerant parse of one Received header.  Superset of ``parse_received``
    with the extra keys ``rdns``, ``tls``, ``authenticated``, ``parsed``, ``raw``."""
    text = " ".join((value or "").split())
    depths = _depth_map(text)
    split_at = -1
    for position, ch in enumerate(text):
        if ch == ";" and depths[position] == 0:
            split_at = position
    if split_at >= 0:
        body, date_text = text[:split_at], text[split_at + 1:]
    else:
        body, date_text = text, ""
    clauses = _split_clauses(body)
    from_host, from_ip, rdns = _parse_from_clause(clauses.get("from", ""))
    with_text = _strip_comments(clauses.get("with", ""))
    protocol = _protocol_from(with_text)
    return {
        "raw": text,
        "from_host": from_host,
        "from_ip": from_ip,
        "by_host": _first_token(_strip_comments(clauses.get("by", ""))).strip("[];,").rstrip(".").lower(),
        "protocol": protocol,
        "hop_id": _first_token(_strip_comments(clauses.get("id", ""))).strip(";,"),
        "timestamp": _parse_timestamp(date_text),
        "for_addr": _first_token(_strip_comments(clauses.get("for", ""))).strip("<>;,").lower(),
        "rdns": rdns,
        "tls": bool(_TLS_RE.search(text)) or protocol.upper().endswith(("SMTPS", "SMTPSA")),
        "authenticated": bool(_AUTH_RE.search(text)),
        "parsed": bool(clauses),
    }


def parse_received(value: str) -> dict[str, Any]:
    """Parse one Received header into ``from_host``, ``from_ip``, ``by_host``,
    ``protocol``, ``hop_id``, ``timestamp`` (aware UTC datetime or None) and
    ``for_addr``.  Never raises."""
    full = _parse_received_full(value)
    keys = ("from_host", "from_ip", "by_host", "protocol", "hop_id", "timestamp", "for_addr")
    return {key: full[key] for key in keys}


# --------------------------------------------------------------------------- #
# Hop chain
# --------------------------------------------------------------------------- #
def _build_hops(infos: list[dict[str, Any]], cfg: Settings) -> list[Hop]:
    """Turn chronologically ordered parses into Hop models with per-hop anomalies."""
    hops: list[Hop] = []
    previous_ts: datetime | None = None
    for index, info in enumerate(infos):
        from_ip: str = info["from_ip"]
        from_host: str = info["from_host"]
        timestamp: datetime | None = info["timestamp"]
        private = bool(from_ip) and is_private_ip(from_ip)
        anomalies: list[str] = []
        if not info["parsed"] and timestamp is None:
            anomalies.append("unparseable")
        elif timestamp is None:
            anomalies.append("missing_timestamp")
        if private:
            anomalies.append("private_ip")
        delay: float | None = None
        if timestamp is not None and previous_ts is not None:
            delay = (timestamp - previous_ts).total_seconds()
            if delay < -60:
                anomalies.append("negative_delay")
            elif delay > 6 * 3600:
                anomalies.append("large_delay")
        if timestamp is not None:
            previous_ts = timestamp
        rdns: str = info["rdns"]
        if (
            from_host and rdns and "." in from_host and "." in rdns
            and registrable_domain(from_host) != registrable_domain(rdns)
        ):
            anomalies.append("helo_mismatch")
        if (
            from_ip and not private and info["protocol"]
            and _PLAINTEXT_PROTOCOL_RE.match(info["protocol"]) and not info["tls"]
        ):
            anomalies.append("no_tls")
        hops.append(
            Hop(
                index=index,
                raw=info["raw"],
                from_host=from_host,
                from_ip=from_ip,
                by_host=info["by_host"],
                protocol=info["protocol"],
                hop_id=info["hop_id"],
                timestamp=timestamp,
                delay_seconds=delay,
                is_private_ip=private,
                is_internal=_is_internal_host(info["by_host"], cfg) or _is_internal_host(from_host, cfg),
                anomalies=anomalies,
            )
        )
    return hops


def _flag_forged_order(hops: list[Hop], cfg: Settings) -> None:
    """A hop claiming delivery *by* an organisation server that sits earlier
    than a hop received *from* an external relay was injected by the sender."""
    for position, hop in enumerate(hops):
        if not _is_internal_host(hop.by_host, cfg):
            continue
        for later in hops[position + 1:]:
            if later.from_host and _is_internal_host(later.from_host, cfg):
                break  # the organisation handed the message onward itself: legitimate
            if later.from_ip and not later.is_private_ip and not _is_internal_host(later.from_host, cfg):
                hop.anomalies.append("forged_received_order")
                break


def _x_originating_ip(parsed: ParsedEmail) -> str:
    for header in parsed.headers:
        if header.name.lower() in _CLIENT_IP_HEADERS:
            for ip in extract_ips(header.value):
                if not is_private_ip(ip):
                    return ip
    return ""


def _select_origin(
    hops: list[Hop], infos: list[dict[str, Any]], x_originating_ip: str, cfg: Settings
) -> tuple[str, int | None, float, str]:
    """Return (originating_ip, hop_index, confidence, reasoning)."""
    if not hops:
        if x_originating_ip:
            return (
                x_originating_ip, None, 0.6,
                "No Received headers are present; using the client address recorded in an "
                "X-Originating-IP style header.",
            )
        return "", None, 0.0, "No Received headers are present, so the routing path cannot be reconstructed."

    for hop in hops:
        if not hop.from_ip or hop.is_private_ip or _is_internal_host(hop.from_host, cfg):
            continue
        doubts = sorted({a for h in hops[: hop.index + 1] for a in h.anomalies if a in _CHAIN_DOUBT})
        confidence = 0.7 if doubts else 0.9
        submission = bool(infos[hop.index]["authenticated"])
        if hop.index == 1 and hops[0].is_private_ip and submission:
            reason = (
                f"Authenticated submission from a client behind NAT: hop 0 shows the private address "
                f"{hops[0].from_ip} and hop 1 is an authenticated submission from {hop.from_ip} "
                f"to {hop.by_host or 'the submission server'}."
            )
        elif submission:
            reason = (
                f"Earliest public hop is an authenticated submission ({hop.protocol or 'SMTP AUTH'}) "
                f"from {hop.from_ip} to {hop.by_host or 'the submission server'}."
            )
        else:
            reason = (
                f"Earliest public, non-trusted hop: {hop.from_ip} handed the message to "
                f"{hop.by_host or 'an unnamed relay'} via {hop.protocol or 'an unknown protocol'}."
            )
        if doubts:
            reason += " Confidence reduced because the chain below this hop shows: " + ", ".join(doubts) + "."
        return hop.from_ip, hop.index, confidence, reason

    if x_originating_ip:
        return (
            x_originating_ip, None, 0.6,
            "The Received chain exposes no public external address; using the client address "
            "recorded by the submission server in an X-Originating-IP style header.",
        )
    for hop in hops:
        if hop.from_ip and not hop.is_private_ip:
            return (
                hop.from_ip, hop.index, 0.4,
                f"Only trusted or organisation relays expose public addresses; falling back to the "
                f"earliest of them ({hop.from_ip} at hop {hop.index}).",
            )
    return (
        "", None, 0.0,
        "Every hop shows a private or missing address; the true origin is hidden behind internal infrastructure.",
    )


# --------------------------------------------------------------------------- #
# Identity checks
# --------------------------------------------------------------------------- #
def _message_id_domain(message_id: str) -> str:
    value = (message_id or "").strip().strip("<>").strip()
    if "@" not in value:
        return ""
    return value.rsplit("@", 1)[1].strip().strip(">").rstrip(".").lower()


def _brand_in_display_name(name: str, cfg: Settings) -> tuple[str, list[str]]:
    """Return (brand_key, legitimate_domains) for the first brand named in ``name``."""
    for phrase in _ALIAS_PHRASES:
        if _word_match(phrase, name):
            key = _BRAND_ALIASES[phrase]
            return key, list(BRANDS.get(key, []))
    for key in _BRAND_KEYS:
        if _word_match(key, name):
            return key, list(BRANDS[key])
    for brand in cfg.protected_brands:
        brand = brand.strip().lower()
        if brand and _word_match(brand, name):
            return brand, list(cfg.org_domains)
    return "", []


def _executive_in_display_name(name: str, cfg: Settings) -> str:
    tokens = {t.strip().lower() for t in list(cfg.executives) + EXEC_TITLES if t.strip()}
    for token in sorted(tokens, key=len, reverse=True):
        if _word_match(token, name):
            return token
    return ""


def _finding(fid: str, severity: Severity, title: str, detail: str, **evidence: Any) -> Finding:
    return Finding(id=fid, module=MODULE, severity=severity, title=title, detail=detail, evidence=dict(evidence))


def _hop_label(hop: Hop) -> str:
    return f"hop {hop.index} ({hop.from_ip or hop.from_host or 'unnamed'} -> {hop.by_host or 'unnamed'})"


def _sentence(text: str) -> str:
    """Upper-case the first character without touching the rest (hostnames, IPs)."""
    return text[:1].upper() + text[1:]


def _timing_sentence(hop: Hop) -> str:
    delay = hop.delay_seconds or 0.0
    if delay < 0:
        return f"{_hop_label(hop)} is stamped {abs(delay):.0f} s earlier than the previous hop"
    return f"{_hop_label(hop)} waited {delay / 3600:.1f} h after the previous hop"


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #
def analyze_headers(parsed: ParsedEmail, cfg: Settings) -> HeaderAnalysis:
    """Reconstruct the routing chain, select the origin IP and check the
    identity headers for forgery.  Never raises on malformed input."""
    received = [h.value for h in parsed.headers if h.name.lower() == "received"]
    # Header order is latest-first; reverse so that index 0 is the earliest hop.
    infos = [_parse_received_full(value) for value in reversed(received)]
    hops = _build_hops(infos, cfg)
    _flag_forged_order(hops, cfg)
    x_originating_ip = _x_originating_ip(parsed)
    origin_ip, origin_index, origin_confidence, origin_reasoning = _select_origin(
        hops, infos, x_originating_ip, cfg
    )

    # Registrable domains of the identity headers ---------------------------
    sender_address = parsed.sender.address.lower()
    sender_domain = (parsed.sender.domain or "").lower()
    sender_rd = registrable_domain(sender_domain) if sender_domain else ""
    sender_freemail = sender_rd in FREEMAIL_DOMAINS
    return_path_domain = (parsed.return_path.domain or "").lower()
    return_path_rd = registrable_domain(return_path_domain) if return_path_domain else ""
    return_path_mismatch = bool(sender_rd and return_path_rd and sender_rd != return_path_rd)

    mismatched_reply: list[str] = []  # addresses whose registrable domain differs from the sender's
    mismatched_reply_domains: list[str] = []
    for reply in parsed.reply_to:
        if reply.domain and sender_rd:
            reply_rd = registrable_domain(reply.domain.lower())
            label = (reply.address or reply.domain).lower()
            if reply_rd != sender_rd and label not in mismatched_reply:
                mismatched_reply.append(label)
                mismatched_reply_domains.append(reply_rd)
    reply_to_mismatch = bool(mismatched_reply)

    message_id_domain = _message_id_domain(parsed.message_id)
    message_id_rd = registrable_domain(message_id_domain) if message_id_domain else ""
    relay_domains = {registrable_domain(h.by_host) for h in hops if h.by_host}
    message_id_mismatch = bool(
        message_id_rd and sender_rd and message_id_rd != sender_rd
        and message_id_rd not in relay_domains and message_id_rd not in _RELAY_PROVIDER_DOMAINS
    )

    # Display-name impersonation --------------------------------------------
    display_name = " ".join((parsed.sender.display_name or "").split())
    display_lower = display_name.lower()
    display_name_spoof = False
    display_name_brand = ""
    brand_key, brand_domains = _brand_in_display_name(display_lower, cfg) if display_lower else ("", [])
    brand_spoof = bool(brand_key and sender_rd and sender_rd not in {d.lower() for d in brand_domains})
    if brand_spoof:
        display_name_spoof = True
        display_name_brand = brand_key
    embedded = _EMAIL_RE.search(display_name)
    embedded_domain = embedded.group(1).lower() if embedded else ""
    embedded_spoof = bool(embedded_domain and sender_rd and registrable_domain(embedded_domain) != sender_rd)
    if embedded_spoof:
        display_name_spoof = True
        display_name_brand = display_name_brand or embedded_domain
    exec_token = ""
    if display_lower and sender_rd and not _host_matches(sender_domain, cfg.org_domains):
        exec_token = _executive_in_display_name(display_lower, cfg)
    if exec_token:
        display_name_spoof = True
        display_name_brand = display_name_brand or exec_token

    mailer = " ".join((parsed.mailer or "").split())
    bulk_mailer = bool(mailer and _BULK_MAILER_RE.search(mailer))

    # Chain-level facts -----------------------------------------------------
    public_hops = [h for h in hops if h.from_ip and not h.is_private_ip]
    private_only = bool(hops) and not public_hops
    negative_hops = [h for h in hops if "negative_delay" in h.anomalies]
    timing_hops = [h for h in hops if "negative_delay" in h.anomalies or "large_delay" in h.anomalies]
    forged_hops = [h for h in hops if "forged_received_order" in h.anomalies]
    no_tls_hops = [h for h in hops if "no_tls" in h.anomalies]
    helo_hops = [h for h in hops if "helo_mismatch" in h.anomalies]

    score = 0.0
    if reply_to_mismatch:
        score += 0.35
    if return_path_mismatch:
        score += 0.25
    if display_name_spoof:
        score += 0.45
    if message_id_mismatch:
        score += 0.15
    if forged_hops:
        score += 0.4
    if negative_hops:
        score += 0.2
    if private_only:
        score += 0.2
    if bulk_mailer:
        score += 0.1
    score = min(1.0, max(0.0, score))

    # Findings --------------------------------------------------------------
    findings: list[Finding] = []
    if not hops:
        findings.append(_finding(
            "empty_received_chain", Severity.MEDIUM, "No Received headers",
            "The message carries no Received headers, so its delivery path cannot be reconstructed; "
            "mail that was genuinely delivered over SMTP always has at least one.",
            received_count=0,
        ))
    if origin_ip:
        origin_hop = hops[origin_index] if origin_index is not None else None
        findings.append(_finding(
            "origin_identified", Severity.INFO, f"Origin IP {origin_ip}",
            f"{origin_ip} is the most likely origin of the message (confidence {origin_confidence:.2f}). "
            f"{origin_reasoning}",
            ip=origin_ip, hop_index=origin_index, confidence=origin_confidence,
            from_host=origin_hop.from_host if origin_hop else "",
            by_host=origin_hop.by_host if origin_hop else "",
            protocol=origin_hop.protocol if origin_hop else "",
            hop_count=len(hops), mailer=mailer,
        ))
    if x_originating_ip:
        findings.append(_finding(
            "x_originating_ip", Severity.INFO, "Submitting client IP recorded by the mail service",
            f"An X-Originating-IP style header records {x_originating_ip} as the client that submitted "
            f"the message; such headers are written by the submission server, not by the sender.",
            ip=x_originating_ip, used_as_origin=(x_originating_ip == origin_ip),
        ))
    if private_only:
        findings.append(_finding(
            "private_ip_origin", Severity.LOW, "Only private addresses in the routing chain",
            "Every Received hop shows a private, loopback or missing address, so the message was "
            "generated inside internal infrastructure or the external hops were stripped.",
            hops=[{"index": h.index, "from_ip": h.from_ip, "by_host": h.by_host} for h in hops],
        ))
    if forged_hops:
        findings.append(_finding(
            "forged_received_order", Severity.HIGH, "Received chain order is inconsistent",
            f"Hop(s) {', '.join(str(h.index) for h in forged_hops)} claim delivery by an organisation server "
            f"before the message was received from an external relay; such lines are typically injected "
            f"by the sender to make the message look internal.",
            hops=[{"index": h.index, "by_host": h.by_host, "raw": h.raw} for h in forged_hops],
        ))
    if timing_hops:
        findings.append(_finding(
            "timestamp_anomaly", Severity.MEDIUM if negative_hops else Severity.LOW,
            "Hop timestamps are inconsistent",
            _sentence("; ".join(_timing_sentence(h) for h in timing_hops))
            + ". Backwards clocks suggest forged or manipulated Received headers; very long gaps "
            "suggest queued or replayed mail.",
            hops=[
                {"index": h.index, "delay_seconds": h.delay_seconds, "from_ip": h.from_ip, "by_host": h.by_host,
                 "timestamp": h.timestamp.isoformat() if h.timestamp else None}
                for h in timing_hops
            ],
        ))
    if no_tls_hops:
        findings.append(_finding(
            "no_tls_hop", Severity.LOW, "Plaintext SMTP hop from a public address",
            f"{len(no_tls_hops)} public hop(s) delivered the message with plain "
            f"{', '.join(sorted({h.protocol for h in no_tls_hops}))} and no TLS: "
            f"{'; '.join(_hop_label(h) for h in no_tls_hops)}. Modern mail services negotiate TLS; "
            f"scripted senders and open relays often do not.",
            hops=[{"index": h.index, "from_ip": h.from_ip, "by_host": h.by_host, "protocol": h.protocol}
                  for h in no_tls_hops],
        ))
    if helo_hops:
        findings.append(_finding(
            "helo_mismatch", Severity.LOW, "HELO name does not match reverse DNS",
            _sentence("; ".join(
                f"hop {h.index} announced itself as {h.from_host} but the connecting address "
                f"{h.from_ip} resolves to {infos[h.index]['rdns']}"
                for h in helo_hops
            )) + ". Legitimate mail servers normally identify themselves consistently.",
            hops=[{"index": h.index, "from_host": h.from_host, "reverse_dns": infos[h.index]["rdns"],
                   "from_ip": h.from_ip} for h in helo_hops],
        ))
    if reply_to_mismatch:
        reply_freemail = any(domain in FREEMAIL_DOMAINS for domain in mismatched_reply_domains)
        findings.append(_finding(
            "reply_to_mismatch",
            Severity.HIGH if reply_freemail and not sender_freemail else Severity.MEDIUM,
            "Reply-To points to a different domain",
            f"Replies would go to {', '.join(mismatched_reply)} instead of the sender's domain {sender_rd}; "
            f"redirecting the conversation to an attacker-controlled mailbox is a classic BEC and phishing "
            f"technique.",
            reply_to=mismatched_reply, sender=sender_address, sender_domain=sender_rd,
        ))
    if return_path_mismatch:
        findings.append(_finding(
            "return_path_mismatch",
            Severity.LOW if return_path_rd in _RELAY_PROVIDER_DOMAINS else Severity.MEDIUM,
            "Return-Path domain differs from the From domain",
            f"The envelope sender {parsed.return_path.address.lower()} belongs to {return_path_rd} while the "
            f"visible From address belongs to {sender_rd}; the message was sent on behalf of the From "
            f"identity by a different party.",
            return_path=parsed.return_path.address.lower(), sender=sender_address,
            return_path_domain=return_path_rd, sender_domain=sender_rd,
        ))
    if message_id_mismatch:
        findings.append(_finding(
            "message_id_mismatch", Severity.LOW, "Message-ID generated by an unrelated host",
            f"The Message-ID was generated at {message_id_domain}, which matches neither the sender domain "
            f"{sender_rd} nor any relay in the Received chain; mail composed by scripts or on rogue hosts "
            f"often shows this.",
            message_id=parsed.message_id, message_id_domain=message_id_domain, sender_domain=sender_rd,
            relay_domains=sorted(d for d in relay_domains if d),
        ))
    if brand_spoof or embedded_spoof:
        if brand_spoof:
            detail = (
                f'The display name "{display_name}" references {brand_key} but the message comes from '
                f"{sender_domain}, which is not a {brand_key} domain"
                + (f" (legitimate: {', '.join(brand_domains)})" if brand_domains else "") + "."
            )
        else:
            detail = (
                f'The display name "{display_name}" embeds the address {embedded.group(0) if embedded else ""} '
                f"whose domain differs from the real sender {sender_domain}; recipients see the fake address "
                f"instead of the true one."
            )
        findings.append(_finding(
            "display_name_spoof", Severity.HIGH, f"Display name imitates {display_name_brand}",
            detail, display_name=display_name, brand=display_name_brand, sender=sender_address,
            sender_domain=sender_domain, legitimate_domains=brand_domains,
        ))
    if exec_token:
        findings.append(_finding(
            "executive_impersonation_display",
            Severity.HIGH if sender_freemail else Severity.MEDIUM,
            "Display name claims an executive identity",
            f'The display name "{display_name}" carries the executive marker "{exec_token}" while the message '
            f"originates outside the organisation's domains ({sender_domain}); this is the hallmark of "
            f"CEO-fraud first-touch emails.",
            display_name=display_name, marker=exec_token, sender=sender_address, sender_domain=sender_domain,
            free_mail_sender=sender_freemail,
        ))
    if bulk_mailer:
        findings.append(_finding(
            "bulk_mailer", Severity.LOW, "Scripted or bulk mailing software",
            f"The message was generated by {mailer}, a scripting or bulk-mailing library that is rarely used "
            f"for personal or transactional correspondence.",
            mailer=mailer,
        ))

    anomalies: list[str] = []
    for hop in hops:
        for anomaly in hop.anomalies:
            if anomaly not in anomalies:
                anomalies.append(anomaly)
    for flag, name in (
        (private_only, "private_only_chain"),
        (not hops, "empty_received_chain"),
        (reply_to_mismatch, "reply_to_mismatch"),
        (return_path_mismatch, "return_path_mismatch"),
        (message_id_mismatch, "message_id_mismatch"),
        (brand_spoof or embedded_spoof, "display_name_spoof"),
        (bool(exec_token), "executive_impersonation"),
        (bulk_mailer, "bulk_mailer"),
    ):
        if flag and name not in anomalies:
            anomalies.append(name)

    log.debug(
        "headers: %d hops, origin=%s (conf %.2f), score=%.2f, anomalies=%s",
        len(hops), origin_ip or "-", origin_confidence, score, anomalies,
    )
    return HeaderAnalysis(
        hops=hops,
        originating_ip=origin_ip,
        originating_hop_index=origin_index,
        origin_confidence=origin_confidence,
        origin_reasoning=origin_reasoning,
        x_originating_ip=x_originating_ip,
        message_id_domain=message_id_domain,
        message_id_mismatch=message_id_mismatch,
        return_path_mismatch=return_path_mismatch,
        reply_to_mismatch=reply_to_mismatch,
        display_name_spoof=display_name_spoof,
        display_name_brand=display_name_brand,
        anomalies=anomalies,
        score=score,
        findings=findings,
    )
