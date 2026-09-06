"""URL extraction and analysis."""
from __future__ import annotations

import base64
import binascii
import ipaddress
import logging
import re
from collections.abc import Callable
from html import unescape
from html.parser import HTMLParser
from urllib.parse import parse_qsl, unquote, urlsplit, urlunsplit

from ..config import Settings
from ..schemas import SEVERITY_ORDER, Finding, ParsedEmail, Severity, UrlAnalysis, UrlInfo
from .knowledge import (
    BRANDS,
    FREEMAIL_DOMAINS,
    HOMOGLYPHS,
    RISKY_EXTENSIONS,
    SUSPICIOUS_TLDS,
    URL_SHORTENERS,
    URL_SUSPICIOUS_KEYWORDS,
)

log = logging.getLogger("mailtrace.urls")

# Registrable domain (public-suffix aware, no network)
_FALLBACK_SUFFIXES: frozenset[str] = frozenset({
    "co.in", "net.in", "org.in", "ac.in", "gov.in", "nic.in", "res.in", "edu.in", "firm.in", "gen.in", "ind.in",
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "ltd.uk", "plc.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au",
    "co.jp", "ne.jp", "or.jp", "ac.jp", "go.jp",
    "co.za", "org.za", "gov.za",
    "com.br", "net.br", "org.br", "gov.br",
    "com.sg", "edu.sg", "gov.sg", "com.my", "gov.my",
    "co.nz", "org.nz", "govt.nz", "com.mx", "gob.mx", "com.ar",
    "co.kr", "or.kr", "com.tr", "gov.tr", "com.cn", "net.cn", "org.cn", "gov.cn",
    "com.hk", "com.tw", "com.pk", "gov.pk", "com.bd", "com.np", "com.lk", "gov.lk",
    "com.ng", "com.gh", "com.ke", "co.ke", "com.eg", "com.sa", "com.ae", "co.id", "com.ph", "com.vn",
})

_EXTRACTOR = None
try:  # tldextract ships a bundled public-suffix snapshot; never touch the network
    import tldextract

    _EXTRACTOR = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)
except ImportError:
    log.warning("tldextract unavailable; using built-in public-suffix fallback")


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def registrable_domain(host: str) -> str:
    """Return the organisational (registrable) domain of ``host``."""
    host = (host or "").strip().lower().rstrip(".")
    if not host:
        return ""
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    if _is_ip(host):
        return host
    if _EXTRACTOR is not None:
        try:
            ext = _EXTRACTOR(host)
            if ext.domain and ext.suffix:
                return f"{ext.domain}.{ext.suffix}"
            if ext.domain:
                return ext.domain
        except (ValueError, TypeError):  # a label tldextract cannot split
            pass
    labels = [label for label in host.split(".") if label]
    if len(labels) >= 3 and ".".join(labels[-2:]) in _FALLBACK_SUFFIXES:
        return ".".join(labels[-3:])
    if len(labels) >= 2:
        return ".".join(labels[-2:])
    return host


# Brand knowledge derived once
BRAND_LEGIT_DOMAINS: frozenset[str] = frozenset(d.lower() for domains in BRANDS.values() for d in domains)
_DOMAIN_TO_BRAND: dict[str, str] = {}
for _key, _domains in BRANDS.items():
    for _d in _domains:
        _DOMAIN_TO_BRAND.setdefault(_d.lower(), _key)

_CREDENTIAL_KEYWORDS: frozenset[str] = frozenset({
    "login", "log-in", "signin", "sign-in", "verify", "verification", "password", "credential",
    "auth", "authenticate", "account", "confirm", "kyc", "unlock", "recover", "secure", "webmail",
    "owa", "update", "aadhaar", "pan", "wallet",
})
_REDIRECT_KEYS: frozenset[str] = frozenset({
    "url", "redirect", "redirect_uri", "redirect_url", "redirecturl", "next", "return", "returnurl",
    "return_url", "goto", "dest", "dest_url", "destination", "continue", "r", "u", "q", "target", "link",
    "forward", "to", "ref", "rurl", "redir", "location",
})
_MULTI_CHAR_CONFUSABLES: tuple[tuple[str, str], ...] = (("rn", "m"), ("vv", "w"), ("cl", "d"))
_SAAS_TENANT_DOMAINS: frozenset[str] = frozenset({
    "zendesk.com", "freshdesk.com", "freshservice.com", "atlassian.net", "myshopify.com",
    "salesforce.com", "force.com", "hubspot.com", "hubspotemail.net", "mailchimp.com",
    "list-manage.com", "sendgrid.net", "workday.com", "greenhouse.io", "lever.co",
    "bamboohr.com", "servicenow.com", "onmicrosoft.com", "office.net", "slack.com",
    "zoho.com", "zohodesk.com", "notion.site", "wixsite.com", "squarespace.com",
})
# TLDs accepted when deciding whether visible anchor text "looks like" a host.
_PLAUSIBLE_TLDS: frozenset[str] = frozenset({
    "com", "net", "org", "in", "co", "io", "gov", "edu", "info", "biz", "me", "us", "uk", "de",
    "fr", "au", "ca", "jp", "sg", "ae", "sbi", "bank", "xyz", "top", "online", "site", "app",
    "dev", "ai", "cloud", "shop", "store", "tech", "live", "link", "click", "icu", "buzz", "cc",
    "tv", "ly", "gl", "ru", "cn", "eu", "nl", "it", "es", "br", "za", "nz", "ie", "ch", "se",
})

_RISK_VALUE: dict[str, float] = {"info": 0.0, "low": 0.2, "medium": 0.45, "high": 0.75, "critical": 1.0}
_MAX_URLS = 60


# Extraction
_TEXT_URL_RE = re.compile(
    r"""
    (?:https?|ftp)://[^\s<>"'`\)\]]+                                   # explicit scheme
    | (?<![@\w./-])www\.[a-z0-9-]+(?:\.[a-z0-9-]+)+(?:/[^\s<>"'`\)\]]*)?  # www. links
    | (?<![@\w./:-])(?:[a-z0-9-]+\.)+[a-z]{2,24}/[^\s<>"'`\)\]]*          # bare domain WITH a path
    """,
    re.IGNORECASE | re.VERBOSE,
)
_TRAILING_PUNCT = ".,;:!?'\"<>"
_SKIP_SCHEMES = ("mailto:", "cid:", "tel:", "sms:", "callto:")


class _LinkParser(HTMLParser):
    """Collects hrefs with their visible anchor text."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[tuple[str, str]] = []
        self._href: str | None = None
        self._text: list[str] = []
        self._skip_depth = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = {name.lower(): (value or "") for name, value in attrs}
        if tag in ("script", "style"):
            self._skip_depth += 1
            return
        if tag in ("a", "area"):
            if self._href is not None:
                self._flush()
            self._href = attributes.get("href", "").strip()
            self._text = []
        elif tag == "form":
            action = attributes.get("action", "").strip()
            if action:
                self.links.append((action, ""))
        elif tag == "iframe":
            src = attributes.get("src", "").strip()
            if src:
                self.links.append((src, ""))

    def handle_endtag(self, tag: str) -> None:
        if tag in ("script", "style"):
            self._skip_depth = max(0, self._skip_depth - 1)
        elif tag in ("a", "area") and self._href is not None:
            self._flush()

    def handle_data(self, data: str) -> None:
        if self._href is not None and not self._skip_depth:
            self._text.append(data)

    def _flush(self) -> None:
        href = self._href or ""
        text = " ".join(" ".join(self._text).split())
        if href:
            self.links.append((href, text))
        self._href = None
        self._text = []

    def finish(self) -> None:
        if self._href is not None:
            self._flush()


def _clean_text_url(raw: str) -> str:
    url = raw.strip()
    while url and url[-1] in _TRAILING_PUNCT:
        url = url[:-1]
    # A closing parenthesis only belongs to the URL if it was opened inside it.
    while url.endswith(")") and url.count("(") < url.count(")"):
        url = url[:-1]
    return url


def _keep(url: str) -> bool:
    lowered = url.strip().lower()
    if not lowered or lowered.startswith("#"):
        return False
    return not lowered.startswith(_SKIP_SCHEMES)


def extract_urls(text: str, html: str) -> list[tuple[str, str]]:
    """Return ``(url, anchor_text)`` pairs from both message parts, deduplicated"""
    found: dict[str, tuple[str, str]] = {}

    def add(url: str, anchor: str) -> None:
        url = unescape(url).strip()
        if not _keep(url):
            return
        key = normalize_url(url)
        if not key:
            return
        if key in found:
            existing_url, existing_anchor = found[key]
            if not existing_anchor and anchor:
                found[key] = (existing_url, anchor)
            return
        found[key] = (url, anchor)

    if html:
        parser = _LinkParser()
        try:
            parser.feed(html)
            parser.close()
        except Exception:  # malformed HTML must not abort
            log.debug("HTML link parsing stopped early", exc_info=True)
        parser.finish()
        for href, anchor in parser.links:
            add(href, anchor)
        # Links that only appear as text inside the HTML (unlinked URLs).
        for match in _TEXT_URL_RE.finditer(_strip_tags(html)):
            add(_clean_text_url(match.group(0)), "")
    if text:
        for match in _TEXT_URL_RE.finditer(text):
            add(_clean_text_url(match.group(0)), "")
    return list(found.values())[:_MAX_URLS]


_TAG_RE = re.compile(r"<[^>]+>")


def _strip_tags(html: str) -> str:
    return _TAG_RE.sub(" ", html)


# Normalisation
_UNRESERVED = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")
_PCT_RE = re.compile(r"%([0-9A-Fa-f]{2})")


def _unquote_unreserved(value: str) -> str:
    def repl(match: re.Match[str]) -> str:
        char = chr(int(match.group(1), 16))
        return char if char in _UNRESERVED else match.group(0).upper()

    return _PCT_RE.sub(repl, value)


def normalize_url(url: str) -> str:
    """Lower-case scheme/host, drop the fragment and default ports, decode"""
    url = (url or "").strip()
    if not url:
        return ""
    lowered = url.lower()
    if lowered.startswith(("data:", "javascript:")):
        scheme, _, rest = url.partition(":")
        return f"{scheme.lower()}:{rest.strip()}"
    if "://" not in url:
        if url.startswith("//"):
            url = "http:" + url
        else:
            url = "http://" + url
    try:
        parts = urlsplit(url)
    except ValueError:
        return ""
    scheme = parts.scheme.lower()
    try:
        host = (parts.hostname or "").lower().rstrip(".")
        port = parts.port
    except ValueError:  # e.g. non-numeric port
        host, port = parts.netloc.lower(), None
    if not host:
        return ""
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    netloc = host
    if port and not ((scheme == "http" and port == 80) or (scheme == "https" and port == 443)):
        netloc = f"{host}:{port}"
    if parts.username:
        userinfo = parts.username + (f":{parts.password}" if parts.password else "")
        netloc = f"{userinfo}@{netloc}"
    path = _unquote_unreserved(parts.path) or "/"
    query = _unquote_unreserved(parts.query)
    return urlunsplit((scheme, netloc, path, query, ""))


_MAX_TYPOSQUAT_DISTANCE = 2


def damerau_levenshtein(a: str, b: str) -> int:
    """Optimal-string-alignment distance (insert, delete, substitute, transpose)."""
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    previous2: list[int] = []
    previous = list(range(len(b) + 1))
    for i, char_a in enumerate(a, start=1):
        current = [i] + [0] * len(b)
        for j, char_b in enumerate(b, start=1):
            cost = 0 if char_a == char_b else 1
            current[j] = min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + cost)
            if i > 1 and j > 1 and char_a == b[j - 2] and a[i - 2] == char_b:
                current[j] = min(current[j], previous2[j - 2] + 1)
        previous2, previous = previous, current
    return previous[len(b)]


def _fold_homoglyphs(value: str) -> str:
    return "".join(HOMOGLYPHS.get(ch, ch) for ch in value)


def _fold_multichar(value: str) -> str:
    for pair, replacement in _MULTI_CHAR_CONFUSABLES:
        value = value.replace(pair, replacement)
    return value


def _decode_idna(host: str) -> str:
    try:
        return host.encode("ascii").decode("idna")
    except (UnicodeError, ValueError):
        return host


def _sld(registrable: str) -> str:
    return registrable.split(".")[0] if registrable else ""


def _candidates(cfg: Settings) -> dict[str, tuple[str, frozenset[str]]]:
    """key -> (display name, legitimate domains).  Brands first, then the"""
    result: dict[str, tuple[str, frozenset[str]]] = {}
    for key, domains in BRANDS.items():
        result[key] = (key, frozenset(d.lower() for d in domains))
    for org in cfg.org_domains:
        org_rd = registrable_domain(org)
        key = _sld(org_rd)
        if key:
            result[key] = (org_rd, frozenset({org_rd}))
    for brand in cfg.protected_brands:
        brand = brand.strip().lower()
        if not brand:
            continue
        if "." in brand:
            rd = registrable_domain(brand)
            key = _sld(rd)
            if key:
                result.setdefault(key, (rd, frozenset({rd})))
        else:
            result.setdefault(brand, (brand, frozenset()))
    return result


def _token_contains(sld: str, key: str) -> bool:
    if len(key) < 3 or key not in sld or sld == key:
        return False
    return re.search(rf"(?:^|[-_.0-9]){re.escape(key)}(?:[-_.0-9]|$)", sld) is not None


def is_lookalike(host: str, cfg: Settings) -> tuple[str, str]:
    """Return ``(imitated, technique)`` or ``("", "")``."""
    host = (host or "").strip().lower().rstrip(".")
    if not host or _is_ip(host):
        return "", ""
    org_domains = {registrable_domain(d) for d in cfg.org_domains if d}
    rd = registrable_domain(host)
    if not rd or rd in org_domains or rd in BRAND_LEGIT_DOMAINS or rd in FREEMAIL_DOMAINS:
        return "", ""

    candidates = _candidates(cfg)
    all_legit = set(BRAND_LEGIT_DOMAINS) | org_domains

    technique_prefix = ""
    if "xn--" in host:
        decoded = _decode_idna(host)
        if decoded != host:
            technique_prefix = "punycode"
            host = decoded
            rd = registrable_domain(host)
            if rd in all_legit:
                # An IDN encoding of a legitimate name is itself deceptive.
                return _DOMAIN_TO_BRAND.get(rd, rd), "punycode"
    sld = _sld(rd)
    if not sld:
        return "", ""

    def result(name: str, technique: str) -> tuple[str, str]:
        return name, (technique_prefix or technique)

    # 2. homoglyph -------------------------------------------------------
    folded = _fold_homoglyphs(sld)
    if folded != sld:
        suffix = rd[len(sld) + 1:] if len(rd) > len(sld) else ""
        for key, (name, legit) in candidates.items():
            if folded == key or (suffix and f"{folded}.{suffix}" in legit):
                return result(name, "homoglyph")
        if suffix and f"{folded}.{suffix}" in all_legit:
            return result(_DOMAIN_TO_BRAND.get(f"{folded}.{suffix}", f"{folded}.{suffix}"), "homoglyph")

    multichar = _fold_multichar(_fold_homoglyphs(sld))
    for key, (name, legit) in candidates.items():
        if len(key) < 5 or sld == key or rd in legit:
            continue
        if multichar == key:
            return result(name, "typosquat")
        if sld[0] != key[0] or abs(len(sld) - len(key)) > _MAX_TYPOSQUAT_DISTANCE:
            continue
        distance = damerau_levenshtein(sld, key)
        if distance == 1:
            return result(name, "typosquat")
        if distance == 2 and len(key) >= 8:
            return result(name, "typosquat")

    # 4. tld swap --------------------------------------------------------
    for key, (name, legit) in candidates.items():
        if sld == key and rd not in legit:
            return result(name, "tld_swap")

    # 5. extra token -----------------------------------------------------
    for key, (name, legit) in candidates.items():
        if rd not in legit and _token_contains(sld, key):
            return result(name, "extra_token")

    # 6. sub-domain abuse ------------------------------------------------
    sub = host[: -len(rd)].rstrip(".") if host.endswith(rd) and len(host) > len(rd) else ""
    if sub:
        labels = sub.split(".")
        dotted_sub = f".{sub}."
        for key, (name, legit) in candidates.items():
            if name in org_domains and rd in _SAAS_TENANT_DOMAINS:
                continue  # "<org>.zendesk.com" is a normal tenant host
            if key in labels or any(f".{d}." in dotted_sub for d in legit):
                return result(name, "subdomain_abuse")
    return "", ""


# Per-URL analysis
_HOST_IN_TEXT_RE = re.compile(
    r"(?:(?:https?|ftp)://)?(?:www\.)?((?:[a-z0-9-]+\.)+[a-z]{2,24})(?:[/:?#]|$)", re.IGNORECASE
)
_HEX_IP_RE = re.compile(r"^0x[0-9a-f]+$", re.IGNORECASE)
_DOTTED_NUMERIC_RE = re.compile(r"^(?:0x[0-9a-f]+|0[0-7]+|\d+)(?:\.(?:0x[0-9a-f]+|0[0-7]+|\d+)){1,3}$", re.IGNORECASE)
_B64_RE = re.compile(r"^[A-Za-z0-9+/_-]{16,}={0,2}$")


def _anchor_host(anchor_text: str) -> str:
    """Host named by visible link text such as 'https://onlinesbi.sbi' or"""
    text = (anchor_text or "").strip().lower()
    if not text:
        return ""
    first = text.split()[0]
    match = _HOST_IN_TEXT_RE.search(first)
    if not match:
        return ""
    host = match.group(1)
    explicit = "://" in first or first.startswith("www.")
    if not explicit and host.rsplit(".", 1)[-1] not in _PLAUSIBLE_TLDS:
        return ""
    return host


def _numeric_ip_form(host: str) -> bool:
    """Decimal (3232235777), hex (0xC0A80101) or mixed/octal dotted forms."""
    if host.isdigit() and int(host) > 255:
        return True
    if _HEX_IP_RE.match(host):
        return True
    return bool(_DOTTED_NUMERIC_RE.match(host)) and not _is_ip(host)


def _looks_base64(value: str) -> bool:
    if not _B64_RE.match(value):
        return False
    padded = value + "=" * (-len(value) % 4)
    for decoder in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            decoded = decoder(padded)
        except (binascii.Error, ValueError):
            continue
        if decoded and sum(32 <= b < 127 for b in decoded) / len(decoded) > 0.8:
            return True
    return False


def _path_extension(path: str) -> str:
    segment = path.rsplit("/", 1)[-1]
    if "." not in segment:
        return ""
    return segment.rsplit(".", 1)[-1].lower()


def analyze_url(url: str, anchor_text: str, cfg: Settings) -> UrlInfo:
    """Classify one link.  Never raises."""
    original = (url or "").strip()
    normalized = normalize_url(original)
    info = UrlInfo(url=original[:2048], normalized=normalized[:2048], anchor_text=(anchor_text or "")[:200])
    reasons: list[str] = []
    obfuscation: list[str] = []
    lowered = normalized.lower()

    if lowered.startswith("data:"):
        info.scheme = "data"
        obfuscation.append("data_uri")
        reasons.append("Link is an inline data: URI (hidden payload delivered inside the message)")
        info.obfuscation, info.reasons, info.risk = obfuscation, reasons, Severity.HIGH
        return info
    if lowered.startswith("javascript:"):
        info.scheme = "javascript"
        obfuscation.append("javascript_uri")
        reasons.append("Link executes script (javascript: URI) instead of opening a page")
        info.obfuscation, info.reasons, info.risk = obfuscation, reasons, Severity.HIGH
        return info
    if not normalized:
        info.risk = Severity.INFO
        info.reasons = ["Could not be parsed as a URL"]
        return info

    parts = urlsplit(normalized)  # normalize_url already proved this splits
    host = (parts.hostname or "").lower()
    try:
        port = parts.port
    except ValueError:  # non-numeric port survives normalisation as text
        port = None
    userinfo = "@" in parts.netloc
    try:
        raw_netloc = urlsplit(original if "://" in original else "http://" + original).netloc
    except ValueError:
        raw_netloc = ""
    info.scheme = parts.scheme
    info.host = host
    info.path = parts.path
    info.registrable_domain = registrable_domain(host)
    info.tld = host.rsplit(".", 1)[-1] if "." in host else ""
    org_domains = {registrable_domain(d) for d in cfg.org_domains if d}
    legit_brand = info.registrable_domain in BRAND_LEGIT_DOMAINS or info.registrable_domain in org_domains

    # Host shape -----------------------------------------------------------
    if _is_ip(host):
        info.is_ip_literal = True
        reasons.append(f"Link points at a raw IP address ({host}) instead of a domain name")
    elif _numeric_ip_form(host):
        info.is_ip_literal = True
        obfuscation.append("numeric_ip_form")
        reasons.append(f"Host '{host}' is an obfuscated numeric IP address")
    if info.registrable_domain in URL_SHORTENERS or host in URL_SHORTENERS:
        info.is_shortener = True
        reasons.append(f"URL shortener {info.registrable_domain} hides the real destination")
    if "xn--" in host:
        info.is_punycode = True
        reasons.append(f"Internationalised (punycode) host {host} can imitate a familiar name")
    if userinfo:
        info.has_userinfo = True
        reasons.append("Authority contains '@': the text before it is a decoy, the real host follows it")

    # Obfuscation ------------------------------------------------------------
    if "%" in raw_netloc:
        obfuscation.append("percent_encoded_host")
    if host and not info.is_ip_literal:
        extra_labels = host.count(".") - info.registrable_domain.count(".")
        if extra_labels > 3:
            obfuscation.append("excessive_subdomains")
    if len(normalized) > 120:
        obfuscation.append("long_url")
    query_pairs = parse_qsl(parts.query, keep_blank_values=True) if normalized else []
    if any(_looks_base64(value) for _, value in query_pairs):
        obfuscation.append("base64_in_query")
    tail = normalized.split("://", 1)[1] if "://" in normalized else normalized
    if "://" in tail or re.search(r"https?(?::|%3a)", tail, re.IGNORECASE):
        obfuscation.append("double_scheme")
    if len(_PCT_RE.findall(parts.path + parts.query)) >= 3 or "\\x" in lowered:
        obfuscation.append("hex_escapes")
    redirect = False
    for key, value in query_pairs:
        target = unquote(value).lower()
        if key.lower() in _REDIRECT_KEYS and (target.startswith(("http://", "https://", "//")) or "://" in target):
            redirect = True
            break
    if redirect:
        obfuscation.append("redirect_parameter")
        reasons.append("Query string carries a redirect target: the visible host is only a relay")
    sub_part = host[: -len(info.registrable_domain)].rstrip(".") if info.registrable_domain and host.endswith(info.registrable_domain) else ""
    if sub_part and not legit_brand:
        sub_labels = sub_part.split(".")
        brands_in_sub = [key for key in BRANDS if key in sub_labels or any(d == sub_part or sub_part.endswith("." + d) for d in BRANDS[key])]
        if brands_in_sub:
            obfuscation.append("brand_in_subdomain")
            reasons.append(f"Brand '{brands_in_sub[0]}' appears in the sub-domain but the site belongs to {info.registrable_domain}")
    if info.tld in SUSPICIOUS_TLDS and not legit_brand:
        obfuscation.append("suspicious_tld")
        reasons.append(f"Top-level domain .{info.tld} is heavily abused in phishing")
    if port and port not in (80, 443, 8080, 8443):
        obfuscation.append("port_unusual")
        reasons.append(f"Unusual port {port}")
    extension = _path_extension(parts.path if normalized else "")
    executable = RISKY_EXTENSIONS.get(extension) in ("critical", "high")
    if executable:
        obfuscation.append("file_extension_executable")
        reasons.append(f"Link downloads a .{extension} file")

    # Keywords & lookalike ---------------------------------------------------
    haystack = f"{host} {unquote(parts.path).lower()}" if normalized else host
    info.suspicious_keywords = [kw for kw in URL_SUSPICIOUS_KEYWORDS if kw in haystack]
    imitated, technique = ("", "") if legit_brand else is_lookalike(host, cfg)
    if imitated:
        info.lookalike_of = imitated
        reasons.append(f"Host {host} imitates {imitated} ({technique})")

    # Anchor mismatch ----------------------------------------------------------
    anchor_host = _anchor_host(anchor_text)
    if anchor_host:
        anchor_rd = registrable_domain(anchor_host)
        if anchor_rd and info.registrable_domain and anchor_rd != info.registrable_domain:
            info.anchor_mismatch = True
            reasons.append(f"Visible link text shows {anchor_host} but the link opens {host}")

    cred_keywords = [kw for kw in info.suspicious_keywords if kw in _CREDENTIAL_KEYWORDS]
    if cred_keywords and not legit_brand:
        reasons.append(f"Path/host contains credential-harvest keywords {', '.join(cred_keywords[:4])}")

    # Risk -----------------------------------------------------------------------
    brand_userinfo = info.has_userinfo and any(key in lowered.split("@")[0] for key in BRANDS)
    if executable or ((imitated or "brand_in_subdomain" in obfuscation) and info.suspicious_keywords) or brand_userinfo:
        risk = Severity.CRITICAL
    elif (
        info.is_ip_literal or info.anchor_mismatch or info.is_punycode or info.has_userinfo or imitated
        or (redirect and info.suspicious_keywords)
    ):
        risk = Severity.HIGH
    elif info.is_shortener or "suspicious_tld" in obfuscation or "brand_in_subdomain" in obfuscation or len(obfuscation) >= 2:
        risk = Severity.MEDIUM
    elif obfuscation or (len(cred_keywords) >= 2 and not legit_brand):
        risk = Severity.LOW
    else:
        risk = Severity.INFO
    if legit_brand and risk in (Severity.LOW, Severity.MEDIUM) and not info.anchor_mismatch and not info.has_userinfo:
        risk = Severity.INFO
    info.obfuscation = obfuscation
    info.reasons = reasons
    info.risk = risk
    return info


# Whole-message analysis
def _finding(fid: str, severity: Severity, title: str, detail: str, evidence: dict[str, object]) -> Finding:
    return Finding(id=fid, module="urls", severity=severity, title=title, detail=detail, evidence=evidence)


def analyze_urls(parsed: ParsedEmail, cfg: Settings) -> UrlAnalysis:
    """Extract and classify every link; aggregate a score and findings."""
    pairs = extract_urls(parsed.text_body or "", parsed.html_body or "")
    urls: list[UrlInfo] = []
    for url, anchor in pairs:
        try:
            urls.append(analyze_url(url, anchor, cfg))
        except Exception:  # one bad link must not abort the analysis
            log.exception("failed to analyse url %r", url[:200])
    unique_domains: list[str] = []
    for u in urls:
        if u.registrable_domain and u.registrable_domain not in unique_domains:
            unique_domains.append(u.registrable_domain)

    severe = [u for u in urls if SEVERITY_ORDER[u.risk.value] >= SEVERITY_ORDER["high"]]
    top = max((_RISK_VALUE[u.risk.value] for u in urls), default=0.0)
    score = min(1.0, top + 0.05 * max(0, len(severe) - 1))

    findings: list[Finding] = []
    org_domains = {registrable_domain(d) for d in cfg.org_domains if d}

    def urls_where(predicate: Callable[[UrlInfo], bool]) -> list[UrlInfo]:
        return [u for u in urls if predicate(u)]

    def evidence_for(items: list[UrlInfo]) -> dict[str, object]:
        return {"urls": [u.url[:300] for u in items[:8]], "count": len(items)}

    harvest = urls_where(
        lambda u: any(kw in _CREDENTIAL_KEYWORDS for kw in u.suspicious_keywords)
        and SEVERITY_ORDER[u.risk.value] >= SEVERITY_ORDER["medium"]
        and u.registrable_domain not in BRAND_LEGIT_DOMAINS
        and u.registrable_domain not in org_domains
    )
    if harvest:
        hosts = ", ".join(dict.fromkeys(u.host for u in harvest[:3]))
        findings.append(_finding(
            "credential_harvest_link", Severity.HIGH, "Credential-harvest link",
            f"{len(harvest)} link(s) lead to login/verification pages on non-brand hosts ({hosts}).",
            evidence_for(harvest),
        ))
    lookalikes = urls_where(lambda u: bool(u.lookalike_of))
    if lookalikes:
        imitated = ", ".join(dict.fromkeys(u.lookalike_of for u in lookalikes))
        sev = Severity.CRITICAL if any(u.lookalike_of in org_domains for u in lookalikes) else Severity.HIGH
        findings.append(_finding(
            "lookalike_domain_link", sev, "Link to a lookalike domain",
            f"Link host(s) imitate {imitated}: {', '.join(dict.fromkeys(u.host for u in lookalikes[:3]))}.",
            evidence_for(lookalikes) | {"imitated": imitated},
        ))
    mismatched = urls_where(lambda u: u.anchor_mismatch)
    if mismatched:
        sample = mismatched[0]
        findings.append(_finding(
            "anchor_href_mismatch", Severity.HIGH, "Visible link text differs from real destination",
            f"The text '{sample.anchor_text[:80]}' opens {sample.host} instead of the site it displays.",
            evidence_for(mismatched) | {"anchor_text": sample.anchor_text[:120]},
        ))
    ip_links = urls_where(lambda u: u.is_ip_literal)
    if ip_links:
        findings.append(_finding(
            "ip_literal_link", Severity.HIGH, "Link to a raw IP address",
            f"{len(ip_links)} link(s) use an IP address instead of a domain, which bypasses domain reputation.",
            evidence_for(ip_links),
        ))
    shorteners = urls_where(lambda u: u.is_shortener)
    if shorteners:
        findings.append(_finding(
            "url_shortener", Severity.MEDIUM, "Shortened link hides destination",
            f"{len(shorteners)} link(s) go through URL shorteners ({', '.join(dict.fromkeys(u.registrable_domain for u in shorteners[:3]))}).",
            evidence_for(shorteners),
        ))
    puny = urls_where(lambda u: u.is_punycode)
    if puny:
        findings.append(_finding(
            "punycode_url", Severity.HIGH, "Internationalised domain in link",
            "Punycode hosts render as familiar-looking Unicode names and are a classic homograph technique.",
            evidence_for(puny),
        ))
    userinfo = urls_where(lambda u: u.has_userinfo)
    if userinfo:
        findings.append(_finding(
            "userinfo_trick", Severity.HIGH, "Decoy text before '@' in link",
            "The part before '@' is ignored by browsers; the real host is the one after it.",
            evidence_for(userinfo),
        ))
    redirects = urls_where(lambda u: "redirect_parameter" in u.obfuscation)
    if redirects:
        findings.append(_finding(
            "open_redirect", Severity.HIGH, "Redirect parameter in link",
            "The link bounces through a redirect parameter, so the visible host is not the final destination.",
            evidence_for(redirects),
        ))
    executables = urls_where(lambda u: "file_extension_executable" in u.obfuscation)
    if executables:
        findings.append(_finding(
            "executable_link", Severity.CRITICAL, "Link downloads an executable",
            f"{len(executables)} link(s) point directly at executable or script files.",
            evidence_for(executables),
        ))
    bad_tld = urls_where(lambda u: "suspicious_tld" in u.obfuscation)
    if bad_tld:
        findings.append(_finding(
            "suspicious_tld_link", Severity.MEDIUM, "Link on an abuse-prone TLD",
            f"Top-level domains used: {', '.join(dict.fromkeys('.' + u.tld for u in bad_tld[:4]))}.",
            evidence_for(bad_tld),
        ))
    data_uris = urls_where(lambda u: "data_uri" in u.obfuscation or "javascript_uri" in u.obfuscation)
    if data_uris:
        findings.append(_finding(
            "data_uri", Severity.HIGH, "Inline data/script URI",
            "Links embed their payload (data:) or run script (javascript:) rather than opening a web page.",
            evidence_for(data_uris),
        ))
    other_obfuscated = urls_where(
        lambda u: any(
            o not in ("redirect_parameter", "file_extension_executable", "suspicious_tld", "data_uri", "javascript_uri")
            for o in u.obfuscation
        )
    )
    if other_obfuscated:
        techniques = sorted({o for u in other_obfuscated for o in u.obfuscation})
        heavy = any(len(u.obfuscation) >= 3 for u in other_obfuscated)
        findings.append(_finding(
            "obfuscated_url", Severity.HIGH if heavy else Severity.MEDIUM, "Obfuscated link structure",
            f"Techniques observed: {', '.join(techniques)}.",
            evidence_for(other_obfuscated) | {"techniques": techniques},
        ))
    if urls:
        findings.append(_finding(
            "link_inventory", Severity.INFO, "Link inventory",
            f"{len(urls)} link(s) across {len(unique_domains)} domain(s): {', '.join(unique_domains[:6])}.",
            {"count": len(urls), "domains": unique_domains, "urls": [u.url[:300] for u in urls[:20]]},
        ))
    return UrlAnalysis(urls=urls, unique_domains=unique_domains, score=score, findings=findings)
