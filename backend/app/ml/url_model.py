"""
URL / domain risk model (XGBoost), the learned half of the Stage 4 URL pillar.

What this is
------------
A gradient-boosted decision tree over 31 numeric features engineered from a
:class:`~app.schemas.UrlInfo` (produced by the deterministic extractor in
``app/engine/urls.py``) and, when it is available, the
:class:`~app.schemas.DomainIntel` for that link's registrable domain.  It emits
``P(malicious)`` per link; ``score_urls`` reduces that to the worst link in the
message and ``app/engine/scoring.py`` folds it into the URL term.

What it is NOT
--------------
It is not an independent second opinion.  Fifteen of the thirty-one columns are
read straight off ``UrlInfo`` (the deception flags and the lookalike verdict),
so on those the model sees exactly what the rule engine saw and cannot discover
a signal the rules missed; the other sixteen are continuous URL-shape measures
the rules never compute.  Its contribution is therefore a
*graded, monotone lift*: the deterministic score stays the floor and the model
may only push a link further up (see ``engine/scoring._url_score``).  What it
buys is resolution -- the rules emit five severity buckets, the model emits a
continuous probability that separates "two weak obfuscation flags" from "seven".

Training data (generated, and honest about it)
----------------------------------------------
``build_dataset`` assembles a labelled URL set from three sources:

1. **Knowledge-base synthesis** (the bulk).  Benign rows are built from
   ``BRANDS`` legitimate domains, ``COMMON_URL_HOSTS``, the protected org
   domains and free-mail webmail hosts, deliberately including brand-hosted
   ``/login`` and ``/verify`` paths so the model learns that a credential
   keyword on a real brand domain is normal.  Malicious rows are built by
   applying the six lookalike techniques to those same brands and by composing
   the documented deception patterns (IP literals, shorteners, punycode, the
   ``user@host`` trick, abuse-prone TLDs, redirect parameters, executable
   paths, base64 query blobs, excessive sub-domains).
2. **Seed corpus** (``app/ml/seed_corpus.json``).  Real URLs written into the
   message bodies, weakly labelled by the message's own class: a link in a
   Legitimate message is benign, a link in a Phishing/Fraud/Impersonated/
   Suspicious message is malicious *unless* its registrable domain is a known
   brand or a common infrastructure host (unsubscribe links, w3.org, CDNs),
   which are dropped rather than mislabelled.
3. **Sample corpus** (``samples/*.eml``), extracted and labelled by the same
   weak rule from the file name.

Two consequences to keep in view:

* Hold-out accuracy on this set measures *self-consistency with the knowledge
  base*, not field performance.  It is printed by the CLI and stored in the
  bundle for the record; it is not a claim about real phishing traffic.
* The three DomainIntel columns (``domain_age_days``, ``resolves``, ``has_mx``)
  cannot be observed for synthesised hosts.  They are filled from a documented
  **prior** -- attack infrastructure is young and often has no MX, established
  brand domains are old and do -- and are set to NaN on a deliberate fraction
  of rows so the model is trained to work when enrichment did not run, which is
  the offline/free-tier case.  XGBoost learns a default branch for NaN natively.

Optional dependency
-------------------
``xgboost`` is a ~58 MB manylinux wheel (87 MB unpacked, one 86 MB
``libxgboost.so``) with no build step, so it is listed in requirements.txt.
Every entry point here still degrades cleanly when it is absent: ``load_or_train``
logs once and returns ``None``, ``score_urls`` returns ``None``, and the URL
pillar falls back to the deterministic score alone.  Set
``MAILTRACE_URL_MODEL=0`` to switch it off without uninstalling anything.

Caching
-------
Same bundle convention as the text model: a joblib dict at
``Settings.url_model_path`` carrying the fitted estimator, the feature-name
list, the row count and a ``corpus_sha256`` fingerprint.  The fingerprint
covers the seed corpus, the sample ``.eml`` files, ``engine/knowledge.py`` (the
single source of truth for brands, TLDs, shorteners and keywords) and the
feature list itself, so editing any of them retrains automatically.  The
in-process cache is keyed on that fingerprint rather than on the file path, so
a fresh ``data_dir`` (every pytest tmp_path, for instance) reuses the model
already fitted in this process instead of refitting it.

CLI
---
``python -m app.ml.url_model``            retrain and print hold-out metrics
``python -m app.ml.url_model --report``   also dump gain-ranked feature importances
"""
from __future__ import annotations

import argparse
import hashlib
import json
import logging
import math
import random
import re
import sys
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlsplit

from ..config import Settings
from ..config import settings as default_settings
from ..engine.knowledge import (
    BRANDS,
    COMMON_URL_HOSTS,
    FREEMAIL_DOMAINS,
    RISKY_EXTENSIONS,
    SUSPICIOUS_TLDS,
    URL_SHORTENERS,
    URL_SUSPICIOUS_KEYWORDS,
)
from ..engine.urls import (
    BRAND_LEGIT_DOMAINS,
    analyze_url,
    damerau_levenshtein,
    extract_urls,
    normalize_url,
    registrable_domain,
)
from ..schemas import DomainIntel, UrlInfo

log = logging.getLogger("mailtrace.ml.url")

#: Bump whenever FEATURE_NAMES or the dataset generator changes shape.
MODEL_VERSION = "xgb-url-1"

#: Column order of the design matrix.  Persisted in the bundle and checked on
#: load, so a bundle fitted against an older feature set is discarded.
FEATURE_NAMES: list[str] = [
    # --- URL shape (continuous; the model's own view, not read off the rules)
    "url_length",
    "host_length",
    "path_length",
    "query_length",
    "host_digit_count",
    "host_digit_ratio",
    "host_hyphen_count",
    "host_dot_count",
    "subdomain_depth",
    "path_depth",
    "host_entropy",
    "longest_label_length",
    # --- deception flags lifted from the deterministic extractor
    "is_ip_literal",
    "is_shortener",
    "is_punycode",
    "has_userinfo",
    "anchor_mismatch",
    "is_https",
    "tld_risk",
    "keyword_hits",
    "credential_keyword_hits",
    "obfuscation_count",
    "brand_in_subdomain",
    "redirect_parameter",
    "executable_path",
    "known_good_domain",
    # --- lookalike geometry
    "lookalike_flag",
    "lookalike_distance",
    # --- domain intelligence (NaN when enrichment did not run)
    "domain_age_days",
    "resolves",
    "has_mx",
]

#: Credential-harvest subset of URL_SUSPICIOUS_KEYWORDS (same list urls.py uses).
#: Intersected with the real vocabulary so a word dropped from knowledge.py can
#: never leave a dead entry here that silently stops contributing to the feature.
_CREDENTIAL_KEYWORDS: frozenset[str] = frozenset({
    "login", "log-in", "signin", "sign-in", "verify", "verification", "password", "credential",
    "auth", "authenticate", "account", "confirm", "kyc", "unlock", "recover", "secure", "webmail",
    "owa", "update", "aadhaar", "pan", "wallet",
}) & frozenset(URL_SUSPICIOUS_KEYWORDS)

#: Brand keys long enough that an edit-distance comparison means anything.
_BRAND_KEYS: tuple[str, ...] = tuple(sorted({k for k in BRANDS if len(k) >= 4}))

_NAN = float("nan")


# --------------------------------------------------------------------------- #
# Feature engineering
# --------------------------------------------------------------------------- #
def shannon_entropy(value: str) -> float:
    """Shannon entropy of the character distribution of ``value``, bits/char.

    The same measure the attachment analyzer applies to file bytes, here applied
    to the host string: algorithmically generated hosts (DGA-style, long random
    labels) sit near 4 bits/char while ``mail.google.com`` sits near 3.
    """
    text = value or ""
    if not text:
        return 0.0
    counts: dict[str, int] = {}
    for char in text:
        counts[char] = counts.get(char, 0) + 1
    total = len(text)
    return -sum((n / total) * math.log2(n / total) for n in counts.values())


def _sld(registrable: str) -> str:
    return registrable.split(".")[0] if registrable else ""


def lookalike_distance(host: str) -> float:
    """Normalised Damerau-Levenshtein distance from the host's second-level
    label to the *nearest* known brand name, in [0, 1].

    0.0 means the label is exactly a brand name (which is only innocent when the
    whole registrable domain is that brand's real domain -- the model gets that
    from ``known_good_domain``); 1.0 means nothing brand-like.  Unlike
    ``is_lookalike`` this is continuous, so "paypa1" (0.17) and "paypaI-secure"
    (0.46) are distinguishable instead of both being a single boolean.
    """
    sld = _sld(registrable_domain(host))
    if not sld:
        return 1.0
    best = 1.0
    for key in _BRAND_KEYS:
        span = max(len(sld), len(key))
        if not span or abs(len(sld) - len(key)) / span >= best:
            continue  # cannot beat the incumbent: length gap alone exceeds it
        best = min(best, damerau_levenshtein(sld, key) / span)
        if best == 0.0:
            break
    return round(min(1.0, max(0.0, best)), 6)


def _intel_features(intel: Optional[DomainIntel]) -> tuple[float, float, float]:
    """(age_days, resolves, has_mx) with NaN wherever nothing was observed.

    ``source in ("offline", "unavailable", "")`` means the domain engine never
    ran a live lookup, so ``resolves``/``has_mx`` being False carries no
    information and must not be handed to the model as a real zero.
    """
    if intel is None:
        return _NAN, _NAN, _NAN
    age = _NAN if intel.age_days is None else float(intel.age_days)
    observed = (intel.source or "") in ("live", "cache")
    resolves = float(bool(intel.resolves)) if observed else _NAN
    has_mx = float(bool(intel.has_mx)) if observed else _NAN
    return age, resolves, has_mx


def features(info: UrlInfo, intel: Optional[DomainIntel] = None) -> list[float]:
    """Feature row for one link, in ``FEATURE_NAMES`` order.  Never raises."""
    normalized = info.normalized or info.url or ""
    host = (info.host or "").lower()
    path = info.path or ""
    try:
        query = urlsplit(normalized).query
    except ValueError:
        query = ""
    labels = [label for label in host.split(".") if label]
    rd = info.registrable_domain or ""
    digits = sum(1 for c in host if c.isdigit())
    obfuscation = list(info.obfuscation or [])
    keywords = list(info.suspicious_keywords or [])
    extension = path.rsplit("/", 1)[-1].rsplit(".", 1)[-1].lower() if "." in path.rsplit("/", 1)[-1] else ""
    known_good = bool(rd and (rd in BRAND_LEGIT_DOMAINS or rd in COMMON_URL_HOSTS or host in COMMON_URL_HOSTS))
    age, resolves, has_mx = _intel_features(intel)

    values: dict[str, float] = {
        "url_length": float(len(normalized)),
        "host_length": float(len(host)),
        "path_length": float(len(path)),
        "query_length": float(len(query)),
        "host_digit_count": float(digits),
        "host_digit_ratio": float(digits) / float(len(host)) if host else 0.0,
        "host_hyphen_count": float(host.count("-")),
        "host_dot_count": float(host.count(".")),
        "subdomain_depth": float(max(0, host.count(".") - rd.count(".")) if rd and host.endswith(rd) else 0),
        "path_depth": float(len([seg for seg in path.split("/") if seg])),
        "host_entropy": round(shannon_entropy(host), 6),
        "longest_label_length": float(max((len(label) for label in labels), default=0)),
        "is_ip_literal": float(bool(info.is_ip_literal)),
        "is_shortener": float(bool(info.is_shortener)),
        "is_punycode": float(bool(info.is_punycode)),
        "has_userinfo": float(bool(info.has_userinfo)),
        "anchor_mismatch": float(bool(info.anchor_mismatch)),
        "is_https": float((info.scheme or "").lower() == "https"),
        "tld_risk": float((info.tld or "") in SUSPICIOUS_TLDS),
        "keyword_hits": float(len(keywords)),
        "credential_keyword_hits": float(sum(1 for kw in keywords if kw in _CREDENTIAL_KEYWORDS)),
        "obfuscation_count": float(len(obfuscation)),
        "brand_in_subdomain": float("brand_in_subdomain" in obfuscation),
        "redirect_parameter": float("redirect_parameter" in obfuscation),
        "executable_path": float(RISKY_EXTENSIONS.get(extension) in ("critical", "high")),
        "known_good_domain": float(known_good),
        "lookalike_flag": float(bool(info.lookalike_of)),
        "lookalike_distance": lookalike_distance(host),
        "domain_age_days": age,
        "resolves": resolves,
        "has_mx": has_mx,
    }
    return [float(values[name]) for name in FEATURE_NAMES]


def features_for(url: str, anchor: str, cfg: Settings, intel: Optional[DomainIntel] = None) -> list[float]:
    """Convenience wrapper: run the deterministic extractor, then featurise."""
    return features(analyze_url(url, anchor, cfg), intel)


# --------------------------------------------------------------------------- #
# Dataset generation
# --------------------------------------------------------------------------- #
#: Prior used to fill the DomainIntel columns for synthesised hosts.  These are
#: assumptions, not observations -- see the module docstring.
_PRIOR_MISSING_RATE = 0.5          # fraction of rows with no enrichment at all
_PRIOR_BENIGN_AGE = (900, 9000)    # days: an established brand or corporate site
_PRIOR_MALICIOUS_AGE = (1, 220)    # days: purpose-built attack infrastructure
_PRIOR_MALICIOUS_MX_RATE = 0.25    # attack hosts that do publish an MX anyway

_BENIGN_PATHS: tuple[str, ...] = (
    "/", "/about", "/help", "/support/contact", "/blog/2026/quarterly-update",
    "/docs/getting-started", "/pricing", "/careers", "/legal/privacy",
    # Real brands host credential pages too: the model must not read "login" or
    # "verify" on a genuine brand domain as evidence of anything.
    "/login", "/signin", "/account/security", "/account/settings",
    "/help/verify-email", "/password/reset", "/billing/invoices",
    "/unsubscribe?u=91a2c4&id=88213", "/track/open.gif?mid=44120",
    "/order/status?id=INV-2026-0042", "/download/report.pdf",
    "/organizations/acme-corp-india/settings/receipts",
    # Marketing mail really does send 150-character tracked links; they trip the
    # ``long_url`` obfuscation flag, so they belong in the benign class as hard
    # negatives or the model learns that length alone is guilt.
    "/campaign/click?utm_source=newsletter&utm_medium=email&utm_campaign=2026_q3_update&utm_content=cta_primary&sid=7f4c19ab2d",
    "/e/c/eyJlbWFpbF9pZCI6IjQ0MTIwIn0/aHR0cHM6Ly9leGFtcGxlLmNvbQ?mkt_tok=NDQxMjA",
)
_BENIGN_SUBDOMAINS: tuple[str, ...] = ("", "www.", "mail.", "support.", "cdn.", "static.", "docs.", "app.")
#: Word stock for ordinary, non-brand business hosts (the hard negatives).
_ORDINARY_WORDS: tuple[str, ...] = (
    "northwind", "bluepeak", "sundaram", "vertex", "greenfield", "orbit", "kestrel",
    "meridian", "harbour", "lakeview", "silverline", "tatva", "prayaan", "quanta",
    "redwood", "stellar", "trident", "urbanleaf", "vantage", "westbrook", "yellowstone",
    "acme", "corebridge", "delta", "everest", "fairwind", "granite", "highpoint",
)
_ORDINARY_SUFFIXES: tuple[str, ...] = ("com", "in", "co.in", "org", "net", "co", "io", "com.au", "co.uk")
_ORDINARY_SUBDOMAINS: tuple[str, ...] = (
    "", "www.", "mail.", "portal.", "hr.", "invoices.", "assets.", "eu-west-1.cdn.", "my.",
)

_LURE_PATHS: tuple[str, ...] = (
    "/verify", "/login/verify", "/secure/account/confirm", "/kyc/update",
    "/account/unlock", "/webmail/owa/auth", "/signin/password/confirm",
    "/update-billing", "/refund/claim", "/wallet/recover", "/netbanking/login",
    "/aadhaar/verify", "/prize/claim", "/security-check/confirm-identity",
)
_LURE_QUERIES: tuple[str, ...] = (
    "", "", "?ref=mail", "?session=8812ab44f0", "?next=https://microsoft.com/",
    "?redirect_url=https%3A%2F%2Fpaypal.com%2Fsignin", "?d=aHR0cHM6Ly9ldmlsLmV4YW1wbGUvbG9naW4=",
)
_BAD_TLDS: tuple[str, ...] = (
    "xyz", "top", "icu", "buzz", "click", "link", "online", "site", "shop", "cyou",
    "quest", "monster", "rest", "cam", "sbs", "bond", "cfd", "lol", "win", "loan",
)
_EXEC_PATHS: tuple[str, ...] = ("/files/invoice.exe", "/dl/update.scr", "/get/setup.msi", "/pay/receipt.js", "/doc/statement.hta")
_ATTACK_WORDS: tuple[str, ...] = (
    "secure", "verify", "account", "update", "service", "portal", "online", "center",
    "support", "billing", "auth", "id", "web", "net", "cloud", "gateway",
)

_URL_IN_TEXT_RE = re.compile(r"(?:https?://|www\.)[^\s<>\"'`\)\]]+", re.IGNORECASE)
#: Weak label carried by each seed-corpus / sample class.
_MALICIOUS_LABELS: frozenset[str] = frozenset({"Phishing", "Fraud-Related", "Impersonated", "Suspicious"})


def _homoglyph_swap(word: str, rng: random.Random) -> str:
    table = {"l": "1", "i": "1", "o": "0", "e": "3", "a": "4", "s": "5", "g": "9", "b": "8", "t": "7"}
    positions = [i for i, ch in enumerate(word) if ch in table]
    if not positions:
        return word + rng.choice(("s", "x"))
    i = rng.choice(positions)
    return word[:i] + table[word[i]] + word[i + 1:]


def _typo(word: str, rng: random.Random) -> str:
    """One edit that keeps the first character, the shape real typosquats take."""
    if len(word) < 4:
        return word + word[-1]
    kind = rng.randrange(4)
    i = rng.randrange(1, len(word))
    if kind == 0:                                   # doubled character
        return word[:i] + word[i] + word[i:]
    if kind == 1:                                   # dropped character
        return word[:i] + word[i + 1:]
    if kind == 2 and i < len(word) - 1:             # transposition
        return word[:i] + word[i + 1] + word[i] + word[i + 2:]
    return _homoglyph_swap(word, rng)


#: Scheme mix. Both classes are mostly https on purpose: free certificates made
#: TLS universal, and phishing kits use it as readily as anyone. An earlier
#: version of this generator emitted http for every attack URL, and the model
#: promptly learned "http means malicious" -- 0.56 of total gain on one leaked
#: column. Keeping the distributions close forces it onto real signal.
_BENIGN_HTTPS_RATE = 0.92
_MALICIOUS_HTTPS_RATE = 0.80


def _benign_rows(rng: random.Random, cfg: Settings) -> list[tuple[str, str]]:
    """(url, anchor) pairs that a real message would legitimately carry.

    Deliberately more than brand domains: two thirds of the benign class are
    *ordinary* hosts with no brand status at all, so the model cannot settle on
    "not a known brand therefore dangerous" -- which would flag every small
    supplier's invoice link in the deployment this ships into.
    """
    rows: list[tuple[str, str]] = []

    def add(host: str, path: str, anchor: str = "") -> None:
        scheme = "https" if rng.random() < _BENIGN_HTTPS_RATE else "http"
        rows.append((f"{scheme}://{host}{path}", anchor))

    known: list[str] = sorted(BRAND_LEGIT_DOMAINS) + sorted(COMMON_URL_HOSTS)
    known += [registrable_domain(d) for d in cfg.org_domains if d]
    known += sorted(FREEMAIL_DOMAINS)
    for host in known:
        if not host or "." not in host:
            continue
        for _ in range(2):
            sub = rng.choice(_BENIGN_SUBDOMAINS) if host.count(".") <= 2 else ""
            add(f"{sub}{host}", rng.choice(_BENIGN_PATHS))

    # Ordinary businesses: no brand, no reputation, entirely legitimate.
    for first in _ORDINARY_WORDS:
        for _ in range(9):
            shape = rng.randrange(4)
            if shape == 0:
                sld = first
            elif shape == 1:
                sld = f"{first}-{rng.choice(_ORDINARY_WORDS)}"
            elif shape == 2:
                sld = f"{first}{rng.choice(('group', 'labs', 'tech', 'india', 'global', 'works'))}"
            else:
                sld = f"{first}{rng.randrange(1, 99)}"
            host = f"{rng.choice(_ORDINARY_SUBDOMAINS)}{sld}.{rng.choice(_ORDINARY_SUFFIXES)}"
            add(host, rng.choice(_BENIGN_PATHS))
    return rows


def _malicious_rows(rng: random.Random, cfg: Settings) -> list[tuple[str, str]]:
    """(url, anchor) pairs composing the documented deception techniques."""
    rows: list[tuple[str, str]] = []
    brands = [(key, domains[0]) for key, domains in sorted(BRANDS.items()) if domains]
    org_domains = [registrable_domain(d) for d in cfg.org_domains if d]

    def add(host: str, path: str = "", anchor: str = "") -> None:
        scheme = "https" if rng.random() < _MALICIOUS_HTTPS_RATE else "http"
        rows.append((f"{scheme}://{host}{path or rng.choice(_LURE_PATHS)}{rng.choice(_LURE_QUERIES)}", anchor))

    for key, legit in brands:
        sld, _, suffix = legit.partition(".")
        bad_tld = rng.choice(_BAD_TLDS)
        add(f"{_typo(sld, rng)}.{suffix or 'com'}")                       # typosquat
        add(f"{sld}.{bad_tld}")                                          # TLD swap
        add(f"{sld}-{rng.choice(_ATTACK_WORDS)}.{bad_tld}")              # extra token
        add(f"{rng.choice(_ATTACK_WORDS)}-{sld}.{bad_tld}")              # extra token
        add(f"{key}.{rng.choice(_ATTACK_WORDS)}.{bad_tld}")              # brand in sub-domain
        add(f"{legit}.{rng.choice(_ATTACK_WORDS)}-{rng.choice(_ATTACK_WORDS)}.{bad_tld}")  # sub-domain abuse
        add(f"xn--{sld[:6]}-{rng.randrange(10, 99)}a.{suffix or 'com'}")  # punycode
        # The '@' trick: everything before it is decoy text the browser ignores.
        add(f"{legit}@{rng.choice(_ATTACK_WORDS)}-{rng.randrange(100, 999)}.{bad_tld}", anchor=legit)
        # Visible anchor text naming the brand while the href goes elsewhere.
        add(f"{rng.choice(_ATTACK_WORDS)}{rng.randrange(10, 99)}.{bad_tld}", anchor=f"https://{legit}/login")

    for org in org_domains:
        sld, _, suffix = org.partition(".")
        add(f"{_typo(sld, rng)}.{suffix or 'com'}")
        add(f"{sld}-{rng.choice(_ATTACK_WORDS)}.{rng.choice(_BAD_TLDS)}")

    for _ in range(60):                                                   # raw IP literals
        octets = ".".join(str(rng.randrange(1, 254)) for _ in range(4))
        add(octets)
    for shortener in sorted(URL_SHORTENERS):                              # shorteners
        add(shortener, path=f"/{''.join(rng.choice('abcdefghijkmnpqrstuvwxyz0123456789') for _ in range(7))}")
    for _ in range(80):                                                   # DGA-ish hosts
        label = "".join(rng.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(rng.randrange(10, 22)))
        add(f"{label}.{rng.choice(_BAD_TLDS)}")
    for _ in range(50):                                                   # executable downloads
        add(f"{rng.choice(_ATTACK_WORDS)}-{rng.randrange(10, 999)}.{rng.choice(_BAD_TLDS)}", path=rng.choice(_EXEC_PATHS))
    for _ in range(40):                                                   # excessive sub-domains
        depth = rng.randrange(4, 7)
        host = ".".join(rng.choice(_ATTACK_WORDS) for _ in range(depth)) + "." + rng.choice(_BAD_TLDS)
        add(host)
    return rows


def _corpus_rows(cfg: Settings) -> list[tuple[str, str, int]]:
    """(url, anchor, label) weakly labelled from the seed corpus message class.

    Links to known brands / common infrastructure inside a malicious message are
    dropped rather than labelled 1: a phishing mail still carries a real
    unsubscribe link, and mislabelling those would teach the model that
    ``microsoft.com`` is dangerous.
    """
    rows: list[tuple[str, str, int]] = []
    try:
        raw = json.loads(Path(cfg.corpus_path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        log.debug("seed corpus unreadable for URL dataset; using synthesis only", exc_info=True)
        return rows
    for entry in raw if isinstance(raw, list) else []:
        if not isinstance(entry, dict):
            continue
        label = str(entry.get("label", ""))
        text = f"{entry.get('subject', '')} {entry.get('body', '')}"
        malicious = label in _MALICIOUS_LABELS
        for match in _URL_IN_TEXT_RE.finditer(text):
            url = match.group(0).rstrip(".,;:!?'\")")
            rd = registrable_domain(urlsplit(normalize_url(url)).hostname or "")
            if malicious and (rd in BRAND_LEGIT_DOMAINS or rd in COMMON_URL_HOSTS):
                continue
            rows.append((url, "", 1 if malicious else 0))
    return rows


def _sample_rows(cfg: Settings) -> list[tuple[str, str, int]]:
    """Same weak labelling applied to the bundled ``samples/*.eml`` corpus."""
    rows: list[tuple[str, str, int]] = []
    directory = Path(cfg.samples_dir)
    if not directory.is_dir():
        return rows
    from ..engine.parser import parse_email  # local: keeps module import cheap

    for path in sorted(directory.glob("*.eml")):
        malicious = not path.name.startswith("legit")
        try:
            parsed, _ = parse_email(path.read_bytes())
        except Exception:  # noqa: BLE001 - a bad sample must not stop training
            log.debug("sample %s could not be parsed for the URL dataset", path.name, exc_info=True)
            continue
        for url, anchor in extract_urls(parsed.text_body or "", parsed.html_body or ""):
            rd = registrable_domain(urlsplit(normalize_url(url)).hostname or "")
            if malicious and (rd in BRAND_LEGIT_DOMAINS or rd in COMMON_URL_HOSTS):
                continue
            rows.append((url, anchor, 1 if malicious else 0))
    return rows


def _apply_intel_prior(row: list[float], label: int, rng: random.Random) -> None:
    """Fill the three DomainIntel columns from the documented prior, in place.

    Half the rows keep NaN: enrichment is off on the free tier and in the test
    suite, so the model has to be good without these columns.
    """
    age_i = FEATURE_NAMES.index("domain_age_days")
    res_i = FEATURE_NAMES.index("resolves")
    mx_i = FEATURE_NAMES.index("has_mx")
    if rng.random() < _PRIOR_MISSING_RATE:
        row[age_i] = row[res_i] = row[mx_i] = _NAN
        return
    low, high = _PRIOR_MALICIOUS_AGE if label else _PRIOR_BENIGN_AGE
    row[age_i] = float(rng.randrange(low, high))
    row[res_i] = 1.0
    row[mx_i] = float(rng.random() < _PRIOR_MALICIOUS_MX_RATE) if label else 1.0


def build_dataset(cfg: Optional[Settings] = None, seed: int = 20260905) -> tuple[list[list[float]], list[int], dict[str, Any]]:
    """(X, y, meta).  Deterministic for a given seed and knowledge base."""
    cfg = cfg or default_settings
    rng = random.Random(seed)
    labelled: list[tuple[str, str, int]] = []
    labelled += [(url, anchor, 0) for url, anchor in _benign_rows(rng, cfg)]
    labelled += [(url, anchor, 1) for url, anchor in _malicious_rows(rng, cfg)]
    n_synthetic = len(labelled)
    from_corpus = _corpus_rows(cfg)
    from_samples = _sample_rows(cfg)
    labelled += from_corpus
    labelled += from_samples

    seen: set[tuple[str, int]] = set()
    x: list[list[float]] = []
    y: list[int] = []
    for url, anchor, label in labelled:
        key = (normalize_url(url), label)
        if not key[0] or key in seen:
            continue
        seen.add(key)
        try:
            row = features(analyze_url(url, anchor, cfg))
        except Exception:  # noqa: BLE001 - one bad row must not stop training
            log.debug("could not featurise %r", url[:120], exc_info=True)
            continue
        _apply_intel_prior(row, label, rng)
        x.append(row)
        y.append(label)
    meta = {
        "n_rows": len(y),
        "n_malicious": sum(y),
        "n_benign": len(y) - sum(y),
        "n_synthetic": n_synthetic,
        "n_from_corpus": len(from_corpus),
        "n_from_samples": len(from_samples),
    }
    return x, y, meta


# --------------------------------------------------------------------------- #
# Fingerprint / persistence
# --------------------------------------------------------------------------- #
def _sha256_file(path: Path) -> str:
    try:
        return hashlib.sha256(Path(path).read_bytes()).hexdigest()
    except OSError:
        return ""


def dataset_fingerprint(cfg: Optional[Settings] = None) -> str:
    """Hash of every input the dataset is generated from.

    Cheap on purpose (a handful of file reads, no featurisation) because it is
    checked on every ``load_or_train``: the seed corpus, the sample ``.eml``
    files, ``engine/knowledge.py`` and the feature list.  Editing any of them
    invalidates the cached bundle exactly as editing the text corpus does.
    """
    cfg = cfg or default_settings
    digest = hashlib.sha256()
    digest.update(MODEL_VERSION.encode())
    digest.update("\n".join(FEATURE_NAMES).encode())
    digest.update(_sha256_file(cfg.corpus_path).encode())
    digest.update(_sha256_file(Path(__file__).resolve().parent.parent / "engine" / "knowledge.py").encode())
    directory = Path(cfg.samples_dir)
    if directory.is_dir():
        for path in sorted(directory.glob("*.eml")):
            digest.update(path.name.encode())
            digest.update(_sha256_file(path).encode())
    digest.update(",".join(sorted(str(d).lower() for d in cfg.org_domains)).encode())
    return digest.hexdigest()


def build_classifier():  # type: ignore[no-untyped-def]
    """A deliberately small booster: 120 trees of depth 4, single-threaded.

    The bundle is ~200 KB and inference is microseconds.  ``n_jobs=1`` matters:
    the deployment target is a 512 MB single-CPU free tier, where XGBoost's
    default thread pool is pure overhead.
    """
    from xgboost import XGBClassifier

    return XGBClassifier(
        n_estimators=120,
        max_depth=4,
        learning_rate=0.2,
        subsample=0.9,
        colsample_bytree=0.9,
        reg_lambda=1.0,
        min_child_weight=2,
        tree_method="hist",
        n_jobs=1,
        random_state=42,
        eval_metric="logloss",
    )


def _bundle(model, meta: dict[str, Any], fingerprint: str, metrics: dict[str, float]) -> dict[str, Any]:  # type: ignore[no-untyped-def]
    import xgboost

    return {
        "model": model,
        "version": MODEL_VERSION,
        "features": list(FEATURE_NAMES),
        "n_samples": int(meta.get("n_rows", 0)),
        "corpus_sha256": fingerprint,
        "dataset": dict(meta),
        "metrics": dict(metrics),
        "xgboost_version": xgboost.__version__,
    }


def _holdout_metrics(x: list[list[float]], y: list[int]) -> dict[str, float]:
    """Stratified 80/20 hold-out.  Self-consistency with the generated set, not
    a field-performance claim -- see the module docstring."""
    from sklearn.metrics import accuracy_score, roc_auc_score
    from sklearn.model_selection import train_test_split

    if len(set(y)) < 2 or len(y) < 20:
        return {}
    x_train, x_test, y_train, y_test = train_test_split(x, y, test_size=0.2, random_state=42, stratify=y)
    model = build_classifier().fit(x_train, y_train)
    predicted = model.predict(x_test)
    probabilities = model.predict_proba(x_test)[:, 1]
    return {
        "holdout_accuracy": float(accuracy_score(y_test, predicted)),
        "holdout_auc": float(roc_auc_score(y_test, probabilities)),
        "n_holdout": float(len(y_test)),
    }


def train(cfg: Optional[Settings] = None, model_path: Optional[Path] = None, with_metrics: bool = True):  # type: ignore[no-untyped-def]
    """Generate the dataset, fit, persist the bundle, return the fitted model."""
    import joblib

    cfg = cfg or default_settings
    path = Path(model_path or cfg.url_model_path)
    x, y, meta = build_dataset(cfg)
    if len(set(y)) < 2:
        raise ValueError("URL dataset needs both classes")
    metrics = _holdout_metrics(x, y) if with_metrics else {}
    model = build_classifier().fit(x, y)
    bundle = _bundle(model, meta, dataset_fingerprint(cfg), metrics)
    path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(bundle, path)
    log.info("trained %s on %d URLs (%d malicious) -> %s", MODEL_VERSION, meta["n_rows"], meta["n_malicious"], path)
    return model


def _load_bundle(path: Path, fingerprint: str):  # type: ignore[no-untyped-def]
    import joblib

    if not Path(path).is_file():
        return None
    try:
        bundle = joblib.load(path)
    except Exception:  # noqa: BLE001 - corrupt cache, or xgboost gone -> retrain/degrade
        log.warning("cached URL model at %s could not be loaded; retraining", path)
        return None
    if not isinstance(bundle, dict) or bundle.get("version") != MODEL_VERSION:
        return None
    if list(bundle.get("features") or []) != FEATURE_NAMES:
        return None
    if fingerprint and bundle.get("corpus_sha256") != fingerprint:
        return None
    return bundle.get("model")


# --------------------------------------------------------------------------- #
# Process-wide cache
# --------------------------------------------------------------------------- #
_lock = threading.Lock()
_models: dict[str, Any] = {}
#: Fingerprints whose load/train already failed (xgboost missing, fit error).
#: Retrying per message would cost a doomed import on every analysis.
_failed: set[str] = set()


def available() -> bool:
    """True when xgboost can be imported in this process."""
    try:
        import xgboost  # noqa: F401, PLC0415
    except Exception:  # noqa: BLE001 - missing, or a broken native install
        return False
    return True


def load_or_train(cfg: Optional[Settings] = None):  # type: ignore[no-untyped-def]
    """The fitted model, training it once if needed; ``None`` if unavailable.

    Never raises.  Keyed on the dataset fingerprint, not on the file path, so
    every ``Settings`` pointing at the same knowledge base shares one fitted
    model in this process.
    """
    cfg = cfg or default_settings
    if not getattr(cfg, "url_model_enabled", True):
        return None
    try:
        fingerprint = dataset_fingerprint(cfg)
    except Exception:  # noqa: BLE001
        log.debug("could not fingerprint the URL dataset", exc_info=True)
        return None
    with _lock:
        cached = _models.get(fingerprint)
        if cached is not None:
            return cached
        if fingerprint in _failed:
            return None
        try:
            model = _load_bundle(Path(cfg.url_model_path), fingerprint)
            if model is None:
                model = train(cfg, with_metrics=False)
        except ImportError as exc:
            _failed.add(fingerprint)
            log.warning("xgboost unavailable (%s); the URL pillar stays rule-only", exc)
            return None
        except Exception:  # noqa: BLE001 - never let a model break the analysis
            _failed.add(fingerprint)
            log.exception("URL model could not be trained; the URL pillar stays rule-only")
            return None
        _models[fingerprint] = model
        return model


# --------------------------------------------------------------------------- #
# Scoring
# --------------------------------------------------------------------------- #
@dataclass
class UrlModelOutcome:
    """What the model concluded about one message's links."""

    max_probability: float = 0.0
    per_url: list[tuple[str, float]] = field(default_factory=list)
    model: str = MODEL_VERSION
    n_urls: int = 0
    n_with_intel: int = 0


def _intel_index(domain_intel: Any) -> dict[str, DomainIntel]:
    index: dict[str, DomainIntel] = {}
    for intel in domain_intel or []:
        key = (getattr(intel, "domain", "") or "").lower()
        if key:
            index.setdefault(key, intel)
    return index


def score_urls(urls: Any, domain_intel: Any, cfg: Optional[Settings] = None) -> Optional[UrlModelOutcome]:
    """``P(malicious)`` for every link in the message, worst-first.

    Returns ``None`` -- never raises -- when there are no links, when the model
    is disabled, or when xgboost is not installed.  The caller then uses the
    deterministic URL score on its own.
    """
    cfg = cfg or default_settings
    items: list[UrlInfo] = [u for u in (urls or []) if getattr(u, "url", "")]
    if not items:
        return None
    model = load_or_train(cfg)
    if model is None:
        return None
    index = _intel_index(domain_intel)
    try:
        import numpy as np

        rows = []
        matched = 0
        for info in items:
            intel = index.get((info.registrable_domain or "").lower()) or index.get((info.host or "").lower())
            if intel is not None:
                matched += 1
            rows.append(features(info, intel))
        probabilities = model.predict_proba(np.asarray(rows, dtype=np.float32))[:, 1]
    except Exception:  # noqa: BLE001 - inference failure must never abort scoring
        log.exception("URL model inference failed; the URL pillar stays rule-only")
        return None
    per_url = sorted(
        ((info.url[:300], float(p)) for info, p in zip(items, probabilities)),
        key=lambda item: -item[1],
    )
    return UrlModelOutcome(
        max_probability=float(max(probabilities)) if len(probabilities) else 0.0,
        per_url=per_url,
        model=MODEL_VERSION,
        n_urls=len(items),
        n_with_intel=matched,
    )


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Train the MailTrace URL/domain risk model.")
    parser.add_argument("--out", type=Path, default=None, help="model output path")
    parser.add_argument("--report", action="store_true", help="print gain-ranked feature importances")
    args = parser.parse_args(argv)

    cfg = default_settings
    x, y, meta = build_dataset(cfg)
    print(
        f"Dataset: {meta['n_rows']} URLs "
        f"({meta['n_malicious']} malicious / {meta['n_benign']} benign); "
        f"{meta['n_synthetic']} synthesised, {meta['n_from_corpus']} from the seed corpus, "
        f"{meta['n_from_samples']} from samples/"
    )
    metrics = _holdout_metrics(x, y)
    if metrics:
        print(
            f"Hold-out (20% of the GENERATED set, not field data): "
            f"accuracy {metrics['holdout_accuracy']:.3f}, ROC-AUC {metrics['holdout_auc']:.3f} "
            f"over {int(metrics['n_holdout'])} rows"
        )
    model = train(cfg, args.out)
    print(f"Saved model to {args.out or cfg.url_model_path}")
    if args.report:
        importances = sorted(zip(FEATURE_NAMES, model.feature_importances_), key=lambda item: -item[1])
        print("\nFeature importance (gain-normalised):")
        for name, value in importances:
            if value > 0:
                print(f"  {name:<26} {value:.4f}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
