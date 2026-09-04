"""
Decision brain of MailTrace: fuses every analyzer's sub-report into one Verdict.

Approach
--------
1. ``component_scores`` converts the evidence into the five Stage 4 pillars -
   AI core, authentication/protocols, GeoIP/route, domain, and threat
   intelligence - as 0-100 analyst-scale scores using documented increments.
2. ``weighted_risk`` sums them with ``Settings.weights`` into the raw risk score.
3. ``rule_classify`` is a deterministic first-match policy (Fraud > Phishing >
   Impersonated > Suspicious > Legitimate) whose rationale lines name the exact
   signals that fired ("SPF fail for sbi-kyc-update.xyz").
4. ``fuse_category`` performs the dual validation: the rule engine decides the
   category, the ML classifier modulates confidence, and any disagreement is
   surfaced as a finding.
5. Per-category risk floors and a ceiling for "Legitimate" keep the numeric
   score and the label consistent.
6. ``attribute_source`` explains where the message most plausibly came from
   (spoofed domain, lookalike domain, compromised account, attacker-owned
   infrastructure) and lists the indicators an investigator should pivot on.

Everything here is pure and offline: no I/O, no network, deterministic output
for identical input, and robust to empty sub-reports.
"""
from __future__ import annotations

import logging
from typing import Any, Iterable, Optional

from ..config import DEFAULT_WEIGHTS, Settings
from ..schemas import (
    SEVERITY_ORDER,
    AttachmentAnalysis,
    Attribution,
    AuthResult,
    DomainIntel,
    Finding,
    HeaderAnalysis,
    InfraAnalysis,
    NlpAnalysis,
    ParsedEmail,
    RiskBreakdown,
    Severity,
    SourceType,
    ThreatCategory,
    ThreatIntel,
    UrlAnalysis,
    UrlInfo,
    Verdict,
)
from .knowledge import BRANDS, FREEMAIL_DOMAINS
from .urls import registrable_domain

log = logging.getLogger("mailtrace.scoring")

# Every legitimate domain of every known brand (flattened once at import).
BRAND_DOMAINS: frozenset[str] = frozenset(d for domains in BRANDS.values() for d in domains)

# Minimum risk score a message may carry once it has been given a threat label.
RISK_FLOORS: dict[ThreatCategory, int] = {
    ThreatCategory.PHISHING: 60,
    ThreatCategory.FRAUD: 60,
    ThreatCategory.IMPERSONATED: 45,
    ThreatCategory.SUSPICIOUS: 25,
}
# A "Legitimate" label is never allowed at or above this risk score.
LEGITIMATE_RISK_CEILING = 40

_ATTACK_CATEGORIES: frozenset[ThreatCategory] = frozenset(
    {ThreatCategory.PHISHING, ThreatCategory.FRAUD, ThreatCategory.IMPERSONATED}
)
_ROLE_LABELS: dict[str, str] = {"sender": "Sender", "reply_to": "Reply-To", "return_path": "Return-Path"}


# --------------------------------------------------------------------------- #
# Small pure helpers
# --------------------------------------------------------------------------- #
def _clamp(value: Any, low: float = 0.0, high: float = 100.0) -> float:
    """Coerce to float and clamp; NaN, None and garbage become ``low``."""
    try:
        number = float(value)
    except (TypeError, ValueError):
        return low
    if number != number:  # NaN
        return low
    return max(low, min(high, number))


def _sev(value: Any) -> int:
    """Numeric rank of a Severity (enum or plain string); unknown -> 0."""
    return SEVERITY_ORDER.get(getattr(value, "value", value), 0)


def _short(text: str, limit: int = 80) -> str:
    text = " ".join((text or "").split())
    return text if len(text) <= limit else text[: limit - 3] + "..."


def _quote(items: Iterable[str], limit: int = 3) -> str:
    """'a', 'b', 'c' (+2 more) -- empty string when nothing to show."""
    values = [str(v).strip() for v in items if str(v).strip()]
    shown = ", ".join(f"'{v}'" for v in values[:limit])
    extra = len(values) - limit
    return f"{shown} (+{extra} more)" if extra > 0 else shown


def _unique(items: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        if item and item not in seen:
            seen.add(item)
            out.append(item)
    return out


def _registrable(host: str) -> str:
    host = (host or "").strip().lower().rstrip(".")
    if not host:
        return ""
    try:
        return (registrable_domain(host) or host).lower()
    except Exception:  # noqa: BLE001 - a helper must never break the verdict
        return host


def _is_freemail(domain: str) -> bool:
    domain = (domain or "").lower()
    return bool(domain) and (domain in FREEMAIL_DOMAINS or _registrable(domain) in FREEMAIL_DOMAINS)


def _org_domains(cfg: Settings) -> set[str]:
    return {_registrable(d) for d in cfg.org_domains if d}


def _is_protected_domain(domain: str, cfg: Settings) -> bool:
    """True when the domain belongs to the protected organisation or a known brand."""
    return bool(domain) and (domain in _org_domains(cfg) or domain in BRAND_DOMAINS)


def _as_category(value: Any) -> ThreatCategory:
    try:
        return ThreatCategory(value)
    except ValueError:
        return ThreatCategory.LEGITIMATE


def _ml_prob(probs: Optional[dict[str, float]], category: Any) -> float:
    """Probability the classifier assigned to ``category``; 0 when unknown."""
    if not probs:
        return 0.0
    cat = _as_category(category)
    raw = probs.get(cat.value)
    if raw is None:
        raw = probs.get(cat.name, 0.0)
    return _clamp(raw, 0.0, 1.0)


def _bec_confidence(nlp: NlpAnalysis, pattern: str) -> tuple[float, list[str]]:
    """Highest confidence recorded for a BEC pattern and its evidence phrases."""
    best = 0.0
    evidence: list[str] = []
    for item in nlp.bec_patterns:
        conf = _clamp(item.confidence, 0.0, 1.0)
        if item.pattern == pattern and conf >= best:
            best = conf
            evidence = list(item.evidence)
    return best, evidence


def _finding(findings: Iterable[Finding], finding_id: str) -> Optional[Finding]:
    return next((f for f in findings if f.id == finding_id), None)


def _lookalike_sender_domains(domain_intel: Iterable[DomainIntel]) -> list[DomainIntel]:
    return [d for d in domain_intel if d.lookalike_of and d.role in ("sender", "reply_to")]


def _role_label(role: str) -> str:
    return _ROLE_LABELS.get(role, (role or "domain").replace("_", " ").title())


def _describe_url(url: UrlInfo) -> str:
    reason = f": {url.reasons[0]}" if url.reasons else ""
    return f"{url.host or _short(url.url, 60)} [{url.risk.value}{reason}]"


# --------------------------------------------------------------------------- #
# Severity bands
# --------------------------------------------------------------------------- #
def severity_for(score: float, has_findings: bool = True) -> Severity:
    """<25 LOW, <50 MEDIUM, <75 HIGH, else CRITICAL; a zero score with no
    findings at all is INFO."""
    value = _clamp(score)
    if value <= 0 and not has_findings:
        return Severity.INFO
    if value < 25:
        return Severity.LOW
    if value < 50:
        return Severity.MEDIUM
    if value < 75:
        return Severity.HIGH
    return Severity.CRITICAL


# --------------------------------------------------------------------------- #
# Component scores (0-100)
# --------------------------------------------------------------------------- #
def _authentication_score(auth: AuthResult, sender_domain: str, cfg: Settings) -> float:
    spf, dkim, dmarc = auth.spf.lower(), auth.dkim.lower(), auth.dmarc.lower()
    score = 0.0
    if spf == "fail":
        score += 45
    elif spf == "softfail":
        score += 25
    elif spf in {"none", "neutral"}:
        score += 15
    elif spf in {"unverifiable", "temperror", "permerror"}:
        score += 10
    if dkim == "fail":
        score += 35
    elif dkim == "none":
        score += 10
    elif dkim in {"unverifiable", "temperror", "permerror"}:
        score += 5
    if dmarc == "fail":
        score += 60 if auth.dmarc_policy.lower() == "reject" else 40
    elif dmarc == "none":
        score += 10
    if auth.spf_aligned is False:
        score += 15
    if auth.dkim_aligned is False:
        score += 15
    # A failure on a domain that belongs to us or to a known brand is a spoof
    # of a high-value identity, not a misconfigured small business.
    any_failure = spf in {"fail", "softfail"} or dkim == "fail" or dmarc == "fail"
    if any_failure and _is_protected_domain(sender_domain, cfg):
        score += 20
    return _clamp(score)


def _ai_score(nlp: NlpAnalysis, urls: UrlAnalysis, atts: AttachmentAnalysis) -> float:
    """Pillar 1 - AI core.

    Everything the model and the content analysers concluded about intent: the
    classifier's non-legitimate mass and social-engineering signals (``nlp.score``),
    the strongest BEC pattern, the lure links, and the attachment risk, which now
    includes the Shannon-entropy check for packed or encrypted payloads.
    """
    max_bec = max((_clamp(p.confidence, 0.0, 1.0) for p in nlp.bec_patterns), default=0.0)
    intent = 0.7 * _clamp(nlp.score, 0.0, 1.0) + 0.3 * max_bec
    payload = max(_clamp(urls.score, 0.0, 1.0), _clamp(atts.score, 0.0, 1.0) * 0.9)
    score = 100 * max(intent, payload)
    # A message that is both worded like an attack and carries a hostile payload
    # is worse than either alone.
    if intent > 0.4 and payload > 0.4:
        score += 10
    return _clamp(score)


def _identity_forgery_score(header_analysis: HeaderAnalysis) -> float:
    """Forged sender fields, scored with the authentication pillar because they
    are protocol-level identity claims rather than wording."""
    score = 0.0
    if header_analysis.display_name_spoof:
        score += 45
    if header_analysis.reply_to_mismatch:
        score += 35
    if header_analysis.return_path_mismatch:
        score += 25
    if header_analysis.message_id_mismatch:
        score += 15
    return score


def _authentication_pillar(auth: AuthResult, header_analysis: HeaderAnalysis, sender_domain: str, cfg: Settings) -> float:
    """Pillar 2 - Auth/protocols: SPF, DKIM, DMARC, alignment and forged fields."""
    return _clamp(_authentication_score(auth, sender_domain, cfg) + _identity_forgery_score(header_analysis))


_ROUTING_ANOMALIES: dict[str, float] = {
    "forged_received_order": 40.0,
    "negative_delay": 25.0,
    "large_delay": 10.0,
    "no_tls": 10.0,
    "helo_mismatch": 10.0,
    "unparseable": 5.0,
}


def _geoip_route_score(header_analysis: HeaderAnalysis, infra: InfraAnalysis) -> float:
    """Pillar 3 - GeoIP and route: where it came from and how it travelled.

    Combines the origin-infrastructure verdict (Tor, VPN, hosting, blocklisted
    address, suspected open relay, botnet traits) with the delivery-path
    anomalies found in the Received chain, including the hop time deltas.
    """
    infra_part = 100 * _clamp(infra.score, 0.0, 1.0)
    seen: set[str] = set()
    for hop in header_analysis.hops:
        seen.update(hop.anomalies)
    routing_part = sum(weight for name, weight in _ROUTING_ANOMALIES.items() if name in seen)
    if header_analysis.hops and not any(h.from_ip and not h.is_private_ip for h in header_analysis.hops):
        routing_part += 20  # the true origin is hidden behind private addressing
    if not header_analysis.hops:
        routing_part += 25  # no delivery record at all
    if header_analysis.originating_ip and header_analysis.origin_confidence < 0.5:
        routing_part += 10
    return _clamp(max(infra_part, _clamp(routing_part)) + 0.25 * min(infra_part, _clamp(routing_part)))


def _domain_score(domain_intel: list[DomainIntel], header_analysis: HeaderAnalysis) -> float:
    """Pillar 4 - Domain: registration age, lookalikes and DNS/MX posture."""
    score = 0.0
    for d in domain_intel:
        weight = 1.0 if d.role in ("sender", "reply_to", "return_path") else 0.6
        candidate = 0.0
        if d.lookalike_of:
            candidate = max(candidate, 85.0)
        if d.age_days is not None and not d.is_free_mail:
            if d.age_days < 30:
                candidate = max(candidate, 80.0)
            elif d.age_days < 90:
                candidate = max(candidate, 55.0)
            elif d.age_days < 365:
                candidate = max(candidate, 25.0)
        if d.is_disposable:
            candidate = max(candidate, 60.0)
        if d.role == "sender" and not d.is_free_mail and d.source not in ("offline", "unavailable"):
            if not d.resolves:
                candidate = max(candidate, 70.0)
            elif not d.has_mx:
                candidate = max(candidate, 40.0)
        if d.is_free_mail and d.role == "sender" and header_analysis.display_name_spoof:
            candidate = max(candidate, 30.0)
        score = max(score, candidate * weight)
    return _clamp(score)


def _threat_intel_score(domain_intel: list[DomainIntel], infra: InfraAnalysis, intel: ThreatIntel) -> float:
    """Pillar 5 - Threat intel: blocklists, reputation feeds and prior incidents."""
    score = 0.0
    if intel.ip_blacklists:
        score = max(score, 80.0)
    if intel.tor_exits:
        score = max(score, 85.0)
    if any(d.reputation for d in domain_intel):
        feeds = [t for d in domain_intel for t in d.reputation if t not in ("suspicious_tld", "disposable")]
        score = max(score, 90.0 if feeds else 30.0)
    if infra.blacklisted:
        score = max(score, 75.0)
    if intel.related_incidents:
        worst = max((r.risk_score for r in intel.related_incidents), default=0)
        score = max(score, 40.0 + 0.4 * worst)
    return _clamp(score)


def _normalized_weights(cfg: Settings) -> dict[str, float]:
    configured = cfg.weights or {}
    weights = {name: _clamp(configured.get(name, default), 0.0, 1e6) for name, default in DEFAULT_WEIGHTS.items()}
    total = sum(weights.values())
    if total <= 0.0:
        weights = dict(DEFAULT_WEIGHTS)
        total = sum(weights.values())
    return {name: value / total for name, value in weights.items()}


def component_scores(
    header_analysis: HeaderAnalysis,
    url_analysis: UrlAnalysis,
    att_analysis: AttachmentAnalysis,
    nlp_analysis: NlpAnalysis,
    domain_intel: list[DomainIntel],
    infra: InfraAnalysis,
    intel: ThreatIntel,
    cfg: Settings,
    sender_domain: str = "",
) -> RiskBreakdown:
    """Per-family 0-100 scores plus the normalised weights used to combine them.

    ``sender_domain`` (registrable) enables the protected-domain bonus in the
    authentication score; when omitted it is taken from the sender DomainIntel.
    """
    domain_intel = list(domain_intel or [])
    if not sender_domain:
        sender_domain = next((d.domain.lower() for d in domain_intel if d.role == "sender"), "")
    return RiskBreakdown(
        ai=_ai_score(nlp_analysis, url_analysis, att_analysis),
        authentication=_authentication_pillar(header_analysis.auth, header_analysis, sender_domain, cfg),
        geoip_route=_geoip_route_score(header_analysis, infra),
        domain=_domain_score(domain_intel, header_analysis),
        threat_intel=_threat_intel_score(domain_intel, infra, intel),
        weights=_normalized_weights(cfg),
    )


def weighted_risk(breakdown: RiskBreakdown) -> int:
    weights = breakdown.weights or DEFAULT_WEIGHTS
    total = sum(weights.get(name, 0.0) * getattr(breakdown, name) for name in DEFAULT_WEIGHTS)
    return int(round(_clamp(total)))


def _breakdown_line(breakdown: RiskBreakdown, risk: int) -> str:
    parts = ", ".join(
        f"{name} {getattr(breakdown, name):.0f} x {breakdown.weights.get(name, 0.0):.2f}" for name in DEFAULT_WEIGHTS
    )
    return f"Weighted risk {risk}/100 = {parts}."


# --------------------------------------------------------------------------- #
# Rule policy
# --------------------------------------------------------------------------- #
def _pressure_cues(
    parsed: ParsedEmail, header_analysis: HeaderAnalysis, nlp: NlpAnalysis, sender_domain: str, sender_free: bool
) -> list[str]:
    """Signals that turn a financial topic into a fraud lure."""
    cues: list[str] = []
    if header_analysis.reply_to_mismatch:
        reply_domains = _unique(_registrable(r.domain) for r in parsed.reply_to if r.domain)
        other = next((d for d in reply_domains if d != sender_domain), reply_domains[0] if reply_domains else "another domain")
        cues.append(f"Reply-To domain {other} differs from sender domain {sender_domain or 'unknown'}")
    if sender_free:
        cues.append(f"free-mail sender domain {sender_domain}")
    if nlp.urgency_score >= 0.5:
        phrases = f" ({_quote(nlp.urgency_phrases, 2)})" if nlp.urgency_phrases else ""
        cues.append(f"urgency score {nlp.urgency_score:.2f}{phrases}")
    return cues


def rule_classify(
    parsed: ParsedEmail,
    header_analysis: HeaderAnalysis,
    url_analysis: UrlAnalysis,
    att_analysis: AttachmentAnalysis,
    nlp_analysis: NlpAnalysis,
    domain_intel: list[DomainIntel],
    findings: list[Finding],
    risk_score: int,
    cfg: Settings,
) -> tuple[ThreatCategory, list[str]]:
    """Deterministic first-match policy.  Rules are evaluated in the fixed
    order Fraud > Phishing > Impersonated > Suspicious > Legitimate; inside the
    winning rule every satisfied sub-condition contributes one evidence line."""
    auth = header_analysis.auth
    sender_domain = _registrable(parsed.sender.domain)
    sender_free = _is_freemail(sender_domain)
    fin_terms = nlp_analysis.financial_terms
    cred_terms = nlp_analysis.credential_terms
    ml_cat = _as_category(nlp_analysis.ml_category)
    ml_p = _ml_prob(nlp_analysis.ml_probabilities, ml_cat)
    payment_conf, payment_ev = _bec_confidence(nlp_analysis, "payment_diversion")
    invoice_conf, invoice_ev = _bec_confidence(nlp_analysis, "fake_invoice")
    cred_conf, cred_ev = _bec_confidence(nlp_analysis, "credential_harvesting")
    exec_conf, exec_ev = _bec_confidence(nlp_analysis, "executive_impersonation")
    spf, dkim, dmarc = auth.spf.lower(), auth.dkim.lower(), auth.dmarc.lower()
    spf_fail, dmarc_fail = spf == "fail", dmarc == "fail"
    any_auth_failure = spf in {"fail", "softfail"} or dkim == "fail" or dmarc_fail
    protected_sender = _is_protected_domain(sender_domain, cfg)
    high_urls = [u for u in url_analysis.urls if _sev(u.risk) >= SEVERITY_ORDER["high"]]
    medium_urls = [u for u in url_analysis.urls if _sev(u.risk) >= SEVERITY_ORDER["medium"]]
    critical_atts = [a for a in att_analysis.attachments if _sev(a.risk) >= SEVERITY_ORDER["critical"]]

    # 1. Fraud-Related -------------------------------------------------------
    why: list[str] = []
    # A dominant credential-harvest pattern is a phishing signal; it must not
    # be re-read as fraud just because the lure also mentions money or asks the
    # victim to "update" an account number (KYC lures do exactly that).
    credential_dominant = cred_conf >= 0.5 and cred_conf >= max(payment_conf, invoice_conf)
    if payment_conf >= 0.5 and not credential_dominant:
        why.append(
            f"Payment-diversion BEC pattern (confidence {payment_conf:.2f}): "
            f"{_quote(payment_ev) or 'request to pay into new bank details'}"
        )
    if invoice_conf >= 0.5 and not credential_dominant:
        why.append(
            f"Fake-invoice BEC pattern (confidence {invoice_conf:.2f}): "
            f"{_quote(invoice_ev) or 'invoice/payment demand with pressure'}"
        )
    pressure = _pressure_cues(parsed, header_analysis, nlp_analysis, sender_domain, sender_free)
    if len(fin_terms) >= 2 and pressure and risk_score >= 40 and not credential_dominant:
        why.append(f"Financial lure {_quote(fin_terms)} combined with {'; '.join(pressure)} at risk {risk_score}/100")
    if ml_cat == ThreatCategory.FRAUD and ml_p >= 0.6 and fin_terms and cred_conf < 0.5:
        why.append(f"ML classifier rates Fraud-Related at p={ml_p:.2f} and the text carries financial terms {_quote(fin_terms)}")
    if exec_conf >= 0.5 and fin_terms:
        why.append(
            f"Executive-impersonation pattern (confidence {exec_conf:.2f}, {_quote(exec_ev, 2) or 'executive persona'}) "
            f"paired with a money request {_quote(fin_terms)}"
        )
    if why:
        return ThreatCategory.FRAUD, why

    # 2. Phishing -------------------------------------------------------------
    why = []
    if cred_conf >= 0.5:
        why.append(
            f"Credential-harvesting BEC pattern (confidence {cred_conf:.2f}): "
            f"{_quote(cred_ev) or 'credential request paired with a link'}"
        )
    if high_urls and cred_terms:
        why.append(f"High-risk link {_describe_url(high_urls[0])} alongside credential terms {_quote(cred_terms)}")
    harvest = _finding(findings, "credential_harvest_link")
    if harvest is not None:
        why.append(f"Link flagged as a credential-harvest page: {harvest.detail}")
    lookalike_link = _finding(findings, "lookalike_domain_link")
    if lookalike_link is not None and cred_terms:
        why.append(f"Lookalike-domain link ({lookalike_link.detail}) combined with credential terms {_quote(cred_terms)}")
    if ml_cat == ThreatCategory.PHISHING and ml_p >= 0.6 and medium_urls:
        why.append(f"ML classifier rates Phishing at p={ml_p:.2f} and the message links to {_describe_url(medium_urls[0])}")
    if critical_atts and cred_terms:
        att = critical_atts[0]
        reason = att.reasons[0] if att.reasons else (att.magic_type or att.extension or "critical risk")
        why.append(f"Critical attachment '{att.filename}' ({reason}) delivered with a credential lure {_quote(cred_terms)}")
    if why:
        return ThreatCategory.PHISHING, why

    # 3. Impersonated ---------------------------------------------------------
    why = []
    if header_analysis.display_name_spoof:
        name = parsed.sender.display_name or parsed.sender.raw or "(empty)"
        brand = header_analysis.display_name_brand or "a trusted identity"
        why.append(f"Display name '{_short(name, 60)}' imitates {brand} while the sender domain is {sender_domain or 'unknown'}")
    if exec_conf >= 0.35:
        why.append(
            f"Executive-impersonation pattern (confidence {exec_conf:.2f}): "
            f"{_quote(exec_ev) or 'first-touch request from an executive persona'}"
        )
    for d in _lookalike_sender_domains(domain_intel):
        why.append(f"{_role_label(d.role)} domain {d.domain} is a {d.lookalike_technique or 'lookalike'} imitation of {d.lookalike_of}")
    if (spf_fail or dmarc_fail) and protected_sender:
        failed = " and ".join(name for name, flag in (("SPF", spf_fail), ("DMARC", dmarc_fail)) if flag)
        owner = "protected organisation" if sender_domain in _org_domains(cfg) else "brand"
        why.append(f"{failed} fail for {owner} domain {sender_domain}: the message did not come from the domain it claims")
    if ml_cat == ThreatCategory.IMPERSONATED and ml_p >= 0.6 and any_auth_failure:
        why.append(f"ML classifier rates Impersonated at p={ml_p:.2f} with authentication failure (SPF {spf}, DKIM {dkim}, DMARC {dmarc})")
    if why:
        return ThreatCategory.IMPERSONATED, why

    # 4. Suspicious -----------------------------------------------------------
    why = []
    if risk_score >= 25:
        why.append(f"Weighted risk score {risk_score}/100 is at or above the suspicious threshold of 25")
    severe = [f for f in findings if _sev(f.severity) >= SEVERITY_ORDER["high"]]
    if severe:
        why.append(f"{len(severe)} high/critical finding(s): {_quote([f.title for f in severe])}")
    if ml_cat != ThreatCategory.LEGITIMATE and ml_p >= 0.6:
        why.append(f"ML classifier favours {ml_cat.value} at p={ml_p:.2f}")
    if why:
        return ThreatCategory.SUSPICIOUS, why

    # 5. Legitimate -----------------------------------------------------------
    return ThreatCategory.LEGITIMATE, [
        f"No policy rule matched: SPF {spf}, DKIM {dkim}, DMARC {dmarc}; {len(url_analysis.urls)} link(s), "
        f"{len(att_analysis.attachments)} attachment(s), {len(nlp_analysis.bec_patterns)} BEC pattern(s); risk {risk_score}/100"
    ]


# --------------------------------------------------------------------------- #
# Dual validation
# --------------------------------------------------------------------------- #
def fuse_category(
    rule_cat: ThreatCategory,
    ml_cat: ThreatCategory,
    ml_probs: Optional[dict[str, float]],
    risk_score: int,
) -> tuple[ThreatCategory, float, bool]:
    """The rule engine decides; the ML model modulates confidence.

    Agreement: 0.75 + 0.25 * P(rule category), capped at 0.98.
    Disagreement: 0.6, +0.1 when the risk score supports the rule verdict.
    """
    rule_cat = _as_category(rule_cat)
    ml_cat = _as_category(ml_cat)
    agreement = rule_cat == ml_cat
    if agreement:
        confidence = min(0.98, 0.75 + 0.25 * _ml_prob(ml_probs, rule_cat))
    else:
        confidence = 0.6
        rule_is_threat = rule_cat != ThreatCategory.LEGITIMATE
        if (rule_is_threat and risk_score >= 50) or (not rule_is_threat and risk_score < 25):
            confidence += 0.1
    return rule_cat, _clamp(confidence, 0.0, 1.0), agreement


# --------------------------------------------------------------------------- #
# Attribution
# --------------------------------------------------------------------------- #
def _attribution_indicators(
    parsed: ParsedEmail,
    header_analysis: HeaderAnalysis,
    url_analysis: UrlAnalysis,
    att_analysis: AttachmentAnalysis,
    infra: InfraAnalysis,
) -> list[str]:
    items: list[str] = []
    if header_analysis.originating_ip:
        items.append(f"origin_ip:{header_analysis.originating_ip}")
    geo = infra.origin_geo
    if geo is not None:
        if geo.asn:
            items.append(f"asn:{geo.asn}")
        if geo.isp:
            items.append(f"isp:{geo.isp}")
        if geo.country_code:
            items.append(f"origin_country:{geo.country_code}")
    if parsed.sender.address:
        items.append(f"sender:{parsed.sender.address.lower()}")
    sender_domain = _registrable(parsed.sender.domain)
    if sender_domain:
        items.append(f"sender_domain:{sender_domain}")
    for reply in parsed.reply_to:
        if reply.address:
            items.append(f"reply_to:{reply.address.lower()}")
    for host in _unique(u.host.lower() for u in url_analysis.urls if u.host)[:10]:
        items.append(f"url_host:{host}")
    for att in att_analysis.attachments[:10]:
        if att.sha256:
            items.append(f"attachment_sha256:{att.sha256}")
    return _unique(items)


def attribute_source(
    parsed: ParsedEmail,
    header_analysis: HeaderAnalysis,
    url_analysis: UrlAnalysis,
    att_analysis: AttachmentAnalysis,
    domain_intel: list[DomainIntel],
    infra: InfraAnalysis,
    category: ThreatCategory,
    confidence: float,
    findings: list[Finding],
    cfg: Settings,
) -> Attribution:
    """Explain the most plausible origin of the message.

    A Legitimate verdict always maps to ``legitimate_sender``; the attacker
    source types are then tested in the contract order (lookalike domain,
    spoofed domain, compromised account, attacker infrastructure, throwaway
    free-mail box) and fall through to ``undetermined``.
    """
    category = _as_category(category)
    domain_intel = list(domain_intel or [])
    auth = header_analysis.auth
    sender_domain = _registrable(parsed.sender.domain)
    sender_free = _is_freemail(sender_domain)
    sender_intel = next((d for d in domain_intel if d.role == "sender"), None)
    if sender_intel is None:
        sender_intel = next((d for d in domain_intel if d.domain.lower() == sender_domain), None)
    age = sender_intel.age_days if sender_intel is not None else None
    finding_ids = {f.id for f in findings}
    indicators = _attribution_indicators(parsed, header_analysis, url_analysis, att_analysis, infra)
    origin = header_analysis.originating_ip or "unknown"
    auth_summary = f"SPF {auth.spf}, DKIM {auth.dkim}, DMARC {auth.dmarc}"

    def make(source: SourceType, conf: float, reasoning: list[str]) -> Attribution:
        return Attribution(source_type=source, confidence=_clamp(conf, 0.0, 1.0), reasoning=reasoning, indicators=indicators)

    if category == ThreatCategory.LEGITIMATE:
        return make(
            "legitimate_sender",
            confidence,
            [f"No threat category was assigned; {parsed.sender.address or 'the sender'} passed policy review ({auth_summary})."],
        )

    lookalikes = _lookalike_sender_domains(domain_intel)
    if lookalikes:
        d = lookalikes[0]
        newly = d.age_days is not None and d.age_days < 90
        reasoning = [
            f"{_role_label(d.role)} domain {d.domain} imitates {d.lookalike_of} ({d.lookalike_technique or 'lookalike'}); "
            "the attacker registered a deceptive domain instead of spoofing the real one."
        ]
        if newly:
            reasoning.append(f"The domain was registered only {d.age_days} day(s) ago, typical of purpose-built attack infrastructure.")
        return make("lookalike_domain", 0.9 if newly else 0.8, reasoning)

    spf_fail = auth.spf.lower() == "fail"
    dmarc_fail = auth.dmarc.lower() == "fail"
    auth_missing = "auth_all_missing" in finding_ids
    established = (age is not None and age >= 365) or _is_protected_domain(sender_domain, cfg)
    sender_lookalike = bool(sender_intel is not None and sender_intel.lookalike_of)
    if (spf_fail or dmarc_fail or auth_missing) and established and not sender_lookalike:
        failed = ", ".join(
            name
            for name, flag in (("SPF fail", spf_fail), ("DMARC fail", dmarc_fail), ("no SPF/DKIM/DMARC evidence", auth_missing))
            if flag
        )
        pedigree = f"registered {age} days ago" if age is not None else "a known brand or protected organisation"
        reasoning = [f"{sender_domain} is an established domain ({pedigree}) but the message failed authentication ({failed}): the From address was forged."]
        if origin != "unknown":
            reasoning.append(f"Delivery originated from {origin}, which is not an authorised sender for {sender_domain}.")
        return make("spoofed_domain", 0.85 if dmarc_fail else 0.75, reasoning)

    aligned = bool(auth.spf_aligned) or bool(auth.dkim_aligned)
    if auth.spf.lower() == "pass" and auth.dkim.lower() == "pass" and aligned and category in _ATTACK_CATEGORIES and not sender_free:
        return make(
            "compromised_account",
            0.7,
            [
                f"SPF and DKIM pass with domain alignment for {sender_domain}, so the message went through that domain's genuine mail system; "
                f"a {category.value} message from a real account points to a compromised mailbox ({parsed.sender.address})."
            ],
        )

    infra_reasons: list[str] = []
    infra_conf = 0.0
    geo = infra.origin_geo
    provider = (geo.isp or geo.org) if geo is not None else ""
    if infra.tor_exit:
        infra_reasons.append(f"Origin IP {origin} is a Tor exit node (anonymised attacker infrastructure).")
        infra_conf = max(infra_conf, 0.85)
    if sender_intel is not None and sender_intel.is_disposable:
        infra_reasons.append(f"Sender domain {sender_domain} is a disposable mailbox provider.")
        infra_conf = max(infra_conf, 0.8)
    if age is not None and age < 90 and not sender_free:
        infra_reasons.append(f"Sender domain {sender_domain} was registered only {age} day(s) ago.")
        infra_conf = max(infra_conf, 0.75)
    if infra.vpn_or_proxy:
        infra_reasons.append(f"Origin IP {origin} is a VPN/proxy egress point{f' ({provider})' if provider else ''}.")
        infra_conf = max(infra_conf, 0.7)
    if infra.hosting_provider:
        infra_reasons.append(f"Origin IP {origin} belongs to a hosting provider{f' ({provider})' if provider else ''} rather than a mail service or ISP.")
        infra_conf = max(infra_conf, 0.65)
    if infra_reasons:
        return make("direct_attacker_infrastructure", infra_conf, infra_reasons)

    if sender_free and (header_analysis.display_name_spoof or category in {ThreatCategory.FRAUD, ThreatCategory.PHISHING}):
        who = header_analysis.display_name_brand or parsed.sender.display_name
        posture = f"posing as {who}" if who else f"used for a {category.value} message"
        return make(
            "direct_attacker_infrastructure",
            0.6 if header_analysis.display_name_spoof else 0.55,
            [f"Free-mail mailbox {parsed.sender.address} {posture}: a throwaway account under the attacker's direct control."],
        )

    return make(
        "undetermined",
        0.3,
        [f"No decisive attribution signal: {auth_summary}; sender domain {sender_domain or 'unknown'}; origin {origin}."],
    )


# --------------------------------------------------------------------------- #
# Recommended actions
# --------------------------------------------------------------------------- #
def recommended_actions(
    category: ThreatCategory,
    findings: list[Finding],
    parsed: ParsedEmail,
    header_analysis: HeaderAnalysis,
    url_analysis: UrlAnalysis,
    att_analysis: AttachmentAnalysis,
    attribution: Optional[Attribution] = None,
) -> list[str]:
    """Concrete analyst playbook for the verdict, naming the actual IOCs."""
    category = _as_category(category)
    finding_ids = {f.id for f in findings}
    sender = parsed.sender.address or "the sender address"
    sender_domain = _registrable(parsed.sender.domain)
    origin_ip = header_analysis.originating_ip
    risky_hosts = _unique(u.host for u in url_analysis.urls if u.host and _sev(u.risk) >= SEVERITY_ORDER["medium"])
    risky_atts = [a for a in att_analysis.attachments if _sev(a.risk) >= SEVERITY_ORDER["high"]]
    actions: list[str] = []

    if category == ThreatCategory.LEGITIMATE:
        notable = [f.title for f in findings if _sev(f.severity) >= SEVERITY_ORDER["medium"]]
        if notable:
            actions.append(f"Deliver normally, but keep the residual observations on file for the analyst: {_quote(notable)}.")
        else:
            actions.append("No action required: the message shows no threat indicators and can be delivered normally.")
        return actions

    # Never block a whole free-mail provider because of one abusive mailbox.
    block_scope = sender if (_is_freemail(sender_domain) or not sender_domain) else f"{sender} and the domain {sender_domain}"
    block = f"Block {block_scope} at the mail gateway and purge copies of this message from user mailboxes."

    if category == ThreatCategory.FRAUD:
        if finding_ids & {"bec_payment_diversion", "bec_fake_invoice"}:
            actions.append(
                "Do not act on any payment or bank-detail instruction in this message: have Finance verify the change with the "
                "counterparty on a previously known phone number, never by replying to this thread."
            )
        else:
            actions.append("Treat every request for money, fees or personal identifiers in this message as fraudulent; do not respond, pay or share documents.")
        actions.append(block)
    elif category == ThreatCategory.PHISHING:
        actions.append(
            "Reset passwords and revoke active sessions for any recipient who followed the link or entered credentials; "
            "enforce MFA on the affected accounts."
        )
        if risky_hosts:
            actions.append(f"Block the phishing host(s) {_quote(risky_hosts)} at the web proxy / DNS filter.")
        actions.append(block)
    elif category == ThreatCategory.IMPERSONATED:
        who = header_analysis.display_name_brand or parsed.sender.display_name or "the claimed sender"
        actions.append(f"Verify any request in this message with {who} through an independent, known channel (phone or in person); do not reply to the message.")
        actions.append(block)
        if header_analysis.display_name_spoof and parsed.sender.display_name:
            actions.append(f"Add a gateway rule that flags external mail using the display name '{_short(parsed.sender.display_name, 60)}'.")
    else:
        actions.append("Quarantine the message pending analyst review; do not open attachments or follow links until the sender is verified.")
        actions.append(f"Verify the sender ({sender}) through a known contact channel before responding.")

    for att in risky_atts[:2]:
        reason = att.reasons[0] if att.reasons else (att.magic_type or att.extension or att.content_type or "risky file type")
        hash_note = f" and block its SHA-256 {att.sha256[:16]}..." if att.sha256 else ""
        actions.append(f"Do not open attachment '{att.filename}' ({att.risk.value}: {reason}); detonate it in a sandbox{hash_note}.")
    if "tor_exit_node" in finding_ids:
        actions.append("The origin IP is a Tor exit node and does not identify the actor; pivot on the Reply-To address, link hosts and attachment hashes instead.")
    if attribution is not None and attribution.source_type == "compromised_account" and sender_domain:
        actions.append(f"Notify the administrator of {sender_domain} that the mailbox {sender} appears compromised so they can secure it.")
    if "known_campaign_overlap" in finding_ids:
        actions.append("This message overlaps with prior incidents: extend containment to every member of the campaign and review the shared indicators.")

    iocs: list[str] = []
    if origin_ip:
        iocs.append(f"origin IP {origin_ip}")
    iocs.extend(f"host {host}" for host in risky_hosts[:3])
    iocs.extend(f"SHA-256 {att.sha256}" for att in att_analysis.attachments[:2] if att.sha256)
    iocs.extend(f"Reply-To {reply.address}" for reply in parsed.reply_to if reply.address)
    if iocs:
        actions.append(f"Add these IOCs to the mail gateway / SIEM blocklists: {'; '.join(iocs)}.")

    if category == ThreatCategory.SUSPICIOUS:
        watch = sender + (f" and origin IP {origin_ip}" if origin_ip else "")
        actions.append(f"Monitor for further messages from {watch}; escalate if the pattern repeats.")
    else:
        actions.append(
            "Preserve the original .eml and this report as evidence (hashes are recorded in the custody ledger) and report the incident "
            "to CERT-In (incident@cert-in.org.in) and the National Cybercrime Reporting Portal (cybercrime.gov.in)."
        )
    subject = _short(parsed.subject, 60) or "(no subject)"
    actions.append(f"Circulate a short user-awareness note describing this lure (subject: '{subject}') so recipients recognise similar messages.")
    return _unique(actions)[:10]


# --------------------------------------------------------------------------- #
# Findings merge
# --------------------------------------------------------------------------- #
def collect_findings(*finding_lists: Optional[Iterable[Finding]]) -> list[Finding]:
    """Merge finding lists, dedupe by (module, id) keeping the first, and sort
    by severity descending, then module, then id."""
    seen: set[tuple[str, str]] = set()
    merged: list[Finding] = []
    for group in finding_lists:
        if not group:
            continue
        for finding in group:
            key = (finding.module, finding.id)
            if key in seen:
                continue
            seen.add(key)
            merged.append(finding)
    merged.sort(key=lambda f: (-_sev(f.severity), f.module, f.id))
    return merged


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #
def evaluate(
    parsed: ParsedEmail,
    header_analysis: HeaderAnalysis,
    url_analysis: UrlAnalysis,
    att_analysis: AttachmentAnalysis,
    nlp_analysis: NlpAnalysis,
    domain_intel: list[DomainIntel],
    infra: InfraAnalysis,
    intel: ThreatIntel,
    cfg: Settings,
) -> tuple[Verdict, Attribution, list[Finding]]:
    """Produce the Verdict, the Attribution and the merged finding list."""
    domain_intel = list(domain_intel or [])
    findings = collect_findings(
        header_analysis.findings,
        url_analysis.findings,
        att_analysis.findings,
        nlp_analysis.findings,
        *(d.findings for d in domain_intel),
        infra.findings,
        intel.findings,
    )
    sender_domain = _registrable(parsed.sender.domain)
    breakdown = component_scores(
        header_analysis, url_analysis, att_analysis, nlp_analysis, domain_intel, infra, intel, cfg, sender_domain=sender_domain
    )
    raw_risk = weighted_risk(breakdown)
    rationale: list[str] = [_breakdown_line(breakdown, raw_risk)]

    rule_cat, rule_lines = rule_classify(
        parsed, header_analysis, url_analysis, att_analysis, nlp_analysis, domain_intel, findings, raw_risk, cfg
    )
    rationale.extend(rule_lines)

    ml_cat = _as_category(nlp_analysis.ml_category)
    ml_p = _ml_prob(nlp_analysis.ml_probabilities, ml_cat)
    model_name = nlp_analysis.ml_model or "unavailable"
    category, confidence, agreement = fuse_category(rule_cat, ml_cat, nlp_analysis.ml_probabilities, raw_risk)
    scoring_findings: list[Finding] = []
    if agreement:
        rationale.append(f"ML classifier ({model_name}) agrees: {ml_cat.value} (p={ml_p:.2f}); confidence {confidence:.2f}.")
    else:
        because = rule_lines[0] if rule_lines else "the policy rules above"
        rationale.append(
            f"ML model favoured {ml_cat.value} (p={ml_p:.2f}); rule engine selected {rule_cat.value} because {because}. "
            f"Confidence lowered to {confidence:.2f}."
        )
        scoring_findings.append(
            Finding(
                id="dual_validation_disagreement",
                module="scoring",
                severity=Severity.LOW,
                title="Rule engine and ML classifier disagree",
                detail=(
                    f"The rule engine classified the message as {rule_cat.value} while the ML model favoured {ml_cat.value} "
                    f"(p={ml_p:.2f}). The rule verdict stands; confidence was reduced to {confidence:.2f}."
                ),
                evidence={
                    "rule_category": rule_cat.value,
                    "ml_category": ml_cat.value,
                    "ml_probability": round(ml_p, 3),
                    "ml_model": model_name,
                    "risk_score": raw_risk,
                },
            )
        )

    risk = raw_risk
    if category == ThreatCategory.LEGITIMATE and risk >= LEGITIMATE_RISK_CEILING:
        category = ThreatCategory.SUSPICIOUS
        rationale.append(
            f"Risk score {risk}/100 is too high for a Legitimate verdict (ceiling {LEGITIMATE_RISK_CEILING}); category raised to Suspicious."
        )
    floor = RISK_FLOORS.get(category, 0)
    if risk < floor:
        rationale.append(f"Risk score raised from {risk} to the {category.value} floor of {floor}.")
        scoring_findings.append(
            Finding(
                id="risk_floor_applied",
                module="scoring",
                severity=Severity.INFO,
                title="Risk floor applied",
                detail=f"The weighted score was {risk}/100 but a {category.value} verdict carries a minimum risk of {floor}; the score was raised to {floor}.",
                evidence={"category": category.value, "weighted_risk": risk, "floor": floor},
            )
        )
        risk = floor

    all_findings = collect_findings(findings, scoring_findings)
    attribution = attribute_source(
        parsed, header_analysis, url_analysis, att_analysis, domain_intel, infra, category, confidence, all_findings, cfg
    )
    verdict = Verdict(
        category=category,
        confidence=confidence,
        risk_score=risk,
        severity=severity_for(risk, has_findings=bool(all_findings)),
        breakdown=breakdown,
        ml_category=ml_cat,
        rule_category=rule_cat,
        dual_validation_agreement=agreement,
        rationale=rationale,
        recommended_actions=recommended_actions(
            category, all_findings, parsed, header_analysis, url_analysis, att_analysis, attribution
        ),
    )
    log.debug(
        "verdict %s risk=%d rule=%s ml=%s agreement=%s source=%s",
        category.value, risk, rule_cat.value, ml_cat.value, agreement, attribution.source_type,
    )
    return verdict, attribution, all_findings
