"""
Threat-intelligence correlation and campaign clustering.

Approach
--------
* ``extract_indicators`` reduces an analysis to normalised IOC keys
  (``ip:``, ``sender:``, ``domain:``, ``replyto:``, ``urlhost:``, ``file:`` are
  *strong*; ``subject:``, ``asn:``, ``mailer:`` are *weak*).
* ``correlate`` gathers feed hits already collected by the geo/domain
  analyzers and looks up prior incidents that share at least one strong
  indicator or two weak ones.
* ``assign_campaign`` runs after persistence: related emails are pulled into
  one campaign (creating it, joining the existing one, or merging several
  into the oldest) and the campaign's aggregate fields are recomputed.
"""
from __future__ import annotations

import ipaddress
import logging
import re
import uuid
from collections import Counter
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Optional

from ..schemas import (
    AnalysisResult,
    AttachmentAnalysis,
    Campaign,
    CaseSummary,
    DomainIntel,
    Finding,
    HeaderAnalysis,
    InfraAnalysis,
    ParsedEmail,
    RelatedIncident,
    Severity,
    ThreatIntel,
    UrlAnalysis,
)
from .knowledge import COMMON_URL_HOSTS, FREEMAIL_DOMAINS
from .urls import registrable_domain

if TYPE_CHECKING:  # pragma: no cover
    from ..db import Store

log = logging.getLogger("mailtrace.campaigns")

STRONG_PREFIXES: tuple[str, ...] = ("ip:", "sender:", "domain:", "replyto:", "urlhost:", "file:")
WEAK_PREFIXES: tuple[str, ...] = ("subject:", "asn:", "mailer:")
_LOCAL_TAGS = {"disposable", "suspicious_tld"}
_SUBJECT_PREFIX_RE = re.compile(r"^\s*(?:(?:re|fw|fwd|aw|wg|sv|tr)\s*:\s*|\[[^\]]{1,30}\]\s*)+", re.IGNORECASE)


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def normalize_subject(subject: str) -> str:
    text = _SUBJECT_PREFIX_RE.sub("", (subject or "").lower())
    text = re.sub(r"\d+", "#", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text[:80]


def _subject_stem(subject: str) -> str:
    text = _SUBJECT_PREFIX_RE.sub("", (subject or "").strip())
    text = re.sub(r"\s+", " ", text).strip()
    return text[:40]


def is_strong(indicator: str) -> bool:
    return indicator.startswith(STRONG_PREFIXES)


def extract_indicators(
    parsed: ParsedEmail,
    header_analysis: HeaderAnalysis,
    url_analysis: UrlAnalysis,
    att_analysis: AttachmentAnalysis,
    domain_intel: list[DomainIntel],
    infra: InfraAnalysis,
) -> list[str]:
    indicators: list[str] = []
    if header_analysis.originating_ip:
        indicators.append(f"ip:{header_analysis.originating_ip}")
    sender = (parsed.sender.address or "").lower()
    if sender:
        indicators.append(f"sender:{sender}")
    sender_rd = registrable_domain(parsed.sender.domain)
    if sender_rd and sender_rd not in FREEMAIL_DOMAINS and not _is_ip(sender_rd):
        indicators.append(f"domain:{sender_rd}")
    for reply in parsed.reply_to:
        if reply.address:
            indicators.append(f"replyto:{reply.address.lower()}")
    common = set(COMMON_URL_HOSTS) | {registrable_domain(h) for h in COMMON_URL_HOSTS}
    for url in url_analysis.urls:
        host = (url.host or "").lower()
        if not host or host in common or url.registrable_domain in common or _is_ip(host):
            continue
        indicators.append(f"urlhost:{host}")
    for att in att_analysis.attachments:
        if att.sha256 and not att.content_type.lower().startswith("image/"):
            indicators.append(f"file:{att.sha256}")
    subject = normalize_subject(parsed.subject)
    if len(subject) >= 12:
        indicators.append(f"subject:{subject}")
    geo = infra.origin_geo
    if geo is not None and geo.asn:
        indicators.append(f"asn:{geo.asn.upper()}")
    if parsed.mailer:
        indicators.append(f"mailer:{parsed.mailer.lower()[:60]}")
    return list(dict.fromkeys(indicators))


def _related(store: "Store", indicators: list[str], exclude_email_id: str) -> dict[str, list[str]]:
    """email_id -> shared indicators, keeping only convincing overlaps."""
    try:
        raw = store.find_emails_by_indicators(indicators, exclude_email_id)
    except Exception:  # noqa: BLE001
        log.exception("indicator lookup failed")
        return {}
    matches: dict[str, list[str]] = {}
    for email_id, shared in raw.items():
        strong = [s for s in shared if is_strong(s)]
        weak = [s for s in shared if not is_strong(s)]
        if strong or len(weak) >= 2:
            matches[email_id] = sorted(set(shared))
    return matches


def _finding(fid: str, severity: Severity, title: str, detail: str, evidence: dict) -> Finding:
    return Finding(id=fid, module="intel", severity=severity, title=title, detail=detail, evidence=evidence)


def correlate(
    email_id: str,
    parsed: ParsedEmail,
    header_analysis: HeaderAnalysis,
    url_analysis: UrlAnalysis,
    att_analysis: AttachmentAnalysis,
    domain_intel: list[DomainIntel],
    infra: InfraAnalysis,
    store: Optional["Store"],
) -> ThreatIntel:
    indicators = extract_indicators(parsed, header_analysis, url_analysis, att_analysis, domain_intel, infra)
    intel = ThreatIntel(indicators=indicators)

    geos = [hop.geo for hop in header_analysis.hops if hop.geo is not None]
    if infra.origin_geo is not None:
        geos.append(infra.origin_geo)
    for geo in geos:
        if geo.blacklists:
            intel.ip_blacklists[geo.ip] = sorted(set(intel.ip_blacklists.get(geo.ip, [])) | set(geo.blacklists))
        if geo.is_tor_exit and geo.ip not in intel.tor_exits:
            intel.tor_exits.append(geo.ip)
    for domain in domain_intel:
        feeds = [t for t in domain.reputation if t not in _LOCAL_TAGS]
        if feeds:
            intel.domain_reputation[domain.domain] = feeds

    findings: list[Finding] = []
    if intel.ip_blacklists or intel.domain_reputation or intel.tor_exits:
        parts: list[str] = []
        for ip, zones in intel.ip_blacklists.items():
            parts.append(f"{ip} listed on {', '.join(zones)}")
        for domain, feeds in intel.domain_reputation.items():
            parts.append(f"{domain} flagged by {', '.join(feeds)}")
        for ip in intel.tor_exits:
            parts.append(f"{ip} is a Tor exit node")
        findings.append(_finding(
            "threat_feed_hit", Severity.HIGH, "Threat-intelligence feed hit",
            "; ".join(parts) + ".",
            {"ip_blacklists": intel.ip_blacklists, "domain_reputation": intel.domain_reputation, "tor_exits": intel.tor_exits},
        ))

    if store is not None:
        matches = _related(store, indicators, email_id)
        summaries: list[CaseSummary] = []
        if matches:
            try:
                summaries = store.summaries_for(list(matches))
            except Exception:  # noqa: BLE001
                log.exception("summary lookup failed")
        for summary in summaries:
            intel.related_incidents.append(RelatedIncident(
                email_id=summary.id,
                subject=summary.subject,
                sender=summary.sender,
                risk_score=summary.risk_score,
                category=summary.category,
                shared_indicators=matches.get(summary.id, []),
            ))
        if intel.related_incidents:
            worst = max(r.risk_score for r in intel.related_incidents)
            shared = sorted({s for r in intel.related_incidents for s in r.shared_indicators})
            findings.append(_finding(
                "known_campaign_overlap", Severity.HIGH if worst >= 50 else Severity.MEDIUM, "Overlaps with prior incidents",
                f"{len(intel.related_incidents)} earlier message(s) share indicators {', '.join(shared[:4])}"
                f"{' ...' if len(shared) > 4 else ''}; highest prior risk {worst}/100.",
                {"related": [r.email_id for r in intel.related_incidents], "shared_indicators": shared},
            ))
            try:
                intel.campaign_id = next(
                    (cid for cid in (store.campaign_for_email(r.email_id) for r in intel.related_incidents) if cid), None
                )
            except Exception:  # noqa: BLE001
                intel.campaign_id = None
        else:
            findings.append(_finding(
                "no_prior_incidents", Severity.INFO, "No prior incidents",
                "None of this message's indicators appear in previously analysed emails.",
                {"indicators": indicators[:12]},
            ))
    intel.findings = findings
    return intel


def campaign_name(result: AnalysisResult, summaries: list[CaseSummary]) -> str:
    sender_rd = registrable_domain(result.email.sender.domain)
    if sender_rd and sender_rd not in FREEMAIL_DOMAINS:
        return f"Campaign - {sender_rd}"
    stem = _subject_stem(result.email.subject)
    if stem:
        return f"Campaign - {stem}"
    if result.headers.originating_ip:
        return f"Campaign - {result.headers.originating_ip}"
    return f"Campaign - {result.id}"


def assign_campaign(result: AnalysisResult, store: "Store") -> Optional[str]:
    """Cluster ``result`` with related prior emails; returns the campaign id."""
    indicators = result.intel.indicators or []
    store.save_indicators(result.id, indicators)
    matches = _related(store, indicators, result.id)
    if not matches:
        return None
    related_ids = list(matches)
    now = datetime.now(timezone.utc)
    existing_ids: list[str] = []
    for email_id in related_ids:
        cid = store.campaign_for_email(email_id)
        if cid and cid not in existing_ids:
            existing_ids.append(cid)
    campaigns = [c for c in (store.get_campaign(cid) for cid in existing_ids) if c is not None]

    member_ids: list[str] = []

    def add_members(ids: list[str]) -> None:
        for email_id in ids:
            if email_id and email_id not in member_ids:
                member_ids.append(email_id)

    if not campaigns:
        campaign = Campaign(id="cmp-" + uuid.uuid4().hex[:8], name="", created_at=now, updated_at=now)
    else:
        campaigns.sort(key=lambda c: c.created_at)
        campaign = campaigns[0]
        add_members(campaign.email_ids)
        for other in campaigns[1:]:
            add_members(other.email_ids)
            store.delete_campaign(other.id)
    add_members(related_ids)
    add_members([result.id])

    summaries = store.summaries_for([i for i in member_ids if i != result.id])
    for email_id in member_ids:
        store.update_campaign_id(email_id, campaign.id)

    shared: set[str] = set(campaign.indicators)
    for lst in matches.values():
        shared.update(lst)
    categories: Counter = Counter(s.category.value for s in summaries)
    categories[result.verdict.category.value] += 1
    countries: list[str] = []
    origin = result.infrastructure.origin_geo
    for country in [s.origin_country for s in summaries] + [origin.country if origin else ""]:
        if country and country not in countries:
            countries.append(country)

    campaign.email_ids = member_ids
    campaign.indicators = sorted(shared)
    campaign.max_risk = max([s.risk_score for s in summaries] + [result.verdict.risk_score])
    campaign.categories = dict(categories)
    campaign.countries = countries
    campaign.updated_at = now
    if not campaign.name:
        campaign.name = campaign_name(result, summaries)
    store.upsert_campaign(campaign)
    log.info("email %s assigned to campaign %s (%d members)", result.id, campaign.id, len(member_ids))
    return campaign.id
