"""
Forensic report generation.

Turns one persisted AnalysisResult plus its chain-of-custody ledger into a
ForensicReport (the JSON artefact served by the API) and renders that report
as a single, self-contained, printable HTML document intended for hand-over
to legal teams and law enforcement.

Approach
--------
* Everything in the report is a projection of the AnalysisResult and the
  CustodyChain passed in.  Nothing is re-derived or looked up, so a report is
  reproducible from stored data alone and this module depends on no analyzer.
* The executive summary is composed one sentence per topic (message, verdict,
  claimed identity, origin, authentication, lures, attribution, campaign) so a
  non-technical reader can follow the case without reading the tables.
* HTML rendering is plain string assembly: inline CSS, no scripts, no external
  assets, A4 print rules with page breaks between major sections, and every
  dynamic value passes through html.escape.  Hashes and URLs are monospace with
  word-break so nothing is truncated or hidden.
* Optional values (dates, geolocation, coordinates, ages, delays) render as an
  em dash rather than "None".
"""
from __future__ import annotations

import html
import json
import logging
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

from ..schemas import (
    SEVERITY_ORDER,
    AddressInfo,
    AnalysisResult,
    CustodyChain,
    ForensicReport,
    GeoInfo,
    Severity,
)

log = logging.getLogger("mailtrace.reporting")

_DASH = "&mdash;"
_MEDIUM = SEVERITY_ORDER[Severity.MEDIUM.value]

_SOURCE_LABELS: dict[str, str] = {
    "spoofed_domain": "spoofed sender domain: the visible From address was forged without control of that domain",
    "lookalike_domain": "attacker-registered look-alike domain",
    "compromised_account": "compromised legitimate account",
    "direct_attacker_infrastructure": "attacker-controlled infrastructure",
    "legitimate_sender": "legitimate sender",
    "undetermined": "source could not be determined",
}
_SPF_TEXT: dict[str, str] = {
    "pass": "SPF passed",
    "fail": "SPF failed",
    "softfail": "SPF soft-failed",
    "neutral": "SPF was neutral",
    "none": "no SPF result was available",
}
_DKIM_TEXT: dict[str, str] = {
    "pass": "the DKIM signature verified",
    "fail": "the DKIM signature failed verification",
    "none": "no DKIM signature was present",
}

_CSS = """
*{box-sizing:border-box}
html{-webkit-print-color-adjust:exact;print-color-adjust:exact}
body{margin:0;background:#eef1f5;color:#1c2430;font-family:"Segoe UI",Arial,Helvetica,sans-serif;font-size:10.5pt;line-height:1.45}
.page{max-width:210mm;margin:0 auto;background:#fff;padding:16mm 15mm;box-shadow:0 0 6px rgba(0,0,0,.12)}
h1{font-size:18pt;line-height:1.25;margin:0 0 10pt;word-break:break-word}
h2{font-size:13.5pt;margin:0 0 8pt;padding-bottom:3pt;border-bottom:2px solid #1c2430}
h3{font-size:11pt;margin:12pt 0 5pt;color:#2d3748}
p{margin:0 0 7pt}
ul,ol{margin:0 0 8pt 18pt;padding:0}
li{margin:0 0 3pt}
table{width:100%;border-collapse:collapse;margin:0 0 10pt;font-size:9pt}
th,td{border:1px solid #cbd3dc;padding:3.5pt 5pt;text-align:left;vertical-align:top;word-break:break-word}
th{background:#e8edf3;font-weight:600}
table.kv th{width:30%;background:#f4f6f9}
code{font-family:Consolas,"Courier New",monospace;font-size:8.5pt;word-break:break-all}
pre{font-family:Consolas,"Courier New",monospace;font-size:8pt;line-height:1.35;white-space:pre-wrap;word-break:break-all;background:#f4f6f9;border:1px solid #cbd3dc;padding:7pt;margin:0}
.sec{margin:0 0 16pt}
.muted{color:#5b6674}
.brand{font-size:9.5pt;letter-spacing:.14em;text-transform:uppercase;color:#5b6674;margin:0 0 4pt}
.brand strong{color:#1c2430}
.classification{display:inline-block;font-size:8.5pt;letter-spacing:.1em;text-transform:uppercase;color:#9b2c2c;border:1px solid #9b2c2c;padding:2pt 8pt;margin:0 0 10pt}
.badge{display:inline-block;padding:0 5pt;border-radius:2.5pt;font-size:8pt;font-weight:600;line-height:13pt;text-transform:uppercase;letter-spacing:.03em;color:#fff;background:#5b6674;margin:0 2pt 2pt 0;white-space:nowrap}
.sev-info{background:#5b6674}
.sev-low{background:#2f855a}
.sev-medium{background:#b7791f}
.sev-high{background:#c05621}
.sev-critical{background:#9b2c2c}
.ok{background:#2f855a}
.bad{background:#9b2c2c}
.neutral{background:#5b6674}
.meter{display:flex;align-items:center;gap:6pt}
.bar{position:relative;flex:1;min-width:70pt;height:8pt;background:#e2e8f0;border-radius:2pt;overflow:hidden}
.fill{position:absolute;left:0;top:0;bottom:0}
.meter-label{font-size:8.5pt;white-space:nowrap}
.verdict-box{color:#fff;padding:10pt 12pt;border-radius:4pt;margin:0 0 12pt}
.verdict-cat{font-size:16pt;font-weight:700;margin:0 0 2pt}
.verdict-meta{font-size:9.5pt;margin:0 0 6pt}
.verdict-box .bar{background:rgba(255,255,255,.35)}
.verdict-box .fill{background:#fff}
.verdict-box .meter-label{color:#fff}
.footer{margin-top:20pt;padding-top:6pt;border-top:1px solid #cbd3dc;font-size:8pt;color:#5b6674}
@page{size:A4;margin:14mm 12mm}
@media print{
body{background:#fff}
.page{max-width:none;margin:0;padding:0;box-shadow:none}
.pb{page-break-before:always;break-before:page}
tr,.verdict-box{page-break-inside:avoid;break-inside:avoid}
thead{display:table-header-group}
}
"""


# --------------------------------------------------------------------------- #
# Plain-text helpers
# --------------------------------------------------------------------------- #
def _clean(text: Any) -> str:
    """Collapse whitespace so a value never breaks the one-sentence-per-line summary."""
    return " ".join(str(text).split()) if text else ""


def _val(value: Any) -> str:
    """String form of a value; enum members yield their value, never 'Severity.HIGH'."""
    if isinstance(value, Enum):
        return str(value.value)
    return "" if value is None else str(value)


def _human(slug: str) -> str:
    return slug.replace("_", " ")


def _plural(count: int, noun: str) -> str:
    return f"{count} {noun}" if count == 1 else f"{count} {noun}s"


def _join_and(items: list[str]) -> str:
    if not items:
        return ""
    if len(items) == 1:
        return items[0]
    return ", ".join(items[:-1]) + " and " + items[-1]


def _examples(items: list[str], limit: int = 3) -> str:
    picked = [_clean(item) for item in items if _clean(item)][:limit]
    if not picked:
        return ""
    quoted = ", ".join(f'"{item}"' for item in picked)
    return f" (e.g. {quoted})"


def _short_list(items: list[str], limit: int) -> str:
    text = ", ".join(items[:limit])
    return text + " ..." if len(items) > limit else text


def _unique(items: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        if item and item not in seen:
            seen.add(item)
            out.append(item)
    return out


def _pct(value: float) -> str:
    return f"{int(round(max(0.0, min(1.0, value)) * 100))}%"


def _sentence(clauses: list[str]) -> str:
    text = "; ".join(clauses)
    return text[:1].upper() + text[1:] + "."


def _sev_rank(value: Any) -> int:
    return SEVERITY_ORDER.get(_val(value), 0)


def _place(geo: Optional[GeoInfo]) -> str:
    if geo is None:
        return ""
    if geo.is_private:
        return "private network"
    return ", ".join(part for part in (geo.city, geo.region, geo.country) if part)


def _describe_address(addr: AddressInfo) -> str:
    name = _clean(addr.display_name)
    address = _clean(addr.address)
    if name and address:
        return f'"{name}" <{address}>'
    if address:
        return address
    return f'"{name}"' if name else "an unknown sender"


def _fmt_dt(value: Optional[datetime]) -> str:
    if value is None:
        return ""
    if value.tzinfo is None:
        return value.strftime("%Y-%m-%d %H:%M:%S")
    return value.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _fmt_date(value: Optional[datetime]) -> str:
    return value.strftime("%Y-%m-%d") if value is not None else ""


def _iso(value: Optional[datetime]) -> Optional[str]:
    return value.isoformat() if value is not None else None


def _fmt_delay(seconds: Optional[float]) -> str:
    if seconds is None:
        return ""
    sign = "-" if seconds < 0 else "+"
    magnitude = abs(seconds)
    if magnitude < 120:
        return f"{sign}{magnitude:.0f} s"
    if magnitude < 7200:
        return f"{sign}{magnitude / 60:.1f} min"
    return f"{sign}{magnitude / 3600:.1f} h"


def _fmt_size(size: int) -> str:
    if size < 1024:
        return f"{size} B"
    if size < 1024 * 1024:
        return f"{size / 1024:.1f} KB"
    return f"{size / (1024 * 1024):.2f} MB"


# --------------------------------------------------------------------------- #
# Executive summary
# --------------------------------------------------------------------------- #
def _summary_message(result: AnalysisResult) -> str:
    email = result.email
    subject = _clean(email.subject) or "(no subject)"
    recipients = len(email.to) + len(email.cc)
    audience = f"to {_plural(recipients, 'recipient')}" if recipients else "with no visible recipient addresses"
    when = f" on {_fmt_dt(email.date)}" if email.date is not None else ""
    return (
        f'The message "{subject}" (file: {_clean(result.filename)}) was sent{when} '
        f"by {_describe_address(email.sender)} {audience}."
    )


def _summary_verdict(result: AnalysisResult) -> str:
    verdict = result.verdict
    stance = "agree" if verdict.dual_validation_agreement else "disagree"
    return (
        f"MailTrace classifies it as {_val(verdict.category)} with a risk score of "
        f"{verdict.risk_score}/100 ({_val(verdict.severity)} severity) at {_pct(verdict.confidence)} "
        f"confidence; the rule engine ({_val(verdict.rule_category)}) and the machine-learning model "
        f"({_val(verdict.ml_category)}) {stance}."
    )


def _summary_identity(result: AnalysisResult) -> str:
    email = result.email
    hdr = result.headers
    sender_domain = _clean(email.sender.domain)
    domain_text = f"the sending domain {sender_domain}" if sender_domain else "the sending domain"
    clauses: list[str] = []
    if hdr.display_name_spoof:
        name = _clean(email.sender.display_name)
        shown = f'"{name}"' if name else "used"
        brand = _clean(hdr.display_name_brand)
        target = f" and imitates {brand}" if brand else ""
        clauses.append(f"the display name {shown} is not backed by {domain_text}{target}")
    lookalike = next((d for d in result.domains if d.role == "sender" and d.lookalike_of), None)
    if lookalike is not None:
        technique = f" ({_human(lookalike.lookalike_technique)})" if lookalike.lookalike_technique else ""
        clauses.append(
            f"the sender domain {lookalike.domain} is a look-alike of {lookalike.lookalike_of}{technique}"
        )
    reply_to = [_clean(r.address) for r in email.reply_to if _clean(r.address)]
    if hdr.reply_to_mismatch and reply_to:
        clauses.append(f"replies are redirected to {_join_and(reply_to)}, a different domain from the sender")
    return_path = _clean(email.return_path.address)
    if hdr.return_path_mismatch and return_path:
        clauses.append(f"the envelope sender {return_path} differs from the visible From address")
    if hdr.message_id_mismatch and hdr.message_id_domain:
        clauses.append(
            f"the Message-ID was generated at {_clean(hdr.message_id_domain)}, not by the sender's domain"
        )
    if not clauses:
        return (
            f"The sender identity ({_describe_address(email.sender)}) shows no display-name, "
            "reply-to or envelope-sender inconsistencies."
        )
    return _sentence(clauses)


def _summary_origin(result: AnalysisResult) -> str:
    hdr = result.headers
    infra = result.infrastructure
    ip = _clean(hdr.originating_ip)
    if not ip:
        return "The originating IP address could not be established from the Received chain."
    geo = infra.origin_geo
    place = _place(geo)
    provider = _clean(geo.isp or geo.org) if geo is not None else ""
    where_bits = [bit for bit in (place, provider) if bit]
    where = f" ({'; '.join(where_bits)})" if where_bits else ""
    hop = f" at hop {hdr.originating_hop_index}" if hdr.originating_hop_index is not None else ""
    traits: list[str] = []
    if infra.tor_exit:
        traits.append("a Tor exit node")
    if infra.vpn_or_proxy:
        traits.append("a VPN or proxy service")
    if infra.hosting_provider:
        traits.append("a hosting or cloud provider")
    if infra.open_relay_suspected:
        traits.append("a suspected open relay")
    if infra.blacklisted:
        traits.append("listed on threat blocklists")
    trait_text = f"; the address is {_join_and(traits)}" if traits else ""
    return (
        f"The message entered the mail system from IP {ip}{where}{hop} "
        f"(origin confidence {_pct(hdr.origin_confidence)}){trait_text}."
    )


def _summary_auth(result: AnalysisResult) -> str:
    auth = result.headers.auth
    spf = _SPF_TEXT.get(auth.spf, "SPF could not be verified")
    dkim = _DKIM_TEXT.get(auth.dkim, "the DKIM signature could not be verified")
    policy = f" (policy: {auth.dmarc_policy})" if auth.dmarc_policy else ""
    if auth.dmarc == "pass":
        dmarc = f"DMARC passed{policy}"
    elif auth.dmarc == "fail":
        dmarc = f"DMARC failed{policy}"
    else:
        dmarc = f"no DMARC verdict was available{policy}"
    outcomes = (auth.spf, auth.dkim, auth.dmarc)
    if any(outcome in ("fail", "softfail") for outcome in outcomes):
        meaning = (
            "the sending infrastructure was not authorised for the claimed sender domain, "
            "a strong indicator of spoofing"
        )
    elif all(outcome == "pass" for outcome in outcomes):
        meaning = "the message passed through infrastructure authorised for the sender domain"
    else:
        meaning = "the sender identity could not be cryptographically confirmed"
    misaligned = auth.spf_aligned is False or auth.dkim_aligned is False
    alignment = "; the authenticated domain does not align with the visible From domain" if misaligned else ""
    return f"Authentication: {spf}, {dkim} and {dmarc}, meaning {meaning}{alignment}."


def _summary_lures(result: AnalysisResult) -> str:
    nlp = result.nlp
    lures: list[str] = []
    if nlp.urgency_phrases or nlp.urgency_score >= 0.3:
        lures.append(f"pressure and urgency language{_examples(nlp.urgency_phrases)}")
    if nlp.social_engineering_cues:
        lures.append(f"{_join_and([_human(cue) for cue in nlp.social_engineering_cues])} cues")
    if nlp.credential_terms:
        lures.append(f"requests for credentials or identity data{_examples(nlp.credential_terms)}")
    if nlp.financial_terms:
        lures.append(f"financial themes{_examples(nlp.financial_terms)}")
    if nlp.generic_greeting:
        lures.append("a generic, impersonal greeting")
    if nlp.requests_reply_not_click:
        lures.append("an instruction to respond directly by e-mail")
    if nlp.bec_patterns:
        patterns = sorted(nlp.bec_patterns, key=lambda item: item.confidence, reverse=True)
        names = ", ".join(f"{_human(item.pattern)} ({_pct(item.confidence)})" for item in patterns)
        lures.append(f"{_plural(len(patterns), 'business-e-mail-compromise pattern')}: {names}")
    risky_urls = [url for url in result.urls.urls if _sev_rank(url.risk) >= _MEDIUM]
    if risky_urls:
        hosts = _unique([url.host for url in risky_urls])[:3]
        sample = f" ({', '.join(hosts)})" if hosts else ""
        lures.append(f"{_plural(len(risky_urls), 'suspicious link')}{sample}")
    risky_files = [item for item in result.attachments.attachments if _sev_rank(item.risk) >= _MEDIUM]
    if risky_files:
        names = ", ".join(_clean(item.filename) for item in risky_files[:3])
        lures.append(f"{_plural(len(risky_files), 'dangerous attachment')} ({names})")
    if not lures:
        return "The content shows no notable pressure tactics, credential requests, dangerous links or attachments."
    return f"Lures observed in the content: {'; '.join(lures)}."


def _summary_attribution(result: AnalysisResult) -> str:
    attribution = result.attribution
    label = _SOURCE_LABELS.get(attribution.source_type, _human(attribution.source_type))
    reason = _clean(attribution.reasoning[0]).rstrip(".") if attribution.reasoning else ""
    tail = f": {reason}" if reason else ""
    return f"Attribution assessment: {label} (confidence {_pct(attribution.confidence)}){tail}."


def _summary_campaign(result: AnalysisResult) -> str:
    intel = result.intel
    related = len(intel.related_incidents)
    campaign = result.campaign_id or intel.campaign_id
    if related and campaign:
        text = (
            f"It shares indicators with {_plural(related, 'previously analysed message')} "
            f"and has been grouped into campaign {campaign}."
        )
    elif related:
        text = (
            f"It shares indicators with {_plural(related, 'previously analysed message')} "
            "but has not been assigned to a campaign."
        )
    elif campaign:
        text = f"It has been grouped into campaign {campaign}."
    else:
        text = "No links to previously analysed messages or known campaigns were found."
    hits = (
        sum(1 for zones in intel.ip_blacklists.values() if zones)
        + sum(1 for feeds in intel.domain_reputation.values() if feeds)
        + len(intel.tor_exits)
    )
    if hits:
        text += f" Threat-intelligence feeds flag {_plural(hits, 'indicator')} from this message."
    return text


def render_text_summary(result: AnalysisResult) -> str:
    """Return an eight-line plain-English executive summary, one sentence per line."""
    lines = (
        _summary_message(result),
        _summary_verdict(result),
        _summary_identity(result),
        _summary_origin(result),
        _summary_auth(result),
        _summary_lures(result),
        _summary_attribution(result),
        _summary_campaign(result),
    )
    return "\n".join(_clean(line) for line in lines)


# --------------------------------------------------------------------------- #
# Report assembly
# --------------------------------------------------------------------------- #
def _key_indicators(result: AnalysisResult) -> list[str]:
    email = result.email
    items: list[str] = []
    if result.headers.originating_ip:
        items.append(f"origin_ip: {result.headers.originating_ip}")
    if email.sender.address:
        items.append(f"sender: {email.sender.address}")
    if email.sender.domain:
        items.append(f"sender_domain: {email.sender.domain}")
    items.extend(f"reply_to: {addr.address}" for addr in email.reply_to if addr.address)
    items.extend(f"url_host: {url.host}" for url in result.urls.urls if url.host)
    items.extend(
        f"attachment_sha256: {item.sha256} ({item.filename})"
        for item in result.attachments.attachments
        if item.sha256
    )
    if email.message_id:
        items.append(f"message_id: {email.message_id}")
    return _unique(items)


def _evidence_integrity(result: AnalysisResult, custody: CustodyChain) -> dict[str, Any]:
    return {
        "raw_sha256": result.email.raw_sha256,
        "raw_md5": result.email.raw_md5,
        "raw_size": result.email.raw_size,
        "custody_head_hash": custody.head_hash,
        "custody_valid": custody.valid,
        "custody_events": len(custody.events),
        "engine_version": result.engine_version,
        "analyzed_at": result.analyzed_at.isoformat(),
    }


def _timeline(result: AnalysisResult, custody: CustodyChain) -> list[dict[str, Any]]:
    hdr = result.headers
    entries: list[dict[str, Any]] = []
    for hop in sorted(hdr.hops, key=lambda item: item.index):
        geo = hop.geo
        entries.append(
            {
                "kind": "hop",
                "sequence": hop.index,
                "timestamp": _iso(hop.timestamp),
                "from_host": hop.from_host,
                "from_ip": hop.from_ip,
                "by_host": hop.by_host,
                "protocol": hop.protocol,
                "delay_seconds": hop.delay_seconds,
                "location": _place(geo),
                "provider": (geo.isp or geo.org) if geo is not None else "",
                "is_origin": hdr.originating_hop_index is not None and hop.index == hdr.originating_hop_index,
                "is_private_ip": hop.is_private_ip,
                "is_internal": hop.is_internal,
                "anomalies": list(hop.anomalies),
                "summary": (
                    f"Hop {hop.index}: from {hop.from_host or hop.from_ip or 'unknown'} "
                    f"to {hop.by_host or 'unknown'} via {hop.protocol or 'unknown protocol'}"
                ),
            }
        )
    for event in custody.events:
        entries.append(
            {
                "kind": "custody",
                "sequence": event.seq,
                "timestamp": _iso(event.timestamp),
                "actor": event.actor,
                "action": event.action,
                "detail": dict(event.detail),
                "hash": event.hash,
                "summary": f"Custody event {event.seq}: {event.action} by {event.actor}",
            }
        )
    return entries


def _legal_notes(result: AnalysisResult, custody: CustodyChain, masked: bool) -> list[str]:
    ledger = "VALID" if custody.valid else "INVALID"
    if masked:
        privacy = (
            "Personally identifiable information (names, e-mail addresses, phone numbers, identity "
            "numbers) has been masked in this copy; domains, IP addresses, URLs and hashes are left intact. "
            "An unmasked copy can be produced from the preserved original by an authorised user, and such "
            "access is itself recorded in the custody ledger."
        )
    else:
        privacy = (
            "This copy is unmasked: it contains personal data exactly as present in the original message "
            "and must be handled under the applicable data-protection obligations (Digital Personal Data "
            "Protection Act, 2023)."
        )
    return [
        "The evidence was acquired as-is: the original message bytes were preserved unmodified at "
        "ingestion, and every analysis in this report is a read-only projection of that file.",
        f"SHA-256 and MD5 digests were computed over the exact message bytes at ingestion "
        f"({_fmt_dt(result.analyzed_at)}); recomputing them over the preserved file demonstrates that "
        "the exhibit has not been altered since.",
        "The chain of custody is a hash-linked, append-only ledger: each entry incorporates the hash of "
        "the previous entry, so altering or removing any record invalidates every later hash. Ledger "
        f"status at report generation: {ledger} ({_plural(len(custody.events), 'event')}, head hash "
        f"{custody.head_hash or 'n/a'}).",
        f"This report is the output of automated analysis (MailTrace engine {result.engine_version}). "
        "It supports, and does not replace, examination by a qualified forensic examiner; the "
        "classification, risk score and attribution are probabilistic assessments, not conclusive findings.",
        "The digests, timestamps, custody ledger and system details recorded here are intended to assist in "
        "preparing the certificate for electronic records under Section 65B of the Indian Evidence Act, "
        "1872 (inserted by the Information Technology Act, 2000; now Section 63 of the Bharatiya Sakshya "
        "Adhiniyam, 2023). The certificate itself must be executed by the person responsible for the "
        "system that produced the record.",
        "Network enrichment (geolocation, WHOIS, DNS and reputation feeds) reflects third-party data as "
        "observed at analysis time and may change; the source of each enrichment is recorded in the "
        "analysis data.",
        privacy,
    ]


def build_report(
    result: AnalysisResult,
    custody: CustodyChain,
    masked: bool,
    generated_by: str = "system",
) -> ForensicReport:
    """Assemble the forensic report for one analysis.

    ``masked`` states whether ``result`` has already been passed through PII
    masking; this function never masks anything itself.
    """
    now = datetime.now(timezone.utc)
    is_masked = masked or result.masked
    report = ForensicReport(
        report_id=f"RPT-{result.id}-{now:%Y%m%d%H%M}",
        generated_at=now,
        generated_by=generated_by,
        masked=is_masked,
        executive_summary=render_text_summary(result),
        key_indicators=_key_indicators(result),
        evidence_integrity=_evidence_integrity(result, custody),
        timeline=_timeline(result, custody),
        recommended_actions=list(result.verdict.recommended_actions),
        legal_notes=_legal_notes(result, custody, is_masked),
        custody=custody,
        analysis=result,
    )
    log.debug("built report %s for email %s (masked=%s)", report.report_id, result.id, is_masked)
    return report


# --------------------------------------------------------------------------- #
# HTML building blocks (every dynamic value is escaped here)
# --------------------------------------------------------------------------- #
def _esc(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, Enum):
        value = value.value
    return html.escape(str(value), quote=True)


def _cell(value: Any) -> str:
    text = _esc(value)
    return text if text else _DASH


def _cell_list(items: list[Any]) -> str:
    return ", ".join(_esc(item) for item in items) or _DASH


def _mono(value: Any) -> str:
    text = _esc(value)
    return f"<code>{text}</code>" if text else _DASH


def _yes_no(flag: bool) -> str:
    return "Yes" if flag else "No"


def _tri(flag: Optional[bool], yes: str, no: str) -> str:
    if flag is None:
        return "unknown"
    return yes if flag else no


def _badge(text: Any, css: str) -> str:
    return f'<span class="badge {_esc(css)}">{_esc(text)}</span>'


def _sev_badge(severity: Any) -> str:
    value = _val(severity) or Severity.INFO.value
    return _badge(value, f"sev-{value}")


def _sev_for_score(score: float) -> str:
    if score < 25:
        return Severity.LOW.value
    if score < 50:
        return Severity.MEDIUM.value
    if score < 75:
        return Severity.HIGH.value
    return Severity.CRITICAL.value


def _flag(hit: bool, yes: str = "flagged", no: str = "clear") -> str:
    return _badge(yes, "bad") if hit else _badge(no, "ok")


def _auth_badge(outcome: str) -> str:
    text = outcome or "none"
    if text == "pass":
        css = "ok"
    elif text in ("fail", "softfail"):
        css = "bad"
    else:
        css = "neutral"
    return _badge(text, css)


def _bar(percent: float, css: str, label: str) -> str:
    width = int(round(max(0.0, min(100.0, percent))))
    return (
        f'<div class="meter"><div class="bar"><span class="fill {_esc(css)}" style="width:{width}%"></span></div>'
        f'<span class="meter-label">{_esc(label)}</span></div>'
    )


def _table(headers: list[str], rows: list[list[str]], empty: str) -> str:
    """Render pre-escaped cell HTML as a table; show ``empty`` when there are no rows."""
    if not rows:
        return f'<p class="muted">{_esc(empty)}</p>' if empty else ""
    head = "".join(f"<th>{_esc(header)}</th>" for header in headers)
    body = "".join("<tr>" + "".join(f"<td>{cell}</td>" for cell in row) + "</tr>" for row in rows)
    return f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>"


def _kv(rows: list[tuple[str, str]]) -> str:
    """Two-column label/value table; labels are escaped here, values are pre-escaped HTML."""
    body = "".join(f"<tr><th>{_esc(label)}</th><td>{value}</td></tr>" for label, value in rows)
    return f'<table class="kv"><tbody>{body}</tbody></table>'


def _list(items: list[Any], ordered: bool = False, empty: str = "None recorded.") -> str:
    if not items:
        return f'<p class="muted">{_esc(empty)}</p>'
    tag = "ol" if ordered else "ul"
    inner = "".join(f"<li>{_esc(item)}</li>" for item in items)
    return f"<{tag}>{inner}</{tag}>"


def _section(title: str, body: str, page_break: bool) -> str:
    css = "sec pb" if page_break else "sec"
    return f'<section class="{css}"><h2>{_esc(title)}</h2>{body}</section>'


def _addr_html(addr: AddressInfo) -> str:
    name = _esc(addr.display_name)
    address = _esc(addr.address)
    if name and address:
        return f"{name} &lt;<code>{address}</code>&gt;"
    if address:
        return f"<code>{address}</code>"
    return name or _DASH


def _recipients(addrs: list[AddressInfo]) -> str:
    shown = [_addr_html(addr) for addr in addrs[:5]]
    if not shown:
        return _DASH
    text = "<br>".join(shown)
    extra = len(addrs) - len(shown)
    if extra > 0:
        text += f'<br><span class="muted">and {extra} more</span>'
    return text


def _geo_flags(geo: GeoInfo) -> list[str]:
    flags: list[str] = []
    if geo.is_tor_exit:
        flags.append(_badge("tor exit", "sev-critical"))
    if geo.is_proxy:
        flags.append(_badge("proxy/vpn", "sev-medium"))
    if geo.is_hosting:
        flags.append(_badge("hosting", "sev-medium"))
    if geo.is_mobile:
        flags.append(_badge("mobile", "neutral"))
    if geo.blacklists:
        flags.append(_badge(f"dnsbl x{len(geo.blacklists)}", "sev-high"))
    if geo.abuse_confidence is not None and geo.abuse_confidence >= 50:
        flags.append(_badge(f"abuse {geo.abuse_confidence}", "sev-high"))
    return flags


def _geo_cell(geo: Optional[GeoInfo]) -> str:
    if geo is None:
        return _DASH
    if geo.is_private:
        return '<span class="muted">private network</span>'
    bits: list[str] = []
    place = _place(geo)
    if place:
        bits.append(_esc(place))
    provider = geo.isp or geo.org
    if provider:
        bits.append(_esc(provider))
    if geo.asn:
        bits.append(_mono(geo.asn))
    flags = _geo_flags(geo)
    if flags:
        bits.append(" ".join(flags))
    if not bits:
        return f'<span class="muted">{_esc(geo.source or "unavailable")}</span>'
    return "<br>".join(bits)


# --------------------------------------------------------------------------- #
# HTML sections
# --------------------------------------------------------------------------- #
def _cover(report: ForensicReport, result: AnalysisResult) -> str:
    verdict = result.verdict
    severity = _val(verdict.severity)
    subject = _esc(_clean(result.email.subject) or "(no subject)")
    masking = (
        "Applied &mdash; personal identifiers are redacted in this copy"
        if report.masked
        else "Not applied &mdash; this copy contains personal data"
    )
    meta = _kv(
        [
            ("Report ID", _mono(report.report_id)),
            ("Generated", _cell(_fmt_dt(report.generated_at))),
            ("Generated by", _cell(report.generated_by)),
            ("Case / e-mail ID", _mono(result.id)),
            ("Source file", _cell(result.filename)),
            ("Analysed", f"{_cell(_fmt_dt(result.analyzed_at))} by MailTrace engine {_esc(result.engine_version)}"),
            ("PII masking", masking),
        ]
    )
    gauge = _bar(float(verdict.risk_score), "neutral", f"{verdict.risk_score} / 100")
    box = (
        f'<div class="verdict-box sev-{_esc(severity)}"><div class="verdict-cat">{_esc(verdict.category)}</div>'
        f'<div class="verdict-meta">Risk score {verdict.risk_score}/100 &middot; {_esc(severity)} severity '
        f"&middot; confidence {_esc(_pct(verdict.confidence))}</div>{gauge}</div>"
    )
    return (
        '<header class="cover"><p class="brand"><strong>MailTrace</strong> &middot; '
        "Forensic e-mail analysis report</p>"
        '<p class="classification">Confidential &middot; forensic evidence &middot; authorised investigators only</p>'
        f"<h1>{subject}</h1>{box}{meta}</header>"
    )


def _summary_section(report: ForensicReport) -> str:
    paragraphs = [line.strip() for line in report.executive_summary.split("\n") if line.strip()]
    if not paragraphs:
        return '<p class="muted">No summary available.</p>'
    return "".join(f"<p>{_esc(line)}</p>" for line in paragraphs)


def _verdict_section(result: AnalysisResult) -> str:
    verdict = result.verdict
    breakdown = verdict.breakdown
    agreement = _badge("agree", "ok") if verdict.dual_validation_agreement else _badge("disagree", "bad")
    stance = "agree" if verdict.dual_validation_agreement else "disagree"
    risk = float(verdict.risk_score)
    model = _esc(result.nlp.ml_model or "unavailable")
    overview = _kv(
        [
            ("Final category", f"<strong>{_esc(verdict.category)}</strong>"),
            ("Risk score", _bar(risk, f"sev-{_sev_for_score(risk)}", f"{verdict.risk_score} / 100")),
            ("Severity", _sev_badge(verdict.severity)),
            ("Confidence", _esc(_pct(verdict.confidence))),
            ("Rule engine", _esc(verdict.rule_category)),
            ("ML classifier", f'{_esc(verdict.ml_category)} <span class="muted">({model})</span>'),
            ("Dual validation", f"{agreement} rule engine and ML classifier {stance}"),
        ]
    )
    rows: list[list[str]] = []
    components = (
        ("authentication", breakdown.authentication),
        ("content", breakdown.content),
        ("links", breakdown.links),
        ("infrastructure", breakdown.infrastructure),
        ("anomaly", breakdown.anomaly),
    )
    for name, score in components:
        weight = breakdown.weights.get(name)
        rows.append(
            [
                _esc(name.capitalize()),
                _bar(score, f"sev-{_sev_for_score(score)}", f"{score:.0f}"),
                _cell(f"{weight:.2f}" if weight is not None else ""),
                _cell(f"{score * weight:.1f}" if weight is not None else ""),
            ]
        )
    table = _table(["Component", "Score (0-100)", "Weight", "Weighted contribution"], rows, "")
    rationale = _list(verdict.rationale, empty="No rationale recorded.")
    return overview + "<h3>Risk breakdown</h3>" + table + "<h3>Rationale</h3>" + rationale


def _evidence_section(result: AnalysisResult, custody: CustodyChain) -> str:
    email = result.email
    status = _badge("valid", "ok") if custody.valid else _badge("invalid", "bad")
    integrity = _kv(
        [
            ("SHA-256 of original message", _mono(email.raw_sha256)),
            ("MD5 of original message", _mono(email.raw_md5)),
            ("Size", _esc(f"{email.raw_size:,} bytes ({_fmt_size(email.raw_size)})")),
            ("Analysed at", _cell(_fmt_dt(result.analyzed_at))),
            ("Engine version", _esc(result.engine_version)),
            ("Custody ledger", f"{status} {_esc(_plural(len(custody.events), 'recorded event'))}"),
            ("Ledger head hash", _mono(custody.head_hash)),
        ]
    )
    rows = [
        [
            _esc(event.seq),
            _cell(_fmt_dt(event.timestamp)),
            _cell(event.actor),
            _cell(event.action),
            _mono(json.dumps(event.detail, sort_keys=True, default=str)) if event.detail else _DASH,
            _mono(event.evidence_sha256),
            _mono(event.prev_hash),
            _mono(event.hash),
        ]
        for event in custody.events
    ]
    table = _table(
        ["#", "Timestamp", "Actor", "Action", "Detail", "Evidence SHA-256", "Previous hash", "Entry hash"],
        rows,
        "No custody events have been recorded for this exhibit.",
    )
    return integrity + "<h3>Chain of custody</h3>" + table


def _identity_section(result: AnalysisResult) -> str:
    email = result.email
    hdr = result.headers
    auth = hdr.auth
    identity = _kv(
        [
            ("From", _addr_html(email.sender)),
            ("Sender domain", _mono(email.sender.domain)),
            ("Reply-To", "<br>".join(_addr_html(addr) for addr in email.reply_to) or _DASH),
            ("Return-Path (envelope sender)", _addr_html(email.return_path)),
            ("To", _recipients(email.to)),
            ("Cc", _recipients(email.cc)),
            ("Date header", _cell(_fmt_dt(email.date))),
            ("Message-ID", _mono(email.message_id)),
            ("Mailer", _cell(email.mailer)),
        ]
    )
    checks = _table(
        ["Check", "Status", "Detail"],
        [
            [
                "Display-name impersonation",
                _flag(hdr.display_name_spoof),
                _cell(f"imitates {hdr.display_name_brand}" if hdr.display_name_brand else ""),
            ],
            [
                "Reply-To domain mismatch",
                _flag(hdr.reply_to_mismatch),
                _cell_list([addr.address for addr in email.reply_to if addr.address]),
            ],
            ["Return-Path domain mismatch", _flag(hdr.return_path_mismatch), _cell(email.return_path.address)],
            ["Message-ID domain mismatch", _flag(hdr.message_id_mismatch), _cell(hdr.message_id_domain)],
            ["Header anomalies", _flag(bool(hdr.anomalies)), _cell_list([_human(item) for item in hdr.anomalies])],
        ],
        "",
    )
    dkim_parts: list[str] = []
    if auth.dkim_domain:
        dkim_parts.append(f"d={auth.dkim_domain}")
    if auth.dkim_selector:
        dkim_parts.append(f"s={auth.dkim_selector}")
    dkim_detail = " ".join(dkim_parts)
    auth_table = _table(
        ["Mechanism", "Result", "Domain / detail", "Alignment with From", "Source"],
        [
            [
                "SPF",
                _auth_badge(auth.spf),
                _cell(auth.spf_domain),
                _esc(_tri(auth.spf_aligned, "aligned", "not aligned")),
                _cell(auth.spf_source),
            ],
            [
                "DKIM",
                _auth_badge(auth.dkim),
                _cell(dkim_detail),
                _esc(_tri(auth.dkim_aligned, "aligned", "not aligned")),
                _cell(auth.dkim_source),
            ],
            [
                "DMARC",
                _auth_badge(auth.dmarc),
                _cell(f"policy: {auth.dmarc_policy}" if auth.dmarc_policy else ""),
                _DASH,
                _cell(auth.dmarc_source),
            ],
        ],
        "",
    )
    notes = _list(auth.notes, empty="No additional authentication notes.")
    return (
        identity
        + "<h3>Forged-field checks</h3>"
        + checks
        + "<h3>Authentication (SPF / DKIM / DMARC)</h3>"
        + auth_table
        + notes
    )


def _routing_section(result: AnalysisResult) -> str:
    hdr = result.headers
    rows: list[list[str]] = []
    for hop in sorted(hdr.hops, key=lambda item: item.index):
        is_origin = hdr.originating_hop_index is not None and hop.index == hdr.originating_hop_index
        notes: list[str] = []
        if is_origin:
            notes.append(_badge("origin", "sev-high"))
        if hop.is_private_ip:
            notes.append(_badge("private ip", "neutral"))
        if hop.is_internal:
            notes.append(_badge("internal", "neutral"))
        notes.extend(_badge(_human(anomaly), "sev-medium") for anomaly in hop.anomalies)
        from_bits = [_esc(hop.from_host)]
        if hop.from_ip:
            from_bits.append(_mono(hop.from_ip))
        by_bits = [_esc(hop.by_host)]
        if hop.hop_id:
            by_bits.append(f'<span class="muted">id {_esc(hop.hop_id)}</span>')
        rows.append(
            [
                _esc(hop.index),
                _cell(_fmt_dt(hop.timestamp)),
                "<br>".join(bit for bit in from_bits if bit) or _DASH,
                "<br>".join(bit for bit in by_bits if bit) or _DASH,
                _cell(hop.protocol),
                _cell(_fmt_delay(hop.delay_seconds)),
                _geo_cell(hop.geo),
                " ".join(notes) or _DASH,
            ]
        )
    table = _table(
        ["#", "Timestamp", "From (host / IP)", "Received by", "Protocol", "Delay", "Location / provider", "Notes"],
        rows,
        "No Received headers were present; the routing path cannot be reconstructed.",
    )
    origin = _kv(
        [
            ("Originating IP", _mono(hdr.originating_ip)),
            ("Origin hop", _cell(hdr.originating_hop_index)),
            ("Origin confidence", _esc(_pct(hdr.origin_confidence))),
            ("Reasoning", _cell(hdr.origin_reasoning)),
            ("X-Originating-IP header", _mono(hdr.x_originating_ip)),
            ("Routing anomaly score", _esc(f"{hdr.score:.2f}")),
        ]
    )
    return table + "<h3>Origin determination</h3>" + origin


def _infra_section(result: AnalysisResult) -> str:
    infra = result.infrastructure
    geo = infra.origin_geo
    if geo is None:
        origin = '<p class="muted">No origin geolocation is available for this message.</p>'
    else:
        country = geo.country
        if geo.country_code:
            country = f"{country} ({geo.country_code})".strip()
        coords = f"{geo.lat:.4f}, {geo.lon:.4f}" if geo.lat is not None and geo.lon is not None else ""
        abuse = f"{geo.abuse_confidence}/100" if geo.abuse_confidence is not None else ""
        kinds: list[str] = []
        if geo.is_private:
            kinds.append("private address")
        if geo.is_tor_exit:
            kinds.append("Tor exit node")
        if geo.is_proxy:
            kinds.append("proxy / VPN")
        if geo.is_hosting:
            kinds.append("hosting / data centre")
        if geo.is_mobile:
            kinds.append("mobile network")
        origin = _kv(
            [
                ("IP address", _mono(geo.ip)),
                ("Country", _cell(country)),
                ("Region / city", _cell(", ".join(part for part in (geo.region, geo.city) if part))),
                ("Coordinates (lat, lon)", _cell(coords)),
                ("ISP", _cell(geo.isp)),
                ("Organisation", _cell(geo.org)),
                ("ASN", _cell(geo.asn)),
                ("Reverse DNS", _mono(geo.reverse_dns)),
                ("Network classification", _cell_list(kinds) if kinds else "no special classification"),
                ("DNSBL listings", _cell_list(geo.blacklists)),
                ("AbuseIPDB confidence", _cell(abuse)),
                ("Data source", _cell(geo.source)),
            ]
        )
    botnet = _cell_list(infra.botnet_indicators) if infra.botnet_indicators else _badge("clear", "ok")
    flags = _table(
        ["Indicator", "Status"],
        [
            ["Tor exit node", _flag(infra.tor_exit)],
            ["VPN / proxy", _flag(infra.vpn_or_proxy)],
            ["Hosting / cloud provider", _flag(infra.hosting_provider)],
            ["Blocklisted IP", _flag(infra.blacklisted)],
            ["Open relay suspected", _flag(infra.open_relay_suspected)],
            ["Botnet indicators", botnet],
            ["Infrastructure score", _esc(f"{infra.score:.2f}")],
        ],
        "",
    )
    return "<h3>Origin geolocation</h3>" + origin + "<h3>Infrastructure indicators</h3>" + flags


def _domains_section(result: AnalysisResult) -> str:
    rows: list[list[str]] = []
    for intel in result.domains:
        registration: list[str] = []
        if intel.registrar:
            registration.append(intel.registrar)
        if intel.created is not None:
            registration.append(f"created {_fmt_date(intel.created)}")
        if intel.age_days is not None:
            registration.append(f"age {_plural(intel.age_days, 'day')}")
        if intel.expires is not None:
            registration.append(f"expires {_fmt_date(intel.expires)}")
        if intel.registrant_country:
            registration.append(f"registrant country {intel.registrant_country}")
        dns = [f"resolves: {_yes_no(intel.resolves)}", f"MX: {_yes_no(intel.has_mx)}"]
        if intel.mx:
            dns.append("MX hosts: " + _short_list(intel.mx, 2))
        if intel.a_records:
            dns.append("A: " + _short_list(intel.a_records, 3))
        if intel.name_servers:
            dns.append("NS: " + _short_list(intel.name_servers, 2))
        dns.append(f"SPF record: {'present' if intel.spf_record else 'absent'}")
        dns.append(f"DMARC record: {'present' if intel.dmarc_record else 'absent'}")
        tags: list[str] = []
        if intel.is_free_mail:
            tags.append(_badge("free-mail", "neutral"))
        if intel.is_disposable:
            tags.append(_badge("disposable", "sev-high"))
        if intel.lookalike_of:
            technique = f" ({_human(intel.lookalike_technique)})" if intel.lookalike_technique else ""
            tags.append(_badge(f"look-alike of {intel.lookalike_of}{technique}", "sev-critical"))
        rows.append(
            [
                _mono(intel.domain),
                _cell(_human(intel.role)),
                "<br>".join(_esc(item) for item in registration) or _DASH,
                "<br>".join(_esc(item) for item in dns),
                " ".join(tags) or _DASH,
                _cell_list(intel.reputation),
                _cell(intel.hosting_fingerprint),
                _cell(intel.source),
            ]
        )
    return _table(
        ["Domain", "Role", "Registration", "DNS", "Classification", "Reputation", "Hosting", "Source"],
        rows,
        "No domains were available for intelligence lookup.",
    )


def _links_section(result: AnalysisResult) -> str:
    analysis = result.urls
    rows: list[list[str]] = []
    for index, url in enumerate(analysis.urls, 1):
        tags: list[str] = []
        if url.anchor_mismatch:
            tags.append(_badge("anchor mismatch", "sev-high"))
        if url.is_ip_literal:
            tags.append(_badge("ip literal", "sev-high"))
        if url.is_shortener:
            tags.append(_badge("shortener", "sev-medium"))
        if url.is_punycode:
            tags.append(_badge("punycode", "sev-high"))
        if url.has_userinfo:
            tags.append(_badge("userinfo trick", "sev-high"))
        if url.lookalike_of:
            tags.append(_badge(f"look-alike of {url.lookalike_of}", "sev-critical"))
        tags.extend(_badge(_human(item), "neutral") for item in url.obfuscation)
        if url.suspicious_keywords:
            tags.append(f'<span class="muted">keywords: {_cell_list(url.suspicious_keywords)}</span>')
        host = _mono(url.host)
        if url.registrable_domain and url.registrable_domain != url.host:
            host += f'<br><span class="muted">{_esc(url.registrable_domain)}</span>'
        rows.append(
            [
                _esc(index),
                _mono(url.url),
                host,
                _cell(url.anchor_text),
                _sev_badge(url.risk),
                " ".join(tags) or _DASH,
                _cell_list(url.reasons),
            ]
        )
    summary = _kv(
        [
            ("Links found", _esc(len(analysis.urls))),
            ("Unique registrable domains", _cell_list(analysis.unique_domains)),
            ("Link risk score", _esc(f"{analysis.score:.2f}")),
        ]
    )
    return summary + _table(
        ["#", "URL", "Host", "Anchor text", "Risk", "Indicators", "Reasons"],
        rows,
        "The message contains no links.",
    )


def _attachments_section(result: AnalysisResult) -> str:
    analysis = result.attachments
    rows: list[list[str]] = []
    for index, item in enumerate(analysis.attachments, 1):
        tags: list[str] = []
        if item.mime_mismatch:
            tags.append(_badge("type mismatch", "sev-high"))
        if item.double_extension:
            tags.append(_badge("double extension", "sev-high"))
        if item.has_macros:
            tags.append(_badge("macros", "sev-high"))
        if item.is_archive:
            tags.append(_badge("archive", "neutral"))
        declared = _cell(item.content_type)
        if item.extension:
            declared += f'<br><span class="muted">.{_esc(item.extension)}</span>'
        rows.append(
            [
                _esc(index),
                _cell(item.filename),
                declared,
                _esc(_fmt_size(item.size)),
                _cell(item.magic_type),
                f"SHA-256 {_mono(item.sha256)}<br>MD5 {_mono(item.md5)}",
                " ".join(tags) or _DASH,
                _sev_badge(item.risk),
                _cell_list(item.reasons),
            ]
        )
    summary = _kv(
        [
            ("Attachments", _esc(len(analysis.attachments))),
            ("Attachment risk score", _esc(f"{analysis.score:.2f}")),
        ]
    )
    return summary + _table(
        ["#", "File", "Declared type", "Size", "Magic", "Hashes", "Indicators", "Risk", "Reasons"],
        rows,
        "The message carries no attachments.",
    )


def _content_section(result: AnalysisResult) -> str:
    nlp = result.nlp
    urgency = nlp.urgency_score * 100
    overview = _kv(
        [
            ("Language", _cell(nlp.language)),
            ("Word count", _esc(nlp.word_count)),
            ("Urgency score", _bar(urgency, f"sev-{_sev_for_score(urgency)}", f"{nlp.urgency_score:.2f}")),
            ("Urgency phrases", _cell_list(nlp.urgency_phrases)),
            ("Social-engineering cues", _cell_list([_human(cue) for cue in nlp.social_engineering_cues])),
            ("Financial terms", _cell_list(nlp.financial_terms)),
            ("Credential terms", _cell_list(nlp.credential_terms)),
            ("Threat terms", _cell_list(nlp.threat_terms)),
            ("Generic greeting", _esc(_yes_no(nlp.generic_greeting))),
            ("Asks to reply rather than click", _esc(_yes_no(nlp.requests_reply_not_click))),
            ("Content score", _esc(f"{nlp.score:.2f}")),
        ]
    )
    patterns = sorted(nlp.bec_patterns, key=lambda item: item.confidence, reverse=True)
    bec_rows = [
        [
            _esc(_human(item.pattern)),
            _bar(item.confidence * 100, f"sev-{_sev_for_score(item.confidence * 100)}", _pct(item.confidence)),
            _cell_list(item.evidence),
        ]
        for item in patterns
    ]
    bec = _table(
        ["Pattern", "Confidence", "Evidence"],
        bec_rows,
        "No business-e-mail-compromise patterns were detected.",
    )
    probabilities = sorted(nlp.ml_probabilities.items(), key=lambda item: item[1], reverse=True)
    prob_rows = [[_esc(label), _bar(prob * 100, "neutral", _pct(prob))] for label, prob in probabilities]
    ml = _kv(
        [
            ("Model", _cell(nlp.ml_model)),
            ("Predicted class", _esc(nlp.ml_category)),
            ("Most influential terms", _cell_list(nlp.ml_top_terms)),
        ]
    ) + _table(["Class", "Probability"], prob_rows, "No class probabilities are available (model unavailable).")
    return overview + "<h3>BEC patterns</h3>" + bec + "<h3>Machine-learning classification</h3>" + ml


def _intel_section(report: ForensicReport, result: AnalysisResult) -> str:
    intel = result.intel
    ioc_rows: list[list[str]] = []
    for item in report.key_indicators:
        kind, sep, value = item.partition(": ")
        if sep:
            ioc_rows.append([_esc(_human(kind)), _mono(value)])
        else:
            ioc_rows.append([_DASH, _mono(item)])
    iocs = _table(["Type", "Value"], ioc_rows, "No indicators of compromise were extracted.")
    blacklists = "<br>".join(
        f"{_mono(ip)}: {_cell_list(zones)}" for ip, zones in intel.ip_blacklists.items() if zones
    ) or _DASH
    reputation = "<br>".join(
        f"{_mono(domain)}: {_cell_list(feeds)}" for domain, feeds in intel.domain_reputation.items() if feeds
    ) or _DASH
    overview = _kv(
        [
            ("Campaign", _mono(result.campaign_id or intel.campaign_id)),
            ("Correlation indicators", "<br>".join(_mono(item) for item in intel.indicators) or _DASH),
            ("IP blocklist hits", blacklists),
            ("Domain reputation hits", reputation),
            ("Tor exit nodes", _cell_list(intel.tor_exits)),
        ]
    )
    related_rows = [
        [
            _mono(incident.email_id),
            _cell(incident.subject),
            _cell(incident.sender),
            _esc(incident.category),
            _esc(incident.risk_score),
            _cell_list(incident.shared_indicators),
        ]
        for incident in intel.related_incidents
    ]
    related = _table(
        ["E-mail ID", "Subject", "Sender", "Category", "Risk", "Shared indicators"],
        related_rows,
        "No related incidents were found in the case database.",
    )
    return (
        "<h3>Key indicators of compromise</h3>"
        + iocs
        + "<h3>Correlation</h3>"
        + overview
        + "<h3>Related incidents</h3>"
        + related
    )


def _attribution_section(result: AnalysisResult) -> str:
    attribution = result.attribution
    label = _SOURCE_LABELS.get(attribution.source_type, "")
    source = f"<strong>{_esc(_human(attribution.source_type))}</strong>"
    if label:
        source += f" &mdash; {_esc(label)}"
    indicators = "<br>".join(_mono(item) for item in attribution.indicators)
    return _kv(
        [
            ("Assessed source type", source),
            ("Confidence", _bar(attribution.confidence * 100, "neutral", _pct(attribution.confidence))),
            ("Reasoning", _list(attribution.reasoning, empty="No reasoning recorded.")),
            ("Actor infrastructure indicators", indicators or _DASH),
        ]
    )


def _graph_section(result: AnalysisResult) -> str:
    graph = result.graph
    degree: dict[str, int] = {}
    for edge in graph.edges:
        degree[edge.source] = degree.get(edge.source, 0) + 1
        degree[edge.target] = degree.get(edge.target, 0) + 1
    by_type: dict[str, int] = {}
    for node in graph.nodes:
        by_type[node.type] = by_type.get(node.type, 0) + 1
    pivots = [node for node in graph.nodes if node.type not in ("email", "campaign")]
    pivots.sort(key=lambda node: (-_sev_rank(node.risk), -degree.get(node.id, 0), node.id))
    kinds = ", ".join(f"{_esc(kind)}: {count}" for kind, count in sorted(by_type.items()))
    overview = _kv(
        [
            ("Nodes", _esc(len(graph.nodes))),
            ("Edges", _esc(len(graph.edges))),
            ("Nodes by type", kinds or _DASH),
        ]
    )
    rows = [
        [_mono(node.id), _esc(node.type), _cell(node.label), _sev_badge(node.risk), _esc(degree.get(node.id, 0))]
        for node in pivots[:8]
    ]
    table = _table(
        ["Node", "Type", "Label", "Risk", "Connections"],
        rows,
        "The relationship graph contains no entities beyond the message itself.",
    )
    return overview + "<h3>Top pivot entities</h3>" + table


def _findings_section(result: AnalysisResult) -> str:
    findings = sorted(result.findings, key=lambda item: -_sev_rank(item.severity))
    rows = [
        [_sev_badge(item.severity), _cell(item.module), _cell(item.title), _cell(item.detail)]
        for item in findings
    ]
    return _table(["Severity", "Module", "Finding", "Detail"], rows, "No findings were recorded.")


def _appendix_section(result: AnalysisResult) -> str:
    email = result.email
    lines = "\n".join(f"{_esc(field.name)}: {_esc(field.value)}" for field in email.headers)
    if lines:
        headers = f"<pre>{lines}</pre>"
    else:
        headers = '<p class="muted">No headers were recovered from the message.</p>'
    issues = _list(
        email.charset_issues,
        empty="No character-set problems were noted while decoding the message.",
    )
    return "<h3>Full header block</h3>" + headers + "<h3>Decoding notes</h3>" + issues


def _footer(report: ForensicReport) -> str:
    return (
        f'<p class="footer">Report {_esc(report.report_id)} generated {_esc(_fmt_dt(report.generated_at))} '
        f"by MailTrace engine {_esc(report.analysis.engine_version)} for {_esc(report.generated_by)}. "
        "Automated analysis &mdash; see the legal notes.</p>"
    )


def render_html(report: ForensicReport) -> str:
    """Render the report as one self-contained, printable HTML document (no scripts, no external assets)."""
    result = report.analysis
    sections: list[tuple[str, str, bool]] = [
        ("Executive summary", _summary_section(report), False),
        ("Verdict and dual validation", _verdict_section(result), True),
        ("Evidence integrity and chain of custody", _evidence_section(result, report.custody), False),
        ("Sender identity and authentication", _identity_section(result), True),
        ("Routing trace", _routing_section(result), False),
        ("Origin and infrastructure", _infra_section(result), True),
        ("Domain intelligence", _domains_section(result), False),
        ("Links", _links_section(result), True),
        ("Attachments", _attachments_section(result), False),
        ("Content analysis", _content_section(result), True),
        ("Threat intelligence and campaign correlation", _intel_section(report, result), True),
        ("Attribution assessment", _attribution_section(result), False),
        ("Relationship summary", _graph_section(result), False),
        (
            "Recommended actions",
            _list(report.recommended_actions, ordered=True, empty="No specific actions recommended."),
            True,
        ),
        ("Legal notes", _list(report.legal_notes, ordered=True), False),
        ("All findings", _findings_section(result), True),
        ("Appendix: full message headers", _appendix_section(result), True),
    ]
    body = "".join(
        _section(f"{number}. {title}", content, page_break)
        for number, (title, content, page_break) in enumerate(sections, 1)
    )
    return (
        "<!DOCTYPE html>\n"
        '<html lang="en">\n'
        "<head>\n"
        '<meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
        f"<title>{_esc(report.report_id)} - MailTrace forensic report</title>\n"
        f"<style>{_CSS}</style>\n"
        "</head>\n"
        "<body>\n"
        '<div class="page">\n'
        f"{_cover(report, result)}\n{body}\n{_footer(report)}\n"
        "</div>\n"
        "</body>\n"
        "</html>\n"
    )
