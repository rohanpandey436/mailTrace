"""
Configurable PII masking.

What is masked: email addresses (local part), display names (initials),
phone numbers, Aadhaar numbers, PAN numbers and Luhn-valid card numbers.
What is deliberately kept: domains, IPs, URLs, hashes, message ids and
timestamps, because they are the investigative indicators.  Hex strings of
32+ characters (hashes, ids) are protected from every regex.

``mask_result`` returns a deep copy; the stored analysis is never altered.
"""
from __future__ import annotations

import hashlib
import re
from typing import Any

from ..schemas import AddressInfo, AnalysisResult, ForensicReport, GraphEdge, GraphNode, HeaderField

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-'=]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
PHONE_RE = re.compile(
    r"(?<![\w.\-/])(?:(?:\+91|0091|0)?[\s-]?[6-9]\d{4}[\s-]?\d{5}|\+\d{1,3}[\s-]?\d{2,4}[\s-]?\d{3,4}[\s-]?\d{3,4})(?!\w)"
)
AADHAAR_RE = re.compile(r"(?<![\d-])\d{4}[\s-]?\d{4}[\s-]?\d{4}(?![\d-])")
PAN_RE = re.compile(r"(?<![A-Z0-9])[A-Z]{5}[0-9]{4}[A-Z](?![A-Z0-9])")
CARD_RE = re.compile(r"(?<![\d-])(?:\d[ -]?){12,18}\d(?![\d-])")
HEX_RE = re.compile(r"([A-Fa-f0-9]{32,})")
_UNMASKED_HEADERS = {"message-id", "in-reply-to", "references", "x-google-smtp-source", "x-gm-message-state", "dkim-signature", "arc-seal", "arc-message-signature"}


def _luhn_ok(digits: str) -> bool:
    total = 0
    for index, char in enumerate(reversed(digits)):
        value = int(char)
        if index % 2 == 1:
            value *= 2
            if value > 9:
                value -= 9
        total += value
    return total % 10 == 0


def mask_email(addr: str) -> str:
    """'rohan.pandey@acme-corp.in' -> 'r***y@acme-corp.in'; domain is kept."""
    addr = addr or ""
    if "@" not in addr:
        return addr
    local, _, domain = addr.rpartition("@")
    if len(local) <= 1:
        masked = "*"
    elif len(local) == 2:
        masked = local[0] + "*"
    else:
        masked = f"{local[0]}***{local[-1]}"
    return f"{masked}@{domain}"


def mask_name(name: str) -> str:
    """'Rohan Pandey' -> 'R. P.'; keeps role/brand words in parentheses out."""
    name = (name or "").strip().strip('"')
    if not name:
        return ""
    words = [w for w in re.split(r"[\s,]+", name) if w and w[0].isalnum()]
    if not words:
        return "*"
    return " ".join(f"{w[0].upper()}." for w in words[:3])


def _mask_card(match: re.Match) -> str:
    raw = match.group(0)
    digits = re.sub(r"\D", "", raw)
    if 13 <= len(digits) <= 19 and _luhn_ok(digits):
        return "**** **** **** " + digits[-4:]
    return raw


def _mask_aadhaar(match: re.Match) -> str:
    digits = re.sub(r"\D", "", match.group(0))
    return f"XXXX-XXXX-{digits[-4:]}"


def _mask_phone(match: re.Match) -> str:
    digits = re.sub(r"\D", "", match.group(0))
    return f"+**-*****-**{digits[-2:]}" if len(digits) >= 2 else "**"


def _mask_segment(text: str) -> str:
    text = EMAIL_RE.sub(lambda m: mask_email(m.group(0)), text)
    text = CARD_RE.sub(_mask_card, text)
    text = AADHAAR_RE.sub(_mask_aadhaar, text)
    text = PAN_RE.sub(lambda m: m.group(0)[0] + "****####*", text)
    text = PHONE_RE.sub(_mask_phone, text)
    return text


def mask_text(text: Any) -> Any:
    """Mask PII in a string; non-strings are returned untouched."""
    if not isinstance(text, str) or not text:
        return text
    # Protect long hex tokens (hashes, ids) from the digit-based patterns.
    pieces = HEX_RE.split(text)
    return "".join(piece if index % 2 else _mask_segment(piece) for index, piece in enumerate(pieces))


def mask_any(value: Any) -> Any:
    """Recursively mask every string inside dicts/lists/tuples."""
    if isinstance(value, str):
        return mask_text(value)
    if isinstance(value, dict):
        return {key: mask_any(item) for key, item in value.items()}
    if isinstance(value, list):
        return [mask_any(item) for item in value]
    if isinstance(value, tuple):
        return tuple(mask_any(item) for item in value)
    return value


def mask_address(address: AddressInfo) -> AddressInfo:
    masked_addr = mask_email(address.address)
    masked_name = mask_name(address.display_name)
    local_part = masked_addr.rpartition("@")[0] if "@" in masked_addr else mask_text(address.local_part)
    raw = f"{masked_name} <{masked_addr}>".strip() if masked_name else masked_addr
    return AddressInfo(raw=raw, display_name=masked_name, address=masked_addr, local_part=local_part, domain=address.domain)


def _mask_findings(findings: list) -> None:
    for finding in findings:
        finding.title = mask_text(finding.title)
        finding.detail = mask_text(finding.detail)
        finding.evidence = mask_any(finding.evidence)


def _address_node_id(node_id: str) -> str:
    key = node_id.split(":", 1)[1] if ":" in node_id else node_id
    return "address:" + hashlib.sha1(key.encode("utf-8", errors="replace")).hexdigest()[:10]


def mask_result(result: AnalysisResult) -> AnalysisResult:
    """Deep-copied, PII-masked view of an analysis (``masked=True``)."""
    masked = result.model_copy(deep=True)
    email = masked.email
    email.sender = mask_address(email.sender)
    email.reply_to = [mask_address(a) for a in email.reply_to]
    email.return_path = mask_address(email.return_path)
    email.to = [mask_address(a) for a in email.to]
    email.cc = [mask_address(a) for a in email.cc]
    email.subject = mask_text(email.subject)
    email.text_body = mask_text(email.text_body)
    email.html_body = mask_text(email.html_body)
    email.headers = [
        HeaderField(name=h.name, value=h.value if h.name.lower() in _UNMASKED_HEADERS else mask_text(h.value))
        for h in email.headers
    ]

    for hop in masked.headers.hops:
        hop.raw = mask_text(hop.raw)
    masked.headers.origin_reasoning = mask_text(masked.headers.origin_reasoning)
    masked.headers.auth.notes = [mask_text(n) for n in masked.headers.auth.notes]

    _mask_findings(masked.headers.findings)
    _mask_findings(masked.urls.findings)
    _mask_findings(masked.attachments.findings)
    _mask_findings(masked.nlp.findings)
    for domain in masked.domains:
        _mask_findings(domain.findings)
    _mask_findings(masked.infrastructure.findings)
    _mask_findings(masked.intel.findings)
    _mask_findings(masked.findings)

    for url in masked.urls.urls:
        url.anchor_text = mask_text(url.anchor_text)
    for pattern in masked.nlp.bec_patterns:
        pattern.evidence = [mask_text(e) for e in pattern.evidence]
    masked.nlp.urgency_phrases = [mask_text(p) for p in masked.nlp.urgency_phrases]
    # LIME's interpretable features are raw words split straight out of this
    # message, so unlike the SHAP tokens (which can only come from the fitted
    # corpus vocabulary) they can carry a phone number or an account number
    # lifted verbatim from the body. Mask them.
    for weight in masked.nlp.lime_weights:
        weight.token = mask_text(weight.token)

    masked.verdict.rationale = [mask_text(r) for r in masked.verdict.rationale]
    masked.verdict.recommended_actions = [mask_text(a) for a in masked.verdict.recommended_actions]
    masked.attribution.reasoning = [mask_text(r) for r in masked.attribution.reasoning]
    masked.attribution.indicators = [mask_text(i) for i in masked.attribution.indicators]
    masked.intel.indicators = [mask_text(i) for i in masked.intel.indicators]
    for incident in masked.intel.related_incidents:
        incident.subject = mask_text(incident.subject)
        incident.sender = mask_email(incident.sender)
        incident.shared_indicators = [mask_text(s) for s in incident.shared_indicators]

    id_map: dict[str, str] = {}
    nodes: list[GraphNode] = []
    for node in masked.graph.nodes:
        if node.type == "address":
            new_id = _address_node_id(node.id)
            id_map[node.id] = new_id
            node.id = new_id
            node.label = mask_email(node.label) if "@" in node.label else mask_text(node.label)
        else:
            node.label = mask_text(node.label)
        node.attrs = mask_any(node.attrs)
        nodes.append(node)
    masked.graph.nodes = nodes
    masked.graph.edges = [
        GraphEdge(source=id_map.get(e.source, e.source), target=id_map.get(e.target, e.target), relation=e.relation, weight=e.weight)
        for e in masked.graph.edges
    ]
    masked.masked = True
    return masked


def mask_report_fields(report: ForensicReport) -> ForensicReport:
    """Mask the report-level prose; the embedded analysis must already be masked."""
    masked = report.model_copy(deep=True)
    masked.executive_summary = mask_text(masked.executive_summary)
    masked.key_indicators = [mask_text(i) for i in masked.key_indicators]
    masked.timeline = mask_any(masked.timeline)
    masked.recommended_actions = [mask_text(a) for a in masked.recommended_actions]
    masked.legal_notes = [mask_text(n) for n in masked.legal_notes]
    masked.evidence_integrity = mask_any(masked.evidence_integrity)
    masked.masked = True
    return masked
