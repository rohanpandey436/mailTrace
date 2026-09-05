"""
MailTrace data contracts.

Every analyzer produces Findings and a typed sub-report; the pipeline fuses them
into an AnalysisResult which is the single persisted/served artefact.  Reports,
graphs and campaign views are all projections of AnalysisResult.

Conventions
-----------
* All scores inside sub-reports are floats in [0, 1].  Only Verdict/RiskBreakdown
  use the 0-100 analyst scale.
* Findings carry their own evidence so the UI and the forensic report never need
  to re-derive anything.
* Datetimes are timezone-aware UTC where known, else None.
"""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Literal, TypedDict

from pydantic import BaseModel, ConfigDict, Field

ENGINE_VERSION = "1.0.0"


# Enumerations
class ThreatCategory(str, Enum):
    LEGITIMATE = "Legitimate"
    SUSPICIOUS = "Suspicious"
    IMPERSONATED = "Impersonated"
    PHISHING = "Phishing"
    FRAUD = "Fraud-Related"


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


SEVERITY_ORDER: dict[str, int] = {
    Severity.INFO.value: 0,
    Severity.LOW.value: 1,
    Severity.MEDIUM.value: 2,
    Severity.HIGH.value: 3,
    Severity.CRITICAL.value: 4,
}

BecPatternName = Literal[
    "payment_diversion",
    "fake_invoice",
    "credential_harvesting",
    "executive_impersonation",
]

SourceType = Literal[
    "spoofed_domain",
    "lookalike_domain",
    "compromised_account",
    "direct_attacker_infrastructure",
    "legitimate_sender",
    "undetermined",
]

NodeType = Literal["email", "address", "domain", "ip", "asn", "url", "attachment", "campaign"]

# Stage 6 quick-bar: the analyst's decision on a case.  This is a MailTrace
# bookkeeping state and nothing more - see ``app/api/analyze.py`` - it does not
# mean a mail gateway quarantined or blocked anything.
CaseStatus = Literal["open", "quarantined", "blocked"]
CASE_STATUSES: tuple[CaseStatus, ...] = ("open", "quarantined", "blocked")


# Building blocks
class Finding(BaseModel):
    """One evidence-backed observation produced by any analyzer."""

    id: str = Field(description="Stable slug, e.g. 'spf_fail', 'reply_to_mismatch'")
    module: str = Field(description="headers|auth|urls|attachments|nlp|domains|geoip|scoring|intel")
    severity: Severity
    title: str
    detail: str
    evidence: dict[str, object] = Field(default_factory=dict)


class AddressInfo(BaseModel):
    raw: str = ""
    display_name: str = ""
    address: str = ""
    local_part: str = ""
    domain: str = ""


class HeaderField(BaseModel):
    name: str
    value: str


class AttachmentMeta(BaseModel):
    filename: str
    content_type: str = ""
    size: int = 0
    sha256: str = ""
    md5: str = ""
    extension: str = ""
    magic_type: str = Field(default="", description="Type sniffed from magic bytes, e.g. 'pe', 'zip', 'pdf'")
    mime_mismatch: bool = False
    is_archive: bool = False
    has_macros: bool = False
    double_extension: bool = False
    shannon_entropy: float = Field(
        default=0.0, ge=0.0, le=8.0,
        description="Shannon entropy of the file bytes in bits/byte (8.0 = uniformly random)",
    )
    high_entropy: bool = Field(
        default=False,
        description="Entropy above Settings.entropy_threshold (default 7.0): packed, encrypted or obfuscated",
    )
    risk: Severity = Severity.INFO
    reasons: list[str] = Field(default_factory=list)


class FuzzyDigest(BaseModel):
    """Locality-sensitive digests of the message body.

    Unlike SHA-256, these stay close when the text is only slightly edited, so
    a campaign that rewrites a few words per victim still clusters together.
    """

    simhash: str = Field(default="", description="64-bit Charikar SimHash over body shingles, hex")
    tlsh: str = Field(default="", description="TLSH digest when the py-tlsh package is installed and the body is long enough")
    body_length: int = 0


class ParsedEmail(BaseModel):
    """Output of the parser: structure only, no analysis."""

    message_id: str = ""
    subject: str = ""
    date: datetime | None = None
    sender: AddressInfo = Field(default_factory=AddressInfo, description="RFC5322 From")
    reply_to: list[AddressInfo] = Field(default_factory=list)
    return_path: AddressInfo = Field(default_factory=AddressInfo, description="Envelope sender")
    to: list[AddressInfo] = Field(default_factory=list)
    cc: list[AddressInfo] = Field(default_factory=list)
    headers: list[HeaderField] = Field(default_factory=list, description="All headers, original order, duplicates kept")
    text_body: str = ""
    html_body: str = ""
    has_html: bool = False
    attachments: list[AttachmentMeta] = Field(default_factory=list)
    raw_sha256: str = ""
    raw_md5: str = ""
    raw_size: int = 0
    mailer: str = Field(default="", description="X-Mailer / User-Agent if present")
    charset_issues: list[str] = Field(default_factory=list)
    parse_ms: float = Field(default=0.0, description="Stage 1-2 wall-clock parse time in milliseconds")
    fuzzy: FuzzyDigest = Field(default_factory=FuzzyDigest, description="SimHash / TLSH digests used for campaign clustering")


# Header / protocol analysis
class GeoInfo(BaseModel):
    ip: str
    country: str = ""
    country_code: str = ""
    region: str = ""
    city: str = ""
    lat: float | None = None
    lon: float | None = None
    isp: str = ""
    org: str = ""
    asn: str = ""
    reverse_dns: str = ""
    is_private: bool = False
    is_proxy: bool = False
    is_hosting: bool = False
    is_mobile: bool = False
    is_tor_exit: bool = False
    blacklists: list[str] = Field(default_factory=list, description="DNSBL zones that list this IP")
    abuse_confidence: int | None = Field(default=None, description="AbuseIPDB 0-100 if configured")
    source: str = Field(default="", description="ip-api|cache|private|offline|unavailable")


class Hop(BaseModel):
    index: int = Field(description="0 = earliest (origin), chronological order")
    raw: str
    from_host: str = ""
    from_ip: str = ""
    by_host: str = ""
    protocol: str = ""
    hop_id: str = ""
    timestamp: datetime | None = None
    delay_seconds: float | None = Field(default=None, description="Seconds since previous hop; negative = clock anomaly")
    is_private_ip: bool = False
    is_internal: bool = Field(default=False, description="Belongs to recipient org / trusted relay")
    anomalies: list[str] = Field(default_factory=list)
    geo: GeoInfo | None = None


class AuthResult(BaseModel):
    spf: str = Field(default="none", description="pass|fail|softfail|neutral|none|temperror|permerror|unverifiable")
    spf_domain: str = ""
    spf_source: str = Field(default="none", description="authentication-results|live|none")
    dkim: str = "none"
    dkim_domain: str = ""
    dkim_selector: str = ""
    dkim_source: str = "none"
    dmarc: str = Field(default="none", description="pass|fail|none")
    dmarc_policy: str = Field(default="", description="none|quarantine|reject or ''")
    dmarc_source: str = "none"
    spf_aligned: bool | None = None
    dkim_aligned: bool | None = None
    notes: list[str] = Field(default_factory=list)


class HeaderAnalysis(BaseModel):
    hops: list[Hop] = Field(default_factory=list)
    originating_ip: str = ""
    originating_hop_index: int | None = None
    origin_confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    origin_reasoning: str = ""
    x_originating_ip: str = ""
    message_id_domain: str = ""
    message_id_mismatch: bool = False
    return_path_mismatch: bool = False
    reply_to_mismatch: bool = False
    display_name_spoof: bool = False
    display_name_brand: str = Field(default="", description="Brand/executive the display name imitates, if any")
    auth: AuthResult = Field(default_factory=AuthResult)
    anomalies: list[str] = Field(default_factory=list)
    score: float = Field(default=0.0, ge=0.0, le=1.0, description="Header/routing anomaly score")
    findings: list[Finding] = Field(default_factory=list)


# Content analysis
class UrlInfo(BaseModel):
    url: str
    normalized: str = ""
    scheme: str = ""
    host: str = ""
    registrable_domain: str = ""
    tld: str = ""
    path: str = ""
    anchor_text: str = ""
    anchor_mismatch: bool = False
    is_ip_literal: bool = False
    is_shortener: bool = False
    is_punycode: bool = False
    has_userinfo: bool = Field(default=False, description="'@' trick in authority")
    obfuscation: list[str] = Field(default_factory=list)
    suspicious_keywords: list[str] = Field(default_factory=list)
    lookalike_of: str = ""
    risk: Severity = Severity.INFO
    reasons: list[str] = Field(default_factory=list)


class UrlAnalysis(BaseModel):
    urls: list[UrlInfo] = Field(default_factory=list)
    unique_domains: list[str] = Field(default_factory=list)
    score: float = Field(default=0.0, ge=0.0, le=1.0)
    findings: list[Finding] = Field(default_factory=list)


class AttachmentAnalysis(BaseModel):
    attachments: list[AttachmentMeta] = Field(default_factory=list)
    score: float = Field(default=0.0, ge=0.0, le=1.0)
    findings: list[Finding] = Field(default_factory=list)


class BecPattern(BaseModel):
    pattern: BecPatternName
    confidence: float = Field(ge=0.0, le=1.0)
    evidence: list[str] = Field(default_factory=list)


class ShapWeight(BaseModel):
    """One token's signed contribution to the predicted class.

    For the linear classifier these are exact SHAP values,
    ``phi_i = coef_i * (x_i - E[x_i])``, where the expectation is the mean
    feature value over the training corpus. Positive pushes toward the
    predicted class, negative pushes away from it.
    """

    token: str
    weight: float = Field(description="SHAP value in log-odds units; sign carries the direction")


class LimeWeight(BaseModel):
    """One token's coefficient in the LIME local surrogate.

    Not a SHAP value and not in the same units: this is the slope of a weighted
    ridge regression fitted to the classifier's *probability* for the predicted
    class over a neighbourhood of messages with words randomly removed. It reads
    as "dropping this word moves p(class) by about this much". SHAP reads the
    model's coefficients exactly; LIME measures what the whole pipeline does
    when the input changes. Agreement between them is corroboration, not
    duplication.
    """

    token: str
    weight: float = Field(description="Local surrogate coefficient in probability units; sign carries the direction")


class LimeReport(BaseModel):
    """A case's LIME explanation, built on request rather than during ingest.

    ``available`` is False when LIME is switched off, when the transformer
    backend produced the verdict (its neighbourhood would be 160 forward
    passes), or when the surrogate could not be fitted.
    """

    email_id: str
    available: bool = False
    method: str = ""
    weights: list[LimeWeight] = Field(default_factory=list)
    fidelity: float = Field(default=0.0, description="Local R^2 of the surrogate against the real model")
    n_samples: int = 0
    n_features: int = 0
    category: ThreatCategory = ThreatCategory.LEGITIMATE
    agreement_with_shap: list[str] = Field(
        default_factory=list, description="Tokens this explanation shares with the exact SHAP list"
    )


class NlpAnalysis(BaseModel):
    language: str = "en"
    word_count: int = 0
    urgency_score: float = Field(default=0.0, ge=0.0, le=1.0)
    urgency_phrases: list[str] = Field(default_factory=list)
    social_engineering_cues: list[str] = Field(default_factory=list, description="authority|fear|scarcity|secrecy|reward|curiosity")
    financial_terms: list[str] = Field(default_factory=list)
    credential_terms: list[str] = Field(default_factory=list)
    threat_terms: list[str] = Field(default_factory=list)
    generic_greeting: bool = False
    requests_reply_not_click: bool = False
    ml_category: ThreatCategory = ThreatCategory.LEGITIMATE
    ml_probabilities: dict[str, float] = Field(default_factory=dict)
    ml_top_terms: list[str] = Field(default_factory=list, description="Most influential tokens for ml_category")
    shap_weights: list[ShapWeight] = Field(
        default_factory=list, description="Token-level SHAP attributions for ml_category, strongest first",
    )
    # Filled in by app/core/explanations.py on the report path; empty on a
    # freshly ingested case, which is what keeps ingest inside its budget.
    lime_weights: list[LimeWeight] = Field(
        default_factory=list,
        description="LIME local-surrogate coefficients for ml_category, strongest first; empty when LIME is off or unavailable",
    )
    lime_fidelity: float = Field(
        default=0.0,
        description="Weighted R^2 of the LIME surrogate against the real model in this neighbourhood; low means do not trust the LIME weights",
    )
    lime_method: str = Field(default="", description="Which LIME ran, e.g. 'lime-builtin'; empty when it did not run")
    ml_model: str = Field(default="", description="Backend that produced the verdict, e.g. 'distilroberta' or 'tfidf-logreg-1'")
    ml_backend: str = Field(default="", description="transformer | linear | unavailable")
    bec_patterns: list[BecPattern] = Field(default_factory=list)
    score: float = Field(default=0.0, ge=0.0, le=1.0)
    findings: list[Finding] = Field(default_factory=list)


# Domain / infrastructure intelligence
class DomainIntel(BaseModel):
    domain: str
    role: str = Field(default="", description="sender|reply_to|return_path|url|message_id")
    registrar: str = ""
    created: datetime | None = None
    expires: datetime | None = None
    age_days: int | None = None
    registrant_country: str = ""
    name_servers: list[str] = Field(default_factory=list)
    mx: list[str] = Field(default_factory=list)
    a_records: list[str] = Field(default_factory=list)
    spf_record: str = ""
    dmarc_record: str = ""
    has_mx: bool = False
    resolves: bool = False
    is_free_mail: bool = False
    is_disposable: bool = False
    lookalike_of: str = Field(default="", description="Brand or protected domain it imitates")
    lookalike_technique: str = Field(default="", description="homoglyph|typosquat|tld_swap|subdomain_abuse|punycode|extra_token")
    hosting_fingerprint: str = Field(default="", description="ISP/org of A record")
    reputation: list[str] = Field(default_factory=list, description="Feeds that flag this domain")
    source: str = Field(default="", description="live|cache|offline")
    findings: list[Finding] = Field(default_factory=list)


class InfraAnalysis(BaseModel):
    origin_geo: GeoInfo | None = None
    tor_exit: bool = False
    vpn_or_proxy: bool = False
    hosting_provider: bool = False
    blacklisted: bool = False
    open_relay_suspected: bool = False
    botnet_indicators: list[str] = Field(default_factory=list)
    score: float = Field(default=0.0, ge=0.0, le=1.0)
    findings: list[Finding] = Field(default_factory=list)


# Correlation, attribution, graph
class RelatedIncident(BaseModel):
    email_id: str
    subject: str = ""
    sender: str = ""
    risk_score: int = 0
    category: ThreatCategory = ThreatCategory.LEGITIMATE
    shared_indicators: list[str] = Field(default_factory=list)


class ThreatIntel(BaseModel):
    indicators: list[str] = Field(default_factory=list, description="Normalised IOC keys, e.g. 'ip:1.2.3.4'")
    ip_blacklists: dict[str, list[str]] = Field(default_factory=dict)
    domain_reputation: dict[str, list[str]] = Field(default_factory=dict)
    tor_exits: list[str] = Field(default_factory=list)
    related_incidents: list[RelatedIncident] = Field(default_factory=list)
    campaign_id: str | None = None
    findings: list[Finding] = Field(default_factory=list)


class Attribution(BaseModel):
    source_type: SourceType = "undetermined"
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    reasoning: list[str] = Field(default_factory=list)
    indicators: list[str] = Field(default_factory=list, description="Actor infrastructure indicators for investigators")


class GraphNode(BaseModel):
    id: str = Field(description="'<type>:<key>' e.g. 'ip:1.2.3.4'")
    type: NodeType
    label: str
    risk: Severity = Severity.INFO
    attrs: dict[str, object] = Field(default_factory=dict)


class GraphEdge(BaseModel):
    source: str
    target: str
    relation: str = Field(description="sent_by|reply_to|return_path|originated_from|relayed_via|hosted_on|links_to|contains|resolves_to|member_of|shares")
    weight: float = 1.0


class AttributionGraph(BaseModel):
    nodes: list[GraphNode] = Field(default_factory=list)
    edges: list[GraphEdge] = Field(default_factory=list)


# Verdict
class RiskBreakdown(BaseModel):
    """The five terms of the Stage 4 threat score, each 0-100 before weighting.

    THREAT SCORE = 0.20 Auth + 0.35 Text + 0.25 URL + 0.10 Network + 0.10 Entropy
    """

    auth: float = Field(ge=0, le=100, description="SPF, DKIM, DMARC, alignment and forged sender fields")
    text: float = Field(ge=0, le=100, description="NLP intent, BEC patterns and social-engineering language")
    url: float = Field(ge=0, le=100, description="Link risk, lookalike and deceptive domains")
    network: float = Field(ge=0, le=100, description="Origin infrastructure, VPN/TOR, routing anomalies, blocklists")
    entropy: float = Field(ge=0, le=100, description="Attachment Shannon entropy and file-level payload risk")
    weights: dict[str, float] = Field(default_factory=dict, description="Normalised weight applied to each term")


class Verdict(BaseModel):
    category: ThreatCategory
    confidence: float = Field(ge=0.0, le=1.0)
    risk_score: int = Field(ge=0, le=100)
    severity: Severity
    breakdown: RiskBreakdown
    ml_category: ThreatCategory
    rule_category: ThreatCategory
    dual_validation_agreement: bool
    rationale: list[str] = Field(default_factory=list)
    recommended_actions: list[str] = Field(default_factory=list)


# Chain of custody / alerts / campaigns
class CustodyEvent(BaseModel):
    seq: int
    timestamp: datetime
    actor: str
    action: str = Field(description="ingested|analyzed|viewed|viewed_unmasked|report_generated|exported")
    email_id: str
    detail: dict[str, object] = Field(default_factory=dict)
    evidence_sha256: str
    prev_hash: str
    hash: str


class CustodyChain(BaseModel):
    email_id: str
    events: list[CustodyEvent] = Field(default_factory=list)
    valid: bool = True
    head_hash: str = ""


class Alert(BaseModel):
    id: str
    created_at: datetime
    email_id: str
    subject: str = ""
    sender: str = ""
    category: ThreatCategory
    risk_score: int
    severity: Severity
    message: str = ""
    acknowledged: bool = False


class Campaign(BaseModel):
    id: str
    name: str
    created_at: datetime
    updated_at: datetime
    email_ids: list[str] = Field(default_factory=list)
    indicators: list[str] = Field(default_factory=list, description="Shared IOC keys that bind the members")
    max_risk: int = 0
    categories: dict[str, int] = Field(default_factory=dict)
    countries: list[str] = Field(default_factory=list)


# Top-level result
class AnalysisResult(BaseModel):
    model_config = ConfigDict(use_enum_values=False)

    id: str
    filename: str
    analyzed_at: datetime
    engine_version: str = ENGINE_VERSION
    processing_ms: int = 0
    masked: bool = Field(default=False, description="True when PII masking was applied to this representation")
    email: ParsedEmail
    headers: HeaderAnalysis
    urls: UrlAnalysis
    attachments: AttachmentAnalysis
    nlp: NlpAnalysis
    domains: list[DomainIntel] = Field(default_factory=list)
    infrastructure: InfraAnalysis
    intel: ThreatIntel
    attribution: Attribution
    graph: AttributionGraph
    verdict: Verdict
    findings: list[Finding] = Field(default_factory=list, description="All findings, sorted by severity desc")
    campaign_id: str | None = None


class CaseSummary(BaseModel):
    id: str
    filename: str
    subject: str = ""
    sender: str = ""
    sender_domain: str = ""
    category: ThreatCategory
    risk_score: int
    severity: Severity
    confidence: float = 0.0
    analyzed_at: datetime
    campaign_id: str | None = None
    originating_ip: str = ""
    origin_country: str = ""
    source_type: SourceType = "undetermined"
    spf: str = "none"
    dkim: str = "none"
    dmarc: str = "none"
    status: CaseStatus = Field(
        default="open",
        description="Analyst decision recorded in MailTrace; not the state of any mail system",
    )


class CaseDecision(BaseModel):
    """The analyst decision currently recorded against a case.

    ``enforced`` is always False: MailTrace records and exports decisions, it
    does not actuate a mail gateway.  See ``POST /api/emails/{id}/quarantine``.
    """

    email_id: str
    status: CaseStatus = "open"
    enforced: bool = False
    indicators: list[str] = Field(default_factory=list, description="IOCs to hand to whatever does enforce")
    history: list[CustodyEvent] = Field(default_factory=list, description="Decision events from the custody ledger")


class Section65BCertificate(BaseModel):
    """Statement of the particulars required by Section 65B(4) of the Indian
    Evidence Act 1872 (carried forward as Section 63(4) of the Bharatiya Sakshya
    Adhiniyam 2023) for electronic records produced by a computer.

    The tool states the facts it can attest to. Clauses (a) to (d) still have to
    be signed by a person occupying a responsible official position in relation
    to the operation of the device; ``signatory_name`` and ``signatory_position``
    are left for that person to complete.
    """

    statement_of_record: str = Field(description="65B(4)(a) - what the electronic record is and how it was produced")
    computer_description: str = Field(description="65B(4)(b) - the computer that produced it and its regular use")
    operation_period: str = Field(description="65B(4)(c) - the period of regular operation and any lapse")
    integrity_statement: str = Field(description="65B(4)(d) - how the contents were derived and preserved unaltered")
    evidence_sha256: str = Field(description="SHA-256 of the original message as received")
    evidence_md5: str = ""
    custody_head_hash: str = Field(default="", description="Head of the hash-linked custody ledger at generation time")
    custody_chain_valid: bool = True
    custody_event_count: int = 0
    tool_name: str = "MailTrace"
    tool_version: str = ENGINE_VERSION
    generated_at: datetime
    signatory_name: str = Field(default="", description="To be completed by the responsible official")
    signatory_position: str = Field(default="", description="To be completed by the responsible official")
    declaration: str = Field(
        default=(
            "The contents of this electronic record and the accompanying analysis were produced by the computer "
            "described above during its regular use. The original message was hashed on receipt and has not been "
            "altered; every subsequent action is recorded in the hash-linked custody ledger reproduced in this report."
        ),
    )


class EvidenceIntegrity(TypedDict):
    """The hashes and ledger state a report attests to."""

    raw_sha256: str
    raw_md5: str
    raw_size: int
    custody_head_hash: str
    custody_valid: bool
    custody_events: int
    engine_version: str
    analyzed_at: str


class TimelineEntry(TypedDict, total=False):
    """One row of a report's chronological timeline: a delivery hop or a custody event."""

    kind: str
    sequence: int
    timestamp: str | None
    summary: str
    # Delivery hop
    from_host: str
    from_ip: str
    by_host: str
    protocol: str
    delay_seconds: float | None
    location: str
    provider: str
    is_origin: bool
    is_private_ip: bool
    is_internal: bool
    anomalies: list[str]
    # Custody event
    actor: str
    action: str
    detail: dict[str, object]
    hash: str


class ForensicReport(BaseModel):
    report_id: str
    generated_at: datetime
    generated_by: str = "system"
    masked: bool = False
    section_65b: Section65BCertificate | None = Field(
        default=None, description="Section 65B(4) / BSA 63(4) certificate particulars",
    )
    executive_summary: str
    key_indicators: list[str] = Field(default_factory=list)
    evidence_integrity: EvidenceIntegrity = Field(description="raw hashes, custody head hash, chain validity")
    timeline: list[TimelineEntry] = Field(default_factory=list, description="Chronological hop / event timeline")
    recommended_actions: list[str] = Field(default_factory=list)
    legal_notes: list[str] = Field(default_factory=list)
    custody: CustodyChain
    analysis: AnalysisResult


class CountryCount(BaseModel):
    country: str
    count: int


class DashboardStats(BaseModel):
    total_emails: int = 0
    high_risk: int = 0
    campaigns: int = 0
    alerts_open: int = 0
    by_category: dict[str, int] = Field(default_factory=dict)
    top_countries: list[CountryCount] = Field(default_factory=list)
    top_source_types: dict[str, int] = Field(default_factory=dict)
    avg_risk: float = 0.0


class RawSubmission(BaseModel):
    raw: str = Field(description="Full RFC822 message text")
    filename: str = "pasted.eml"


# API response envelopes
class AnalyzeResponse(BaseModel):
    """``POST /api/analyze``: one result per message, plus any alerts they raised."""

    results: list[AnalysisResult]
    alerts: list[Alert] = Field(default_factory=list)


class CaseListResponse(BaseModel):
    items: list[CaseSummary]
    total: int


class CampaignDetail(BaseModel):
    campaign: Campaign
    emails: list[CaseSummary]
    graph: AttributionGraph


class CustodyVerification(BaseModel):
    valid: bool
    head_hash: str


class Acknowledged(BaseModel):
    ok: bool = True


class HealthStatus(BaseModel):
    status: str = "ok"
    engine_version: str = ENGINE_VERSION
    network: bool
    pii_mask_default: bool
    zero_persistence: bool
    webhooks: int
    database: str = Field(description="The store engine actually in use: sqlite or postgresql")
    database_note: str = Field(
        default="", description="Why the configured database is not the one in use; empty when it is"
    )
    url_model: str = Field(description="Which backend is serving the URL model: onnx, xgboost or not loaded")
    geoip_source: str = Field(
        description="Where geolocation comes from: a MaxMind database path, or ip-api.com"
    )
    native_engine: bool = Field(description="Whether the C++ dissector is doing the MIME work")
    native_engine_version: str
    native_engine_status: str
