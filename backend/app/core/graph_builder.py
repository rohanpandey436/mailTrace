"""
Relationship graph for one analysed email and for a whole campaign.

Approach
--------
``build_graph`` projects an analysis into a small typed graph whose node ids are
stable IOC keys (``ip:1.2.3.4``, ``domain:paypa1.com``, ``attachment:<sha256>``),
so graphs of different emails can be overlaid: after ``merge_graphs`` every node
carrying ``shared_by >= 2`` is a pivot point that binds several messages.

* Node ids are always ``"<type>:<key>"`` with a normalised key (lower-case
  address / host / domain, lower-case hash hex, raw IP literal).
* Node risk comes from the analyzer that judged the entity: the verdict for the
  email, ``UrlInfo.risk`` / ``AttachmentMeta.risk`` for links and files, the
  domain's own findings for domains (CRITICAL override for lookalike,
  newly-registered and blocklisted domains), geo and threat-intel flags for IPs
  (Tor / blocklisted = CRITICAL, proxy / hosting = MEDIUM) and, for addresses,
  the header/auth findings that concern that address role, never lower than the
  address's own domain.
* Nodes are deduplicated by id and edges by (source, target, relation).

``merge_graphs`` unions member graphs (highest risk per node, blank attributes
filled from later members), counts the members that contain each node and, when
a Campaign is given, links every email node to the ``campaign:<id>`` node.

Pure and offline: no I/O, deterministic for identical input, tolerant of empty
sub-reports (no hops, no links, no attachments, no geo enrichment).
"""
from __future__ import annotations

import logging
from typing import Any, Iterable

from ..schemas import (
    SEVERITY_ORDER,
    AttachmentAnalysis,
    AttributionGraph,
    Campaign,
    DomainIntel,
    GeoInfo,
    GraphEdge,
    GraphNode,
    HeaderAnalysis,
    Hop,
    InfraAnalysis,
    NodeType,
    ParsedEmail,
    Severity,
    ThreatIntel,
    UrlAnalysis,
    UrlInfo,
    Verdict,
)
from .link_analyzer import registrable_domain
from .scoring import severity_for

log = logging.getLogger("mailtrace.graph")

LABEL_MAX = 60
NEWLY_REGISTERED_DAYS = 30
ABUSE_CONFIDENCE_CRITICAL = 50

# Address role -> relation of the edge from the email node.
_ROLE_RELATION: dict[str, str] = {"sender": "sent_by", "reply_to": "reply_to", "return_path": "return_path"}
# Address role -> header/auth finding ids whose severity flags that address.
_ROLE_FINDINGS: dict[str, tuple[str, ...]] = {
    "sender": ("display_name_spoof", "executive_impersonation_display", "spf_fail", "spf_softfail", "dkim_fail", "dmarc_fail"),
    "reply_to": ("reply_to_mismatch",),
    "return_path": ("return_path_mismatch", "spf_fail", "spf_softfail"),
}


# --------------------------------------------------------------------------- #
# Small pure helpers
# --------------------------------------------------------------------------- #
def _name(severity: Any) -> str:
    """Plain severity string from an enum or a string."""
    return str(getattr(severity, "value", severity))


def _rank(severity: Any) -> int:
    return SEVERITY_ORDER.get(_name(severity), 0)


def _max_severity(severities: Iterable[Any], floor: Severity = Severity.INFO) -> Severity:
    """Highest severity among ``severities``, never below ``floor``."""
    best: Any = floor
    for severity in severities:
        if _rank(severity) > _rank(best):
            best = severity
    return Severity(_name(best))


def _short(text: str, limit: int = LABEL_MAX) -> str:
    text = " ".join((text or "").split())
    return text if len(text) <= limit else text[: limit - 3] + "..."


def _unique(items: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        if item and item not in seen:
            seen.add(item)
            out.append(item)
    return out


def _blank(value: Any) -> bool:
    return value in (None, "", [], {})


def _registrable(host: str) -> str:
    host = (host or "").strip().lower().rstrip(".")
    if not host:
        return ""
    return (registrable_domain(host) or host).lower()


# --------------------------------------------------------------------------- #
# Builder: the single place where nodes and edges are deduplicated
# --------------------------------------------------------------------------- #
class _GraphBuilder:
    """Accumulates nodes keyed by id and edges keyed by (source, target, relation)."""

    def __init__(self) -> None:
        self.nodes: dict[str, GraphNode] = {}
        self.edges: dict[tuple[str, str, str], GraphEdge] = {}

    def add(self, node: GraphNode) -> str:
        """Insert ``node`` or merge it into the node with the same id: the
        higher risk wins and blank attributes are filled from the newcomer."""
        existing = self.nodes.get(node.id)
        if existing is None:
            self.nodes[node.id] = node
            return node.id
        if _rank(node.risk) > _rank(existing.risk):
            existing.risk = node.risk
        for key, value in node.attrs.items():
            if _blank(existing.attrs.get(key)):
                existing.attrs[key] = value
        return existing.id

    def node(
        self, node_type: NodeType, key: str, label: str, risk: Severity, attrs: dict[str, Any] | None = None
    ) -> str:
        return self.add(
            GraphNode(id=f"{node_type}:{key}", type=node_type, label=_short(label) or key, risk=risk, attrs=dict(attrs or {}))
        )

    def edge(self, source: str, target: str, relation: str, weight: float = 1.0) -> None:
        key = (source, target, relation)
        if key not in self.edges:
            self.edges[key] = GraphEdge(source=source, target=target, relation=relation, weight=weight)

    def build(self) -> AttributionGraph:
        return AttributionGraph(nodes=list(self.nodes.values()), edges=list(self.edges.values()))


# --------------------------------------------------------------------------- #
# Per-entity risk and attributes
# --------------------------------------------------------------------------- #
def _url_domain(url: UrlInfo) -> str:
    """Registrable domain behind a link; IP-literal hosts have none."""
    if url.is_ip_literal:
        return ""
    return _registrable(url.registrable_domain or url.host)


def _domain_risk(info: DomainIntel | None, url_risk: Severity) -> Severity:
    """Contract override first (lookalike / newly registered / blocklisted are
    CRITICAL), otherwise the worst domain finding, never below the risk of the
    links that point at the domain."""
    if info is None:
        return url_risk
    newly = info.age_days is not None and info.age_days < NEWLY_REGISTERED_DAYS and not info.is_free_mail
    if info.lookalike_of or info.reputation or newly:
        return Severity.CRITICAL
    return _max_severity((f.severity for f in info.findings), url_risk)


def _domain_attrs(info: DomainIntel | None) -> dict[str, Any]:
    if info is None:
        return {}
    return {
        "age_days": info.age_days,
        "lookalike_of": info.lookalike_of,
        "reputation": list(info.reputation),
        "is_free_mail": info.is_free_mail,
    }


def _ip_profile(
    ip: str,
    geo: GeoInfo | None,
    hop_index: int | None,
    is_origin: bool,
    infra: InfraAnalysis,
    intel: ThreatIntel,
) -> tuple[Severity, dict[str, Any]]:
    """Risk and attributes of one public IP from its geo record, the threat
    intel tables and (for the origin) the infrastructure flags."""
    blacklists = _unique([*(geo.blacklists if geo is not None else []), *intel.ip_blacklists.get(ip, [])])
    tor = bool(geo is not None and geo.is_tor_exit) or ip in intel.tor_exits or (is_origin and infra.tor_exit)
    abusive = geo is not None and geo.abuse_confidence is not None and geo.abuse_confidence >= ABUSE_CONFIDENCE_CRITICAL
    anonymised = bool(geo is not None and (geo.is_proxy or geo.is_hosting)) or (
        is_origin and (infra.vpn_or_proxy or infra.hosting_provider)
    )
    if tor or blacklists or abusive or (is_origin and infra.blacklisted):
        risk = Severity.CRITICAL
    elif anonymised:
        risk = Severity.MEDIUM
    else:
        risk = Severity.INFO
    attrs: dict[str, Any] = {
        "hop_index": hop_index,
        "is_origin": is_origin,
        "city": geo.city if geo is not None else "",
        "country": (geo.country or geo.country_code) if geo is not None else "",
        "isp": (geo.isp or geo.org) if geo is not None else "",
        "tor": tor,
        "blacklists": blacklists,
    }
    return risk, attrs


# --------------------------------------------------------------------------- #
# Entry points
# --------------------------------------------------------------------------- #
def build_graph(
    email_id: str,
    parsed: ParsedEmail,
    header_analysis: HeaderAnalysis,
    url_analysis: UrlAnalysis,
    att_analysis: AttachmentAnalysis,
    domain_intel: list[DomainIntel],
    infra: InfraAnalysis,
    intel: ThreatIntel,
    verdict: Verdict,
) -> AttributionGraph:
    """Project one analysis into an AttributionGraph (see module docstring)."""
    builder = _GraphBuilder()
    intel_by_domain = {d.domain.strip().lower(): d for d in (domain_intel or []) if d.domain}
    email_node = builder.node(
        "email",
        email_id,
        parsed.subject or "(no subject)",
        verdict.severity,
        {"risk_score": verdict.risk_score, "category": verdict.category.value},
    )

    # Links: one node per host; a host's domain inherits the worst link on it.
    host_urls: dict[str, list[UrlInfo]] = {}
    for url in url_analysis.urls:
        host = url.host.strip().lower().rstrip(".")
        if host:
            host_urls.setdefault(host, []).append(url)
    host_domain = {host: _url_domain(urls[0]) for host, urls in host_urls.items()}
    url_domain_risk: dict[str, Severity] = {}
    for host, urls in host_urls.items():
        domain = host_domain[host]
        if domain:
            url_domain_risk[domain] = _max_severity((u.risk for u in urls), url_domain_risk.get(domain, Severity.INFO))

    # Addresses: sender / reply-to / return-path, one node per mailbox with its role list.
    address_roles: dict[str, list[str]] = {}
    address_domain: dict[str, str] = {}
    labelled = [("sender", parsed.sender), *(("reply_to", r) for r in parsed.reply_to), ("return_path", parsed.return_path)]
    for role, mailbox in labelled:
        address = mailbox.address.strip().lower()
        if not address:
            continue
        roles = address_roles.setdefault(address, [])
        if role not in roles:
            roles.append(role)
        fallback_domain = address.rpartition("@")[2] if "@" in address else ""
        address_domain.setdefault(address, _registrable(mailbox.domain or fallback_domain))

    # Domains: every address domain and every link domain.
    domain_ids: dict[str, str] = {}
    for domain in _unique([*address_domain.values(), *host_domain.values()]):
        info = intel_by_domain.get(domain)
        risk = _domain_risk(info, url_domain_risk.get(domain, Severity.INFO))
        domain_ids[domain] = builder.node("domain", domain, domain, risk, _domain_attrs(info))

    for address, roles in address_roles.items():
        domain = address_domain[address]
        floor = builder.nodes[domain_ids[domain]].risk if domain else Severity.INFO
        flagged = {finding_id for role in roles for finding_id in _ROLE_FINDINGS[role]}
        risk = _max_severity((f.severity for f in header_analysis.findings if f.id in flagged), floor)
        address_node = builder.node("address", address, address, risk, {"roles": list(roles)})
        for role in roles:
            builder.edge(email_node, address_node, _ROLE_RELATION[role])
        if domain:
            builder.edge(address_node, domain_ids[domain], "resolves_to")

    for host, urls in host_urls.items():
        risk = _max_severity(u.risk for u in urls)
        url_node = builder.node("url", host, host, risk, {"count": len(urls), "risk": _name(risk)})
        builder.edge(email_node, url_node, "links_to")
        if host_domain[host]:
            builder.edge(url_node, domain_ids[host_domain[host]], "resolves_to")

    # Routing: the origin first, then every public relay; ASN nodes hang off the IPs.
    origin_ip = header_analysis.originating_ip.strip()
    hop_by_ip: dict[str, Hop] = {}
    for hop in header_analysis.hops:
        ip = hop.from_ip.strip()
        if ip and not hop.is_private_ip:
            hop_by_ip.setdefault(ip, hop)
    ip_ids: dict[str, str] = {}
    for ip in _unique([origin_ip, *hop_by_ip]):
        relay = hop_by_ip.get(ip)
        is_origin = ip == origin_ip
        geo = infra.origin_geo if is_origin else None
        if geo is None and relay is not None:
            geo = relay.geo
        hop_index = relay.index if relay is not None else header_analysis.originating_hop_index
        risk, attrs = _ip_profile(ip, geo, hop_index, is_origin, infra, intel)
        ip_node = builder.node("ip", ip, ip, risk, attrs)
        ip_ids[ip] = ip_node
        if is_origin:
            builder.edge(email_node, ip_node, "originated_from")
        elif relay is not None:
            builder.edge(email_node, ip_node, "relayed_via", float(relay.index))
        asn = geo.asn.strip() if geo is not None else ""
        if asn:
            builder.edge(ip_node, builder.node("asn", asn, asn, Severity.INFO), "hosted_on")

    # Attachments keyed by content hash so identical payloads collapse across emails.
    for att in att_analysis.attachments:
        key = (att.sha256 or att.md5 or att.filename).strip().lower()
        if not key:
            continue
        att_node = builder.node(
            "attachment", key, att.filename or key, att.risk, {"size": att.size, "magic": att.magic_type, "risk": _name(att.risk)}
        )
        builder.edge(email_node, att_node, "contains")

    # Domain -> IP for A records that already appear as routing nodes.
    for domain, domain_node in domain_ids.items():
        info = intel_by_domain.get(domain)
        if info is None:
            continue
        for record in info.a_records:
            resolved = ip_ids.get(record.strip())
            if resolved is not None:
                builder.edge(domain_node, resolved, "resolves_to")

    graph = builder.build()
    log.debug("graph %s: %d nodes, %d edges", email_id, len(graph.nodes), len(graph.edges))
    return graph


def merge_graphs(graphs: list[AttributionGraph], campaign: Campaign | None = None) -> AttributionGraph:
    """Union of member graphs; nodes present in two or more members carry
    ``shared_by`` (the campaign's pivot points) and, when ``campaign`` is
    given, every email node is linked ``member_of`` the campaign node."""
    builder = _GraphBuilder()
    members: dict[str, int] = {}
    for graph in graphs:
        for node in graph.nodes:
            builder.add(node.model_copy(deep=True))
        for node_id in dict.fromkeys(node.id for node in graph.nodes):
            members[node_id] = members.get(node_id, 0) + 1
        for edge in graph.edges:
            builder.edge(edge.source, edge.target, edge.relation, edge.weight)
    for node_id, count in members.items():
        if count >= 2:
            builder.nodes[node_id].attrs["shared_by"] = count
    if campaign is not None:
        campaign_node = builder.node(
            "campaign",
            campaign.id,
            campaign.name or campaign.id,
            severity_for(campaign.max_risk),
            {"max_risk": campaign.max_risk, "members": len(campaign.email_ids)},
        )
        for node in builder.nodes.values():
            if node.type == "email":
                builder.edge(node.id, campaign_node, "member_of")
    merged = builder.build()
    log.debug("merged %d graphs: %d nodes, %d edges", len(graphs), len(merged.nodes), len(merged.edges))
    return merged
