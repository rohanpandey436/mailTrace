"""
Analysis pipeline.

Orchestrates every analyzer in a fixed order and fuses their output into one
AnalysisResult.  The pipeline is synchronous (the web layer runs it in a
thread pool); network-bound enrichment runs concurrently inside it and is
fault-tolerant: an enrichment failure degrades the result, it never aborts
the analysis.

Order of operations
-------------------
1. parse            -> ParsedEmail + raw attachment bytes
2. headers          -> Received chain, origin IP, forged-field checks
3. auth             -> SPF / DKIM / DMARC (Authentication-Results + live)
4. urls             -> link extraction, needed by two of the three engines
5. the three intelligence engines, concurrently:
     3A  attachments + nlp   (entropy, intent, ML classification, SHAP)
     3B  geoip               (origin trace, VPN/TOR, hop timing)
     3C  domains             (WHOIS age, DNS/MX, lookalikes, reputation)
6. threat_intel.correlate        (threat-intel + prior-incident correlation)
7. scoring          -> verdict, attribution, merged findings
8. graph            -> relationship graph
9. persist, cluster into campaign, chain-of-custody events
"""
from __future__ import annotations

import logging
import time
import uuid
from concurrent.futures import Future, ThreadPoolExecutor
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from ..config import Settings
from ..config import settings as default_settings
from ..schemas import ENGINE_VERSION, AnalysisResult, AttachmentAnalysis, DomainIntel, InfraAnalysis, NlpAnalysis

if TYPE_CHECKING:  # pragma: no cover
    from ..database.case_manager import Store

log = logging.getLogger("mailtrace.pipeline")


def new_email_id() -> str:
    return uuid.uuid4().hex[:12]


def _safe_result[T](fut: Future[T], default: T, name: str) -> T:
    try:
        return fut.result()
    except Exception:  # enrichment must never abort analysis
        log.exception("enrichment stage '%s' failed; continuing with defaults", name)
        return default


def analyze_bytes(
    raw: bytes,
    filename: str,
    store: Store | None = None,
    cfg: Settings | None = None,
    actor: str = "system",
) -> AnalysisResult:
    """Run the full analysis on one RFC 822 message.

    ``store`` may be None (pure analysis, nothing persisted, no campaign
    correlation).  ``actor`` is recorded in the chain of custody.
    """
    from ..utils import virustotal
    from . import (
        ai_engine,
        auth_checker,
        domain_intel,
        file_analyzer,
        geoip_mapper,
        graph_builder,
        header_analyzer,
        link_analyzer,
        parser,
        scoring,
        threat_intel,
    )

    cfg = cfg or default_settings
    t0 = time.perf_counter()
    email_id = new_email_id()

    # 1. Structure --------------------------------------------------------
    parsed, raw_attachments = parser.parse_email(raw)

    # 2. Header / routing analysis (offline) ------------------------------
    header_analysis = header_analyzer.analyze_headers(parsed, cfg)

    # 3. Authentication ---------------------------------------------------
    auth_result, auth_findings = auth_checker.evaluate_auth(parsed, header_analysis, cfg, raw)
    header_analysis.auth = auth_result
    header_analysis.findings.extend(auth_findings)

    # 4. Link extraction -------------------------------------------------
    # Cheap, offline, and a prerequisite of two of the three engines below:
    # the AI core scores the lure links, and the domain engine enriches the
    # hosts they point at.
    url_analysis = link_analyzer.analyze_urls(parsed, cfg)
    domain_targets = domain_intel.collect_domains(parsed, header_analysis, url_analysis, cfg)

    def run_ai_core() -> tuple[AttachmentAnalysis, NlpAnalysis]:
        """Engine 3A: attachment inspection (including Shannon entropy) and the
        NLP/ML intent analysis that consumes it.

        The optional VirusTotal hash lookup runs last, so a network stall can
        only delay the attachment findings and never the NLP verdict.  With no
        ``MAILTRACE_VIRUSTOTAL_KEY`` configured it returns without making a
        request, which is the deployed default.
        """
        atts = file_analyzer.analyze_attachments(raw_attachments, cfg)
        content = ai_engine.analyze_content(parsed, url_analysis, atts, cfg)
        virustotal.enrich(atts, raw_attachments, cfg, store)
        return atts, content

    # 5. The three intelligence engines, genuinely in parallel ------------
    # 3A is CPU-bound (vectorising and classifying) while 3B and 3C are almost
    # entirely waiting on DNS, WHOIS and HTTP, so overlapping them turns the sum
    # of their times into roughly the slowest one. Each is isolated: a failure
    # degrades that engine's contribution and never aborts the analysis.
    with ThreadPoolExecutor(max_workers=3, thread_name_prefix="mt-engine") as pool:
        fut_ai = pool.submit(run_ai_core)          # 3A - AI core
        fut_infra = pool.submit(geoip_mapper.analyze_infrastructure, header_analysis, cfg, store)  # 3B - GeoIP/route
        fut_domains = pool.submit(domain_intel.analyze_domains, domain_targets, cfg, store)      # 3C - domain intel
        att_analysis, nlp_analysis = _safe_result(fut_ai, (AttachmentAnalysis(), NlpAnalysis()), "ai_core")
        infra = _safe_result(fut_infra, InfraAnalysis(), "geoip")
        domain_results: list[DomainIntel] = _safe_result(fut_domains, [], "domains")

    # 6. Threat-intel / prior-incident correlation ------------------------
    # cfg is passed explicitly so the fuzzy-matching thresholds come from this
    # analysis's settings rather than the module-level singleton.
    intel = threat_intel.correlate(
        email_id, parsed, header_analysis, url_analysis, att_analysis, domain_results, infra, store, cfg
    )

    # 7. Fusion -----------------------------------------------------------
    verdict, attribution, all_findings = scoring.evaluate(
        parsed, header_analysis, url_analysis, att_analysis, nlp_analysis, domain_results, infra, intel, cfg
    )

    # 8. Relationship graph -----------------------------------------------
    relationship_graph = graph_builder.build_graph(
        email_id, parsed, header_analysis, url_analysis, att_analysis, domain_results, infra, intel, verdict
    )

    result = AnalysisResult(
        id=email_id,
        filename=filename,
        analyzed_at=datetime.now(UTC),
        engine_version=ENGINE_VERSION,
        processing_ms=int((time.perf_counter() - t0) * 1000),
        email=parsed,
        headers=header_analysis,
        urls=url_analysis,
        attachments=att_analysis,
        nlp=nlp_analysis,
        domains=domain_results,
        infrastructure=infra,
        intel=intel,
        attribution=attribution,
        graph=relationship_graph,
        verdict=verdict,
        findings=all_findings,
    )

    # 9. Persistence, campaign clustering, custody ------------------------
    if store is not None:
        store.record_custody(
            email_id, actor, "ingested",
            {"filename": filename, "size": len(raw), "sha256": parsed.raw_sha256, "md5": parsed.raw_md5},
            parsed.raw_sha256,
        )
        campaign_id = threat_intel.assign_campaign(result, store, cfg)
        result.campaign_id = campaign_id
        result.intel.campaign_id = campaign_id
        result.processing_ms = int((time.perf_counter() - t0) * 1000)
        store.save_analysis(result, raw)
        store.record_custody(
            email_id, actor, "analyzed",
            {
                "category": result.verdict.category.value,
                "risk_score": result.verdict.risk_score,
                "confidence": result.verdict.confidence,
                "engine_version": ENGINE_VERSION,
                "campaign_id": campaign_id,
            },
            parsed.raw_sha256,
        )
    return result


def analyze_text(
    raw_text: str,
    filename: str = "pasted.eml",
    store: Store | None = None,
    cfg: Settings | None = None,
    actor: str = "system",
) -> AnalysisResult:
    return analyze_bytes(raw_text.encode("utf-8", errors="surrogateescape"), filename, store, cfg, actor)
