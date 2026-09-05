"""
LIME, computed when someone asks to see it.

LIME never changes a verdict.  It fits a local surrogate to explain a decision
the engine has already made, and it costs 26-130 ms per message - several times
the whole rest of the analysis.  Running it on the ingest path would push
Stage 1-5 from about 20 ms to well over 100 ms for an artefact most messages
are never opened to look at.

So it is built here instead: on request, and cached in the store, so the second
viewer of a case pays nothing.  ``attach`` puts it back into an ``AnalysisResult``
for the forensic report, where the explanation belongs in the record rather than
only on a screen.  Exact SHAP still runs on every message - it is a closed-form
read of the model's own coefficients and costs microseconds.
"""
from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from ..config import Settings
from ..schemas import AnalysisResult, Finding, LimeReport, LimeWeight, Severity
from ..utils.cache import cache_get, cache_set
from .ai_engine import model_input

if TYPE_CHECKING:  # pragma: no cover
    from ..database.case_manager import Store

log = logging.getLogger("mailtrace.explanations")

#: How many surrogate coefficients are carried on the report.
TOP_K = 12
#: Explanations are deterministic for a given message and model, so they never
#: need to expire; the ceiling only bounds the cache table.
CACHE_TTL_SECONDS = 30 * 24 * 3600


def _cache_key(email_id: str) -> str:
    return f"lime:{email_id}"


def _compute(result: AnalysisResult, cfg: Settings) -> LimeReport:
    """Fit the surrogate.  Returns an unavailable report rather than raising."""
    unavailable = LimeReport(email_id=result.id, category=result.nlp.ml_category)
    if not cfg.lime_enabled:
        return unavailable
    # Only the linear backend is supported: with a transformer the neighbourhood
    # would be 160 forward passes, which is minutes rather than milliseconds.
    if result.nlp.ml_backend != "linear":
        return unavailable
    try:
        from ..ai import lime_explainer, model_trainer
    except ImportError:  # pragma: no cover - both ship with the app
        log.debug("LIME is unavailable in this install", exc_info=True)
        return unavailable

    label = result.nlp.ml_category.value
    try:
        pipeline = model_trainer.load_or_train(cfg)
        explanation = lime_explainer.explain_pipeline(
            pipeline, model_input(result.email), label, n_samples=lime_explainer.resolve_samples(cfg), top_k=TOP_K
        )
    except ImportError as exc:
        log.warning("LIME needs the ML packages (%s); no explanation produced", exc)
        return unavailable
    except Exception:  # an explanation must never break a case view
        log.exception("LIME failed for email %s", result.id)
        return unavailable
    if not explanation:
        return unavailable

    shap_tokens = {weight.token for weight in result.nlp.shap_weights}
    weights = [LimeWeight(token=str(token), weight=round(float(value), 6)) for token, value in explanation.weights]
    return LimeReport(
        email_id=result.id,
        available=True,
        method=explanation.method,
        weights=weights,
        fidelity=round(float(explanation.local_r2), 4),
        n_samples=explanation.n_samples,
        n_features=explanation.n_features,
        category=result.nlp.ml_category,
        agreement_with_shap=[weight.token for weight in weights if weight.token in shap_tokens],
    )


def lime_report(result: AnalysisResult, cfg: Settings, store: Store | None = None) -> LimeReport:
    """The LIME explanation for a stored case, from the cache when it is there."""
    key = _cache_key(result.id)
    cached = cache_get(store, key)
    if isinstance(cached, dict):
        try:
            return LimeReport.model_validate(cached)
        except ValueError:  # an entry written by an older schema
            log.debug("discarding a malformed cached explanation for %s", result.id)
    report = _compute(result, cfg)
    if report.available:
        cache_set(store, key, report.model_dump(mode="json"), CACHE_TTL_SECONDS)
    return report


def finding(report: LimeReport) -> Finding:
    """The report's evidence entry.

    SHAP and LIME are independent: SHAP reads the linear model's coefficients
    exactly, LIME fits a fresh surrogate to what the whole pipeline does when
    words are removed.  Overlap between them is corroboration, so it is stated
    as a count rather than implied.
    """
    summary = ", ".join(f"{weight.token} {weight.weight:+.3f}" for weight in report.weights[:5])
    return Finding(
        id="lime_explanation",
        module="nlp",
        severity=Severity.INFO,
        title="LIME local explanation",
        detail=(
            f"A weighted linear surrogate fitted to {report.n_samples} perturbations of this message "
            f"(R^2 {report.fidelity:.2f} against the real model) attributes {report.category.value} to: "
            f"{summary or 'n/a'}. {len(report.agreement_with_shap)} of its top {len(report.weights)} "
            "token(s) also appear in the SHAP list."
        ),
        evidence={
            "method": report.method,
            "local_r2": report.fidelity,
            "n_samples": report.n_samples,
            "n_interpretable_features": report.n_features,
            "category": report.category.value,
            "lime_weights": [{"token": w.token, "weight": round(w.weight, 4)} for w in report.weights[:8]],
            "agreement_with_shap": report.agreement_with_shap,
        },
    )


def attach(result: AnalysisResult, cfg: Settings, store: Store | None = None) -> AnalysisResult:
    """``result`` with the LIME fields and evidence entry filled in.

    Used on the report path, so a forensic PDF carries both explanations even
    though only SHAP is computed during ingest.  The input is not modified.
    """
    report = lime_report(result, cfg, store)
    if not report.available:
        return result
    nlp = result.nlp.model_copy(
        update={
            "lime_weights": report.weights,
            "lime_fidelity": report.fidelity,
            "lime_method": report.method,
            "findings": [*result.nlp.findings, finding(report)],
        }
    )
    return result.model_copy(update={"nlp": nlp, "findings": [*result.findings, finding(report)]})
