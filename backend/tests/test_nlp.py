from __future__ import annotations

import pytest

from app.core.ai_engine import analyze_content, detect_language, normalize_text
from app.core.file_analyzer import analyze_attachments
from app.core.link_analyzer import analyze_urls
from app.core.parser import parse_email


def _nlp(raw: bytes, cfg):
    parsed, atts = parse_email(raw)
    return analyze_content(parsed, analyze_urls(parsed, cfg), analyze_attachments(atts, cfg), cfg)


def _pattern(analysis, name):
    return max((p.confidence for p in analysis.bec_patterns if p.pattern == name), default=0.0)


def test_normalize_and_language():
    assert normalize_text("Hello", "  World\n\n\nagain ") == "hello\nworld\nagain"
    assert detect_language("नमस्ते आप कैसे हैं") == "hi"
    assert detect_language("hello there") == "en"


def test_phishing_sample_content(sample, cfg):
    analysis = _nlp(sample("phishing"), cfg)
    assert analysis.urgency_score >= 0.5
    assert "fear" in analysis.social_engineering_cues
    assert analysis.generic_greeting is True
    assert _pattern(analysis, "credential_harvesting") >= 0.5
    assert analysis.credential_terms and analysis.threat_terms
    ids = {f.id for f in analysis.findings}
    assert {"urgency_language", "fear_or_threat_language", "credential_request", "bec_credential_harvesting", "ml_classification"} <= ids


def test_bec_sample_payment_diversion(sample, cfg):
    analysis = _nlp(sample("bec"), cfg)
    assert _pattern(analysis, "payment_diversion") >= 0.5
    assert _pattern(analysis, "executive_impersonation") >= 0.35
    assert "secrecy" in analysis.social_engineering_cues
    assert len(analysis.financial_terms) >= 2


def test_ceo_sample_executive_impersonation(sample, cfg):
    analysis = _nlp(sample("ceo"), cfg)
    assert _pattern(analysis, "executive_impersonation") >= 0.5
    assert analysis.requests_reply_not_click is True
    assert _pattern(analysis, "payment_diversion") == 0.0


def test_fraud_sample_lures(sample, cfg):
    analysis = _nlp(sample("fraud"), cfg)
    assert "reward" in analysis.social_engineering_cues
    assert len(analysis.financial_terms) >= 3
    assert any(f.id == "reward_lure" for f in analysis.findings)
    assert 0.0 <= analysis.score <= 1.0


def test_legit_sample_is_quiet(sample, cfg):
    analysis = _nlp(sample("legit"), cfg)
    assert analysis.urgency_score < 0.25
    assert all(p.confidence < 0.5 for p in analysis.bec_patterns)
    assert not analysis.credential_terms
    assert analysis.score < 0.5


def test_ml_model_trains_and_predicts(sample, cfg):
    pytest.importorskip("sklearn")
    analysis = _nlp(sample("phishing"), cfg)
    assert analysis.ml_model != "unavailable"
    assert abs(sum(analysis.ml_probabilities.values()) - 1.0) < 0.01
    assert set(analysis.ml_probabilities) == {"Legitimate", "Suspicious", "Impersonated", "Phishing", "Fraud-Related"}
    assert analysis.ml_category.value in ("Phishing", "Impersonated")
    assert analysis.ml_top_terms
