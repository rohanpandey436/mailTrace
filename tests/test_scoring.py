from __future__ import annotations

from app.engine.scoring import RISK_FLOORS, severity_for
from app.schemas import SEVERITY_ORDER, Severity, ThreatCategory


def test_severity_bands():
    assert severity_for(0, has_findings=False) == Severity.INFO
    assert severity_for(10) == Severity.LOW
    assert severity_for(25) == Severity.MEDIUM
    assert severity_for(50) == Severity.HIGH
    assert severity_for(75) == Severity.CRITICAL
    assert severity_for(999) == Severity.CRITICAL


def test_sample_verdicts(analyses):
    expected = {
        "phishing": ThreatCategory.PHISHING,
        "bec": ThreatCategory.FRAUD,
        "fraud": ThreatCategory.FRAUD,
        "ceo": ThreatCategory.IMPERSONATED,
        "legit": ThreatCategory.LEGITIMATE,
    }
    for key, category in expected.items():
        verdict = analyses[key].verdict
        assert verdict.category == category, f"{key}: got {verdict.category} ({verdict.rationale})"
        assert verdict.risk_score >= RISK_FLOORS.get(category, 0)
        assert 0.0 <= verdict.confidence <= 1.0
        assert verdict.severity == severity_for(verdict.risk_score, has_findings=bool(analyses[key].findings))


def test_risk_scale_and_breakdown(analyses):
    legit = analyses["legit"].verdict
    assert legit.risk_score < 25
    for key in ("phishing", "bec", "fraud"):
        assert analyses[key].verdict.risk_score >= 60
    b = analyses["phishing"].verdict.breakdown
    # The five Stage 4 pillars all exist, are in range, and their weights normalise.
    for pillar in ("ai", "authentication", "geoip_route", "domain", "threat_intel"):
        value = getattr(b, pillar)
        assert 0 <= value <= 100, f"{pillar} out of range: {value}"
        assert pillar in b.weights
    assert abs(sum(b.weights.values()) - 1.0) < 1e-6
    assert b.authentication >= 45  # SPF fail plus a spoofed display name and Reply-To
    assert b.ai >= 70              # credential-harvest wording and a critical lure link
    assert b.domain >= 50          # sbi-kyc-update.xyz is a lookalike domain


def test_attribution(analyses):
    assert analyses["bec"].attribution.source_type == "lookalike_domain"
    assert analyses["legit"].attribution.source_type == "legitimate_sender"
    assert analyses["ceo"].attribution.source_type == "direct_attacker_infrastructure"
    assert analyses["phishing"].attribution.source_type in ("direct_attacker_infrastructure", "spoofed_domain", "lookalike_domain", "undetermined")
    for result in analyses.values():
        assert 0.0 <= result.attribution.confidence <= 1.0
        assert result.attribution.reasoning


def test_findings_sorted_and_unique(analyses):
    for result in analyses.values():
        ranks = [SEVERITY_ORDER[f.severity.value] for f in result.findings]
        assert ranks == sorted(ranks, reverse=True)
        keys = [(f.module, f.id) for f in result.findings]
        assert len(keys) == len(set(keys))


def test_rationale_and_actions_are_specific(analyses):
    phishing = analyses["phishing"].verdict
    assert any("sbi" in line.lower() for line in phishing.rationale)
    assert any("password" in a.lower() or "credential" in a.lower() for a in phishing.recommended_actions)
    bec = analyses["bec"].verdict
    assert any("bank" in a.lower() or "payment" in a.lower() for a in bec.recommended_actions)
    assert analyses["legit"].verdict.recommended_actions
