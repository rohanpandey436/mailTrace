from __future__ import annotations

from app.engine import pipeline
from app.engine.campaigns import extract_indicators, is_strong, normalize_subject


def test_normalize_subject():
    assert normalize_subject("Re: FW: Invoice #4471 due") == "invoice ## due"
    assert normalize_subject("") == ""
    assert is_strong("ip:1.2.3.4") and not is_strong("subject:x")


def test_indicators_for_sample(analyses):
    r = analyses["phishing"]
    indicators = extract_indicators(r.email, r.headers, r.urls, r.attachments, r.domains, r.infrastructure)
    assert "ip:45.148.10.72" in indicators
    assert "sender:alerts@sbi-kyc-update.xyz" in indicators
    assert "domain:sbi-kyc-update.xyz" in indicators
    assert "replyto:sbi.kyc.helpdesk@gmail.com" in indicators
    assert any(i.startswith("urlhost:sbi-online-kyc-verify.xyz") for i in indicators)
    assert not any(i.startswith("domain:gmail.com") for i in indicators)


def test_two_related_emails_form_a_campaign(sample, cfg, store):
    first = pipeline.analyze_bytes(sample("phishing"), "one.eml", store, cfg)
    assert first.campaign_id is None
    assert any(f.id == "no_prior_incidents" for f in first.findings)
    second = pipeline.analyze_bytes(sample("phishing"), "two.eml", store, cfg)
    assert second.campaign_id
    assert any(f.id == "known_campaign_overlap" for f in second.findings)
    assert second.intel.related_incidents and second.intel.related_incidents[0].email_id == first.id
    campaign = store.get_campaign(second.campaign_id)
    assert campaign is not None
    assert set(campaign.email_ids) == {first.id, second.id}
    assert campaign.max_risk >= 60
    assert "ip:45.148.10.72" in campaign.indicators
    assert store.campaign_for_email(first.id) == campaign.id
    assert store.get_analysis(first.id).campaign_id == campaign.id
    assert campaign.name.startswith("Campaign")


def test_unrelated_emails_stay_apart(sample, cfg, store):
    a = pipeline.analyze_bytes(sample("legit"), "a.eml", store, cfg)
    b = pipeline.analyze_bytes(sample("ceo"), "b.eml", store, cfg)
    assert a.campaign_id is None and b.campaign_id is None
    assert store.list_campaigns() == []
