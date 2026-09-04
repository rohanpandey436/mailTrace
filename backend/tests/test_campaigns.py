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


# --------------------------------------------------------------------------- #
# Threshold calibration
# --------------------------------------------------------------------------- #
# The substitutions a mail-merge campaign actually makes per victim. The
# SimHash threshold in Settings is justified by the numbers this test measures,
# so if the digest or the tokenisation ever changes, this fails rather than
# silently letting campaigns stop clustering.
_CAMPAIGN_EDITS = [
    (r"\bDear\b", "Hello"),
    (r"\b24 hours\b", "48 hours"),
    (r"\b(?:Rs\.?|₹)\s?[\d,]+", "Rs. 9,99,999"),
    (r"\b\d{4,}\b", "778812"),
    (r"\bRegards\b", "Best regards"),
    (r"\bimmediately\b", "without delay"),
]


def test_simhash_threshold_calibration(sample, cfg):
    """Rewritten bodies must stay inside the threshold, unrelated ones outside.

    Measured on the bundled samples: six campaign-style substitutions move a
    body by at most 9 bits, while genuinely unrelated samples sit at 20 or more.
    The shipped threshold of 12 lives in that gap.
    """
    import re

    from app.engine.parser import hamming_distance, parse_email, simhash_hex

    threshold = cfg.simhash_max_distance
    assert threshold == 12, "the calibration below justifies 12; update both together"

    bodies = {}
    for key in ("phishing", "bec", "fraud", "ceo", "legit"):
        parsed, _ = parse_email(sample(key))
        bodies[key] = parsed.text_body

    worst_rewrite = 0
    for key, body in bodies.items():
        edited = body
        for pattern, replacement in _CAMPAIGN_EDITS:
            edited = re.sub(pattern, replacement, edited, flags=re.IGNORECASE)
        distance = hamming_distance(simhash_hex(body), simhash_hex(edited))
        worst_rewrite = max(worst_rewrite, distance)
        assert distance <= threshold, f"{key}: a rewritten body at {distance} would no longer cluster"

    closest_unrelated = 64
    keys = list(bodies)
    for i, a in enumerate(keys):
        for b in keys[i + 1:]:
            distance = hamming_distance(simhash_hex(bodies[a]), simhash_hex(bodies[b]))
            closest_unrelated = min(closest_unrelated, distance)
            assert distance > threshold, f"{a} and {b} are unrelated but only {distance} apart"

    # The threshold must sit strictly inside the gap, with room on both sides.
    assert worst_rewrite <= threshold < closest_unrelated
