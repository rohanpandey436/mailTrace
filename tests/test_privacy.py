from __future__ import annotations

from app.engine.privacy import mask_email, mask_name, mask_result, mask_text


def test_mask_email_and_name():
    assert mask_email("rohan.pandey@acme-corp.in") == "r***y@acme-corp.in"
    assert mask_email("ab@x.com") == "a*@x.com"
    assert mask_email("a@x.com") == "*@x.com"
    assert mask_email("not-an-address") == "not-an-address"
    assert mask_name("Rohan Pandey") == "R. P."
    assert mask_name("") == ""


def test_mask_text_patterns():
    text = "Contact rohan.pandey@acme-corp.in or +91 98765 43210. Aadhaar 1234 5678 9012, PAN ABCDE1234F, card 4111 1111 1111 1111."
    masked = mask_text(text)
    assert "rohan.pandey@" not in masked and "@acme-corp.in" in masked
    assert "98765 43210" not in masked
    assert "1234 5678 9012" not in masked and "9012" in masked
    assert "ABCDE1234F" not in masked
    assert "4111 1111 1111 1111" not in masked and "1111" in masked


def test_mask_text_keeps_indicators():
    text = "sha256 3b1f2c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f809 from 45.148.10.72 http://evil.top/login id 4471"
    masked = mask_text(text)
    assert "3b1f2c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f809" in masked
    assert "45.148.10.72" in masked and "http://evil.top/login" in masked and "4471" in masked
    assert mask_text(None) is None and mask_text(42) == 42


def test_mask_result_is_deep_and_consistent(analyses):
    original = analyses["phishing"]
    masked = mask_result(original)
    assert masked.masked is True and original.masked is False
    assert original.email.sender.address == "alerts@sbi-kyc-update.xyz"
    assert masked.email.sender.address == "a***s@sbi-kyc-update.xyz"
    assert masked.email.sender.domain == "sbi-kyc-update.xyz"
    assert all("rohan.pandey@" not in h.value for h in masked.email.headers)
    assert "rohan.pandey@" not in masked.email.text_body
    assert masked.headers.originating_ip == original.headers.originating_ip
    assert any(u.url == "http://sbi-online-kyc-verify.xyz/login" for u in masked.urls.urls)
    address_ids = {n.id for n in masked.graph.nodes if n.type == "address"}
    assert address_ids and all(not i.startswith("address:alerts@") for i in address_ids)
    edge_refs = {e.source for e in masked.graph.edges} | {e.target for e in masked.graph.edges}
    node_ids = {n.id for n in masked.graph.nodes}
    assert edge_refs <= node_ids
    assert masked.verdict.risk_score == original.verdict.risk_score
