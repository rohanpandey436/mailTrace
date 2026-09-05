from __future__ import annotations

from app.core.header_analyzer import analyze_headers, extract_ips, is_private_ip, parse_received
from app.core.parser import parse_email


def test_is_private_ip():
    assert is_private_ip("10.1.2.3") and is_private_ip("192.168.0.1") and is_private_ip("127.0.0.1")
    assert is_private_ip("172.16.5.5") and is_private_ip("100.64.1.1") and is_private_ip("fe80::1")
    assert not is_private_ip("45.148.10.72") and not is_private_ip("2001:4860::8888")
    assert not is_private_ip("not-an-ip")


def test_extract_ips_orders_and_dedupes():
    ips = extract_ips("from a (b [45.148.10.72]) by c [10.0.0.1] then 45.148.10.72 and 2001:db8::1")
    assert ips[0] == "45.148.10.72" and "10.0.0.1" in ips and ips.count("45.148.10.72") == 1


def test_parse_received_gmail_style():
    value = ("from relay-eu2.bulkmail-hub.icu (relay-eu2.bulkmail-hub.icu. [193.42.33.118]) "
             "by mx.google.com with ESMTP id d9443c01a7336si2231907plg.88 for <rohan.pandey@acme-corp.in>; "
             "Mon, 31 Aug 2026 21:22:41 -0700 (PDT)")
    hop = parse_received(value)
    assert hop["from_host"] == "relay-eu2.bulkmail-hub.icu"
    assert hop["from_ip"] == "193.42.33.118"
    assert hop["by_host"] == "mx.google.com"
    assert "ESMTP" in hop["protocol"]
    assert hop["timestamp"] is not None and hop["timestamp"].tzinfo is not None


def test_parse_received_prefers_public_ip_in_comment():
    value = ("from [127.0.0.1] (unknown [185.220.101.45]) (Authenticated sender: x@y) "
             "by mail.acme-corp-in.com (Postfix) with ESMTPSA id 2B7D4C0A91; Wed,  2 Sep 2026 09:01:12 +0000 (UTC)")
    hop = parse_received(value)
    assert hop["from_ip"] == "185.220.101.45"
    assert hop["by_host"] == "mail.acme-corp-in.com"


def test_parse_received_without_from_clause():
    hop = parse_received("by 2002:a05:6a00:2e1b:b0:71e with SMTP id fa4csp2214893pfb; Mon, 31 Aug 2026 21:25:02 -0700 (PDT)")
    assert hop["from_host"] == "" and hop["from_ip"] == ""
    assert hop["timestamp"] is not None


def test_phishing_chain_origin_and_anomaly(sample, cfg):
    parsed, _ = parse_email(sample("phishing"))
    analysis = analyze_headers(parsed, cfg)
    assert len(analysis.hops) == 4
    assert analysis.hops[0].index == 0
    assert analysis.hops[0].is_private_ip  # localhost injection hop
    assert analysis.originating_ip == "45.148.10.72"
    assert analysis.originating_hop_index == 1
    assert 0.5 <= analysis.origin_confidence <= 1.0
    negative = [h for h in analysis.hops if h.delay_seconds is not None and h.delay_seconds < -60]
    assert negative, "the sample carries a deliberate -3 minute clock anomaly"
    assert any("negative" in a for h in analysis.hops for a in h.anomalies)
    assert analysis.reply_to_mismatch is True
    assert analysis.display_name_spoof is True
    assert analysis.display_name_brand.lower().startswith("sbi") or "sbi" in analysis.display_name_brand.lower()
    assert analysis.message_id_domain == "srv-mail01.sbi-kyc-update.xyz"
    ids = {f.id for f in analysis.findings}
    assert {"reply_to_mismatch", "display_name_spoof", "origin_identified"} <= ids
    assert 0.0 <= analysis.score <= 1.0


def test_bec_chain_origin_behind_loopback(sample, cfg):
    parsed, _ = parse_email(sample("bec"))
    analysis = analyze_headers(parsed, cfg)
    assert analysis.originating_ip == "185.220.101.45"
    assert analysis.reply_to_mismatch is True  # protonmail vs acme-corp-in.com
    assert analysis.return_path_mismatch is False


def test_ceo_sample_flags_executive_display_name(sample, cfg):
    parsed, _ = parse_email(sample("ceo"))
    analysis = analyze_headers(parsed, cfg)
    assert analysis.display_name_spoof is True
    assert analysis.originating_ip == "49.36.220.14"
    assert not analysis.reply_to_mismatch


def test_legit_sample_is_clean(sample, cfg):
    parsed, _ = parse_email(sample("legit"))
    analysis = analyze_headers(parsed, cfg)
    assert analysis.originating_ip == "192.30.252.206"
    assert not analysis.display_name_spoof and not analysis.reply_to_mismatch and not analysis.return_path_mismatch
    assert analysis.score < 0.35


def test_empty_message_has_no_hops(cfg):
    parsed, _ = parse_email(b"Subject: x\n\nbody\n")
    analysis = analyze_headers(parsed, cfg)
    assert analysis.hops == [] and analysis.originating_ip == ""
    assert any(f.id == "empty_received_chain" for f in analysis.findings)
