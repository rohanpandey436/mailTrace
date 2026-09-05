from __future__ import annotations

from app.core.link_analyzer import (
    analyze_url,
    analyze_urls,
    damerau_levenshtein,
    extract_urls,
    is_lookalike,
    normalize_url,
    registrable_domain,
)
from app.core.parser import parse_email


def test_registrable_domain():
    assert registrable_domain("mail.google.com") == "google.com"
    assert registrable_domain("a.b.sbi.co.in") == "sbi.co.in"
    assert registrable_domain("Example.COM.") == "example.com"
    assert registrable_domain("45.148.10.72") == "45.148.10.72"
    assert registrable_domain("") == ""
    assert registrable_domain("localhost") == "localhost"


def test_damerau_levenshtein():
    assert damerau_levenshtein("paypal", "paypal") == 0
    assert damerau_levenshtein("paypal", "paypa") == 1
    assert damerau_levenshtein("paypal", "papyal") == 1  # transposition
    assert damerau_levenshtein("", "abc") == 3


def test_lookalike_detection(cfg):
    assert is_lookalike("sbi-online-kyc-verify.xyz", cfg)[0] == "sbi"
    assert is_lookalike("acme-corp-in.com", cfg) == ("acme-corp.in", "extra_token")
    assert is_lookalike("paypa1.com", cfg)[0] == "paypal"
    assert is_lookalike("rnicrosoft.com", cfg)[0] == "microsoft"
    assert is_lookalike("paypal.xyz", cfg) == ("paypal", "tld_swap")
    assert is_lookalike("login.microsoft.com.evil.top", cfg) == ("microsoft", "subdomain_abuse")
    assert is_lookalike("xn--pypal-4ve.com", cfg)[1] == "punycode"
    # never flag the real thing, its sub-domains, the protected org or free-mail
    assert is_lookalike("mail.google.com", cfg) == ("", "")
    assert is_lookalike("github.io", cfg) == ("", "")
    assert is_lookalike("acme-corp.in", cfg) == ("", "")
    assert is_lookalike("hr.acme-corp.in", cfg) == ("", "")
    assert is_lookalike("zoho.com", cfg) == ("", "")
    assert is_lookalike("acme-corp.zendesk.com", cfg) == ("", "")


def test_normalize_url():
    assert normalize_url("HTTP://Example.com:80/a/../b#frag") == "http://example.com/a/../b"
    assert normalize_url("www.example.com/x") == "http://www.example.com/x"
    assert normalize_url("https://ex.com:8443/p?q=1") == "https://ex.com:8443/p?q=1"
    assert normalize_url("javascript:alert(1)") == "javascript:alert(1)"
    assert normalize_url("") == ""


def test_extract_urls_from_html_and_text():
    html = '<p><a href="http://sbi-online-kyc-verify.xyz/login">https://onlinesbi.sbi</a> <a href="mailto:x@y.com">mail</a></p>'
    text = "Visit http://example.org/a. Also www.test.com/path and bare example.net/login (see it)."
    pairs = extract_urls(text, html)
    urls = [u for u, _ in pairs]
    assert "http://sbi-online-kyc-verify.xyz/login" in urls
    assert dict(pairs)["http://sbi-online-kyc-verify.xyz/login"] == "https://onlinesbi.sbi"
    assert "http://example.org/a" in urls
    assert any(u.startswith("www.test.com/path") for u in urls)
    assert any(u.startswith("example.net/login") for u in urls)
    assert not any(u.startswith("mailto:") for u in urls)


def test_analyze_url_signals(cfg):
    u = analyze_url("http://sbi-online-kyc-verify.xyz/login", "https://onlinesbi.sbi", cfg)
    assert u.anchor_mismatch and u.lookalike_of == "sbi" and "login" in u.suspicious_keywords
    assert u.risk.value == "critical"
    ip = analyze_url("http://45.148.10.72/verify", "", cfg)
    assert ip.is_ip_literal and ip.risk.value in ("high", "critical")
    redirect = analyze_url("https://google.com/url?q=https://evil.top/login", "", cfg)
    assert "redirect_parameter" in redirect.obfuscation
    data = analyze_url("data:text/html;base64,PGh0bWw+", "", cfg)
    assert "data_uri" in data.obfuscation and data.risk.value == "high"
    userinfo = analyze_url("http://paypal.com@evil.top/", "", cfg)
    assert userinfo.has_userinfo and userinfo.host == "evil.top"
    short = analyze_url("https://bit.ly/abc", "", cfg)
    assert short.is_shortener and short.risk.value == "medium"
    legit = analyze_url("https://github.com/organizations/acme-corp-india/settings/receipts", "View your receipts", cfg)
    assert legit.risk.value == "info" and not legit.anchor_mismatch


def test_analyze_urls_on_samples(sample, cfg):
    parsed, _ = parse_email(sample("phishing"))
    analysis = analyze_urls(parsed, cfg)
    ids = {f.id for f in analysis.findings}
    assert {"credential_harvest_link", "anchor_href_mismatch", "lookalike_domain_link", "link_inventory"} <= ids
    assert "sbi-online-kyc-verify.xyz" in analysis.unique_domains
    assert analysis.score >= 0.75

    parsed, _ = parse_email(sample("legit"))
    analysis = analyze_urls(parsed, cfg)
    assert analysis.score < 0.3
    assert all(f.severity.value in ("info", "low") for f in analysis.findings)

    parsed, _ = parse_email(sample("ceo"))
    assert analyze_urls(parsed, cfg).urls == []
