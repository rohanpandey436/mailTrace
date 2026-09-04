from __future__ import annotations

from app.engine.auth import evaluate_auth, parse_authentication_results, parse_dkim_signature
from app.engine.headers import analyze_headers
from app.engine.parser import parse_email
from app.schemas import HeaderField


def _auth(sample_bytes: bytes, cfg):
    parsed, _ = parse_email(sample_bytes)
    header_analysis = analyze_headers(parsed, cfg)
    result, findings = evaluate_auth(parsed, header_analysis, cfg, sample_bytes)
    return parsed, result, findings


def test_parse_authentication_results_sbi(sample):
    parsed, _ = parse_email(sample("phishing"))
    parsed_ar = parse_authentication_results(parsed.headers)
    assert parsed_ar["spf"][0] == "fail"
    assert parsed_ar["dmarc"][0] == "fail"
    assert parsed_ar["dkim"][0] == "none"


def test_parse_dkim_signature_absent_and_present(sample):
    parsed, _ = parse_email(sample("phishing"))
    assert not parse_dkim_signature(parsed.headers).get("d")
    headers = [HeaderField(name="DKIM-Signature", value="v=1; a=rsa-sha256; d=github.com; s=pf2023; h=from:to; b=abc")]
    sig = parse_dkim_signature(headers)
    assert sig["d"] == "github.com" and sig["s"] == "pf2023"


def test_offline_auth_for_phishing_sample(sample, cfg):
    _, result, findings = _auth(sample("phishing"), cfg)
    assert result.spf == "fail" and result.spf_source == "authentication-results"
    assert result.dmarc == "fail"
    assert result.dkim == "none"
    ids = {f.id for f in findings}
    assert "spf_fail" in ids and "dmarc_fail" in ids
    assert all(f.module == "auth" for f in findings)


def test_offline_auth_for_legit_sample(sample, cfg):
    _, result, findings = _auth(sample("legit"), cfg)
    assert result.spf == "pass" and result.dkim == "pass" and result.dmarc == "pass"
    assert result.dmarc_policy.lower() == "reject"
    assert result.spf_aligned is True and result.dkim_aligned is True
    assert result.dkim_domain == "github.com"
    ids = {f.id for f in findings}
    assert "spf_pass" in ids and "spf_fail" not in ids


def test_bec_sample_has_no_auth_evidence_of_pass(sample, cfg):
    _, result, findings = _auth(sample("bec"), cfg)
    assert result.spf in ("none", "unverifiable")
    assert result.dmarc in ("none", "fail")
    assert {f.id for f in findings} & {"spf_none", "spf_unverifiable", "dmarc_no_record", "dmarc_fail"}


def test_no_headers_at_all(cfg):
    parsed, _ = parse_email(b"From: a@b.com\nSubject: hi\n\nhello\n")
    header_analysis = analyze_headers(parsed, cfg)
    result, findings = evaluate_auth(parsed, header_analysis, cfg, None)
    assert result.spf == "none" and result.dkim == "none"
    assert any(f.id == "auth_all_missing" for f in findings)
