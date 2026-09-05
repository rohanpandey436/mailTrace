from __future__ import annotations

from app.core.parser import decode_header_value, html_to_text, parse_address, parse_address_list, parse_email


def test_parses_every_sample_without_error(sample):
    for key in ("phishing", "bec", "legit", "fraud", "ceo"):
        parsed, _ = parse_email(sample(key))
        assert parsed.sender.address, key
        assert parsed.subject, key
        assert parsed.raw_size > 0 and len(parsed.raw_sha256) == 64
        assert len(parsed.headers) > 5
        assert parsed.text_body


def test_sbi_sample_structure(sample):
    parsed, _ = parse_email(sample("phishing"))
    assert parsed.sender.display_name == "State Bank of India"
    assert parsed.sender.address == "alerts@sbi-kyc-update.xyz"
    assert parsed.sender.domain == "sbi-kyc-update.xyz"
    assert parsed.reply_to and parsed.reply_to[0].domain == "gmail.com"
    assert parsed.return_path.address == "kyc-noreply@sbi-kyc-update.xyz"
    assert parsed.has_html and "sbi-online-kyc-verify.xyz" in parsed.html_body
    assert parsed.message_id.endswith("srv-mail01.sbi-kyc-update.xyz")
    assert parsed.date is not None and parsed.date.tzinfo is not None
    assert len([h for h in parsed.headers if h.name.lower() == "received"]) == 4


def test_rfc2047_subject_and_attachment(sample):
    parsed, raw_atts = parse_email(sample("fraud"))
    assert "₹25,00,000" in parsed.subject
    assert parsed.mailer.startswith("PHPMailer")
    assert len(raw_atts) == 1
    assert raw_atts[0].filename == "claim_form.pdf.exe"
    assert raw_atts[0].data.startswith(b"MZ")
    assert parsed.attachments[0].extension == "exe"
    assert parsed.attachments[0].sha256


def test_pdf_attachment_bytes(sample):
    parsed, raw_atts = parse_email(sample("legit"))
    assert raw_atts and raw_atts[0].data.startswith(b"%PDF")
    assert raw_atts[0].content_type == "application/pdf"
    assert parsed.attachments[0].extension == "pdf"


def test_garbage_input_never_raises():
    for blob in (b"", b"\x00\xff\xfe garbage", b"Subject: only a subject\n", b"plain text no headers"):
        parsed, atts = parse_email(blob)
        assert parsed.raw_size == len(blob)
        assert atts == [] or isinstance(atts, list)


def test_decode_header_value_tolerant():
    assert decode_header_value("=?UTF-8?B?4oK5MjU=?=") == "₹25"
    assert decode_header_value("plain\n value") == "plain value"
    assert decode_header_value("=?bogus-charset?Q?abc?=")  # falls back instead of raising
    assert decode_header_value(None) == ""


def test_parse_address_variants():
    a = parse_address('"Rajesh Mehta, Director" <rajesh.mehta@acme-corp-in.com>')
    assert a.display_name == "Rajesh Mehta, Director" and a.domain == "acme-corp-in.com"
    b = parse_address("<>")
    assert b.address == "" and b.domain == ""
    c = parse_address("Broken Name <not-an-address>")
    assert c.address == "not-an-address" or c.address == ""
    d = parse_address("UPPER@Example.COM")
    assert d.address == "upper@example.com" and d.local_part == "upper"
    lst = parse_address_list("a@x.com, Bob <b@y.org>")
    assert [x.address for x in lst] == ["a@x.com", "b@y.org"] and lst[1].display_name == "Bob"


def test_html_to_text_drops_scripts_and_keeps_links():
    html = "<html><head><style>p{}</style><script>evil()</script></head><body><p>Hello <a href='http://x'>click here</a></p><ul><li>one</li></ul></body></html>"
    text = html_to_text(html)
    assert "evil" not in text and "p{}" not in text
    assert "click here" in text and "- one" in text
