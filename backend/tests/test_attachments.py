from __future__ import annotations

import io
import zipfile

from app.core.file_analyzer import analyze_attachment, analyze_attachments, sniff_magic
from app.core.parser import RawAttachment, parse_email

MZ = b"MZ\x90\x00 This program cannot be run in DOS mode." + b"\x00" * 64
PDF = b"%PDF-1.4\n1 0 obj << >> endobj\n%%EOF\n"


def _zip(members: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as archive:
        for name, data in members.items():
            archive.writestr(name, data)
    return buf.getvalue()


def test_sniff_magic():
    assert sniff_magic(MZ) == "pe"
    assert sniff_magic(PDF) == "pdf"
    assert sniff_magic(_zip({"a.txt": b"hi"})) == "zip"
    assert sniff_magic(_zip({"[Content_Types].xml": b"<x/>", "word/document.xml": b"<w/>"})) == "ooxml"
    assert sniff_magic(b"<!DOCTYPE html><html><script>1</script></html>") == "html"
    assert sniff_magic(b"#!/bin/sh\necho hi") == "script"
    assert sniff_magic(b"just some text") == "text"
    assert sniff_magic(b"") == ""


def test_double_extension_executable(cfg):
    meta = analyze_attachment(RawAttachment("claim_form.pdf.exe", "application/pdf", MZ), cfg)
    assert meta.risk.value == "critical"
    assert meta.double_extension and meta.mime_mismatch and meta.magic_type == "pe"
    assert meta.extension == "exe" and meta.sha256


def test_pdf_disguised_executable(cfg):
    meta = analyze_attachment(RawAttachment("invoice.pdf", "application/pdf", MZ), cfg)
    assert meta.risk.value == "critical" and meta.mime_mismatch


def test_clean_pdf_is_low(cfg):
    meta = analyze_attachment(RawAttachment("receipt.pdf", "application/pdf", PDF), cfg)
    assert meta.risk.value == "low" and not meta.mime_mismatch and meta.magic_type == "pdf"


def test_archive_with_executable(cfg):
    data = _zip({"docs/readme.txt": b"hi", "invoice.exe": MZ})
    analysis = analyze_attachments([RawAttachment("invoice.zip", "application/zip", data)], cfg)
    meta = analysis.attachments[0]
    assert meta.is_archive and meta.risk.value == "critical"
    ids = {f.id for f in analysis.findings}
    assert {"archive_with_executable", "dangerous_attachment", "attachment_inventory"} <= ids
    assert analysis.score >= 0.9


def test_password_protected_archive_flag(cfg):
    data = bytearray(_zip({"secret.docx": b"PK\x03\x04"}))
    marker = data.find(b"PK\x01\x02")  # central directory entry: flags at offset 8
    assert marker > 0
    data[marker + 8] = 0x01
    analysis = analyze_attachments([RawAttachment("secret.zip", "application/zip", bytes(data))], cfg)
    assert any(f.id == "password_protected_archive" for f in analysis.findings)


def test_macro_document(cfg):
    data = _zip({"[Content_Types].xml": b"<x/>", "word/vbaProject.bin": b"\x00" * 10})
    meta = analyze_attachment(RawAttachment("report.docm", "application/vnd.ms-word.document.macroEnabled.12", data), cfg)
    assert meta.has_macros and meta.risk.value in ("high", "critical")


def test_inline_image_excluded_from_score(cfg):
    png = b"\x89PNG\r\n\x1a\n" + b"\x00" * 32
    analysis = analyze_attachments([RawAttachment("logo.png", "image/png", png, content_id="logo", is_inline=True)], cfg)
    assert analysis.score == 0.0
    assert analysis.attachments[0].risk.value == "info"


def test_sample_attachments(sample, cfg):
    _, raw = parse_email(sample("fraud"))
    analysis = analyze_attachments(raw, cfg)
    assert analysis.attachments[0].risk.value == "critical"
    assert {"dangerous_attachment", "double_extension", "mime_mismatch"} <= {f.id for f in analysis.findings}
    _, raw = parse_email(sample("legit"))
    analysis = analyze_attachments(raw, cfg)
    assert analysis.attachments[0].risk.value == "low" and analysis.score < 0.3
