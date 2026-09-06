"""Attachment risk analysis."""
from __future__ import annotations

import hashlib
import io
import logging
import math
import re
import zipfile
from collections import Counter
from typing import TypedDict

from ..config import Settings
from ..schemas import SEVERITY_ORDER, AttachmentAnalysis, AttachmentMeta, Finding, Severity
from .knowledge import ARCHIVE_EXTENSIONS, EXECUTABLE_MAGIC, MACRO_EXTENSIONS, RISKY_EXTENSIONS
from .parser import RawAttachment

log = logging.getLogger("mailtrace.attachments")

_MAGIC: tuple[tuple[bytes, str], ...] = (
    (b"MZ", "pe"),
    (b"\x7fELF", "elf"),
    (b"\xfe\xed\xfa\xce", "macho"),
    (b"\xfe\xed\xfa\xcf", "macho"),
    (b"\xcf\xfa\xed\xfe", "macho"),
    (b"\xce\xfa\xed\xfe", "macho"),
    (b"%PDF", "pdf"),
    (b"Rar!\x1a\x07", "rar"),
    (b"7z\xbc\xaf\x27\x1c", "7z"),
    (b"\x1f\x8b", "gz"),
    (b"BZh", "bz2"),
    (b"\xfd7zXZ\x00", "xz"),
    (b"MSCF", "cab"),
    (b"\x89PNG", "png"),
    (b"\xff\xd8\xff", "jpg"),
    (b"GIF8", "gif"),
    (b"{\\rtf", "rtf"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "ole"),
    (b"L\x00\x00\x00\x01\x14\x02\x00", "lnk"),
)
_ZIP_MAGICS = (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")
_ARCHIVE_MAGIC = {"zip", "rar", "7z", "gz", "bz2", "xz", "iso", "cab"}
_IMAGE_MAGIC = {"png", "jpg", "gif"}
_IMAGE_EXTS = {"png", "jpg", "jpeg", "gif", "bmp", "webp", "svg"}
_DOCUMENT_EXTS = {
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "jpg", "jpeg", "png", "gif", "txt", "csv",
    "zip", "html", "htm", "rtf", "odt", "ods", "mp3", "mp4", "avi",
}
_EXEC_EXTS = {"exe", "dll", "scr", "com", "msi", "pif", "cpl", "sys", "drv", "ocx"}
_SCRIPT_MARKERS = (
    b"powershell", b"cmd.exe", b"wscript", b"cscript", b"createobject(", b"@echo off",
    b"set-executionpolicy", b"invoke-expression", b"iex(", b"rundll32", b"regsvr32", b"mshta",
)
_RISK_VALUE: dict[str, float] = {"info": 0.0, "low": 0.15, "medium": 0.4, "high": 0.75, "critical": 1.0}

_INCOMPRESSIBLE_EXTS: set[str] = {
    "doc", "dot", "xls", "xlt", "ppt", "pdf", "rtf", "txt", "csv", "tsv", "log", "md",
    "html", "htm", "shtml", "xml", "svg", "json", "eml", "msg", "ics", "vcf",
}
_ZIP_CONTAINER_DOC_EXTS: set[str] = {
    "docx", "docm", "dotm", "xlsx", "xlsm", "xlam", "xltm", "pptx", "pptm", "odt", "ods", "odp",
}
_MEDIA_EXTS: set[str] = {
    "mp3", "m4a", "aac", "ogg", "oga", "opus", "flac", "wma",
    "mp4", "m4v", "avi", "mov", "mkv", "webm", "wmv", "mpg", "mpeg", "3gp",
}
_NATURALLY_COMPRESSED_EXTS: set[str] = ARCHIVE_EXTENSIONS | (_IMAGE_EXTS - {"svg"}) | _MEDIA_EXTS
_NATURALLY_COMPRESSED_MAGIC: set[str] = _ARCHIVE_MAGIC | _IMAGE_MAGIC | {"ooxml"}
_SNIFFABLE_IMAGE_EXTS: set[str] = {"png", "jpg", "jpeg", "gif"}


# Entropy
def shannon_entropy(data: bytes) -> float:
    """Shannon entropy of ``data`` in bits per byte over the 256-symbol alphabet."""
    total = len(data)
    if not total:
        return 0.0
    entropy = 0.0
    for count in Counter(data).values():
        p = count / total
        entropy -= p * math.log2(p)
    return entropy


def _image_claim_mismatch(ext: str, magic: str) -> bool:
    """True when a file claims an image extension its content does not back up."""
    if ext in _SNIFFABLE_IMAGE_EXTS:
        return magic not in _IMAGE_MAGIC  # includes '' - no PNG/JPEG/GIF header at all
    if ext in _IMAGE_EXTS:  # bmp/webp/svg: the sniffer has no signature, so only a
        return bool(magic) and magic not in _IMAGE_MAGIC  # positive foreign magic counts
    return False


def _entropy_escalates(extension: str, magic: str, high_entropy: bool) -> bool:
    """Whether high entropy is *unexplained* by the file's declared type."""
    if not high_entropy or magic in EXECUTABLE_MAGIC:
        return False
    if extension in _INCOMPRESSIBLE_EXTS:
        return True
    if extension in _ZIP_CONTAINER_DOC_EXTS:
        return magic not in ("ooxml", "zip")  # a real OOXML/ODF file is deflated, so 8.0 is normal
    return _image_claim_mismatch(extension, magic)


# Content sniffing
def _looks_text(sample: bytes) -> bool:
    if not sample or b"\x00" in sample:
        return False
    printable = sum(1 for b in sample if 32 <= b < 127 or b in (9, 10, 13))
    return printable / len(sample) > 0.9


def _is_ooxml(data: bytes) -> bool:
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            return "[Content_Types].xml" in archive.namelist()
    except Exception:  # noqa: BLE001 - corrupt/hostile zip
        return False


def sniff_magic(data: bytes) -> str:
    """Identify content by magic bytes; '' when unknown."""
    if not data:
        return ""
    head = data[:16]
    for signature, name in _MAGIC:
        if head.startswith(signature):
            return name
    if head.startswith(_ZIP_MAGICS):
        return "ooxml" if _is_ooxml(data) else "zip"
    if len(data) > 0x8006 and data[0x8001:0x8006] == b"CD001":
        return "iso"
    sample = data[:2048]
    stripped = sample.lstrip().lower()
    if stripped.startswith(b"#!"):
        return "script"
    if b"<hta:application" in stripped:
        return "hta"
    if stripped.startswith((b"<!doctype html", b"<html")) or b"<script" in stripped or b"<body" in stripped:
        return "html"
    if stripped.startswith(b"<?xml"):
        return "html" if b"<html" in stripped else "xml"
    if _looks_text(sample[:512]):
        return "script" if any(marker in stripped for marker in _SCRIPT_MARKERS) else "text"
    return ""


class _ZipReport(TypedDict):
    members: list[str]
    encrypted: bool
    risky_members: list[str]
    has_vba: bool
    ok: bool


def _inspect_zip(data: bytes) -> _ZipReport:
    """Member names, encryption flag, risky members and macro presence."""
    result: _ZipReport = {"members": [], "encrypted": False, "risky_members": [], "has_vba": False, "ok": False}
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            for info in archive.infolist()[:500]:
                name = info.filename
                result["members"].append(name)
                if info.flag_bits & 0x1:
                    result["encrypted"] = True
                lowered = name.lower()
                if lowered.endswith("vbaproject.bin"):
                    result["has_vba"] = True
                ext = lowered.rsplit(".", 1)[-1] if "." in lowered else ""
                if RISKY_EXTENSIONS.get(ext) in ("critical", "high") and not lowered.endswith("/"):
                    result["risky_members"].append(name)
            result["ok"] = True
    except Exception:  # a corrupt or hostile archive is data, not an error
        log.debug("zip inspection failed", exc_info=True)
    return result


_OLE_VBA_MARKERS = ("_VBA_PROJECT".encode("utf-16-le"), "Macros".encode("utf-16-le"), "VBA".encode("utf-16-le"))


def _ole_has_macros(data: bytes) -> bool:
    """Stream names are stored UTF-16LE inside the OLE directory; the VBA"""
    return _OLE_VBA_MARKERS[0] in data or (_OLE_VBA_MARKERS[1] in data and _OLE_VBA_MARKERS[2] in data)


# Per-attachment analysis
def _worse(current: str, candidate: str) -> str:
    return candidate if SEVERITY_ORDER[candidate] > SEVERITY_ORDER[current] else current


def _extension(filename: str) -> str:
    if "." not in filename:
        return ""
    ext = filename.rsplit(".", 1)[-1].strip().lower()
    return ext if ext and len(ext) <= 10 and ext.isalnum() else ""


def analyze_attachment(att: RawAttachment, cfg: Settings) -> AttachmentMeta:
    data = att.data or b""
    filename = att.filename or "unnamed"
    collapsed = re.sub(r"\s{2,}", " ", filename)
    ext = _extension(collapsed)
    magic = sniff_magic(data)
    reasons: list[str] = []
    severity = RISKY_EXTENSIONS.get(ext, "low")
    is_archive = ext in ARCHIVE_EXTENSIONS or magic in _ARCHIVE_MAGIC
    has_macros = False
    mime_mismatch = False
    declared = (att.content_type or "").lower()

    if ext and severity in ("critical", "high"):
        reasons.append(f".{ext} files can execute code or scripts when opened")

    # Double extension: "invoice.pdf.exe" or "photo.jpg .scr".
    parts = collapsed.lower().replace(" ", "").split(".")
    double_extension = len(parts) >= 3 and parts[-2] in _DOCUMENT_EXTS and RISKY_EXTENSIONS.get(ext) in ("critical", "high")
    if double_extension:
        severity = _worse(severity, "high")
        reasons.append(f"Double extension disguises a .{ext} file as a .{parts[-2]} document")

    # Content vs declaration ------------------------------------------------
    if magic in EXECUTABLE_MAGIC:
        severity = "critical"
        reasons.append(f"File content is an executable ({magic}) regardless of its name")
        if ext not in _EXEC_EXTS:
            mime_mismatch = True
    if (ext == "pdf" and magic and magic != "pdf") or (ext in _IMAGE_EXTS and magic and magic not in _IMAGE_MAGIC and ext != "svg") or (ext in ("docx", "xlsx", "pptx", "docm", "xlsm", "pptm") and magic and magic not in ("ooxml", "zip")) or (ext in ("doc", "xls", "ppt") and magic and magic not in ("ole", "rtf", "text", "xml", "html")) or (ext == "zip" and magic and magic not in ("zip", "ooxml")) or (declared == "application/pdf" and magic and magic != "pdf"):
        mime_mismatch = True
    if mime_mismatch:
        severity = _worse(severity, "high")
        reasons.append(f"Declared as {declared or ('.' + ext) or 'unknown'} but the content looks like {magic}")

    # Macros --------------------------------------------------------------
    if magic == "ooxml" or (ext in ("docm", "xlsm", "pptm", "dotm", "xltm", "xlam") and magic in ("ooxml", "zip")):
        if _inspect_zip(data)["has_vba"]:
            has_macros = True
    elif magic == "ole" and _ole_has_macros(data):
        has_macros = True
    if ext in ("docm", "xlsm", "pptm", "dotm", "xltm", "xlam") and not has_macros:
        has_macros = True  # the format exists only to carry macros
    if has_macros:
        severity = _worse(severity, "high")
        reasons.append("Document contains VBA macros")
    elif ext in MACRO_EXTENSIONS and ext in ("doc", "xls", "ppt"):
        reasons.append("Legacy Office format can carry macros; open only in Protected View")

    # Archives ------------------------------------------------------------
    if is_archive and magic in ("zip", "ooxml", "") and (ext in ("zip", "jar", "apk") or magic == "zip"):
        inspection = _inspect_zip(data)
        if inspection["ok"]:
            if inspection["risky_members"]:
                severity = "critical"
                shown = ", ".join(inspection["risky_members"][:3])
                reasons.append(f"Archive contains executable content: {shown}")
            if inspection["encrypted"]:
                severity = _worse(severity, "high")
                reasons.append("Password-protected archive: contents cannot be scanned by gateways")
    elif is_archive and magic in ("rar", "7z", "iso", "cab"):
        severity = _worse(severity, "medium")
        reasons.append(f"{magic.upper()} container hides its contents from most mail scanners")

    # HTML / HTA ------------------------------------------------------------
    if magic == "hta":
        severity = "critical"
        reasons.append("HTML Application (HTA) runs with full local privileges")
    elif magic == "html" or ext in ("html", "htm", "shtml"):
        lowered = data[:65536].lower()
        if b"<script" in lowered or b"<form" in lowered or b"password" in lowered:
            severity = _worse(severity, "high")
            reasons.append("HTML attachment contains script/form content (typical credential-phishing page)")
    if magic == "script" and ext not in ("txt", "csv", "log", "md"):
        severity = _worse(severity, "high")
        reasons.append("Content contains shell/PowerShell/script commands")

    entropy = shannon_entropy(data)
    high_entropy = entropy >= cfg.entropy_threshold
    if high_entropy:
        measured = f"entropy {entropy:.2f} of a possible 8.00, above the {cfg.entropy_threshold:.1f} threshold"
        if magic in EXECUTABLE_MAGIC:
            severity = _worse(severity, "critical")
            reasons.append(
                f"Executable is packed or obfuscated ({measured}): the real code is unpacked only at run "
                "time, which is how malware hides from signature scanners",
            )
        elif _entropy_escalates(ext, magic, high_entropy):
            severity = _worse(severity, "high")
            if _image_claim_mismatch(ext, magic):
                claimed = f"a .{ext} image, but the bytes carry no image header"
            elif ext in _ZIP_CONTAINER_DOC_EXTS:
                claimed = f"a .{ext} file, and the bytes are not the document container that name implies"
            else:
                claimed = f"a .{ext} file, which stores its contents uncompressed"
            reasons.append(
                f"Content is almost random ({measured}) for {claimed}: this indicates packing, encryption "
                "or an embedded payload rather than an ordinary document",
            )
        elif ext in _NATURALLY_COMPRESSED_EXTS or magic in _NATURALLY_COMPRESSED_MAGIC or is_archive:
            kind = magic.upper() if magic else (f".{ext}" if ext else "this")
            reasons.append(f"High {measured}, which is expected for {kind} content because it is compressed by design")

    if not data:
        reasons.append("Attachment is empty")

    if att.is_inline and (magic in _IMAGE_MAGIC or ext in _IMAGE_EXTS) and not mime_mismatch:
        severity = "info"
        reasons = []

    return AttachmentMeta(
        filename=filename,
        content_type=att.content_type,
        size=len(data),
        sha256=hashlib.sha256(data).hexdigest(),
        md5=hashlib.md5(data).hexdigest(),
        extension=ext,
        magic_type=magic,
        mime_mismatch=mime_mismatch,
        is_archive=is_archive,
        has_macros=has_macros,
        double_extension=double_extension,
        shannon_entropy=round(entropy, 3),
        high_entropy=high_entropy,
        risk=Severity(severity),
        reasons=reasons,
    )


# Whole-message analysis
def _finding(fid: str, severity: Severity, title: str, detail: str, evidence: dict[str, object]) -> Finding:
    return Finding(id=fid, module="attachments", severity=severity, title=title, detail=detail, evidence=evidence)


def _names(items: list[AttachmentMeta]) -> str:
    return ", ".join(a.filename for a in items[:4]) + (" ..." if len(items) > 4 else "")


def analyze_attachments(raw_attachments: list[RawAttachment], cfg: Settings) -> AttachmentAnalysis:
    metas: list[AttachmentMeta] = []
    inline_flags: list[bool] = []
    for att in raw_attachments or []:
        try:
            metas.append(analyze_attachment(att, cfg))
            inline_flags.append(bool(att.is_inline))
        except Exception:  # one hostile file must not abort the analysis
            log.exception("attachment analysis failed for %r", att.filename)
    scored = [m for m, inline in zip(metas, inline_flags) if not inline]
    severe = [m for m in scored if SEVERITY_ORDER[m.risk.value] >= SEVERITY_ORDER["high"]]
    top = max((_RISK_VALUE[m.risk.value] for m in scored), default=0.0)
    score = min(1.0, top + 0.05 * max(0, len(severe) - 1))

    findings: list[Finding] = []
    if severe:
        worst = max(severe, key=lambda m: SEVERITY_ORDER[m.risk.value])
        findings.append(_finding(
            "dangerous_attachment", worst.risk, "Dangerous attachment",
            f"{_names(severe)}: {worst.reasons[0] if worst.reasons else 'high-risk file type'}.",
            {"files": [{"filename": m.filename, "sha256": m.sha256, "risk": m.risk.value, "reasons": m.reasons} for m in severe[:8]]},
        ))
    macros = [m for m in scored if m.has_macros]
    if macros:
        findings.append(_finding(
            "macro_document", Severity.HIGH, "Macro-enabled document",
            f"{_names(macros)} carry VBA macros, the most common malware delivery mechanism in email.",
            {"files": [m.filename for m in macros]},
        ))
    archive_exec = [m for m in scored if m.is_archive and any("executable content" in r for r in m.reasons)]
    if archive_exec:
        findings.append(_finding(
            "archive_with_executable", Severity.CRITICAL, "Archive contains executable",
            f"{_names(archive_exec)} wrap executable files inside an archive to evade gateway filters.",
            {"files": [{"filename": m.filename, "reasons": m.reasons} for m in archive_exec]},
        ))
    mismatched = [m for m in scored if m.mime_mismatch]
    if mismatched:
        findings.append(_finding(
            "mime_mismatch", Severity.HIGH, "File content does not match its name/type",
            f"{_names(mismatched)}: the bytes inside are a different format from what the name or MIME type claims.",
            {"files": [{"filename": m.filename, "content_type": m.content_type, "magic_type": m.magic_type} for m in mismatched]},
        ))
    entropic = [m for m in scored if _entropy_escalates(m.extension, m.magic_type, m.high_entropy)]
    if entropic:
        lead = max(entropic, key=lambda m: m.shannon_entropy)
        others = [m for m in entropic if m is not lead]
        detail = (
            f"{lead.filename} measures {lead.shannon_entropy:.2f} out of 8.00 on the Shannon entropy scale, "
            f"above the {cfg.entropy_threshold:.2f} threshold. Files of this type normally hold readable, "
            "repetitive content, so bytes this close to random mean the file has been packed, encrypted or "
            "has a payload hidden inside it."
        )
        if others:
            detail += f" {_names(others)} show the same pattern."
        findings.append(_finding(
            "high_entropy_payload", Severity.HIGH, "High-entropy attachment", detail,
            {"files": [{"filename": m.filename, "entropy": m.shannon_entropy,
                        "type": m.magic_type or m.content_type or m.extension} for m in entropic[:8]]},
        ))
    doubles = [m for m in scored if m.double_extension]
    if doubles:
        findings.append(_finding(
            "double_extension", Severity.HIGH, "Double file extension",
            f"{_names(doubles)} use a document extension to hide the real executable extension.",
            {"files": [m.filename for m in doubles]},
        ))
    encrypted = [m for m in scored if any("Password-protected" in r for r in m.reasons)]
    if encrypted:
        findings.append(_finding(
            "password_protected_archive", Severity.HIGH, "Password-protected archive",
            f"{_names(encrypted)} cannot be inspected; attackers use encryption to bypass scanners.",
            {"files": [m.filename for m in encrypted]},
        ))
    if len(scored) > 5:
        findings.append(_finding(
            "many_attachments", Severity.LOW, "Unusually many attachments",
            f"The message carries {len(scored)} attachments.",
            {"count": len(scored)},
        ))
    if metas:
        findings.append(_finding(
            "attachment_inventory", Severity.INFO, "Attachment inventory",
            f"{len(metas)} attachment(s): {_names(metas)}.",
            {"files": [{"filename": m.filename, "size": m.size, "sha256": m.sha256, "type": m.magic_type or m.content_type,
                        "entropy": m.shannon_entropy, "inline": inline} for m, inline in zip(metas, inline_flags)]},
        ))
    return AttachmentAnalysis(attachments=metas, score=score, findings=findings)
