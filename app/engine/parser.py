"""
RFC 822 / MIME parsing into the structure the analyzers consume.

Approach
--------
* The message is parsed with the ``compat32`` policy, which never raises on
  malformed input; header values are unfolded and RFC 2047-decoded by hand so
  broken encodings degrade to replacement characters instead of exceptions.
* MIME parts are walked recursively: ``text/plain`` and ``text/html`` parts
  without an attachment disposition become the bodies, ``message/rfc822`` parts
  are captured whole as ``.eml`` attachments, everything else (including inline
  images) becomes a ``RawAttachment`` whose bytes go to ``attachments.py``.
* ``ParsedEmail`` only carries structure (no analysis) plus integrity hashes of
  the exact bytes received, so the chain of custody can reference them.

``parse_email`` never raises: an empty or binary blob yields an empty
``ParsedEmail`` with a ``charset_issues`` note.
"""
from __future__ import annotations

import email
import hashlib
import logging
import mimetypes
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from email import policy
from email.header import decode_header, make_header
from email.message import Message
from email.utils import collapse_rfc2231_value, getaddresses, parseaddr, parsedate_to_datetime
from html.parser import HTMLParser
from typing import Iterator, Optional

from ..schemas import AddressInfo, AttachmentMeta, HeaderField, ParsedEmail

log = logging.getLogger("mailtrace.parser")

_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-'=]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
_FOLD_RE = re.compile(r"\r?\n[ \t]+")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
_MAX_DEPTH = 40
_MAX_PARTS = 500


@dataclass
class RawAttachment:
    """Attachment bytes handed to the attachment analyzer (never persisted)."""

    filename: str
    content_type: str
    data: bytes
    content_id: str = ""
    is_inline: bool = False


# --------------------------------------------------------------------------- #
# Header helpers
# --------------------------------------------------------------------------- #
def _unfold(value: str) -> str:
    return " ".join(_FOLD_RE.sub(" ", value).split())


def decode_header_value(value: object) -> str:
    """Unfold and RFC 2047-decode a header value, tolerating broken input."""
    if value is None:
        return ""
    text = _unfold(str(value))
    if "=?" not in text:
        return text
    try:
        chunks = decode_header(text)
    except Exception:  # noqa: BLE001 - malformed encoded-word syntax
        return text
    try:
        return _unfold(str(make_header(chunks)))
    except Exception:  # noqa: BLE001 - unknown charset / undecodable bytes
        pass
    out: list[str] = []
    for chunk, charset in chunks:
        if isinstance(chunk, bytes):
            decoded = ""
            for encoding in (charset, "utf-8", "latin-1"):
                if not encoding:
                    continue
                try:
                    decoded = chunk.decode(encoding, errors="replace")
                    break
                except (LookupError, UnicodeError):
                    continue
            out.append(decoded or chunk.decode("latin-1", errors="replace"))
        else:
            out.append(str(chunk))
    return _unfold("".join(out))


def _address_from_pair(name: str, addr: str, raw: str) -> AddressInfo:
    addr = (addr or "").strip().strip("<>").strip().lower()
    if "@" not in addr:
        match = _EMAIL_RE.search(raw)
        if match:
            addr = match.group(0).lower()
            if not name:
                name = raw.replace(match.group(0), "")
    name = _CONTROL_RE.sub("", (name or "")).strip().strip("<>").strip().strip('"').strip("'").strip()
    local_part, _, domain = addr.rpartition("@") if "@" in addr else (addr, "", "")
    return AddressInfo(raw=raw, display_name=name, address=addr, local_part=local_part, domain=domain)


def parse_address(value: str) -> AddressInfo:
    """Parse a single mailbox ('Name <a@b>', 'a@b', '<a@b>'); tolerant of junk."""
    raw = decode_header_value(value or "").strip()
    if not raw:
        return AddressInfo()
    try:
        name, addr = parseaddr(raw)
    except Exception:  # noqa: BLE001
        name, addr = "", ""
    return _address_from_pair(name, addr, raw)


def parse_address_list(value: str) -> list[AddressInfo]:
    """Parse a comma-separated address list; falls back to scanning for
    anything that looks like an address."""
    raw = decode_header_value(value or "").strip()
    if not raw:
        return []
    result: list[AddressInfo] = []
    try:
        pairs = getaddresses([raw])
    except Exception:  # noqa: BLE001
        pairs = []
    for name, addr in pairs:
        if addr and "@" in addr:
            result.append(_address_from_pair(name, addr, f"{name} <{addr}>".strip() if name else addr))
    if not result:
        for match in _EMAIL_RE.finditer(raw):
            result.append(_address_from_pair("", match.group(0), match.group(0)))
    return result


def _first_header(msg: Message, name: str) -> str:
    try:
        value = msg.get(name)
    except Exception:  # noqa: BLE001
        return ""
    return decode_header_value(value) if value is not None else ""


def _joined_headers(msg: Message, name: str) -> str:
    try:
        values = msg.get_all(name) or []
    except Exception:  # noqa: BLE001
        return ""
    return ", ".join(decode_header_value(v) for v in values if v is not None)


def _parse_date(value: str) -> Optional[datetime]:
    if not value:
        return None
    try:
        parsed = parsedate_to_datetime(value)
    except (TypeError, ValueError, IndexError, OverflowError):
        return None
    if parsed is None:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


# --------------------------------------------------------------------------- #
# HTML -> text
# --------------------------------------------------------------------------- #
_BLOCK_TAGS = {
    "p", "div", "br", "li", "tr", "h1", "h2", "h3", "h4", "h5", "h6", "table", "ul", "ol",
    "blockquote", "section", "article", "header", "footer", "pre", "hr", "dd", "dt",
}
_SKIP_TAGS = {"script", "style", "head", "title", "noscript", "template"}


class _TextExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.chunks: list[str] = []
        self._skip_depth = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, Optional[str]]]) -> None:
        if tag in _SKIP_TAGS:
            self._skip_depth += 1
            return
        if tag in _BLOCK_TAGS:
            self.chunks.append("\n")
        if tag == "li":
            self.chunks.append("- ")
        elif tag in ("td", "th"):
            self.chunks.append(" ")

    def handle_endtag(self, tag: str) -> None:
        if tag in _SKIP_TAGS:
            self._skip_depth = max(0, self._skip_depth - 1)
        elif tag in _BLOCK_TAGS:
            self.chunks.append("\n")

    def handle_data(self, data: str) -> None:
        if not self._skip_depth:
            self.chunks.append(data)


def html_to_text(html: str) -> str:
    """Visible text of an HTML document: scripts/styles dropped, block
    elements separated by newlines, link text kept."""
    if not html:
        return ""
    extractor = _TextExtractor()
    try:
        extractor.feed(html)
        extractor.close()
    except Exception:  # noqa: BLE001 - keep whatever was extracted
        log.debug("html_to_text stopped early", exc_info=True)
    text = "".join(extractor.chunks)
    text = re.sub(r"[ \t\r\f\v ]+", " ", text)
    text = re.sub(r" *\n *", "\n", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


# --------------------------------------------------------------------------- #
# MIME walking
# --------------------------------------------------------------------------- #
def _parse_message(raw: bytes) -> Optional[Message]:
    try:
        return email.message_from_bytes(raw, policy=policy.compat32)
    except Exception:  # noqa: BLE001
        log.warning("message_from_bytes failed; retrying with a sanitised copy", exc_info=True)
    try:
        return email.message_from_string(raw.decode("utf-8", errors="replace"), policy=policy.compat32)
    except Exception:  # noqa: BLE001
        return None


def _iter_parts(part: Message, depth: int = 0) -> Iterator[tuple[str, Message]]:
    """Yield ('rfc822', part) for embedded messages and ('leaf', part) for
    every other non-multipart part, in document order."""
    if depth > _MAX_DEPTH:
        return
    try:
        ctype = part.get_content_type().lower()
    except Exception:  # noqa: BLE001
        ctype = "application/octet-stream"
    if ctype == "message/rfc822":
        yield "rfc822", part
        return
    if part.is_multipart():
        payload = part.get_payload()
        if isinstance(payload, list):
            for sub in payload:
                if isinstance(sub, Message):
                    yield from _iter_parts(sub, depth + 1)
            return
    yield "leaf", part


def _sanitize_filename(name: str) -> str:
    name = _CONTROL_RE.sub("", name or "").strip()
    name = re.split(r"[\\/]", name)[-1].strip()
    return name[:255]


def _part_filename(part: Message) -> str:
    name: object = None
    try:
        name = part.get_filename()
    except Exception:  # noqa: BLE001
        name = None
    if not name:
        try:
            name = part.get_param("name")
        except Exception:  # noqa: BLE001
            name = None
    if isinstance(name, tuple):
        try:
            name = collapse_rfc2231_value(name)
        except Exception:  # noqa: BLE001
            name = name[-1]
    return _sanitize_filename(decode_header_value(str(name))) if name else ""


def _extension(filename: str) -> str:
    if "." not in filename:
        return ""
    ext = filename.rsplit(".", 1)[-1].strip().lower()
    return ext if ext and len(ext) <= 10 and ext.isalnum() else ""


def _decode_payload(part: Message) -> bytes:
    try:
        payload = part.get_payload(decode=True)
    except Exception:  # noqa: BLE001
        payload = None
    if payload is None:
        try:
            raw = part.get_payload()
            payload = raw.encode("utf-8", errors="replace") if isinstance(raw, str) else b""
        except Exception:  # noqa: BLE001
            payload = b""
    return payload if isinstance(payload, bytes) else b""


def _decode_text(part: Message, issues: list[str], label: str) -> str:
    data = _decode_payload(part)
    if not data:
        return ""
    charset = None
    try:
        charset = part.get_content_charset()
    except Exception:  # noqa: BLE001
        charset = None
    for encoding in (charset, "utf-8"):
        if not encoding:
            continue
        try:
            return data.decode(encoding, errors="strict").replace("\r\n", "\n")
        except (LookupError, UnicodeError):
            continue
    # Neither the declared charset nor UTF-8 fits: keep the text, note the defect.
    try:
        text = data.decode(charset or "cp1252", errors="replace")
    except LookupError:
        text = data.decode("cp1252", errors="replace")
    issues.append(f"{label} part could not be decoded cleanly (declared charset {charset or 'none'})")
    return text.replace("\r\n", "\n")


def _embedded_message_bytes(part: Message) -> bytes:
    payload = part.get_payload()
    if isinstance(payload, list) and payload and isinstance(payload[0], Message):
        try:
            return payload[0].as_bytes()
        except Exception:  # noqa: BLE001
            try:
                return payload[0].as_string().encode("utf-8", errors="replace")
            except Exception:  # noqa: BLE001
                return b""
    return _decode_payload(part)


def _basic_meta(att: RawAttachment) -> AttachmentMeta:
    return AttachmentMeta(
        filename=att.filename,
        content_type=att.content_type,
        size=len(att.data),
        sha256=hashlib.sha256(att.data).hexdigest(),
        md5=hashlib.md5(att.data).hexdigest(),
        extension=_extension(att.filename),
    )


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #
def parse_email(raw: bytes) -> tuple[ParsedEmail, list[RawAttachment]]:
    """Parse one message.  Returns the structural view plus attachment bytes."""
    raw = bytes(raw or b"")
    parsed = ParsedEmail(
        raw_sha256=hashlib.sha256(raw).hexdigest(),
        raw_md5=hashlib.md5(raw).hexdigest(),
        raw_size=len(raw),
    )
    if not raw.strip():
        parsed.charset_issues.append("empty message")
        return parsed, []
    msg = _parse_message(raw)
    if msg is None:
        parsed.charset_issues.append("message could not be parsed")
        return parsed, []

    # Headers ------------------------------------------------------------
    headers: list[HeaderField] = []
    try:
        for name, value in msg.items():
            headers.append(HeaderField(name=str(name), value=decode_header_value(value)))
    except Exception:  # noqa: BLE001
        log.warning("header iteration failed", exc_info=True)
    parsed.headers = headers
    parsed.message_id = _first_header(msg, "Message-ID").strip().strip("<>").strip()
    parsed.subject = _first_header(msg, "Subject")
    parsed.date = _parse_date(_first_header(msg, "Date"))
    parsed.sender = parse_address(_first_header(msg, "From"))
    parsed.reply_to = parse_address_list(_joined_headers(msg, "Reply-To"))
    parsed.return_path = parse_address(_first_header(msg, "Return-Path"))
    parsed.to = parse_address_list(_joined_headers(msg, "To"))
    parsed.cc = parse_address_list(_joined_headers(msg, "Cc"))
    parsed.mailer = _first_header(msg, "X-Mailer") or _first_header(msg, "User-Agent")
    if not headers:
        parsed.charset_issues.append("no headers found")

    # Bodies and attachments ----------------------------------------------
    text_parts: list[str] = []
    html_parts: list[str] = []
    raw_attachments: list[RawAttachment] = []
    issues = parsed.charset_issues
    counter = 0
    for kind, part in _iter_parts(msg):
        counter += 1
        if counter > _MAX_PARTS:
            issues.append("message has more MIME parts than the parser limit; remainder ignored")
            break
        try:
            ctype = part.get_content_type().lower()
        except Exception:  # noqa: BLE001
            ctype = "application/octet-stream"
        try:
            disposition = str(part.get("Content-Disposition") or "").lower()
        except Exception:  # noqa: BLE001
            disposition = ""
        filename = _part_filename(part)
        is_attachment_disposition = disposition.strip().startswith("attachment")
        if kind == "rfc822":
            data = _embedded_message_bytes(part)
            raw_attachments.append(RawAttachment(filename or f"forwarded-{counter}.eml", "message/rfc822", data))
            continue
        if ctype == "text/plain" and not is_attachment_disposition and not filename:
            text_parts.append(_decode_text(part, issues, "text/plain"))
            continue
        if ctype == "text/html" and not is_attachment_disposition and not filename:
            html_parts.append(_decode_text(part, issues, "text/html"))
            continue
        data = _decode_payload(part)
        try:
            content_id = str(part.get("Content-ID") or "").strip().strip("<>").strip()
        except Exception:  # noqa: BLE001
            content_id = ""
        is_inline = disposition.strip().startswith("inline") or (bool(content_id) and ctype.startswith("image/"))
        if not filename:
            guessed = mimetypes.guess_extension(ctype) or ""
            filename = f"part-{counter}{guessed or '.bin'}"
        raw_attachments.append(RawAttachment(filename, ctype, data, content_id=content_id, is_inline=is_inline))

    parsed.text_body = "\n\n".join(p for p in text_parts if p).strip()
    parsed.html_body = "\n\n".join(p for p in html_parts if p).strip()
    parsed.has_html = bool(parsed.html_body)
    if not parsed.text_body and parsed.html_body:
        parsed.text_body = html_to_text(parsed.html_body)
    if not parsed.text_body and not parsed.html_body and not raw_attachments and not msg.is_multipart():
        # Non-MIME message whose Content-Type could not be interpreted.
        parsed.text_body = _decode_text(msg, issues, "body")
    parsed.attachments = [_basic_meta(att) for att in raw_attachments]
    return parsed, raw_attachments
