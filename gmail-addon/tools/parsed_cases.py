from __future__ import annotations

import base64
import random
from typing import Any

from mime_cases import ALPHABET, address_cases, date_cases, fuzzed, handcrafted, mutate


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def parsed_case(name: str, raw: bytes) -> dict[str, Any]:
    from app.core import parser

    parsed, attachments = parser.parse_email(raw)
    payload = parsed.model_dump(mode="json")
    payload.pop("parse_ms", None)
    return {
        "name": name,
        "raw": b64(raw),
        "parsed": payload,
        "raw_attachments": [
            {
                "filename": item.filename,
                "content_type": item.content_type,
                "size": len(item.data),
                "sha256": __import__("hashlib").sha256(item.data).hexdigest(),
                "content_id": item.content_id,
                "is_inline": item.is_inline,
            }
            for item in attachments
        ],
    }


def header_texts(rng: random.Random) -> list[str]:
    texts: list[str] = []
    for _name, raw in address_cases() + date_cases():
        for line in raw.split(b"\r\n"):
            if b":" in line:
                texts.append(line.split(b":", 1)[1].strip().decode("latin-1"))
    extra = [
        "=?utf-8?Q?S=C3=A9nder?= <s@example.com>",
        "=?utf-8?B?4KSw4KS+4KSc?= <raj@example.in>, =?utf-8?Q?B=C3=B6b?= <bob@example.org>",
        "\"=?utf-8?Q?Quoted?=\" <q@example.com>",
        "a@example.com (=?utf-8?Q?comment?=)",
        "=?utf-8?Q?a@example.com?=",
        "=?utf-8?Q?Alice_<a@example.com>?=",
        "=?utf-8?Q?=E2=82=B9?= <r@example.com>",
        "=?x-unknown?Q?=E9?= <u@example.com>",
        "=?utf-8?B?!!!!?= <bad@example.com>",
        "=?utf-8?Q?first?= =?utf-8?Q?second?= <two@example.com>",
        "Mon, 7 Sep 2026 10:00:00 +0530 (=?utf-8?Q?IST?=)",
    ]
    texts += extra
    base = [text for text in texts if text]
    for _ in range(2500):
        chosen = rng.choice(base)
        texts.append(mutate(rng, chosen.encode("latin-1", errors="replace")).decode("latin-1"))
    unique: list[str] = []
    seen: set[str] = set()
    for text in texts:
        if text not in seen:
            seen.add(text)
            unique.append(text)
    return unique


def header_vectors(rng: random.Random) -> list[dict[str, Any]]:
    from email.utils import getaddresses, parseaddr

    from app.core import parser

    out = []
    for text in header_texts(rng):
        entry: dict[str, Any] = {"text": text, "decoded": parser.decode_header_value(text)}
        try:
            entry["parseaddr"] = list(parseaddr(text))
        except Exception as exc:
            entry["parseaddr"] = {"error": type(exc).__name__}
        try:
            entry["getaddresses"] = [list(pair) for pair in getaddresses([text])]
        except Exception as exc:
            entry["getaddresses"] = {"error": type(exc).__name__}
        entry["address"] = parser.parse_address(text).model_dump(mode="json")
        entry["addresses"] = [item.model_dump(mode="json") for item in parser.parse_address_list(text)]
        date = parser._parse_date(text)
        entry["date"] = date.isoformat().replace("+00:00", "Z") if date else None
        out.append(entry)
    return out


def build(rng: random.Random, fuzz: int = 2500) -> dict[str, Any]:
    from export_fixtures import collect

    crafted = handcrafted()
    emails = list(crafted) + [(f"corpus_{name}", raw) for name, raw in collect()]
    emails += fuzzed(rng, [raw for _name, raw in crafted], fuzz)
    seen: set[bytes] = set()
    cases = []
    for name, raw in emails:
        if raw in seen:
            continue
        seen.add(raw)
        cases.append(parsed_case(name, raw))
    return {"emails": cases, "headers": header_vectors(rng)}
