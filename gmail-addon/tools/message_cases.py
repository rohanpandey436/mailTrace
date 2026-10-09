from __future__ import annotations

import base64
import email
import random
from email import policy
from email.message import Message
from typing import Any, Callable

from mime_cases import fuzzed, handcrafted


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def attempt(call: Callable[[], Any]) -> dict[str, Any]:
    try:
        return {"ok": call()}
    except Exception as exc:
        return {"error": type(exc).__name__}


def plain(value: Any) -> Any:
    if isinstance(value, tuple):
        return {"extended": [plain(item) for item in value]}
    if isinstance(value, list):
        return [plain(item) for item in value]
    return value


def params(msg: Message, header: str) -> Any:
    found = msg.get_params(header=header)
    if found is None:
        return None
    return [[name, plain(value)] for name, value in found]


def tree(msg: Message) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "headers": [[name, str(value)] for name, value in msg.items()],
        "type": msg.get_content_type(),
        "boundary": attempt(msg.get_boundary),
        "filename": attempt(lambda: plain(msg.get_filename())),
        "charset": attempt(msg.get_content_charset),
        "params": attempt(lambda: params(msg, "content-type")),
        "disposition": attempt(lambda: params(msg, "content-disposition")),
        "preamble": msg.preamble,
        "epilogue": msg.epilogue,
        "unixfrom": msg.get_unixfrom(),
        "defects": [type(defect).__name__ for defect in msg.defects],
    }
    payload = vars(msg)["_payload"]
    if isinstance(payload, list):
        entry["parts"] = [tree(part) for part in payload if isinstance(part, Message)]
    else:
        entry["payload"] = payload
        entry["decoded"] = attempt(lambda: b64(msg.get_payload(decode=True)))
    return entry


def describe(name: str, raw: bytes) -> dict[str, Any]:
    case: dict[str, Any] = {"name": name, "raw": b64(raw)}
    try:
        msg = email.message_from_bytes(raw, policy=policy.compat32)
    except Exception as exc:
        case["error"] = type(exc).__name__
        return case
    case["tree"] = tree(msg)
    case["as_bytes"] = attempt(lambda: b64(email.message_from_bytes(raw, policy=policy.compat32).as_bytes()))
    case["as_string"] = attempt(
        lambda: b64(email.message_from_bytes(raw, policy=policy.compat32).as_string().encode("utf-8", errors="replace"))
    )
    return case


def collect(rng: random.Random, fuzz: int) -> list[tuple[str, bytes]]:
    from export_fixtures import collect as corpus

    crafted = handcrafted()
    emails = list(crafted)
    emails += [(f"corpus_{name}", raw) for name, raw in corpus()]
    emails += fuzzed(rng, [raw for _name, raw in crafted], fuzz)
    seen: set[bytes] = set()
    unique = []
    for name, raw in emails:
        if raw in seen:
            continue
        seen.add(raw)
        unique.append((name, raw))
    return unique


def build(rng: random.Random, fuzz: int = 3000) -> list[dict[str, Any]]:
    return [describe(name, raw) for name, raw in collect(rng, fuzz)]
