from __future__ import annotations

import base64
import binascii
import hashlib
import random
from email import _encoded_words
from email.message import _decode_uu
from typing import Any, Callable

LF = bytes([10])
CR = bytes([13])
TAB = bytes([9])
FF = bytes([12])
BASE64_ALPHABET = b"ABCabc012+/=-_ !" + LF + CR + bytes([255])
QP_ALPHABET = b"=0A9fFgG_ ab==" + LF + CR + TAB + bytes([0xE9])
UU_ALPHABET = bytes(range(30, 100)) + LF + CR


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def attempt(call: Callable[[], bytes]) -> dict[str, Any]:
    try:
        return {"ok": b64(call())}
    except Exception as exc:
        return {"error": type(exc).__name__}


def noise(rng: random.Random, alphabet: bytes, low: int, high: int) -> bytes:
    return bytes(rng.choice(alphabet) for _ in range(rng.randrange(low, high)))


def corrupt(rng: random.Random, data: bytes, alphabet: bytes) -> bytes:
    chars = bytearray(data)
    for _ in range(rng.randrange(0, 4)):
        action = rng.randrange(3)
        position = rng.randrange(len(chars) + 1)
        if action == 0:
            chars.insert(position, rng.choice(alphabet))
        elif action == 1 and chars:
            del chars[min(position, len(chars) - 1)]
        elif chars:
            chars[min(position, len(chars) - 1)] = rng.choice(alphabet)
    return bytes(chars)


def base64_cases(rng: random.Random) -> list[dict[str, Any]]:
    inputs = [b"", b"=", b"==", b"A", b"AA", b"AAA", b"AAAA", b"AA==", b"AAA=", b"A===", b"AA=A", b"AA==AA==", b"=AAA"]
    for _ in range(1500):
        inputs.append(noise(rng, BASE64_ALPHABET, 0, 24))
    for _ in range(1500):
        raw = bytes(rng.randrange(256) for _ in range(rng.randrange(0, 40)))
        encoded = base64.encodebytes(raw) if rng.random() < 0.5 else base64.b64encode(raw)
        inputs.append(corrupt(rng, encoded, BASE64_ALPHABET))
    out = []
    for data in inputs:
        out.append({
            "data": b64(data),
            "lenient": attempt(lambda: binascii.a2b_base64(data)),
            "strict": attempt(lambda: binascii.a2b_base64(data, strict_mode=True)),
            "decode_b": b64(_encoded_words.decode_b(data)[0]),
        })
    return out


def qp_cases(rng: random.Random) -> list[dict[str, Any]]:
    out = []
    for index in range(2500):
        data = noise(rng, QP_ALPHABET, 0, 24)
        header = index % 2 == 0
        out.append({"data": b64(data), "header": header, "out": b64(binascii.a2b_qp(data, header=header))})
    return out


def uu_cases(rng: random.Random) -> list[dict[str, Any]]:
    out = []
    for _ in range(1500):
        raw = bytes(rng.randrange(256) for _ in range(rng.randrange(0, 46)))
        line = binascii.b2a_uu(raw, backtick=rng.random() < 0.5)
        data = corrupt(rng, line, UU_ALPHABET) or b" "
        out.append({"data": b64(data), "out": attempt(lambda: binascii.a2b_uu(data))})
    for _ in range(1000):
        data = noise(rng, UU_ALPHABET, 1, 30)
        out.append({"data": b64(data), "out": attempt(lambda: binascii.a2b_uu(data))})
    return out


def uu_documents(rng: random.Random) -> list[dict[str, Any]]:
    headers = [
        b"begin 644 file.bin", b"begin 0o644 x", b"begin 888 bad", b"begin  644 two", b"begin 644", b"begin",
        b"BEGIN 644 x", b"begin +7 x", b"begin 7_7 x", b"begin _7 x", b"begin 0o_7 x", b"begin " + TAB + b"7 x",
        b"begin 0O17 x", b"begin -7 x", b"begin 7__7 x", b"begin 7_ x", b"begin 0o x", b"begin 08 x",
    ]
    endings = [b"end", b" end ", b"end" + FF, b"END", b"", b"`"]
    out = []
    for _ in range(600):
        raw = bytes(rng.randrange(256) for _ in range(rng.randrange(0, 120)))
        lines = [rng.choice(headers)] if rng.random() < 0.9 else []
        if rng.random() < 0.3:
            lines.insert(0, b"some preface text")
        for start in range(0, len(raw), 45):
            lines.append(binascii.b2a_uu(raw[start:start + 45]).rstrip(LF))
        if rng.random() < 0.7:
            lines.append(b"`")
        lines.append(rng.choice(endings))
        separator = rng.choice([LF, CR + LF, CR])
        document = corrupt(rng, separator.join(lines) + separator, UU_ALPHABET)
        out.append({"data": b64(document), "out": attempt(lambda: _decode_uu(document))})
    return out


def blake_cases(rng: random.Random) -> list[dict[str, Any]]:
    lengths = [0, 1, 2, 3, 63, 64, 65, 127, 128, 129, 255, 256, 257, 300, 1024]
    out = []
    for index in range(300):
        length = lengths[index] if index < len(lengths) else rng.randrange(0, 400)
        data = bytes(rng.randrange(256) for _ in range(length))
        out.append({
            "data": b64(data),
            "d8": hashlib.blake2b(data, digest_size=8).hexdigest(),
            "d64": hashlib.blake2b(data).hexdigest(),
            "d20": hashlib.blake2b(data, digest_size=20).hexdigest(),
        })
    return out


def build(rng: random.Random) -> dict[str, Any]:
    return {
        "base64": base64_cases(rng),
        "qp": qp_cases(rng),
        "uu": uu_cases(rng),
        "uu_documents": uu_documents(rng),
        "blake2b": blake_cases(rng),
    }
