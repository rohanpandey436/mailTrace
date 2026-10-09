from __future__ import annotations

import base64
import random
from typing import Any

BACKSLASH = bytes([92])
SAMPLE_TEXTS = [
    "", "plain ascii", "café au lait", "₹5,000 due", "आपका खाता", "日本語のテキスト", "中文文本 €", "한국어",
    "emoji 😀 money 💰", "mixed ascii + अक्षर + 😀", "a+b-c", "+-", "tabs\tand\nnewlines", "Привет мир",
    "xn--test", "ñandú.example", "bücher", "faß", "ΑΣ", "İstanbul",
]
LABEL_TEXTS = ["café", "bücher", "ñandú", "рф", "中国", "भारत", "faß", "ǅabc", "a-b", "日本", "испытание", "테스트", "😀", "a"*63, "a"*64, "", "-abc", "abc-", "ab--cd", "xn--abc"]
CJK_TEXTS = [
    "日本語のテキスト", "半角ｶﾀｶﾅ", "か゚ き゚", "𠂉俱剝吞噓", "中文文本", "繁體中文，廣東話", "한국어 테스트", "ㅤ", "€ ① ② ¥ ‾ ～ 〜",
    "髙﨑 鷗", "a" + chr(92) + "b~c", "line1\nline2", "mixed 日本 and 中文 and 한글", "𨘥 𠄎", "Ａ１ｚ", "「引用」・『二重』",
]
CJK_FAMILIES: dict[tuple[str, ...], bytes] = {
    ("gb2312", "gbk", "gb18030", "hz"): bytes(
        [0x21, 0x30, 0x39, 0x3A, 0x41, 0x7B, 0x7D, 0x7E, 0x0A, 0x80, 0x81, 0x84, 0x85, 0x8F, 0x90, 0xA1, 0xA4, 0xA8, 0xAA, 0xB0, 0xD7, 0xE3, 0xFE, 0xFF],
    ),
    ("big5", "cp950", "big5hkscs"): bytes([0x21, 0x40, 0x41, 0x7E, 0x7F, 0x80, 0x81, 0x87, 0x88, 0xA0, 0xA1, 0xA3, 0xA4, 0xC6, 0xC7, 0xC8, 0xF9, 0xFA, 0xFE, 0xFF]),
    ("euc_kr", "cp949", "johab", "iso2022_kr"): bytes(
        [0x0E, 0x0F, 0x1B, 0x21, 0x24, 0x29, 0x43, 0x41, 0x7E, 0x80, 0x81, 0x84, 0xA1, 0xA4, 0xBE, 0xBF, 0xD3, 0xD4, 0xD8, 0xFE, 0xFF],
    ),
    ("shift_jis", "cp932", "shift_jis_2004", "shift_jisx0213"): bytes(
        [0x21, 0x40, 0x5C, 0x7E, 0x7F, 0x80, 0x81, 0x87, 0x9F, 0xA0, 0xA1, 0xDF, 0xE0, 0xEA, 0xEF, 0xF0, 0xF9, 0xFC, 0xFD, 0xFF],
    ),
    ("euc_jp", "euc_jis_2004", "euc_jisx0213"): bytes([0x21, 0x41, 0x7E, 0x80, 0x8E, 0x8F, 0xA1, 0xA2, 0xAD, 0xAE, 0xB0, 0xCF, 0xF4, 0xFE, 0xFF]),
    ("iso2022_jp", "iso2022_jp_1", "iso2022_jp_2", "iso2022_jp_2004", "iso2022_jp_3", "iso2022_jp_ext"): (
        bytes([0x1B, 0x0E, 0x0F, 0x0A, 0x20, 0x7F, 0x80, 0xA1]) + b"$()&.@ABCDFIJNOPQZ!#$%&*.0Aab~"
    ),
}
ENCODE_SPECIALS = [
    chr(0xA5), chr(0x203E), chr(0xFF5E), chr(0x301C), chr(0xFF3C), chr(0x2212), chr(0x2225), chr(0xA6), chr(0xFFE2), chr(0x80), chr(0xA0),
    chr(0xE9), chr(0xB620), chr(0x3164), chr(0x1100), chr(0x1F600), chr(0xFFFD), chr(0xFFFE), chr(0xCA) + chr(0x304), chr(0x304B) + chr(0x309A),
    chr(0x309A), "~", chr(92), "\n", "\r\n", "\t", chr(0x2014), chr(0x2015), chr(0xB7), chr(0x2022), chr(0x2027), chr(0x20AC), chr(0xE000),
    chr(0xF8F0), chr(0x9AD9), chr(0x4E2D), chr(0x65E5), chr(0xAC00), chr(0x4E00), chr(0x2016), chr(0x2225) + chr(0x2016),
]
SURROGATE_TEXTS = [chr(0xDC80), chr(0xDCFF), chr(0xDCC3) + chr(0xDCA9), chr(0xD800), chr(0xDFFF)]
ISO2022_PREFIXES = (b"\x1b$B", b"\x1b$(D", b"\x1b$(Q", b"\x1b$(P", b"\x1b$A", b"\x1b$)C\x0e")


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def outcome(data: bytes, codec: str, errors: str) -> dict[str, Any]:
    try:
        return {"ok": data.decode(codec, errors)}
    except Exception as exc:
        return {"error": type(exc).__name__}


def encode_outcome(text: str, codec: str, errors: str) -> dict[str, Any]:
    try:
        return {"ok": b64(text.encode(codec, errors))}
    except Exception as exc:
        return {"error": type(exc).__name__}


def corrupt(rng: random.Random, data: bytes, alphabet: bytes) -> bytes:
    chars = bytearray(data)
    for _ in range(rng.randrange(0, 4)):
        action = rng.randrange(4)
        position = rng.randrange(len(chars) + 1)
        if action == 0:
            chars.insert(position, rng.choice(alphabet))
        elif action == 1 and chars:
            del chars[min(position, len(chars) - 1)]
        elif action == 2 and chars:
            chars[min(position, len(chars) - 1)] = rng.choice(alphabet)
        elif chars:
            chars = chars[: max(1, position)]
    return bytes(chars)


def noise(rng: random.Random, alphabet: bytes, low: int, high: int) -> bytes:
    return bytes(rng.choice(alphabet) for _ in range(rng.randrange(low, high)))


def cases_for(rng: random.Random, codec: str, alphabet: bytes, count: int, encoder: str | None = None) -> list[dict[str, Any]]:
    inputs: list[bytes] = []
    if encoder:
        for text in SAMPLE_TEXTS:
            try:
                encoded = text.encode(encoder)
            except Exception:
                continue
            inputs.append(encoded)
            for _ in range(count // (2 * len(SAMPLE_TEXTS)) + 1):
                inputs.append(corrupt(rng, encoded, alphabet))
    for _ in range(count // 2):
        inputs.append(noise(rng, alphabet, 0, 20))
    out = []
    for data in inputs:
        out.append({"codec": codec, "data": b64(data), "strict": outcome(data, codec, "strict"), "replace": outcome(data, codec, "replace")})
    return out


def cjk_cases(rng: random.Random) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for codecs, alphabet in CJK_FAMILIES.items():
        for codec in codecs:
            inputs: list[bytes] = []
            for text in CJK_TEXTS + SAMPLE_TEXTS:
                try:
                    encoded = text.encode(codec)
                except Exception:
                    continue
                inputs.append(encoded)
                for _ in range(20):
                    inputs.append(corrupt(rng, encoded, alphabet))
            for _ in range(900):
                inputs.append(noise(rng, alphabet, 0, 24))
            for data in inputs:
                out.append({"codec": codec, "data": b64(data), "strict": outcome(data, codec, "strict"), "replace": outcome(data, codec, "replace")})
    return out


def decodable(codec: str, data: bytes) -> str | None:
    try:
        return data.decode(codec)
    except (UnicodeDecodeError, ValueError):
        return None


def encode_pool(codec: str) -> list[str]:
    pool: list[str] = []
    for lead in range(0x81, 0xFF, 7):
        for trail in (0x40, 0x5B, 0x7E, 0xA1, 0xC3, 0xFE):
            text = decodable(codec, bytes([lead, trail]))
            if text:
                pool.append(text)
    for lead in range(0x21, 0x7F, 5):
        for trail in (0x21, 0x40, 0x5F, 0x7E):
            for prefix in ISO2022_PREFIXES:
                text = decodable(codec, prefix + bytes([lead, trail]))
                if text and text.isprintable():
                    pool.append(text)
    return pool + ENCODE_SPECIALS + CJK_TEXTS + SAMPLE_TEXTS


def encode_entries(codec: str, texts: list[str]) -> list[dict[str, Any]]:
    return [
        {
            "encode": True, "codec": codec, "text": text,
            "strict": encode_outcome(text, codec, "strict"),
            "surrogateescape": encode_outcome(text, codec, "surrogateescape"),
        }
        for text in texts
    ]


def encode_cases(rng: random.Random) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for codecs in CJK_FAMILIES:
        for codec in codecs:
            pool = encode_pool(codec)
            texts: list[str] = list(CJK_TEXTS) + list(SAMPLE_TEXTS) + ENCODE_SPECIALS
            for _ in range(500):
                pieces = [rng.choice(pool) for _ in range(rng.randrange(1, 7))]
                if rng.random() < 0.15:
                    pieces.insert(rng.randrange(len(pieces) + 1), rng.choice(SURROGATE_TEXTS))
                texts.append("".join(pieces))
            out += encode_entries(codec, texts)
    for codec in ("utf-8", "utf-16", "utf-16-le", "utf-16-be", "utf-32", "utf-32-be", "cp1252", "iso8859-1", "iso8859-7", "koi8-r", "us-ascii", "utf-8-sig", "utf-7"):
        texts = list(CJK_TEXTS) + list(SAMPLE_TEXTS) + ENCODE_SPECIALS + ["caf" + chr(0xE9) + chr(0xDCFF), chr(0xD83D), "abc" + chr(0xDC80) + "def"]
        if codec == "utf-7":
            texts += ["a+b", "+", "a-b", "hi+-there", "x" + chr(0) + "y", chr(0x7F) + "~" + chr(92), chr(0xE9) + chr(0xE9) + "-", chr(0xE9) + "A", chr(0xE9) + "a", chr(0x1F600) + "!", "tab" + chr(9) + "nl" + chr(10), "1+1=2"]
        out += encode_entries(codec, texts)
    return out


def idna_cases(rng: random.Random) -> list[dict[str, Any]]:
    inputs: list[bytes] = []
    for text in LABEL_TEXTS + SAMPLE_TEXTS:
        for label in (text, text.upper(), "www." + text + ".com", text + ".", "." + text):
            try:
                inputs.append(label.encode("idna"))
            except Exception:
                pass
            try:
                inputs.append(("xn--" + text.encode("punycode").decode("ascii")).encode("ascii"))
            except Exception:
                pass
            try:
                inputs.append(("XN--" + text.encode("punycode").decode("ascii").upper()).encode("ascii"))
            except Exception:
                pass
    alphabet = b"abcxyz0123456789-.XN" + bytes([0xE9])
    base = list(inputs)
    for _ in range(1500):
        inputs.append(corrupt(rng, rng.choice(base), alphabet))
    out = []
    seen = set()
    for data in inputs:
        if data in seen:
            continue
        seen.add(data)
        out.append({"codec": "idna", "data": b64(data), "strict": outcome(data, "idna", "strict"), "replace": outcome(data, "idna", "replace")})
    return out


def build(rng: random.Random) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    out += cjk_cases(rng)
    out += encode_cases(rng)
    out += cases_for(rng, "utf-7", b"ABCabcxyz+-/0189 !~." + bytes([0xE9, 0x80]), 3000, "utf-7")
    escape_alphabet = BACKSLASH + b"uUxN{}0123456789abcdefgn'" + bytes([0xE9, 0x0A])
    out += cases_for(rng, "unicode_escape", escape_alphabet, 3000, "unicode_escape")
    out += cases_for(rng, "raw_unicode_escape", escape_alphabet, 3000, "raw_unicode_escape")
    out += cases_for(rng, "punycode", b"abcxyz0123456789-ABCXYZ" + bytes([0xE9]), 3000, "punycode")
    out += cases_for(rng, "hz", b"~{}\n abcxyz0123!" + bytes([0x21, 0x30, 0x50, 0x77, 0x7E, 0x80, 0xB0]), 2500, "hz")
    out += cases_for(rng, "charmap", bytes(range(256)), 300)
    out += cases_for(rng, "undefined", bytes(range(256)), 50)
    for codec in ("utf-16", "utf-16-le", "utf-16-be", "utf-32", "utf-32-be", "utf-8-sig"):
        out += cases_for(rng, codec, bytes([0, 0x41, 0x42, 0xD8, 0xDC, 0xFF, 0xFE, 0x00, 0x10, 0x11, 0xEF, 0xBB, 0xBF]), 1200, codec)
    for codec in ("cp1252", "iso8859-1", "iso8859-15", "koi8-r", "cp437", "mac-roman", "tis-620", "cp037", "iso8859-7"):
        out += cases_for(rng, codec, bytes(range(256)), 600)
    out += idna_cases(rng)
    return out
