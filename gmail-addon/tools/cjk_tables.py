from __future__ import annotations

import gzip
import json
import sys
from typing import Any

TWO_BYTE = (
    "gb2312", "gbk", "gb18030", "big5", "cp950", "big5hkscs", "euc_kr", "cp949", "johab",
    "shift_jis", "cp932", "shift_jis_2004", "shift_jisx0213", "euc_jp", "euc_jis_2004", "euc_jisx0213",
)
THREE_BYTE = ("euc_jp", "euc_jis_2004", "euc_jisx0213")
SUPPLEMENTARY = ("big5hkscs", "gb18030", "euc_jis_2004", "euc_jisx0213", "shift_jis_2004", "shift_jisx0213")
DESIGNATIONS = {
    "jisx0208": ("iso2022_jp", b"\x1b$B"),
    "jisx0212": ("iso2022_jp_1", b"\x1b$(D"),
    "jisx0213_1_2000": ("iso2022_jp_3", b"\x1b$(O"),
    "jisx0213_1_2004": ("iso2022_jp_2004", b"\x1b$(Q"),
    "jisx0213_2": ("iso2022_jp_2004", b"\x1b$(P"),
    "ksc5601": ("iso2022_kr", b"\x1b$)C\x0e"),
    "gb2312_iso": ("iso2022_jp_2", b"\x1b$A"),
}
BASES = {
    "gbk": "gb2312", "gb18030": "gbk", "cp950": "big5", "big5hkscs": "big5", "cp949": "euc_kr",
    "cp932": "shift_jis", "shift_jis_2004": "shift_jis", "shift_jisx0213": "shift_jis_2004",
    "euc_jis_2004": "euc_jp", "euc_jisx0213": "euc_jis_2004",
    "euc_jis_2004_3": "euc_jp_3", "euc_jisx0213_3": "euc_jis_2004_3",
    "jisx0213_1_2000": "jisx0213_1_2004",
}
DERIVED = {
    "jisx0208": "euc_jp",
    "jisx0212": "euc_jp_3",
    "jisx0213_1_2004": "euc_jis_2004",
    "ksc5601": "euc_kr",
    "gb2312_iso": "gb2312",
}
DBCS = chr(0x80)
ISO2022_ORDER = {
    "iso2022_jp": ["B" + DBCS, "J"],
    "iso2022_jp_1": ["B" + DBCS, "D" + DBCS, "J"],
    "iso2022_jp_2": ["B" + DBCS, "D" + DBCS, "C" + DBCS, "A" + DBCS, "J"],
    "iso2022_jp_2004": ["B" + DBCS, "Q" + DBCS, "P" + DBCS],
    "iso2022_jp_3": ["B" + DBCS, "O" + DBCS, "P" + DBCS],
    "iso2022_jp_ext": ["B" + DBCS, "D" + DBCS, "J", "I"],
    "iso2022_kr": ["C" + DBCS],
}
MARK_TABLES = {
    "A" + DBCS: "gb2312_iso", "B" + DBCS: "jisx0208", "C" + DBCS: "ksc5601", "D" + DBCS: "jisx0212",
    "O" + DBCS: "jisx0213_1_2000", "P" + DBCS: "jisx0213_2", "Q" + DBCS: "jisx0213_1_2004",
}
ESCAPES = {
    b"\x1b(J": "J", b"\x1b(I": "I", b"\x1b$@": "@" + DBCS, b"\x1b$A": "A" + DBCS, b"\x1b$B": "B" + DBCS,
    b"\x1b$(C": "C" + DBCS, b"\x1b$(D": "D" + DBCS, b"\x1b$(O": "O" + DBCS, b"\x1b$(P": "P" + DBCS,
    b"\x1b$(Q": "Q" + DBCS, b"\x1b$)C": "C" + DBCS, b"\x1b$(B": "B" + DBCS, b"\x1b$(A": "A" + DBCS,
}


def decode_one(codec: str, data: bytes) -> str | None:
    try:
        return data.decode(codec)
    except (UnicodeDecodeError, ValueError):
        return None


def encode_one(codec: str, text: str) -> bytes | None:
    try:
        return text.encode(codec)
    except (UnicodeEncodeError, ValueError):
        return None


def error_length(codec: str, data: bytes) -> int | None:
    try:
        data.decode(codec)
        return None
    except UnicodeDecodeError as exc:
        return exc.end - exc.start


def single_bytes(codec: str) -> dict[int, str]:
    out: dict[int, str] = {}
    for value in range(0x100):
        text = decode_one(codec, bytes([value]))
        if text is not None and text:
            out[value] = text
    return out


def two_byte_table(codec: str, singles: dict[int, str]) -> tuple[dict[int, str], list[int]]:
    table: dict[int, str] = {}
    long_errors: list[int] = []
    for lead in range(0x80, 0x100):
        if lead in singles:
            continue
        for trail in range(0x100):
            data = bytes([lead, trail])
            text = decode_one(codec, data)
            if text is not None and text:
                table[lead << 8 | trail] = text
                continue
            if codec == "gb18030" and 0x30 <= trail <= 0x39:
                continue
            if codec == "euc_kr" and lead == 0xA4 and trail == 0xD4:
                continue
            length = error_length(codec, data + b"AAA")
            if length == 2:
                long_errors.append(lead << 8 | trail)
            elif length != 1:
                raise SystemExit(f"{codec}: unexpected error length {length} for {data!r}")
    return table, long_errors


def three_byte_table(codec: str) -> dict[int, str]:
    table: dict[int, str] = {}
    for second in range(0x80, 0x100):
        for third in range(0x80, 0x100):
            text = decode_one(codec, bytes([0x8F, second, third]))
            if text is not None and text:
                table[second << 8 | third] = text
    return table


def designated_table(codec: str, prefix: bytes) -> dict[int, str]:
    table: dict[int, str] = {}
    for row in range(0x21, 0x7F):
        for col in range(0x21, 0x7F):
            text = decode_one(codec, prefix + bytes([row, col]))
            if text is not None and text:
                table[row << 8 | col] = text
    return table


def mask7(table: dict[int, str]) -> dict[int, str]:
    out: dict[int, str] = {}
    for key, text in table.items():
        lead, trail = key >> 8, key & 0xFF
        if lead >= 0xA1 and trail >= 0xA1:
            out[(lead & 0x7F) << 8 | (trail & 0x7F)] = text
    return out


def gb18030_ranges() -> list[list[int]]:
    ranges: list[list[int]] = []
    linear = 0
    for b1 in range(0x81, 0x85):
        for b2 in range(0x30, 0x3A):
            for b3 in range(0x81, 0xFF):
                for b4 in range(0x30, 0x3A):
                    text = decode_one("gb18030", bytes([b1, b2, b3, b4]))
                    if text is not None and len(text) == 1:
                        code = ord(text)
                        if ranges and ranges[-1][0] + ranges[-1][2] == linear and ranges[-1][1] + ranges[-1][2] == code:
                            ranges[-1][2] += 1
                        else:
                            ranges.append([linear, code, 1])
                    linear += 1
    return ranges


def jamo_tables() -> dict[str, dict[int, int]]:
    cho: dict[int, int] = {}
    jung: dict[int, int] = {}
    jong: dict[int, int] = {}
    for value in range(0xA1, 0xBF):
        text = decode_one("euc_kr", bytes([0xA4, 0xD4, 0xA4, value, 0xA4, 0xBF, 0xA4, 0xD4]))
        if text is not None and len(text) == 1:
            cho[value] = (ord(text) - 0xAC00) // 588
        text = decode_one("euc_kr", bytes([0xA4, 0xD4, 0xA4, 0xA1, 0xA4, 0xBF, 0xA4, value]))
        if text is not None and len(text) == 1:
            jong[value] = (ord(text) - 0xAC00) % 28
    for value in range(0xBF, 0xD4):
        text = decode_one("euc_kr", bytes([0xA4, 0xD4, 0xA4, 0xA1, 0xA4, value, 0xA4, 0xD4]))
        if text is not None and len(text) == 1:
            jung[value] = ((ord(text) - 0xAC00) % 588) // 28
    return {"cho": cho, "jung": jung, "jong": jong}


def delta(table: dict[int, str], base: dict[int, str] | None) -> dict[str, Any]:
    runs: list[list[Any]] = []
    pairs: list[list[Any]] = []
    for key in sorted(table):
        text = table[key]
        if base is not None and base.get(key) == text:
            continue
        if len(text) != 1:
            pairs.append([key, text])
            continue
        if runs and runs[-1][0] + len(runs[-1][1]) == key:
            runs[-1][1] += text
        else:
            runs.append([key, text])
    removed = sorted(key for key in (base or {}) if key not in table)
    return {"runs": runs, "pairs": pairs, "removed": removed}


def key_bytes(key: int, width: int) -> list[int]:
    if width == 3:
        return [0x8F, key >> 8, key & 0xFF]
    return [key >> 8, key & 0xFF]


def default_dbcs(codec: str, singles: dict[int, str], tables: dict[str, dict[int, str]]) -> tuple[dict[str, list[int]], dict[str, list[int]]]:
    forward: dict[str, list[int]] = {}
    pairs: dict[str, list[int]] = {}
    for byte in sorted(singles):
        forward.setdefault(singles[byte], [byte])
    for name, width in ((codec, 2), (f"{codec}_3", 3)):
        table = tables.get(name)
        if table is None:
            continue
        for key in sorted(table):
            text = table[key]
            if len(text) == 1:
                forward.setdefault(text, key_bytes(key, width))
            else:
                pairs.setdefault(text, key_bytes(key, width))
    return forward, pairs


def gb18030_four(code: int, ranges: list[list[int]]) -> list[int] | None:
    if 0xD800 <= code <= 0xDFFF:
        return None
    if code >= 0x10000:
        linear = code - 0x10000
        b1 = 0x90 + linear // 12600
    else:
        linear = -1
        for start, ucs, count in ranges:
            if ucs <= code < ucs + count:
                linear = start + (code - ucs)
                break
        if linear < 0:
            return None
        b1 = 0x81 + linear // 12600
    rest = linear % 12600
    return [b1, 0x30 + rest // 1260, 0x81 + (rest % 1260) // 10, 0x30 + rest % 10]


def euc_kr_jamo(code: int, jamo: dict[str, dict[int, int]]) -> list[int] | None:
    if not 0xAC00 <= code <= 0xD7A3:
        return None
    offset = code - 0xAC00
    cho = {index: byte for byte, index in jamo["cho"].items()}
    jung = {index: byte for byte, index in jamo["jung"].items()}
    jong = {index: byte for byte, index in jamo["jong"].items()}
    jong[0] = 0xD4
    parts = [cho.get(offset // 588), jung.get(offset % 588 // 28), jong.get(offset % 28)]
    if None in parts:
        return None
    return [0xA4, 0xD4, 0xA4, parts[0], 0xA4, parts[1], 0xA4, parts[2]]


def code_points(codec: str) -> range:
    return range(0x30000) if codec in SUPPLEMENTARY else range(0x10000)


def encoder_export(
    codec: str, singles: dict[int, str], tables: dict[str, dict[int, str]], ranges: list[list[int]], jamo: dict[str, dict[int, int]]
) -> dict[str, Any]:
    forward, pairs = default_dbcs(codec, singles, tables)
    overrides: list[list[Any]] = []
    removed: list[str] = []
    for code in code_points(codec):
        if 0xD800 <= code <= 0xDFFF:
            continue
        char = chr(code)
        expected = encode_one(codec, char)
        guess = forward.get(char)
        if guess is None and codec == "gb18030":
            guess = gb18030_four(code, ranges)
        if guess is None and codec == "euc_kr":
            guess = euc_kr_jamo(code, jamo)
        if expected is None:
            if guess is not None:
                removed.append(char)
        elif guess is None or list(expected) != guess:
            overrides.append([char, list(expected)])
    pair_overrides: list[list[Any]] = []
    for text, guess in pairs.items():
        expected = encode_one(codec, text)
        if expected is None:
            removed.append(text)
        elif list(expected) != guess:
            pair_overrides.append([text, list(expected)])
    return {"overrides": overrides, "pairs": pair_overrides, "removed": removed}


def parse_iso2022(codec: str, data: bytes) -> tuple[str, list[int]] | None:
    mark = "B"
    rest = data
    while rest[:1] == b"\x1b":
        found = None
        for escape, target in ESCAPES.items():
            if rest.startswith(escape):
                found = (escape, target)
                break
        if found is None:
            return None
        rest = rest[len(found[0]) :]
        mark = found[1]
    if codec == "iso2022_kr":
        if rest[:1] != b"\x0e" or rest[-1:] != b"\x0f":
            return None
        rest = rest[1:-1]
    elif rest.endswith(b"\x1b(B"):
        rest = rest[:-3]
    return mark, list(rest)


def default_iso2022(codec: str, tables: dict[str, dict[int, str]]) -> tuple[dict[str, tuple[str, list[int]]], dict[str, tuple[str, list[int]]]]:
    forward: dict[str, tuple[str, list[int]]] = {}
    pairs: dict[str, tuple[str, list[int]]] = {}
    for mark in ISO2022_ORDER[codec]:
        if mark == "J":
            forward.setdefault(chr(0xA5), ("J", [0x5C]))
            forward.setdefault(chr(0x203E), ("J", [0x7E]))
            continue
        if mark == "I":
            for code in range(0xFF61, 0xFFA0):
                forward.setdefault(chr(code), ("I", [code - 0xFF40]))
            continue
        table = tables[MARK_TABLES[mark]]
        for key in sorted(table):
            text = table[key]
            if len(text) == 1:
                forward.setdefault(text, (mark, [key >> 8, key & 0xFF]))
            else:
                pairs.setdefault(text, (mark, [key >> 8, key & 0xFF]))
    return forward, pairs


def iso2022_export(codec: str, tables: dict[str, dict[int, str]]) -> dict[str, Any]:
    forward, pairs = default_iso2022(codec, tables)
    overrides: list[list[Any]] = []
    removed: list[str] = []
    for code in range(0x80, 0x30000 if codec in ("iso2022_jp_2004", "iso2022_jp_3") else 0x10000):
        if 0xD800 <= code <= 0xDFFF:
            continue
        char = chr(code)
        expected = encode_one(codec, char)
        guess = forward.get(char)
        if expected is None:
            if guess is not None:
                removed.append(char)
            continue
        parsed = parse_iso2022(codec, expected)
        if parsed is None:
            raise SystemExit(f"{codec}: cannot parse {expected!r} for {char!r}")
        if guess is None or (parsed[0], parsed[1]) != (guess[0], guess[1]):
            overrides.append([char, parsed[0], parsed[1]])
    pair_overrides: list[list[Any]] = []
    for text, guess in pairs.items():
        expected = encode_one(codec, text)
        if expected is None:
            removed.append(text)
            continue
        parsed = parse_iso2022(codec, expected)
        if parsed is None or (parsed[0], parsed[1]) != (guess[0], guess[1]):
            pair_overrides.append([text, parsed[0] if parsed else "", parsed[1] if parsed else []])
    return {"order": ISO2022_ORDER[codec], "overrides": overrides, "pairs": pair_overrides, "removed": removed}


def hz_export(tables: dict[str, dict[int, str]]) -> dict[str, Any]:
    forward: dict[str, list[int]] = {}
    table = tables["gb2312_iso"]
    for key in sorted(table):
        forward.setdefault(table[key], [key >> 8, key & 0xFF])
    overrides: list[list[Any]] = []
    removed: list[str] = []
    for code in range(0x80, 0x10000):
        if 0xD800 <= code <= 0xDFFF:
            continue
        char = chr(code)
        expected = encode_one("hz", char)
        guess = forward.get(char)
        if expected is None:
            if guess is not None:
                removed.append(char)
            continue
        if not (expected.startswith(b"~{") and expected.endswith(b"~}")):
            raise SystemExit(f"hz: unexpected {expected!r} for {char!r}")
        actual = list(expected[2:-2])
        if guess is None or actual != guess:
            overrides.append([char, actual])
    return {"overrides": overrides, "pairs": [], "removed": removed}


def build() -> dict[str, Any]:
    singles = {codec: single_bytes(codec) for codec in TWO_BYTE}
    tables: dict[str, dict[int, str]] = {}
    long_errors: dict[str, list[int]] = {}
    for codec in TWO_BYTE:
        tables[codec], long_errors[codec] = two_byte_table(codec, singles[codec])
    for codec in THREE_BYTE:
        tables[f"{codec}_3"] = three_byte_table(codec)
    for name, (codec, prefix) in DESIGNATIONS.items():
        tables[name] = designated_table(codec, prefix)
    encoded: dict[str, Any] = {}
    for name, table in tables.items():
        if name in DERIVED:
            entry = delta(table, mask7(tables[DERIVED[name]]))
            entry["derive"] = DERIVED[name]
        elif name in BASES:
            entry = delta(table, tables[BASES[name]])
            entry["base"] = BASES[name]
        else:
            entry = delta(table, None)
        encoded[name] = entry
    ranges = gb18030_ranges()
    jamo = jamo_tables()
    encoders: dict[str, Any] = {}
    for codec in TWO_BYTE:
        encoders[codec] = encoder_export(codec, singles[codec], tables, ranges, jamo)
    for codec in ISO2022_ORDER:
        encoders[codec] = iso2022_export(codec, tables)
    encoders["hz"] = hz_export(tables)
    return {
        "tables": encoded,
        "singles": {codec: {str(key): value for key, value in sorted(items.items())} for codec, items in singles.items()},
        "errlen2": {codec: keys for codec, keys in long_errors.items() if keys},
        "gb18030_ranges": ranges,
        "jamo": {name: {str(key): value for key, value in items.items()} for name, items in jamo.items()},
        "encode": encoders,
    }


def main() -> int:
    data = build()
    for name, entry in data["tables"].items():
        chars = sum(len(run[1]) for run in entry["runs"])
        origin = entry.get("base") or (entry.get("derive") and f"mask7({entry['derive']})") or "-"
        print(f"{name:20s} runs {len(entry['runs']):5d} chars {chars:6d} pairs {len(entry['pairs']):3d} removed {len(entry['removed']):3d} from {origin}")
    for codec, entry in data["encode"].items():
        print(f"encode {codec:16s} overrides {len(entry['overrides']):5d} pairs {len(entry['pairs']):3d} removed {len(entry['removed']):4d}")
    raw = json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    print("json bytes", len(raw), "gzip bytes", len(gzip.compress(raw, 9)), "ranges", len(data["gb18030_ranges"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
