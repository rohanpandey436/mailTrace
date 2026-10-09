from __future__ import annotations

import argparse
import base64
import html
import json
import random
import sys
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
BACKEND = ROOT / "backend"
for entry in (BACKEND, BACKEND / "tests", HERE):
    if str(entry) not in sys.path:
        sys.path.insert(0, str(entry))

SEED = 20260928


def number_vectors(rng: random.Random) -> list[dict[str, Any]]:
    values = [
        0.0, -0.0, 0.5, 1.5, 2.5, 0.125, 0.375, 0.625, 0.875, 0.005, 0.015, 0.025, 0.045, 1.005, 2.675, 0.1, 0.2,
        0.30000000000000004, 1e-7, 123456.789, 99.995, 9.995, 0.9999, 0.99995, 49.5, 50.5, 24.5, 25.5, 74.5, 75.5,
        -0.5, -1.5, -2.5, -0.125, 1 / 3, 2 / 3, 100.0, 59.999999, 0.55, 0.45, 0.35, 0.65, 0.85, 0.7000000000000001,
    ]
    values += [rng.uniform(0, 100) for _ in range(400)]
    values += [round(rng.uniform(0, 1), rng.randrange(1, 5)) for _ in range(300)]
    values += [rng.randrange(0, 2000) / 8 for _ in range(200)]
    values += [rng.randrange(0, 4000) / 200 for _ in range(200)]
    out = []
    for value in values:
        out.append({
            "value": value,
            "fixed": [f"{value:.{places}f}" for places in range(5)],
            "signed3": f"{value:+.3f}",
            "round": [round(value, places) for places in range(7)],
            "round_int": round(value),
            "repr": repr(float(value)),
            "sci3": f"{value:.3e}",
        })
    return out


def utf8_vectors(rng: random.Random) -> list[dict[str, Any]]:
    seeds = [
        b"", b"plain", "café ₹ \U0001F600".encode(), b"\xe2\x82", b"\xe2\x82A", b"\xf0\x9f\x98A", b"\xc3",
        b"\x80", b"\xc0\xaf", b"\xed\xa0\x80", b"\xf4\x90\x80\x80", b"\xf8\x88\x80\x80\x80", b"\xe0\x80\x80",
        b"\xf0\x80\x80\x80", b"A\xffB\xfeC", b"\xef\xbb\xbfbom", b"\xe2\x82\xac\xe2\x82", b"\xf0\x9f", b"\xf0",
        b"\xf0\x9f\x98", b"\xc2\xa0", b"\xdf\xbf", b"\xe1\x80", b"\xee\x80\x80", b"\xef\xbf\xbf",
    ]
    alphabet = [0x41, 0x20, 0x80, 0xBF, 0xC2, 0xC3, 0xE0, 0xE2, 0xED, 0xEF, 0xF0, 0xF4, 0xF5, 0xFF, 0x9F, 0xA0, 0x8F, 0x90]
    for _ in range(600):
        seeds.append(bytes(rng.choice(alphabet) for _ in range(rng.randrange(1, 9))))
    out = []
    for raw in seeds:
        try:
            strict: str | None = raw.decode("utf-8")
        except UnicodeDecodeError:
            strict = None
        replaced = raw.decode("utf-8", errors="replace")
        out.append({
            "raw": base64.b64encode(raw).decode("ascii"),
            "strict": strict,
            "replace": [ord(ch) for ch in replaced],
        })
    return out


def string_vectors(rng: random.Random) -> list[dict[str, Any]]:
    samples = [
        "", " ", "  padded  ", "\tTabbed\n", "\x1cfs\x1d", "\x85nel\x85", " nbsp ", " em ",
        "﻿bom﻿", "a b  c\td\ne", "one", "  lead", "trail  ", "a,b,,c", ",a,", "x=1;y=2", "no separator",
        "धमकी दो", "emoji \U0001F600 \U0001F4B0 tail", "MiXeD Case İstanbul ΣΣ",
        "straße Über", "hello world", "HELLO", "hello-world foo_bar", "ǅungla", "o'neil mc-donald",
    ]
    out = []
    for text in samples:
        out.append({
            "text": text,
            "strip": text.strip(),
            "lstrip": text.lstrip(),
            "rstrip": text.rstrip(),
            "strip_chars": text.strip(" ,;"),
            "split": text.split(),
            "split1": text.split(None, 1),
            "split_comma": text.split(","),
            "split_comma1": text.split(",", 1),
            "rsplit_comma1": text.rsplit(",", 1),
            "partition": list(text.partition("=")),
            "rpartition": list(text.rpartition(",")),
            "count_a": text.count("a"),
            "lower": text.lower(),
            "upper": text.upper(),
            "title": text.title(),
            "capitalize": text.capitalize(),
            "length": len(text),
            "isalnum": text.isalnum(),
            "isalpha": text.isalpha(),
            "slice": text[:5],
            "join_words": " ".join(text.split()),
        })
    return out


def entity_vectors() -> list[dict[str, Any]]:
    samples = [
        "plain", "&amp;", "&amp", "&lt;b&gt;", "&nbsp;x", "&#65;&#x41;&#X41;", "&#0;", "&#128512;", "&#x1F600;",
        "&#xD800;", "&#1114112;", "&#x80;&#x9f;&#150;", "&notit;", "&notin;", "&amp;amp;", "&unknown;", "&;", "&#;",
        "&#x;", "a&b", "AT&T", "&copy 2026", "&copy;2026", "&rarr;&larr;", "&#13;&#10;", "&#x0B;", "&#xFFFE;",
        "&NotEqualTilde;", "&acE;", "&#38;#38;", "&quot;quoted&quot; &apos;single&apos;", "&#x110000;", "&#9;tab",
    ]
    return [{"text": text, "unescape": html.unescape(text)} for text in samples]


def regex_vectors() -> list[dict[str, Any]]:
    import importlib
    import re

    from export_data import ENGINE_MODULES, module_export
    from export_fixtures import collect

    texts: list[str] = []
    from app.core import ai_engine, parser

    for _name, raw in collect()[::3]:
        parsed, _ = parser.parse_email(raw)
        texts.append(ai_engine.normalize_text(parsed.subject, parsed.text_body or parser.html_to_text(parsed.html_body))[:6000])
        texts.append((parsed.html_body or parsed.text_body)[:6000])
        for header in parsed.headers:
            if header.name.lower() in ("received", "authentication-results", "received-spf", "dkim-signature"):
                texts.append(header.value)
    texts += [
        "pay rs. 5,000 or ₹5000 to raju.k@okaxis, wallet bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh, ifsc HDFC0001234",
        "call +91 98765 43210 or 1800-123-4567 now, visit www.example.co.in/login?x=1, http://1.2.3.4/a",
        "पैसे दो वरना जान से मार दूंगा, 50000 रुपये",
        "from mail.example.com (mail.example.com [203.0.113.5]) by mx.google.com with ESMTPS id x1 for <a@b.in> (version=TLS1_3); Mon, 7 Sep 2026 10:00:00 +0530",
        "from [IPv6:2001:db8::1] (helo=[192.168.0.2]) by relay.example.org with esmtpa; 1 Jan 2026 00:00:00 -0000",
    ]
    out = []
    modules = [importlib.import_module(f"app.core.{name}") for name in ENGINE_MODULES]
    from app.ai import url_model

    modules.append(url_model)
    for module in modules:
        _constants, patterns = module_export(module)
        short = module.__name__.rsplit(".", 1)[-1]
        for name, entry in patterns.items():
            compiled = re.compile(entry["pattern"], entry["flags"])
            results = []
            for index, text in enumerate(texts):
                found = [[m.start(), m.end(), m.group(0)] for m in compiled.finditer(text)]
                if found:
                    results.append({"text": index, "matches": found[:40]})
            out.append({"module": short, "name": name, "results": results})
    return [{"texts": texts, "patterns": out}]


def html_vectors(rng: random.Random, fuzz: int | None = None) -> list[dict[str, Any]]:
    from app.core import link_analyzer, parser
    from export_fixtures import collect
    from html_cases import HANDCRAFTED, fragments, random_markup, record

    bodies: list[str] = []
    for _name, raw in collect():
        parsed, _ = parser.parse_email(raw)
        if parsed.html_body:
            bodies.append(parsed.html_body)
    texts = list(HANDCRAFTED) + bodies
    texts += fragments(rng, list(HANDCRAFTED) + bodies, 2500 if fuzz is None else fuzz)
    texts += random_markup(rng, 1500 if fuzz is None else max(1, fuzz * 3 // 5))
    out = []
    seen: set[str] = set()
    for text in texts:
        if text in seen:
            continue
        seen.add(text)
        entry = record(text)
        entry["html"] = text
        entry["text"] = parser.html_to_text(text)
        entry["links"] = [[url, anchor] for url, anchor in link_analyzer.extract_urls("", text)]
        entry["stripped"] = link_analyzer._strip_tags(text)
        out.append(entry)
    return out


ESCAPED = ("message", "parsed", "codec", "url", "pipeline")


def write(target: Path, document: Any, escaped: bool = False) -> None:
    target.write_text(json.dumps(document, ensure_ascii=escaped, separators=(",", ":")), encoding="utf-8", newline="\n")
    print(f"{target.name} written ({target.stat().st_size / 1024:.0f} KB)")


def main(argv: list[str] | None = None) -> int:
    import binary_cases
    import message_cases
    import parsed_cases
    import codec_cases
    import pipeline_cases
    import url_cases

    parser = argparse.ArgumentParser(description="Write vectors that pin the JavaScript helpers to Python behaviour.")
    parser.add_argument("--out", type=Path, default=HERE.parent / "tests" / "fixtures")
    parser.add_argument("--only", default="", help="comma separated vector files to write, without the _vectors.json suffix")
    parser.add_argument("--fuzz", type=int, default=None, help="number of fuzzed cases per set (default: the full counts)")
    args = parser.parse_args(argv)
    fuzz = args.fuzz
    args.out.mkdir(parents=True, exist_ok=True)

    def helpers() -> dict[str, Any]:
        rng = random.Random(SEED)
        return {
            "numbers": number_vectors(rng),
            "utf8": utf8_vectors(rng),
            "strings": string_vectors(rng),
            "entities": entity_vectors(),
            "regex": regex_vectors(),
        }

    builders: dict[str, Any] = {
        "py": helpers,
        "html": lambda: html_vectors(random.Random(SEED + 1), fuzz),
        "binary": lambda: binary_cases.build(random.Random(SEED + 2)),
        "message": lambda: message_cases.build(random.Random(SEED + 3), **({} if fuzz is None else {"fuzz": fuzz})),
        "parsed": lambda: parsed_cases.build(random.Random(SEED + 4), **({} if fuzz is None else {"fuzz": fuzz})),
        "codec": lambda: codec_cases.build(random.Random(SEED + 5)),
        "url": lambda: url_cases.build(random.Random(SEED + 6)),
        "pipeline": lambda: pipeline_cases.build(random.Random(SEED + 7), **({} if fuzz is None else {"fuzz": fuzz})),
    }
    wanted = [name.strip() for name in args.only.split(",") if name.strip()] or list(builders)
    for name in wanted:
        if name not in builders:
            raise SystemExit(f"unknown vector set '{name}'; choose from {', '.join(builders)}")
        write(args.out / f"{name}_vectors.json", builders[name](), escaped=name in ESCAPED)
    return 0


if __name__ == "__main__":
    sys.exit(main())
