from __future__ import annotations

import argparse
import base64
import enum
import gzip
import hashlib
import html.entities
import json
import math
import mimetypes
import re
import struct
import sys
import tempfile
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
BACKEND = ROOT / "backend"
for entry in (BACKEND, BACKEND / "tests", HERE):
    if str(entry) not in sys.path:
        sys.path.insert(0, str(entry))

NL = chr(10)
CHUNK = 60000
TF_TABLE_SIZE = 4096
ENGINE_MODULES = (
    "knowledge", "parser", "header_analyzer", "auth_checker", "link_analyzer", "file_analyzer",
    "ai_engine", "domain_intel", "geoip_mapper", "threat_intel", "scoring",
)
SELFTEST_SAMPLES = ("phishing_sbi_kyc", "legit_transactional", "fraud_lottery_advance_fee", "impersonation_ceo_gift_cards")


def _plain(value: Any) -> Any:
    if isinstance(value, enum.Enum):
        return value.value
    if isinstance(value, bool) or value is None or isinstance(value, (int, str)):
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else None
    if isinstance(value, bytes):
        return {"__bytes__": base64.b64encode(value).decode("ascii")}
    if isinstance(value, (set, frozenset)):
        items = [_plain(item) for item in value]
        return {"__set__": sorted(items, key=lambda item: json.dumps(item, ensure_ascii=False, sort_keys=True))}
    if isinstance(value, (list, tuple)):
        return [_plain(item) for item in value]
    if isinstance(value, dict):
        return {"__dict__": [[_plain(key), _plain(item)] for key, item in value.items()]}
    raise TypeError(type(value).__name__)


def _pattern(value: re.Pattern[str]) -> dict[str, Any]:
    return {"pattern": value.pattern, "flags": int(value.flags)}


def module_export(module: Any) -> tuple[dict[str, Any], dict[str, Any]]:
    constants: dict[str, Any] = {}
    patterns: dict[str, Any] = {}
    for name, value in vars(module).items():
        if name.startswith("__") or callable(value) or isinstance(value, type(sys)):
            continue
        if isinstance(value, re.Pattern):
            if isinstance(value.pattern, str):
                patterns[name] = _pattern(value)
            continue
        if isinstance(value, dict) and value and all(isinstance(item, re.Pattern) for item in value.values()):
            for key, item in value.items():
                patterns[f"{name}.{key}"] = _pattern(item)
            continue
        if not (name.isupper() or name.startswith("_") and name[1:].replace("_", "").isupper()):
            continue
        try:
            constants[name] = _plain(value)
        except TypeError:
            continue
    return constants, patterns


def knowledge_blob(cfg: Any) -> dict[str, Any]:
    import importlib

    from app.ai import model_trainer, url_model
    from app.schemas import ENGINE_VERSION

    constants: dict[str, Any] = {}
    patterns: dict[str, Any] = {}
    for name in ENGINE_MODULES:
        module = importlib.import_module(f"app.core.{name}")
        constants[name], patterns[name] = module_export(module)
    constants["url_model"], patterns["url_model"] = module_export(url_model)
    constants["model_trainer"] = {"LABELS": list(model_trainer.LABELS), "MODEL_VERSION": model_trainer.MODEL_VERSION}
    constants["config"] = {"DEFAULT_WEIGHTS": _plain(dict(cfg.weights)), "PILLARS": list(cfg.weights)}
    pure = mimetypes.MimeTypes()
    return {
        "engine_version": ENGINE_VERSION,
        "constants": constants,
        "patterns": patterns,
        "entities": dict(html.entities.html5),
        "mimetypes": {ctype: extensions[0] for ctype, extensions in pure.types_map_inv[True].items() if extensions},
        "codecs": codec_tables(),
        "email_charsets": email_charsets(),
        "unicode": unicode_tables(),
        "stringprep": stringprep_tables(),
    }


def ranges(predicate: Any) -> list[list[int]]:
    out: list[list[int]] = []
    for point in range(sys.maxunicode + 1):
        if not predicate(chr(point)):
            continue
        if out and out[-1][1] == point - 1:
            out[-1][1] = point
        else:
            out.append([point, point])
    return out


def unicode_tables() -> dict[str, Any]:
    import unicodedata

    return {
        "version": unicodedata.unidata_version,
        "digit": ranges(str.isdigit),
        "alpha": ranges(str.isalpha),
        "alnum": ranges(str.isalnum),
    }


MULTIBYTE_CODECS = (
    "big5", "big5hkscs", "cp932", "cp949", "cp950", "euc_jis_2004", "euc_jisx0213", "euc_jp", "euc_kr",
    "gb18030", "gb2312", "gbk", "hz", "iso2022_jp", "iso2022_jp_1", "iso2022_jp_2", "iso2022_jp_2004",
    "iso2022_jp_3", "iso2022_jp_ext", "iso2022_kr", "johab", "shift_jis", "shift_jis_2004", "shift_jisx0213",
)
UNICODE_CODECS = (
    "utf_8", "utf_8_sig", "utf_16", "utf_16_le", "utf_16_be", "utf_32", "utf_32_le", "utf_32_be",
)
SPECIAL_CODECS = ("utf_7", "idna", "punycode", "unicode_escape", "raw_unicode_escape", "charmap", "undefined")
UNPORTED_CODECS = ("mbcs", "oem")


def codec_tables() -> dict[str, Any]:
    import codecs
    import encodings
    import encodings.aliases
    import pkgutil

    single: dict[str, Any] = {}
    for info in pkgutil.iter_modules(encodings.__path__):
        name = info.name
        if name in MULTIBYTE_CODECS or name in UNICODE_CODECS or name in SPECIAL_CODECS or name in UNPORTED_CODECS:
            continue
        if name == "aliases":
            continue
        try:
            entry = codecs.lookup(name)
        except LookupError:
            continue
        if not getattr(entry, "_is_text_encoding", True):
            continue
        table: list[int] = []
        try:
            for byte in range(256):
                try:
                    decoded = bytes([byte]).decode(name)
                except UnicodeDecodeError:
                    table.append(-1)
                    continue
                if len(decoded) != 1:
                    raise ValueError(name)
                table.append(ord(decoded))
            probe = bytes(range(256)) * 2
            if len(probe.decode(name, errors="replace")) != len(probe):
                raise ValueError(name)
        except (ValueError, LookupError, UnicodeError):
            continue
        if table[:128] == list(range(128)):
            single[name] = {"high": table[128:]}
        else:
            single[name] = {"table": table}
    return {
        "aliases": dict(encodings.aliases.aliases),
        "single": single,
        "multibyte": list(MULTIBYTE_CODECS),
        "unicode": list(UNICODE_CODECS),
        "special": list(SPECIAL_CODECS),
    }


def stringprep_tables() -> dict[str, Any]:
    import stringprep
    import unicodedata

    old = unicodedata.ucd_3_2_0
    prohibited = ("c12", "c22", "c3", "c4", "c5", "c6", "c7", "c8", "c9")
    mapping: dict[str, str] = {}
    nfkc: dict[str, str] = {}
    for point in range(sys.maxunicode + 1):
        char = chr(point)
        mapped = stringprep.map_table_b2(char)
        if mapped != char:
            mapping[str(point)] = mapped
        if 0xD800 <= point <= 0xDFFF or old.category(char) == "Cn":
            continue
        legacy = old.normalize("NFKC", char)
        if legacy != unicodedata.normalize("NFKC", char):
            nfkc[str(point)] = legacy
    return {
        "b1": ranges(stringprep.in_table_b1),
        "b2": mapping,
        "prohibited": ranges(lambda char: any(getattr(stringprep, "in_table_" + name)(char) for name in prohibited)),
        "d1": ranges(stringprep.in_table_d1),
        "d2": ranges(stringprep.in_table_d2),
        "unassigned": ranges(lambda char: old.category(char) == "Cn" and unicodedata.category(char) != "Cn"),
        "nfkc": nfkc,
    }


def email_charsets() -> dict[str, Any]:
    from email import charset

    return {
        "aliases": dict(charset.ALIASES),
        "charsets": {name: [row[0], row[1], row[2]] for name, row in charset.CHARSETS.items()},
        "codec_map": dict(charset.CODEC_MAP),
    }


def psl_blob() -> dict[str, Any]:
    from app.core import link_analyzer

    extractor = link_analyzer._EXTRACTOR
    if extractor is None:
        raise SystemExit("tldextract is required to export the public suffix list")
    import idna

    suffixes = sorted(extractor._get_tld_extractor().tlds_excl_private)
    punycode: dict[str, str] = {}
    for suffix in suffixes:
        for label in suffix.split("."):
            if label.isascii() or label in ("*", "!"):
                continue
            bare = label[1:] if label.startswith("!") else label
            try:
                punycode[idna.encode(bare).decode("ascii")] = bare
            except idna.IDNAError:
                continue
    return {"suffixes": suffixes, "fallback": sorted(link_analyzer._FALLBACK_SUFFIXES), "punycode": punycode}


def _floats(values: Any) -> bytes:
    import numpy as np

    return bytes(np.ascontiguousarray(np.asarray(values, dtype="<f8")).tobytes())


def text_model_blobs(cfg: Any) -> tuple[dict[str, Any], bytes]:
    import numpy as np

    from app.ai import model_trainer

    pipeline = model_trainer.load_or_train(cfg)
    features = dict(pipeline.named_steps["features"].transformer_list)
    word, char = features["word"], features["char"]
    classifier = pipeline.named_steps["clf"]
    expected = getattr(pipeline, model_trainer.EXPECTED_ATTR, None)

    def vocabulary(vectorizer: Any) -> list[str]:
        ordered = sorted(vectorizer.vocabulary_.items(), key=lambda item: item[1])
        assert [index for _, index in ordered] == list(range(len(ordered)))
        return [term for term, _ in ordered]

    word_terms, char_terms = vocabulary(word), vocabulary(char)
    n_word, n_char = len(word_terms), len(char_terms)
    coef = np.asarray(classifier.coef_, dtype=np.float64)
    assert coef.shape == (len(classifier.classes_), n_word + n_char), coef.shape
    baseline = np.zeros(n_word, dtype=np.float64)
    if expected is not None:
        usable = min(n_word, len(expected))
        baseline[:usable] = np.asarray(expected, dtype=np.float64)[:usable]
    tf_table = 1.0 + np.log(np.arange(1, TF_TABLE_SIZE + 1, dtype=np.float64))

    segments = [
        ("idf_word", word.idf_),
        ("idf_char", char.idf_),
        ("coef", coef.ravel()),
        ("intercept", classifier.intercept_),
        ("expected_word", baseline),
        ("tf_table", tf_table),
    ]
    layout: dict[str, list[int]] = {}
    payload = b""
    for name, values in segments:
        raw = _floats(values)
        layout[name] = [len(payload) // 8, len(raw) // 8]
        payload += raw
    meta = {
        "version": model_trainer.MODEL_VERSION,
        "labels": list(model_trainer.LABELS),
        "classes": [str(item) for item in classifier.classes_],
        "n_word": n_word,
        "n_char": n_char,
        "word": {
            "ngram_range": list(word.ngram_range), "sublinear_tf": bool(word.sublinear_tf),
            "lowercase": bool(word.lowercase), "token_pattern": word.token_pattern, "norm": word.norm,
        },
        "char": {
            "ngram_range": list(char.ngram_range), "sublinear_tf": bool(char.sublinear_tf),
            "lowercase": bool(char.lowercase), "norm": char.norm, "analyzer": char.analyzer,
        },
        "layout": layout,
        "vocabulary_word": word_terms,
        "vocabulary_char": char_terms,
        "corpus_sha256": model_trainer.corpus_sha256(cfg.corpus_path),
    }
    return meta, payload


def url_model_blob(cfg: Any) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    import numpy as np
    import onnx

    from app.ai import onnx_url, url_model

    graph = onnx.load(str(onnx_url.BUNDLED))
    node = next(item for item in graph.graph.node if item.op_type == "TreeEnsembleClassifier")
    attrs = {item.name: onnx.helper.get_attribute_value(item) for item in node.attribute}
    modes = [mode.decode("ascii") for mode in attrs["nodes_modes"]]
    assert set(modes) <= {"BRANCH_LT", "LEAF"}, set(modes)
    assert attrs["post_transform"] == b"LOGISTIC" and list(attrs["classlabels_int64s"]) == [0, 1]
    assert set(attrs["class_ids"]) == {0} and len(attrs["base_values"]) == 1

    leaf_weight = {(tree, leaf): weight for tree, leaf, weight in zip(attrs["class_treeids"], attrs["class_nodeids"], attrs["class_weights"])}
    trees: dict[int, dict[int, list[Any]]] = {}
    for position, tree in enumerate(attrs["nodes_treeids"]):
        node_id = attrs["nodes_nodeids"][position]
        if modes[position] == "LEAF":
            record = [1, 0, 0.0, 0, 0, 0, float(leaf_weight[(tree, node_id)])]
        else:
            record = [
                0,
                int(attrs["nodes_featureids"][position]),
                float(attrs["nodes_values"][position]),
                int(attrs["nodes_truenodeids"][position]),
                int(attrs["nodes_falsenodeids"][position]),
                int(attrs["nodes_missing_value_tracks_true"][position]),
                0.0,
            ]
        trees.setdefault(int(tree), {})[int(node_id)] = record
    ordered = []
    for tree in sorted(trees):
        nodes = trees[tree]
        assert sorted(nodes) == list(range(len(nodes))), (tree, sorted(nodes))
        ordered.append([nodes[index] for index in range(len(nodes))])

    rng = np.random.default_rng(20260928)
    width = len(url_model.FEATURE_NAMES)
    rows = rng.uniform(0.0, 3.0, size=(400, width))
    rows[:, :4] = rng.integers(0, 300, size=(400, 4))
    rows[:, 12:27] = rng.integers(0, 2, size=(400, 15))
    rows[:, 28] = rng.integers(0, 9000, size=400)
    rows[rng.random(size=(400, width)) < 0.08] = np.nan
    rows = rows.astype(np.float32)
    scorer = onnx_url.load("", onnx_url.BUNDLED)
    if scorer is None:
        raise SystemExit("onnxruntime is required to export URL model test vectors")
    probabilities = scorer.predict_proba(rows)[:, 1]
    vectors = [
        {"features": [None if math.isnan(float(v)) else float(v) for v in row], "probability": float(p)}
        for row, p in zip(rows, probabilities)
    ]
    model = {
        "version": url_model.MODEL_VERSION,
        "features": list(url_model.FEATURE_NAMES),
        "base_value": float(attrs["base_values"][0]),
        "trees": ordered,
        "fingerprint": next((item.value for item in graph.metadata_props if item.key == onnx_url.FINGERPRINT_KEY), ""),
    }
    return model, vectors


def text_vectors(cfg: Any) -> list[dict[str, Any]]:
    from app.ai import model_trainer

    pipeline = model_trainer.load_or_train(cfg)
    texts, _labels = model_trainer.load_corpus(cfg.corpus_path)
    chosen = texts[::7] + [
        "",
        "ok",
        "a",
        "urgent urgent urgent verify your account now!!! ₹ 5,00,000",
        "पैसे दो वरना जान से मार दूंगा",
        "emoji 😀 test 💰💰 café naïve über straße",
        "tab\tseparated\nnew line\r\nwindows  double  space \u00a0nbsp",
    ]
    vectors = []
    for text in chosen:
        lowered = text.lower()
        label, probabilities = model_trainer.predict(pipeline, lowered)
        vectors.append({
            "text": lowered,
            "label": label,
            "probabilities": probabilities,
            "shap": [[token, weight] for token, weight in model_trainer.shap_values(pipeline, lowered, label, top_k=12)],
            "explain": model_trainer.explain(pipeline, lowered, label),
        })
    return vectors


def selftest_blob(cfg: Any) -> dict[str, Any]:
    from app.core import pipeline
    from export_fixtures import addon_config

    cases = []
    for stem in SELFTEST_SAMPLES:
        raw = (ROOT / "samples" / f"{stem}.eml").read_bytes()
        result = pipeline.analyze_bytes(raw, f"{stem}.eml", None, cfg)
        cases.append({
            "name": stem,
            "raw": base64.b64encode(raw).decode("ascii"),
            "category": result.verdict.category.value,
            "risk_score": result.verdict.risk_score,
            "severity": result.verdict.severity.value,
            "ml_category": result.nlp.ml_category.value,
            "sha256": result.email.raw_sha256,
            "simhash": result.email.fuzzy.simhash,
            "finding_ids": [f"{finding.module}:{finding.id}" for finding in result.findings],
        })
    return {"config": addon_config(cfg), "cases": cases}


def pack(value: Any) -> bytes:
    if isinstance(value, bytes):
        raw = value
    else:
        raw = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return gzip.compress(raw, compresslevel=9, mtime=0)


PART_LIMIT = 600_000


def render(name: str, packed: bytes) -> str:
    return render_files(name, packed)[0][1]


def _chunk_lines(encoded: str) -> str:
    chunks = [encoded[start:start + CHUNK] for start in range(0, len(encoded), CHUNK)] or [""]
    return ("," + NL + "    ").join(json.dumps(chunk) for chunk in chunks)


def render_files(name: str, packed: bytes) -> list[tuple[str, str]]:
    encoded = base64.b64encode(packed).decode("ascii")
    digest = hashlib.sha256(packed).hexdigest()
    label = json.dumps(name)
    join_empty = '].join(' + json.dumps('') + ')'
    if len(encoded) <= PART_LIMIT:
        lines = [
            "var MT_DATA = MT_DATA || {};",
            "",
            f"MT_DATA[{label}] = function () {{",
            "  return {",
            f"    sha256: {json.dumps(digest)},",
            "    gzip: [",
            "    " + _chunk_lines(encoded),
            "    " + join_empty,
            "  };",
            "};",
            "",
        ]
        return [(f"data_{name}.js", NL.join(lines))]
    parts = [encoded[start:start + PART_LIMIT] for start in range(0, len(encoded), PART_LIMIT)]
    files: list[tuple[str, str]] = []
    for index, part in enumerate(parts):
        lines = ["var MT_DATA = MT_DATA || {};", "var MT_DATA_PARTS = MT_DATA_PARTS || {};", ""]
        if index == 0:
            lines += [
                f"MT_DATA[{label}] = function () {{",
                "  return {",
                f"    sha256: {json.dumps(digest)},",
                f"    gzip: MT_DATA_PARTS[{label}].join({json.dumps('')})",
                "  };",
                "};",
                "",
            ]
        lines += [
            f"MT_DATA_PARTS[{label}] = MT_DATA_PARTS[{label}] || [];",
            f"MT_DATA_PARTS[{label}][{index}] = [",
            "    " + _chunk_lines(part),
            join_empty + ';',
            "",
        ]
        suffix = "" if index == 0 else f"_part{index + 1}"
        files.append((f"data_{name}{suffix}.js", NL.join(lines)))
    return files

def main(argv: list[str] | None = None) -> int:
    from export_fixtures import settings

    parser = argparse.ArgumentParser(description="Write the data files the Gmail add-on engine loads.")
    parser.add_argument("--out", type=Path, default=HERE.parent / "src")
    parser.add_argument("--fixtures", type=Path, default=HERE.parent / "tests" / "fixtures")
    parser.add_argument(
        "--check", action="store_true",
        help="write nothing; fail when the knowledge, PSL or URL-model data files in --out are stale",
    )
    args = parser.parse_args(argv)
    args.out.mkdir(parents=True, exist_ok=True)
    args.fixtures.mkdir(parents=True, exist_ok=True)

    cfg = settings(Path(tempfile.mkdtemp(prefix="mailtrace-addon-")))
    cfg.ensure_dirs()
    if args.check:
        stale = []
        import cjk_tables

        checks = (("knowledge", knowledge_blob(cfg)), ("psl", psl_blob()), ("cjk", cjk_tables.build()), ("url_model", url_model_blob(cfg)[0]))
        for name, value in checks:
            target = args.out / f"data_{name}.js"
            current = target.read_text(encoding="utf-8") if target.is_file() else ""
            if current != render(name, pack(value)):
                stale.append(target.name)
        if stale:
            print("stale data files: " + ", ".join(stale) + "; run python tools/export_data.py")
            return 1
        print("knowledge, PSL, CJK and URL-model data files are up to date")
        return 0
    meta, weights = text_model_blobs(cfg)
    url_trees, url_vectors = url_model_blob(cfg)
    import cjk_tables

    blobs: dict[str, Any] = {
        "knowledge": knowledge_blob(cfg),
        "psl": psl_blob(),
        "cjk": cjk_tables.build(),
        "text_model_meta": meta,
        "text_model_weights": weights,
        "url_model": url_trees,
        "selftest": selftest_blob(cfg),
    }
    for name, vectors in (("url_model_vectors", url_vectors), ("text_vectors", text_vectors(cfg))):
        target = args.fixtures / f"{name}.json"
        target.write_text(json.dumps(vectors, ensure_ascii=False, separators=(",", ":")), encoding="utf-8", newline="\n")
        print(f"{target.name:32s} {target.stat().st_size / 1024:9.1f} KB  (tests only)")
    total = 0
    for stale in args.out.glob("data_*_part*.js"):
        stale.unlink()
    for name, value in blobs.items():
        packed = pack(value)
        for filename, text in render_files(name, packed):
            target = args.out / filename
            target.write_text(text, encoding="utf-8", newline=NL)
            total += target.stat().st_size
            print(f"{target.name:32s} {target.stat().st_size / 1024:9.1f} KB")
    print(f"{'total':32s} {total / 1024:9.1f} KB")
    return 0


if __name__ == "__main__":
    sys.exit(main())
