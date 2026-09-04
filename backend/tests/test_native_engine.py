"""
Tests for the optional C++ dissector integration (engine/, Stage 2 PARSE-C++).

There is no C++ compiler in this environment, so ``mailtrace_engine`` itself
cannot be built or executed here.  What *can* be tested - and is, below - is
everything that decides whether shipping it is safe:

* ``_MirrorEngine`` is a pure-Python transcription of the algorithm in
  engine/src/mime.cpp: the same line splitting, the same header-block rule, the
  same boundary grammar, the same "the newline before a boundary belongs to the
  boundary" rule, the same decline conditions.  Running it against CPython's own
  ``email`` parser on the real samples and on hostile input checks that the
  algorithm the C++ implements is the right one.  It does *not* check that the
  C++ implements it correctly - only a build can do that, and engine/README.md
  says how.
* The adapter in ``app.engine.parser`` - tree rebuilding, structural
  cross-checking, the import-time self-check and every fallback path - is the
  code that will actually run in production, and it is tested directly.

The headline assertion is the boring one: with the engine installed,
``parse_email`` must return exactly what it returns without it.
"""
from __future__ import annotations

import sys
import types

import pytest

from app.engine import parser

# --------------------------------------------------------------------------- #
# Pure-Python mirror of engine/src/mime.cpp
# --------------------------------------------------------------------------- #
_MAX_DEPTH = 30
_MAX_NODES = 2000
_WS = b" \t\n\r\f\v"


def _line_end(data: bytes, pos: int) -> int:
    """End offset (terminator included) of the line beginning at ``pos``."""
    while pos < len(data):
        char = data[pos : pos + 1]
        if char == b"\n":
            return pos + 1
        if char == b"\r":
            return pos + 2 if data[pos + 1 : pos + 2] == b"\n" else pos + 1
        pos += 1
    return len(data)


def _trailing_eol(line: bytes) -> int:
    if line.endswith(b"\r\n"):
        return 2
    if line.endswith(b"\r") or line.endswith(b"\n"):
        return 1
    return 0


def _is_header_block_line(line: bytes) -> bool:
    """feedparser.headerRE = r'^(From |[\\041-\\071\\073-\\176]*:|[\\t ])'"""
    if not line:
        return False
    if line[0:1] in (b" ", b"\t"):
        return True
    if line.startswith(b"From "):
        return True
    index = 0
    while index < len(line):
        char = line[index]
        if 0x21 <= char <= 0x39 or 0x3B <= char <= 0x7E:
            index += 1
            continue
        break
    return index < len(line) and line[index : index + 1] == b":"


def _is_blank_line(line: bytes) -> bool:
    return line[:1] in (b"\r", b"\n")


def _match_boundary(line: bytes, separator: bytes) -> tuple[bool, bool]:
    if not separator or not line.startswith(separator):
        return False, False
    index = len(separator)
    is_end = False
    if index + 1 < len(line) and line[index : index + 2] == b"--":
        is_end = True
        index += 2
    while line[index : index + 1] in (b" ", b"\t"):
        index += 1
    if index < len(line):
        if line[index : index + 1] == b"\r":
            index += 2 if line[index + 1 : index + 2] == b"\n" else 1
        elif line[index : index + 1] == b"\n":
            index += 1
    if index == len(line) or (len(line) - index == 1 and line[index : index + 1] == b"\n"):
        return True, is_end
    return False, False


def _find_region_end(body: bytes, pos: int, separators: list[bytes]) -> int:
    while pos < len(body):
        end = _line_end(body, pos)
        line = body[pos:end]
        for separator in separators:
            if _match_boundary(line, separator)[0]:
                return pos
        pos = end
    return len(body)


def _unquote(value: bytes) -> bytes:
    if len(value) > 1 and value[:1] == b'"' and value[-1:] == b'"':
        return value[1:-1].replace(b"\\\\", b"\\").replace(b'\\"', b'"')
    if len(value) > 1 and value[:1] == b"<" and value[-1:] == b">":
        return value[1:-1]
    return value


def _split_parameters(value: bytes) -> list[bytes]:
    segments: list[bytes] = []
    start = 0
    in_quotes = False
    index = 0
    while index < len(value):
        char = value[index : index + 1]
        if in_quotes and char == b"\\":
            index += 2
            continue
        if char == b'"':
            in_quotes = not in_quotes
        elif char == b";" and not in_quotes:
            segments.append(value[start:index])
            start = index + 1
        index += 1
    segments.append(value[start:])
    return segments


def _header_parameter(header_value: bytes, name: bytes) -> bytes | None:
    for segment in _split_parameters(header_value)[1:]:
        equals = segment.find(b"=")
        if equals == -1:
            if segment.strip(_WS).lower() == name:
                return b""  # bare attribute: present, but empty
            continue
        if segment[:equals].strip(_WS).lower() != name:
            continue
        return _unquote(segment[equals + 1 :].strip(_WS))
    return None


def _find_header(headers: list[tuple[bytes, bytes]], name: bytes) -> bytes | None:
    for field_name, field_value in headers:
        if field_name.lower() == name:
            return field_value
    return None


def _content_type_of(headers: list[tuple[bytes, bytes]], default_type: bytes) -> bytes:
    raw = _find_header(headers, b"content-type")
    if raw is None:
        return default_type
    semicolon = raw.find(b";")
    if semicolon != -1:
        raw = raw[:semicolon]
    ctype = raw.strip(_WS).lower()
    if ctype.count(b"/") != 1:
        return b"text/plain"
    return ctype


def _main_type(content_type: bytes) -> bytes:
    slash = content_type.find(b"/")
    return content_type if slash == -1 else content_type[:slash]


class _Context:
    def __init__(self) -> None:
        self.declined = False
        self.reason = ""
        self.nodes = 0

    def decline(self, why: str) -> None:
        if not self.declined:
            self.declined = True
            self.reason = why


def _parse_header_block(region: bytes, out: list[tuple[bytes, bytes]], ctx: _Context) -> int:
    lines: list[bytes] = []
    pos = 0
    while pos < len(region):
        end = _line_end(region, pos)
        line = region[pos:end]
        if not _is_header_block_line(line):
            if _is_blank_line(line):
                pos = end
            break
        if line.startswith(b"From "):
            ctx.decline("unix-from line inside a header block")
            return len(region)
        lines.append(line)
        pos = end
    body_start = pos

    index = 0
    while index < len(lines):
        first = lines[index]
        if first[0:1] in (b" ", b"\t"):
            ctx.decline("header block opens with a continuation line")
            return len(region)
        colon = first.find(b":")
        if colon == -1:
            ctx.decline("header line without a colon")
            return len(region)
        if colon == 0:
            ctx.decline("header line with an empty name")
            return len(region)
        name = first[:colon]
        value = first[colon + 1 :]
        following = index + 1
        while following < len(lines) and lines[following][0:1] in (b" ", b"\t"):
            value += lines[following]
            following += 1
        out.append((name, value.lstrip(b" \t\r\n").rstrip(b"\r\n")))
        index = following
    return body_start


def _parse_node(region: bytes, default_type: bytes, ancestors: list[bytes], depth: int, ctx: _Context) -> dict:
    node: dict = {
        "kind": "leaf",
        "content_type": b"",
        "boundary": b"",
        "body": b"",
        "trim_last": False,
        "headers": [],
        "children": [],
    }
    if ctx.declined:
        return node
    if depth > _MAX_DEPTH:
        ctx.decline("message nested deeper than the native depth limit")
        return node
    ctx.nodes += 1
    if ctx.nodes > _MAX_NODES:
        ctx.decline("more MIME parts than the native node limit")
        return node

    body_start = _parse_header_block(region, node["headers"], ctx)
    if ctx.declined:
        return node
    node["body"] = region[body_start:]
    node["content_type"] = _content_type_of(node["headers"], default_type)
    content_type = node["content_type"]

    if content_type == b"message/rfc822":
        node["kind"] = "rfc822"
        return node
    if _main_type(content_type) == b"message":
        ctx.decline("message/* part other than message/rfc822")
        return node
    if _main_type(content_type) != b"multipart":
        return node

    raw_content_type = _find_header(node["headers"], b"content-type")
    boundary = None if raw_content_type is None else _header_parameter(raw_content_type, b"boundary")
    if boundary is None:
        return node  # NoBoundaryInMultipartDefect: a leaf despite the media type
    boundary = _unquote(boundary).rstrip(_WS)
    if not boundary:
        ctx.decline("multipart boundary parameter is empty")
        return node

    separator = b"--" + boundary
    active = list(ancestors) + [separator]
    child_default = b"message/rfc822" if content_type == b"multipart/digest" else b"text/plain"
    body = node["body"]
    pos = 0
    saw_start = False
    while pos < len(body):
        end = _line_end(body, pos)
        matched, is_end = _match_boundary(body[pos:end], separator)
        if not matched:
            if saw_start:
                ctx.decline("boundary scan desynchronised")
                return node
            pos = end
            continue
        if is_end:
            break
        saw_start = True
        pos = end
        while pos < len(body):
            following = _line_end(body, pos)
            if not _match_boundary(body[pos:following], separator)[0]:
                break
            pos = following
        child_end = _find_region_end(body, pos, active)
        child = _parse_node(body[pos:child_end], child_default, active, depth + 1, ctx)
        if ctx.declined:
            return node
        if child["kind"] == "leaf" and _main_type(child["content_type"]) != b"multipart":
            eol = _trailing_eol(child["body"])
            if eol:
                child["body"] = child["body"][:-eol]
        elif child["kind"] == "rfc822":
            child["trim_last"] = True
        node["children"].append(child)
        pos = child_end

    if not saw_start:
        ctx.decline("multipart start boundary never appears")
        return node

    node["kind"] = "container"
    node["boundary"] = boundary
    node["body"] = b""
    return node


def _dissect(raw: bytes) -> dict:
    ctx = _Context()
    root = _parse_node(bytes(raw), b"text/plain", [], 0, ctx)
    if ctx.declined:
        return {"schema": 1, "ok": False, "reason": ctx.reason, "root": {}}
    return {"schema": 1, "ok": True, "reason": "", "root": root}


def _make_engine(dissect, version: str = "mirror-1.0.0", schema: int = 1) -> types.ModuleType:
    module = types.ModuleType("mailtrace_engine")
    module.__version__ = version  # type: ignore[attr-defined]
    module.DISSECT_SCHEMA = schema  # type: ignore[attr-defined]
    module.dissect = dissect  # type: ignore[attr-defined]
    return module


# --------------------------------------------------------------------------- #
# Fixtures
# --------------------------------------------------------------------------- #
HOSTILE: tuple[bytes, ...] = (
    b"",
    b"\x00\xff\xfe garbage",
    b"plain text no headers",
    b"Subject: only a subject\n",
    b"Subject: no separator\nbody starts here\n",
    b":empty header name\r\n\r\nbody\r\n",
    b"  leading continuation\r\nSubject: x\r\n\r\nbody\r\n",
    b"From someone Mon Jan 1 00:00:00 2020\r\nSubject: mbox\r\n\r\nbody\r\n",
    b"Content-Type: multipart/mixed\r\n\r\nno boundary parameter at all\r\n",
    b"Content-Type: multipart/mixed; boundary=X\r\n\r\nstart boundary never appears\r\n",
    b"Content-Type: multipart/mixed; boundary=X\r\n\r\n--X--\r\nonly a close boundary\r\n",
    b"Content-Type: multipart/mixed; boundary=X\r\n\r\n--X\r\n--X\r\n--X\r\n",
    b"Content-Type: multipart/mixed; boundary=X\r\n\r\n--X\r\nContent-Type: text/plain\r\n\r\ntruncated",
    b"Content-Type: message/delivery-status\r\n\r\nStatus: 5.0.0\r\n",
    b"Content-Type: multipart/digest; boundary=D\r\n\r\n--D\r\n\r\nSubject: nested\r\n\r\nhi\r\n--D--\r\n",
    b"Content-Type: text/plain\rlone carriage returns\r\rbody\r",
    b'Content-Type: multipart/mixed; boundary="quoted bound"\r\n\r\n'
    b"--quoted bound\r\nContent-Type: text/plain\r\n\r\nhi\r\n--quoted bound--\r\n",
    (
        b'Content-Type: multipart/mixed; boundary="OUT"\r\n\r\n--OUT\r\n'
        b'Content-Type: multipart/mixed; boundary="IN"\r\n\r\n--IN\r\n'
        b"Content-Type: text/plain\r\n\r\ninner never closes\r\n--OUT\r\n"
        b"Content-Type: text/plain\r\n\r\nsecond outer part\r\n--OUT--\r\n"
    ),
    (
        b"Content-Type: multipart/mixed; boundary=B\r\n\r\n--B\r\n"
        b"Content-Type: message/rfc822\r\n\r\n"
        b"Subject: forwarded\r\nFrom: x@y.example\r\n\r\nforwarded body\r\n--B--\r\n"
    ),
    b"Content-Type: multipart/mixed; boundary=B\r\n\r\n--B  \r\nContent-Type: text/plain\r\n\r\nws after boundary\r\n--B--  \r\n",
)


@pytest.fixture
def restore_engine():
    """Save and restore every module-level flag the activation path touches."""
    saved = (
        parser._native,
        parser.NATIVE_ENGINE,
        parser.NATIVE_ENGINE_VERSION,
        parser.NATIVE_ENGINE_STATUS,
        dict(parser._native_stats),
        sys.modules.get("mailtrace_engine"),
    )
    yield
    (
        parser._native,
        parser.NATIVE_ENGINE,
        parser.NATIVE_ENGINE_VERSION,
        parser.NATIVE_ENGINE_STATUS,
        stats,
        module,
    ) = saved
    parser._native_stats.clear()
    parser._native_stats.update(stats)
    if module is None:
        sys.modules.pop("mailtrace_engine", None)
    else:
        sys.modules["mailtrace_engine"] = module


@pytest.fixture
def mirror(restore_engine):
    """Install the mirror engine as if the extension had been built."""
    module = _make_engine(_dissect)
    sys.modules["mailtrace_engine"] = module
    parser._activate_native_engine()
    assert parser.NATIVE_ENGINE, parser.NATIVE_ENGINE_STATUS
    return module


def _comparable(raw: bytes) -> tuple:
    parsed, attachments = parser.parse_email(raw)
    payload = parsed.model_dump()
    payload.pop("parse_ms")  # wall-clock, never equal between two runs
    return payload, [(a.filename, a.content_type, a.data, a.content_id, a.is_inline) for a in attachments]


# --------------------------------------------------------------------------- #
# The engine is genuinely optional
# --------------------------------------------------------------------------- #
def test_module_flags_exist_and_are_honest():
    assert isinstance(parser.NATIVE_ENGINE, bool)
    assert isinstance(parser.NATIVE_ENGINE_VERSION, str)
    assert isinstance(parser.NATIVE_ENGINE_STATUS, str) and parser.NATIVE_ENGINE_STATUS
    if not parser.NATIVE_ENGINE:
        assert parser.NATIVE_ENGINE_VERSION == ""


def test_engine_status_reports_the_live_state():
    status = parser.engine_status()
    assert status["native_engine"] is parser.NATIVE_ENGINE
    assert status["native_engine_status"] == parser.NATIVE_ENGINE_STATUS
    for key in ("parsed_native", "parsed_python", "native_declined"):
        assert isinstance(status[key], int)


def test_health_endpoint_reports_the_engine(cfg):
    from fastapi.testclient import TestClient

    from app.main import create_app

    with TestClient(create_app(cfg)) as client:
        body = client.get("/api/health").json()
    assert body["native_engine"] is parser.NATIVE_ENGINE
    assert body["native_engine_status"] == parser.NATIVE_ENGINE_STATUS


def test_env_switch_blocks_activation(monkeypatch, restore_engine):
    monkeypatch.setenv("MAILTRACE_NATIVE_ENGINE", "0")
    sys.modules["mailtrace_engine"] = _make_engine(_dissect)
    parser._native = None
    parser.NATIVE_ENGINE = False
    parser._activate_native_engine()
    assert parser.NATIVE_ENGINE is False
    assert "disabled" in parser.NATIVE_ENGINE_STATUS


# --------------------------------------------------------------------------- #
# Identical results, which is the whole point
# --------------------------------------------------------------------------- #
def test_samples_parse_identically_with_the_engine(sample, mirror):
    for key in ("phishing", "bec", "legit", "fraud", "ceo"):
        raw = sample(key)
        parser._native = None
        parser.NATIVE_ENGINE = False
        baseline = _comparable(raw)
        parser._native = mirror
        parser.NATIVE_ENGINE = True
        assert _comparable(raw) == baseline, key


def test_hostile_input_parses_identically_with_the_engine(mirror):
    for raw in HOSTILE:
        parser._native = None
        parser.NATIVE_ENGINE = False
        baseline = _comparable(raw)
        parser._native = mirror
        parser.NATIVE_ENGINE = True
        assert _comparable(raw) == baseline, raw[:60]


def test_mirror_tree_matches_cpython_on_samples(sample, mirror):
    """The dissection rules themselves, checked against email.feedparser."""
    for key in ("phishing", "bec", "legit", "fraud", "ceo"):
        raw = sample(key)
        native = parser._native_message(raw)
        assert native is not None, key
        assert parser._tree_signature(native) == parser._tree_signature(parser._python_message(raw)), key


def test_mirror_tree_matches_cpython_on_hostile_input(mirror):
    for raw in HOSTILE:
        native = parser._native_message(raw)
        if native is None:
            continue  # declined or cross-checked away; the fallback covers it
        assert parser._tree_signature(native) == parser._tree_signature(parser._python_message(raw)), raw[:60]


def test_engine_is_actually_used_when_active(sample, mirror):
    before = parser._native_stats["native"]
    parser.parse_email(sample("phishing"))
    assert parser._native_stats["native"] == before + 1


# --------------------------------------------------------------------------- #
# Every way the engine can be wrong, and the fallback that catches it
# --------------------------------------------------------------------------- #
def test_declined_message_falls_back(sample, restore_engine):
    parser._native = _make_engine(lambda raw: {"schema": 1, "ok": False, "reason": "nope", "root": {}})
    parser.NATIVE_ENGINE = True
    before = parser._native_stats["declined"]
    parsed, _ = parser.parse_email(sample("phishing"))
    assert parsed.sender.address == "alerts@sbi-kyc-update.xyz"
    assert parser._native_stats["declined"] == before + 1


def test_raising_engine_falls_back(sample, restore_engine):
    def explode(raw):
        raise RuntimeError("segfault-adjacent")

    parser._native = _make_engine(explode)
    parser.NATIVE_ENGINE = True
    parsed, _ = parser.parse_email(sample("phishing"))
    assert parsed.sender.address == "alerts@sbi-kyc-update.xyz"


def test_garbage_tree_falls_back(sample, restore_engine):
    parser._native = _make_engine(lambda raw: {"schema": 1, "ok": True, "reason": "", "root": {"kind": "wat"}})
    parser.NATIVE_ENGINE = True
    parsed, _ = parser.parse_email(sample("phishing"))
    assert parsed.sender.address == "alerts@sbi-kyc-update.xyz"


def test_wrong_boundary_is_cross_checked_away(restore_engine):
    """A boundary the standard library does not agree with is rejected."""
    raw = b"Content-Type: multipart/mixed; boundary=REAL\r\n\r\n--REAL\r\nContent-Type: text/plain\r\n\r\nhi\r\n--REAL--\r\n"

    def lying(data: bytes) -> dict:
        tree = _dissect(data)
        tree["root"]["boundary"] = b"FAKE"
        return tree

    parser._native = _make_engine(lying)
    parser.NATIVE_ENGINE = True
    assert parser._native_message(raw) is None
    parsed, _ = parser.parse_email(raw)
    assert parsed.text_body == "hi"


def test_flattened_multipart_is_cross_checked_away(restore_engine):
    """Calling a live multipart a leaf must be caught, not trusted."""
    raw = b"Content-Type: multipart/mixed; boundary=B\r\n\r\n--B\r\nContent-Type: text/plain\r\n\r\nhi\r\n--B--\r\n"

    def flattening(data: bytes) -> dict:
        tree = _dissect(data)
        root = tree["root"]
        root["kind"] = "leaf"
        root["children"] = []
        root["body"] = b"whatever"
        return tree

    parser._native = _make_engine(flattening)
    parser.NATIVE_ENGINE = True
    assert parser._native_message(raw) is None


def test_mislabelled_embedded_message_is_cross_checked_away(restore_engine):
    raw = b"Content-Type: text/plain\r\n\r\nhi\r\n"

    def lying(data: bytes) -> dict:
        tree = _dissect(data)
        tree["root"]["kind"] = "rfc822"
        return tree

    parser._native = _make_engine(lying)
    parser.NATIVE_ENGINE = True
    assert parser._native_message(raw) is None


def test_schema_mismatch_refuses_activation(restore_engine):
    sys.modules["mailtrace_engine"] = _make_engine(_dissect, schema=99)
    parser._native = None
    parser.NATIVE_ENGINE = False
    parser._activate_native_engine()
    assert parser.NATIVE_ENGINE is False
    assert "schema" in parser.NATIVE_ENGINE_STATUS


def test_self_check_rejects_a_subtly_wrong_engine(restore_engine):
    """An engine that mangles one payload must never be switched on."""

    def sloppy(data: bytes) -> dict:
        tree = _dissect(data)
        root = tree["root"]
        if root.get("kind") == "container" and root["children"]:
            child = root["children"][0]
            if child["kind"] == "leaf":
                child["body"] = child["body"] + b"X"
        return tree

    sys.modules["mailtrace_engine"] = _make_engine(sloppy)
    parser._native = None
    parser.NATIVE_ENGINE = False
    parser._activate_native_engine()
    assert parser.NATIVE_ENGINE is False
    assert "self-check" in parser.NATIVE_ENGINE_STATUS


def test_self_check_rejects_an_engine_that_declines_everything(restore_engine):
    sys.modules["mailtrace_engine"] = _make_engine(
        lambda raw: {"schema": 1, "ok": False, "reason": "too hard", "root": {}}
    )
    parser._native = None
    parser.NATIVE_ENGINE = False
    parser._activate_native_engine()
    assert parser.NATIVE_ENGINE is False


def test_unimportable_engine_is_simply_absent(restore_engine, monkeypatch):
    sys.modules.pop("mailtrace_engine", None)
    monkeypatch.setattr(parser, "_native", None)
    parser.NATIVE_ENGINE = False
    parser._activate_native_engine()
    assert parser.NATIVE_ENGINE is False
    assert parser._native is None


# --------------------------------------------------------------------------- #
# The self-check fixtures are worth something on their own
# --------------------------------------------------------------------------- #
def test_self_check_fixtures_cover_the_awkward_shapes():
    joined = b"".join(fixture for fixture, _ in parser._SELF_CHECK_FIXTURES)
    assert b"multipart/mixed" in joined and b"multipart/alternative" in joined
    assert b"message/rfc822" in joined
    assert b"base64" in joined and b"quoted-printable" in joined
    assert b"\r\n" in joined and b"\n" in joined
    assert any(fixture == b"" and required for fixture, required in parser._SELF_CHECK_FIXTURES)
    assert any(not required for _, required in parser._SELF_CHECK_FIXTURES)


# --------------------------------------------------------------------------- #
# Parity against the real extension.  Skipped until somebody builds it
# (see engine/README.md); this is the check that a build is actually correct,
# as opposed to the checks above, which only prove the algorithm and the
# adapter are right.
# --------------------------------------------------------------------------- #
try:  # pragma: no cover - depends on whether the extension was built
    import mailtrace_engine as _real_engine
except Exception:  # noqa: BLE001
    _real_engine = None

requires_extension = pytest.mark.skipif(_real_engine is None, reason="mailtrace_engine is not built")


@requires_extension
def test_extension_sha256_matches_hashlib():
    import hashlib
    import os

    for data in [b"", b"a", b"abc", os.urandom(55), os.urandom(56), os.urandom(64), os.urandom(200000)]:
        assert _real_engine.sha256(data) == hashlib.sha256(data).hexdigest()


@requires_extension
def test_extension_entropy_matches_python():
    import os

    from app.engine.attachments import shannon_entropy

    for data in [b"", b"aaaa", bytes(range(256)), os.urandom(50000)]:
        assert abs(_real_engine.shannon_entropy(data) - shannon_entropy(data)) < 1e-9


@requires_extension
def test_extension_dissection_matches_the_mirror(sample):
    """The C++ and the transcribed algorithm must agree node for node."""
    corpus = [sample(key) for key in ("phishing", "bec", "legit", "fraud", "ceo")]
    corpus += list(HOSTILE)
    corpus += [fixture for fixture, _ in parser._SELF_CHECK_FIXTURES]
    for raw in corpus:
        assert _real_engine.dissect(raw) == _dissect(raw), raw[:60]


@requires_extension
def test_extension_parses_samples_identically(sample, restore_engine):
    for key in ("phishing", "bec", "legit", "fraud", "ceo"):
        raw = sample(key)
        parser._native = None
        parser.NATIVE_ENGINE = False
        baseline = _comparable(raw)
        parser._native = _real_engine
        parser.NATIVE_ENGINE = True
        assert _comparable(raw) == baseline, key


@requires_extension
def test_extension_passes_the_self_check(restore_engine):
    sys.modules["mailtrace_engine"] = _real_engine
    parser._native = None
    parser.NATIVE_ENGINE = False
    parser._activate_native_engine()
    assert parser.NATIVE_ENGINE is True, parser.NATIVE_ENGINE_STATUS


@requires_extension
def test_extension_convenience_view(sample):
    result = _real_engine.parse_message(sample("fraud"))
    assert result["ok"] is True
    assert len(result["sha256"]) == 64
    assert 0.0 <= result["entropy"] <= 8.0
    assert any(b"claim_form.pdf.exe" in a["filename"] for a in result["attachments"])
    assert any(a["data"].startswith(b"MZ") for a in result["attachments"])


def test_mirror_declines_the_shapes_the_engine_is_not_asked_to_handle(mirror):
    """The decline conditions are contract, not accident."""
    declines = {
        b"From someone Mon Jan  1 00:00:00 2020\r\nSubject: mbox\r\n\r\nbody\r\n",
        b"Content-Type: message/delivery-status\r\n\r\nStatus: 5.0.0\r\n",
        b"Content-Type: multipart/mixed; boundary=X\r\n\r\nstart boundary never appears\r\n",
        b"  leading continuation\r\nSubject: x\r\n\r\nbody\r\n",
        b":empty header name\r\n\r\nbody\r\n",
    }
    for raw in declines:
        assert _dissect(raw)["ok"] is False, raw[:40]
        assert parser._native_message(raw) is None, raw[:40]
