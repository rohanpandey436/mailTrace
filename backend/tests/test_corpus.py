from __future__ import annotations

import pytest
from corpus_builder import build_all

from app.core import pipeline

CORPUS = build_all()


@pytest.mark.parametrize("name, raw, expect, ok", CORPUS, ids=[row[0] for row in CORPUS])
def test_corpus_verdict(session_cfg, name: str, raw: bytes, expect: str, ok: list[str]) -> None:
    result = pipeline.analyze_bytes(raw, f"{name}.eml", None, session_cfg)
    got = result.verdict.category.value
    assert got in ok, f"{name}: expected {expect} (accepting {ok}), got {got} at risk {result.verdict.risk_score}: {result.verdict.rationale}"


def test_corpus_covers_every_category() -> None:
    expected = {row[2] for row in CORPUS}
    assert {"Legitimate", "Suspicious", "Impersonated", "Phishing", "Fraud-Related", "Threat"} <= expected
    assert len(CORPUS) >= 70
