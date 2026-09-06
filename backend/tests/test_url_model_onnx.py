"""The ONNX graph must score exactly what the booster it was exported from scores."""
from __future__ import annotations

import pytest

from app.ai import onnx_url, url_model

pytest.importorskip("onnxruntime", reason="the ONNX graph is served by onnxruntime")
pytest.importorskip("onnxmltools", reason="exporting the graph is a development dependency")
pytest.importorskip("xgboost", reason="the booster is what the graph is exported from")
numpy = pytest.importorskip("numpy")

TOLERANCE = 1e-5


@pytest.fixture(scope="module")
def fitted(session_cfg, tmp_path_factory):
    """A booster, the graph exported from it, and the dataset they both score."""
    rows, _, _ = url_model.build_dataset(session_cfg)
    booster = url_model.train(session_cfg, model_path=tmp_path_factory.mktemp("url") / "url.joblib", with_metrics=False)
    fingerprint = url_model.dataset_fingerprint(session_cfg)
    path = tmp_path_factory.mktemp("onnx") / "url_model.onnx"
    onnx_url.export(booster, fingerprint, path)
    return booster, path, fingerprint, numpy.asarray(rows, dtype=numpy.float32)


def test_onnx_agrees_with_the_booster(fitted):
    booster, path, fingerprint, rows = fitted
    scorer = onnx_url.load(fingerprint, path)
    assert scorer is not None

    from_onnx = scorer.predict_proba(rows)[:, 1]
    from_booster = booster.predict_proba(rows)[:, 1]

    assert from_onnx.shape == from_booster.shape
    assert numpy.abs(from_onnx - from_booster).max() < TOLERANCE
    # The decision the pipeline acts on has to be identical, not merely close.
    assert ((from_onnx >= 0.5) == (from_booster >= 0.5)).all()


def test_a_graph_from_another_dataset_is_refused(fitted):
    _, path, fingerprint, _ = fitted
    assert onnx_url.load(fingerprint, path) is not None
    assert onnx_url.load("a-fingerprint-from-a-different-knowledge-base", path) is None


def test_missing_graph_is_not_an_error(tmp_path):
    assert onnx_url.load("anything", tmp_path / "absent.onnx") is None


def test_scoring_path_prefers_the_graph_when_it_matches(session_cfg, monkeypatch, fitted):
    """``load_or_train`` reaches for ONNX before it reaches for the booster."""
    _, path, _, _ = fitted
    monkeypatch.setattr(onnx_url, "BUNDLED", path)
    url_model._models.clear()
    url_model._failed.clear()
    try:
        assert isinstance(url_model.load_or_train(session_cfg), onnx_url.OnnxUrlScorer)
    finally:
        url_model._models.clear()
        url_model._failed.clear()


def test_fingerprint_ignores_line_endings(tmp_path):
    """The same source must hash the same on Windows and Linux.

    A Windows checkout stores source with CRLF and a Linux one with LF. Hashing
    raw bytes made the fingerprint platform-dependent, so the committed graph
    was refused in CI and the URL pillar fell back to the booster.
    """
    lf = tmp_path / "lf.py"
    crlf = tmp_path / "crlf.py"
    lf.write_bytes(b"BRANDS = {\n    'sbi': 'onlinesbi.sbi',\n}\n")
    crlf.write_bytes(b"BRANDS = {\r\n    'sbi': 'onlinesbi.sbi',\r\n}\r\n")

    assert url_model._sha256_file(lf) == url_model._sha256_file(crlf)


def test_the_committed_graph_matches_the_deployed_configuration():
    """The shipped graph must be usable by the deployment that ships it.

    render.yaml sets MAILTRACE_ORG_DOMAINS, and the org domains are part of the
    fingerprint, so a graph exported with different ones is silently refused.
    """
    from dataclasses import replace

    from app.config import Settings

    deployed = replace(Settings(), org_domains=["acme-corp.in"])
    assert onnx_url.load(url_model.dataset_fingerprint(deployed)) is not None
