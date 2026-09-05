"""The ONNX graph must score exactly what the booster it was exported from scores.

XGBoost fits the URL model; ONNX Runtime serves it.  That is only sound while
the two agree to within rounding, so this exports a graph from a freshly fitted
booster and compares them over the whole generated dataset.

The fingerprint check is tested too.  ``dataset_fingerprint`` covers
``org_domains``, because the dataset contains typosquats of the protected
organisation's own domain - so a graph exported for one deployment must be
refused by another rather than quietly scoring the wrong thing.
"""
from __future__ import annotations

import pytest

from app.ai import onnx_url, url_model

pytest.importorskip("onnxruntime", reason="the ONNX graph is served by onnxruntime")
pytest.importorskip("onnxmltools", reason="exporting the graph is a development dependency")
pytest.importorskip("xgboost", reason="the booster is what the graph is exported from")
numpy = pytest.importorskip("numpy")

#: A float32 conversion is faithful, not approximate; more than rounding noise
#: means the export drifted from the booster.
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
