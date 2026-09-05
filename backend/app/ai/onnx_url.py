"""
The URL/domain model, served by ONNX Runtime.

Training stays with XGBoost: it is the better tool for fitting a small gradient
-boosted ensemble, and ``url_model.train`` is unchanged.  Inference does not
need it.  Exporting the fitted booster to ONNX once, committing the 26 KB graph
beside this module and serving it with ``onnxruntime`` means a deployment
carries a 13 MB wheel instead of xgboost's 87 MB unpacked - a real saving on a
512 MB instance - and starts without training anything.

The export is exact: over the full generated dataset the largest probability
difference against the booster is 1.3e-07 and every label agrees.
``tests/test_url_model_onnx.py`` re-checks that whenever xgboost is installed,
so the two can never drift apart unnoticed.

Note on int8: dynamic quantisation does not apply here.  A tree ensemble is a
``TreeEnsembleClassifier`` node in the ``ai.onnx.ml`` domain with no MatMul to
quantise, and ``quantize_dynamic`` refuses it.  int8 belongs to the transformer
backend, where the weights actually are matrices.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:  # pragma: no cover - annotations only; both are imported lazily
    import numpy as np
    import onnxruntime as ort
    from numpy.typing import NDArray

log = logging.getLogger("mailtrace.ml.url.onnx")

#: The exported graph, committed so a deployment needs no training step.
BUNDLED = Path(__file__).resolve().parent / "url_model.onnx"
#: Metadata key carrying the dataset fingerprint the graph was fitted on.
FINGERPRINT_KEY = "mailtrace_fingerprint"
#: onnxmltools' XGBoost converter supports up to this opset.
TARGET_OPSET = 15
_INPUT = "input"


class OnnxUrlScorer:
    """A fitted URL model backed by an ONNX session.

    Exposes only ``predict_proba``, which is all the scoring path uses, so it
    drops in wherever the ``XGBClassifier`` did.
    """

    __slots__ = ("_session", "fingerprint")

    def __init__(self, session: ort.InferenceSession, fingerprint: str) -> None:
        self._session = session
        self.fingerprint = fingerprint

    def predict_proba(self, rows: NDArray[np.float32]) -> NDArray[np.float64]:
        """``[[p(benign), p(malicious)], ...]``, matching scikit-learn's shape."""
        import numpy as np

        outputs = self._session.run(None, {_INPUT: np.asarray(rows, dtype=np.float32)})
        probabilities = outputs[1]
        # The ZipMap output is a list of {class: probability} dicts; without it
        # the same values arrive as a plain array. Accept both.
        if isinstance(probabilities, list):
            return np.asarray([[row[0], row[1]] for row in probabilities], dtype=np.float64)
        return np.asarray(probabilities, dtype=np.float64)


def export(model: Any, fingerprint: str, path: Path = BUNDLED) -> Path:
    """Convert a fitted ``XGBClassifier`` to ONNX and stamp it with ``fingerprint``.

    Raises ``ImportError`` when the conversion packages are absent - they are
    development dependencies, because only ``python -m app.ai.url_model`` needs
    them.
    """
    from onnxmltools.convert import convert_xgboost
    from onnxmltools.convert.common.data_types import FloatTensorType

    from .url_model import FEATURE_NAMES

    graph = convert_xgboost(
        model, initial_types=[(_INPUT, FloatTensorType([None, len(FEATURE_NAMES)]))], target_opset=TARGET_OPSET
    )
    entry = graph.metadata_props.add()
    entry.key, entry.value = FINGERPRINT_KEY, fingerprint
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(graph.SerializeToString())
    log.info("exported the URL model to %s (%d bytes)", path, path.stat().st_size)
    return path


def load(fingerprint: str, path: Path = BUNDLED) -> OnnxUrlScorer | None:
    """The bundled graph when it matches ``fingerprint``; None otherwise.

    A mismatch means the knowledge base, the sample messages or the feature list
    changed after the export, so the caller retrains rather than serving a model
    that no longer describes its own inputs.
    """
    if not path.is_file():
        return None
    try:
        import onnxruntime as ort
    except ImportError:
        log.info("onnxruntime is not installed; falling back to xgboost for URL scoring")
        return None
    try:
        session = ort.InferenceSession(str(path), providers=["CPUExecutionProvider"])
        stamped = dict(session.get_modelmeta().custom_metadata_map)
    except Exception:  # a corrupt or foreign graph must not stop startup
        log.warning("the bundled URL model at %s could not be loaded", path, exc_info=True)
        return None
    found = stamped.get(FINGERPRINT_KEY, "")
    if fingerprint and found != fingerprint:
        log.info(
            "the bundled URL model was exported for a different dataset (%s != %s); retraining",
            found[:12] or "unstamped", fingerprint[:12],
        )
        return None
    return OnnxUrlScorer(session, found)
