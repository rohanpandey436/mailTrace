from __future__ import annotations

import logging
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    import numpy as np
    import onnxruntime as ort
    from numpy.typing import NDArray

log = logging.getLogger("mailtrace.ml.url.onnx")

BUNDLED = Path(__file__).resolve().parent / "url_model.onnx"
FINGERPRINT_KEY = "mailtrace_fingerprint"
TARGET_OPSET = 15
_INPUT = "input"


class OnnxUrlScorer:

    __slots__ = ("_session", "fingerprint")

    def __init__(self, session: ort.InferenceSession, fingerprint: str) -> None:
        self._session = session
        self.fingerprint = fingerprint

    def predict_proba(self, rows: NDArray[np.float32]) -> NDArray[np.float64]:
        import numpy as np

        outputs = self._session.run(None, {_INPUT: np.asarray(rows, dtype=np.float32)})
        probabilities = outputs[1]
        if isinstance(probabilities, list):
            return np.asarray([[row[0], row[1]] for row in probabilities], dtype=np.float64)
        return np.asarray(probabilities, dtype=np.float64)


def export(model: Any, fingerprint: str, path: Path = BUNDLED) -> Path:
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
    except Exception:
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
