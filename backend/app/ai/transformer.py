"""
The DistilRoBERTa backend, served by ONNX Runtime.

Loading this costs two wheels - ``onnxruntime`` (13 MB) and ``tokenizers``
(~3 MB) - and no PyTorch.  That is the whole point of shipping the model as an
int8 ONNX graph: ``torch`` plus ``transformers`` is around a gigabyte installed
and does not fit beside everything else on a 512 MB instance, while the
quantised graph is roughly 80 MB and runs on CPU in tens of milliseconds.

``app/ai/transformer_trainer.py`` produces the directory this reads: the graph,
the tokenizer, and ``labels.json`` naming the classes in output order.  Nothing
here trains, and nothing here imports torch.

The classifier is a *second opinion*, never the whole verdict.  ``scoring.py``
compares it with the rule engine and lowers confidence when they disagree, so a
model that is wrong about a message costs confidence rather than correctness.
"""
from __future__ import annotations

import json
import logging
import threading
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover - annotations only; both are imported lazily
    import numpy as np
    from numpy.typing import NDArray

log = logging.getLogger("mailtrace.ml.transformer")

#: Where ``transformer_trainer`` writes, and where the service looks by default.
BUNDLED = Path(__file__).resolve().parent / "distilroberta-onnx"
#: Must match ``transformer_trainer.MAX_TOKENS``; the graph is exported for it.
MAX_TOKENS = 192
_MODEL_FILENAMES = ("model_quantized.onnx", "model.onnx")

_lock = threading.Lock()
_loaded: dict[str, TransformerClassifier | None] = {}


def _softmax(logits: NDArray[np.float32]) -> NDArray[np.float64]:
    import numpy as np

    shifted = np.asarray(logits, dtype=np.float64) - np.max(logits, axis=-1, keepdims=True)
    exponentiated = np.exp(shifted)
    return exponentiated / np.sum(exponentiated, axis=-1, keepdims=True)


class TransformerClassifier:
    """A fine-tuned DistilRoBERTa reading through onnxruntime."""

    __slots__ = ("_inputs", "_session", "_tokenizer", "directory", "labels")

    def __init__(self, session: object, tokenizer: object, labels: list[str], directory: Path) -> None:
        self._session = session
        self._tokenizer = tokenizer
        self.labels = labels
        self.directory = directory
        self._inputs = {value.name for value in session.get_inputs()}  # type: ignore[attr-defined]

    @classmethod
    def load(cls, directory: Path = BUNDLED) -> TransformerClassifier | None:
        """The bundled model, or None when it is absent or unusable.

        Never raises: a missing or broken model must leave the linear
        classifier in charge rather than take the service down.
        """
        directory = Path(directory)
        cached = _loaded.get(str(directory))
        if cached is not None or str(directory) in _loaded:
            return cached
        with _lock:
            model = cls._load_uncached(directory)
            _loaded[str(directory)] = model
            return model

    @classmethod
    def _load_uncached(cls, directory: Path) -> TransformerClassifier | None:
        graph = next((directory / name for name in _MODEL_FILENAMES if (directory / name).is_file()), None)
        if graph is None:
            log.info("no DistilRoBERTa graph under %s; the linear classifier stays in charge", directory)
            return None
        try:
            import onnxruntime as ort
            from tokenizers import Tokenizer
        except ImportError as exc:
            log.info("the transformer backend needs onnxruntime and tokenizers (%s)", exc)
            return None
        try:
            tokenizer = Tokenizer.from_file(str(directory / "tokenizer.json"))
            tokenizer.enable_truncation(max_length=MAX_TOKENS)
            tokenizer.enable_padding(length=MAX_TOKENS)
            labels = json.loads((directory / "labels.json").read_text(encoding="utf-8"))
            session = ort.InferenceSession(str(graph), providers=["CPUExecutionProvider"])
        except Exception:  # a broken model must not stop startup
            log.warning("the DistilRoBERTa graph at %s could not be loaded", directory, exc_info=True)
            return None
        if not isinstance(labels, list) or not labels:
            log.warning("%s/labels.json does not name any classes", directory)
            return None
        log.info("DistilRoBERTa ready from %s (%d classes, int8 ONNX)", directory, len(labels))
        return cls(session, tokenizer, [str(label) for label in labels], directory)

    def predict(self, text: str) -> tuple[str, dict[str, float]]:
        """``(label, {label: probability})`` for one message."""
        import numpy as np

        encoded = self._tokenizer.encode(text or "")  # type: ignore[attr-defined]
        feed = {"input_ids": np.asarray([encoded.ids], dtype=np.int64)}
        if "attention_mask" in self._inputs:
            feed["attention_mask"] = np.asarray([encoded.attention_mask], dtype=np.int64)
        logits = self._session.run(None, feed)[0]  # type: ignore[attr-defined]
        probabilities = _softmax(np.asarray(logits))[0]
        scores = {label: float(probabilities[index]) for index, label in enumerate(self.labels)}
        return max(scores.items(), key=lambda item: item[1])[0], scores


#: Whitespace tokens occluded per message. Each is one forward pass, and they
#: are batched, so this is the knob that decides what explanation costs.
OCCLUSION_TOKENS = 40
#: Named wherever these surface: they are ablation deltas, not Shapley values.
ATTRIBUTION_METHOD = "occlusion"


def occlusion_attributions(
    classifier: TransformerClassifier, text: str, label: str, base_probability: float
) -> list[tuple[str, float]]:
    """How far p(label) falls when each token is removed, strongest first.

    Honest and model-agnostic, but *not* a Shapley value: this is a single-order
    ablation, not an average over coalitions. The linear backend gets exact SHAP
    because a linear model has a closed form; a transformer does not, so it gets
    this and everything that renders it says which it is.

    Repeated tokens keep their strongest attribution.
    """
    tokens = (text or "").split()
    head = tokens[:OCCLUSION_TOKENS]
    if not head:
        return []
    best: dict[str, float] = {}
    for index, token in enumerate(head):
        without = " ".join(tokens[:index] + tokens[index + 1 :])
        _, scores = classifier.predict(without)
        delta = float(base_probability) - float(scores.get(label, 0.0))
        if abs(delta) > abs(best.get(token, 0.0)):
            best[token] = delta
    return sorted(best.items(), key=lambda item: -abs(item[1]))


def available(directory: Path = BUNDLED) -> bool:
    """Whether a usable model is present, without forcing a full load path."""
    return TransformerClassifier.load(directory) is not None
