"""Text classifier: training, caching, prediction and token-level explanation."""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import logging
import re
import sys
import threading
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import TYPE_CHECKING

from ..config import Settings
from ..config import settings as default_settings

if TYPE_CHECKING:  # pragma: no cover - annotations only; numpy and scikit-learn are imported lazily at runtime
    import numpy as np
    from numpy.typing import ArrayLike, NDArray
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression
    from sklearn.pipeline import Pipeline

_Transformer = Callable[..., object]

log = logging.getLogger("mailtrace.ml")

LABELS: list[str] = ["Legitimate", "Suspicious", "Impersonated", "Phishing", "Fraud-Related"]
MODEL_VERSION = "tfidf-logreg-2"

#: Attribute holding the SHAP baseline E[x] (word block) on a loaded pipeline.
EXPECTED_ATTR = "expected_features_"

_lock = threading.Lock()
_models: dict[str, Pipeline] = {}


# Corpus
def compose_text(subject: str, body: str) -> str:
    return f"{(subject or '').strip()}\n{(body or '').strip()}".strip()


def corpus_sha256(path: Path) -> str:
    try:
        return hashlib.sha256(Path(path).read_bytes()).hexdigest()
    except OSError:
        return ""


def load_corpus(path: Path) -> tuple[list[str], list[str]]:
    """Read ``[{"subject","body","label"}, ...]``; invalid rows are skipped."""
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    texts: list[str] = []
    labels: list[str] = []
    for row in raw if isinstance(raw, list) else []:
        if not isinstance(row, dict):
            continue
        label = str(row.get("label", "")).strip()
        text = compose_text(str(row.get("subject", "")), str(row.get("body", "")))
        if label in LABELS and text:
            texts.append(text)
            labels.append(label)
    if len(set(labels)) < 2:
        raise ValueError(f"corpus {path} needs at least two classes, found {sorted(set(labels))}")
    return texts, labels


def load_csv(path: Path, subject_col: str, body_col: str, text_col: str, label_col: str) -> tuple[list[str], list[str]]:
    texts: list[str] = []
    labels: list[str] = []
    with Path(path).open(encoding="utf-8", newline="") as handle:
        for row in csv.DictReader(handle):
            label = (row.get(label_col) or "").strip()
            if text_col in row and row.get(text_col):
                text = (row.get(text_col) or "").strip()
            else:
                text = compose_text(row.get(subject_col) or "", row.get(body_col) or "")
            if label in LABELS and text:
                texts.append(text)
                labels.append(label)
    if len(set(labels)) < 2:
        raise ValueError(f"CSV {path} needs at least two classes with labels in {LABELS}")
    return texts, labels


# Model
def build_pipeline() -> Pipeline:
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression
    from sklearn.pipeline import FeatureUnion, Pipeline

    features = FeatureUnion([
        ("word", TfidfVectorizer(ngram_range=(1, 2), min_df=1, sublinear_tf=True, max_features=50000, lowercase=True)),
        ("char", TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), min_df=1, sublinear_tf=True, max_features=80000)),
    ])
    classifier = LogisticRegression(C=4.0, max_iter=2000, class_weight="balanced")
    return Pipeline([("features", features), ("clf", classifier)])


def _word_vectorizer(pipeline: Pipeline) -> TfidfVectorizer:
    """The word/bigram TF-IDF block of the FeatureUnion (first block, so its"""
    return dict(pipeline.named_steps["features"].transformer_list)["word"]


def expected_features(pipeline: Pipeline, texts: Sequence[str]) -> NDArray[np.float64]:
    """Mean feature vector E[x] over ``texts``, full FeatureUnion width, dense."""
    import numpy as np

    matrix = pipeline.named_steps["features"].transform(list(texts))
    return np.asarray(matrix.mean(axis=0), dtype=np.float64).ravel()


def attach_expected(pipeline: Pipeline, expected: ArrayLike | None) -> None:
    """Hang the SHAP baseline off the fitted pipeline so ``shap_values`` can"""
    import numpy as np

    try:
        value = None if expected is None else np.asarray(expected, dtype=np.float64).ravel()
        setattr(pipeline, EXPECTED_ATTR, value)
    except (TypeError, ValueError):  # the baseline is an optimisation, never fatal
        log.debug("could not attach expected features", exc_info=True)


def _bundle_expected(bundle: Mapping[str, object]) -> NDArray[np.float64] | None:
    """The persisted SHAP baseline, if the (untyped, pickled) bundle carries one."""
    import numpy as np

    value = bundle.get("expected_features")
    return value if isinstance(value, np.ndarray) else None


def _bundle(pipeline: Pipeline, texts: list[str], corpus_hash: str) -> dict[str, object]:
    """Serialisable bundle: the fitted pipeline plus the word-block SHAP baseline."""
    word_expected = None
    try:
        n_word = len(_word_vectorizer(pipeline).get_feature_names_out())
        word_expected = expected_features(pipeline, texts)[:n_word]
    except (TypeError, ValueError, AttributeError):  # a bundle without a baseline still predicts
        log.warning("could not compute expected features; SHAP values will fall back to a zero baseline", exc_info=True)
    return {
        "pipeline": pipeline,
        "labels": LABELS,
        "version": MODEL_VERSION,
        "n_samples": len(texts),
        "corpus_sha256": corpus_hash,
        "expected_features": word_expected,
    }


def train(corpus_path: Path, model_path: Path) -> Pipeline:
    """Fit on the corpus, persist the bundle, return the fitted pipeline."""
    import joblib

    texts, labels = load_corpus(corpus_path)
    pipeline = build_pipeline()
    pipeline.fit(texts, labels)
    bundle = _bundle(pipeline, texts, corpus_sha256(corpus_path))
    model_path = Path(model_path)
    model_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(bundle, model_path)
    attach_expected(pipeline, _bundle_expected(bundle))
    log.info("trained %s on %d samples -> %s", MODEL_VERSION, len(texts), model_path)
    return pipeline


def _load_bundle(model_path: Path, expected_hash: str) -> Pipeline | None:
    import joblib

    if not Path(model_path).is_file():
        return None
    try:
        bundle = joblib.load(model_path)
    except Exception:  # noqa: BLE001 - corrupt/incompatible cache -> retrain
        log.warning("cached model at %s could not be loaded; retraining", model_path)
        return None
    if not isinstance(bundle, dict) or bundle.get("version") != MODEL_VERSION:
        return None
    if expected_hash and bundle.get("corpus_sha256") != expected_hash:
        return None
    pipeline = bundle.get("pipeline")
    if pipeline is not None:
        attach_expected(pipeline, _bundle_expected(bundle))
    return pipeline


def load_or_train(cfg: Settings | None = None) -> Pipeline:
    """Return the process-wide fitted pipeline, training it once if needed."""
    cfg = cfg or default_settings
    key = str(cfg.model_path)
    with _lock:
        cached = _models.get(key)
        if cached is not None:
            return cached
        pipeline = _load_bundle(cfg.model_path, corpus_sha256(cfg.corpus_path))
        if pipeline is None:
            cfg.model_path.parent.mkdir(parents=True, exist_ok=True)
            pipeline = train(cfg.corpus_path, cfg.model_path)
        _models[key] = pipeline
        return pipeline


def predict(pipeline: Pipeline, text: str) -> tuple[str, dict[str, float]]:
    """(label, {label: probability}) with every known label present."""
    probabilities = pipeline.predict_proba([text or ""])[0]
    classes = [str(c) for c in pipeline.classes_]
    probs = dict.fromkeys(LABELS, 0.0)
    for cls, value in zip(classes, probabilities):
        probs[cls] = float(value)
    label = max(probs.items(), key=lambda item: item[1])[0]
    return label, probs


# Exact SHAP for the linear model
def _class_weights(classifier: LogisticRegression, label: str) -> tuple[NDArray[np.float64], float]:
    """(coefficient row, intercept) of the decision function for ``label``."""
    classes = [str(c) for c in classifier.classes_]
    if label not in classes:
        raise ValueError(f"unknown class {label!r}")
    index = classes.index(label)
    if classifier.coef_.shape[0] == 1:
        sign = 1.0 if index == 1 else -1.0
        return sign * classifier.coef_[0], sign * float(classifier.intercept_[0])
    return classifier.coef_[index], float(classifier.intercept_[index])


def _baseline(pipeline: Pipeline, width: int, expected: ArrayLike | None = None) -> NDArray[np.float64]:
    """E[x] as a dense vector of ``width``, from the argument, the pipeline"""
    import numpy as np

    if expected is None:
        expected = getattr(pipeline, EXPECTED_ATTR, None)
    if expected is None:
        log.debug("no expected_features on the model; SHAP falls back to a zero baseline")
        return np.zeros(width, dtype=np.float64)
    vector = np.asarray(expected, dtype=np.float64).ravel()
    if vector.shape[0] == width:
        return vector
    padded = np.zeros(width, dtype=np.float64)
    usable = min(width, vector.shape[0])
    padded[:usable] = vector[:usable]
    return padded


def _word_contributions(
    pipeline: Pipeline, text: str, label: str, expected: ArrayLike | None = None
) -> list[tuple[str, float]]:
    """Signed SHAP value of every word/bigram feature *present* in ``text``,"""
    classifier = pipeline.named_steps["clf"]
    vectorizer = _word_vectorizer(pipeline)
    coefficients, _ = _class_weights(classifier, label)
    row = vectorizer.transform([text or ""])
    n_word = row.shape[1]
    coefficients = coefficients[:n_word]
    baseline = _baseline(pipeline, n_word, expected)
    names = vectorizer.get_feature_names_out()
    coo = row.tocoo()
    contributions = [
        (str(names[int(col)]), float(coefficients[int(col)]) * (float(value) - float(baseline[int(col)])))
        for col, value in zip(coo.col, coo.data)
    ]
    contributions.sort(key=lambda item: -abs(item[1]))
    return contributions


def shap_values(
    pipeline: Pipeline, text: str, label: str, top_k: int = 10, expected: ArrayLike | None = None
) -> list[tuple[str, float]]:
    """Exact per-token SHAP values ``phi_i = w_i * (x_i - E[x_i])`` for ``label``."""
    try:
        contributions = _word_contributions(pipeline, text, label, expected)
    except Exception:  # explanation must never break analysis
        log.debug("shap_values failed", exc_info=True)
        return []
    return contributions if top_k <= 0 else contributions[:top_k]


def explain(pipeline: Pipeline, text: str, label: str, top_k: int = 8) -> list[str]:
    """Word/bigram features that pushed ``text`` toward ``label`` the most."""
    try:
        contributions = _word_contributions(pipeline, text, label)
    except Exception:  # explanation is best effort
        log.debug("explain failed", exc_info=True)
        return []
    positive = [token for token, phi in contributions if phi > 0]
    return positive[:top_k]


def additivity_check(
    pipeline: Pipeline,
    text: str,
    label: str,
    texts: Sequence[str] | None = None,
    expected_full: ArrayLike | None = None,
) -> dict[str, float]:
    """Numerically verify ``decision == base_value + sum(phi)`` over ALL features."""
    import numpy as np

    if expected_full is None:
        if texts is None:
            raise ValueError("additivity_check needs expected_full or the training texts")
        expected_full = expected_features(pipeline, texts)
    classifier = pipeline.named_steps["clf"]
    coefficients, intercept = _class_weights(classifier, label)
    row = pipeline.named_steps["features"].transform([text or ""])
    x = np.asarray(row.todense(), dtype=np.float64).ravel()
    baseline = np.asarray(expected_full, dtype=np.float64).ravel()
    phi = np.asarray(coefficients, dtype=np.float64) * (x - baseline)
    base_value = intercept + float(np.dot(np.asarray(coefficients, dtype=np.float64), baseline))

    scores = pipeline.decision_function([text or ""])
    classes = [str(c) for c in classifier.classes_]
    raw = np.asarray(scores)
    if raw.ndim == 1:  # binary: one column scoring classes_[1]
        decision = float(raw[0]) * (1.0 if classes.index(label) == 1 else -1.0)
    else:
        decision = float(raw[0][classes.index(label)])
    phi_sum = float(phi.sum())
    return {
        "decision": decision,
        "base_value": base_value,
        "phi_sum": phi_sum,
        "reconstructed": base_value + phi_sum,
        "residual": abs(decision - (base_value + phi_sum)),
        "n_features": int(phi.shape[0]),
    }


TRANSFORMER_ATTRIBUTION = "occlusion"
TRANSFORMER_MAX_TOKENS = 60          # forward passes per message: keep it bounded
TRANSFORMER_CHAR_LIMIT = 4000        # the tokenizer truncates anyway

_transformer_lock = threading.Lock()
_transformers: dict[str, _Transformer] = {}
_transformer_failed: set[str] = set()

_TRANSFORMER_LABELS: dict[str, str] = {
    "legitimate": "Legitimate", "legit": "Legitimate", "benign": "Legitimate", "ham": "Legitimate",
    "safe": "Legitimate", "clean": "Legitimate", "normal": "Legitimate", "not_phishing": "Legitimate",
    "no_phishing": "Legitimate", "non_phishing": "Legitimate", "genuine": "Legitimate",
    "suspicious": "Suspicious", "spam": "Suspicious", "suspect": "Suspicious", "unsure": "Suspicious",
    "impersonated": "Impersonated", "impersonation": "Impersonated", "spoof": "Impersonated",
    "spoofed": "Impersonated", "spoofing": "Impersonated", "brand_impersonation": "Impersonated",
    "ceo_fraud": "Impersonated", "bec": "Impersonated",
    "phishing": "Phishing", "phish": "Phishing", "phishing_url": "Phishing", "malicious": "Phishing",
    "credential_phishing": "Phishing", "smishing": "Phishing",
    "fraud_related": "Fraud-Related", "fraud": "Fraud-Related", "fraudulent": "Fraud-Related",
    "scam": "Fraud-Related", "advance_fee": "Fraud-Related", "money_scam": "Fraud-Related",
}


def _normalize_label(raw: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", str(raw or "").strip().lower()).strip("_")


def map_transformer_label(raw: str) -> str | None:
    """Map one of the model's own labels onto a MailTrace class, or None."""
    return _TRANSFORMER_LABELS.get(_normalize_label(raw))


def _map_scores(scored: object) -> dict[str, float]:
    """``[{'label': ..., 'score': ...}, ...]`` -> probabilities over LABELS."""
    probs = dict.fromkeys(LABELS, 0.0)
    items: list[object] = [scored] if isinstance(scored, dict) else list(scored) if isinstance(scored, list) else []
    unmapped: list[str] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        mapped = map_transformer_label(str(item.get("label", "")))
        if mapped is None:
            unmapped.append(str(item.get("label", "")))
            continue
        probs[mapped] += float(item.get("score", 0.0) or 0.0)
    if unmapped:
        log.debug("transformer labels with no MailTrace class were dropped: %s", sorted(set(unmapped)))
    total = sum(probs.values())
    if total > 0 and abs(total - 1.0) > 1e-6:
        probs = {label: value / total for label, value in probs.items()}
    return probs


def _get_transformer(model_id: str) -> _Transformer:
    """Load (once) and cache a text-classification pipeline for ``model_id``."""
    with _transformer_lock:
        cached = _transformers.get(model_id)
        if cached is not None:
            return cached
        import torch  # noqa: F401 - fail fast when the backend is missing
        from transformers import pipeline as hf_pipeline

        log.info("loading transformer %s (first use downloads and pins ~300 MB+ of weights)", model_id)
        clf: _Transformer = hf_pipeline("text-classification", model=model_id, tokenizer=model_id, top_k=None, truncation=True)
        _transformers[model_id] = clf
        return clf


def _occlusion_attributions(clf: _Transformer, text: str, label: str, base_prob: float) -> list[tuple[str, float]]:
    """Leave-one-token-out attributions: how much p(label) falls when a token"""
    tokens = (text or "").split()
    head = tokens[:TRANSFORMER_MAX_TOKENS]
    if not head:
        return []
    variants = [" ".join(tokens[:i] + tokens[i + 1:]) for i in range(len(head))]
    outputs = clf(variants)
    if not isinstance(outputs, list):
        return []
    best: dict[str, float] = {}
    for token, scored in zip(head, outputs):
        without = _map_scores(scored).get(label, 0.0)
        delta = float(base_prob) - float(without)
        if abs(delta) > abs(best.get(token, 0.0)):
            best[token] = delta
    return sorted(best.items(), key=lambda item: -abs(item[1]))


def transformer_predict(text: str, cfg: Settings) -> tuple[str, dict[str, float], list[tuple[str, float]]] | None:
    """(label, probabilities over the five classes, token attributions), or None."""
    model_id = (getattr(cfg, "transformer_model", "") or "").strip()
    if not model_id:
        return None
    if model_id in _transformer_failed:
        return None
    body = (text or "").strip()
    if not body:
        return None
    try:
        clf = _get_transformer(model_id)
    except Exception as exc:  # noqa: BLE001 - missing packages, no network, bad id, OOM
        _transformer_failed.add(model_id)
        log.warning(
            "transformer backend %s unavailable (%s: %s); falling back to the linear model",
            model_id, type(exc).__name__, exc,
        )
        return None
    try:
        probs = _map_scores(clf(body[:TRANSFORMER_CHAR_LIMIT]))
        if not any(probs.values()):
            log.warning("transformer %s emitted no label that maps onto a MailTrace class; falling back", model_id)
            return None
        label = max(probs.items(), key=lambda item: item[1])[0]
        attributions = _occlusion_attributions(clf, body[:TRANSFORMER_CHAR_LIMIT], label, probs[label])
        return label, probs, attributions
    except Exception as exc:  # noqa: BLE001 - inference failure must never abort analysis
        log.warning(
            "transformer inference with %s failed (%s: %s); falling back to the linear model",
            model_id, type(exc).__name__, exc,
        )
        return None


# CLI
def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Train the MailTrace email classifier.")
    parser.add_argument("--csv", type=Path, help="CSV with subject/body (or text) and label columns")
    parser.add_argument("--subject-col", default="subject")
    parser.add_argument("--body-col", default="body")
    parser.add_argument("--text-col", default="text")
    parser.add_argument("--label-col", default="label")
    parser.add_argument("--corpus", type=Path, default=default_settings.corpus_path, help="seed corpus JSON (default)")
    parser.add_argument("--out", type=Path, default=default_settings.model_path, help="model output path")
    args = parser.parse_args(argv)

    import joblib
    from sklearn.metrics import accuracy_score, classification_report
    from sklearn.model_selection import train_test_split

    if args.csv:
        texts, labels = load_csv(args.csv, args.subject_col, args.body_col, args.text_col, args.label_col)
        source = str(args.csv)
    else:
        texts, labels = load_corpus(args.corpus)
        source = str(args.corpus)
    print(f"Loaded {len(texts)} samples from {source}")

    stratify = labels if min(labels.count(label) for label in set(labels)) >= 2 else None
    x_train, x_test, y_train, y_test = train_test_split(texts, labels, test_size=0.2, random_state=42, stratify=stratify)
    holdout = build_pipeline().fit(x_train, y_train)
    predicted = holdout.predict(x_test)
    print(f"Hold-out accuracy: {accuracy_score(y_test, predicted):.3f}")
    print(classification_report(y_test, predicted, zero_division=0))

    final = build_pipeline().fit(texts, labels)
    corpus_hash = corpus_sha256(args.csv) if args.csv else corpus_sha256(args.corpus)
    bundle = _bundle(final, texts, corpus_hash)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(bundle, args.out)
    print(f"Saved model to {args.out}")

    # Prove the explanation is exact SHAP rather than a coefficient read-off.
    attach_expected(final, _bundle_expected(bundle))
    full_expected = expected_features(final, texts)
    label, _ = predict(final, texts[0])
    check = additivity_check(final, texts[0], label, expected_full=full_expected)
    print(
        f"SHAP additivity on sample 0 ({label}): decision {check['decision']:.6f} = "
        f"base {check['base_value']:.6f} + sum(phi) {check['phi_sum']:.6f}; "
        f"residual {check['residual']:.3e} over {check['n_features']} features"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
