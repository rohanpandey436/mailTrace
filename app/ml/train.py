"""
Text classifier: training, caching, prediction and explanation.

Model
-----
A scikit-learn Pipeline: word TF-IDF (1-2 grams) + character TF-IDF
(3-5 char_wb grams) concatenated by a FeatureUnion, feeding a balanced
multinomial LogisticRegression.  It is small enough to train from the seed
corpus in a couple of seconds at first start and is cached to
``data/model.joblib`` keyed on the corpus hash, so editing the corpus
retrains automatically.

The module is import-safe without scikit-learn: every sklearn/joblib import
happens inside functions and surfaces as ``ImportError`` to the caller
(``nlp.py`` catches it and falls back to rules).

CLI
---
``python -m app.ml.train``                      retrain from the seed corpus
``python -m app.ml.train --csv data.csv``       retrain from a CSV with
``subject``/``body`` (or ``text``) and ``label`` columns; prints hold-out accuracy.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import logging
import sys
import threading
from pathlib import Path
from typing import Any, Optional

from ..config import Settings
from ..config import settings as default_settings

log = logging.getLogger("mailtrace.ml")

LABELS: list[str] = ["Legitimate", "Suspicious", "Impersonated", "Phishing", "Fraud-Related"]
MODEL_VERSION = "tfidf-logreg-1"

_lock = threading.Lock()
_models: dict[str, Any] = {}


# --------------------------------------------------------------------------- #
# Corpus
# --------------------------------------------------------------------------- #
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


# --------------------------------------------------------------------------- #
# Model
# --------------------------------------------------------------------------- #
def build_pipeline():  # type: ignore[no-untyped-def]
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression
    from sklearn.pipeline import FeatureUnion, Pipeline

    features = FeatureUnion([
        ("word", TfidfVectorizer(ngram_range=(1, 2), min_df=1, sublinear_tf=True, max_features=50000, lowercase=True)),
        ("char", TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), min_df=1, sublinear_tf=True, max_features=80000)),
    ])
    classifier = LogisticRegression(C=4.0, max_iter=2000, class_weight="balanced")
    return Pipeline([("features", features), ("clf", classifier)])


def train(corpus_path: Path, model_path: Path):  # type: ignore[no-untyped-def]
    """Fit on the corpus, persist the bundle, return the fitted pipeline."""
    import joblib

    texts, labels = load_corpus(corpus_path)
    pipeline = build_pipeline()
    pipeline.fit(texts, labels)
    bundle = {
        "pipeline": pipeline,
        "labels": LABELS,
        "version": MODEL_VERSION,
        "n_samples": len(texts),
        "corpus_sha256": corpus_sha256(corpus_path),
    }
    model_path = Path(model_path)
    model_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(bundle, model_path)
    log.info("trained %s on %d samples -> %s", MODEL_VERSION, len(texts), model_path)
    return pipeline


def _load_bundle(model_path: Path, expected_hash: str):  # type: ignore[no-untyped-def]
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
    return bundle.get("pipeline")


def load_or_train(cfg: Optional[Settings] = None):  # type: ignore[no-untyped-def]
    """Return the process-wide fitted pipeline, training it once if needed.
    Raises ImportError when scikit-learn/joblib are unavailable."""
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


def predict(pipeline, text: str) -> tuple[str, dict[str, float]]:  # type: ignore[no-untyped-def]
    """(label, {label: probability}) with every known label present."""
    probabilities = pipeline.predict_proba([text or ""])[0]
    classes = [str(c) for c in pipeline.classes_]
    probs = {label: 0.0 for label in LABELS}
    for cls, value in zip(classes, probabilities):
        probs[cls] = float(value)
    label = max(probs.items(), key=lambda item: item[1])[0]
    return label, probs


def explain(pipeline, text: str, label: str, top_k: int = 8) -> list[str]:  # type: ignore[no-untyped-def]
    """Word/bigram features that pushed ``text`` toward ``label`` the most."""
    try:
        features = pipeline.named_steps["features"]
        classifier = pipeline.named_steps["clf"]
        word_vectorizer = dict(features.transformer_list)["word"]
        classes = [str(c) for c in classifier.classes_]
        if label not in classes:
            return []
        row = word_vectorizer.transform([text or ""])
        n_word = row.shape[1]
        coef = classifier.coef_
        if coef.shape[0] == 1:  # binary model: positive class is classes[1]
            class_coef = coef[0] if classes.index(label) == 1 else -coef[0]
        else:
            class_coef = coef[classes.index(label)]
        word_coef = class_coef[:n_word]
        names = word_vectorizer.get_feature_names_out()
        coo = row.tocoo()
        scored = [(float(value * word_coef[col]), int(col)) for col, value in zip(coo.col, coo.data)]
        scored = [item for item in scored if item[0] > 0]
        scored.sort(key=lambda item: -item[0])
        return [str(names[col]) for _, col in scored[:top_k]]
    except Exception:  # noqa: BLE001 - explanation is best effort
        log.debug("explain failed", exc_info=True)
        return []


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def main(argv: Optional[list[str]] = None) -> int:
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

    stratify = labels if min(labels.count(l) for l in set(labels)) >= 2 else None
    x_train, x_test, y_train, y_test = train_test_split(texts, labels, test_size=0.2, random_state=42, stratify=stratify)
    holdout = build_pipeline().fit(x_train, y_train)
    predicted = holdout.predict(x_test)
    print(f"Hold-out accuracy: {accuracy_score(y_test, predicted):.3f}")
    print(classification_report(y_test, predicted, zero_division=0))

    final = build_pipeline().fit(texts, labels)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(
        {
            "pipeline": final,
            "labels": LABELS,
            "version": MODEL_VERSION,
            "n_samples": len(texts),
            "corpus_sha256": corpus_sha256(args.csv) if args.csv else corpus_sha256(args.corpus),
        },
        args.out,
    )
    print(f"Saved model to {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
