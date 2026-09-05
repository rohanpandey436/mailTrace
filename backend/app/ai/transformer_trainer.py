"""
Fine-tune DistilRoBERTa for the five MailTrace classes and export it to ONNX int8.

A development tool, not part of the service: it needs ``torch``, ``transformers``
and ``optimum``, none of which are runtime dependencies.  What it produces -
an int8 ONNX graph and its tokenizer - is what the service loads, through
``app/ai/transformer.py`` and ``onnxruntime`` alone.

Why two stages
--------------
The seed corpus is 249 messages.  Fine-tuning an 82M-parameter model on that
directly memorises it.  So the run is staged:

1. **Binary pre-training** on a public phishing corpus (~18k messages), which
   teaches the encoder what phishing language looks like at all.
2. **Five-class fine-tuning** on the seed corpus, which teaches it the
   distinctions MailTrace reports.

Stage 1 is skipped with ``--skip-pretrain`` when the public dataset cannot be
reached; the model is then weaker and the CLI says so.

Why int8
--------
``distilroberta-base`` is ~330 MB in float32, which does not fit beside
everything else on a 512 MB instance.  Dynamic int8 quantisation takes it to
about 80 MB with a small, *measured* accuracy cost - the CLI prints the
before/after so the trade is a number rather than a hope.  Unlike the URL
model, a transformer is almost entirely MatMul, which is exactly what dynamic
quantisation is for.

Usage
-----
    python -m app.ai.transformer_trainer --out app/ai/distilroberta-onnx
    python -m app.ai.transformer_trainer --skip-pretrain --epochs 4
"""
from __future__ import annotations

import argparse
import json
import logging
import shutil
import sys
import time
from pathlib import Path
from typing import Any

from ..config import settings as default_settings
from .model_trainer import LABELS, load_corpus

log = logging.getLogger("mailtrace.ml.transformer")

BASE_MODEL = "distilroberta-base"
#: Public binary phishing corpus used for stage 1.
PRETRAIN_DATASET = "zefang-liu/phishing-email-dataset"
#: Long enough for a subject plus the opening of a body, which is where the
#: lure lives; every extra token costs quadratically in attention.
MAX_TOKENS = 192
SEED = 42


def _device_note() -> str:
    import torch

    return f"torch {torch.__version__} on CPU with {torch.get_num_threads()} threads"


def _pretrain_frame() -> tuple[list[str], list[int]] | None:
    """(texts, 0/1 labels) from the public corpus, or None when unreachable."""
    try:
        from datasets import load_dataset

        data = load_dataset(PRETRAIN_DATASET, split="train")
    except Exception as exc:  # noqa: BLE001 - an offline machine must still be able to train
        log.warning("could not load %s (%s); skipping stage 1", PRETRAIN_DATASET, exc)
        return None
    text_column = next((c for c in data.column_names if "text" in c.lower()), None)
    label_column = next((c for c in data.column_names if "type" in c.lower() or "label" in c.lower()), None)
    if not text_column or not label_column:
        log.warning("%s has unexpected columns %s; skipping stage 1", PRETRAIN_DATASET, data.column_names)
        return None
    texts: list[str] = []
    labels: list[int] = []
    for row in data:
        text = (row[text_column] or "").strip()
        raw = str(row[label_column]).strip().lower()
        if not text:
            continue
        texts.append(text[:4000])
        labels.append(0 if "safe" in raw or raw in {"0", "ham", "legitimate"} else 1)
    return (texts, labels) if len(set(labels)) == 2 else None


def _tokenized(tokenizer: Any, texts: list[str], labels: list[int]) -> Any:
    import torch
    from torch.utils.data import TensorDataset

    encoded = tokenizer(texts, truncation=True, padding="max_length", max_length=MAX_TOKENS, return_tensors="pt")
    return TensorDataset(encoded["input_ids"], encoded["attention_mask"], torch.tensor(labels, dtype=torch.long))


def _train(model: Any, dataset: Any, epochs: int, batch_size: int, learning_rate: float, note: str) -> None:
    import torch
    from torch.utils.data import DataLoader

    loader = DataLoader(dataset, batch_size=batch_size, shuffle=True)
    optimiser = torch.optim.AdamW(model.parameters(), lr=learning_rate)
    total = epochs * len(loader)
    scheduler = torch.optim.lr_scheduler.OneCycleLR(optimiser, max_lr=learning_rate, total_steps=max(1, total))
    model.train()
    step = 0
    started = time.perf_counter()
    for epoch in range(1, epochs + 1):
        running = 0.0
        for input_ids, attention_mask, target in loader:
            optimiser.zero_grad()
            out = model(input_ids=input_ids, attention_mask=attention_mask, labels=target)
            out.loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            optimiser.step()
            scheduler.step()
            running += float(out.loss)
            step += 1
            if step % 20 == 0:
                rate = step / (time.perf_counter() - started)
                print(f"  {note} step {step}/{total}  loss {running / (step % len(loader) or len(loader)):.4f}  {rate:.1f} steps/s", flush=True)
        print(f"  {note} epoch {epoch}/{epochs} mean loss {running / max(1, len(loader)):.4f}", flush=True)


def _accuracy(model: Any, tokenizer: Any, texts: list[str], labels: list[int]) -> float:
    import torch

    model.eval()
    correct = 0
    with torch.no_grad():
        for start in range(0, len(texts), 16):
            batch = texts[start:start + 16]
            encoded = tokenizer(batch, truncation=True, padding=True, max_length=MAX_TOKENS, return_tensors="pt")
            predicted = model(**encoded).logits.argmax(-1).tolist()
            correct += sum(int(p == t) for p, t in zip(predicted, labels[start:start + 16]))
    return correct / max(1, len(texts))


def _onnx_accuracy(directory: Path, texts: list[str], labels: list[int]) -> float:
    """Accuracy of the exported graph, read back the way the service reads it."""
    from .transformer import TransformerClassifier

    classifier = TransformerClassifier.load(directory)
    if classifier is None:
        return 0.0
    correct = 0
    for text, target in zip(texts, labels):
        predicted, _ = classifier.predict(text)
        correct += int(LABELS.index(predicted) == target)
    return correct / max(1, len(texts))


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out", type=Path, default=Path(__file__).resolve().parent / "distilroberta-onnx")
    parser.add_argument("--epochs", type=int, default=6, help="fine-tuning epochs on the seed corpus")
    parser.add_argument("--pretrain-epochs", type=int, default=1)
    parser.add_argument("--pretrain-rows", type=int, default=8000, help="cap on stage-1 rows, for wall-clock")
    parser.add_argument("--batch-size", type=int, default=16)
    parser.add_argument("--learning-rate", type=float, default=3e-5)
    parser.add_argument("--skip-pretrain", action="store_true")
    parser.add_argument("--test-size", type=float, default=0.2)
    args = parser.parse_args(argv)

    import numpy as np
    import torch
    from sklearn.model_selection import train_test_split
    from transformers import AutoModelForSequenceClassification, AutoTokenizer

    torch.manual_seed(SEED)
    np.random.seed(SEED)
    print(_device_note(), flush=True)

    tokenizer = AutoTokenizer.from_pretrained(BASE_MODEL)

    # Stage 1 -------------------------------------------------------------
    if not args.skip_pretrain:
        frame = _pretrain_frame()
        if frame is not None:
            texts, labels = frame
            if len(texts) > args.pretrain_rows:
                keep = np.random.RandomState(SEED).choice(len(texts), args.pretrain_rows, replace=False)
                texts = [texts[i] for i in keep]
                labels = [labels[i] for i in keep]
            print(f"stage 1: {len(texts)} messages from {PRETRAIN_DATASET} ({sum(labels)} phishing)", flush=True)
            binary = AutoModelForSequenceClassification.from_pretrained(BASE_MODEL, num_labels=2)
            _train(binary, _tokenized(tokenizer, texts, labels), args.pretrain_epochs, args.batch_size, args.learning_rate, "stage1")
            staged = args.out.parent / "_distilroberta-pretrained"
            binary.save_pretrained(staged)
            base = str(staged)
        else:
            base = BASE_MODEL
    else:
        base = BASE_MODEL
    print(f"stage 2 starts from {base}", flush=True)

    # Stage 2 -------------------------------------------------------------
    corpus_texts, corpus_labels = load_corpus(default_settings.corpus_path)
    y = [LABELS.index(label) for label in corpus_labels]
    x_train, x_test, y_train, y_test = train_test_split(
        corpus_texts, y, test_size=args.test_size, random_state=SEED, stratify=y
    )
    print(f"stage 2: {len(x_train)} train / {len(x_test)} held out, {len(LABELS)} classes", flush=True)

    model = AutoModelForSequenceClassification.from_pretrained(
        base,
        num_labels=len(LABELS),
        ignore_mismatched_sizes=True,
        id2label=dict(enumerate(LABELS)),
        label2id={label: index for index, label in enumerate(LABELS)},
    )
    _train(model, _tokenized(tokenizer, x_train, y_train), args.epochs, args.batch_size, args.learning_rate, "stage2")
    torch_accuracy = _accuracy(model, tokenizer, x_test, y_test)
    print(f"\nfloat32 (PyTorch) hold-out accuracy: {torch_accuracy:.4f}", flush=True)

    # Export ---------------------------------------------------------------
    from optimum.onnxruntime import ORTModelForSequenceClassification, ORTQuantizer
    from optimum.onnxruntime.configuration import AutoQuantizationConfig

    work = args.out.parent / "_distilroberta-fp32"
    if work.exists():
        shutil.rmtree(work)
    model.save_pretrained(work)
    tokenizer.save_pretrained(work)

    onnx_model = ORTModelForSequenceClassification.from_pretrained(work, export=True)
    onnx_model.save_pretrained(work)
    tokenizer.save_pretrained(work)

    if args.out.exists():
        shutil.rmtree(args.out)
    args.out.mkdir(parents=True, exist_ok=True)
    quantizer = ORTQuantizer.from_pretrained(work)
    quantizer.quantize(
        save_dir=args.out,
        quantization_config=AutoQuantizationConfig.avx512_vnni(is_static=False, per_channel=False),
    )
    tokenizer.save_pretrained(args.out)
    (args.out / "labels.json").write_text(json.dumps(LABELS, indent=2), encoding="utf-8")

    size = sum(p.stat().st_size for p in args.out.rglob("*") if p.is_file()) / 1e6
    onnx_accuracy = _onnx_accuracy(args.out, x_test, y_test)
    print(
        f"\nint8 ONNX at {args.out}: {size:.0f} MB\n"
        f"  float32 PyTorch hold-out accuracy : {torch_accuracy:.4f}\n"
        f"  int8 ONNX  hold-out accuracy      : {onnx_accuracy:.4f}\n"
        f"  cost of quantisation              : {torch_accuracy - onnx_accuracy:+.4f}",
        flush=True,
    )
    for leftover in (args.out.parent / "_distilroberta-pretrained", work):
        if leftover.exists():
            shutil.rmtree(leftover)
    return 0


if __name__ == "__main__":
    sys.exit(main())
