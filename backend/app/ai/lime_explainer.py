"""
LIME for the text classifier: a local, sampling-based second explanation.

Which LIME is this?
-------------------
**A from-scratch implementation, not the ``lime`` package.**  The published
package was evaluated and rejected on two grounds, both of which matter for the
512 MB free tier this service is deployed on:

* it ships as an sdist only (``lime-0.2.0.1.tar.gz``, no wheel), so every deploy
  would build it from source -- exactly the "could fail to build on a Linux free
  tier" case the project rules out; and
* its ``install_requires`` is ``matplotlib, numpy, scipy, tqdm,
  scikit-learn>=0.18, scikit-image>=0.12`` -- scikit-image and matplotlib alone
  add well over 100 MB installed, for plotting and image-segmentation code this
  service would never call.

So the algorithm is reimplemented here, in ~120 lines, against dependencies the
project already has (numpy + scikit-learn's ``Ridge``).  It follows
``lime.lime_text.LimeTextExplainer`` / ``lime.lime_base.LimeBase`` step for step:

1. **Interpretable representation.**  The message is split on ``\\W+`` into
   words; the interpretable features are the *unique* words, and switching a
   feature off removes every occurrence of that word (LIME's ``bow=True``).
2. **Perturbation.**  ``n_samples`` neighbours are drawn.  For each, a count
   ``k ~ Uniform{1..d}`` of words is chosen and those ``k`` words are removed.
   Row 0 is the unperturbed message, as in LIME.
3. **Labelling.**  The *real* classifier scores every neighbour -- one batched
   ``predict_proba`` call, so the whole neighbourhood costs one vectorisation
   pass.
4. **Locality weighting.**  ``pi(z) = sqrt(exp(-D^2 / width^2))`` with ``D`` the
   cosine distance from the original binary vector scaled by 100, and
   ``width = 25`` (LIME's default kernel width for text).
5. **Feature selection.**  ``highest_weights``: a weighted ridge over all
   features, keep the ``top_k`` largest ``|coefficient|``.
6. **Local surrogate.**  A second weighted ``Ridge(alpha=1)`` on just those
   features.  Its coefficients are the explanation and its weighted R^2 is
   reported as ``local_r2`` -- the fidelity of the surrogate to the real model
   in this neighbourhood.  A low R^2 means the explanation should not be
   trusted, and saying so is the point of reporting it.

Deviations from the package, all for latency, all deliberate:

* the message is truncated to ``CHAR_LIMIT`` characters before tokenising;
* ``n_samples`` defaults to ``Settings.lime_samples`` (160) rather than LIME's
  5000, which is tuned for image and tabular models with far more features.

Why bother, given SHAP is already exact?
----------------------------------------
The SHAP values in ``app/ai/model_trainer.py`` are exact *for the linear model* --
they are a closed-form read of its coefficients, so they can only ever tell you
what the model's weights are.  LIME asks a different question: it perturbs the
input, watches what the *whole pipeline* actually does (both TF-IDF blocks, the
sublinear scaling, the character n-grams SHAP's token view never shows), and
fits a fresh local model to that behaviour.  The two agreeing is genuine
corroboration; the two disagreeing is a signal that the token-level story is
incomplete.  Neither is a substitute for the other.

Everything here is best effort: any failure returns an empty explanation and is
logged, never raised.
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Callable, Sequence

if TYPE_CHECKING:  # pragma: no cover - annotations only; numpy is imported lazily at runtime
    import numpy as np
    from numpy.typing import NDArray

log = logging.getLogger("mailtrace.ml.lime")

#: Name recorded on the analysis so a reader knows which implementation ran.
METHOD = "lime-builtin"

#: LIME's default exponential kernel width for text.
KERNEL_WIDTH = 25.0
#: Ridge penalty of the local surrogate; LIME's default model_regressor.
RIDGE_ALPHA = 1.0
#: Characters of the message fed to LIME (see the deviations note above).
CHAR_LIMIT = 2400
#: Below this many distinct words a local surrogate is meaningless.
MIN_FEATURES = 2

_TOKEN_RE = re.compile(r"\W+", re.UNICODE)


@dataclass
class LimeExplanation:
    """Coefficients of the local weighted ridge surrogate, strongest first."""

    weights: list[tuple[str, float]] = field(default_factory=list)
    intercept: float = 0.0
    local_r2: float = 0.0
    n_samples: int = 0
    n_features: int = 0
    method: str = METHOD

    def __bool__(self) -> bool:
        return bool(self.weights)


def tokenize(text: str) -> tuple[list[str], list[str]]:
    """(pieces, vocabulary): the message split on ``\\W+`` keeping the
    separators, and the unique words in order of first appearance.

    Splitting with a capturing regex means the original text can be rebuilt
    exactly by joining ``pieces``, so a perturbation only ever differs from the
    original by the words it removed -- no whitespace or punctuation drift that
    the character n-gram block would otherwise notice.
    """
    body = (text or "")[:CHAR_LIMIT]
    pieces = re.split(r"(\W+)", body, flags=re.UNICODE)
    seen: dict[str, None] = {}
    for piece in pieces:
        if piece and not _TOKEN_RE.fullmatch(piece):
            seen.setdefault(piece, None)
    return pieces, list(seen)


def _perturbations(
    pieces: Sequence[str], vocabulary: Sequence[str], n_samples: int, rng: np.random.Generator
) -> tuple[list[str], NDArray[np.float64]]:
    """``n_samples`` neighbours plus the binary on/off matrix that describes them.

    Row 0 is the original message with every word present, which is what makes
    the surrogate local: the kernel gives it the largest possible weight.
    """
    import numpy as np

    index = {word: i for i, word in enumerate(vocabulary)}
    d = len(vocabulary)
    mask = np.ones((n_samples, d), dtype=np.float64)
    texts: list[str] = ["".join(pieces)]
    sizes = rng.integers(1, d + 1, size=n_samples - 1)
    for row, size in enumerate(sizes, start=1):
        off = rng.choice(d, size=int(size), replace=False)
        mask[row, off] = 0.0
        dropped = {vocabulary[i] for i in off}
        texts.append("".join("" if (p and p in index and p in dropped) else p for p in pieces))
    return texts, mask


def _kernel(mask: NDArray[np.float64], width: float = KERNEL_WIDTH) -> NDArray[np.float64]:
    """LIME's exponential kernel over the cosine distance from the original."""
    import numpy as np

    reference = np.ones((1, mask.shape[1]), dtype=np.float64)
    dot = mask @ reference.T
    norms = np.linalg.norm(mask, axis=1, keepdims=True) * np.linalg.norm(reference)
    with np.errstate(divide="ignore", invalid="ignore"):
        cosine = np.where(norms > 0, dot / np.maximum(norms, 1e-12), 0.0)
    distance = (1.0 - cosine).ravel() * 100.0
    return np.sqrt(np.exp(-(distance ** 2) / (width ** 2)))


def explain(
    predict_proba: Callable[[list[str]], Any],
    text: str,
    class_index: int,
    n_samples: int = 160,
    top_k: int = 12,
    seed: int = 42,
) -> LimeExplanation:
    """Fit a local linear surrogate around ``text`` and return its coefficients.

    ``predict_proba`` takes a list of texts and returns an ``(n, n_classes)``
    array -- the real model, called once for the whole neighbourhood.  Never
    raises: on any failure an empty :class:`LimeExplanation` comes back and the
    caller simply has no LIME weights.
    """
    empty = LimeExplanation()
    try:
        import numpy as np
        from sklearn.linear_model import Ridge
    except ImportError as exc:  # pragma: no cover - sklearn is a hard dependency
        log.warning("LIME needs numpy/scikit-learn (%s); skipping", exc)
        return empty

    pieces, vocabulary = tokenize(text)
    if len(vocabulary) < MIN_FEATURES:
        return empty
    n_samples = max(MIN_FEATURES * 4, int(n_samples))
    try:
        rng = np.random.default_rng(seed)
        texts, mask = _perturbations(pieces, vocabulary, n_samples, rng)
        probabilities = np.asarray(predict_proba(texts), dtype=np.float64)
        if probabilities.ndim != 2 or not (0 <= class_index < probabilities.shape[1]):
            log.debug("LIME got an unusable probability matrix %s", getattr(probabilities, "shape", None))
            return empty
        target = probabilities[:, class_index]
        weights = _kernel(mask)

        # 1. Feature selection: a weighted ridge over everything, keep the
        #    largest |coefficient| -- LIME's 'highest_weights' strategy.
        scout = Ridge(alpha=RIDGE_ALPHA, fit_intercept=True, random_state=seed)
        scout.fit(mask, target, sample_weight=weights)
        keep = list(np.argsort(np.abs(scout.coef_))[::-1][: max(1, int(top_k))])

        # 2. The explanation itself: refit on just those features.
        surrogate = Ridge(alpha=RIDGE_ALPHA, fit_intercept=True, random_state=seed)
        surrogate.fit(mask[:, keep], target, sample_weight=weights)
        r2 = float(surrogate.score(mask[:, keep], target, sample_weight=weights))
    except Exception:  # explanation must never break analysis
        log.debug("LIME explanation failed", exc_info=True)
        return empty

    pairs = [(str(vocabulary[i]), float(coefficient)) for i, coefficient in zip(keep, surrogate.coef_)]
    pairs.sort(key=lambda item: -abs(item[1]))
    return LimeExplanation(
        weights=pairs,
        intercept=float(surrogate.intercept_),
        local_r2=r2 if r2 == r2 else 0.0,          # NaN R^2 (degenerate target) -> 0
        n_samples=len(texts),
        n_features=len(vocabulary),
        method=METHOD,
    )


def explain_pipeline(
    pipeline: Any, text: str, label: str, n_samples: int = 160, top_k: int = 12, seed: int = 42
) -> LimeExplanation:
    """LIME over a fitted scikit-learn classification pipeline for one class.

    Resolves ``label`` against ``pipeline.classes_`` and hands
    ``pipeline.predict_proba`` to :func:`explain`.  Returns an empty explanation
    when the label is not one the pipeline knows.
    """
    try:
        classes = [str(c) for c in pipeline.classes_]
        class_index = classes.index(str(label))
    except (AttributeError, ValueError):
        log.debug("LIME could not resolve label %r on the pipeline", label)
        return LimeExplanation()
    return explain(
        lambda batch: pipeline.predict_proba(batch),
        text,
        class_index,
        n_samples=n_samples,
        top_k=top_k,
        seed=seed,
    )


def resolve_samples(cfg: Any | None = None, default: int = 160) -> int:
    """``Settings.lime_samples`` clamped to a sane range."""
    raw = getattr(cfg, "lime_samples", default) if cfg is not None else default
    try:
        value = int(raw)
    except (TypeError, ValueError):
        value = default
    return max(16, min(2000, value))
