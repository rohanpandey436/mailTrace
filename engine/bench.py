"""
Measure the native dissector against the pure-Python parser.

Run it from anywhere:

    python engine/bench.py                    # all samples/, 200 iterations each
    python engine/bench.py path/to/mail.eml -n 1000

Without the extension built it still runs and reports the Python baseline, so
the pitch deck's "MIME dissection < 5 ms" claim can be checked either way.
Nothing here is part of the service.
"""
from __future__ import annotations

import argparse
import statistics
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
BACKEND = HERE.parent / "backend"
SAMPLES = HERE.parent / "samples"
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

from app.core import parser  # noqa: E402


def timed(function, raw: bytes, iterations: int) -> tuple[float, float]:
    """Median and best milliseconds per call."""
    function(raw)  # warm caches
    timings = []
    for _ in range(iterations):
        start = time.perf_counter()
        function(raw)
        timings.append((time.perf_counter() - start) * 1000.0)
    return statistics.median(timings), min(timings)


def main(argv: list[str] | None = None) -> int:
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("files", nargs="*", type=Path, help="messages to time (default: samples/*.eml)")
    cli.add_argument("-n", "--iterations", type=int, default=200)
    args = cli.parse_args(argv)

    files = args.files or sorted(SAMPLES.glob("*.eml"))
    if not files:
        print("no messages to benchmark", file=sys.stderr)
        return 1

    print(f"native engine: {parser.NATIVE_ENGINE_STATUS}")
    if parser.NATIVE_ENGINE:
        print(f"version: {parser.NATIVE_ENGINE_VERSION}")
    print(f"{'message':<38}{'size':>9}{'python ms':>12}{'native ms':>12}{'speedup':>10}")
    print("-" * 81)

    for path in files:
        raw = path.read_bytes()
        python_ms, _ = timed(parser._python_message, raw, args.iterations)
        if parser.NATIVE_ENGINE:
            native_ms, _ = timed(parser._native_message, raw, args.iterations)
            speedup = f"{python_ms / native_ms:.2f}x" if native_ms > 0 else "-"
            native_text = f"{native_ms:.3f}"
        else:
            native_text, speedup = "-", "-"
        print(f"{path.name[:37]:<38}{len(raw):>9}{python_ms:>12.3f}{native_text:>12}{speedup:>10}")

    print()
    print("parse_email end to end (dissection + digests + hashing):")
    for path in files:
        raw = path.read_bytes()
        total_ms, best_ms = timed(lambda data: parser.parse_email(data), raw, args.iterations)
        print(f"  {path.name[:37]:<38}{total_ms:>10.3f} ms median{best_ms:>10.3f} ms best")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
