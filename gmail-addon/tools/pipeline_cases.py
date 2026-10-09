from __future__ import annotations

import base64
import random
import tempfile
from pathlib import Path
from typing import Any

from mime_cases import fuzzed, handcrafted


def build(rng: random.Random, fuzz: int = 1500) -> dict[str, Any]:
    from export_fixtures import addon_config, collect, expected, settings

    cfg = settings(Path(tempfile.mkdtemp(prefix="mailtrace-pipeline-")))
    cfg.ensure_dirs()
    crafted = handcrafted()
    emails = list(crafted) + [(f"corpus_{name}", raw) for name, raw in collect()]
    emails += fuzzed(rng, [raw for _name, raw in crafted], fuzz)
    seen: set[bytes] = set()
    cases = []
    for name, raw in emails:
        if raw in seen:
            continue
        seen.add(raw)
        cases.append({"name": name, "raw": base64.b64encode(raw).decode("ascii"), "expected": expected(raw, name, cfg)})
    return {"config": addon_config(cfg), "cases": cases}
