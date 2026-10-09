from __future__ import annotations

import argparse
import base64
import json
import sys
import tempfile
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
BACKEND = ROOT / "backend"
for entry in (BACKEND, BACKEND / "tests", HERE):
    if str(entry) not in sys.path:
        sys.path.insert(0, str(entry))

VOLATILE = ("id", "analyzed_at", "processing_ms", "graph", "campaign_id")


def settings(data_dir: Path) -> Any:
    from app.config import Settings

    return Settings(
        data_dir=data_dir,
        org_name="Acme Corp",
        org_domains=["acme-corp.in"],
        executives=["ceo", "cfo", "managing director", "sarthak srivastava"],
        enable_network=False,
        alert_threshold=70,
    )


def addon_config(cfg: Any) -> dict[str, object]:
    return {
        "org_domains": list(cfg.org_domains),
        "executives": list(cfg.executives),
        "protected_brands": list(cfg.protected_brands),
        "trusted_relays": list(cfg.trusted_relays),
        "entropy_threshold": cfg.entropy_threshold,
        "max_domain_lookups": cfg.max_domain_lookups,
        "max_geo_lookups": cfg.max_geo_lookups,
        "simhash_max_distance": cfg.simhash_max_distance,
        "weights": dict(cfg.weights),
    }


def collect() -> list[tuple[str, bytes]]:
    from corpus_builder import build_all
    from extras import build_extras

    emails: list[tuple[str, bytes]] = []
    for path in sorted((ROOT / "samples").glob("*.eml")):
        emails.append((f"sample/{path.stem}", path.read_bytes()))
    for name, raw, _expect, _ok in build_all():
        emails.append((f"corpus/{name}", raw))
    for name, raw in build_extras():
        emails.append((f"extra/{name}", raw))
    return emails


def expected(raw: bytes, name: str, cfg: Any) -> dict[str, Any]:
    from app.core import pipeline

    result = pipeline.analyze_bytes(raw, f"{name.rsplit('/', 1)[-1]}.eml", None, cfg)
    payload = result.model_dump(mode="json")
    for key in VOLATILE:
        payload.pop(key, None)
    payload["email"].pop("parse_ms", None)
    return payload


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Write the verdicts the add-on engine must reproduce.")
    parser.add_argument("--out", type=Path, default=HERE.parent / "tests" / "fixtures")
    parser.add_argument("--only", default="", help="keep cases whose name contains this text")
    args = parser.parse_args(argv)

    args.out.mkdir(parents=True, exist_ok=True)
    cfg = settings(Path(tempfile.mkdtemp(prefix="mailtrace-fixtures-")))
    cfg.ensure_dirs()
    cases = []
    for name, raw in collect():
        if args.only and args.only not in name:
            continue
        cases.append({"name": name, "raw": base64.b64encode(raw).decode("ascii"), "expected": expected(raw, name, cfg)})
    document = {"config": addon_config(cfg), "cases": cases}
    target = args.out / "expected.json"
    target.write_text(json.dumps(document, ensure_ascii=False, separators=(",", ":")), encoding="utf-8", newline="\n")
    print(f"{len(cases)} case(s) written to {target} ({target.stat().st_size / 1024:.0f} KB)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
