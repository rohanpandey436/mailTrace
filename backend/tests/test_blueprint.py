from __future__ import annotations

from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml")

BLUEPRINT = Path(__file__).resolve().parent.parent.parent / "render.yaml"


def _service() -> dict[str, object]:
    document = yaml.safe_load(BLUEPRINT.read_text(encoding="utf-8"))
    return next(service for service in document["services"] if service["name"] == "mailtrace")


def test_a_dashboard_only_push_redeploys_the_service() -> None:
    service = _service()

    assert service["rootDir"] == "backend"
    assert service["buildFilter"]["paths"] == ["backend/**", "frontend/**", "engine/**"]


def test_the_service_is_told_to_keep_itself_awake() -> None:
    variables = {entry["key"]: entry.get("value") for entry in _service()["envVars"]}

    assert variables["MAILTRACE_KEEPAWAKE_URL"] == "https://mailtrace-t9vo.onrender.com"
