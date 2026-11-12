from __future__ import annotations

import importlib.util
import re
from pathlib import Path
from types import ModuleType

from fastapi.testclient import TestClient

from app.config import Settings
from app.main import CACHE_FOREVER, CACHE_REVALIDATE, create_app

FRONTEND = Path(__file__).resolve().parent.parent.parent / "frontend"


def _builder() -> ModuleType:
    spec = importlib.util.spec_from_file_location("build_index", FRONTEND / "build_index.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _page() -> str:
    return (FRONTEND / "index.html").read_text(encoding="utf-8").replace("\r\n", "\n")


def test_the_page_lists_every_script_with_its_current_version() -> None:
    page = _page()

    assert _builder().render(page) == page


def test_the_script_list_comes_before_anything_that_loads_a_module() -> None:
    page = _page()

    assert page.index('<script type="importmap">') < page.index('<link rel="modulepreload"')
    assert page.index('<link rel="modulepreload"') < page.index('<script type="module"')


def test_every_versioned_address_in_the_page_is_cached_for_good(cfg: Settings) -> None:
    addresses = sorted(set(re.findall(r'(?:href|src)="((?:js|css)/[^"]+\?v=[0-9a-f]+)"', _page())))

    assert len(addresses) > 30
    with TestClient(create_app(cfg)) as client:
        for address in addresses:
            assert client.get(f"/{address}").headers["cache-control"] == CACHE_FOREVER, address


def test_anything_else_is_checked_with_the_server_every_time(cfg: Settings) -> None:
    with TestClient(create_app(cfg)) as client:
        assert client.get("/").headers["cache-control"] == CACHE_REVALIDATE
        assert client.get("/js/main.js").headers["cache-control"] == CACHE_REVALIDATE
        assert client.get("/js/main.js?v=000000000000").headers["cache-control"] == CACHE_REVALIDATE
        assert client.get("/css/app.css").headers["cache-control"] == CACHE_REVALIDATE


def test_a_changed_file_stops_being_cached_under_its_old_version(cfg: Settings, tmp_path: Path) -> None:
    site = tmp_path / "site"
    (site / "js").mkdir(parents=True)
    (site / "index.html").write_text("<!DOCTYPE html><title>t</title>", encoding="utf-8")
    script = site / "js" / "main.js"
    script.write_text("export const answer = 1;\n", encoding="utf-8")
    old = _builder().version(script)

    class Here(Settings):
        @property
        def static_dir(self) -> Path:
            return site

    here = Here(**{name: getattr(cfg, name) for name in cfg.__dataclass_fields__})
    with TestClient(create_app(here)) as client:
        assert client.get(f"/js/main.js?v={old}").headers["cache-control"] == CACHE_FOREVER
        script.write_text("export const answer = 22;\n", encoding="utf-8")
        assert client.get(f"/js/main.js?v={old}").headers["cache-control"] == CACHE_REVALIDATE
        assert client.get(f"/js/main.js?v={_builder().version(script)}").headers["cache-control"] == CACHE_FOREVER
