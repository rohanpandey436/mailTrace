"""
FastAPI application factory.

``create_app(settings)`` wires the routers, the CORS policy (MailTrace is a
local analyst tool), the uniform ``{"error": ...}`` error shape and the
lifespan that owns the runtime state: the SQLite ``Store`` on ``app.state``,
the alert broadcaster bound to the running event loop, and a background
warm-up of the ML classifier that never blocks or fails startup.  ``app`` at
module level is what ``run.py`` / uvicorn import; tests call
``create_app(Settings(...))`` with a temporary data directory.
"""
from __future__ import annotations

import asyncio
import logging
import threading
from contextlib import asynccontextmanager
from typing import Any, AsyncIterator, Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.requests import ClientDisconnect

from .api import alerts, analyze, cases, reports
from .config import Settings
from .config import settings as default_settings
from .db import Store
from .schemas import ENGINE_VERSION

log = logging.getLogger("mailtrace.main")


def _warm_model(cfg: Settings) -> None:
    """Load or train the classifier in a daemon thread; failure only costs the ML signal."""

    def run() -> None:
        try:
            from .ml import train

            train.load_or_train(cfg)
            log.info("ML classifier ready (%s)", cfg.model_path)
        except Exception as exc:  # noqa: BLE001 - the rule engine works without the model
            log.warning("ML classifier unavailable, continuing with rule-based analysis: %s", exc)

    threading.Thread(target=run, name="mt-ml-warmup", daemon=True).start()


async def _http_error(request: Request, exc: StarletteHTTPException) -> JSONResponse:
    return JSONResponse(status_code=exc.status_code, content={"error": str(exc.detail)}, headers=exc.headers)


async def _validation_error(request: Request, exc: RequestValidationError) -> JSONResponse:
    problems = "; ".join(
        f"{'.'.join(str(part) for part in error.get('loc', ())) or 'request'}: {error.get('msg', 'invalid value')}"
        for error in exc.errors()[:5]
    )
    return JSONResponse(status_code=422, content={"error": f"invalid request: {problems}"})


async def _unhandled_error(request: Request, exc: Exception) -> JSONResponse:
    if isinstance(exc, ClientDisconnect):
        log.debug("client disconnected during %s %s", request.method, request.url.path)
    else:
        log.error("unhandled error on %s %s", request.method, request.url.path, exc_info=exc)
    return JSONResponse(status_code=500, content={"error": "internal server error"})


def create_app(settings: Optional[Settings] = None) -> FastAPI:
    cfg = settings or default_settings

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        cfg.ensure_dirs()
        app.state.store = Store(cfg.db_path, cfg.evidence_dir)
        alerts.broadcaster.bind(asyncio.get_running_loop())
        _warm_model(cfg)
        log.info(
            "MailTrace %s ready: data=%s network=%s pii_mask_default=%s",
            ENGINE_VERSION, cfg.data_dir, cfg.enable_network, cfg.pii_mask_default,
        )
        try:
            yield
        finally:
            app.state.store.close()
            log.info("MailTrace store closed")

    app = FastAPI(
        title="MailTrace",
        version=ENGINE_VERSION,
        description="AI-powered email threat detection, geolocation and forensic intelligence.",
        lifespan=lifespan,
    )
    app.state.settings = cfg
    app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])
    app.add_exception_handler(StarletteHTTPException, _http_error)
    app.add_exception_handler(RequestValidationError, _validation_error)
    app.add_exception_handler(Exception, _unhandled_error)
    app.include_router(analyze.router)
    app.include_router(cases.router)
    app.include_router(reports.router)
    app.include_router(alerts.router)

    @app.get("/api/health", tags=["system"])
    def health() -> dict[str, Any]:
        return {
            "status": "ok",
            "engine_version": ENGINE_VERSION,
            "network": cfg.enable_network,
            "pii_mask_default": cfg.pii_mask_default,
        }

    @app.get("/", include_in_schema=False)
    def index() -> FileResponse:
        page = cfg.static_dir / "index.html"
        if not page.is_file():
            raise HTTPException(status_code=404, detail="web UI not installed: app/static/index.html is missing")
        return FileResponse(page, media_type="text/html")

    return app


app = create_app()
