"""
FastAPI application factory.

``create_app(settings)`` wires the routers, the CORS policy (MailTrace is a
local analyst tool), the uniform ``{"error": ...}`` error shape and the
lifespan that owns the runtime state: the SQLite ``Store`` on ``app.state``,
the alert broadcaster bound to the running event loop, and a background
warm-up of the ML classifier that never blocks or fails startup.  ``app`` at
module level is what ``run.py`` / uvicorn import; tests call
``create_app(Settings(...))`` with a temporary data directory.

With ``MAILTRACE_ZERO_PERSISTENCE=true`` the lifespan builds an in-memory
store instead and creates no directories at all, the mode is logged loudly at
startup and reported by ``/api/health`` so nobody has to guess which mode a
running instance is in.
"""
from __future__ import annotations

import asyncio
import logging
import threading
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.requests import ClientDisconnect

from .api import alerts, analyze, cases, reports
from .config import Settings
from .config import settings as default_settings
from .core.errors import NotFound
from .database.case_manager import Store
from .schemas import ENGINE_VERSION, HealthStatus

log = logging.getLogger("mailtrace.main")


def _warm_model(cfg: Settings) -> None:
    """Load or train the classifier in a daemon thread; failure only costs the ML signal."""

    def run() -> None:
        try:
            from .ai import model_trainer as train

            train.load_or_train(cfg)
            log.info("ML classifier ready (%s)", cfg.model_path)
        except Exception as exc:  # noqa: BLE001 - the rule engine works without the model
            log.warning("ML classifier unavailable, continuing with rule-based analysis: %s", exc)

    threading.Thread(target=run, name="mt-ml-warmup", daemon=True).start()


async def _http_error(request: Request, exc: Exception) -> JSONResponse:
    assert isinstance(exc, StarletteHTTPException)  # registered for this type only
    return JSONResponse(status_code=exc.status_code, content={"error": str(exc.detail)}, headers=exc.headers)


async def _not_found(request: Request, exc: Exception) -> JSONResponse:
    """A domain-layer ``NotFound`` is a 404 in the API's uniform error shape."""
    return JSONResponse(status_code=404, content={"error": str(exc)})


async def _validation_error(request: Request, exc: Exception) -> JSONResponse:
    assert isinstance(exc, RequestValidationError)  # registered for this type only
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


def create_app(settings: Settings | None = None) -> FastAPI:
    cfg = settings or default_settings

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        if cfg.zero_persistence:
            # Stage 5C: no data directory, no evidence directory, no database file.
            # ``ensure_dirs`` is deliberately not called - creating the directories
            # would already be a write.
            app.state.store = Store(cfg.db_path, cfg.evidence_dir, in_memory=True)
        else:
            cfg.ensure_dirs()
            # database_url is empty unless MAILTRACE_DATABASE_URL / DATABASE_URL
            # names a PostgreSQL server; the Store falls back to SQLite by
            # itself if the driver or the server is missing.
            app.state.store = Store(cfg.db_path, cfg.evidence_dir, database_url=cfg.database_url)
        alerts.broadcaster.bind(asyncio.get_running_loop())
        _warm_model(cfg)
        if cfg.zero_persistence:
            log.warning(
                "*** ZERO-PERSISTENCE MODE *** MailTrace %s is analysing in memory only: no database, "
                "no evidence .eml, no email data written under %s. Every case, campaign, alert and "
                "custody record is lost when this process stops. (The one file this mode may still "
                "write there is the classifier cache %s, which is built from the bundled seed corpus "
                "and holds no email data.)",
                ENGINE_VERSION, cfg.data_dir, cfg.model_path.name,
            )
        log.info(
            "MailTrace %s ready: data=%s network=%s pii_mask_default=%s zero_persistence=%s webhooks=%d",
            ENGINE_VERSION, cfg.data_dir, cfg.enable_network, cfg.pii_mask_default,
            cfg.zero_persistence, len(cfg.webhook_urls),
        )
        try:
            yield
        finally:
            alerts.shutdown_webhooks()
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
    app.add_exception_handler(NotFound, _not_found)
    app.add_exception_handler(Exception, _unhandled_error)
    app.include_router(analyze.router)
    app.include_router(cases.router)
    app.include_router(reports.router)
    app.include_router(alerts.router)

    @app.get("/api/health", tags=["system"])
    def health() -> HealthStatus:
        # Imported inside the handler so the reported state is always the
        # parser's live state and main.py keeps no import-time dependency on
        # the analysis engine.
        from .ai import url_model
        from .core import parser

        store: Store | None = getattr(app.state, "store", None)
        return HealthStatus(
            network=cfg.enable_network,
            pii_mask_default=cfg.pii_mask_default,
            # Stage 5C: an auditor (and the UI) can see which mode is running.
            zero_persistence=cfg.zero_persistence,
            webhooks=len(cfg.webhook_urls),
            # The engine actually in use ("sqlite" / "postgresql"), not the one
            # that was configured: a PostgreSQL URL whose driver or server is
            # missing degrades to SQLite, and that must be visible, not guessed.
            database=store.backend if store is not None else "sqlite",
            database_note=store.backend_note if store is not None else "store not initialised",
            # Stage 2 PARSE-C++: whether the optional native dissector
            # (engine/) is doing the MIME work, or the pure-Python fallback.
            # Both produce identical results - this only says which is
            # installed and healthy.  See engine/README.md.
            # Stage 4: onnxruntime serves the URL model from the graph committed
            # at app/ai/url_model.onnx; xgboost fits it and is the fallback.
            url_model=url_model.loaded_backend(),
            # Stage 3B: a local GeoLite2 database when the build downloaded one,
            # otherwise ip-api.com, which is rate-limited and city-level at best.
            geoip_source=cfg.maxmind_db or "ip-api.com",
            native_engine=parser.NATIVE_ENGINE,
            native_engine_version=parser.NATIVE_ENGINE_VERSION,
            native_engine_status=parser.NATIVE_ENGINE_STATUS,
        )

    _mount_dashboard(app, cfg.static_dir)
    return app


def _mount_dashboard(app: FastAPI, static_dir: Path) -> None:
    """Serve the dashboard (index.html with its css/ and js/) at the site root.

    Mounted after every router so the ``/api`` routes always win.  When the
    frontend directory is absent - a backend-only install - ``/`` explains
    what is missing instead of returning a bare 404.
    """
    page = static_dir / "index.html"
    if page.is_file():
        app.mount("/", StaticFiles(directory=static_dir, html=True), name="dashboard")
        return

    @app.get("/", include_in_schema=False)
    def missing_dashboard() -> None:
        raise HTTPException(
            status_code=404,
            detail=f"web UI not installed: {page} is missing (expected the dashboard beside the backend)",
        )


app = create_app()
