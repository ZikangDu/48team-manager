"""48 Team Manager application factory."""

from __future__ import annotations

import asyncio
import hashlib
import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.gzip import GZipMiddleware
from starlette.middleware.sessions import SessionMiddleware

from app import __version__
from app.application.auth import initialize_admin_password
from app.core.config import Settings, load_settings
from app.persistence.database import create_engine, create_session_factory
from app.persistence.migrations.bootstrap import bootstrap_schema
from app.web.deps import html_login_redirect, session_dependency
from app.web.routes.auth import build_auth_router
from app.web.routes.credential_import import build_credential_import_router
from app.web.routes.assisted_login import build_assisted_login_router
from app.web.routes.protocol_auth import build_protocol_auth_router
from app.web.routes.bridge_workbench import build_bridge_workbench_router
from app.web.routes.api import build_api_router
from app.web.routes.extension import build_extension_router
from app.web.routes.pages import build_pages_router
from app.web.routes.pool import build_pool_router
from app.web.routes.runner import build_runner_router

WEB_DIR = Path(__file__).resolve().parent / "web"
STATIC_DIR = WEB_DIR / "static"
_asset_versions: dict[str, tuple[int, str]] = {}


def static_url(path: str) -> str:
    """Content-hashed static URL so a deploy never mixes fresh HTML with cached CSS/JS."""
    path = path.lstrip("/")
    file = STATIC_DIR / path
    try:
        mtime = file.stat().st_mtime_ns
    except OSError:
        return f"/static/{path}"
    cached = _asset_versions.get(path)
    if cached is None or cached[0] != mtime:
        cached = (mtime, hashlib.sha256(file.read_bytes()).hexdigest()[:10])
        _asset_versions[path] = cached
    return f"/static/{path}?v={cached[1]}"


def configure_logging(settings: Settings) -> None:
    logging.basicConfig(
        level=getattr(logging, settings.log_level.upper(), logging.INFO),
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or load_settings()
    configure_logging(settings)
    logger = logging.getLogger("team48")

    engine = create_engine(settings)
    session_factory = create_session_factory(engine)
    get_db = session_dependency(session_factory)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        if settings.secret_key == "your-secret-key-here-change-in-production":
            logger.warning("SECRET_KEY is still the example value")
        if settings.admin_password == "admin123":
            logger.warning("ADMIN_PASSWORD is still the example value")
        if settings.auto_rotate_enabled or settings.force_refill:
            logger.warning("auto rotate / force refill must stay off until explicitly approved")
        await bootstrap_schema(engine)
        async with session_factory() as session:
            await initialize_admin_password(session, settings)
            from app.application.operations import recover_stale_operations

            await recover_stale_operations(session)
            from app.application.assisted_login import recover_assisted_logins

            await recover_assisted_logins(session)
            from app.application.protocol_auth import recover_protocol_auth

            await recover_protocol_auth(session)
            from app.application.console_actions import recover_runner_selfchecks

            # Self-checks live in this process only; after a restart none of them can still be running.
            await recover_runner_selfchecks(session)
        app.state.engine = engine
        app.state.session_factory = session_factory
        app.state.settings = settings
        from app.application.jobs.scheduler import start_scheduler, stop_scheduler
        from app.application.jobs.dispatcher import reauth_dispatcher
        from app.application.jobs.commands import command_runner

        start_scheduler(settings, session_factory)
        reauth_dispatcher.start(session_factory, deployment_allowed=settings.auto_reauth_enabled)
        command_runner.start(session_factory)

        bridge_task = None
        if settings.auth_bridge_enabled and settings.auth_bridge_managed:
            # The bundled GPTAuthBridge runs as Team48's own child process. Start it in the
            # background so its browser-pool warm-up never delays Team48 boot, and so a failure
            # here only disables protocol login, never the rest of the app.
            from urllib.parse import urlsplit
            from app.integrations.auth_bridge.supervisor import bridge_supervisor, team48_python
            from app.persistence.database import sqlite_path_from_url

            async def start_bridge() -> None:
                try:
                    bridge_port = urlsplit(settings.auth_bridge_url).port or 4174
                    db_path = sqlite_path_from_url(settings.database_url)
                    runtime_dir = (db_path.parent if db_path else Path("data")) / "auth-bridge"
                    state = await bridge_supervisor.start(port=bridge_port, runtime_dir=runtime_dir,
                                                          python=team48_python(), proxy=settings.auth_bridge_proxy)
                    if state not in {"running", "external"}:
                        logger.warning("auth bridge not available: %s", bridge_supervisor.reason)
                except Exception:
                    logger.exception("auth bridge supervisor failed to start")

            bridge_task = asyncio.create_task(start_bridge())

        async def backfill_revenue() -> None:
            # Departures found before sync-time booking existed (or missed by it); reads Sub2API, so off the startup path.
            from app.application.revenue_ledger import revenue_ledger

            try:
                async with session_factory() as session:
                    count = await revenue_ledger.backfill_departures(session)
                if count:
                    logger.info("revenue ledger: backfilled %s departed members", count)
            except Exception:
                logger.exception("revenue ledger: startup backfill failed")
            # Daily revenue of recently departed accounts (read-only against Sub2API).
            from app.application.revenue_daily import revenue_daily

            try:
                async with session_factory() as session:
                    written = await revenue_daily.backfill_recent(session)
                if written:
                    logger.info("revenue daily: backfilled %s day rows", written)
            except Exception:
                logger.exception("revenue daily: startup backfill failed")

        backfill_task = asyncio.create_task(backfill_revenue())
        yield
        backfill_task.cancel()
        await asyncio.gather(backfill_task, return_exceptions=True)
        stop_scheduler()
        await command_runner.stop()
        if bridge_task is not None:
            from app.integrations.auth_bridge.supervisor import bridge_supervisor

            bridge_task.cancel()
            await asyncio.gather(bridge_task, return_exceptions=True)
            await bridge_supervisor.stop()
        from app.application.assisted_login import cleanup_assisted_logins

        await cleanup_assisted_logins()
        from app.application.credential_import import clear_previews

        clear_previews()
        await reauth_dispatcher.stop()
        await engine.dispose()

    app = FastAPI(
        title="48 Team Manager",
        description="Self-hosted operations console for ChatGPT Team / Workspace accounts.",
        version=__version__,
        lifespan=lifespan,
    )
    app.state.settings = settings

    @app.middleware("http")
    async def protect_import_responses(request: Request, call_next):
        response = await call_next(request)
        if any(request.url.path == prefix or request.url.path.startswith(prefix + "/")
               for prefix in ("/api/credential-import", "/api/assisted-login", "/api/protocol-auth", "/api/bridge-workbench")):
            response.headers["Cache-Control"] = "no-store"
            response.headers["Pragma"] = "no-cache"
        return response

    @app.exception_handler(StarletteHTTPException)
    async def http_exception_handler(request: Request, exc: StarletteHTTPException):
        redirected = html_login_redirect(request, HTTPException(status_code=exc.status_code, detail=exc.detail))
        if redirected is not None:
            return redirected
        return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})

    app.add_middleware(
        SessionMiddleware,
        secret_key=settings.effective_session_secret_key,
        session_cookie="session",
        max_age=14 * 24 * 60 * 60,
        same_site="lax",
        https_only=settings.session_cookie_secure,
    )
    app.add_middleware(GZipMiddleware, minimum_size=1024)

    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
    templates = Jinja2Templates(directory=str(WEB_DIR / "templates"))
    templates.env.globals["app_version"] = __version__
    templates.env.globals["static_url"] = static_url

    app.include_router(build_pages_router(templates, __version__))
    app.include_router(build_auth_router(get_db, settings))
    app.include_router(build_credential_import_router(get_db))
    app.include_router(build_assisted_login_router(get_db))
    app.include_router(build_protocol_auth_router(get_db))
    app.include_router(build_bridge_workbench_router(get_db))
    app.include_router(build_api_router(get_db))
    app.include_router(build_pool_router(get_db))
    app.include_router(build_extension_router(get_db, settings))
    # Loopback API for the Chromix extension runner; authenticated by the per-run token only.
    app.include_router(build_runner_router(get_db))

    @app.get("/health")
    async def health():
        from app.application.jobs.dispatcher import reauth_dispatcher

        runtime = await reauth_dispatcher.summary()
        from app.integrations.auth_bridge.supervisor import bridge_supervisor

        return {
            "status": "healthy",
            "app": "48 Team Manager",
            "version": __version__,
            "runtime": runtime,
            "auth_bridge": bridge_supervisor.summary(),
        }

    @app.get("/favicon.ico", include_in_schema=False)
    async def favicon():
        return FileResponse(WEB_DIR / "static" / "logo.svg")

    return app


app = create_app()
