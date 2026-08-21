import asyncio
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles

from blockwart.api.errors import (
    install_api_error_contract,
    install_batch_request_bound,
    install_request_context,
)
from blockwart.api.routes import admin, agent, auth, catalog, health, v1, webhooks
from blockwart.config import Settings, get_settings
from blockwart.domain.schema_projection import object_schema_projection
from blockwart.services.login_protection import LoginProtector
from blockwart.services.monitoring import run_monitoring_poller
from blockwart.ui.admin import router as admin_ui_router
from blockwart.ui.auth import router as auth_router
from blockwart.ui.i18n import persist_locale_cookie, validate_locale_catalogs
from blockwart.ui.paths import STATIC_DIR
from blockwart.ui.routes import router as ui_router


def create_app(settings: Settings | None = None) -> FastAPI:
    validate_locale_catalogs()
    resolved_settings = settings or get_settings()
    app = FastAPI(
        title="Blockwart",
        version="0.1.0",
        lifespan=_monitoring_lifespan(resolved_settings),
    )
    app.state.settings = resolved_settings
    app.state.login_protector = LoginProtector(
        window_seconds=resolved_settings.auth_login_rate_window_seconds,
        source_attempt_limit=resolved_settings.auth_login_source_attempt_limit,
        account_attempt_limit=resolved_settings.auth_login_account_attempt_limit,
        global_attempt_limit=resolved_settings.auth_login_global_attempt_limit,
        source_challenge_limit=resolved_settings.auth_login_source_challenge_limit,
        global_challenge_limit=resolved_settings.auth_login_global_challenge_limit,
        max_password_concurrency=resolved_settings.auth_password_max_concurrency,
    )
    install_batch_request_bound(app)
    install_api_error_contract(app)
    app.middleware("http")(persist_locale_cookie)
    app.middleware("http")(principal_scoped_cache_control)

    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
    app.include_router(health.router, prefix="/api")
    app.include_router(catalog.router, prefix="/api")
    app.include_router(agent.router, prefix="/api")
    app.include_router(v1.router, prefix="/api")
    app.include_router(webhooks.router, prefix="/api")
    app.include_router(admin.router, prefix="/api")
    app.include_router(auth.router, prefix="/api")
    app.include_router(auth_router)
    app.include_router(admin_ui_router)
    app.include_router(ui_router)
    install_request_context(app)
    default_openapi = app.openapi

    def canonical_openapi():
        schema = default_openapi()
        schema["x-blockwart-object-schema"] = object_schema_projection()
        return schema

    app.openapi = canonical_openapi
    return app


def _monitoring_lifespan(
    settings: Settings,
) -> Callable[[FastAPI], AsyncIterator[None]]:
    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        stop_event = asyncio.Event()
        task: asyncio.Task[None] | None = None
        if settings.monitoring_poller_enabled:
            task = asyncio.create_task(run_monitoring_poller(settings, stop_event))
        try:
            yield
        finally:
            if task is not None:
                stop_event.set()
                await task

    return lifespan


async def principal_scoped_cache_control(request: Request, call_next):
    response = await call_next(request)
    if _is_principal_scoped_path(request.url.path):
        response.headers["Cache-Control"] = "private, no-store"
        response.headers["Pragma"] = "no-cache"
        vary = {
            value.strip() for value in response.headers.get("Vary", "").split(",") if value.strip()
        }
        vary.update({"Authorization", "Cookie"})
        response.headers["Vary"] = ", ".join(sorted(vary))
    return response


def _is_principal_scoped_path(path: str) -> bool:
    return (
        path == "/"
        or path.startswith("/objects")
        or path.startswith("/admin/")
        or path.startswith("/settings/")
        or path.startswith("/api/objects")
        or path.startswith("/api/agent")
        or path.startswith("/api/v1")
    )


app = create_app()
