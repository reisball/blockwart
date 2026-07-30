from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from blockwart.api.errors import install_api_error_contract
from blockwart.api.routes import agent, auth, catalog, health, v1
from blockwart.config import Settings, get_settings
from blockwart.ui.admin import router as admin_router
from blockwart.ui.auth import router as auth_router
from blockwart.ui.i18n import persist_locale_cookie, validate_locale_catalogs
from blockwart.ui.paths import STATIC_DIR
from blockwart.ui.routes import router as ui_router


def create_app(settings: Settings | None = None) -> FastAPI:
    validate_locale_catalogs()
    app = FastAPI(title="Blockwart", version="0.1.0")
    app.state.settings = settings or get_settings()
    install_api_error_contract(app)
    app.middleware("http")(persist_locale_cookie)

    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
    app.include_router(health.router, prefix="/api")
    app.include_router(catalog.router, prefix="/api")
    app.include_router(agent.router, prefix="/api")
    app.include_router(v1.router, prefix="/api")
    app.include_router(auth.router, prefix="/api")
    app.include_router(admin_router)
    app.include_router(auth_router)
    app.include_router(ui_router)
    return app


app = create_app()
