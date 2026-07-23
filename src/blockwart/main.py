from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from blockwart.api.routes import agent, catalog, health
from blockwart.config import Settings, get_settings
from blockwart.db.session import DatabaseTransactionError
from blockwart.ui.admin import router as admin_router
from blockwart.ui.routes import router as ui_router

PACKAGE_STATIC_DIR = Path(__file__).resolve().parent / "ui" / "static"
SOURCE_STATIC_DIR = Path.cwd() / "src" / "blockwart" / "ui" / "static"
STATIC_DIR = PACKAGE_STATIC_DIR if PACKAGE_STATIC_DIR.exists() else SOURCE_STATIC_DIR


def create_app(settings: Settings | None = None) -> FastAPI:
    app = FastAPI(title="Blockwart", version="0.1.0")
    app.state.settings = settings or get_settings()

    @app.exception_handler(DatabaseTransactionError)
    async def database_transaction_error_handler(
        _request: Request,
        _exc: DatabaseTransactionError,
    ) -> JSONResponse:
        return JSONResponse(
            status_code=503,
            content={"detail": "Database transaction failed"},
        )

    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
    app.include_router(health.router, prefix="/api")
    app.include_router(catalog.router, prefix="/api")
    app.include_router(agent.router, prefix="/api")
    app.include_router(admin_router)
    app.include_router(ui_router)
    return app


app = create_app()
