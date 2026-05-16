from fastapi import FastAPI

from blockwart.api.routes import agent, catalog, health
from blockwart.ui.routes import router as ui_router


def create_app() -> FastAPI:
    app = FastAPI(title="Blockwart", version="0.1.0")
    app.include_router(health.router, prefix="/api")
    app.include_router(catalog.router, prefix="/api")
    app.include_router(agent.router, prefix="/api")
    app.include_router(ui_router)
    return app


app = create_app()
