from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from blockwart import __version__
from blockwart.db.readiness import DatabaseReadinessError, check_database_readiness
from blockwart.schemas.catalog import HealthOut, ReadinessOut

router = APIRouter(tags=["health"])


@router.get("/health", response_model=HealthOut)
@router.get("/health/live", response_model=HealthOut)
def liveness(request: Request) -> HealthOut:
    settings = request.app.state.settings
    return HealthOut(
        ok=True,
        status="alive",
        service="blockwart",
        version=__version__,
        build_revision=settings.build_revision,
    )


@router.get(
    "/health/ready",
    response_model=ReadinessOut,
    responses={503: {"model": ReadinessOut}},
)
def readiness(request: Request):
    settings = request.app.state.settings
    try:
        database = check_database_readiness(settings)
    except DatabaseReadinessError as exc:
        response = ReadinessOut(
            ok=False,
            status="not_ready",
            service="blockwart",
            version=__version__,
            build_revision=settings.build_revision,
            checks=exc.checks,
            revision=exc.revision,
            error_code=exc.code,
        )
        return JSONResponse(status_code=503, content=response.model_dump())

    return ReadinessOut(
        ok=True,
        status="ready",
        service="blockwart",
        version=__version__,
        build_revision=settings.build_revision,
        checks=database.checks,
        revision=database.revision,
    )
