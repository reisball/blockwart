from fastapi import APIRouter

from blockwart import __version__
from blockwart.schemas.catalog import HealthOut

router = APIRouter(tags=["health"])


@router.get("/health", response_model=HealthOut)
def health() -> HealthOut:
    return HealthOut(ok=True, service="blockwart", version=__version__)

