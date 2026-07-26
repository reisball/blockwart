from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from blockwart.api.deps import get_session
from blockwart.api.errors import API_ERROR_RESPONSES
from blockwart.domain.asset_state import AssetHealth, AssetLifecycle
from blockwart.schemas.catalog import CatalogObjectOut
from blockwart.services.catalog import get_object, list_objects

router = APIRouter(
    prefix="/objects",
    tags=["catalog"],
    responses=API_ERROR_RESPONSES,
)


@router.get("", response_model=list[CatalogObjectOut])
def get_objects(
    session: Annotated[Session, Depends(get_session)],
    lifecycle: Annotated[
        AssetLifecycle | None,
        Query(description="Exact asset lifecycle"),
    ] = None,
    health: Annotated[
        AssetHealth | None,
        Query(description="Exact asset health"),
    ] = None,
) -> list[CatalogObjectOut]:
    return list_objects(session, lifecycle=lifecycle, health=health)


@router.get("/{object_id}", response_model=CatalogObjectOut)
def get_object_by_id(
    object_id: str,
    session: Annotated[Session, Depends(get_session)],
) -> CatalogObjectOut:
    catalog_object = get_object(session, object_id)
    if catalog_object is None:
        raise HTTPException(status_code=404, detail="Catalog object not found")
    return catalog_object
