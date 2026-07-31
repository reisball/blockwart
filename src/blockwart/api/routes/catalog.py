from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from blockwart.api.deps import get_session
from blockwart.api.errors import API_ERROR_RESPONSES
from blockwart.api.security import require_api_read_access
from blockwart.domain.asset_state import AssetHealth, AssetLifecycle
from blockwart.schemas.catalog import CatalogObjectReadOut
from blockwart.services.queries import (
    get_catalog_object,
    list_catalog_objects,
)
from blockwart.services.read_access import ReadAccess

router = APIRouter(
    prefix="/objects",
    tags=["catalog"],
    responses=API_ERROR_RESPONSES,
)


@router.get("", response_model=list[CatalogObjectReadOut])
def get_objects(
    session: Annotated[Session, Depends(get_session)],
    access: Annotated[ReadAccess, Depends(require_api_read_access)],
    lifecycle: Annotated[
        AssetLifecycle | None,
        Query(description="Exact asset lifecycle"),
    ] = None,
    health: Annotated[
        AssetHealth | None,
        Query(description="Exact asset health"),
    ] = None,
) -> list[CatalogObjectReadOut]:
    return list_catalog_objects(
        session,
        access,
        lifecycle=lifecycle,
        health=health,
    )


@router.get("/{object_id}", response_model=CatalogObjectReadOut)
def get_object_by_id(
    object_id: str,
    session: Annotated[Session, Depends(get_session)],
    access: Annotated[ReadAccess, Depends(require_api_read_access)],
) -> CatalogObjectReadOut:
    catalog_object = get_catalog_object(session, object_id, access)
    if catalog_object is None:
        raise HTTPException(status_code=404, detail="Catalog object not found")
    return catalog_object
