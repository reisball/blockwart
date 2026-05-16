from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from blockwart.api.deps import get_session
from blockwart.schemas.catalog import CatalogObjectIn, CatalogObjectOut
from blockwart.services.catalog import list_objects, upsert_object

router = APIRouter(prefix="/objects", tags=["catalog"])


@router.get("", response_model=list[CatalogObjectOut])
def get_objects(session: Annotated[Session, Depends(get_session)]) -> list[CatalogObjectOut]:
    return list_objects(session)


@router.put("/{object_id}", response_model=CatalogObjectOut)
def put_object(
    object_id: str,
    payload: CatalogObjectIn,
    session: Annotated[Session, Depends(get_session)],
) -> CatalogObjectOut:
    if payload.id != object_id:
        raise HTTPException(status_code=400, detail="Path object_id must match payload.id")
    return upsert_object(session, payload)
