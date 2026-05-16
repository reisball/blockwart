from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from blockwart.api.deps import get_session
from blockwart.schemas.agent import AgentContextOut, AgentSearchOut
from blockwart.schemas.catalog import ObjectKind
from blockwart.services.agent import (
    build_agent_context,
    get_agent_object_context,
    search_agent_objects,
)

router = APIRouter(prefix="/agent", tags=["agent-readonly"])


@router.get("/search", response_model=AgentSearchOut)
def agent_search(
    session: Annotated[Session, Depends(get_session)],
    q: Annotated[
        str | None,
        Query(description="Search term for id, label, summary, or data"),
    ] = None,
    kind: ObjectKind | None = None,
    limit: Annotated[int, Query(ge=1, le=50)] = 10,
) -> AgentSearchOut:
    results = search_agent_objects(session, query=q, kind=kind, limit=limit)
    return AgentSearchOut(query=q, kind=kind, count=len(results), results=results)


@router.get("/objects/{object_id}", response_model=AgentContextOut)
def agent_object_context(
    object_id: str,
    session: Annotated[Session, Depends(get_session)],
) -> AgentContextOut:
    context = get_agent_object_context(session, object_id)
    if context is None:
        raise HTTPException(status_code=404, detail="Catalog object not found")
    return AgentContextOut(query=object_id, count=1, objects=[context])


@router.get("/context", response_model=AgentContextOut)
def agent_context(
    session: Annotated[Session, Depends(get_session)],
    q: Annotated[str | None, Query(description="Search term for context retrieval")] = None,
    kind: ObjectKind | None = None,
    limit: Annotated[int, Query(ge=1, le=20)] = 5,
) -> AgentContextOut:
    objects = build_agent_context(session, query=q, kind=kind, limit=limit)
    return AgentContextOut(query=q, kind=kind, count=len(objects), objects=objects)
