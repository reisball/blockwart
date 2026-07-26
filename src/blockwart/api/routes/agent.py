from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from blockwart.api.deps import get_session
from blockwart.api.errors import API_ERROR_RESPONSES
from blockwart.domain.asset_state import AssetHealth, AssetLifecycle
from blockwart.schemas.agent import AgentContextOut, AgentSearchOut
from blockwart.schemas.catalog import ObjectKind
from blockwart.services.agent import (
    build_agent_context,
    get_agent_object_context,
    search_agent_objects,
)

router = APIRouter(
    prefix="/agent",
    tags=["agent-readonly"],
    responses=API_ERROR_RESPONSES,
)


@router.get("/search", response_model=AgentSearchOut)
def agent_search(
    session: Annotated[Session, Depends(get_session)],
    q: Annotated[
        str | None,
        Query(description="Search term for id, label, summary, or data"),
    ] = None,
    kind: ObjectKind | None = None,
    parent: Annotated[str | None, Query(description="Typed parent reference")] = None,
    ip: Annotated[str | None, Query(description="Resolved exact IP address")] = None,
    port: Annotated[int | None, Query(ge=1, le=65535)] = None,
    endpoint_type: str | None = None,
    protocol: str | None = None,
    exposure: str | None = None,
    status: str | None = None,
    lifecycle: AssetLifecycle | None = None,
    health: AssetHealth | None = None,
    limit: Annotated[int, Query(ge=1, le=50)] = 10,
) -> AgentSearchOut:
    filters = _active_filters(
        parent=parent,
        ip=ip,
        port=port,
        endpoint_type=endpoint_type,
        protocol=protocol,
        exposure=exposure,
        status=status,
        lifecycle=lifecycle,
        health=health,
    )
    results = search_agent_objects(
        session,
        query=q,
        kind=kind,
        **filters,
        limit=limit,
    )
    return AgentSearchOut(
        query=q,
        kind=kind,
        filters=filters,
        count=len(results),
        results=results,
    )


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
    parent: Annotated[str | None, Query(description="Typed parent reference")] = None,
    ip: Annotated[str | None, Query(description="Resolved exact IP address")] = None,
    port: Annotated[int | None, Query(ge=1, le=65535)] = None,
    endpoint_type: str | None = None,
    protocol: str | None = None,
    exposure: str | None = None,
    status: str | None = None,
    lifecycle: AssetLifecycle | None = None,
    health: AssetHealth | None = None,
    limit: Annotated[int, Query(ge=1, le=20)] = 5,
) -> AgentContextOut:
    filters = _active_filters(
        parent=parent,
        ip=ip,
        port=port,
        endpoint_type=endpoint_type,
        protocol=protocol,
        exposure=exposure,
        status=status,
        lifecycle=lifecycle,
        health=health,
    )
    objects = build_agent_context(
        session,
        query=q,
        kind=kind,
        **filters,
        limit=limit,
    )
    return AgentContextOut(
        query=q,
        kind=kind,
        filters=filters,
        count=len(objects),
        objects=objects,
    )


def _active_filters(
    *,
    parent: str | None,
    ip: str | None,
    port: int | None,
    endpoint_type: str | None,
    protocol: str | None,
    exposure: str | None,
    status: str | None,
    lifecycle: AssetLifecycle | None,
    health: AssetHealth | None,
) -> dict[str, str | int]:
    filters: dict[str, str | int | None] = {
        "parent": parent,
        "ip": ip,
        "port": port,
        "endpoint_type": endpoint_type,
        "protocol": protocol,
        "exposure": exposure,
        "status": status,
        "lifecycle": lifecycle,
        "health": health,
    }
    return {key: value for key, value in filters.items() if value is not None}
