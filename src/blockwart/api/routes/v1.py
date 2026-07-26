from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from blockwart.api.deps import get_session
from blockwart.api.errors import API_ERROR_RESPONSES
from blockwart.domain.asset_state import AssetHealth, AssetLifecycle
from blockwart.domain.provenance import SourceType
from blockwart.schemas.agent import AgentCatalogObjectContext
from blockwart.schemas.catalog import ObjectKind, ObjectStatus
from blockwart.schemas.v1 import (
    ObjectSortField,
    SortDirection,
    V1AuditPageOut,
    V1ContextPageOut,
    V1ObjectPageOut,
    V1RelationshipPageOut,
    V1TopologyOut,
)
from blockwart.services.agent import (
    get_agent_object_context,
    query_agent_context_page,
    query_agent_objects_page,
)
from blockwart.services.pagination import InvalidCursor
from blockwart.services.v1 import (
    query_audit_page,
    query_relationship_page,
    query_topology_resource,
)

router = APIRouter(
    prefix="/v1",
    tags=["api-v1-readonly"],
    responses=API_ERROR_RESPONSES,
)

QueryText = Annotated[
    str | None,
    Query(
        max_length=200,
        description="Case-insensitive search over id, label, summary, and catalog data",
    ),
]
ParentFilter = Annotated[
    str | None,
    Query(max_length=192, description="Exact typed ancestor reference"),
]
IpFilter = Annotated[
    str | None,
    Query(max_length=64, description="Exact resolved IP address"),
]
EndpointTypeFilter = Annotated[
    str | None,
    Query(max_length=64, description="Exact endpoint capability"),
]
ProtocolFilter = Annotated[
    str | None,
    Query(max_length=32, description="Exact application protocol"),
]
ExposureFilter = Annotated[
    str | None,
    Query(max_length=32, description="Exact endpoint exposure"),
]
CursorParameter = Annotated[
    str | None,
    Query(max_length=2048, description="Opaque cursor returned by the previous page"),
]
PageLimit = Annotated[int, Query(ge=1, le=100)]


@router.get("/objects", response_model=V1ObjectPageOut)
def list_v1_objects(
    session: Annotated[Session, Depends(get_session)],
    q: QueryText = None,
    kind: ObjectKind | None = None,
    parent: ParentFilter = None,
    ip: IpFilter = None,
    port: Annotated[int | None, Query(ge=1, le=65535)] = None,
    endpoint_type: EndpointTypeFilter = None,
    protocol: ProtocolFilter = None,
    exposure: ExposureFilter = None,
    status: ObjectStatus | None = None,
    lifecycle: AssetLifecycle | None = None,
    health: AssetHealth | None = None,
    source_type: SourceType | None = None,
    stale: Annotated[
        bool | None,
        Query(description="Exact computed freshness state"),
    ] = None,
    limit: PageLimit = 50,
    cursor: CursorParameter = None,
    sort: ObjectSortField = "id",
    direction: SortDirection = "asc",
    include_total: Annotated[
        bool,
        Query(description="Compute the total matching result count"),
    ] = False,
) -> V1ObjectPageOut:
    try:
        page = query_agent_objects_page(
            session,
            query=q,
            kind=kind,
            parent=parent,
            ip=ip,
            port=port,
            endpoint_type=endpoint_type,
            protocol=protocol,
            exposure=exposure,
            status=status,
            lifecycle=lifecycle,
            health=health,
            source_type=source_type,
            stale=stale,
            limit=limit,
            cursor=cursor,
            sort=sort,
            direction=direction,
            include_total=include_total,
        )
    except InvalidCursor as exc:
        raise _invalid_cursor() from exc
    return V1ObjectPageOut(
        items=page.items,
        next_cursor=page.next_cursor,
        total=page.total,
        sort=sort,
        direction=direction,
    )


@router.get("/context", response_model=V1ContextPageOut)
def get_v1_context(
    session: Annotated[Session, Depends(get_session)],
    q: QueryText = None,
    kind: ObjectKind | None = None,
    parent: ParentFilter = None,
    ip: IpFilter = None,
    port: Annotated[int | None, Query(ge=1, le=65535)] = None,
    endpoint_type: EndpointTypeFilter = None,
    protocol: ProtocolFilter = None,
    exposure: ExposureFilter = None,
    status: ObjectStatus | None = None,
    lifecycle: AssetLifecycle | None = None,
    health: AssetHealth | None = None,
    source_type: SourceType | None = None,
    stale: Annotated[
        bool | None,
        Query(description="Exact computed freshness state"),
    ] = None,
    limit: Annotated[int, Query(ge=1, le=20)] = 5,
    cursor: CursorParameter = None,
    sort: ObjectSortField = "id",
    direction: SortDirection = "asc",
    include_total: Annotated[
        bool,
        Query(description="Compute the total matching result count"),
    ] = False,
) -> V1ContextPageOut:
    try:
        page = query_agent_context_page(
            session,
            query=q,
            kind=kind,
            parent=parent,
            ip=ip,
            port=port,
            endpoint_type=endpoint_type,
            protocol=protocol,
            exposure=exposure,
            status=status,
            lifecycle=lifecycle,
            health=health,
            source_type=source_type,
            stale=stale,
            limit=limit,
            cursor=cursor,
            sort=sort,
            direction=direction,
            include_total=include_total,
        )
    except InvalidCursor as exc:
        raise _invalid_cursor() from exc
    return V1ContextPageOut(
        items=page.items,
        next_cursor=page.next_cursor,
        total=page.total,
        sort=sort,
        direction=direction,
    )


@router.get(
    "/objects/{object_id}",
    response_model=AgentCatalogObjectContext,
)
def get_v1_object(
    object_id: str,
    session: Annotated[Session, Depends(get_session)],
) -> AgentCatalogObjectContext:
    context = get_agent_object_context(session, object_id)
    if context is None:
        raise HTTPException(status_code=404, detail="Catalog object not found")
    return context


@router.get(
    "/objects/{object_id}/relationships",
    response_model=V1RelationshipPageOut,
)
def get_v1_relationships(
    object_id: str,
    session: Annotated[Session, Depends(get_session)],
    limit: PageLimit = 50,
    cursor: CursorParameter = None,
    direction: SortDirection = "asc",
    include_total: Annotated[
        bool,
        Query(description="Compute the total relationship count"),
    ] = False,
) -> V1RelationshipPageOut:
    try:
        page = query_relationship_page(
            session,
            object_id,
            limit=limit,
            cursor=cursor,
            direction=direction,
            include_total=include_total,
        )
    except InvalidCursor as exc:
        raise _invalid_cursor() from exc
    if page is None:
        raise HTTPException(status_code=404, detail="Catalog object not found")
    return V1RelationshipPageOut(
        items=page.items,
        next_cursor=page.next_cursor,
        total=page.total,
        direction=direction,
    )


@router.get(
    "/objects/{object_id}/audit-events",
    response_model=V1AuditPageOut,
)
def get_v1_audit_events(
    object_id: str,
    session: Annotated[Session, Depends(get_session)],
    limit: PageLimit = 50,
    cursor: CursorParameter = None,
    direction: SortDirection = "desc",
    include_total: Annotated[
        bool,
        Query(description="Compute the total audit-event count"),
    ] = False,
) -> V1AuditPageOut:
    try:
        page = query_audit_page(
            session,
            object_id,
            limit=limit,
            cursor=cursor,
            direction=direction,
            include_total=include_total,
        )
    except InvalidCursor as exc:
        raise _invalid_cursor() from exc
    if page is None:
        raise HTTPException(status_code=404, detail="Catalog object not found")
    return V1AuditPageOut(
        items=page.items,
        next_cursor=page.next_cursor,
        total=page.total,
        direction=direction,
    )


@router.get(
    "/objects/{object_id}/topology",
    response_model=V1TopologyOut,
)
def get_v1_topology(
    object_id: str,
    session: Annotated[Session, Depends(get_session)],
) -> V1TopologyOut:
    resource = query_topology_resource(session, object_id)
    if resource is None:
        raise HTTPException(status_code=404, detail="Catalog object not found")
    return V1TopologyOut(
        object_ref=resource.object_ref,
        chains=resource.topology["chains"],
    )


def _invalid_cursor() -> HTTPException:
    return HTTPException(
        status_code=400,
        detail="Cursor is invalid or does not match the active query",
    )
