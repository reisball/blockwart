from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy.orm import Session

from blockwart.api.deps import get_session
from blockwart.api.errors import API_ERROR_RESPONSES
from blockwart.api.security import require_api_read_access
from blockwart.domain.asset_state import AssetHealth, AssetLifecycle
from blockwart.domain.decisions import (
    APPLIES_TO_MAX_LENGTH,
    APPLIES_TO_PATTERN,
    DecisionStatus,
)
from blockwart.domain.projects import (
    RELATED_OBJECT_MAX_LENGTH,
    RELATED_OBJECT_PATTERN,
    ProjectCategory,
    ProjectStatus,
)
from blockwart.domain.provenance import SourceType
from blockwart.domain.runbooks import RunbookRisk, RunbookStatus
from blockwart.domain.search import (
    AGENT_SEARCH_LIMIT_MAX,
    CONTEXT_LIMIT_MAX,
    SEARCH_LIMIT_MIN,
    SEARCH_TEXT_MAX_LENGTH,
    SearchMatchMode,
    SearchQuery,
)
from blockwart.schemas.agent import AgentContextOut, AgentSearchOut
from blockwart.schemas.catalog import ObjectKind
from blockwart.schemas.v1 import V1NetworkTopologyOut
from blockwart.services.agent import (
    build_agent_context,
    get_agent_object_context,
    search_agent_objects,
)
from blockwart.services.commands import revision_etag
from blockwart.services.read_access import ReadAccess
from blockwart.services.v1 import query_network_topology_resource

router = APIRouter(
    prefix="/agent",
    tags=["agent-readonly"],
    responses=API_ERROR_RESPONSES,
)


@router.get("/search", response_model=AgentSearchOut)
def agent_search(
    session: Annotated[Session, Depends(get_session)],
    access: Annotated[ReadAccess, Depends(require_api_read_access)],
    q: Annotated[
        str | None,
        Query(
            max_length=SEARCH_TEXT_MAX_LENGTH,
            description="Search term for the closed server-defined search projection",
        ),
    ] = None,
    match: Annotated[
        SearchMatchMode,
        Query(description="normal, exact_ref, or exact_label matching"),
    ] = "normal",
    operational_only: Annotated[
        bool,
        Query(description="Exclude inactive, deleted, and retired records"),
    ] = False,
    kind: ObjectKind | None = None,
    parent: Annotated[str | None, Query(description="Typed parent reference")] = None,
    ip: Annotated[str | None, Query(description="Resolved exact IP address")] = None,
    port: Annotated[int | None, Query(ge=1, le=65535)] = None,
    endpoint_type: str | None = None,
    protocol: str | None = None,
    exposure: str | None = None,
    status: str | None = None,
    decision_status: DecisionStatus | None = None,
    applies_to: Annotated[
        str | None,
        Query(
            max_length=APPLIES_TO_MAX_LENGTH,
            pattern=APPLIES_TO_PATTERN,
            description="Exact authorized asset kind:id Decision scope",
        ),
    ] = None,
    runbook_status: RunbookStatus | None = None,
    runbook_risk: RunbookRisk | None = None,
    project_category: ProjectCategory | None = None,
    project_status: ProjectStatus | None = None,
    related_object: Annotated[
        str | None,
        Query(
            max_length=RELATED_OBJECT_MAX_LENGTH,
            pattern=RELATED_OBJECT_PATTERN,
            description="Exact authorized kind:id Project or Runbook relationship target",
        ),
    ] = None,
    lifecycle: AssetLifecycle | None = None,
    health: AssetHealth | None = None,
    source_type: SourceType | None = None,
    stale: Annotated[
        bool | None,
        Query(description="Exact computed freshness state"),
    ] = None,
    limit: Annotated[int, Query(ge=SEARCH_LIMIT_MIN, le=AGENT_SEARCH_LIMIT_MAX)] = 10,
) -> AgentSearchOut:
    filters = _active_filters(
        match=match,
        operational_only=operational_only,
        parent=parent,
        ip=ip,
        port=port,
        endpoint_type=endpoint_type,
        protocol=protocol,
        exposure=exposure,
        status=status,
        decision_status=decision_status,
        applies_to=applies_to,
        runbook_status=runbook_status,
        runbook_risk=runbook_risk,
        project_category=project_category,
        project_status=project_status,
        related_object=related_object,
        lifecycle=lifecycle,
        health=health,
        source_type=source_type,
        stale=stale,
    )
    results = search_agent_objects(
        session,
        access,
        search=SearchQuery(
            query=q,
            match=match,
            operational_only=operational_only,
            kind=kind,
            parent=parent,
            ip=ip,
            port=port,
            endpoint_type=endpoint_type,
            protocol=protocol,
            exposure=exposure,
            status=status,
            decision_status=decision_status,
            applies_to=applies_to,
            runbook_status=runbook_status,
            runbook_risk=runbook_risk,
            project_category=project_category,
            project_status=project_status,
            related_object=related_object,
            lifecycle=lifecycle,
            health=health,
            source_type=source_type,
            stale=stale,
        ),
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
    response: Response,
    session: Annotated[Session, Depends(get_session)],
    access: Annotated[ReadAccess, Depends(require_api_read_access)],
) -> AgentContextOut:
    context = get_agent_object_context(session, object_id, access)
    if context is None:
        raise HTTPException(status_code=404, detail="Catalog object not found")
    revision = getattr(context, "revision", None)
    if isinstance(revision, int):
        response.headers["ETag"] = revision_etag(revision)
    return AgentContextOut(query=object_id, count=1, objects=[context])


@router.get(
    "/objects/{object_id}/network-topology",
    response_model=V1NetworkTopologyOut,
    response_model_exclude_none=True,
)
def agent_network_topology(
    object_id: str,
    session: Annotated[Session, Depends(get_session)],
    access: Annotated[ReadAccess, Depends(require_api_read_access)],
) -> V1NetworkTopologyOut:
    resource = query_network_topology_resource(session, object_id, access)
    if resource is None:
        raise HTTPException(status_code=404, detail="Catalog object not found")
    return V1NetworkTopologyOut.model_validate(resource.topology)


@router.get("/context", response_model=AgentContextOut)
def agent_context(
    session: Annotated[Session, Depends(get_session)],
    access: Annotated[ReadAccess, Depends(require_api_read_access)],
    q: Annotated[
        str | None,
        Query(
            max_length=SEARCH_TEXT_MAX_LENGTH,
            description="Search term for the closed server-defined search projection",
        ),
    ] = None,
    match: Annotated[
        SearchMatchMode,
        Query(description="normal, exact_ref, or exact_label matching"),
    ] = "normal",
    operational_only: Annotated[
        bool,
        Query(description="Exclude inactive, deleted, and retired records"),
    ] = False,
    kind: ObjectKind | None = None,
    parent: Annotated[str | None, Query(description="Typed parent reference")] = None,
    ip: Annotated[str | None, Query(description="Resolved exact IP address")] = None,
    port: Annotated[int | None, Query(ge=1, le=65535)] = None,
    endpoint_type: str | None = None,
    protocol: str | None = None,
    exposure: str | None = None,
    status: str | None = None,
    decision_status: DecisionStatus | None = None,
    applies_to: Annotated[
        str | None,
        Query(
            max_length=APPLIES_TO_MAX_LENGTH,
            pattern=APPLIES_TO_PATTERN,
            description="Exact authorized asset kind:id Decision scope",
        ),
    ] = None,
    runbook_status: RunbookStatus | None = None,
    runbook_risk: RunbookRisk | None = None,
    project_category: ProjectCategory | None = None,
    project_status: ProjectStatus | None = None,
    related_object: Annotated[
        str | None,
        Query(
            max_length=RELATED_OBJECT_MAX_LENGTH,
            pattern=RELATED_OBJECT_PATTERN,
            description="Exact authorized kind:id Project or Runbook relationship target",
        ),
    ] = None,
    lifecycle: AssetLifecycle | None = None,
    health: AssetHealth | None = None,
    source_type: SourceType | None = None,
    stale: Annotated[
        bool | None,
        Query(description="Exact computed freshness state"),
    ] = None,
    limit: Annotated[int, Query(ge=SEARCH_LIMIT_MIN, le=CONTEXT_LIMIT_MAX)] = 5,
) -> AgentContextOut:
    filters = _active_filters(
        match=match,
        operational_only=operational_only,
        parent=parent,
        ip=ip,
        port=port,
        endpoint_type=endpoint_type,
        protocol=protocol,
        exposure=exposure,
        status=status,
        decision_status=decision_status,
        applies_to=applies_to,
        runbook_status=runbook_status,
        runbook_risk=runbook_risk,
        project_category=project_category,
        project_status=project_status,
        related_object=related_object,
        lifecycle=lifecycle,
        health=health,
        source_type=source_type,
        stale=stale,
    )
    objects = build_agent_context(
        session,
        access,
        search=SearchQuery(
            query=q,
            match=match,
            operational_only=operational_only,
            kind=kind,
            parent=parent,
            ip=ip,
            port=port,
            endpoint_type=endpoint_type,
            protocol=protocol,
            exposure=exposure,
            status=status,
            decision_status=decision_status,
            applies_to=applies_to,
            runbook_status=runbook_status,
            runbook_risk=runbook_risk,
            project_category=project_category,
            project_status=project_status,
            related_object=related_object,
            lifecycle=lifecycle,
            health=health,
            source_type=source_type,
            stale=stale,
        ),
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
    match: SearchMatchMode,
    operational_only: bool,
    parent: str | None,
    ip: str | None,
    port: int | None,
    endpoint_type: str | None,
    protocol: str | None,
    exposure: str | None,
    status: str | None,
    decision_status: DecisionStatus | None,
    applies_to: str | None,
    runbook_status: RunbookStatus | None,
    runbook_risk: RunbookRisk | None,
    project_category: ProjectCategory | None,
    project_status: ProjectStatus | None,
    related_object: str | None,
    lifecycle: AssetLifecycle | None,
    health: AssetHealth | None,
    source_type: SourceType | None,
    stale: bool | None,
) -> dict[str, str | int | bool]:
    filters: dict[str, str | int | bool | None] = {
        # Both search modes are echoed only when they leave their default, so
        # an unchanged request keeps its historical response body.
        "match": match if match != "normal" else None,
        "operational_only": operational_only or None,
        "parent": parent,
        "ip": ip,
        "port": port,
        "endpoint_type": endpoint_type,
        "protocol": protocol,
        "exposure": exposure,
        "status": status,
        "decision_status": decision_status,
        "applies_to": applies_to,
        "runbook_status": runbook_status,
        "runbook_risk": runbook_risk,
        "project_category": project_category,
        "project_status": project_status,
        "related_object": related_object,
        "lifecycle": lifecycle,
        "health": health,
        "source_type": source_type,
        "stale": stale,
    }
    return {key: value for key, value in filters.items() if value is not None}
