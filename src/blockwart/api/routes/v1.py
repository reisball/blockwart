from typing import Annotated

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, Response
from pydantic import BeforeValidator
from sqlalchemy.orm import Session

from blockwart.api.deps import get_session
from blockwart.api.errors import API_ERROR_RESPONSES
from blockwart.api.security import require_api_read_access
from blockwart.api.write_commands import api_write_context, execute_api_command
from blockwart.config import Settings
from blockwart.domain.asset_state import AssetHealth, AssetLifecycle
from blockwart.domain.auth import GrantScope
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
from blockwart.domain.read_projection import (
    ACTIVITY_SECTION,
    FIELDS_DESCRIPTION,
    PROJECTION_DESCRIPTION,
    RECENT_COMMENTS_DESCRIPTION,
    ProjectionProfile,
    ProjectionSection,
    resolve_read_projection,
)
from blockwart.domain.runbooks import RunbookRisk, RunbookStatus
from blockwart.domain.search import (
    CONTEXT_LIMIT_MAX,
    SEARCH_LIMIT_MAX,
    SEARCH_LIMIT_MIN,
    SEARCH_TEXT_MAX_LENGTH,
    SearchMatchMode,
    SearchQuery,
)
from blockwart.domain.source_coverage import SourceCoverageError
from blockwart.schemas.agent import AgentCatalogContextRead, ReadProjectionOut
from blockwart.schemas.catalog import CatalogObjectIn, ObjectKind, ObjectStatus
from blockwart.schemas.comments import (
    CommentCommandOut,
    CommentCreateIn,
    CommentPageOut,
)
from blockwart.schemas.errors import ApiErrorResponse
from blockwart.schemas.projects import (
    ProjectChronologyCommandOut,
    ProjectChronologyCreateIn,
    ProjectChronologyPageOut,
    ProjectOverviewPageOut,
    ProjectOverviewSort,
)
from blockwart.schemas.v1 import (
    MAX_BATCH_RESPONSE_BYTES,
    AttentionCategoryValue,
    AttentionItemSignalStateValue,
    AttentionReasonValue,
    AttentionSeverityValue,
    CoverageScopeValue,
    CoverageStateValue,
    McpContractMetadataOut,
    ObjectSortField,
    SortDirection,
    SourceClassificationValue,
    V1AttachedDeviceCreateIn,
    V1AttentionPageOut,
    V1AuditPageOut,
    V1ContextPageOut,
    V1DeleteCommandOut,
    V1DeviceGraphOut,
    V1GrantCommandOut,
    V1GrantCreateIn,
    V1GrantScopePreviewOut,
    V1GrantUpdateIn,
    V1NetworkTopologyOut,
    V1ObjectAccessOut,
    V1ObjectCommandOut,
    V1ObjectContextBatchIn,
    V1ObjectContextBatchOut,
    V1ObjectPageOut,
    V1PrincipalSearchOut,
    V1PrincipalSummaryOut,
    V1ProjectedObjectContextBatchOut,
    V1ProjectedPageOut,
    V1RelationshipCommandIn,
    V1RelationshipCommandOut,
    V1RelationshipPageOut,
    V1SourceCoveragePageOut,
    V1TopologyOut,
)
from blockwart.services.agent import (
    get_agent_object_context,
    query_agent_context_page,
    query_agent_object_contexts,
    query_agent_objects_page,
)
from blockwart.services.attention import (
    AttentionQueryError,
    query_attention_page,
)
from blockwart.services.commands import (
    create_attached_device,
    create_catalog_root,
    create_child_object,
    create_object_relationship,
    delete_catalog_object,
    delete_object_relationship,
    revision_etag,
    update_catalog_object,
)
from blockwart.services.comments import add_object_comment, query_comment_page
from blockwart.services.grant_management import (
    create_managed_grant,
    preview_grant_scope,
    query_object_access,
    revoke_managed_grant,
    search_manageable_principals,
    update_managed_grant,
)
from blockwart.services.pagination import InvalidCursor
from blockwart.services.project_chronology import (
    add_project_chronology_entry,
    query_project_chronology_page,
    query_project_overview_page,
)
from blockwart.services.read_access import ReadAccess
from blockwart.services.read_projection import CapabilitySets, project_read_items
from blockwart.services.source_coverage import (
    CoverageAuthorityDenied,
    query_source_coverage_page,
)
from blockwart.services.v1 import (
    query_audit_page,
    query_device_graph_resource,
    query_network_topology_resource,
    query_relationship_page,
    query_topology_resource,
)

router = APIRouter(
    prefix="/v1",
    tags=["api-v1-readonly"],
    responses=API_ERROR_RESPONSES,
)


@router.get(
    "/mcp-contract",
    response_model=McpContractMetadataOut,
    summary="Read non-secret MCP wrapper contract metadata",
)
def get_mcp_contract_metadata(
    request: Request,
    _: Annotated[ReadAccess, Depends(require_api_read_access)],
) -> McpContractMetadataOut:
    # This stays independent from readiness: a stale external wrapper must
    # never cause the service's database/readiness contract to fail.
    from blockwart.mcp.server import local_contract_metadata

    return McpContractMetadataOut.model_validate(
        local_contract_metadata(build_revision=request.app.state.settings.build_revision)
    )


QueryText = Annotated[
    str | None,
    Query(
        max_length=SEARCH_TEXT_MAX_LENGTH,
        description=(
            "Search term matched against the closed server-defined search "
            "projection: canonical reference, id, label, structured domain "
            "fields, summary, and allowlisted bounded fields"
        ),
    ),
]
MatchMode = Annotated[
    SearchMatchMode,
    Query(
        description=(
            "normal weighted search, exact_ref for an exact kind:id or id, or "
            "exact_label for an exact normalized label"
        ),
    ),
]
OperationalOnly = Annotated[
    bool,
    Query(
        description=(
            "Exclude inactive/deleted status, retired lifecycle, and the "
            "retired canonical knowledge states"
        ),
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
PageLimit = Annotated[int, Query(ge=SEARCH_LIMIT_MIN, le=SEARCH_LIMIT_MAX)]
# The closed read-projection controls. Omitting all of them keeps the exact
# historical full contract, so no existing client sees a changed response.
ProjectionParameter = Annotated[
    ProjectionProfile | None,
    Query(description=PROJECTION_DESCRIPTION),
]


def _decode_empty_projection_fields(value: object) -> object:
    """Treat the explicit ``fields=`` query marker as an empty closed mask.

    MCP encodes an empty JSON array as an explicitly present blank repeated
    query parameter. It is distinct from omitting ``fields`` altogether: the
    former requests the core-only projection, while the latter retains the
    backwards-compatible unmasked full read.
    """
    return [] if value == [""] else value


ProjectionFields = Annotated[
    list[ProjectionSection] | None,
    BeforeValidator(_decode_empty_projection_fields),
    Query(description=FIELDS_DESCRIPTION),
]
IncludeRecentComments = Annotated[
    bool | None,
    Query(description=RECENT_COMMENTS_DESCRIPTION),
]


@router.get(
    "/attention",
    response_model=V1AttentionPageOut,
    summary="Read the authorized catalog-wide attention view",
)
def get_v1_attention(
    session: Annotated[Session, Depends(get_session)],
    access: Annotated[ReadAccess, Depends(require_api_read_access)],
    category: AttentionCategoryValue | None = None,
    severity: AttentionSeverityValue | None = None,
    reason_code: AttentionReasonValue | None = None,
    signal_state: AttentionItemSignalStateValue | None = None,
    kind: ObjectKind | None = None,
    limit: PageLimit = 50,
    cursor: CursorParameter = None,
    direction: SortDirection = "asc",
    include_total: Annotated[
        bool,
        Query(description="Compute the total over the authorized filtered item set"),
    ] = False,
) -> V1AttentionPageOut:
    """Combine existing canonical signals; this request runs no probe or source read."""
    try:
        page = query_attention_page(
            session,
            access,
            category=category,
            severity=severity,
            reason_code=reason_code,
            signal_state=signal_state,
            kind=kind,
            limit=limit,
            cursor=cursor,
            direction=direction,
            include_total=include_total,
        )
    except InvalidCursor as exc:
        raise _invalid_cursor() from exc
    except AttentionQueryError as exc:
        raise HTTPException(status_code=400, detail="Invalid attention request") from exc
    return V1AttentionPageOut.model_validate(
        {
            "summary": page.summary,
            "items": page.items,
            "next_cursor": page.next_cursor,
            "total": page.total,
            "generated_at": page.generated_at,
            "direction": direction,
        }
    )


@router.get(
    "/source-coverage",
    response_model=V1SourceCoveragePageOut,
    summary="Read the authorized source inventory coverage snapshot",
)
def get_v1_source_coverage(
    session: Annotated[Session, Depends(get_session)],
    access: Annotated[ReadAccess, Depends(require_api_read_access)],
    source: Annotated[str | None, Query(max_length=512)] = None,
    classification: SourceClassificationValue | None = None,
    state: CoverageStateValue | None = None,
    target_kind: ObjectKind | None = None,
    scope: CoverageScopeValue = "mapped",
    limit: PageLimit = 50,
    cursor: CursorParameter = None,
    direction: SortDirection = "asc",
    include_total: Annotated[
        bool,
        Query(description="Compute the total over the authorized filtered detail set"),
    ] = False,
) -> V1SourceCoveragePageOut:
    """Project a recorded snapshot; this request never reads workspace files."""
    try:
        page = query_source_coverage_page(
            session,
            access,
            source=source,
            classification=classification,
            state=state,
            target_kind=target_kind,
            scope=scope,
            limit=limit,
            cursor=cursor,
            direction=direction,
            include_total=include_total,
        )
    except InvalidCursor as exc:
        raise _invalid_cursor() from exc
    except CoverageAuthorityDenied as exc:
        raise HTTPException(
            status_code=403,
            detail="Source-only coverage requires platform administrator authority",
        ) from exc
    except SourceCoverageError as exc:
        raise HTTPException(status_code=400, detail="Invalid source coverage request") from exc
    return V1SourceCoveragePageOut.model_validate(
        {
            "snapshot": page.snapshot,
            "summary": page.summary,
            "items": page.items,
            "next_cursor": page.next_cursor,
            "total": page.total,
            "scope": page.scope,
            "direction": direction,
        }
    )


@router.get("/objects", response_model=V1ObjectPageOut | V1ProjectedPageOut)
def list_v1_objects(
    session: Annotated[Session, Depends(get_session)],
    access: Annotated[ReadAccess, Depends(require_api_read_access)],
    q: QueryText = None,
    match: MatchMode = "normal",
    operational_only: OperationalOnly = False,
    kind: ObjectKind | None = None,
    parent: ParentFilter = None,
    ip: IpFilter = None,
    port: Annotated[int | None, Query(ge=1, le=65535)] = None,
    endpoint_type: EndpointTypeFilter = None,
    protocol: ProtocolFilter = None,
    exposure: ExposureFilter = None,
    status: ObjectStatus | None = None,
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
    limit: PageLimit = 50,
    cursor: CursorParameter = None,
    sort: ObjectSortField = "id",
    direction: SortDirection = "asc",
    include_total: Annotated[
        bool,
        Query(description="Compute the total matching result count"),
    ] = False,
    projection: ProjectionParameter = None,
    fields: ProjectionFields = None,
) -> V1ObjectPageOut | V1ProjectedPageOut:
    resolved = resolve_read_projection(
        surface="summary",
        profile=projection,
        fields=fields,
    )
    try:
        page = query_agent_objects_page(
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
            cursor=cursor,
            sort=sort,
            direction=direction,
            include_total=include_total,
        )
    except InvalidCursor as exc:
        raise _invalid_cursor() from exc
    if resolved.is_default:
        return V1ObjectPageOut(
            items=page.items,
            next_cursor=page.next_cursor,
            total=page.total,
            sort=sort,
            direction=direction,
        )
    capability_sets = CapabilitySets()
    return V1ProjectedPageOut(
        projection=ReadProjectionOut.model_validate(resolved.descriptor()),
        items=project_read_items(
            page.items,
            projection=resolved,
            capability_sets=capability_sets,
        ),
        capability_sets=capability_sets.table(),
        next_cursor=page.next_cursor,
        total=page.total,
        sort=sort,
        direction=direction,
    )


@router.get(
    "/projects",
    response_model=ProjectOverviewPageOut,
    summary="Read the authorized focused Project overview",
)
def list_v1_projects(
    session: Annotated[Session, Depends(get_session)],
    access: Annotated[ReadAccess, Depends(require_api_read_access)],
    project_category: ProjectCategory | None = None,
    project_status: ProjectStatus | None = None,
    limit: PageLimit = 50,
    cursor: CursorParameter = None,
    sort: ProjectOverviewSort = "last_activity",
    direction: SortDirection = "desc",
    include_total: Annotated[
        bool,
        Query(description="Compute the authorized filtered Project count"),
    ] = False,
) -> ProjectOverviewPageOut:
    try:
        page = query_project_overview_page(
            session,
            access,
            project_category=project_category,
            project_status=project_status,
            limit=limit,
            cursor=cursor,
            sort=sort,
            direction=direction,
            include_total=include_total,
        )
    except InvalidCursor as exc:
        raise _invalid_cursor() from exc
    return ProjectOverviewPageOut(
        items=page.items,
        next_cursor=page.next_cursor,
        total=page.total,
        sort=sort,
        direction=direction,
    )


@router.get("/context", response_model=V1ContextPageOut | V1ProjectedPageOut)
def get_v1_context(
    session: Annotated[Session, Depends(get_session)],
    access: Annotated[ReadAccess, Depends(require_api_read_access)],
    q: QueryText = None,
    match: MatchMode = "normal",
    operational_only: OperationalOnly = False,
    kind: ObjectKind | None = None,
    parent: ParentFilter = None,
    ip: IpFilter = None,
    port: Annotated[int | None, Query(ge=1, le=65535)] = None,
    endpoint_type: EndpointTypeFilter = None,
    protocol: ProtocolFilter = None,
    exposure: ExposureFilter = None,
    status: ObjectStatus | None = None,
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
    cursor: CursorParameter = None,
    sort: ObjectSortField = "id",
    direction: SortDirection = "asc",
    include_total: Annotated[
        bool,
        Query(description="Compute the total matching result count"),
    ] = False,
    projection: ProjectionParameter = None,
    fields: ProjectionFields = None,
    include_recent_comments: IncludeRecentComments = None,
) -> V1ContextPageOut | V1ProjectedPageOut:
    resolved = resolve_read_projection(
        surface="context",
        profile=projection,
        fields=fields,
        include_recent_comments=include_recent_comments,
    )
    try:
        page = query_agent_context_page(
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
            cursor=cursor,
            sort=sort,
            direction=direction,
            include_total=include_total,
            include_recent_comments=resolved.includes(ACTIVITY_SECTION),
        )
    except InvalidCursor as exc:
        raise _invalid_cursor() from exc
    if resolved.is_default:
        return V1ContextPageOut(
            items=page.items,
            next_cursor=page.next_cursor,
            total=page.total,
            sort=sort,
            direction=direction,
        )
    capability_sets = CapabilitySets()
    return V1ProjectedPageOut(
        projection=ReadProjectionOut.model_validate(resolved.descriptor()),
        items=project_read_items(
            page.items,
            projection=resolved,
            capability_sets=capability_sets,
        ),
        capability_sets=capability_sets.table(),
        next_cursor=page.next_cursor,
        total=page.total,
        sort=sort,
        direction=direction,
    )


@router.get(
    "/objects/{object_id}",
    response_model=AgentCatalogContextRead,
)
def get_v1_object(
    object_id: str,
    response: Response,
    session: Annotated[Session, Depends(get_session)],
    access: Annotated[ReadAccess, Depends(require_api_read_access)],
) -> AgentCatalogContextRead:
    context = get_agent_object_context(session, object_id, access)
    if context is None:
        raise HTTPException(status_code=404, detail="Catalog object not found")
    revision = getattr(context, "revision", None)
    if isinstance(revision, int):
        response.headers["ETag"] = revision_etag(revision)
    return context


_BATCH_RESPONSES = {
    **API_ERROR_RESPONSES,
    413: {"model": ApiErrorResponse, "description": "Request or response payload too large"},
}


@router.post(
    "/object-contexts",
    response_model=V1ObjectContextBatchOut | V1ProjectedObjectContextBatchOut,
    responses=_BATCH_RESPONSES,
)
def post_v1_object_contexts(
    payload: V1ObjectContextBatchIn,
    session: Annotated[Session, Depends(get_session)],
    access: Annotated[ReadAccess, Depends(require_api_read_access)],
) -> V1ObjectContextBatchOut | V1ProjectedObjectContextBatchOut:
    resolved = resolve_read_projection(
        surface="context",
        profile=payload.projection,
        fields=payload.fields,
        include_recent_comments=payload.include_recent_comments,
    )
    batch = query_agent_object_contexts(
        session,
        access,
        payload.object_ids,
        include_recent_comments=resolved.includes(ACTIVITY_SECTION),
    )
    response: V1ObjectContextBatchOut | V1ProjectedObjectContextBatchOut
    if resolved.is_default:
        response = V1ObjectContextBatchOut(
            objects=batch.items,
            count=len(batch.items),
        )
    else:
        capability_sets = CapabilitySets()
        projected = project_read_items(
            batch.items,
            projection=resolved,
            capability_sets=capability_sets,
        )
        response = V1ProjectedObjectContextBatchOut(
            projection=ReadProjectionOut.model_validate(resolved.descriptor()),
            objects=projected,
            capability_sets=capability_sets.table(),
            count=len(projected),
        )
    encoded = response.model_dump_json(by_alias=True, exclude_none=True)
    if len(encoded.encode("utf-8")) > MAX_BATCH_RESPONSE_BYTES:
        raise HTTPException(
            status_code=413,
            detail="Batch response payload exceeds the maximum allowed size.",
        )
    return response


@router.get(
    "/objects/{object_id}/comments",
    response_model=CommentPageOut,
)
def list_v1_object_comments(
    object_id: str,
    session: Annotated[Session, Depends(get_session)],
    access: Annotated[ReadAccess, Depends(require_api_read_access)],
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
    cursor: CursorParameter = None,
    include_total: bool = False,
) -> CommentPageOut:
    try:
        page = query_comment_page(
            session,
            access,
            object_id=object_id,
            limit=limit,
            cursor=cursor,
            include_total=include_total,
        )
    except InvalidCursor as exc:
        raise _invalid_cursor() from exc
    if page is None:
        raise HTTPException(status_code=404, detail="Catalog object not found")
    return CommentPageOut(
        items=page.items,
        next_cursor=page.next_cursor,
        total=page.total,
    )


@router.post(
    "/objects/{object_id}/comments",
    response_model=CommentCommandOut,
    status_code=201,
)
def create_v1_object_comment(
    object_id: str,
    payload: CommentCreateIn,
    request: Request,
    response: Response,
    session: Annotated[Session, Depends(get_session)],
    access: Annotated[ReadAccess, Depends(require_api_read_access)],
    idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
) -> CommentCommandOut:
    if idempotency_key is None:
        raise HTTPException(status_code=400, detail="Idempotency-Key is required")
    context = api_write_context(request, access)
    settings: Settings = request.app.state.settings
    result = execute_api_command(
        session,
        context,
        lambda: add_object_comment(
            session,
            context,
            object_id=object_id,
            body=payload.body,
            idempotency_key=idempotency_key,
            idempotency_ttl_seconds=settings.idempotency_ttl_seconds,
        ),
    )
    response.headers["ETag"] = result.etag
    response.headers["Location"] = f"/objects/{object_id}/comments#comment-{result.comment.id}"
    if result.replayed:
        response.status_code = 200
    return CommentCommandOut(
        comment=result.comment,
        revision=result.revision,
        etag=result.etag,
        replayed=result.replayed,
    )


@router.get(
    "/projects/{object_id}/chronology",
    response_model=ProjectChronologyPageOut,
    summary="Read one authorized Project professional chronology",
)
def list_v1_project_chronology(
    object_id: str,
    session: Annotated[Session, Depends(get_session)],
    access: Annotated[ReadAccess, Depends(require_api_read_access)],
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
    cursor: CursorParameter = None,
    include_total: bool = False,
) -> ProjectChronologyPageOut:
    try:
        page = query_project_chronology_page(
            session,
            access,
            object_id=object_id,
            limit=limit,
            cursor=cursor,
            include_total=include_total,
        )
    except InvalidCursor as exc:
        raise _invalid_cursor() from exc
    if page is None:
        raise HTTPException(status_code=404, detail="Catalog object not found")
    return ProjectChronologyPageOut(
        items=page.items,
        next_cursor=page.next_cursor,
        total=page.total,
    )


@router.post(
    "/projects/{object_id}/chronology",
    response_model=ProjectChronologyCommandOut,
    status_code=201,
    summary="Append one curated Project chronology entry",
)
def create_v1_project_chronology(
    object_id: str,
    payload: ProjectChronologyCreateIn,
    request: Request,
    response: Response,
    session: Annotated[Session, Depends(get_session)],
    access: Annotated[ReadAccess, Depends(require_api_read_access)],
    idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
) -> ProjectChronologyCommandOut:
    if idempotency_key is None:
        raise HTTPException(status_code=400, detail="Idempotency-Key is required")
    context = api_write_context(request, access)
    settings: Settings = request.app.state.settings
    result = execute_api_command(
        session,
        context,
        lambda: add_project_chronology_entry(
            session,
            context,
            object_id=object_id,
            kind=payload.kind,
            body=payload.body,
            idempotency_key=idempotency_key,
            idempotency_ttl_seconds=settings.idempotency_ttl_seconds,
        ),
    )
    response.headers["ETag"] = result.etag
    response.headers["Location"] = f"/projects/{object_id}#chronology-{result.entry.id}"
    if result.replayed:
        response.status_code = 200
    return ProjectChronologyCommandOut(
        entry=result.entry,
        revision=result.revision,
        etag=result.etag,
        replayed=result.replayed,
    )


@router.post(
    "/objects/{parent_id}/children",
    response_model=V1ObjectCommandOut,
    status_code=201,
)
def create_v1_child_object(
    parent_id: str,
    payload: CatalogObjectIn,
    request: Request,
    response: Response,
    session: Annotated[Session, Depends(get_session)],
    access: Annotated[ReadAccess, Depends(require_api_read_access)],
    idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
) -> V1ObjectCommandOut:
    if idempotency_key is None:
        raise HTTPException(status_code=400, detail="Idempotency-Key is required")
    context = api_write_context(request, access)
    settings: Settings = request.app.state.settings
    result = execute_api_command(
        session,
        context,
        lambda: create_child_object(
            session,
            context,
            parent_id=parent_id,
            payload=payload,
            idempotency_key=idempotency_key,
            idempotency_ttl_seconds=settings.idempotency_ttl_seconds,
        ),
    )
    response.headers["ETag"] = result.etag
    response.headers["Location"] = f"/api/v1/objects/{result.catalog_object.id}"
    return V1ObjectCommandOut(
        catalog_object=result.catalog_object,
        etag=result.etag,
        changed=result.changed,
        replayed=result.replayed,
    )


@router.post(
    "/objects/{parent_id}/attached-devices",
    response_model=V1ObjectCommandOut,
    status_code=201,
)
def create_v1_attached_device(
    parent_id: str,
    payload: V1AttachedDeviceCreateIn,
    request: Request,
    response: Response,
    session: Annotated[Session, Depends(get_session)],
    access: Annotated[ReadAccess, Depends(require_api_read_access)],
    idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
) -> V1ObjectCommandOut:
    if idempotency_key is None:
        raise HTTPException(status_code=400, detail="Idempotency-Key is required")
    context = api_write_context(request, access)
    settings: Settings = request.app.state.settings
    metadata_payload = payload.metadata or None
    result = execute_api_command(
        session,
        context,
        lambda: create_attached_device(
            session,
            context,
            parent_id=parent_id,
            payload=payload.device,
            metadata=metadata_payload,
            idempotency_key=idempotency_key,
            idempotency_ttl_seconds=settings.idempotency_ttl_seconds,
        ),
    )
    response.headers["ETag"] = result.etag
    response.headers["Location"] = f"/api/v1/objects/{result.catalog_object.id}"
    return V1ObjectCommandOut(
        catalog_object=result.catalog_object,
        etag=result.etag,
        changed=result.changed,
        replayed=result.replayed,
    )


@router.post(
    "/roots",
    response_model=V1ObjectCommandOut,
    status_code=201,
)
def create_v1_catalog_root(
    payload: CatalogObjectIn,
    request: Request,
    response: Response,
    session: Annotated[Session, Depends(get_session)],
    access: Annotated[ReadAccess, Depends(require_api_read_access)],
    idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
) -> V1ObjectCommandOut:
    if idempotency_key is None:
        raise HTTPException(status_code=400, detail="Idempotency-Key is required")
    context = api_write_context(request, access)
    settings: Settings = request.app.state.settings
    result = execute_api_command(
        session,
        context,
        lambda: create_catalog_root(
            session,
            context,
            payload=payload,
            idempotency_key=idempotency_key,
            idempotency_ttl_seconds=settings.idempotency_ttl_seconds,
        ),
    )
    response.headers["ETag"] = result.etag
    response.headers["Location"] = f"/api/v1/objects/{result.catalog_object.id}"
    return V1ObjectCommandOut(
        catalog_object=result.catalog_object,
        etag=result.etag,
        changed=result.changed,
        replayed=result.replayed,
    )


@router.put(
    "/objects/{object_id}",
    response_model=V1ObjectCommandOut,
)
def update_v1_object(
    object_id: str,
    payload: CatalogObjectIn,
    request: Request,
    response: Response,
    session: Annotated[Session, Depends(get_session)],
    access: Annotated[ReadAccess, Depends(require_api_read_access)],
    if_match: Annotated[str | None, Header(alias="If-Match")] = None,
) -> V1ObjectCommandOut:
    context = api_write_context(request, access)
    result = execute_api_command(
        session,
        context,
        lambda: update_catalog_object(
            session,
            context,
            object_id=object_id,
            payload=payload,
            expected_revision=if_match,
        ),
    )
    response.headers["ETag"] = result.etag
    return V1ObjectCommandOut(
        catalog_object=result.catalog_object,
        etag=result.etag,
        changed=result.changed,
    )


@router.delete(
    "/objects/{object_id}",
    response_model=V1DeleteCommandOut,
)
def delete_v1_object(
    object_id: str,
    request: Request,
    session: Annotated[Session, Depends(get_session)],
    access: Annotated[ReadAccess, Depends(require_api_read_access)],
    if_match: Annotated[str | None, Header(alias="If-Match")] = None,
) -> V1DeleteCommandOut:
    context = api_write_context(request, access)
    result = execute_api_command(
        session,
        context,
        lambda: delete_catalog_object(
            session,
            context,
            object_id=object_id,
            expected_revision=if_match,
        ),
    )
    return V1DeleteCommandOut(
        object_id=result.object_id,
        deleted_revision=result.deleted_revision,
        changed=result.changed,
    )


@router.post(
    "/objects/{object_id}/relationships",
    response_model=V1RelationshipCommandOut,
)
def create_v1_relationship(
    object_id: str,
    payload: V1RelationshipCommandIn,
    request: Request,
    response: Response,
    session: Annotated[Session, Depends(get_session)],
    access: Annotated[ReadAccess, Depends(require_api_read_access)],
    if_match: Annotated[str | None, Header(alias="If-Match")] = None,
) -> V1RelationshipCommandOut:
    context = api_write_context(request, access)
    result = execute_api_command(
        session,
        context,
        lambda: create_object_relationship(
            session,
            context,
            object_id=object_id,
            from_ref=payload.from_ref,
            relation_type=payload.relation_type,
            to_ref=payload.to_ref,
            expected_revision=if_match,
            metadata=payload.metadata or None,
        ),
    )
    response.headers["ETag"] = result.etag
    return V1RelationshipCommandOut(
        from_ref=result.from_ref,
        relation_type=result.relation_type,
        to_ref=result.to_ref,
        metadata=result.metadata,
        object_id=result.object_id,
        revision=result.revision,
        etag=result.etag,
        changed=result.changed,
    )


@router.delete(
    "/objects/{object_id}/relationships",
    response_model=V1RelationshipCommandOut,
)
def delete_v1_relationship(
    object_id: str,
    payload: V1RelationshipCommandIn,
    request: Request,
    response: Response,
    session: Annotated[Session, Depends(get_session)],
    access: Annotated[ReadAccess, Depends(require_api_read_access)],
    if_match: Annotated[str | None, Header(alias="If-Match")] = None,
) -> V1RelationshipCommandOut:
    context = api_write_context(request, access)
    result = execute_api_command(
        session,
        context,
        lambda: delete_object_relationship(
            session,
            context,
            object_id=object_id,
            from_ref=payload.from_ref,
            relation_type=payload.relation_type,
            to_ref=payload.to_ref,
            expected_revision=if_match,
        ),
    )
    response.headers["ETag"] = result.etag
    return V1RelationshipCommandOut(
        from_ref=result.from_ref,
        relation_type=result.relation_type,
        to_ref=result.to_ref,
        metadata=result.metadata,
        object_id=result.object_id,
        revision=result.revision,
        etag=result.etag,
        changed=result.changed,
    )


@router.get(
    "/objects/{object_id}/access",
    response_model=V1ObjectAccessOut,
)
def get_v1_object_access(
    object_id: str,
    request: Request,
    response: Response,
    session: Annotated[Session, Depends(get_session)],
    access: Annotated[ReadAccess, Depends(require_api_read_access)],
) -> V1ObjectAccessOut:
    context = api_write_context(request, access)
    result = execute_api_command(
        session,
        context,
        lambda: query_object_access(
            session,
            context,
            object_id=object_id,
        ),
    )
    response.headers["ETag"] = result.etag
    return V1ObjectAccessOut.model_validate(result)


@router.get(
    "/objects/{object_id}/access/principals",
    response_model=V1PrincipalSearchOut,
)
def search_v1_access_principals(
    object_id: str,
    request: Request,
    session: Annotated[Session, Depends(get_session)],
    access: Annotated[ReadAccess, Depends(require_api_read_access)],
    q: Annotated[str, Query(min_length=2, max_length=100)],
    limit: Annotated[int, Query(ge=1, le=20)] = 20,
) -> V1PrincipalSearchOut:
    context = api_write_context(request, access)
    principals = execute_api_command(
        session,
        context,
        lambda: search_manageable_principals(
            session,
            context,
            object_id=object_id,
            query=q,
            limit=limit,
        ),
    )
    return V1PrincipalSearchOut(
        items=[V1PrincipalSummaryOut.model_validate(principal) for principal in principals]
    )


@router.get(
    "/objects/{object_id}/access/preview",
    response_model=V1GrantScopePreviewOut,
)
def preview_v1_grant_scope(
    object_id: str,
    request: Request,
    session: Annotated[Session, Depends(get_session)],
    access: Annotated[ReadAccess, Depends(require_api_read_access)],
    scope: GrantScope = GrantScope.SUBTREE,
) -> V1GrantScopePreviewOut:
    context = api_write_context(request, access)
    result = execute_api_command(
        session,
        context,
        lambda: preview_grant_scope(
            session,
            context,
            object_id=object_id,
            scope=scope,
        ),
    )
    return V1GrantScopePreviewOut.model_validate(result)


@router.post(
    "/objects/{object_id}/access/grants",
    response_model=V1GrantCommandOut,
    status_code=201,
)
def create_v1_object_grant(
    object_id: str,
    payload: V1GrantCreateIn,
    request: Request,
    response: Response,
    session: Annotated[Session, Depends(get_session)],
    access: Annotated[ReadAccess, Depends(require_api_read_access)],
    if_match: Annotated[str | None, Header(alias="If-Match")] = None,
) -> V1GrantCommandOut:
    context = api_write_context(request, access)
    result = execute_api_command(
        session,
        context,
        lambda: create_managed_grant(
            session,
            context,
            object_id=object_id,
            principal_id=payload.principal_id,
            role=payload.role,
            scope=payload.scope,
            expected_revision=if_match,
        ),
    )
    response.headers["ETag"] = result.etag
    return V1GrantCommandOut.model_validate(result)


@router.put(
    "/objects/{object_id}/access/grants/{grant_id}",
    response_model=V1GrantCommandOut,
)
def update_v1_object_grant(
    object_id: str,
    grant_id: int,
    payload: V1GrantUpdateIn,
    request: Request,
    response: Response,
    session: Annotated[Session, Depends(get_session)],
    access: Annotated[ReadAccess, Depends(require_api_read_access)],
    if_match: Annotated[str | None, Header(alias="If-Match")] = None,
) -> V1GrantCommandOut:
    context = api_write_context(request, access)
    result = execute_api_command(
        session,
        context,
        lambda: update_managed_grant(
            session,
            context,
            object_id=object_id,
            grant_id=grant_id,
            role=payload.role,
            scope=payload.scope,
            expected_revision=if_match,
        ),
    )
    response.headers["ETag"] = result.etag
    return V1GrantCommandOut.model_validate(result)


@router.delete(
    "/objects/{object_id}/access/grants/{grant_id}",
    response_model=V1GrantCommandOut,
)
def revoke_v1_object_grant(
    object_id: str,
    grant_id: int,
    request: Request,
    response: Response,
    session: Annotated[Session, Depends(get_session)],
    access: Annotated[ReadAccess, Depends(require_api_read_access)],
    if_match: Annotated[str | None, Header(alias="If-Match")] = None,
) -> V1GrantCommandOut:
    context = api_write_context(request, access)
    result = execute_api_command(
        session,
        context,
        lambda: revoke_managed_grant(
            session,
            context,
            object_id=object_id,
            grant_id=grant_id,
            expected_revision=if_match,
        ),
    )
    response.headers["ETag"] = result.etag
    return V1GrantCommandOut.model_validate(result)


@router.get(
    "/objects/{object_id}/relationships",
    response_model=V1RelationshipPageOut,
)
def get_v1_relationships(
    object_id: str,
    session: Annotated[Session, Depends(get_session)],
    access: Annotated[ReadAccess, Depends(require_api_read_access)],
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
            access,
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
    access: Annotated[ReadAccess, Depends(require_api_read_access)],
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
            access,
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
    access: Annotated[ReadAccess, Depends(require_api_read_access)],
) -> V1TopologyOut:
    resource = query_topology_resource(session, object_id, access)
    if resource is None:
        raise HTTPException(status_code=404, detail="Catalog object not found")
    return V1TopologyOut(
        object_ref=resource.object_ref,
        chains=resource.topology["chains"],
    )


@router.get(
    "/objects/{object_id}/device-graph",
    response_model=V1DeviceGraphOut,
    response_model_exclude_none=True,
)
def get_v1_device_graph(
    object_id: str,
    session: Annotated[Session, Depends(get_session)],
    access: Annotated[ReadAccess, Depends(require_api_read_access)],
) -> V1DeviceGraphOut:
    resource = query_device_graph_resource(session, object_id, access)
    if resource is None:
        raise HTTPException(status_code=404, detail="Catalog object not found")
    return V1DeviceGraphOut(
        object_ref=resource.object_ref,
        nodes=resource.graph["nodes"],
        edges=resource.graph["edges"],
        upstream_path=resource.graph["upstream_path"],
        downstream_refs=resource.graph["downstream_refs"],
    )


@router.get(
    "/objects/{object_id}/network-topology",
    response_model=V1NetworkTopologyOut,
    response_model_exclude_none=True,
)
def get_v1_network_topology(
    object_id: str,
    session: Annotated[Session, Depends(get_session)],
    access: Annotated[ReadAccess, Depends(require_api_read_access)],
) -> V1NetworkTopologyOut:
    resource = query_network_topology_resource(session, object_id, access)
    if resource is None:
        raise HTTPException(status_code=404, detail="Catalog object not found")
    return V1NetworkTopologyOut.model_validate(resource.topology)


def _invalid_cursor() -> HTTPException:
    return HTTPException(
        status_code=400,
        detail="Cursor is invalid or does not match the active query",
    )
