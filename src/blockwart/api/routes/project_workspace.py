"""Project record endpoints; shared commands enforce all mutations."""

from typing import Annotated

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, Response
from sqlalchemy.orm import Session

from blockwart.api.deps import get_session
from blockwart.api.security import require_api_read_access
from blockwart.api.write_commands import api_write_context, execute_api_command
from blockwart.schemas.project_workspace import (
    ItemStatus,
    ItemType,
    ProjectActionIn,
    ProjectEventPageOut,
    ProjectHistoryPageOut,
    ProjectRecordCommandOut,
    ProjectRecordIn,
    ProjectRecordOut,
    ProjectRecordPageOut,
    ProjectSearchPageOut,
    RecordKind,
)
from blockwart.services.commands import CommandNotFound, CommandValidationFailed
from blockwart.services.pagination import InvalidCursor
from blockwart.services.project_management import (
    apply_action,
    get_record,
    import_legacy,
    project_overview,
    record_events,
)
from blockwart.services.project_workspace import (
    list_records,
    read_project,
    record_history,
    save_record,
    search_workspace,
)
from blockwart.services.read_access import ReadAccess

router = APIRouter(prefix="/projects/{object_id}/workspace")
Db = Annotated[Session, Depends(get_session)]
Access = Annotated[ReadAccess, Depends(require_api_read_access)]
Limit = Annotated[int, Query(ge=1, le=100)]
Cursor = Annotated[str | None, Query(max_length=2048)]


def _read(command):
    try:
        return command()
    except CommandNotFound as exc:
        raise HTTPException(404, "Resource not found") from exc
    except InvalidCursor as exc:
        raise HTTPException(400, "Invalid cursor") from exc
    except CommandValidationFailed as exc:
        raise HTTPException(422, "Invalid filter") from exc


@router.get("/search", response_model=ProjectSearchPageOut)
def search_project_records(
    object_id: str,
    session: Db,
    access: Access,
    q: Annotated[str, Query(min_length=1, max_length=200)],
    limit: Limit = 50,
    cursor: Cursor = None,
):
    return _read(
        lambda: search_workspace(
            session, access, object_id=object_id, q=q, limit=limit, cursor=cursor
        )
    )


@router.get("/history/{record_id}", response_model=ProjectHistoryPageOut)
def get_project_record_history(
    object_id: str,
    record_id: str,
    session: Db,
    access: Access,
    limit: Limit = 50,
    cursor: Cursor = None,
):
    return _read(
        lambda: record_history(
            session, access, object_id=object_id, record_id=record_id, limit=limit, cursor=cursor
        )
    )


@router.get("/overview")
def get_project_overview(object_id: str, session: Db, access: Access):
    return _read(lambda: project_overview(session, access, object_id=object_id))


@router.get("/record/{record_id}", response_model=ProjectRecordOut)
def get_project_record(
    object_id: str, record_id: str, session: Db, access: Access, response: Response
):
    result = _read(lambda: get_record(session, access, object_id=object_id, record_id=record_id))
    response.headers["ETag"] = result.record_etag
    return result


@router.get("/events/{record_id}", response_model=ProjectEventPageOut)
def get_project_events(
    object_id: str,
    record_id: str,
    session: Db,
    access: Access,
    kind: str | None = None,
    limit: Limit = 50,
    cursor: Cursor = None,
):
    return _read(
        lambda: record_events(
            session,
            access,
            object_id=object_id,
            record_id=record_id,
            kind=kind,
            limit=limit,
            cursor=cursor,
        )
    )


@router.post("/actions/{record_id}", response_model=ProjectRecordCommandOut)
def run_project_action(
    object_id: str,
    record_id: str,
    payload: ProjectActionIn,
    request: Request,
    response: Response,
    session: Db,
    access: Access,
    if_match: Annotated[str | None, Header()] = None,
    idempotency_key: Annotated[str | None, Header()] = None,
):
    if not idempotency_key:
        raise HTTPException(400, "Idempotency-Key is required")
    context = api_write_context(request, access)
    result = execute_api_command(
        session,
        context,
        lambda: apply_action(
            session,
            context,
            object_id=object_id,
            record_id=record_id,
            payload=payload,
            expected_record=if_match,
            idempotency_key=idempotency_key,
            idempotency_ttl_seconds=request.app.state.settings.idempotency_ttl_seconds,
        ),
    )
    response.headers["ETag"] = result.record.record_etag
    return result


@router.post("/import-legacy", response_model=ProjectRecordCommandOut)
def import_project_legacy(
    object_id: str,
    payload: dict,
    request: Request,
    response: Response,
    session: Db,
    access: Access,
    if_match: Annotated[str | None, Header()] = None,
    idempotency_key: Annotated[str | None, Header()] = None,
):
    from pydantic import ValidationError

    from blockwart.schemas.project_workspace import LegacyOriginIn

    try:
        origin = LegacyOriginIn.model_validate(payload)
    except ValidationError as exc:
        raise HTTPException(422, "Invalid legacy reference") from exc
    if not idempotency_key:
        raise HTTPException(400, "Idempotency-Key is required")
    context = api_write_context(request, access)
    result = execute_api_command(
        session,
        context,
        lambda: import_legacy(
            session,
            context,
            object_id=object_id,
            **origin.model_dump(),
            expected_revision=if_match,
            idempotency_key=idempotency_key,
            idempotency_ttl_seconds=request.app.state.settings.idempotency_ttl_seconds,
        ),
    )
    response.headers["ETag"] = result.etag
    return result


@router.get("/{kind}", response_model=ProjectRecordPageOut)
def get_project_records(
    object_id: str,
    kind: RecordKind,
    session: Db,
    access: Access,
    response: Response,
    status: ItemStatus | None = None,
    item_type: ItemType | None = None,
    overdue: bool = False,
    priority: str | None = None,
    archived: bool | None = None,
    depends_on: Annotated[str | None, Query(min_length=1, max_length=36)] = None,
    blocked: bool | None = None,
    limit: Limit = 50,
    cursor: Cursor = None,
):
    project = _read(lambda: read_project(session, access, object_id))
    response.headers["ETag"] = f'"rev-{project.revision}"'
    return _read(
        lambda: list_records(
            session,
            access,
            object_id=object_id,
            kind=kind,
            status=status,
            item_type=item_type,
            overdue=overdue,
            priority=priority,
            archived=archived,
            depends_on=depends_on,
            blocked=blocked,
            limit=limit,
            cursor=cursor,
        )
    )


def _save(
    object_id,
    kind,
    record_id,
    payload,
    request,
    response,
    session,
    access,
    if_match,
    idempotency_key,
):
    if kind != payload.kind:
        raise HTTPException(422, "Record kind must match the collection")
    if idempotency_key is None:
        raise HTTPException(400, "Idempotency-Key is required")
    context = api_write_context(request, access)
    result = execute_api_command(
        session,
        context,
        lambda: save_record(
            session,
            context,
            object_id=object_id,
            payload=payload,
            record_id=record_id,
            expected_revision=if_match,
            idempotency_key=idempotency_key,
            idempotency_ttl_seconds=request.app.state.settings.idempotency_ttl_seconds,
        ),
    )
    response.headers["ETag"] = result.etag
    if result.replayed:
        response.status_code = 200
    return result


@router.post("/{kind}", response_model=ProjectRecordCommandOut, status_code=201)
def create_project_record(
    object_id: str,
    kind: RecordKind,
    payload: ProjectRecordIn,
    request: Request,
    response: Response,
    session: Db,
    access: Access,
    if_match: Annotated[str | None, Header()] = None,
    idempotency_key: Annotated[str | None, Header()] = None,
):
    return _save(
        object_id,
        kind,
        None,
        payload,
        request,
        response,
        session,
        access,
        if_match,
        idempotency_key,
    )


@router.put("/{kind}/{record_id}", response_model=ProjectRecordCommandOut)
def update_project_record(
    object_id: str,
    kind: RecordKind,
    record_id: str,
    payload: ProjectRecordIn,
    request: Request,
    response: Response,
    session: Db,
    access: Access,
    if_match: Annotated[str | None, Header()] = None,
    idempotency_key: Annotated[str | None, Header()] = None,
):
    return _save(
        object_id,
        kind,
        record_id,
        payload,
        request,
        response,
        session,
        access,
        if_match,
        idempotency_key,
    )
