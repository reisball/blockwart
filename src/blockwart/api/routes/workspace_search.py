"""Dedicated cross-project workspace read surface."""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from blockwart.api.deps import get_session
from blockwart.api.security import require_api_read_access
from blockwart.schemas.workspace_search import WorkspaceSearchKind, WorkspaceSearchPageOut
from blockwart.services.commands import CommandValidationFailed
from blockwart.services.pagination import InvalidCursor
from blockwart.services.read_access import ReadAccess
from blockwart.services.workspace_search import search_workspaces

router = APIRouter(prefix="/workspace")


@router.get("/search", response_model=WorkspaceSearchPageOut)
def search_project_workspaces(
    session: Annotated[Session, Depends(get_session)],
    access: Annotated[ReadAccess, Depends(require_api_read_access)],
    q: Annotated[str, Query(min_length=1, max_length=200)],
    project_id: Annotated[str | None, Query(min_length=1, max_length=128)] = None,
    kind: WorkspaceSearchKind | None = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    cursor: Annotated[str | None, Query(max_length=2048)] = None,
):
    try:
        return search_workspaces(
            session, access, q=q, project_id=project_id, kind=kind, limit=limit, cursor=cursor
        )
    except InvalidCursor as exc:
        raise HTTPException(400, "Invalid cursor") from exc
    except CommandValidationFailed as exc:
        raise HTTPException(422, "Invalid workspace search") from exc
