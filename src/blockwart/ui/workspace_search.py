"""Browser search and instance-scoped deep links for workspace results."""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from blockwart.api.deps import get_session
from blockwart.domain.comment_markdown import render_comment_source
from blockwart.services.commands import CommandNotFound, CommandValidationFailed
from blockwart.services.pagination import InvalidCursor
from blockwart.services.project_chronology import project_chronology_out
from blockwart.services.workspace_search import read_workspace_chronology_entry, search_workspaces
from blockwart.ui.i18n import translation_context
from blockwart.ui.paths import TEMPLATE_DIR
from blockwart.ui.security import read_access_from_request, require_browser_read_access

router = APIRouter(include_in_schema=False, dependencies=[Depends(require_browser_read_access)])
templates = Jinja2Templates(directory=TEMPLATE_DIR)


@router.get("/workspace/search")
def workspace_search(
    request: Request,
    session: Annotated[Session, Depends(get_session)],
    q: Annotated[str, Query(max_length=200)] = "",
    project_id: Annotated[str | None, Query(min_length=1, max_length=128)] = None,
    kind: str = "",
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    cursor: Annotated[str | None, Query(max_length=2048)] = None,
):
    try:
        page = (
            search_workspaces(
                session,
                read_access_from_request(request),
                q=q,
                project_id=project_id,
                kind=kind or None,
                limit=limit,
                cursor=cursor,
            )
            if q
            else None
        )
    except InvalidCursor as exc:
        raise HTTPException(400, "Invalid cursor") from exc
    except CommandValidationFailed as exc:
        raise HTTPException(422, "Invalid workspace search") from exc
    next_url = (
        str(request.url.include_query_params(cursor=page.next_cursor))
        if page and page.next_cursor
        else None
    )
    return templates.TemplateResponse(
        request,
        "workspace_search.html",
        {
            "q": q,
            "project_id": project_id,
            "kind": kind,
            "limit": limit,
            "page": page,
            "next_url": next_url,
            **translation_context(request),
        },
    )


@router.get("/projects/{object_id}/chronology/{entry_id}")
def workspace_chronology_entry(
    request: Request,
    object_id: str,
    entry_id: str,
    session: Annotated[Session, Depends(get_session)],
):
    try:
        project, row = read_workspace_chronology_entry(
            session, read_access_from_request(request), object_id=object_id, entry_id=entry_id
        )
    except CommandNotFound as exc:
        raise HTTPException(404, "Resource not found") from exc
    entry = project_chronology_out(row)
    return templates.TemplateResponse(
        request,
        "workspace_chronology_entry.html",
        {
            "project": project,
            "entry": entry,
            "body_html": render_comment_source(entry.body, entry.format),
            **translation_context(request),
        },
    )
