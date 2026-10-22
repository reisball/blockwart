"""Structured browser editor for project records (no raw JSON editing)."""

from typing import Annotated
from uuid import uuid4

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from pydantic import ValidationError
from sqlalchemy.orm import Session

from blockwart.api.deps import get_session
from blockwart.domain.auth import ObjectVisibility, Permission
from blockwart.domain.comment_markdown import render_comment_source
from blockwart.models import CatalogObject, ProjectRecord
from blockwart.schemas.project_workspace import RECORD_ADAPTER, RecordKind
from blockwart.services.commands import CommandNotFound, CommandValidationFailed, revision_etag
from blockwart.services.pagination import InvalidCursor
from blockwart.services.project_workspace import (
    list_records,
    read_project,
    record_history,
    record_out,
    save_record,
    search_workspace,
)
from blockwart.ui.i18n import translation_context
from blockwart.ui.paths import TEMPLATE_DIR
from blockwart.ui.security import (
    AUTH_CSRF_COOKIE_NAME,
    read_access_from_request,
    require_browser_read_access,
    require_browser_write_csrf,
)
from blockwart.ui.write_commands import execute_ui_command, ui_write_context

router = APIRouter(include_in_schema=False, dependencies=[Depends(require_browser_read_access)])
templates = Jinja2Templates(directory=TEMPLATE_DIR)
FIELDS = {
    "item": [
        "description",
        "item_type",
        "status",
        "assignee",
        "due_at",
        "parent_id",
        "issue_url",
        "related_objects",
    ],
    "page": ["body", "review_after", "related_objects"],
    "access": ["url", "purpose", "account", "credential_reference"],
}
CHOICES = {
    "status": ["open", "in_progress", "blocked", "done"],
    "item_type": ["task", "question", "blocker"],
}


@router.get("/projects/{object_id}/workspace")
def project_records_ui(
    request: Request,
    object_id: str,
    session: Annotated[Session, Depends(get_session)],
    kind: RecordKind = "item",
    status: str | None = None,
    item_type: str | None = None,
    overdue: bool = False,
    cursor: str | None = None,
    edit_id: str | None = None,
    history_id: str | None = None,
    history_cursor: str | None = None,
    q: str | None = None,
    search_cursor: str | None = None,
):
    access = read_access_from_request(request)
    status, item_type = status or None, item_type or None
    if (
        status
        and status not in CHOICES["status"]
        or item_type
        and item_type not in CHOICES["item_type"]
    ):
        raise HTTPException(422, "Invalid filter")
    try:
        project = read_project(session, access, object_id)
        page = list_records(
            session,
            access,
            object_id=object_id,
            kind=kind,
            status=status,
            item_type=item_type,
            overdue=overdue,
            cursor=cursor,
        )
        editing = None
        if edit_id:
            row = session.get(ProjectRecord, edit_id)
            if row is None or row.project_instance_id != project.instance_id or row.kind != kind:
                raise CommandNotFound("Record not found")
            editing = record_out(session, access, row)
        history = (
            record_history(
                session, access, object_id=object_id, record_id=history_id, cursor=history_cursor
            )
            if history_id
            else None
        )
        search = (
            search_workspace(session, access, object_id=object_id, q=q, cursor=search_cursor)
            if q
            else None
        )
    except CommandNotFound as exc:
        raise HTTPException(404, "Resource not found") from exc
    except InvalidCursor as exc:
        raise HTTPException(400, "Invalid cursor") from exc
    references = (
        session.query(CatalogObject).filter(CatalogObject.kind == "credential_reference").all()
    )
    references = [
        row for row in references if access.policy.visibility_for(row.id) == ObjectVisibility.DETAIL
    ]
    values = editing.data if editing else {}
    values = {
        key: "\n".join(value) if isinstance(value, list) else value for key, value in values.items()
    }
    rendered = {
        row.id: render_comment_source(
            row.data.get("body", row.data.get("description", "")), "markdown"
        )
        for row in page.items
    }
    ctx = {
        "object": project,
        "kind": kind,
        "page": page,
        "fields": FIELDS[kind],
        "choices": CHOICES,
        "values": values,
        "editing": editing,
        "history": history,
        "history_id": history_id,
        "search": search,
        "q": q or "",
        "status": status,
        "item_type": item_type,
        "overdue": overdue,
        "rendered": rendered,
        "references": references,
        "etag": revision_etag(project.revision),
        "can_write": access.policy.can(Permission.WRITE, object_id),
        "can_create_reference": access.policy.can(
            Permission.CREATE_CREDENTIAL_REFERENCE, object_id
        ),
        "csrf_token": request.cookies.get(AUTH_CSRF_COOKIE_NAME, ""),
        "idempotency_key": f"ui-project-record-{uuid4().hex}",
        **translation_context(request),
    }
    response = templates.TemplateResponse(request, "project_records.html", ctx)
    response.headers["ETag"] = revision_etag(project.revision)
    return response


@router.post("/projects/{object_id}/workspace", dependencies=[Depends(require_browser_write_csrf)])
async def save_project_record_ui(
    request: Request,
    object_id: str,
    session: Annotated[Session, Depends(get_session)],
    kind: Annotated[RecordKind, Form()],
    title: Annotated[str, Form()],
    if_match: Annotated[str, Form()],
    idempotency_key: Annotated[str, Form()],
    record_id: Annotated[str | None, Form()] = None,
):
    access = read_access_from_request(request)
    form = await request.form()
    values = {"kind": kind, "title": title}
    for field in FIELDS[kind]:
        value = str(form.get(field) or "").strip()
        if field == "related_objects":
            values[field] = list(dict.fromkeys(value.splitlines())) if value else []
        elif field in {
            "due_at",
            "review_after",
            "parent_id",
            "issue_url",
            "url",
            "credential_reference",
        }:
            values[field] = value or None
        else:
            values[field] = value
    if kind == "access" and form.get("new_reference_id"):
        values["new_credential_reference"] = {
            "id": str(form["new_reference_id"]),
            "kind": "credential_reference",
            "label": str(form.get("new_reference_label") or title),
            "data": {
                "schema_version": 1,
                "provider": "vaultwarden",
                "reference": {"item_hint": str(form.get("new_reference_location") or "")},
            },
        }
    try:
        payload = RECORD_ADAPTER.validate_python(values)
    except ValidationError as exc:
        # Never echo a rejected value or secret-shaped input back to HTML.
        raise HTTPException(
            422, translation_context(request)["t"]("project.records.invalid")
        ) from exc
    context = ui_write_context(request, access)
    try:
        execute_ui_command(
            session,
            context,
            lambda: save_record(
                session,
                context,
                object_id=object_id,
                payload=payload,
                record_id=record_id or None,
                expected_revision=if_match,
                idempotency_key=idempotency_key,
                idempotency_ttl_seconds=request.app.state.settings.idempotency_ttl_seconds,
            ),
        )
    except CommandValidationFailed as exc:
        raise HTTPException(422, str(exc)) from exc
    return RedirectResponse(f"/projects/{object_id}/workspace?kind={kind}", status_code=303)
