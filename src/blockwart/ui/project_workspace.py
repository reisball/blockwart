"""Accessible, structured browser workspace; all writes use shared commands."""

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
from blockwart.models import CatalogObject
from blockwart.schemas.project_workspace import RECORD_ADAPTER, ProjectActionIn, RecordKind
from blockwart.services import project_management as management
from blockwart.services.commands import CommandNotFound, CommandValidationFailed, revision_etag
from blockwart.services.pagination import InvalidCursor
from blockwart.services.project_workspace import (
    list_records,
    read_project,
    record_history,
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
        "priority",
        "assignee",
        "assignee_principal_id",
        "due_at",
        "parent_id",
        "blocked_reason",
        "issue_url",
        "related_objects",
        "mandatory",
        "archived",
        "status_authority",
    ],
    "page": ["body", "review_after", "related_objects", "lifecycle"],
    "access": ["url", "purpose", "account", "credential_reference"],
    "repository": [
        "owner",
        "name",
        "github_id",
        "sync_enabled",
        "credential_reference",
        "archived",
    ],
}
CHOICES = {
    "status": ["open", "in_progress", "blocked", "done", "deferred"],
    "item_type": [
        "task",
        "question",
        "blocker",
        "use_case",
        "requirement_group",
        "requirement",
        "decision",
        "evidence",
    ],
    "priority": ["low", "normal", "high", "urgent"],
    "status_authority": ["local", "github"],
    "lifecycle": ["current", "historical", "superseded"],
    "disposition": ["active", "superseded", "deferred", "waived"],
    "outcome": ["pass", "fail", "inconclusive"],
    "relation": [
        "implements",
        "applies_to",
        "depends_on",
        "precedes",
        "blocked_by",
        "supersedes",
        "documents",
        "informed_by",
        "evidence_for",
    ],
}
NULLABLE = {
    "due_at",
    "review_after",
    "parent_id",
    "issue_url",
    "url",
    "credential_reference",
    "assignee_principal_id",
}
BOOL_FIELDS = {"mandatory", "archived", "sync_enabled"}


def _all_records(session, access, object_id, kind):
    records, cursor = [], None
    while True:
        page = list_records(session, access, object_id=object_id, kind=kind, cursor=cursor)
        records.extend(page.items)
        cursor = page.next_cursor
        if not cursor:
            return records


def _hierarchy(items, visible):
    """Keep ancestors/filtered branches navigable without implying a complete page."""
    nodes = {
        r.id: {"record": r, "children": [], "filtered": r.id not in visible, "missing": False}
        for r in items
    }
    roots = []
    for node in nodes.values():
        parent = node["record"].data.get("parent_id")
        if parent in nodes:
            nodes[parent]["children"].append(node)
        else:
            node["missing"] = bool(parent)
            roots.append(node)
    return roots


def _context(request, session, access, project):
    references = (
        session.query(CatalogObject).filter(CatalogObject.kind == "credential_reference").all()
    )
    items = _all_records(session, access, project.id, "item")
    repositories = _all_records(session, access, project.id, "repository")
    pages = _all_records(session, access, project.id, "page")
    return {
        "object": project,
        "choices": CHOICES,
        "items": items,
        "repositories": repositories,
        "targets": items + pages,
        "references": [
            r for r in references if access.policy.visibility_for(r.id) == ObjectVisibility.DETAIL
        ],
        "etag": revision_etag(project.revision),
        "can_write": access.policy.can(Permission.WRITE, project.id),
        "can_create_reference": access.policy.can(
            Permission.CREATE_CREDENTIAL_REFERENCE, project.id
        ),
        "csrf_token": request.cookies.get(AUTH_CSRF_COOKIE_NAME, ""),
        "idempotency_key": f"ui-project-record-{uuid4().hex}",
        **translation_context(request),
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
    priority: str | None = None,
    archived: str = "active",
    cursor: str | None = None,
    edit_id: str | None = None,
    parent_id: str | None = None,
    history_id: str | None = None,
    history_cursor: str | None = None,
    q: str | None = None,
    search_cursor: str | None = None,
):
    access = read_access_from_request(request)
    status, item_type, priority = status or None, item_type or None, priority or None
    if any(
        value and value not in CHOICES[field]
        for field, value in (("status", status), ("item_type", item_type), ("priority", priority))
    ) or archived not in {"active", "archived", "all"}:
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
            priority=priority,
            archived=None if archived == "all" else archived == "archived",
            overdue=overdue,
            cursor=cursor,
        )
        editing = (
            management.get_record(session, access, object_id=object_id, record_id=edit_id)
            if edit_id
            else None
        )
        if editing and editing.kind != kind:
            raise CommandNotFound("Record not found")
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
        ctx = _context(request, session, access, project)
        overview = management.project_overview(session, access, object_id=object_id)
    except CommandNotFound as exc:
        raise HTTPException(404, "Resource not found") from exc
    except InvalidCursor as exc:
        raise HTTPException(400, "Invalid cursor") from exc
    values = dict(editing.data) if editing else ({"parent_id": parent_id} if parent_id else {})
    ctx.update(
        {
            "kind": kind,
            "page": page,
            "fields": FIELDS[kind],
            "values": values,
            "editing": editing,
            "history": history,
            "history_id": history_id,
            "search": search,
            "q": q or "",
            "status": status,
            "item_type": item_type,
            "priority": priority,
            "archived": archived,
            "overdue": overdue,
            "overview": overview,
            "hierarchy": _hierarchy(ctx["items"], {r.id for r in page.items}),
            "rendered": {
                r.id: render_comment_source(
                    r.data.get("body", r.data.get("description", "")), "markdown"
                )
                for r in page.items
            },
        }
    )
    response = templates.TemplateResponse(request, "project_records.html", ctx)
    response.headers["ETag"] = revision_etag(project.revision)
    return response


def _structured_values(form, kind, values):
    """Only posted controls replace fields: old browser clients cannot erase new metadata."""
    for field in FIELDS[kind]:
        if field in BOOL_FIELDS:
            if field in form or f"{field}_present" in form:
                values[field] = form.get(field) in {"true", "on", "1"}
            continue
        if field not in form:
            continue
        value = str(form.get(field) or "").strip()
        if field == "related_objects":
            values[field] = list(dict.fromkeys(v.strip() for v in value.splitlines() if v.strip()))
        elif field == "github_id":
            values[field] = int(value) if value else None
        else:
            values[field] = value or None if field in NULLABLE else value
    if "relations_present" in form:
        previous = {
            (edge["relation"], edge["target_id"]): edge for edge in values.get("relations", [])
        }
        versions = form.getlist("relation_version")
        values["relations"] = []
        for index, (relation, target) in enumerate(
            zip(form.getlist("relation_type"), form.getlist("relation_target"), strict=True)
        ):
            if target:
                version = (
                    (int(versions[index]) if versions[index] else None)
                    if versions
                    else previous.get((relation, target), {}).get("target_version")
                )
                values["relations"].append(
                    {"relation": relation, "target_id": target, "target_version": version}
                )
    if kind == "item":
        if "criteria_present" in form:
            ids, descriptions = form.getlist("criterion_id"), form.getlist("criterion_description")
            required = set(form.getlist("criterion_required"))
            values["criteria"] = [
                {"id": identity, "description": description, "required": str(index) in required}
                for index, (identity, description) in enumerate(zip(ids, descriptions, strict=True))
                if identity or description
            ]
        if "requirement_present" in form:
            previous_requirement = values.get("requirement")
            requirement = None
            if values.get("item_type") == "requirement":
                requirement = {
                    key: str(form.get(f"requirement_{key}") or "").strip()
                    for key in ["original", "source_url", "change_reason", "disposition"]
                }
                requirement["source_url"] = requirement["source_url"] or None
                # Empty controls must not invent a baseline/revision on a no-op edit.
                if previous_requirement is None and requirement == {
                    "original": "",
                    "source_url": None,
                    "change_reason": "",
                    "disposition": "active",
                }:
                    requirement = None
            values["requirement"] = requirement
        if "evidence_present" in form:
            if values.get("item_type") == "evidence":
                values["evidence"] = {
                    key: str(form.get(f"evidence_{key}") or "").strip()
                    for key in [
                        "requirement_id",
                        "requirement_revision",
                        "outcome",
                        "subject",
                        "scope",
                        "limitations",
                        "source_url",
                        "observed_at",
                    ]
                }
                values["evidence"]["criteria"] = [
                    v.strip()
                    for v in str(form.get("evidence_criteria") or "").splitlines()
                    if v.strip()
                ]
            else:
                values["evidence"] = None
        if "github_present" in form:
            values["github_references"] = []
            leading = str(form.get("leading_reference_index") or "")
            values["leading_reference"] = None
            for index, (repository, refkind, number, sha) in enumerate(
                zip(
                    form.getlist("github_repository"),
                    form.getlist("github_kind"),
                    form.getlist("github_number"),
                    form.getlist("github_sha"),
                    strict=True,
                )
            ):
                if repository:
                    ref = {
                        "repository_id": repository,
                        "kind": refkind,
                        "number": int(number) if number else None,
                        "sha": sha or None,
                    }
                    values["github_references"].append(ref)
                    if leading == str(index):
                        values["leading_reference"] = ref
    return values


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
    try:
        values = (
            dict(
                management.get_record(
                    session, access, object_id=object_id, record_id=record_id
                ).data
            )
            if record_id
            else {}
        )
        if values and values["kind"] != kind:
            raise CommandNotFound("Record not found")
        values.update({"kind": kind, "title": title})
        _structured_values(form, kind, values)
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
        payload = RECORD_ADAPTER.validate_python(values)
    except CommandNotFound as exc:
        raise HTTPException(404, "Resource not found") from exc
    except (ValidationError, ValueError, IndexError) as exc:
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


@router.get("/projects/{object_id}/workspace/record/{record_id}")
def project_record_detail_ui(
    request: Request,
    object_id: str,
    record_id: str,
    session: Annotated[Session, Depends(get_session)],
    event_kind: str | None = None,
    event_cursor: str | None = None,
    history_cursor: str | None = None,
):
    access = read_access_from_request(request)
    if event_kind not in {
        None,
        "",
        "comment",
        "patch",
        "assess",
        "reuse_evidence",
        "sync_github",
        "import_legacy",
    }:
        raise HTTPException(422, "Invalid event filter")
    try:
        project = read_project(session, access, object_id)
        record = management.get_record(session, access, object_id=object_id, record_id=record_id)
        events = management.record_events(
            session,
            access,
            object_id=object_id,
            record_id=record_id,
            kind=event_kind or None,
            cursor=event_cursor,
        )
        history = record_history(
            session, access, object_id=object_id, record_id=record_id, cursor=history_cursor
        )
        ctx = _context(request, session, access, project)
    except CommandNotFound as exc:
        raise HTTPException(404, "Resource not found") from exc
    except InvalidCursor as exc:
        raise HTTPException(400, "Invalid cursor") from exc
    ctx.update(
        {
            "record": record,
            "events": events,
            "event_kind": event_kind or "",
            "history": history,
            "body": render_comment_source(
                record.data.get("body", record.data.get("description", "")), "markdown"
            ),
            "event_bodies": {
                e.id: render_comment_source(
                    e.data.get("body", e.data.get("reason", "")), "markdown"
                )
                for e in events.items
            },
            "by_id": {r.id: r for r in ctx["targets"] + ctx["repositories"]},
        }
    )
    response = templates.TemplateResponse(request, "project_record_detail.html", ctx)
    response.headers["ETag"] = record.record_etag
    return response


@router.post(
    "/projects/{object_id}/workspace/record/{record_id}",
    dependencies=[Depends(require_browser_write_csrf)],
)
async def project_record_action_ui(
    request: Request,
    object_id: str,
    record_id: str,
    session: Annotated[Session, Depends(get_session)],
):
    access = read_access_from_request(request)
    form = await request.form()
    try:
        action = str(form.get("action") or "")
        data = {"action": action}
        if action == "patch":
            if "archived" in form and form["archived"] not in {"true", "false"}:
                raise ValueError("Invalid archive state")
            data["changes"] = {
                key: (form[key] == "true" if key in BOOL_FIELDS else form[key])
                for key in ["status", "priority", "archived", "blocked_reason"]
                if key in form
            }
        elif action == "comment":
            data["body"] = str(form.get("body") or "")
        elif action in {"assess", "reuse_evidence"}:
            data.update(
                reason=str(form.get("reason") or ""), evidence_ids=form.getlist("evidence_ids")
            )
            if action == "assess":
                data["result"] = form.get("result")
        payload = ProjectActionIn.model_validate(data)
        if action == "patch":
            current = management.get_record(
                session, access, object_id=object_id, record_id=record_id
            )
            RECORD_ADAPTER.validate_python({**current.data, **payload.changes})
    except CommandNotFound as exc:
        raise HTTPException(404, "Resource not found") from exc
    except (ValidationError, ValueError) as exc:
        raise HTTPException(
            422, translation_context(request)["t"]("project.records.invalid")
        ) from exc
    context = ui_write_context(request, access)
    try:
        execute_ui_command(
            session,
            context,
            lambda: management.apply_action(
                session,
                context,
                object_id=object_id,
                record_id=record_id,
                payload=payload,
                expected_record=str(form.get("record_etag") or ""),
                idempotency_key=str(form.get("idempotency_key") or ""),
                idempotency_ttl_seconds=request.app.state.settings.idempotency_ttl_seconds,
            ),
        )
    except CommandValidationFailed as exc:
        raise HTTPException(422, str(exc)) from exc
    return RedirectResponse(f"/projects/{object_id}/workspace/record/{record_id}", status_code=303)


@router.post(
    "/projects/{object_id}/workspace/import-legacy",
    dependencies=[Depends(require_browser_write_csrf)],
)
async def import_legacy_ui(
    request: Request, object_id: str, session: Annotated[Session, Depends(get_session)]
):
    access = read_access_from_request(request)
    form = await request.form()
    try:
        index = int(str(form.get("index") or ""))
        if (
            index < 0
            or form.get("field") not in {"open_questions", "blockers", "next_actions"}
            or not str(form.get("text") or "").strip()
        ):
            raise ValueError("Invalid legacy entry")
    except ValueError as exc:
        raise HTTPException(422, "Invalid legacy index") from exc
    context = ui_write_context(request, access)
    try:
        execute_ui_command(
            session,
            context,
            lambda: management.import_legacy(
                session,
                context,
                object_id=object_id,
                field=str(form.get("field") or ""),
                index=index,
                text=str(form.get("text") or ""),
                expected_revision=str(form.get("if_match") or ""),
                idempotency_key=str(form.get("idempotency_key") or ""),
                idempotency_ttl_seconds=request.app.state.settings.idempotency_ttl_seconds,
            ),
        )
    except CommandValidationFailed as exc:
        raise HTTPException(422, str(exc)) from exc
    return RedirectResponse(f"/projects/{object_id}/workspace#overview", status_code=303)
