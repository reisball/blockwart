"""Instance-scoped, authorized project records with lossless explicit history."""

from __future__ import annotations

import json
from dataclasses import replace
from datetime import UTC, datetime
from uuid import uuid4

from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from blockwart.domain.auth import ObjectVisibility, Permission
from blockwart.domain.projects import project_authorized_data
from blockwart.domain.provenance import parse_rfc3339_utc
from blockwart.domain.references import TypedReference
from blockwart.domain.search import normalize_search_text
from blockwart.domain.timestamps import format_rfc3339_utc
from blockwart.models import CatalogObject, ObjectComment, ProjectRecord, ProjectRecordVersion
from blockwart.schemas.project_workspace import (
    ItemStatus,
    ItemType,
    ProjectAccessIn,
    ProjectHistoryPageOut,
    ProjectRecordCommandOut,
    ProjectRecordIn,
    ProjectRecordOut,
    ProjectRecordPageOut,
    ProjectRecordVersionOut,
    ProjectSearchHitOut,
    ProjectSearchPageOut,
    RecordKind,
)
from blockwart.services.access import lock_principal_rows
from blockwart.services.audit import add_audit_event
from blockwart.services.catalog import typed_reference_holders, upsert_object
from blockwart.services.commands import (
    CommandAuthorizationDenied,
    CommandConflict,
    CommandNotFound,
    CommandPreconditionFailed,
    CommandValidationFailed,
    WriteContext,
    _assign_creator_owner,
    _require_knowledge_reference_access,
    authorize_object_command,
    parse_if_match,
    reserve_idempotency_record,
    revision_etag,
)
from blockwart.services.pagination import paginate_items
from blockwart.services.policy import policy_for_principal
from blockwart.services.read_access import ReadAccess


def read_project(session: Session, access: ReadAccess, object_id: str) -> CatalogObject:
    row = session.get(CatalogObject, object_id)
    if (
        row is None
        or row.kind != "project"
        or access.policy.visibility_for(object_id) != ObjectVisibility.DETAIL
    ):
        raise CommandNotFound("Project not found")
    return row


def _record(session, project, record_id):
    row = session.get(ProjectRecord, record_id)
    if row is None or row.project_instance_id != project.instance_id:
        raise CommandNotFound("Project record not found")
    return row


def _projected_data(session, access, raw):
    data = json.loads(raw)
    refs = data.get("related_objects", [])
    if refs:
        data["related_objects"] = [ref for ref in refs if _visible_ref(session, access, ref)]
    ref = data.get("credential_reference")
    if ref and not _visible_ref(session, access, ref):
        data.pop("credential_reference", None)
    return data


def _visible_ref(session, access, value):
    try:
        ref = TypedReference.parse(value)
    except ValueError:
        return False
    target = session.get(CatalogObject, ref.object_id)
    return (
        target is not None
        and target.kind == ref.kind
        and access.policy.visibility_for(target.id) == ObjectVisibility.DETAIL
    )


def record_out(session, access, row):
    data = _projected_data(session, access, row.data_json)
    due = data.get("due_at")
    return ProjectRecordOut(
        id=row.id,
        kind=row.kind,
        data=data,
        version=row.version,
        created_at=format_rfc3339_utc(row.created_at),
        updated_at=format_rfc3339_utc(row.updated_at),
        completed_at=format_rfc3339_utc(row.completed_at),
        overdue=bool(
            due and data.get("status") != "done" and parse_rfc3339_utc(due) < datetime.now(UTC)
        ),
    )


def list_records(
    session: Session,
    access: ReadAccess,
    *,
    object_id: str,
    kind: RecordKind,
    status: ItemStatus | None = None,
    item_type: ItemType | None = None,
    overdue: bool = False,
    limit: int = 50,
    cursor: str | None = None,
) -> ProjectRecordPageOut:
    project = read_project(session, access, object_id)
    rows = session.scalars(
        select(ProjectRecord).where(
            ProjectRecord.project_instance_id == project.instance_id,
            ProjectRecord.kind == kind,
        )
    ).all()
    items = [record_out(session, access, row) for row in rows]
    items = [
        item
        for item in items
        if (status is None or item.data.get("status") == status)
        and (item_type is None or item.data.get("item_type") == item_type)
        and (not overdue or item.overdue)
    ]
    page = paginate_items(
        items,
        key=lambda item: (item.created_at, item.id),
        limit=limit,
        resource=f"projects/{object_id}/workspace/{kind}",
        sort="created_at",
        direction="asc",
        query={
            "access": access.cursor_scope,
            "instance": project.instance_id,
            "status": status,
            "item_type": item_type,
            "overdue": overdue,
        },
        cursor=cursor,
        include_total=True,
    )
    return ProjectRecordPageOut(items=page.items, next_cursor=page.next_cursor, total=page.total)


def record_history(
    session: Session,
    access: ReadAccess,
    *,
    object_id: str,
    record_id: str,
    limit: int = 50,
    cursor: str | None = None,
) -> ProjectHistoryPageOut:
    project = read_project(session, access, object_id)
    row = _record(session, project, record_id)
    versions = session.scalars(
        select(ProjectRecordVersion).where(ProjectRecordVersion.entry_id == row.id)
    ).all()
    items = [
        ProjectRecordVersionOut(
            version=version.version,
            data=_projected_data(session, access, version.data_json),
            author_id=version.author_id,
            author_label=version.author_label,
            origin=version.origin,
            created_at=format_rfc3339_utc(version.created_at),
            completed_at=format_rfc3339_utc(version.completed_at),
        )
        for version in versions
    ]
    page = paginate_items(
        items,
        key=lambda item: (f"{item.version:020d}", ""),
        limit=limit,
        resource=f"projects/{object_id}/workspace/history/{record_id}",
        sort="version",
        direction="desc",
        query={"access": access.cursor_scope, "instance": project.instance_id},
        cursor=cursor,
        include_total=True,
    )
    return ProjectHistoryPageOut(items=page.items, next_cursor=page.next_cursor, total=page.total)


def _validate_refs(session, context, data):
    values = list(data.get("related_objects", []))
    if data.get("credential_reference"):
        if not data["credential_reference"].startswith("credential_reference:"):
            raise CommandValidationFailed("A credential_reference kind:id is required")
        values.append(data["credential_reference"])
    for value in values:
        if not _visible_ref(session, ReadAccess(context.principal, context.policy), value):
            raise CommandNotFound("Referenced object not found")


def _validate_parent(session, project, record_id, data):
    parent_id = data.get("parent_id")
    visited = {record_id}
    while parent_id:
        if parent_id in visited:
            raise CommandConflict("Item hierarchy cannot contain cycles")
        visited.add(parent_id)
        parent = _record(session, project, parent_id)
        if parent.kind != "item":
            raise CommandValidationFailed("The parent must be an item in the same project")
        parent_id = json.loads(parent.data_json).get("parent_id")


def save_record(
    session: Session,
    context: WriteContext,
    *,
    object_id: str,
    payload: ProjectRecordIn,
    record_id: str | None,
    expected_revision: str | None,
    idempotency_key: str,
    idempotency_ttl_seconds: int,
) -> ProjectRecordCommandOut:
    authorize_object_command(session, context, object_id=object_id, permission=Permission.WRITE)
    # History provenance follows the same audience binding as project chronology.
    # Check before idempotency replay as well as before any durable mutation.
    trusted_origin = (
        context.principal.service_token_audience is None
        if context.channel == "ui"
        else context.channel in {"api", "mcp"}
        and context.principal.service_token_audience == context.channel
    )
    if not trusted_origin:
        raise CommandAuthorizationDenied(object_id=object_id, permission=Permission.WRITE)
    access = ReadAccess(context.principal, context.policy)
    project = read_project(session, access, object_id)
    expected = parse_if_match(expected_revision)
    data = payload.model_dump(mode="json")
    new_ref = payload.new_credential_reference if isinstance(payload, ProjectAccessIn) else None
    if new_ref:
        authorize_object_command(
            session, context, object_id=object_id, permission=Permission.CREATE_CREDENTIAL_REFERENCE
        )
    now = datetime.now(UTC).replace(tzinfo=None)
    request_data = {
        "data": data,
        "new_reference": new_ref.model_dump(mode="json") if new_ref else None,
        "record_id": record_id,
        "revision": expected,
    }
    idem, replay = reserve_idempotency_record(
        session,
        context,
        key=idempotency_key,
        operation_context=f"project_record:{project.instance_id}",
        request_payload=request_data,
        ttl_seconds=idempotency_ttl_seconds,
        now=now,
    )
    if replay is not None:
        result = ProjectRecordCommandOut.model_validate(replay)
        # References may have become concealed since the original response.
        result.record.data = _projected_data(session, access, json.dumps(result.record.data))
        result.replayed = True
        return result
    lock_principal_rows(session, (context.principal.id,))
    locked = session.scalar(
        select(CatalogObject)
        .where(
            CatalogObject.id == object_id,
            CatalogObject.instance_id == project.instance_id,
            CatalogObject.revision == expected,
        )
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    if locked is None:
        raise CommandPreconditionFailed("Project revision changed")
    context = replace(context, policy=policy_for_principal(session, context.principal.id))
    access = ReadAccess(context.principal, context.policy)
    authorize_object_command(session, context, object_id=object_id, permission=Permission.WRITE)
    row = _record(session, project, record_id) if record_id else None
    if row and row.kind != payload.kind:
        raise CommandValidationFailed("Record kind cannot be changed")
    # A hidden existing link must not be silently erased by an authorized projected edit.
    if row:
        old = json.loads(row.data_json)
        for field in ("credential_reference", "related_objects"):
            old_refs = old.get(field)
            if (
                field == "credential_reference"
                and old_refs
                and not _visible_ref(session, access, old_refs)
            ):
                if data.get(field) or new_ref:
                    raise CommandNotFound("Referenced object not found")
                data[field] = old_refs
            elif field == "related_objects" and old_refs:
                concealed = [ref for ref in old_refs if not _visible_ref(session, access, ref)]
                data[field] = list(dict.fromkeys([*data.get(field, []), *concealed]))
    visible_data = dict(data)
    if row:
        old = json.loads(row.data_json)
        for field in ("credential_reference", "related_objects"):
            if field == "credential_reference" and data.get(field) == old.get(field):
                visible_data.pop(field, None)
            elif field == "related_objects":
                visible_data[field] = [
                    ref for ref in data.get(field, []) if ref not in old.get(field, [])
                ]
    _validate_refs(session, context, visible_data)
    identity = row.id if row else str(uuid4())
    _validate_parent(session, project, identity, data)
    claimed = session.execute(
        update(CatalogObject)
        .where(
            CatalogObject.id == object_id,
            CatalogObject.instance_id == project.instance_id,
            CatalogObject.revision == expected,
        )
        .values(revision=expected + 1, updated_at=now)
        .execution_options(synchronize_session=False)
    )
    if claimed.rowcount != 1:
        raise CommandPreconditionFailed("Project revision changed")
    if new_ref:
        authorize_object_command(
            session, context, object_id=object_id, permission=Permission.CREATE_CREDENTIAL_REFERENCE
        )
        if session.get(CatalogObject, new_ref.id) or typed_reference_holders(
            session, f"credential_reference:{new_ref.id}"
        ):
            raise CommandConflict("Credential reference id unavailable")
        _require_knowledge_reference_access(session, context, new_ref, all_typed_references=True)
        try:
            created = upsert_object(session, new_ref, write_audit=False)
        except IntegrityError as exc:
            raise CommandConflict("Credential reference id unavailable") from exc
        _assign_creator_owner(session, context, object_id=created.id)
        data["credential_reference"] = f"credential_reference:{created.id}"
        add_audit_event(
            session,
            object_id=created.id,
            action="project_credential_reference_create",
            actor=context.principal.login,
            details={"project_id": object_id},
        )
        context = replace(context, policy=policy_for_principal(session, context.principal.id))
        access = ReadAccess(context.principal, context.policy)
    done = data.get("status") == "done"
    completed_at = (row.completed_at if row and row.completed_at else now) if done else None
    serialized = json.dumps(data, sort_keys=True, ensure_ascii=False)
    if row is None:
        row = ProjectRecord(
            id=identity,
            project_instance_id=project.instance_id,
            kind=payload.kind,
            data_json=serialized,
            version=1,
            created_at=now,
            updated_at=now,
            completed_at=completed_at,
        )
        session.add(row)
    else:
        row.data_json = serialized
        row.version += 1
        row.updated_at = now
        row.completed_at = completed_at
    session.add(
        ProjectRecordVersion(
            entry_id=row.id,
            version=row.version,
            data_json=serialized,
            author_id=context.principal.id,
            author_label=context.principal.display_name,
            origin=context.channel,
            created_at=now,
            completed_at=completed_at,
        )
    )
    add_audit_event(
        session,
        object_id=object_id,
        action="project_record_save",
        actor=context.principal.login,
        details={
            "record_id": row.id,
            "kind": row.kind,
            "version": row.version,
            "old_revision": expected,
            "new_revision": expected + 1,
        },
    )
    session.flush()
    result = ProjectRecordCommandOut(
        record=record_out(session, access, row),
        revision=expected + 1,
        etag=revision_etag(expected + 1),
    )
    idem.resource_id = object_id
    idem.response_json = result.model_dump_json()
    session.expire(project)
    return result


def search_workspace(
    session: Session,
    access: ReadAccess,
    *,
    object_id: str,
    q: str,
    limit: int = 50,
    cursor: str | None = None,
) -> ProjectSearchPageOut:
    project = read_project(session, access, object_id)
    term = normalize_search_text(q)
    hits = []
    # Search all curated canonical fields, not unknown imported extension payloads.
    from blockwart.domain.object_schema import BUILTIN_SCHEMAS

    canonical = project_authorized_data(
        json.loads(project.data_json),
        can_discover=lambda key: access.policy.visibility_for(key) == ObjectVisibility.DETAIL,
    )
    allowed = {
        field.path.split(".")[0].removesuffix("[]") for field in BUILTIN_SCHEMAS["project"].fields
    }
    for key, value in canonical.items():
        if key not in allowed:
            continue
        text = json.dumps(value, ensure_ascii=False) if not isinstance(value, str) else value
        hits.append(ProjectSearchHitOut(kind="field", id=key, title=key, text=text))
    rows = session.scalars(
        select(ProjectRecord).where(ProjectRecord.project_instance_id == project.instance_id)
    ).all()
    for row in rows:
        data = _projected_data(session, access, row.data_json)
        # Secret locations and even visible credential IDs are not indexed as prose.
        text = "\n".join(
            value
            for key, value in data.items()
            if key
            in {
                "title",
                "description",
                "assignee",
                "body",
                "purpose",
                "account",
                "url",
                "issue_url",
            }
            and isinstance(value, str)
        )
        hits.append(ProjectSearchHitOut(kind=row.kind, id=row.id, title=data["title"], text=text))
    comments = session.scalars(
        select(ObjectComment).where(
            ObjectComment.object_id == object_id,
            ObjectComment.object_instance_id == project.instance_id,
            ObjectComment.object_created_at == project.created_at,
        )
    ).all()
    hits.extend(
        ProjectSearchHitOut(
            kind="chronology", id=row.id, title=row.project_chronology_kind or "note", text=row.body
        )
        for row in comments
    )
    hits = [hit for hit in hits if not term or term in (normalize_search_text(hit.text) or "")]
    page = paginate_items(
        hits,
        key=lambda hit: (hit.kind, hit.id),
        limit=limit,
        resource=f"projects/{object_id}/workspace/search",
        sort="identity",
        direction="asc",
        query={"access": access.cursor_scope, "instance": project.instance_id, "q": term},
        cursor=cursor,
        include_total=True,
    )
    return ProjectSearchPageOut(items=page.items, next_cursor=page.next_cursor, total=page.total)


def item_summary(session: Session, access: ReadAccess, object_id: str) -> dict:
    project = read_project(session, access, object_id)
    rows = session.scalars(
        select(ProjectRecord)
        .where(
            ProjectRecord.project_instance_id == project.instance_id, ProjectRecord.kind == "item"
        )
        .order_by(ProjectRecord.created_at, ProjectRecord.id)
    ).all()
    items = [record_out(session, access, row) for row in rows]
    pending = [item for item in items if item.data.get("status") != "done"]
    return {
        "open": len(pending),
        "overdue": sum(item.overdue for item in pending),
        "items": pending[:5],
    }
