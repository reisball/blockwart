from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import uuid4

from sqlalchemy import and_, func, or_, select, tuple_, update
from sqlalchemy.orm import Session, aliased

from blockwart.domain.auth import ObjectVisibility, Permission
from blockwart.domain.provenance import parse_rfc3339_utc
from blockwart.domain.security import find_secret_violations
from blockwart.domain.timestamps import format_rfc3339_utc
from blockwart.models import CatalogObject, ObjectComment
from blockwart.schemas.comments import CommentOut
from blockwart.services.audit import add_audit_event
from blockwart.services.commands import (
    CommandAuthorizationDenied,
    CommandConflict,
    CommandNotFound,
    WriteContext,
    reserve_idempotency_record,
    revision_etag,
)
from blockwart.services.pagination import (
    InvalidCursor,
    decode_page_cursor,
    encode_page_cursor,
)
from blockwart.services.read_access import ReadAccess

MAX_COMMENT_LENGTH = 4000


@dataclass(frozen=True, slots=True)
class CommentPage:
    items: list[CommentOut]
    next_cursor: str | None
    total: int | None


@dataclass(frozen=True, slots=True)
class CommentCommandResult:
    comment: CommentOut
    revision: int
    etag: str
    replayed: bool = False


def query_comment_page(
    session: Session,
    access: ReadAccess,
    *,
    object_id: str,
    limit: int,
    cursor: str | None,
    include_total: bool,
) -> CommentPage | None:
    catalog_object = session.get(CatalogObject, object_id)
    if catalog_object is None or access.policy.visibility_for(object_id) != ObjectVisibility.DETAIL:
        return None
    resource = f"objects/{object_id}/comments"
    query = {
        "access": access.cursor_scope,
        "object_id": object_id,
        "object_instance_id": catalog_object.instance_id,
    }
    position = decode_page_cursor(
        cursor,
        resource=resource,
        sort="created_at",
        direction="desc",
        query=query,
    )
    filters = (
        ObjectComment.object_id == catalog_object.id,
        ObjectComment.object_instance_id == catalog_object.instance_id,
        ObjectComment.object_created_at == catalog_object.created_at,
    )
    statement = select(ObjectComment).where(*filters)
    if position is not None:
        try:
            position_created_at = parse_rfc3339_utc(position[0]).replace(tzinfo=None)
        except ValueError as exc:
            raise InvalidCursor("Cursor timestamp is invalid") from exc
        statement = statement.where(
            or_(
                ObjectComment.created_at < position_created_at,
                and_(
                    ObjectComment.created_at == position_created_at,
                    ObjectComment.id < position[1],
                ),
            )
        )
    rows = list(
        session.scalars(
            statement.order_by(
                ObjectComment.created_at.desc(),
                ObjectComment.id.desc(),
            ).limit(limit + 1)
        ).all()
    )
    items = rows[:limit]
    next_cursor = None
    if len(rows) > limit and items:
        next_cursor = encode_page_cursor(
            resource=resource,
            sort="created_at",
            direction="desc",
            query=query,
            primary=format_rfc3339_utc(items[-1].created_at) or "",
            tie_breaker=items[-1].id,
        )
    total = None
    if include_total:
        total = int(
            session.scalar(
                select(func.count()).select_from(ObjectComment).where(*filters)
            )
            or 0
        )
    return CommentPage(
        items=[comment_out(row) for row in items],
        next_cursor=next_cursor,
        total=total,
    )


def recent_comments_for_object(
    session: Session,
    catalog_object: CatalogObject,
    *,
    limit: int = 5,
) -> list[CommentOut]:
    rows = session.scalars(
        select(ObjectComment)
        .where(
            ObjectComment.object_id == catalog_object.id,
            ObjectComment.object_instance_id == catalog_object.instance_id,
            ObjectComment.object_created_at == catalog_object.created_at,
        )
        .order_by(ObjectComment.created_at.desc(), ObjectComment.id.desc())
        .limit(limit)
    ).all()
    return [comment_out(row) for row in rows]


def recent_comments_for_objects(
    session: Session,
    catalog_objects: list[CatalogObject],
    *,
    limit: int = 5,
) -> dict[str, list[CommentOut]]:
    """Prefetch the newest comments for several objects in one bounded query.

    Each catalog object is matched by its (object_id, object_instance_id,
    object_created_at) identity triple, so stale comments from a previous
    instance of a reused id are excluded. A ``row_number`` window partitions
    by object_id and keeps only the ``limit`` newest rows per object, bounding
    the result to at most ``limit * len(catalog_objects)`` rows. The query
    count is independent of the number of requested objects.
    """
    if not catalog_objects:
        return {}
    keys = [
        (obj.id, obj.instance_id, obj.created_at)
        for obj in catalog_objects
    ]
    row_number = func.row_number().over(
        partition_by=ObjectComment.object_id,
        order_by=[
            ObjectComment.created_at.desc(),
            ObjectComment.id.desc(),
        ],
    ).label("rn")
    inner = (
        select(ObjectComment, row_number)
        .where(
            tuple_(
                ObjectComment.object_id,
                ObjectComment.object_instance_id,
                ObjectComment.object_created_at,
            ).in_(keys)
        )
        .subquery()
    )
    comment_alias = aliased(ObjectComment, inner)
    rows = session.scalars(
        select(comment_alias).where(inner.c.rn <= limit)
    ).all()
    comments_by_object: dict[str, list[CommentOut]] = {
        obj.id: [] for obj in catalog_objects
    }
    for row in rows:
        bucket = comments_by_object.get(row.object_id)
        if bucket is None:
            continue
        bucket.append(comment_out(row))
    for bucket in comments_by_object.values():
        bucket.sort(key=lambda c: (c.created_at, c.id), reverse=True)
    return comments_by_object


def add_object_comment(
    session: Session,
    context: WriteContext,
    *,
    object_id: str,
    body: str,
    idempotency_key: str,
    idempotency_ttl_seconds: int,
    project_chronology_kind: str | None = None,
) -> CommentCommandResult:
    catalog_object = session.get(CatalogObject, object_id)
    visibility = context.policy.visibility_for(object_id)
    if catalog_object is None or visibility == ObjectVisibility.NONE:
        raise CommandNotFound("catalog object not found")
    if not context.policy.can(Permission.WRITE, object_id):
        raise CommandAuthorizationDenied(
            object_id=object_id,
            permission=Permission.WRITE,
        )
    _require_trusted_comment_origin(context, object_id)
    if not body.strip():
        raise CommandConflict("comment body must not be blank")
    if len(body) > MAX_COMMENT_LENGTH:
        raise CommandConflict(f"comment body must contain at most {MAX_COMMENT_LENGTH} characters")
    if find_secret_violations(body, path="comment"):
        raise CommandConflict("comment body contains secret-like content")
    if project_chronology_kind is not None and catalog_object.kind != "project":
        raise CommandConflict("project chronology entries require a Project")

    now = datetime.now(UTC).replace(tzinfo=None)
    instance_key = catalog_object.instance_id
    request_payload = {
        "body": body,
        "format": "markdown",
        "object_id": object_id,
        "object_instance_id": catalog_object.instance_id,
        "object_created_at": format_rfc3339_utc(catalog_object.created_at),
        "origin": context.channel,
    }
    if project_chronology_kind is not None:
        request_payload["project_chronology_kind"] = project_chronology_kind
    record, replay = reserve_idempotency_record(
        session,
        context,
        key=idempotency_key,
        operation_context=(
            f"project_chronology_create:{object_id}:{instance_key}"
            if project_chronology_kind is not None
            else f"object_comment_create:{object_id}:{instance_key}"
        ),
        request_payload=request_payload,
        ttl_seconds=idempotency_ttl_seconds,
        now=now,
    )
    if replay is not None:
        comment_id = replay.get("comment_id")
        revision = replay.get("revision")
        etag = replay.get("etag")
        row = session.get(ObjectComment, comment_id) if isinstance(comment_id, str) else None
        if (
            row is None
            or row.object_id != catalog_object.id
            or row.object_instance_id != catalog_object.instance_id
            or row.object_created_at != catalog_object.created_at
            or not isinstance(revision, int)
            or not isinstance(etag, str)
        ):
            raise CommandConflict("stored idempotency response is invalid")
        return CommentCommandResult(
            comment=comment_out(row),
            revision=revision,
            etag=etag,
            replayed=True,
        )

    row = ObjectComment(
        id=str(uuid4()),
        object_id=catalog_object.id,
        object_instance_id=catalog_object.instance_id,
        object_created_at=catalog_object.created_at,
        author_principal_id=context.principal.id,
        author_login=context.principal.login,
        author_display_name=context.principal.display_name,
        author_principal_type=context.principal.principal_type,
        origin=context.channel,
        format="markdown",
        project_chronology_kind=project_chronology_kind,
        body=body,
        created_at=now,
    )
    session.add(row)
    session.flush()
    revision = _bump_comment_revision(session, catalog_object)
    etag = revision_etag(revision)
    audit_details: dict[str, object] = {
        "comment_id": row.id,
        "principal_id": context.principal.id,
        "channel": context.channel,
        "request_id": context.request_id,
        "new_revision": revision,
    }
    if project_chronology_kind is not None:
        audit_details["project_chronology_kind"] = project_chronology_kind
    add_audit_event(
        session,
        object_id=catalog_object.id,
        action="comment_create",
        actor=context.principal.id,
        details=audit_details,
    )
    record.resource_id = row.id
    record.response_json = json.dumps(
        {"comment_id": row.id, "etag": etag, "revision": revision},
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    )
    session.flush()
    return CommentCommandResult(
        comment=comment_out(row),
        revision=revision,
        etag=etag,
    )


def comment_out(row: ObjectComment) -> CommentOut:
    return CommentOut(
        id=row.id,
        object_id=row.object_id,
        author_principal_id=row.author_principal_id,
        author_login=row.author_login,
        author_display_name=row.author_display_name,
        author_principal_type=row.author_principal_type,
        origin=row.origin,
        format=row.format,
        body=row.body,
        created_at=format_rfc3339_utc(row.created_at),
    )


def _require_trusted_comment_origin(context: WriteContext, object_id: str) -> None:
    if context.channel == "ui":
        if context.principal.service_token_audience is None:
            return
    elif context.channel in {"api", "mcp"}:
        if context.principal.service_token_audience == context.channel:
            return
    raise CommandAuthorizationDenied(
        object_id=object_id,
        permission=Permission.WRITE,
    )


def _bump_comment_revision(session: Session, catalog_object: CatalogObject) -> int:
    result = session.execute(
        update(CatalogObject)
        .where(CatalogObject.id == catalog_object.id)
        .values(
            revision=CatalogObject.revision + 1,
            updated_at=CatalogObject.updated_at,
        )
        .execution_options(synchronize_session=False)
    )
    if result.rowcount != 1:
        raise CommandNotFound("catalog object not found")
    session.expire(catalog_object, attribute_names=["revision", "updated_at"])
    revision = session.scalar(
        select(CatalogObject.revision).where(
            CatalogObject.id == catalog_object.id,
        )
    )
    if revision is None:
        raise CommandNotFound("catalog object not found")
    return int(revision)
