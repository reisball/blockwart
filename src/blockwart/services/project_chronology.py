"""Authorized Project overview and append-only professional chronology."""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import and_, func, or_, select, tuple_
from sqlalchemy.orm import Session, aliased

from blockwart.domain.auth import ObjectVisibility
from blockwart.domain.projects import ProjectCategory, ProjectStatus, project_authorized_data
from blockwart.domain.provenance import parse_rfc3339_utc
from blockwart.domain.timestamps import format_rfc3339_utc
from blockwart.models import CatalogObject, ObjectComment
from blockwart.schemas.projects import (
    ProjectChronologyEntryOut,
    ProjectChronologyKind,
    ProjectOverviewItemOut,
    ProjectOverviewSort,
)
from blockwart.schemas.v1 import SortDirection
from blockwart.services.commands import CommandNotFound, WriteContext
from blockwart.services.comments import CommentCommandResult, add_object_comment
from blockwart.services.pagination import (
    InvalidCursor,
    decode_page_cursor,
    encode_page_cursor,
    paginate_items,
)
from blockwart.services.read_access import ReadAccess


@dataclass(frozen=True, slots=True)
class ProjectChronologyPage:
    items: list[ProjectChronologyEntryOut]
    next_cursor: str | None
    total: int | None


@dataclass(frozen=True, slots=True)
class ProjectChronologyCommandResult:
    entry: ProjectChronologyEntryOut
    revision: int
    etag: str
    replayed: bool = False


@dataclass(frozen=True, slots=True)
class ProjectOverviewPage:
    items: list[ProjectOverviewItemOut]
    next_cursor: str | None
    total: int | None


def query_project_chronology_page(
    session: Session,
    access: ReadAccess,
    *,
    object_id: str,
    limit: int,
    cursor: str | None,
    include_total: bool,
) -> ProjectChronologyPage | None:
    project = session.get(CatalogObject, object_id)
    if (
        project is None
        or project.kind != "project"
        or access.policy.visibility_for(object_id) != ObjectVisibility.DETAIL
    ):
        return None
    resource = f"projects/{object_id}/chronology"
    query = {
        "access": access.cursor_scope,
        "object_id": object_id,
        "object_instance_id": project.instance_id,
    }
    position = decode_page_cursor(
        cursor,
        resource=resource,
        sort="created_at",
        direction="desc",
        query=query,
    )
    filters = _instance_filters(project)
    statement = select(ObjectComment).where(*filters)
    if position is not None:
        try:
            created_at = parse_rfc3339_utc(position[0]).replace(tzinfo=None)
        except ValueError as exc:
            raise InvalidCursor("Cursor timestamp is invalid") from exc
        statement = statement.where(
            or_(
                ObjectComment.created_at < created_at,
                and_(
                    ObjectComment.created_at == created_at,
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
            session.scalar(select(func.count()).select_from(ObjectComment).where(*filters))
            or 0
        )
    return ProjectChronologyPage(
        items=[project_chronology_out(row) for row in items],
        next_cursor=next_cursor,
        total=total,
    )


def add_project_chronology_entry(
    session: Session,
    context: WriteContext,
    *,
    object_id: str,
    kind: ProjectChronologyKind,
    body: str,
    idempotency_key: str,
    idempotency_ttl_seconds: int,
) -> ProjectChronologyCommandResult:
    project = session.get(CatalogObject, object_id)
    if project is None or project.kind != "project":
        raise CommandNotFound("catalog object not found")
    result: CommentCommandResult = add_object_comment(
        session,
        context,
        object_id=object_id,
        body=body,
        idempotency_key=idempotency_key,
        idempotency_ttl_seconds=idempotency_ttl_seconds,
        project_chronology_kind=kind,
    )
    row = session.get(ObjectComment, result.comment.id)
    if row is None:
        raise CommandNotFound("project chronology entry not found")
    return ProjectChronologyCommandResult(
        entry=project_chronology_out(row),
        revision=result.revision,
        etag=result.etag,
        replayed=result.replayed,
    )


def recent_project_chronology_for_object(
    session: Session,
    project: CatalogObject,
    *,
    limit: int = 5,
) -> list[ProjectChronologyEntryOut]:
    if project.kind != "project":
        return []
    rows = session.scalars(
        select(ObjectComment)
        .where(*_instance_filters(project))
        .order_by(ObjectComment.created_at.desc(), ObjectComment.id.desc())
        .limit(limit)
    ).all()
    return [project_chronology_out(row) for row in rows]


def recent_project_chronology_for_objects(
    session: Session,
    objects: list[CatalogObject],
    *,
    limit: int = 5,
) -> dict[str, list[ProjectChronologyEntryOut]]:
    projects = [row for row in objects if row.kind == "project"]
    if not projects:
        return {}
    keys = [(row.id, row.instance_id, row.created_at) for row in projects]
    row_number = func.row_number().over(
        partition_by=ObjectComment.object_id,
        order_by=[ObjectComment.created_at.desc(), ObjectComment.id.desc()],
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
    rows = session.scalars(select(comment_alias).where(inner.c.rn <= limit)).all()
    result = {project.id: [] for project in projects}
    for row in rows:
        result[row.object_id].append(project_chronology_out(row))
    for entries in result.values():
        entries.sort(key=lambda entry: (entry.created_at, entry.id), reverse=True)
    return result


def query_project_overview_page(
    session: Session,
    access: ReadAccess,
    *,
    project_category: ProjectCategory | None,
    project_status: ProjectStatus | None,
    limit: int,
    cursor: str | None,
    sort: ProjectOverviewSort,
    direction: SortDirection,
    include_total: bool,
) -> ProjectOverviewPage:
    # Authorization happens before filtering and before chronology reads. Stubs
    # therefore cannot match hidden fields or contribute activity timestamps/counts.
    projects = [
        row
        for row in session.scalars(
            select(CatalogObject)
            .where(CatalogObject.kind == "project")
            .order_by(CatalogObject.id)
        ).all()
        if access.policy.visibility_for(row.id) == ObjectVisibility.DETAIL
    ]
    filtered: list[tuple[CatalogObject, dict[str, object]]] = []
    for project in projects:
        data = project_authorized_data(
            _safe_project_data(project),
            can_discover=lambda object_id: access.policy.visibility_for(object_id)
            != ObjectVisibility.NONE,
        )
        if project_category is not None and data.get("category") != project_category:
            continue
        if project_status is not None and data.get("project_status") != project_status:
            continue
        filtered.append((project, data))

    latest = recent_project_chronology_for_objects(
        session,
        [project for project, _ in filtered],
        limit=1,
    )
    items = [
        ProjectOverviewItemOut(
            capabilities=access.capabilities_for(project.id),
            ref=f"project:{project.id}",
            id=project.id,
            label=project.label,
            revision=project.revision,
            category=_optional_string(data.get("category")),
            project_status=_optional_string(data.get("project_status")),
            current_summary=_optional_string(data.get("current_summary")),
            next_action=_first_string(data.get("next_actions")),
            last_professional_activity=(
                latest[project.id][0]
                if latest.get(project.id)
                else None
            ),
        )
        for project, data in filtered
    ]
    page = paginate_items(
        items,
        key=lambda item: _overview_sort_key(item, sort),
        limit=limit,
        resource="projects",
        sort=sort,
        direction=direction,
        query={
            "access": access.cursor_scope,
            "project_category": project_category,
            "project_status": project_status,
        },
        cursor=cursor,
        include_total=include_total,
    )
    return ProjectOverviewPage(
        items=page.items,
        next_cursor=page.next_cursor,
        total=page.total,
    )


def project_chronology_out(row: ObjectComment) -> ProjectChronologyEntryOut:
    # Explicit compatibility projection: every pre-0018 Project comment and
    # every generic Project comment is a note. Its text and attribution are untouched.
    kind = row.project_chronology_kind or "note"
    return ProjectChronologyEntryOut(
        id=row.id,
        object_id=row.object_id,
        kind=kind,
        author_principal_id=row.author_principal_id,
        author_login=row.author_login,
        author_display_name=row.author_display_name,
        author_principal_type=row.author_principal_type,
        origin=row.origin,
        format=row.format,
        body=row.body,
        created_at=format_rfc3339_utc(row.created_at),
    )


def _instance_filters(project: CatalogObject) -> tuple[object, object, object]:
    return (
        ObjectComment.object_id == project.id,
        ObjectComment.object_instance_id == project.instance_id,
        ObjectComment.object_created_at == project.created_at,
    )


def _overview_sort_key(
    item: ProjectOverviewItemOut,
    sort: ProjectOverviewSort,
) -> tuple[str, str]:
    if sort == "last_activity":
        activity = item.last_professional_activity
        return (activity.created_at if activity is not None else "", item.id)
    if sort == "label":
        return (item.label.casefold(), item.id)
    return (item.id, item.id)


def _safe_project_data(project: CatalogObject) -> dict[str, object]:
    import json

    try:
        value = json.loads(project.data_json or "{}")
    except (TypeError, json.JSONDecodeError):
        return {}
    return value if isinstance(value, dict) else {}


def _optional_string(value: object) -> str | None:
    return value if isinstance(value, str) else None


def _first_string(value: object) -> str | None:
    if not isinstance(value, list):
        return None
    return next((entry for entry in value if isinstance(entry, str)), None)
