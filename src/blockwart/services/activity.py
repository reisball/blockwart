"""The authorized, catalog-wide agent activity feed (#188).

This module is the single application query behind the HTML view, REST v1, and
MCP. It is FastAPI-independent: it receives a session plus one immutable
principal/policy snapshot and returns one keyset page of classified audit
activity, newest-first by default.

It is strictly a read over rows other reviewed modules already own:

- ``audit_events`` written by catalog commands, seeds, comments, grants, and
  migration normalizers;
- the canonical catalog read model used for the per-object visibility decision.

Authorization happens before items, counts, ordering, and cursor binding. An
event is only ever emitted when its attributed object is currently visible to
the caller with full detail visibility. Events without an object attribution
and events of deleted or concealed objects are dropped fail-closed: they can
influence neither items, nor counts, nor cursors, nor ordering.

Size budget: every request scans at most ``ACTIVITY_MAX_SCAN_EVENTS`` newest
audit rows (bounded in SQL) plus one bounded constant-size catalog/relationship
snapshot for the visibility decision. The feed never requires a full-catalog
read and never rewrites the catalog database into an event store.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from blockwart.domain.activity import (
    ACTIVITY_EVENT_TYPES,
    ActivityItem,
    ActivityObject,
    ActivityPage,
    activity_detail_path,
    classify_activity_event_type,
)
from blockwart.domain.auth import ObjectVisibility
from blockwart.domain.placement import CANONICAL_PLACEMENT_RELATION_TYPE
from blockwart.domain.search import SEARCH_LIMIT_MAX, SEARCH_LIMIT_MIN
from blockwart.domain.timestamps import format_rfc3339_utc
from blockwart.models import AuditEvent, CatalogObject, Relationship
from blockwart.services.audit import load_audit_details, render_audit_summary_english
from blockwart.services.catalog import catalog_objects_from_snapshot
from blockwart.services.pagination import SortDirection, paginate_items
from blockwart.services.queries import project_catalog_objects
from blockwart.services.read_access import ReadAccess

ACTIVITY_RESOURCE = "activity"
ACTIVITY_SORT_FIELD = "occurred_at"
# Documented size budget: at most this many newest audit rows are examined per
# request (after the optional since filter). Older activity outside the window
# stays reachable through narrower filters (since/event type/object), not by
# unbounded scanning.
ACTIVITY_MAX_SCAN_EVENTS = 5000

__all__ = [
    "ACTIVITY_MAX_SCAN_EVENTS",
    "ACTIVITY_RESOURCE",
    "ACTIVITY_SORT_FIELD",
    "ActivityQueryError",
    "query_activity_page",
]


class ActivityQueryError(ValueError):
    """The activity request left the closed vocabulary or its bounds."""


def query_activity_page(
    session: Session,
    access: ReadAccess,
    *,
    since: str | None = None,
    event_type: str | None = None,
    kind: str | None = None,
    parent: str | None = None,
    object_id: str | None = None,
    limit: int = 50,
    cursor: str | None = None,
    direction: SortDirection = "desc",
    include_total: bool = False,
    now: datetime | None = None,
) -> ActivityPage:
    """Return one authorized activity page; counts derive from the same set."""
    if limit < SEARCH_LIMIT_MIN or limit > SEARCH_LIMIT_MAX:
        raise ActivityQueryError("activity limit must be between 1 and 100")
    if direction not in {"asc", "desc"}:
        raise ActivityQueryError("unknown activity ordering")
    if event_type is not None and event_type not in ACTIVITY_EVENT_TYPES:
        raise ActivityQueryError("unknown activity event type")
    if parent is not None and not isinstance(parent, str):
        raise ActivityQueryError("unknown activity parent")
    since_dt = _parse_since(since)

    readable = _readable_objects(session, access)
    subtree_ids = (
        _placement_subtree_ids(session, readable, parent)
        if parent is not None
        else None
    )

    statement = select(AuditEvent).order_by(
        AuditEvent.created_at.desc(),
        AuditEvent.id.desc(),
    )
    if since_dt is not None:
        statement = statement.where(AuditEvent.created_at >= since_dt)
    if object_id is not None:
        statement = statement.where(AuditEvent.object_id == object_id)
    statement = statement.limit(ACTIVITY_MAX_SCAN_EVENTS)

    items: list[ActivityItem] = []
    for row in session.scalars(statement).all():
        item = _project_event(
            row,
            readable=readable,
            event_type=event_type,
            kind=kind,
            subtree_ids=subtree_ids,
        )
        if item is not None:
            items.append(item)

    reference = now or datetime.now(UTC)
    page = paginate_items(
        items,
        key=lambda item: item.key,
        limit=limit,
        resource=ACTIVITY_RESOURCE,
        sort=ACTIVITY_SORT_FIELD,
        direction=direction,
        query={
            "access": access.cursor_scope,
            "authorized_view": _authorized_digest(items),
            "direction_note": "newest_first_default",
            "event_type": event_type or "",
            "kind": kind or "",
            "limit": limit,
            "object_id": object_id or "",
            "parent": parent or "",
            "since": since or "",
        },
        cursor=cursor,
        include_total=include_total,
    )
    return ActivityPage(
        items=page.items,
        next_cursor=page.next_cursor,
        total=page.total,
        generated_at=format_rfc3339_utc(reference) or "",
    )


def _parse_since(value: str | None) -> datetime | None:
    if value is None:
        return None
    normalized = value.strip()
    if not normalized:
        return None
    try:
        parsed = datetime.fromisoformat(normalized.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ActivityQueryError("since must be an RFC3339 timestamp") from exc
    if parsed.tzinfo is not None:
        parsed = parsed.astimezone(UTC)
    # Stored audit timestamps are naive UTC; compare against the same frame.
    return parsed.replace(tzinfo=None)


class _ReadableCatalog:
    """The authorized DETAIL-visibility projection used for attribution."""

    __slots__ = ("ids", "refs", "kinds", "labels")

    def __init__(self) -> None:
        self.ids: set[str] = set()
        self.refs: dict[str, str] = {}
        self.kinds: dict[str, str] = {}
        self.labels: dict[str, str] = {}


def _readable_objects(session: Session, access: ReadAccess) -> _ReadableCatalog:
    catalog_rows = list(
        session.scalars(
            select(CatalogObject).order_by(CatalogObject.kind, CatalogObject.label)
        ).all()
    )
    relationship_rows = list(
        session.scalars(select(Relationship).order_by(Relationship.id)).all()
    )
    canonical = catalog_objects_from_snapshot(
        catalog_rows,
        all_objects=catalog_rows,
        relationships=relationship_rows,
    )
    projected = project_catalog_objects(canonical, access)
    readable = _ReadableCatalog()
    for catalog_object in projected:
        if catalog_object.visibility != ObjectVisibility.DETAIL:
            continue
        readable.ids.add(catalog_object.id)
        readable.refs[catalog_object.id] = (
            f"{catalog_object.kind}:{catalog_object.id}"
        )
        readable.kinds[catalog_object.id] = catalog_object.kind
        readable.labels[catalog_object.id] = catalog_object.label
    return readable


def _placement_subtree_ids(
    session: Session,
    readable: _ReadableCatalog,
    parent: str,
) -> set[str]:
    """Resolve the readable placement subtree of one visible parent.

    An unknown or concealed parent resolves to an empty scope, which yields an
    empty page indistinguishable from a parent without activity.
    """
    if parent not in readable.ids:
        return set()
    children_by_ref: dict[str, list[str]] = {}
    for row in session.scalars(
        select(Relationship).where(
            Relationship.relation_type == CANONICAL_PLACEMENT_RELATION_TYPE
        )
    ).all():
        child_id = row.to_ref.split(":", 1)[1] if ":" in row.to_ref else None
        if child_id is None or child_id not in readable.ids:
            continue
        children_by_ref.setdefault(row.from_ref, []).append(child_id)
    subtree = {parent}
    frontier = [readable.refs[parent]]
    while frontier:
        current = frontier.pop()
        for child_id in children_by_ref.get(current, []):
            if child_id not in subtree:
                subtree.add(child_id)
                frontier.append(readable.refs[child_id])
    return subtree


def _project_event(
    row: AuditEvent,
    *,
    readable: _ReadableCatalog,
    event_type: str | None,
    kind: str | None,
    subtree_ids: set[str] | None,
) -> ActivityItem | None:
    """Classify and authorize one audit row; drop anything not fully visible."""
    object_id = row.object_id
    if object_id is None or object_id not in readable.ids:
        return None
    resolved_type = classify_activity_event_type(row.action)
    if event_type is not None and resolved_type != event_type:
        return None
    object_kind = readable.kinds[object_id]
    if kind is not None and object_kind != kind:
        return None
    if subtree_ids is not None and object_id not in subtree_ids:
        return None
    occurred_at = format_rfc3339_utc(row.created_at)
    if occurred_at is None:
        return None
    details = load_audit_details(row)
    summary = render_audit_summary_english(
        row.action,
        details,
        legacy_summary=row.summary,
    )
    return ActivityItem(
        key=(occurred_at, f"{row.id:020d}"),
        event_id=f"audit:{row.id:020d}",
        event_type=resolved_type,
        occurred_at=occurred_at,
        object=ActivityObject(
            ref=readable.refs[object_id],
            object_id=object_id,
            kind=object_kind,
            label=readable.labels.get(object_id),
        ),
        summary=summary[:512],
        actor=(row.actor or None)[:128] if row.actor else None,
        detail_path=activity_detail_path(resolved_type, object_id),
    )


def _authorized_digest(items: list[ActivityItem]) -> str:
    """Bind cursors to exactly the authorized filtered projection."""
    payload = sorted(f"{item.event_id}|{item.key[0]}|{item.key[1]}" for item in items)
    serialized = json.dumps(payload, ensure_ascii=True, separators=(",", ":"))
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()
