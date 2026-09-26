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

Each page reads at most ``limit + 1`` authorized rows. An optional exact count
reads at most ``ACTIVITY_MAX_SCAN_EVENTS + 1`` authorized rows. If more rows
exist, ``total`` is null and ``total_status`` is ``budget_exhausted``; no
approximate count is advertised.
"""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import and_, bindparam, or_, select, text
from sqlalchemy.orm import Session

from blockwart.domain.activity import (
    ACTIVITY_EVENT_TYPES,
    COMMENT_CREATE_AUDIT_ACTIONS,
    OBJECT_REVISION_AUDIT_ACTIONS,
    RELATIONSHIP_MUTATION_AUDIT_ACTIONS,
    ActivityItem,
    ActivityObject,
    ActivityPage,
    activity_detail_path,
    classify_activity_event_type,
)
from blockwart.domain.auth import Permission
from blockwart.domain.placement import CANONICAL_PLACEMENT_RELATION_TYPE
from blockwart.domain.search import SEARCH_LIMIT_MAX, SEARCH_LIMIT_MIN
from blockwart.domain.timestamps import format_rfc3339_utc
from blockwart.models import AuditEvent, CatalogObject
from blockwart.services.audit import load_audit_details, render_audit_summary_english
from blockwart.services.pagination import (
    InvalidCursor,
    SortDirection,
    decode_page_cursor,
    encode_page_cursor,
)
from blockwart.services.read_access import ReadAccess

ACTIVITY_RESOURCE = "activity"
ACTIVITY_SORT_FIELD = "occurred_at"
# Maximum authorized audit rows returned by one page or exact count. The count
# may fetch one additional row solely to detect budget exhaustion.
ACTIVITY_MAX_SCAN_EVENTS = 5000
# Defensive depth bound for the parent-anchored recursive placement traversal.
# The canonical hierarchy is host -> system -> service (depth <= 2); this bound
# only guards against a malformed cycle, never against legitimate depth.
ACTIVITY_MAX_SUBTREE_DEPTH = 32

__all__ = [
    "ACTIVITY_MAX_SCAN_EVENTS",
    "ACTIVITY_MAX_SUBTREE_DEPTH",
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

    subtree_ids = _placement_subtree_ids(session, access, parent) if parent is not None else None

    query = {
        "access": access.cursor_scope,
        "direction_note": "newest_first_default",
        "event_type": event_type or "",
        "kind": kind or "",
        "limit": limit,
        "object_id": object_id or "",
        "parent": parent or "",
        "since": since or "",
    }
    position = decode_page_cursor(
        cursor,
        resource=ACTIVITY_RESOURCE,
        sort=ACTIVITY_SORT_FIELD,
        direction=direction,
        query=query,
    )

    conditions = _filter_conditions(
        access=access,
        subtree_ids=subtree_ids,
        since_dt=since_dt,
        object_id=object_id,
        event_type=event_type,
        kind=kind,
    )
    base = (
        select(AuditEvent)
        .join(CatalogObject, AuditEvent.object_id == CatalogObject.id)
        .where(*conditions)
    )

    order = (
        (AuditEvent.created_at.asc(), AuditEvent.id.asc())
        if direction == "asc"
        else (AuditEvent.created_at.desc(), AuditEvent.id.desc())
    )
    page_statement = base.order_by(*order)
    if position is not None:
        page_statement = page_statement.where(
            _keyset_predicate(
                _parse_cursor_primary(position[0]),
                _parse_cursor_tie_breaker(position[1]),
                direction,
            )
        )
    page_cap = min(limit + 1, ACTIVITY_MAX_SCAN_EVENTS)
    rows = list(session.scalars(page_statement.limit(page_cap)).all())
    readable = _readable_objects(session, access, {row.object_id for row in rows})
    items: list[ActivityItem] = []
    for row in rows[:limit]:
        item = _project_event(
            row,
            readable=readable,
            event_type=event_type,
            kind=kind,
            subtree_ids=subtree_ids,
        )
        if item is not None:
            items.append(item)
    has_more = len(rows) > limit or (page_cap <= limit and len(rows) == page_cap)
    next_cursor = None
    if has_more and items:
        primary, tie_breaker = items[-1].key
        next_cursor = encode_page_cursor(
            resource=ACTIVITY_RESOURCE,
            sort=ACTIVITY_SORT_FIELD,
            direction=direction,
            query=query,
            primary=primary,
            tie_breaker=tie_breaker,
        )

    total = None
    total_status = "not_requested"
    if include_total:
        count_rows = list(
            session.scalars(
                select(AuditEvent.id)
                .join(CatalogObject, AuditEvent.object_id == CatalogObject.id)
                .where(*conditions)
                .limit(ACTIVITY_MAX_SCAN_EVENTS + 1)
            ).all()
        )
        if len(count_rows) > ACTIVITY_MAX_SCAN_EVENTS:
            total_status = "budget_exhausted"
        else:
            total = len(count_rows)
            total_status = "exact"

    reference = now or datetime.now(UTC)
    return ActivityPage(
        items=items,
        next_cursor=next_cursor,
        total=total,
        generated_at=format_rfc3339_utc(reference) or "",
        total_status=total_status,
    )


def _filter_conditions(
    *,
    access: ReadAccess,
    subtree_ids: set[str] | None,
    since_dt: datetime | None,
    object_id: str | None,
    event_type: str | None,
    kind: str | None,
) -> list:
    """Authorize before ordering, cursors, counts, and page limits."""
    conditions = []
    if since_dt is not None:
        conditions.append(AuditEvent.created_at >= since_dt)
    if object_id is not None:
        conditions.append(AuditEvent.object_id == object_id)
    if not _global_read(access):
        conditions.append(AuditEvent.object_id.in_(access.policy.authorized_ids(Permission.READ)))
    if kind is not None:
        conditions.append(CatalogObject.kind == kind)
    if subtree_ids is not None:
        conditions.append(AuditEvent.object_id.in_(subtree_ids))
    if event_type is not None:
        action_set = _actions_for_event_type(event_type)
        if action_set is not None:
            conditions.append(AuditEvent.action.in_(action_set))
        else:
            all_known = (
                OBJECT_REVISION_AUDIT_ACTIONS
                | RELATIONSHIP_MUTATION_AUDIT_ACTIONS
                | COMMENT_CREATE_AUDIT_ACTIONS
            )
            conditions.append(AuditEvent.action.notin_(all_known))
    return conditions


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


def _parse_cursor_primary(primary: str) -> datetime:
    """Decode a cursor's RFC3339 primary back to a naive-UTC datetime."""
    try:
        parsed = datetime.fromisoformat(primary.replace("Z", "+00:00"))
    except ValueError as exc:
        raise InvalidCursor("Cursor position is malformed") from exc
    if parsed.tzinfo is not None:
        parsed = parsed.astimezone(UTC)
    return parsed.replace(tzinfo=None)


def _parse_cursor_tie_breaker(tie_breaker: str) -> int:
    """Decode a cursor's zero-padded id tie-breaker back to an integer."""
    try:
        return int(tie_breaker)
    except ValueError as exc:
        raise InvalidCursor("Cursor position is malformed") from exc


def _keyset_predicate(
    cursor_dt: datetime,
    cursor_id: int,
    direction: SortDirection,
):
    """Translate a decoded cursor into a ``(created_at, id)`` keyset predicate."""
    if direction == "asc":
        return or_(
            AuditEvent.created_at > cursor_dt,
            and_(AuditEvent.created_at == cursor_dt, AuditEvent.id > cursor_id),
        )
    return or_(
        AuditEvent.created_at < cursor_dt,
        and_(AuditEvent.created_at == cursor_dt, AuditEvent.id < cursor_id),
    )


class _ReadableCatalog:
    """The authorized DETAIL-visibility projection used for attribution."""

    __slots__ = ("ids", "refs", "kinds", "labels")

    def __init__(self) -> None:
        self.ids: set[str] = set()
        self.refs: dict[str, str] = {}
        self.kinds: dict[str, str] = {}
        self.labels: dict[str, str] = {}


def _global_read(access: ReadAccess) -> bool:
    return any(
        Permission.READ in authority.permissions for authority in access.policy.global_authorities
    )


def _readable_objects(
    session: Session, access: ReadAccess, candidate_ids: set[str | None]
) -> _ReadableCatalog:
    """Resolve only scanned candidates against the current catalog and policy."""
    readable = _ReadableCatalog()
    ids = {object_id for object_id in candidate_ids if object_id is not None}
    if not _global_read(access):
        ids.intersection_update(access.policy.authorized_ids(Permission.READ))
    if not ids:
        return readable
    rows = list(session.scalars(select(CatalogObject).where(CatalogObject.id.in_(ids))).all())
    for row in rows:
        readable.ids.add(row.id)
        readable.refs[row.id] = f"{row.kind}:{row.id}"
        readable.kinds[row.id] = row.kind
        readable.labels[row.id] = row.label
    return readable


def _actions_for_event_type(event_type: str) -> frozenset[str] | None:
    """Map one activity event type to its audit action set, or None for ``audit``."""
    if event_type == "object_revision":
        return OBJECT_REVISION_AUDIT_ACTIONS
    if event_type == "relationship_mutation":
        return RELATIONSHIP_MUTATION_AUDIT_ACTIONS
    if event_type == "comment_create":
        return COMMENT_CREATE_AUDIT_ACTIONS
    return None


def _placement_subtree_ids(
    session: Session,
    access: ReadAccess,
    parent: str,
) -> set[str]:
    """Resolve the readable placement subtree of one visible parent.

    The traversal is a parent-anchored recursive CTE (SQLite + PostgreSQL
    compatible) that only follows canonical ``hosts`` edges whose target is
    currently readable. It never loads unrelated placement relationships into
    Python, and the depth bound guards against a malformed cycle.

    An unknown or concealed parent resolves to an empty scope, which yields an
    empty page indistinguishable from a parent without activity.
    """
    readable = _readable_objects(session, access, {parent})
    if parent not in readable.ids:
        return set()
    parent_ref = readable.refs[parent]
    # Object-scoped grants need an explicit readable-target constraint. Global
    # READ is a wildcard: joining the catalog in the CTE avoids enumerating it.
    global_read = _global_read(access)
    if global_read:
        target_guard = "JOIN catalog_objects target ON r.to_ref = target.kind || ':' || target.id"
        readable_guard = ""
        readable_refs: list[str] = []
    else:
        local = _readable_objects(
            session, access, set(access.policy.authorized_ids(Permission.READ))
        )
        target_guard = ""
        readable_guard = "AND r.to_ref IN :readable_refs"
        readable_refs = list(local.refs.values())
    statement = text(
        f"""
        WITH RECURSIVE subtree(ref, depth) AS (
            SELECT :parent_ref, 0
            UNION
            SELECT r.to_ref, s.depth + 1
            FROM relationships r
            JOIN subtree s ON r.from_ref = s.ref
            {target_guard}
            WHERE r.relation_type = :rel_type
              {readable_guard}
              AND s.depth < :max_depth
        )
        SELECT ref FROM subtree
        """
    )
    if not global_read:
        statement = statement.bindparams(bindparam("readable_refs", expanding=True))
    refs = (
        session.execute(
            statement,
            {
                "parent_ref": parent_ref,
                "rel_type": CANONICAL_PLACEMENT_RELATION_TYPE,
                "readable_refs": readable_refs,
                "max_depth": ACTIVITY_MAX_SUBTREE_DEPTH,
            },
        )
        .scalars()
        .all()
    )
    return {ref.split(":", 1)[1] for ref in refs}


def _is_visible(
    row: AuditEvent,
    readable: _ReadableCatalog,
    kind: str | None,
    subtree_ids: set[str] | None,
) -> bool:
    object_id = row.object_id
    return (
        object_id is not None
        and object_id in readable.ids
        and (kind is None or readable.kinds[object_id] == kind)
        and (subtree_ids is None or object_id in subtree_ids)
    )


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
    if not _is_visible(row, readable, kind, subtree_ids):
        return None
    resolved_type = classify_activity_event_type(row.action)
    if event_type is not None and resolved_type != event_type:
        return None
    object_kind = readable.kinds[object_id]
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
