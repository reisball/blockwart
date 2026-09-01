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

Pagination is database-level keyset pagination over ``(created_at, id)``: the
opaque cursor is translated into a SQL predicate before ``LIMIT limit + 1``, so
every matching event stays reachable through cursor walking and no event is
skipped or duplicated. Keyset pagination is bounded per page: each page reads
at most ``limit + 1`` rows. ``include_total`` runs a separate authorized
filtered ``COUNT`` over the same WHERE chain, so the total is the exact full
result count; that exact count is optional and potentially expensive because it
scans the whole authorized filtered set. ``ACTIVITY_MAX_SCAN_EVENTS`` is a
documented size budget: when an exact total is requested and exceeds it, the
response exposes ``total_exceeds_budget: true`` so callers can narrow their
filters instead of mistaking a page for the full result.
"""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import and_, bindparam, func, or_, select, text
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
# Documented size budget: the feed is designed around at most this many newest
# audit rows per result set. It is not a hard scan cap: keyset pagination walks
# the full authorized filtered set one bounded page at a time, and
# ``include_total`` counts it exactly. When an exact total is requested and
# exceeds this budget the response exposes ``total_exceeds_budget: true`` so
# callers can narrow their filters instead of mistaking a page for the full
# result.
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

    readable = _readable_objects(session, access)
    subtree_ids = (
        _placement_subtree_ids(session, readable, parent)
        if parent is not None
        else None
    )

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
        readable=readable,
        subtree_ids=subtree_ids,
        since_dt=since_dt,
        object_id=object_id,
        event_type=event_type,
        kind=kind,
    )
    base = select(AuditEvent).where(*conditions)

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
    page_statement = page_statement.limit(limit + 1)

    rows = list(session.scalars(page_statement).all())
    items: list[ActivityItem] = []
    for row in rows:
        item = _project_event(
            row,
            readable=readable,
            event_type=event_type,
            kind=kind,
            subtree_ids=subtree_ids,
        )
        if item is not None:
            items.append(item)

    has_more = len(rows) > limit
    page_items = items[:limit]
    next_cursor = None
    if has_more and page_items:
        primary, tie_breaker = page_items[-1].key
        next_cursor = encode_page_cursor(
            resource=ACTIVITY_RESOURCE,
            sort=ACTIVITY_SORT_FIELD,
            direction=direction,
            query=query,
            primary=primary,
            tie_breaker=tie_breaker,
        )

    total = None
    if include_total:
        total = session.scalar(
            select(func.count()).select_from(AuditEvent).where(*conditions)
        ) or 0

    reference = now or datetime.now(UTC)
    return ActivityPage(
        items=page_items,
        next_cursor=next_cursor,
        total=total,
        generated_at=format_rfc3339_utc(reference) or "",
        total_exceeds_budget=(
            total > ACTIVITY_MAX_SCAN_EVENTS if include_total and total is not None else None
        ),
    )


def _filter_conditions(
    *,
    readable: _ReadableCatalog,
    subtree_ids: set[str] | None,
    since_dt: datetime | None,
    object_id: str | None,
    event_type: str | None,
    kind: str | None,
) -> list:
    """Build the shared authorized WHERE chain for page and count queries."""
    conditions = []
    if since_dt is not None:
        conditions.append(AuditEvent.created_at >= since_dt)
    if object_id is not None:
        conditions.append(AuditEvent.object_id == object_id)
    # Authorization and filters are pushed into SQL: only rows attributed to
    # currently DETAIL-visible objects are examined, and event_type/kind/parent
    # narrow the set before pagination or counting applies.
    conditions.append(AuditEvent.object_id.in_(readable.ids))
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
    if kind is not None:
        kind_ids = readable.ids_by_kind.get(kind, frozenset())
        conditions.append(AuditEvent.object_id.in_(kind_ids))
    if subtree_ids is not None:
        conditions.append(AuditEvent.object_id.in_(subtree_ids))
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

    __slots__ = ("ids", "refs", "kinds", "labels", "ids_by_kind")

    def __init__(self) -> None:
        self.ids: set[str] = set()
        self.refs: dict[str, str] = {}
        self.kinds: dict[str, str] = {}
        self.labels: dict[str, str] = {}
        self.ids_by_kind: dict[str, set[str]] = {}


def _readable_objects(session: Session, access: ReadAccess) -> _ReadableCatalog:
    """Load only the currently DETAIL-visible catalog rows.

    The visibility decision comes from the already-built policy snapshot
    (``authorized_ids(READ)``), never from a full-catalog scan. Only the rows
    for those ids are loaded, so the feed stays bounded by the authorized set
    instead of the whole catalog.
    """
    readable_ids = access.policy.authorized_ids(Permission.READ)
    readable = _ReadableCatalog()
    if not readable_ids:
        return readable
    rows = list(
        session.scalars(
            select(CatalogObject).where(CatalogObject.id.in_(readable_ids))
        ).all()
    )
    for row in rows:
        readable.ids.add(row.id)
        readable.refs[row.id] = f"{row.kind}:{row.id}"
        readable.kinds[row.id] = row.kind
        readable.labels[row.id] = row.label
        readable.ids_by_kind.setdefault(row.kind, set()).add(row.id)
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
    readable: _ReadableCatalog,
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
    if parent not in readable.ids:
        return set()
    parent_ref = readable.refs[parent]
    readable_refs = list(readable.refs.values())
    statement = text(
        """
        WITH RECURSIVE subtree(ref, depth) AS (
            SELECT :parent_ref, 0
            UNION
            SELECT r.to_ref, s.depth + 1
            FROM relationships r
            JOIN subtree s ON r.from_ref = s.ref
            WHERE r.relation_type = :rel_type
              AND r.to_ref IN :readable_refs
              AND s.depth < :max_depth
        )
        SELECT ref FROM subtree
        """
    ).bindparams(bindparam("readable_refs", expanding=True))
    refs = session.execute(
        statement,
        {
            "parent_ref": parent_ref,
            "rel_type": CANONICAL_PLACEMENT_RELATION_TYPE,
            "readable_refs": readable_refs,
            "max_depth": ACTIVITY_MAX_SUBTREE_DEPTH,
        },
    ).scalars().all()
    return {ref.split(":", 1)[1] for ref in refs}


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
