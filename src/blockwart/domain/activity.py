"""Closed vocabulary and envelope for the authorized activity feed (#188).

The activity feed is a read-only projection over audit events another reviewed
module already owns. It introduces no new catalog state: every event is one
classified, authorization-filtered view of an existing ``audit_events`` row.

The feed deliberately does not re-emit comment bodies, audit diffs, or project
chronology. Those stay canonical in their own resources (#131, #143, #184); an
activity item only carries a safe short description plus a detail path into the
existing resource that owns the type-specific details.

Additive observation/coverage event types from #135/#174 are intentionally not
implemented yet. The vocabulary below is closed so later additions are a
reviewed contract change, never an accidental pass-through.
"""

from __future__ import annotations

from dataclasses import dataclass

ACTIVITY_EVENT_TYPES: tuple[str, ...] = (
    "object_revision",
    "relationship_mutation",
    "comment_create",
    "audit",
)

# Audit actions that represent a catalog object revision (create/update/delete
# including seed application). They carry old/new revision details.
OBJECT_REVISION_AUDIT_ACTIONS = frozenset(
    {
        "create",
        "update",
        "delete",
        "seed_create",
        "seed_update",
    }
)

# Audit actions recorded for relationship mutations on the command path. Every
# command-path relationship mutation attributes its audit row to the readable
# target object, so the feed can authorize it per object.
RELATIONSHIP_MUTATION_AUDIT_ACTIONS = frozenset(
    {
        "relationship_create",
        "relationship_metadata_replace",
        "relationship_delete",
    }
)

# Comment creation is audited next to the immutable comment row itself.
COMMENT_CREATE_AUDIT_ACTIONS = frozenset({"comment_create"})


def classify_activity_event_type(action: str) -> str:
    """Map one audit action to the closed activity event-type vocabulary."""
    if action in COMMENT_CREATE_AUDIT_ACTIONS:
        return "comment_create"
    if action in RELATIONSHIP_MUTATION_AUDIT_ACTIONS:
        return "relationship_mutation"
    if action in OBJECT_REVISION_AUDIT_ACTIONS:
        return "object_revision"
    return "audit"


def activity_detail_path(event_type: str, object_id: str) -> str:
    """Return the canonical existing resource that owns the type details."""
    quoted = object_id
    if event_type == "comment_create":
        return f"/api/v1/objects/{quoted}/comments"
    return f"/api/v1/objects/{quoted}/audit-events"


@dataclass(frozen=True, slots=True)
class ActivityObject:
    """The authorized visible-object reference of one activity event."""

    ref: str
    object_id: str
    kind: str
    label: str | None


@dataclass(frozen=True, slots=True)
class ActivityItem:
    """One authorized envelope entry; no type-specific payload is included."""

    key: tuple[str, str]
    event_id: str
    event_type: str
    occurred_at: str
    object: ActivityObject
    summary: str
    actor: str | None
    detail_path: str


@dataclass(frozen=True, slots=True)
class ActivityPage:
    items: list[ActivityItem]
    next_cursor: str | None
    total: int | None
    generated_at: str
    truncated: bool = False


__all__ = [
    "ACTIVITY_EVENT_TYPES",
    "ActivityItem",
    "ActivityObject",
    "ActivityPage",
    "activity_detail_path",
    "classify_activity_event_type",
]
