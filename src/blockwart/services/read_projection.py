"""Apply one resolved read projection to already authorized agent read models.

Every projection here is a pure, authorization-free transformation of a read
model the resolver already produced. Authorization, concealment, search,
ordering, cursors, ETags, and monitoring resolution happen before this module
runs and are never repeated, re-decided, or relaxed by it. A projected read can
therefore only ever be a subset of the same authorized read, which is what
makes the compact and full contracts agree on identity, revision, visibility,
and effective permissions by construction.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from typing import Any

from blockwart.domain.auth import Permission
from blockwart.domain.read_projection import (
    ReadProjection,
    capability_set_key,
)
from blockwart.schemas.agent import (
    AgentCatalogConcealed,
    AgentCatalogObjectContext,
    AgentCatalogObjectStub,
    AgentCatalogObjectSummary,
    AgentProjectedObject,
    AgentProjectedStub,
)

# The canonical short fields of each knowledge kind. A projected read publishes
# exactly the block of its own kind, so a Runbook never carries empty Decision
# or Project fields and an asset kind carries no knowledge block at all.
KNOWLEDGE_FIELDS: dict[str, tuple[str, ...]] = {
    "decision": ("decision_status", "applies_to"),
    "project": ("project_category", "project_status", "related_assets"),
    "runbook": ("runbook_status", "runbook_risk", "runbook_applies_to"),
}
_NETWORK_SUMMARY_FIELDS: tuple[str, ...] = ("ips", "hostnames", "primary_endpoint")
_DETAIL_FIELDS: tuple[str, ...] = (
    "etag",
    "data",
    "relationships",
    "source_references",
    "updated_at",
    "dependencies",
    "credential_references",
)
_ACTIVITY_FIELDS: tuple[str, ...] = ("recent_comments", "recent_project_chronology")

ProjectedItem = AgentProjectedObject | AgentProjectedStub | AgentCatalogConcealed
FullItem = AgentCatalogObjectSummary | AgentCatalogObjectStub | AgentCatalogConcealed


@dataclass(slots=True)
class CapabilitySets:
    """The response-level table of every distinct effective permission set.

    Deduplication is by exact permission set: two objects share a key only when
    their effective rights are identical, so a page can never merge a
    discover-only and a fully writable object onto one capability block.
    """

    _keys: dict[str, list[Permission]] = field(default_factory=dict)

    def key_for(self, permissions: Iterable[Permission]) -> str:
        materialized = list(permissions)
        key = capability_set_key(materialized)
        self._keys.setdefault(key, materialized)
        return key

    def table(self) -> dict[str, list[Permission]]:
        return {key: self._keys[key] for key in sorted(self._keys)}


def project_read_items(
    items: Sequence[FullItem],
    *,
    projection: ReadProjection,
    capability_sets: CapabilitySets,
) -> list[ProjectedItem]:
    """Project one already authorized, already ordered page of read items."""
    return [
        project_read_item(item, projection=projection, capability_sets=capability_sets)
        for item in items
    ]


def project_read_item(
    item: FullItem,
    *,
    projection: ReadProjection,
    capability_sets: CapabilitySets,
) -> ProjectedItem:
    """Project exactly one already authorized read item.

    A concealed placeholder is returned unchanged. It carries only the
    requested id under every profile and every field mask, so a concealed id
    and a missing id stay indistinguishable from each other and from what they
    look like in the full contract.
    """
    if isinstance(item, AgentCatalogConcealed):
        return item
    if isinstance(item, AgentCatalogObjectStub):
        return _project_stub(item, projection=projection, capability_sets=capability_sets)
    return _project_object(item, projection=projection, capability_sets=capability_sets)


def _project_stub(
    stub: AgentCatalogObjectStub,
    *,
    projection: ReadProjection,
    capability_sets: CapabilitySets,
) -> AgentProjectedStub:
    projected: dict[str, Any] = {
        "visibility": "stub",
        "ref": stub.ref,
        "id": stub.id,
        "kind": stub.kind,
        "label": stub.label,
        "capability_set": capability_sets.key_for(stub.capabilities),
    }
    if stub.parent is not None:
        projected["parent_ref"] = stub.parent.ref
    if stub.placement_state is not None:
        projected["placement_state"] = stub.placement_state
    if projection.includes("detail") and stub.parent_path:
        projected["parent_path_refs"] = [node.ref for node in stub.parent_path]
    return AgentProjectedStub(**projected)


def _project_object(
    summary: AgentCatalogObjectSummary,
    *,
    projection: ReadProjection,
    capability_sets: CapabilitySets,
) -> AgentProjectedObject:
    projected: dict[str, Any] = {
        "visibility": "detail",
        "ref": summary.ref,
        "id": summary.id,
        "kind": summary.kind,
        "label": summary.label,
        "status": summary.status,
        "revision": summary.revision,
        "capability_set": capability_sets.key_for(summary.capabilities),
    }
    if summary.parent is not None:
        projected["parent_ref"] = summary.parent.ref
    for name in ("lifecycle", "health", "placement_state"):
        _copy_present(projected, summary, name)

    if projection.includes("knowledge"):
        for name in KNOWLEDGE_FIELDS.get(summary.kind, ()):
            _copy_present(projected, summary, name)
    if projection.includes("orientation"):
        _copy_orientation(projected, summary)
    if projection.includes("network"):
        for name in _NETWORK_SUMMARY_FIELDS:
            _copy_present(projected, summary, name)
    if projection.includes("integrity"):
        projected["record_state"] = summary.record_state
        _copy_present(projected, summary, "diagnostics")
        projected["provenance"] = summary.provenance
    if projection.includes("monitoring"):
        _copy_present(projected, summary, "monitoring")

    if isinstance(summary, AgentCatalogObjectContext):
        _project_context_sections(projected, summary, projection=projection)
    return AgentProjectedObject(**projected)


def _project_context_sections(
    projected: dict[str, Any],
    context: AgentCatalogObjectContext,
    *,
    projection: ReadProjection,
) -> None:
    if projection.includes("network"):
        _copy_present(projected, context, "endpoints")
    if projection.includes("detail"):
        for name in _DETAIL_FIELDS:
            _copy_present(projected, context, name)
        if context.parent_path:
            projected["parent_path_refs"] = [node.ref for node in context.parent_path]
        if context.children:
            projected["children_refs"] = [node.ref for node in context.children]
    if projection.includes("activity"):
        for name in _ACTIVITY_FIELDS:
            _copy_present(projected, context, name)


def _copy_orientation(projected: dict[str, Any], summary: AgentCatalogObjectSummary) -> None:
    """Publish the orientation line once instead of twice.

    `search_snippet` is derived from `summary` and is usually the same text. A
    projected read publishes the canonical `summary` and adds the snippet only
    when it actually differs, which it does when there is no summary or when
    the snippet had to be truncated. No orientation text is lost either way.
    """
    _copy_present(projected, summary, "summary")
    if summary.search_snippet and summary.search_snippet != summary.summary:
        projected["search_snippet"] = summary.search_snippet


def _copy_present(projected: dict[str, Any], source: Any, name: str) -> None:
    """Copy one field unless it carries nothing.

    An empty value is dropped rather than serialized, because in a projected
    read an absent key already means "no value" and a null or empty container
    would only cost context without carrying a decision.
    """
    value = getattr(source, name)
    if value is None or value == [] or value == {}:
        return
    projected[name] = value
