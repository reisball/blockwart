"""The authorized, read-only "needs attention" application resolver.

This module is the single source of truth behind the HTML view, REST v1, and
MCP. It is FastAPI-independent: it receives a session plus one immutable
principal/policy snapshot and returns one summary and one keyset page derived
from exactly the same filtered item set.

It is strictly a read. It runs no probe, opens no source file, contacts no
network, claims no lease, and writes no catalog, audit, comment, coverage, or
observation row. Every input is a canonical projection another reviewed module
already owns:

- the catalog read model and its record-integrity/placement diagnostics;
- the provider-neutral monitoring projection from #135;
- the authorized source-coverage resolver from #174.

Authorization happens before items, counts, ordering, and cursor binding.
Discover-only stubs are dropped before any signal is derived, so a detail-only
fact can never become a discover-only hint.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from blockwart.domain.attention import (
    ATTENTION_CATEGORIES,
    ATTENTION_REASONS,
    ATTENTION_SEVERITIES,
    AttentionCoverageInput,
    AttentionItem,
    AttentionObjectInput,
    AttentionRelationshipDiagnosticInput,
    AttentionSummary,
    build_attention_derivation,
    summarize_attention,
)
from blockwart.domain.auth import ObjectVisibility, Permission
from blockwart.domain.references import TypedReference
from blockwart.domain.relationships import diagnose_relationship_integrity
from blockwart.domain.search import SEARCH_LIMIT_MAX, SEARCH_LIMIT_MIN
from blockwart.domain.timestamps import format_rfc3339_utc
from blockwart.models import CatalogObject, Relationship
from blockwart.schemas.catalog import ObjectKind
from blockwart.services.catalog import catalog_objects_from_snapshot
from blockwart.services.pagination import SortDirection, paginate_items
from blockwart.services.queries import build_monitoring_index, project_catalog_objects
from blockwart.services.read_access import ReadAccess
from blockwart.services.record_integrity import read_catalog_record_data
from blockwart.services.source_coverage import resolve_authorized_coverage

ATTENTION_RESOURCE = "attention"
ATTENTION_SORT_FIELD = "priority"

# The item signal states a caller may filter on. `not_applicable` describes a
# whole category in the summary and can never belong to an item, so accepting it
# as an item filter would only ever return an empty page.
ATTENTION_ITEM_SIGNAL_STATES = frozenset({"current", "stale", "unknown"})

__all__ = [
    "ATTENTION_ITEM_SIGNAL_STATES",
    "ATTENTION_RESOURCE",
    "ATTENTION_SORT_FIELD",
    "AttentionPage",
    "AttentionQueryError",
    "query_attention_page",
]


class AttentionQueryError(ValueError):
    """The attention request left the closed vocabulary or its bounds."""


@dataclass(frozen=True, slots=True)
class AttentionPage:
    summary: AttentionSummary
    items: list[AttentionItem]
    next_cursor: str | None
    total: int | None
    generated_at: str


def query_attention_page(
    session: Session,
    access: ReadAccess,
    *,
    category: str | None = None,
    severity: str | None = None,
    reason_code: str | None = None,
    signal_state: str | None = None,
    kind: str | None = None,
    limit: int = 50,
    cursor: str | None = None,
    direction: SortDirection = "asc",
    include_total: bool = False,
    now: datetime | None = None,
) -> AttentionPage:
    """Return one authorized attention page plus its matching summary.

    The summary aggregates exactly the authorized, filtered item set the pages
    enumerate, so ``summary.total`` always equals the number of items a caller
    can page through.
    """
    if limit < SEARCH_LIMIT_MIN or limit > SEARCH_LIMIT_MAX:
        raise AttentionQueryError("attention limit must be between 1 and 100")
    if direction not in {"asc", "desc"}:
        raise AttentionQueryError("unknown attention ordering")
    if category is not None and category not in ATTENTION_CATEGORIES:
        raise AttentionQueryError("unknown attention category")
    if severity is not None and severity not in ATTENTION_SEVERITIES:
        raise AttentionQueryError("unknown attention severity")
    if reason_code is not None and reason_code not in ATTENTION_REASONS:
        raise AttentionQueryError("unknown attention reason code")
    if signal_state is not None and signal_state not in ATTENTION_ITEM_SIGNAL_STATES:
        raise AttentionQueryError("unknown attention signal state")
    if kind is not None and kind not in _OBJECT_KINDS:
        raise AttentionQueryError("unknown object kind")

    reference = _aware(now) if now is not None else datetime.now(UTC)
    signals = _load_signals(session, access, now=reference)
    scoped_objects = (
        signals.objects
        if kind is None
        else tuple(item for item in signals.objects if item.kind == kind)
    )
    scoped_ids = {item.object_id for item in scoped_objects}
    scoped_coverage = tuple(
        row for row in signals.coverage if row.object_id in scoped_ids
    )
    derivation = build_attention_derivation(
        objects=scoped_objects,
        coverage=scoped_coverage,
        coverage_collected=bool(scoped_coverage),
        now=reference,
        relationship_diagnostics=tuple(
            diagnostic
            for diagnostic in signals.relationship_diagnostics
            if diagnostic.object_id in scoped_ids
        ),
    )
    filtered = [
        item
        for item in derivation.items
        if _matches_filters(
            item,
            category=category,
            severity=severity,
            reason_code=reason_code,
            signal_state=signal_state,
            kind=kind,
        )
    ]
    authorized_digest = _attention_view_digest(filtered)
    page = paginate_items(
        filtered,
        key=lambda item: item.key,
        limit=limit,
        resource=ATTENTION_RESOURCE,
        sort=ATTENTION_SORT_FIELD,
        direction=direction,
        query={
            "access": access.cursor_scope,
            "authorized_view": authorized_digest,
            "category": category or "",
            "kind": kind or "",
            "limit": limit,
            "reason_code": reason_code or "",
            "severity": severity or "",
            "signal_state": signal_state or "",
        },
        cursor=cursor,
        include_total=include_total,
    )
    return AttentionPage(
        summary=summarize_attention(filtered, derivation),
        items=page.items,
        next_cursor=page.next_cursor,
        total=page.total,
        generated_at=format_rfc3339_utc(reference) or "",
    )


def _matches_filters(
    item: AttentionItem,
    *,
    category: str | None,
    severity: str | None,
    reason_code: str | None,
    signal_state: str | None,
    kind: str | None,
) -> bool:
    if category is not None and item.category != category:
        return False
    if severity is not None and item.severity != severity:
        return False
    if reason_code is not None and item.reason_code != reason_code:
        return False
    if signal_state is not None and item.signal_state != signal_state:
        return False
    if kind is not None and item.target.kind != kind:
        return False
    return True


@dataclass(frozen=True, slots=True)
class _AttentionSignals:
    objects: tuple[AttentionObjectInput, ...]
    coverage: tuple[AttentionCoverageInput, ...]
    relationship_diagnostics: tuple[AttentionRelationshipDiagnosticInput, ...]


def _load_signals(
    session: Session,
    access: ReadAccess,
    *,
    now: datetime,
) -> _AttentionSignals:
    """Load every canonical signal in a bounded, constant number of reads.

    The catalog rows, the observation index, and the coverage snapshot are each
    loaded once for the whole request. Database access therefore does not grow
    per readable object, and a concealed object performs the same work as an
    absent one: the visibility decision is applied to already loaded rows.
    """
    catalog_rows = list(
        session.scalars(
            select(CatalogObject).order_by(CatalogObject.kind, CatalogObject.label)
        ).all()
    )
    relationship_rows = list(
        session.scalars(
            select(Relationship).order_by(
                Relationship.id,
                Relationship.from_ref,
                Relationship.relation_type,
                Relationship.to_ref,
            )
        ).all()
    )
    canonical = catalog_objects_from_snapshot(
        catalog_rows,
        all_objects=catalog_rows,
        relationships=relationship_rows,
    )
    projected = project_catalog_objects(canonical, access)
    readable_ids = {
        catalog_object.id
        for catalog_object in projected
        if catalog_object.visibility == ObjectVisibility.DETAIL
    }
    # Preserve #135's controlled malformed-configuration projection even when
    # the broader catalog record is schema-invalid. Raw documents are never
    # returned: only readable ids are considered and the monitoring resolver
    # emits a closed, redacted diagnostic.
    raw_data_by_id = {
        row.id: read_catalog_record_data(
            row,
            retain_schema_invalid_data=True,
        ).data
        for row in catalog_rows
        if row.id in readable_ids
    }
    monitoring_index = build_monitoring_index(
        session,
        projected,
        now=now,
        data_by_id=raw_data_by_id,
    )
    # The canonical placement state is read from the stored row, never from the
    # authorized projection: a concealed parent downgrades the projected state
    # to `unknown`, and reporting that would let concealment change an
    # observable response property.
    placement_by_id = {
        catalog_object.id: catalog_object.placement_state
        for catalog_object in canonical
    }
    suitable_services = _suitable_runbook_service_ids(
        canonical,
        raw_data_by_id=raw_data_by_id,
        relationships=relationship_rows,
        readable_ids=readable_ids,
    )
    objects = tuple(
        _object_input(
            catalog_object,
            placement_state=placement_by_id.get(catalog_object.id),
            monitoring=monitoring_index.get(catalog_object.id),
            has_suitable_runbook=catalog_object.id in suitable_services,
        )
        for catalog_object in projected
        if catalog_object.visibility == ObjectVisibility.DETAIL
    )
    coverage = resolve_authorized_coverage(session, access)
    coverage_rows = tuple(
        AttentionCoverageInput(
            object_id=mapping.object_id,
            state=detail.state,
            observed_at=detail.observed_at,
        )
        for detail in coverage.details
        for mapping in detail.mappings
        if mapping.exists
    )
    return _AttentionSignals(
        objects=objects,
        coverage=coverage_rows,
        relationship_diagnostics=_relationship_diagnostic_inputs(
            canonical,
            catalog_rows=catalog_rows,
            relationships=relationship_rows,
            access=access,
            readable_ids=readable_ids,
        ),
    )


def _object_input(
    catalog_object: Any,
    *,
    placement_state: str | None,
    monitoring: dict[str, Any] | None,
    has_suitable_runbook: bool,
) -> AttentionObjectInput:
    provenance = catalog_object.provenance
    return AttentionObjectInput(
        object_id=catalog_object.id,
        kind=catalog_object.kind,
        label=catalog_object.label,
        lifecycle=catalog_object.lifecycle,
        health=catalog_object.health,
        record_state=catalog_object.record_state,
        placement_state=placement_state,
        provenance_source_type=provenance.source_type,
        provenance_observed_at=provenance.observed_at,
        provenance_verified_at=provenance.verified_at,
        provenance_stale_after=provenance.stale_after,
        data=catalog_object.data,
        monitoring=monitoring,
        has_suitable_runbook=has_suitable_runbook,
    )


def _suitable_runbook_service_ids(
    canonical: list[Any],
    *,
    raw_data_by_id: dict[str, dict[str, Any]],
    relationships: list[Relationship],
    readable_ids: set[str],
) -> frozenset[str]:
    """Resolve authorized approved/active Runbooks applicable to services."""
    by_id = {item.id: item for item in canonical}
    suitable_runbooks = {
        item.id
        for item in canonical
        if item.id in readable_ids
        and item.kind == "runbook"
        and item.record_state == "valid"
        and item.data.get("runbook_status") in {"approved", "active"}
    }
    service_ids: set[str] = set()
    for runbook_id in suitable_runbooks:
        applies_to = raw_data_by_id.get(runbook_id, {}).get("applies_to")
        if not isinstance(applies_to, list):
            continue
        for value in applies_to:
            reference = _typed_reference(value)
            if (
                reference is not None
                and reference.kind == "service"
                and reference.object_id in readable_ids
                and reference.object_id in by_id
                and by_id[reference.object_id].kind == "service"
            ):
                service_ids.add(reference.object_id)
    for relationship in relationships:
        if relationship.relation_type != "documents":
            continue
        source = _typed_reference(relationship.from_ref)
        target = _typed_reference(relationship.to_ref)
        if (
            source is not None
            and target is not None
            and source.kind == "runbook"
            and target.kind == "service"
            and source.object_id in suitable_runbooks
            and target.object_id in readable_ids
            and target.object_id in by_id
            and by_id[target.object_id].kind == "service"
        ):
            service_ids.add(target.object_id)
    return frozenset(service_ids)


_CONCEALED_REFERENCE = object()


def _project_diagnostic_value(value: Any, readable_ids: frozenset[str]) -> Any:
    """Remove typed references outside READ scope before canonical diagnosis."""
    if isinstance(value, str):
        reference = _typed_reference(value)
        if reference is not None and reference.object_id not in readable_ids:
            return _CONCEALED_REFERENCE
        return value
    if isinstance(value, list):
        projected = (
            _project_diagnostic_value(item, readable_ids)
            for item in value
        )
        return [item for item in projected if item is not _CONCEALED_REFERENCE]
    if isinstance(value, dict):
        projected = {
            key: _project_diagnostic_value(item, readable_ids)
            for key, item in value.items()
        }
        return {
            key: item
            for key, item in projected.items()
            if item is not _CONCEALED_REFERENCE
        }
    return value


def _relationship_diagnostic_inputs(
    canonical: list[Any],
    *,
    catalog_rows: list[CatalogObject],
    relationships: list[Relationship],
    access: ReadAccess,
    readable_ids: set[str],
) -> tuple[AttentionRelationshipDiagnosticInput, ...]:
    """Project canonical diagnostics onto authorized, target-bound facts only."""
    authorized_ids = access.policy.authorized_ids(Permission.READ)
    valid_ids = {
        item.id
        for item in canonical
        if item.id in readable_ids and item.record_state == "valid"
    }
    projected_objects: list[dict[str, str]] = []
    for row in catalog_rows:
        if row.id not in valid_ids:
            continue
        try:
            data = json.loads(row.data_json)
        except (TypeError, json.JSONDecodeError):
            continue
        if not isinstance(data, dict):
            continue
        projected_objects.append(
            {
                "id": row.id,
                "kind": row.kind,
                "data_json": json.dumps(
                    _project_diagnostic_value(data, authorized_ids),
                    ensure_ascii=True,
                    separators=(",", ":"),
                    sort_keys=True,
                ),
            }
        )
    projected_relationships = [
        row
        for row in relationships
        if _relationship_is_authorized(row, authorized_ids)
    ]
    inputs: set[tuple[str, str, str | None]] = set()
    for diagnostic in diagnose_relationship_integrity(
        projected_objects,
        projected_relationships,
    ):
        object_id = next(
            (
                reference.object_id
                for value in diagnostic.object_refs
                if (reference := _typed_reference(value)) is not None
                and reference.object_id in valid_ids
            ),
            None,
        )
        if object_id is not None:
            inputs.add((object_id, diagnostic.code, diagnostic.relation_type))
    return tuple(
        AttentionRelationshipDiagnosticInput(
            object_id=object_id,
            code=code,
            relation_type=relation_type,
        )
        for object_id, code, relation_type in sorted(
            inputs,
            key=lambda item: (item[0], item[1], item[2] or ""),
        )
    )


def _relationship_is_authorized(
    relationship: Relationship,
    authorized_ids: frozenset[str],
) -> bool:
    source = _typed_reference(relationship.from_ref)
    target = _typed_reference(relationship.to_ref)
    return (
        source is not None
        and target is not None
        and source.object_id in authorized_ids
        and target.object_id in authorized_ids
    )


def _typed_reference(value: Any) -> TypedReference | None:
    if not isinstance(value, str):
        return None
    try:
        return TypedReference.parse(value)
    except ValueError:
        return None


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


def _attention_view_digest(items: list[AttentionItem]) -> str:
    """Bind cursors to exactly the authorized filtered projection.

    A correction that adds, removes, reclassifies, or visibly renames an item
    invalidates an older cursor instead of letting it skip across two derived
    states. Concealed facts are absent before this digest is calculated.
    """
    payload = [
        {
            "category": item.category,
            "description": item.description,
            "detail_code": item.detail_code,
            "observed_at": item.observed_at,
            "reason_code": item.reason_code,
            "severity": item.severity,
            "signal_state": item.signal_state,
            "target": {
                "detail_path": item.target.detail_path,
                "kind": item.target.kind,
                "label": item.target.label,
                "object_id": item.target.object_id,
                "ref": item.target.ref,
                "scope": item.target.scope,
            },
        }
        for item in items
    ]
    serialized = json.dumps(
        payload,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    )
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


_OBJECT_KINDS: frozenset[str] = frozenset(ObjectKind.__args__)
