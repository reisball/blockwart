from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from blockwart.domain.placement import (
    CANONICAL_PLACEMENT_RELATION_TYPE,
    PlacementError,
    PlacementGraph,
    is_explicitly_unassigned,
    validate_placement_metadata,
)
from blockwart.domain.relationships import diagnose_relationship_integrity
from blockwart.models import CatalogObject, Relationship
from blockwart.services.audit import add_audit_event

DEFAULT_UNASSIGNED_REASON = "No canonical placement parent has been assigned."


class PlacementMigrationError(RuntimeError):
    pass


@dataclass(frozen=True, order=True)
class PlacementStateDiagnostic:
    code: str
    location: str
    message: str


@dataclass(frozen=True)
class PlacementObjectChange:
    object_id: str
    kind: str
    before: dict[str, Any]
    after: dict[str, Any]
    parent_ref: str | None
    action: str


@dataclass(frozen=True)
class PlacementMigrationPlan:
    scanned_assets: int
    changes: tuple[PlacementObjectChange, ...]
    assigned_refs: tuple[str, ...]
    unassigned_refs: tuple[str, ...]
    diagnostics: tuple[PlacementStateDiagnostic, ...]

    @property
    def changed_objects(self) -> int:
        return len(self.changes)


def build_placement_migration_plan(session: Session) -> PlacementMigrationPlan:
    rows = list(
        session.scalars(
            select(CatalogObject).order_by(CatalogObject.kind, CatalogObject.id)
        ).all()
    )
    relationships = list(
        session.scalars(
            select(Relationship).order_by(
                Relationship.id,
                Relationship.from_ref,
                Relationship.to_ref,
            )
        ).all()
    )
    graph = PlacementGraph(rows, relationships)
    diagnostics = [
        PlacementStateDiagnostic(item.code, item.location, item.message)
        for item in diagnose_relationship_integrity(rows, relationships)
    ]
    changes: list[PlacementObjectChange] = []
    assigned_refs: list[str] = []
    unassigned_refs: list[str] = []
    scanned_assets = 0

    for row in rows:
        if row.kind not in {"system", "service"}:
            continue
        scanned_assets += 1
        object_ref = f"{row.kind}:{row.id}"
        before = _object_data(row)
        try:
            validate_placement_metadata(before, kind=row.kind)
        except ValueError as exc:
            diagnostics.append(
                PlacementStateDiagnostic(
                    "invalid_placement_metadata",
                    f"catalog_objects[{row.id}].data.placement",
                    str(exc),
                )
            )
            continue
        try:
            parent_ref = graph.parent_ref(object_ref)
        except PlacementError as exc:
            diagnostics.append(
                PlacementStateDiagnostic(
                    "multiple_placement_parents",
                    f"catalog_objects[{row.id}]",
                    str(exc),
                )
            )
            continue

        if parent_ref is None:
            unassigned_refs.append(object_ref)
            if is_explicitly_unassigned(before):
                continue
            after = {
                **before,
                "placement": {
                    "state": "unassigned",
                    "reason": DEFAULT_UNASSIGNED_REASON,
                },
            }
            changes.append(
                PlacementObjectChange(
                    object_id=row.id,
                    kind=row.kind,
                    before=before,
                    after=after,
                    parent_ref=None,
                    action="mark_unassigned",
                )
            )
            continue

        assigned_refs.append(object_ref)
        if not is_explicitly_unassigned(before):
            continue
        after = dict(before)
        after.pop("placement", None)
        changes.append(
            PlacementObjectChange(
                object_id=row.id,
                kind=row.kind,
                before=before,
                after=after,
                parent_ref=parent_ref,
                action="clear_unassigned",
            )
        )

    return PlacementMigrationPlan(
        scanned_assets=scanned_assets,
        changes=tuple(changes),
        assigned_refs=tuple(sorted(assigned_refs)),
        unassigned_refs=tuple(sorted(unassigned_refs)),
        diagnostics=tuple(sorted(set(diagnostics))),
    )


def apply_placement_migration_plan(
    session: Session,
    plan: PlacementMigrationPlan,
) -> int:
    if plan.diagnostics:
        raise PlacementMigrationError(
            "placement plan contains integrity diagnostics"
        )
    current_parent_refs = _parent_refs_by_child(session)
    changed_at = datetime.now(UTC).replace(tzinfo=None)
    for change in plan.changes:
        row = session.get(CatalogObject, change.object_id)
        if row is None:
            raise PlacementMigrationError(
                f"catalog object {change.object_id} disappeared after planning"
            )
        current = _object_data(row)
        object_ref = f"{row.kind}:{row.id}"
        parents = current_parent_refs.get(object_ref, ())
        current_parent_ref = parents[0] if len(parents) == 1 else None
        if (
            row.kind != change.kind
            or current != change.before
            or current_parent_ref != change.parent_ref
            or len(parents) > 1
        ):
            raise PlacementMigrationError(
                f"catalog object {change.object_id} changed after planning"
            )
        row.data_json = json.dumps(
            change.after,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        row.revision += 1
        row.updated_at = changed_at
        add_audit_event(
            session,
            object_id=row.id,
            action="placement_state_normalize",
            actor="placement-migration",
            details={
                "object_ref": object_ref,
                "operation": change.action,
            },
        )
    session.flush()
    return len(plan.changes)


def _object_data(row: CatalogObject) -> dict[str, Any]:
    try:
        data = json.loads(row.data_json)
    except (TypeError, json.JSONDecodeError) as exc:
        raise PlacementMigrationError(
            f"catalog object {row.id} has invalid data_json"
        ) from exc
    if not isinstance(data, dict):
        raise PlacementMigrationError(
            f"catalog object {row.id} data_json is not an object"
        )
    return data


def _parent_refs_by_child(session: Session) -> dict[str, tuple[str, ...]]:
    values: dict[str, set[str]] = {}
    rows = session.scalars(
        select(Relationship).where(
            Relationship.relation_type == CANONICAL_PLACEMENT_RELATION_TYPE
        )
    ).all()
    for row in rows:
        values.setdefault(row.to_ref, set()).add(row.from_ref)
    return {
        child_ref: tuple(sorted(parent_refs))
        for child_ref, parent_refs in values.items()
    }
