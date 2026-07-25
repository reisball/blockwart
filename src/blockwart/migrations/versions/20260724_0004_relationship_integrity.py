"""centralize relationship vocabulary and referential integrity

Revision ID: 20260724_0004
Revises: 20260724_0003
"""

from __future__ import annotations

import json
from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from typing import Any

import sqlalchemy as sa
from alembic import op

revision: str = "20260724_0004"
down_revision: str | Sequence[str] | None = "20260724_0003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

VALID_KINDS = {
    "host",
    "system",
    "netzwerk",
    "service",
    "credential_reference",
    "runbook",
    "decision",
    "project",
}
ASSET_KINDS = {"host", "system", "netzwerk", "service"}
RELATIONSHIP_RULES = {
    "hosts": {
        ("host", "system"),
        ("host", "service"),
        ("system", "service"),
    },
    "depends_on": {(source, target) for source in ASSET_KINDS for target in ASSET_KINDS},
    "supports": {("service", "service")},
    "feeds": {("service", "service")},
    "exposes": {("service", "service")},
    "documents": {
        (source, target)
        for source in {"runbook", "decision", "project"}
        for target in VALID_KINDS
    },
    "uses": {(source, target) for source in VALID_KINDS for target in VALID_KINDS},
    "related_to": {(source, target) for source in VALID_KINDS for target in VALID_KINDS},
}
KNOWN_TYPE_SQL = (
    "relation_type IN "
    "('hosts','depends_on','supports','feeds','exposes','documents','uses','related_to')"
)


def upgrade() -> None:
    bind = op.get_bind()
    object_rows = list(
        bind.execute(
            sa.text("SELECT id, kind, data_json FROM catalog_objects ORDER BY id")
        ).mappings()
    )
    relationship_rows = list(
        bind.execute(
            sa.text(
                "SELECT id, from_ref, relation_type, to_ref "
                "FROM relationships ORDER BY id"
            )
        ).mappings()
    )
    object_kinds = {str(row["id"]): str(row["kind"]) for row in object_rows}

    existing_triplets = _validate_relationships(relationship_rows, object_kinds)
    dependency_triplets: set[tuple[str, str, str]] = set()
    dependency_object_ids: list[str] = []
    for row in object_rows:
        object_id = str(row["id"])
        kind = str(row["kind"])
        try:
            data = json.loads(str(row["data_json"]))
        except (TypeError, json.JSONDecodeError) as exc:
            raise RuntimeError(
                f"invalid data_json for catalog object {object_id}"
            ) from exc
        if not isinstance(data, dict):
            raise RuntimeError(f"data_json is not an object for catalog object {object_id}")
        _validate_data_references(data, object_kinds, object_id)
        if "dependencies" not in data:
            continue
        dependency_object_ids.append(object_id)
        dependency_triplets.update(
            _dependency_triplets(
                owner_ref=f"{kind}:{object_id}",
                data=data,
                object_kinds=object_kinds,
            )
        )

    final_triplets = [*existing_triplets, *sorted(dependency_triplets - set(existing_triplets))]
    _validate_triplet_collection(final_triplets)

    for object_id in dependency_object_ids:
        bind.execute(
            sa.text(
                "UPDATE catalog_objects "
                "SET data_json = json_remove(data_json, '$.dependencies') "
                "WHERE id = :object_id"
            ),
            {"object_id": object_id},
        )
    for from_ref, relation_type, to_ref in sorted(
        dependency_triplets - set(existing_triplets)
    ):
        bind.execute(
            sa.text(
                "INSERT INTO relationships (from_ref, relation_type, to_ref) "
                "VALUES (:from_ref, :relation_type, :to_ref)"
            ),
            {
                "from_ref": from_ref,
                "relation_type": relation_type,
                "to_ref": to_ref,
            },
        )

    with op.batch_alter_table("relationships", recreate="always") as batch_op:
        batch_op.create_unique_constraint(
            "uq_relationships_triplet",
            ["from_ref", "relation_type", "to_ref"],
        )
        batch_op.create_check_constraint(
            "ck_relationships_no_self_reference",
            "from_ref <> to_ref",
        )
        batch_op.create_check_constraint(
            "ck_relationships_known_type",
            KNOWN_TYPE_SQL,
        )
    op.create_index(
        "uq_relationships_placement_parent",
        "relationships",
        ["to_ref"],
        unique=True,
        sqlite_where=sa.text("relation_type = 'hosts'"),
    )


def downgrade() -> None:
    raise RuntimeError(
        "automatic downgrade is not supported; restore the paired pre-upgrade backup"
    )


def _validate_relationships(
    rows: Iterable[Mapping[str, Any]],
    object_kinds: Mapping[str, str],
) -> list[tuple[str, str, str]]:
    triplets: list[tuple[str, str, str]] = []
    for row in rows:
        triplet = (
            str(row["from_ref"]),
            str(row["relation_type"]),
            str(row["to_ref"]),
        )
        _validate_triplet(triplet, object_kinds)
        triplets.append(triplet)
    _validate_triplet_collection(triplets)
    return triplets


def _validate_triplet(
    triplet: tuple[str, str, str],
    object_kinds: Mapping[str, str],
) -> None:
    from_ref, relation_type, to_ref = triplet
    allowed_pairs = RELATIONSHIP_RULES.get(relation_type)
    if allowed_pairs is None:
        raise RuntimeError(f"unsupported relationship type: {relation_type}")
    source = _resolve_reference(from_ref, object_kinds)
    target = _resolve_reference(to_ref, object_kinds)
    if source[1] == target[1]:
        raise RuntimeError(f"self relationship is not allowed: {' '.join(triplet)}")
    if (source[0], target[0]) not in allowed_pairs:
        raise RuntimeError(f"invalid relationship direction: {' '.join(triplet)}")


def _validate_triplet_collection(
    triplets: Iterable[tuple[str, str, str]],
) -> None:
    triplet_list = list(triplets)
    duplicate = next(
        (triplet for triplet, count in Counter(triplet_list).items() if count > 1),
        None,
    )
    if duplicate is not None:
        raise RuntimeError(f"duplicate relationship: {' '.join(duplicate)}")
    placement_parents: dict[str, set[str]] = {}
    for from_ref, relation_type, to_ref in triplet_list:
        if relation_type == "hosts":
            placement_parents.setdefault(to_ref, set()).add(from_ref)
    conflict = next(
        (
            (child_ref, sorted(parent_refs))
            for child_ref, parent_refs in placement_parents.items()
            if len(parent_refs) > 1
        ),
        None,
    )
    if conflict is not None:
        child_ref, parent_refs = conflict
        raise RuntimeError(
            f"multiple placement parents for {child_ref}: {', '.join(parent_refs)}"
        )


def _validate_data_references(
    data: Mapping[str, Any],
    object_kinds: Mapping[str, str],
    object_id: str,
) -> None:
    for reference in _iter_typed_references(data):
        try:
            _resolve_reference(reference, object_kinds)
        except RuntimeError as exc:
            raise RuntimeError(
                f"invalid typed reference in catalog object {object_id}: {reference}"
            ) from exc


def _dependency_triplets(
    *,
    owner_ref: str,
    data: Mapping[str, Any],
    object_kinds: Mapping[str, str],
) -> set[tuple[str, str, str]]:
    dependencies = data["dependencies"]
    if not isinstance(dependencies, dict):
        raise RuntimeError(f"invalid data.dependencies for {owner_ref}")
    triplets: set[tuple[str, str, str]] = set()
    for side in ("upstream", "downstream"):
        references = dependencies.get(side, [])
        if not isinstance(references, list):
            raise RuntimeError(f"invalid data.dependencies.{side} for {owner_ref}")
        for reference in references:
            if not isinstance(reference, str):
                raise RuntimeError(
                    f"invalid data.dependencies.{side} entry for {owner_ref}"
                )
            triplet = (
                (owner_ref, "depends_on", reference)
                if side == "upstream"
                else (reference, "depends_on", owner_ref)
            )
            _validate_triplet(triplet, object_kinds)
            triplets.add(triplet)
    return triplets


def _resolve_reference(
    value: str,
    object_kinds: Mapping[str, str],
) -> tuple[str, str]:
    if ":" not in value:
        raise RuntimeError(f"typed reference must use kind:id: {value}")
    kind, object_id = value.split(":", 1)
    if kind not in VALID_KINDS or not object_id:
        raise RuntimeError(f"invalid typed reference: {value}")
    actual_kind = object_kinds.get(object_id)
    if actual_kind is None:
        raise RuntimeError(f"dangling typed reference: {value}")
    if actual_kind != kind:
        raise RuntimeError(
            f"typed reference kind mismatch: {value} points to {actual_kind}"
        )
    return kind, object_id


def _iter_typed_references(value: Any):
    if isinstance(value, dict):
        for child in value.values():
            yield from _iter_typed_references(child)
        return
    if isinstance(value, list):
        for child in value:
            yield from _iter_typed_references(child)
        return
    if not isinstance(value, str) or ":" not in value:
        return
    if value.split(":", 1)[0] in VALID_KINDS:
        yield value
