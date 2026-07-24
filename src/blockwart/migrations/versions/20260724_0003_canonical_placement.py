"""make hosts relationships the canonical asset placement source

Revision ID: 20260724_0003
Revises: 20260723_0002
Create Date: 2026-07-24
"""

import json
from collections.abc import Sequence
from typing import Any

import sqlalchemy as sa
from alembic import op

revision: str = "20260724_0003"
down_revision: str | None = "20260723_0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_PLACEMENT_PAIRS = {
    ("host", "system"),
    ("host", "service"),
    ("system", "service"),
}


def upgrade() -> None:
    connection = op.get_bind()
    object_rows = list(
        connection.execute(
            sa.text(
                "SELECT id, kind, data_json "
                "FROM catalog_objects ORDER BY id"
            )
        ).mappings()
    )
    objects_by_ref = {
        f"{row['kind']}:{row['id']}": row
        for row in object_rows
    }
    relationship_rows = list(
        connection.execute(
            sa.text(
                "SELECT id, from_ref, relation_type, to_ref "
                "FROM relationships ORDER BY id"
            )
        ).mappings()
    )

    parents_by_child: dict[str, set[str]] = {}
    for row in relationship_rows:
        relation_type = str(row["relation_type"])
        if relation_type not in {"hosts", "provides"}:
            continue
        parent_ref = str(row["from_ref"])
        child_ref = str(row["to_ref"])
        _validate_stored_placement(
            objects_by_ref,
            parent_ref=parent_ref,
            child_ref=child_ref,
            legacy_provides=relation_type == "provides",
        )
        parents_by_child.setdefault(child_ref, set()).add(parent_ref)

    service_data_by_ref: dict[str, dict[str, Any]] = {}
    for row in object_rows:
        if row["kind"] != "service":
            continue
        service_ref = f"service:{row['id']}"
        data = _load_object_data(str(row["data_json"]), service_ref)
        system_ref = data.get("system_id")
        if system_ref is None:
            continue
        if not isinstance(system_ref, str):
            raise RuntimeError(
                f"canonical placement migration rejected non-text system_id for {service_ref}"
            )
        parent = objects_by_ref.get(system_ref)
        if parent is None or parent["kind"] != "system":
            raise RuntimeError(
                f"canonical placement migration rejected missing system parent for {service_ref}"
            )
        parents_by_child.setdefault(service_ref, set()).add(system_ref)
        service_data_by_ref[service_ref] = data

    for child_ref, parent_refs in parents_by_child.items():
        if len(parent_refs) > 1:
            joined = ", ".join(sorted(parent_refs))
            raise RuntimeError(
                f"canonical placement migration found multiple parents for "
                f"{child_ref}: {joined}"
            )

    canonical_triplets = {
        (str(row["from_ref"]), "hosts", str(row["to_ref"]))
        for row in relationship_rows
        if row["relation_type"] == "hosts"
    }
    for row in relationship_rows:
        if row["relation_type"] != "provides":
            continue
        triplet = (str(row["from_ref"]), "hosts", str(row["to_ref"]))
        if triplet in canonical_triplets:
            connection.execute(
                sa.text("DELETE FROM relationships WHERE id = :relationship_id"),
                {"relationship_id": row["id"]},
            )
            continue
        connection.execute(
            sa.text(
                "UPDATE relationships SET relation_type = 'hosts' "
                "WHERE id = :relationship_id"
            ),
            {"relationship_id": row["id"]},
        )
        canonical_triplets.add(triplet)

    for service_ref, data in service_data_by_ref.items():
        parent_ref = next(iter(parents_by_child[service_ref]))
        triplet = (parent_ref, "hosts", service_ref)
        if triplet not in canonical_triplets:
            connection.execute(
                sa.text(
                    "INSERT INTO relationships "
                    "(from_ref, relation_type, to_ref) "
                    "VALUES (:from_ref, 'hosts', :to_ref)"
                ),
                {"from_ref": parent_ref, "to_ref": service_ref},
            )
            canonical_triplets.add(triplet)
        del data["system_id"]
        connection.execute(
            sa.text(
                "UPDATE catalog_objects SET data_json = :data_json "
                "WHERE id = :object_id"
            ),
            {
                "object_id": service_ref.split(":", 1)[1],
                "data_json": json.dumps(
                    data,
                    sort_keys=True,
                    separators=(",", ":"),
                ),
            },
        )


def downgrade() -> None:
    raise RuntimeError(
        "canonical placement cannot be downgraded safely; restore the pre-upgrade backup"
    )


def _validate_stored_placement(
    objects_by_ref: dict[str, Any],
    *,
    parent_ref: str,
    child_ref: str,
    legacy_provides: bool,
) -> None:
    parent = objects_by_ref.get(parent_ref)
    child = objects_by_ref.get(child_ref)
    if parent is None or child is None:
        raise RuntimeError(
            f"canonical placement migration rejected dangling relationship "
            f"{parent_ref} -> {child_ref}"
        )
    pair = (str(parent["kind"]), str(child["kind"]))
    allowed_pairs = (
        {("host", "service"), ("system", "service")}
        if legacy_provides
        else _PLACEMENT_PAIRS
    )
    if pair not in allowed_pairs:
        relation_type = "provides" if legacy_provides else "hosts"
        raise RuntimeError(
            f"canonical placement migration rejected unsupported relationship "
            f"{parent_ref} {relation_type} {child_ref}"
        )


def _load_object_data(data_json: str, object_ref: str) -> dict[str, Any]:
    try:
        data = json.loads(data_json)
    except json.JSONDecodeError as exc:
        raise RuntimeError(
            f"canonical placement migration rejected invalid JSON for {object_ref}"
        ) from exc
    if not isinstance(data, dict):
        raise RuntimeError(
            f"canonical placement migration rejected non-object data for {object_ref}"
        )
    return data
