"""canonicalize the backend language contract

Revision ID: 20260729_0007
Revises: 20260726_0006
"""

from __future__ import annotations

import json
from collections import Counter
from collections.abc import Mapping, Sequence
from typing import Any

import sqlalchemy as sa
from alembic import op

revision: str = "20260729_0007"
down_revision: str | Sequence[str] | None = "20260726_0006"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

LEGACY_NETWORK_KIND = "netzwerk"
NETWORK_KIND = "network"
KNOWN_KINDS = {
    "host",
    "system",
    NETWORK_KIND,
    LEGACY_NETWORK_KIND,
    "service",
    "credential_reference",
    "runbook",
    "decision",
    "project",
}
CANONICAL_KINDS = KNOWN_KINDS - {LEGACY_NETWORK_KIND}
TRANSITIONAL_ASSET_STATE_SQL = (
    "(kind IN ('host','system','network','netzwerk','service') "
    "AND lifecycle IS NOT NULL AND health IS NOT NULL) OR "
    "(kind NOT IN ('host','system','network','netzwerk','service') "
    "AND lifecycle IS NULL AND health IS NULL)"
)
CANONICAL_ASSET_STATE_SQL = (
    "(kind IN ('host','system','network','service') "
    "AND lifecycle IS NOT NULL AND health IS NOT NULL) OR "
    "(kind NOT IN ('host','system','network','service') "
    "AND lifecycle IS NULL AND health IS NULL)"
)
EMPTY_AUDIT_DETAILS = '{"event":"legacy","version":1}'


def upgrade() -> None:
    bind = op.get_bind()
    object_rows = list(
        bind.execute(
            sa.text(
                "SELECT id, kind, data_json, provenance_json "
                "FROM catalog_objects ORDER BY id"
            )
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
    audit_rows = list(
        bind.execute(
            sa.text(
                "SELECT id, object_id, action, actor, summary "
                "FROM audit_events ORDER BY id"
            )
        ).mappings()
    )

    plan = _build_plan(object_rows, relationship_rows, audit_rows)

    with op.batch_alter_table("catalog_objects", recreate="always") as batch_op:
        batch_op.drop_constraint(
            "ck_catalog_objects_asset_state",
            type_="check",
        )
        batch_op.create_check_constraint(
            "ck_catalog_objects_asset_state",
            TRANSITIONAL_ASSET_STATE_SQL,
        )

    op.add_column(
        "audit_events",
        sa.Column(
            "details_json",
            sa.Text(),
            nullable=False,
            server_default=EMPTY_AUDIT_DETAILS,
        ),
    )

    for change in plan["objects"]:
        bind.execute(
            sa.text(
                "UPDATE catalog_objects "
                "SET kind = :kind, data_json = :data_json, "
                "provenance_json = :provenance_json "
                "WHERE id = :object_id"
            ),
            change,
        )
    for change in plan["relationships"]:
        bind.execute(
            sa.text(
                "UPDATE relationships SET from_ref = :from_ref, to_ref = :to_ref "
                "WHERE id = :relationship_id"
            ),
            change,
        )
    for change in plan["audits"]:
        bind.execute(
            sa.text(
                "UPDATE audit_events "
                "SET summary = :summary, details_json = :details_json "
                "WHERE id = :audit_id"
            ),
            change,
        )

    with op.batch_alter_table("catalog_objects", recreate="always") as batch_op:
        batch_op.drop_constraint(
            "ck_catalog_objects_asset_state",
            type_="check",
        )
        batch_op.create_check_constraint(
            "ck_catalog_objects_asset_state",
            CANONICAL_ASSET_STATE_SQL,
        )


def downgrade() -> None:
    raise RuntimeError(
        "the canonical English contract cannot be downgraded safely; "
        "restore the paired pre-upgrade backup"
    )


def _build_plan(
    object_rows: list[Mapping[str, Any]],
    relationship_rows: list[Mapping[str, Any]],
    audit_rows: list[Mapping[str, Any]],
) -> dict[str, list[dict[str, Any]]]:
    object_kinds: dict[str, str] = {}
    for row in object_rows:
        object_id = str(row["id"])
        kind = str(row["kind"])
        if kind not in KNOWN_KINDS:
            raise RuntimeError(
                f"English contract migration rejected unknown kind {kind!r} "
                f"for catalog object {object_id}"
            )
        object_kinds[object_id] = kind

    object_changes = [
        _object_change(row, object_kinds)
        for row in object_rows
    ]
    relationship_changes = [
        _relationship_change(row, object_kinds)
        for row in relationship_rows
    ]
    audit_changes = [_audit_change(row) for row in audit_rows]

    canonical_triplets = [
        (
            str(change["from_ref"]),
            str(row["relation_type"]),
            str(change["to_ref"]),
        )
        for row, change in zip(
            relationship_rows,
            relationship_changes,
            strict=True,
        )
    ]
    duplicate = next(
        (
            triplet
            for triplet, count in Counter(canonical_triplets).items()
            if count > 1
        ),
        None,
    )
    if duplicate is not None:
        raise RuntimeError(
            "English contract migration rejected relationship collision: "
            f"{' '.join(duplicate)}"
        )

    return {
        "objects": object_changes,
        "relationships": relationship_changes,
        "audits": audit_changes,
    }


def _object_change(
    row: Mapping[str, Any],
    object_kinds: Mapping[str, str],
) -> dict[str, Any]:
    object_id = str(row["id"])
    kind = str(row["kind"])
    return {
        "object_id": object_id,
        "kind": _canonical_kind(kind),
        "data_json": _canonical_json(
            row["data_json"],
            location=f"catalog_objects[{object_id}].data_json",
            object_kinds=object_kinds,
        ),
        "provenance_json": _canonical_json(
            row["provenance_json"],
            location=f"catalog_objects[{object_id}].provenance_json",
            object_kinds=object_kinds,
        ),
    }


def _relationship_change(
    row: Mapping[str, Any],
    object_kinds: Mapping[str, str],
) -> dict[str, Any]:
    relationship_id = int(row["id"])
    return {
        "relationship_id": relationship_id,
        "from_ref": _canonical_reference(
            str(row["from_ref"]),
            object_kinds,
            location=f"relationships[{relationship_id}].from_ref",
        ),
        "to_ref": _canonical_reference(
            str(row["to_ref"]),
            object_kinds,
            location=f"relationships[{relationship_id}].to_ref",
        ),
    }


def _audit_change(row: Mapping[str, Any]) -> dict[str, Any]:
    audit_id = int(row["id"])
    legacy_summary = row["summary"]
    if not isinstance(legacy_summary, str):
        raise RuntimeError(
            f"English contract migration rejected invalid summary for audit {audit_id}"
        )
    details = {
        "event": "legacy",
        "legacy_summary": legacy_summary,
        "version": 1,
    }
    return {
        "audit_id": audit_id,
        "summary": "legacy",
        "details_json": json.dumps(
            details,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ),
    }


def _canonical_json(
    raw_value: Any,
    *,
    location: str,
    object_kinds: Mapping[str, str],
) -> str:
    try:
        value = json.loads(str(raw_value))
    except (TypeError, json.JSONDecodeError):
        # Corrupt legacy records are already surfaced through the existing
        # record-integrity contract. They remain byte-identical and opaque
        # instead of being silently repaired or discarded by this migration.
        return str(raw_value)
    canonical = _canonical_json_value(
        value,
        location=location,
        object_kinds=object_kinds,
    )
    if canonical == value:
        return str(raw_value)
    return json.dumps(
        canonical,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def _canonical_json_value(
    value: Any,
    *,
    location: str,
    object_kinds: Mapping[str, str],
) -> Any:
    if isinstance(value, dict):
        canonical_mapping: dict[str, Any] = {}
        for key, child in value.items():
            canonical_key = NETWORK_KIND if key == LEGACY_NETWORK_KIND else key
            if canonical_key in canonical_mapping:
                raise RuntimeError(
                    "English contract migration rejected JSON key collision at "
                    f"{location}: {key!r} maps to {canonical_key!r}"
                )
            canonical_mapping[canonical_key] = _canonical_json_value(
                child,
                location=f"{location}.{canonical_key}",
                object_kinds=object_kinds,
            )
        return canonical_mapping
    if isinstance(value, list):
        return [
            _canonical_json_value(
                child,
                location=f"{location}[{index}]",
                object_kinds=object_kinds,
            )
            for index, child in enumerate(value)
        ]
    if isinstance(value, str) and ":" in value:
        kind = value.split(":", 1)[0]
        if kind in KNOWN_KINDS:
            return _canonical_reference(value, object_kinds, location=location)
    return value


def _canonical_reference(
    value: str,
    object_kinds: Mapping[str, str],
    *,
    location: str,
) -> str:
    if ":" not in value:
        raise RuntimeError(
            f"English contract migration rejected untyped reference at {location}: {value}"
        )
    kind, object_id = value.split(":", 1)
    if not object_id or kind not in KNOWN_KINDS:
        raise RuntimeError(
            f"English contract migration rejected invalid reference at {location}: {value}"
        )
    actual_kind = object_kinds.get(object_id)
    if actual_kind is None:
        raise RuntimeError(
            f"English contract migration rejected dangling reference at {location}: {value}"
        )
    if _canonical_kind(actual_kind) != _canonical_kind(kind):
        raise RuntimeError(
            f"English contract migration rejected kind mismatch at {location}: "
            f"{value} points to {actual_kind}"
        )
    return f"{_canonical_kind(actual_kind)}:{object_id}"


def _canonical_kind(kind: str) -> str:
    canonical = NETWORK_KIND if kind == LEGACY_NETWORK_KIND else kind
    if canonical not in CANONICAL_KINDS:
        raise RuntimeError(f"English contract migration rejected kind {kind!r}")
    return canonical
