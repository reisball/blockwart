"""separate asset lifecycle from operational health

Revision ID: 20260726_0005
Revises: 20260724_0004
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from typing import Any

import sqlalchemy as sa
from alembic import op

revision: str = "20260726_0005"
down_revision: str | Sequence[str] | None = "20260724_0004"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

ASSET_KINDS = {"host", "system", "netzwerk", "service"}
LIFECYCLES = {"planned", "active", "retired"}
HEALTH_VALUES = {"unknown", "healthy", "degraded", "down", "maintenance"}


def upgrade() -> None:
    bind = op.get_bind()
    rows = list(
        bind.execute(
            sa.text(
                "SELECT id, kind, status, data_json "
                "FROM catalog_objects ORDER BY id"
            )
        ).mappings()
    )
    migrations = [_migration_for_row(row) for row in rows]

    op.add_column(
        "catalog_objects",
        sa.Column("lifecycle", sa.String(length=32), nullable=True),
    )
    op.add_column(
        "catalog_objects",
        sa.Column("health", sa.String(length=32), nullable=True),
    )

    for migration in migrations:
        if migration is None:
            continue
        bind.execute(
            sa.text(
                "UPDATE catalog_objects "
                "SET status = :status, lifecycle = :lifecycle, health = :health, "
                "data_json = :data_json "
                "WHERE id = :object_id"
            ),
            migration,
        )

    with op.batch_alter_table("catalog_objects", recreate="always") as batch_op:
        batch_op.create_check_constraint(
            "ck_catalog_objects_lifecycle",
            "lifecycle IS NULL OR lifecycle IN ('planned','active','retired')",
        )
        batch_op.create_check_constraint(
            "ck_catalog_objects_health",
            "health IS NULL OR "
            "health IN ('unknown','healthy','degraded','down','maintenance')",
        )
        batch_op.create_check_constraint(
            "ck_catalog_objects_asset_state",
            "(kind IN ('host','system','netzwerk','service') "
            "AND lifecycle IS NOT NULL AND health IS NOT NULL) OR "
            "(kind NOT IN ('host','system','netzwerk','service') "
            "AND lifecycle IS NULL AND health IS NULL)",
        )
        batch_op.create_check_constraint(
            "ck_catalog_objects_compatibility_status",
            "lifecycle IS NULL OR "
            "(lifecycle = 'planned' AND status = 'inactive') OR "
            "(lifecycle = 'retired' AND status = 'deleted') OR "
            "(lifecycle = 'active' AND health IN ('down','maintenance') "
            "AND status = 'inactive') OR "
            "(lifecycle = 'active' AND health IN ('unknown','healthy','degraded') "
            "AND status = 'active')",
        )


def downgrade() -> None:
    raise RuntimeError(
        "asset lifecycle and health cannot be collapsed safely; "
        "restore the paired pre-upgrade backup"
    )


def _load_data(raw_data: Any, object_id: str) -> dict[str, Any]:
    try:
        data = json.loads(str(raw_data))
    except (TypeError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"invalid data_json for catalog object {object_id}") from exc
    if not isinstance(data, dict):
        raise RuntimeError(f"data_json is not an object for catalog object {object_id}")
    return data


def _migration_for_row(row: Mapping[str, Any]) -> dict[str, str] | None:
    object_id = str(row["id"])
    kind = str(row["kind"])
    raw_data = str(row["data_json"])
    data = _load_data(raw_data, object_id)
    if kind not in ASSET_KINDS:
        _reject_non_asset_state(data, object_id)
        return None

    lifecycle, health = _migrated_state(
        status=str(row["status"] or ""),
        data=data,
        object_id=object_id,
    )
    has_legacy_state = "lifecycle" in data or "health" in data
    data.pop("lifecycle", None)
    data.pop("health", None)
    return {
        "object_id": object_id,
        "status": _compatibility_status(lifecycle, health),
        "lifecycle": lifecycle,
        "health": health,
        "data_json": (
            json.dumps(data, sort_keys=True)
            if has_legacy_state
            else raw_data
        ),
    }


def _reject_non_asset_state(data: Mapping[str, Any], object_id: str) -> None:
    if "lifecycle" in data or "health" in data:
        raise RuntimeError(
            f"lifecycle or health is not valid for non-asset catalog object {object_id}"
        )


def _migrated_state(
    *,
    status: str,
    data: Mapping[str, Any],
    object_id: str,
) -> tuple[str, str]:
    lifecycle, health = _state_from_legacy_status(status, object_id)

    raw_lifecycle = data.get("lifecycle")
    if raw_lifecycle is not None:
        if not isinstance(raw_lifecycle, str):
            raise RuntimeError(f"invalid lifecycle for catalog object {object_id}")
        lifecycle_aliases = {
            "production": "active",
            "deleted": "retired",
        }
        lifecycle = lifecycle_aliases.get(raw_lifecycle.casefold(), raw_lifecycle.casefold())
        if lifecycle not in LIFECYCLES:
            raise RuntimeError(f"invalid lifecycle for catalog object {object_id}")

    raw_health = data.get("health")
    if raw_health is not None:
        if not isinstance(raw_health, str):
            raise RuntimeError(f"invalid health for catalog object {object_id}")
        health_aliases = {
            "partial": "degraded",
            "offline": "down",
        }
        health = health_aliases.get(raw_health.casefold(), raw_health.casefold())
        if health not in HEALTH_VALUES:
            raise RuntimeError(f"invalid health for catalog object {object_id}")

    return lifecycle, health


def _state_from_legacy_status(status: str, object_id: str) -> tuple[str, str]:
    normalized = status.casefold().strip()
    if normalized == "active":
        return "active", "unknown"
    if normalized in {"inactive", "planned"}:
        return "planned", "unknown"
    if normalized in {"deleted", "retired"}:
        return "retired", "unknown"
    if normalized in {"partial", "degraded"}:
        return "active", "degraded"
    if normalized == "maintenance":
        return "active", "maintenance"
    if normalized in {"down", "offline"}:
        return "active", "down"
    if normalized in {"", "unknown"}:
        return "active", "unknown"
    raise RuntimeError(f"unsupported status for catalog object {object_id}")


def _compatibility_status(lifecycle: str, health: str) -> str:
    if lifecycle == "retired":
        return "deleted"
    if lifecycle == "planned" or health in {"down", "maintenance"}:
        return "inactive"
    return "active"
