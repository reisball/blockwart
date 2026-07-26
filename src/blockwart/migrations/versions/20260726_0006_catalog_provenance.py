"""add canonical catalog provenance

Revision ID: 20260726_0006
Revises: 20260726_0005
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from typing import Any

import sqlalchemy as sa
from alembic import op

revision: str = "20260726_0006"
down_revision: str | Sequence[str] | None = "20260726_0005"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

UNKNOWN_PROVENANCE = '{"manual_override":false,"source_type":"unknown"}'


def upgrade() -> None:
    bind = op.get_bind()
    rows = list(
        bind.execute(
            sa.text(
                "SELECT id, data_json FROM catalog_objects ORDER BY id"
            )
        ).mappings()
    )
    migrations = [_migration_for_row(row) for row in rows]

    op.add_column(
        "catalog_objects",
        sa.Column(
            "provenance_json",
            sa.Text(),
            nullable=False,
            server_default=UNKNOWN_PROVENANCE,
        ),
    )
    for migration in migrations:
        bind.execute(
            sa.text(
                "UPDATE catalog_objects SET provenance_json = :provenance_json "
                "WHERE id = :object_id"
            ),
            migration,
        )


def downgrade() -> None:
    raise RuntimeError(
        "catalog provenance cannot be removed safely; "
        "restore the paired pre-upgrade backup"
    )


def _migration_for_row(row: Mapping[str, Any]) -> dict[str, str]:
    object_id = str(row["id"])
    provenance = _legacy_provenance(row["data_json"])
    return {
        "object_id": object_id,
        "provenance_json": json.dumps(
            provenance,
            sort_keys=True,
            separators=(",", ":"),
        ),
    }


def _legacy_provenance(raw_data: Any) -> dict[str, Any]:
    try:
        data = json.loads(str(raw_data))
    except (TypeError, json.JSONDecodeError):
        return {"source_type": "unknown", "manual_override": False}
    if not isinstance(data, dict):
        return {"source_type": "unknown", "manual_override": False}

    source_ref = _text(data.get("source"))
    if source_ref is None:
        source_ref = _first_source_reference(data.get("source_references"))
    if source_ref is None and isinstance(data.get("import_notes"), Mapping):
        source_ref = "legacy:import_notes"
    if source_ref is None:
        return {"source_type": "unknown", "manual_override": False}
    return {
        "source_type": "import",
        "source_ref": source_ref,
        "manual_override": False,
    }


def _first_source_reference(value: Any) -> str | None:
    if not isinstance(value, list):
        return None
    for item in value:
        if not isinstance(item, Mapping):
            continue
        uri = _text(item.get("uri"))
        if uri is not None:
            return uri
    return None


def _text(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    normalized = value.strip()
    return normalized or None
