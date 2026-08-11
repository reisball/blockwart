"""add the device and typed relationship foundation

Revision ID: 20260801_0013
Revises: 20260731_0012
"""

from __future__ import annotations

import json
from collections import Counter
from collections.abc import Mapping, Sequence
from typing import Any

import sqlalchemy as sa
from alembic import op

revision: str = "20260801_0013"
down_revision: str | Sequence[str] | None = "20260731_0012"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

ASSET_KINDS = {"host", "system", "network", "device", "service"}
ALL_KINDS = ASSET_KINDS | {"credential_reference", "runbook", "decision", "project"}
NETWORK_CATEGORIES = {
    "segment",
    "switch",
    "router",
    "access_point",
    "mesh",
    "firewall",
    "gateway",
    "other_device",
}
NETWORK_DEVICE_CATEGORIES = NETWORK_CATEGORIES - {"segment"}
DEVICE_CATEGORIES = {"antenna", "sensor", "adapter", "controller", "ups", "other"}
RELATIONSHIP_TYPES = {
    "hosts",
    "depends_on",
    "supports",
    "feeds",
    "exposes",
    "documents",
    "uses",
    "related_to",
    "attached_to",
    "uplinks_to",
}
EMPTY_METADATA = "{}"

CATALOG_ASSET_STATE_SQL = (
    "(kind IN ('host','system','network','device','service') "
    "AND lifecycle IS NOT NULL AND health IS NOT NULL) OR "
    "(kind NOT IN ('host','system','network','device','service') "
    "AND lifecycle IS NULL AND health IS NULL)"
)
COMPATIBILITY_STATUS_SQL = (
    "lifecycle IS NULL OR "
    "(lifecycle = 'planned' AND status = 'inactive') OR "
    "(lifecycle = 'retired' AND status = 'deleted') OR "
    "(lifecycle = 'active' AND health IN ('down','maintenance') "
    "AND status = 'inactive') OR "
    "(lifecycle = 'active' AND health IN ('unknown','healthy','degraded') "
    "AND status = 'active')"
)


def upgrade() -> None:
    bind = op.get_bind()
    _is_sqlite = bind.dialect.name == "sqlite"

    object_rows = list(
        bind.execute(
            sa.text(
                "SELECT id, kind, label, status, lifecycle, health, summary, data_json, "
                "provenance_json, revision, created_at, updated_at "
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
    endpoint_data = _validate_catalog_objects(object_rows)
    _validate_relationships(relationship_rows, endpoint_data)

    _rebuild_catalog_objects()
    _rebuild_relationships()


def downgrade() -> None:
    raise RuntimeError(
        "device and relationship metadata contracts cannot be downgraded safely; "
        "restore the paired pre-migration backup"
    )


def _validate_catalog_objects(
    rows: list[Mapping[str, Any]],
) -> dict[str, tuple[str, dict[str, Any]]]:
    endpoints: dict[str, tuple[str, dict[str, Any]]] = {}
    for row in rows:
        object_id = str(row["id"])
        kind = str(row["kind"])
        if kind not in ALL_KINDS:
            raise RuntimeError(
                f"device foundation migration rejected unknown kind {kind!r} "
                f"for catalog object {object_id}"
            )
        data = _json_object(
            row["data_json"],
            location=f"catalog_objects[{object_id}].data_json",
        )
        _validate_equipment_data(object_id, kind, data)
        endpoints[object_id] = (kind, data)

    for object_id, (_, data) in endpoints.items():
        for index, reference in enumerate(_typed_references(data)):
            _resolve_reference(
                reference,
                endpoints,
                location=f"catalog_objects[{object_id}].data_ref[{index}]",
            )
    return endpoints


def _validate_equipment_data(object_id: str, kind: str, data: Mapping[str, Any]) -> None:
    if kind == "network":
        network = data.get("network")
        if network is not None and not isinstance(network, Mapping):
            raise RuntimeError(
                f"device foundation migration rejected non-object network data for {object_id}"
            )
        category = network.get("category") if isinstance(network, Mapping) else None
        # Missing category is the deliberate read-only transition state. Any
        # category already present must be canonical before the first rebuild.
        if category is not None and category not in NETWORK_CATEGORIES:
            raise RuntimeError(
                f"device foundation migration rejected unknown network category for {object_id}"
            )
        if isinstance(network, Mapping):
            _optional_text(network, "manufacturer", 128, object_id, canonical=True)
            _optional_text(network, "model", 128, object_id, canonical=True)
            _optional_text(network, "location", 255, object_id)
    elif kind == "device":
        device = data.get("device")
        if not isinstance(device, Mapping) or device.get("category") not in DEVICE_CATEGORIES:
            raise RuntimeError(
                f"device foundation migration rejected invalid device category for {object_id}"
            )
        _optional_text(device, "manufacturer", 128, object_id, canonical=True)
        _optional_text(device, "model", 128, object_id, canonical=True)


def _optional_text(
    data: Mapping[str, Any],
    key: str,
    max_length: int,
    object_id: str,
    *,
    canonical: bool = False,
) -> None:
    if key not in data:
        return
    value = data[key]
    if (
        not isinstance(value, str)
        or len(value) > max_length
        or (canonical and (not value or value != value.strip()))
    ):
        raise RuntimeError(
            f"device foundation migration rejected non-canonical {key} for {object_id}"
        )


def _validate_relationships(
    rows: list[Mapping[str, Any]],
    endpoints: Mapping[str, tuple[str, Mapping[str, Any]]],
) -> None:
    triplets: list[tuple[str, str, str]] = []
    placement_parents: dict[str, set[str]] = {}
    attachment_edges: dict[str, set[str]] = {}
    uplink_edges: dict[str, set[str]] = {}
    for row in rows:
        relationship_id = int(row["id"])
        from_ref = str(row["from_ref"])
        relation_type = str(row["relation_type"])
        to_ref = str(row["to_ref"])
        if relation_type not in RELATIONSHIP_TYPES:
            raise RuntimeError(
                "device foundation migration rejected unsupported relationship type "
                f"at relationships[{relationship_id}]"
            )
        source_id, source_kind = _resolve_reference(
            from_ref,
            endpoints,
            location=f"relationships[{relationship_id}].from_ref",
        )
        target_id, target_kind = _resolve_reference(
            to_ref,
            endpoints,
            location=f"relationships[{relationship_id}].to_ref",
        )
        if source_id == target_id:
            raise RuntimeError(
                f"device foundation migration rejected self relationship {relationship_id}"
            )
        if not _relationship_direction_allowed(
            relation_type,
            source_id,
            source_kind,
            target_id,
            target_kind,
            endpoints,
        ):
            raise RuntimeError(
                "device foundation migration rejected invalid relationship direction "
                f"at relationships[{relationship_id}]"
            )
        triplets.append((from_ref, relation_type, to_ref))
        if relation_type == "hosts":
            placement_parents.setdefault(to_ref, set()).add(from_ref)
        elif relation_type == "attached_to" and source_kind == target_kind == "device":
            attachment_edges.setdefault(from_ref, set()).add(to_ref)
        elif relation_type == "uplinks_to":
            uplink_edges.setdefault(from_ref, set()).add(to_ref)

    duplicate = next(
        (triplet for triplet, count in Counter(triplets).items() if count > 1),
        None,
    )
    if duplicate is not None:
        raise RuntimeError(
            "device foundation migration rejected duplicate relationship: "
            f"{' '.join(duplicate)}"
        )
    if any(len(parents) > 1 for parents in placement_parents.values()):
        raise RuntimeError("device foundation migration rejected multiple placement parents")
    if _has_cycle(attachment_edges) or _has_cycle(uplink_edges):
        raise RuntimeError("device foundation migration rejected relationship cycle")


def _relationship_direction_allowed(
    relation_type: str,
    source_id: str,
    source_kind: str,
    target_id: str,
    target_kind: str,
    endpoints: Mapping[str, tuple[str, Mapping[str, Any]]],
) -> bool:
    if relation_type == "hosts":
        return (source_kind, target_kind) in {
            ("host", "system"),
            ("host", "service"),
            ("system", "service"),
        }
    if relation_type == "depends_on":
        return source_kind in ASSET_KINDS and target_kind in ASSET_KINDS
    if relation_type in {"supports", "feeds", "exposes"}:
        return source_kind == target_kind == "service"
    if relation_type == "documents":
        return source_kind in {"runbook", "decision", "project"}
    if relation_type in {"uses", "related_to"}:
        return True
    if relation_type == "attached_to":
        if source_kind == "device":
            return target_kind in {"host", "system", "device"} or _is_network_device(
                target_id, endpoints
            )
        return source_kind in {"host", "system"} and _is_network_device(target_id, endpoints)
    if relation_type == "uplinks_to":
        return _is_network_device(source_id, endpoints) and _is_network_device(
            target_id, endpoints
        )
    return False


def _is_network_device(
    object_id: str,
    endpoints: Mapping[str, tuple[str, Mapping[str, Any]]],
) -> bool:
    kind, data = endpoints[object_id]
    network = data.get("network")
    category = network.get("category") if isinstance(network, Mapping) else None
    return kind == "network" and category in NETWORK_DEVICE_CATEGORIES


def _resolve_reference(
    value: str,
    endpoints: Mapping[str, tuple[str, Mapping[str, Any]]],
    *,
    location: str,
) -> tuple[str, str]:
    if ":" not in value:
        raise RuntimeError(
            f"device foundation migration rejected invalid typed reference at {location}"
        )
    asserted_kind, object_id = value.split(":", 1)
    endpoint = endpoints.get(object_id)
    if not object_id or endpoint is None:
        raise RuntimeError(
            f"device foundation migration rejected dangling typed reference at {location}"
        )
    actual_kind = endpoint[0]
    if asserted_kind not in ALL_KINDS or asserted_kind != actual_kind:
        raise RuntimeError(
            f"device foundation migration rejected typed-reference kind mismatch at {location}"
        )
    return object_id, actual_kind


def _typed_references(value: Any):
    if isinstance(value, Mapping):
        for child in value.values():
            yield from _typed_references(child)
    elif isinstance(value, list):
        for child in value:
            yield from _typed_references(child)
    elif isinstance(value, str) and ":" in value and value.split(":", 1)[0] in ALL_KINDS:
        yield value


def _has_cycle(edges: Mapping[str, set[str]]) -> bool:
    visited: set[str] = set()
    active: set[str] = set()

    def visit(node: str) -> bool:
        if node in active:
            return True
        if node in visited:
            return False
        visited.add(node)
        active.add(node)
        for target in sorted(edges.get(node, set())):
            if visit(target):
                return True
        active.remove(node)
        return False

    return any(visit(node) for node in sorted(edges))


def _json_object(raw_value: Any, *, location: str) -> dict[str, Any]:
    try:
        value = json.loads(str(raw_value))
    except (TypeError, json.JSONDecodeError) as exc:
        raise RuntimeError(
            f"device foundation migration rejected invalid JSON at {location}"
        ) from exc
    if not isinstance(value, dict):
        raise RuntimeError(
            f"device foundation migration rejected non-object JSON at {location}"
        )
    return value


def _rebuild_catalog_objects() -> None:
    _bind = op.get_bind()
    _is_sqlite = _bind.dialect.name == "sqlite"
    _ts_type = "DATETIME" if _is_sqlite else "TIMESTAMP"
    if not _is_sqlite:
        for _constraint in ["ck_catalog_objects_revision_positive", "ck_catalog_objects_lifecycle", "ck_catalog_objects_health", "ck_catalog_objects_asset_state", "ck_catalog_objects_compatibility_status"]:
            op.execute(f"ALTER TABLE catalog_objects DROP CONSTRAINT IF EXISTS {_constraint}")
    op.get_bind().exec_driver_sql(
        f"""
            CREATE TABLE _bw_0013_catalog_objects (
                id VARCHAR(128) NOT NULL,
                kind VARCHAR(64) NOT NULL,
                label VARCHAR(255) NOT NULL,
                status VARCHAR(64) NOT NULL,
                summary TEXT,
                data_json TEXT NOT NULL,
                created_at {_ts_type} DEFAULT CURRENT_TIMESTAMP NOT NULL,
                updated_at {_ts_type} DEFAULT CURRENT_TIMESTAMP NOT NULL,
                lifecycle VARCHAR(32),
                health VARCHAR(32),
                provenance_json TEXT DEFAULT '{{"manual_override":false,"source_type":"unknown"}}'
                    NOT NULL,
                revision INTEGER DEFAULT 1 NOT NULL,
                PRIMARY KEY (id),
                CONSTRAINT ck_catalog_objects_revision_positive CHECK (revision >= 1),
                CONSTRAINT ck_catalog_objects_lifecycle CHECK (
                    lifecycle IS NULL OR lifecycle IN ('planned','active','retired')
                ),
                CONSTRAINT ck_catalog_objects_health CHECK (
                    health IS NULL OR
                    health IN ('unknown','healthy','degraded','down','maintenance')
                ),
                CONSTRAINT ck_catalog_objects_asset_state CHECK ({CATALOG_ASSET_STATE_SQL}),
                CONSTRAINT ck_catalog_objects_compatibility_status
                    CHECK ({COMPATIBILITY_STATUS_SQL})
            )
            """
    )
    op.execute(
        "INSERT INTO _bw_0013_catalog_objects "
        "(id, kind, label, status, summary, data_json, created_at, updated_at, lifecycle, "
        "health, provenance_json, revision) "
        "SELECT id, kind, label, status, summary, data_json, created_at, updated_at, lifecycle, "
        "health, provenance_json, revision FROM catalog_objects"
    )
    if _is_sqlite:
        op.execute("DROP TABLE catalog_objects")
    else:
        op.execute("DROP TABLE catalog_objects CASCADE")
    op.execute("ALTER TABLE _bw_0013_catalog_objects RENAME TO catalog_objects")
    op.create_index("ix_catalog_objects_kind", "catalog_objects", ["kind"])
    op.create_index("ix_catalog_objects_label", "catalog_objects", ["label"])


def _rebuild_relationships() -> None:
    _bind = op.get_bind()
    _is_sqlite = _bind.dialect.name == "sqlite"
    if not _is_sqlite:
        op.execute("ALTER TABLE relationships DROP CONSTRAINT IF EXISTS uq_relationships_triplet")
        op.execute("ALTER TABLE relationships DROP CONSTRAINT IF EXISTS ck_relationships_no_self_reference")
        op.execute("ALTER TABLE relationships DROP CONSTRAINT IF EXISTS ck_relationships_known_type")
    op.execute(
        f"""
        CREATE TABLE _bw_0013_relationships (
            id INTEGER NOT NULL,
            from_ref VARCHAR(192) NOT NULL,
            relation_type VARCHAR(96) NOT NULL,
            to_ref VARCHAR(192) NOT NULL,
            metadata_json TEXT DEFAULT '{EMPTY_METADATA}' NOT NULL,
            PRIMARY KEY (id),
            CONSTRAINT uq_relationships_triplet UNIQUE (from_ref, relation_type, to_ref),
            CONSTRAINT ck_relationships_no_self_reference CHECK (from_ref <> to_ref),
            CONSTRAINT ck_relationships_known_type CHECK (
                relation_type IN
                ('hosts','depends_on','supports','feeds','exposes','documents','uses',
                 'related_to','attached_to','uplinks_to')
            )
        )
        """
    )
    op.execute(
        "INSERT INTO _bw_0013_relationships "
        "(id, from_ref, relation_type, to_ref, metadata_json) "
        "SELECT id, from_ref, relation_type, to_ref, '{}' FROM relationships"
    )
    if _is_sqlite:
        op.execute("DROP TABLE relationships")
    else:
        op.execute("DROP TABLE relationships CASCADE")
    op.execute("ALTER TABLE _bw_0013_relationships RENAME TO relationships")
    op.create_index("ix_relationships_from_ref", "relationships", ["from_ref"])
    op.create_index("ix_relationships_relation_type", "relationships", ["relation_type"])
    op.create_index("ix_relationships_to_ref", "relationships", ["to_ref"])
    op.create_index(
        "uq_relationships_placement_parent",
        "relationships",
        ["to_ref"],
        unique=True,
        sqlite_where=sa.text("relation_type = 'hosts'"),
        postgresql_where=sa.text("relation_type = 'hosts'"),
    )
