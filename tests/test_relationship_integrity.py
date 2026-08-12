from __future__ import annotations

import json

import pytest
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from blockwart.domain.asset_state import is_asset_kind
from blockwart.domain.relationships import (
    RELATIONSHIP_TYPES,
    RelationshipIntegrityError,
    diagnose_relationship_integrity,
    validate_relationship_metadata,
)
from blockwart.models import AuditEvent, CatalogObject, Relationship
from blockwart.schemas.catalog import CatalogObjectIn
from blockwart.services.catalog import (
    create_relationship,
    delete_object,
    relationship_diagnostics,
    upsert_object,
)


@pytest.fixture()
def session(alembic_session_factory) -> Session:
    with alembic_session_factory() as db_session:
        yield db_session


def _add_object(session: Session, object_id: str, kind: str, data: dict | None = None) -> None:
    if data is None and kind == "device":
        data = {"schema_version": 1, "device": {"category": "other"}}
    session.add(
        CatalogObject(
            id=object_id,
            kind=kind,
            label=object_id,
            status="active",
            lifecycle="active" if is_asset_kind(kind) else None,
            health="unknown" if is_asset_kind(kind) else None,
            summary=None,
            data_json=json.dumps(data or {"schema_version": 1}),
        )
    )


def test_relationship_registry_is_explicit_and_stable() -> None:
    assert RELATIONSHIP_TYPES == (
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
    )


def test_attachment_and_uplink_endpoint_contract_is_fail_closed(session: Session) -> None:
    _add_object(session, "hardware", "host")
    _add_object(session, "runtime", "system")
    _add_object(session, "api", "service")
    _add_object(session, "sensor", "device", {"device": {"category": "sensor"}})
    _add_object(
        session,
        "switch",
        "network",
        {"network": {"category": "switch"}},
    )
    _add_object(
        session,
        "segment",
        "network",
        {"network": {"category": "segment"}},
    )
    _add_object(session, "legacy-network", "network", {"network": {}})
    session.flush()

    create_relationship(
        session,
        from_ref="host:hardware",
        relation_type="attached_to",
        to_ref="network:switch",
    )
    create_relationship(
        session,
        from_ref="device:sensor",
        relation_type="attached_to",
        to_ref="system:runtime",
    )

    for from_ref, to_ref in (
        ("service:api", "network:switch"),
        ("host:hardware", "network:segment"),
        ("device:sensor", "network:segment"),
        ("host:hardware", "network:legacy-network"),
    ):
        with pytest.raises(RelationshipIntegrityError) as error:
            create_relationship(
                session,
                from_ref=from_ref,
                relation_type="attached_to",
                to_ref=to_ref,
            )
        assert error.value.code in {
            "invalid_relationship_direction",
            "invalid_relationship_endpoint",
        }

    with pytest.raises(RelationshipIntegrityError) as error:
        create_relationship(
            session,
            from_ref="network:switch",
            relation_type="uplinks_to",
            to_ref="network:segment",
        )
    assert error.value.code == "invalid_relationship_endpoint"


@pytest.mark.parametrize(
    ("source_ref", "relation_type", "target_ref", "updated_object_id"),
    [
        ("device:sensor", "attached_to", "network:switch", "switch"),
        ("network:switch", "uplinks_to", "network:core", "core"),
    ],
)
def test_object_update_rejects_projected_invalid_relationship_endpoints(
    session: Session,
    source_ref: str,
    relation_type: str,
    target_ref: str,
    updated_object_id: str,
) -> None:
    _add_object(session, "sensor", "device", {"device": {"category": "sensor"}})
    _add_object(session, "switch", "network", {"network": {"category": "switch"}})
    _add_object(session, "core", "network", {"network": {"category": "router"}})
    session.flush()
    create_relationship(
        session,
        from_ref=source_ref,
        relation_type=relation_type,
        to_ref=target_ref,
    )

    with pytest.raises(RelationshipIntegrityError) as error:
        upsert_object(
            session,
            CatalogObjectIn(
                id=updated_object_id,
                kind="network",
                label=updated_object_id,
                data={"schema_version": 1, "network": {"category": "segment"}},
            ),
        )

    assert error.value.code == "invalid_relationship_endpoint"
    stored_data = json.loads(session.get(CatalogObject, updated_object_id).data_json)
    assert stored_data["network"]["category"] in {"switch", "router"}


def test_object_update_allows_non_endpoint_network_changes(session: Session) -> None:
    _add_object(session, "sensor", "device", {"device": {"category": "sensor"}})
    _add_object(session, "switch", "network", {"network": {"category": "switch"}})
    session.flush()
    create_relationship(
        session,
        from_ref="device:sensor",
        relation_type="attached_to",
        to_ref="network:switch",
    )

    updated = upsert_object(
        session,
        CatalogObjectIn(
            id="switch",
            kind="network",
            label="Switch updated",
            data={
                "schema_version": 1,
                "network": {"category": "switch", "model": "Model 2"},
            },
        ),
    )

    assert updated.label == "Switch updated"
    assert updated.data["network"]["model"] == "Model 2"


def test_relationship_metadata_is_typed_canonical_and_secret_safe() -> None:
    assert validate_relationship_metadata(
        "attached_to",
        {
            "source_interface": "  ttyUSB0 ",
            "target_interface_or_port": " USB 3 ",
            "link_kind": "usb",
            "primary": True,
            "note": "  Coordinator ",
        },
    ) == {
        "source_interface": "ttyUSB0",
        "target_interface_or_port": "USB 3",
        "link_kind": "usb",
        "primary": True,
        "note": "Coordinator",
    }
    assert validate_relationship_metadata("attached_to", {}) == {}
    assert validate_relationship_metadata("attached_to", {"primary": False}) == {
        "primary": False
    }
    assert validate_relationship_metadata("uplinks_to", {"mode": "trunk"}) == {
        "mode": "trunk"
    }

    invalid = (
        ("hosts", {"note": "not allowed"}, "invalid_relationship_metadata"),
        ("attached_to", {"mode": "access"}, "invalid_relationship_metadata"),
        ("attached_to", {"note": "   "}, "invalid_relationship_metadata"),
        ("attached_to", {"note": "x" * 513}, "invalid_relationship_metadata"),
        (
            "attached_to",
            {"source_interface": "x" * 129},
            "invalid_relationship_metadata",
        ),
        (
            "attached_to",
            {"target_interface_or_port": "x" * 129},
            "invalid_relationship_metadata",
        ),
        ("attached_to", {"link_kind": "coax"}, "invalid_relationship_metadata"),
        ("attached_to", {"primary": 1}, "invalid_relationship_metadata"),
        ("uplinks_to", {"mode": "invalid"}, "invalid_relationship_metadata"),
        (
            "attached_to",
            {"note": "Bearer abcdefghijklmnopqrstuvwxyz123456"},
            "secret_relationship_metadata",
        ),
        ("attached_to", {"token": "not-even-a-secret"}, "secret_relationship_metadata"),
    )
    for relation_type, metadata, code in invalid:
        with pytest.raises(RelationshipIntegrityError) as error:
            validate_relationship_metadata(relation_type, metadata)
        assert error.value.code == code
    with pytest.raises(RelationshipIntegrityError, match="must be an object"):
        validate_relationship_metadata("attached_to", [])  # type: ignore[arg-type]


def test_device_attachment_graph_rejects_cycles_and_multiple_primary_edges(
    session: Session,
) -> None:
    for object_id in ("sensor", "antenna", "controller"):
        _add_object(session, object_id, "device")
    session.flush()

    create_relationship(
        session,
        from_ref="device:sensor",
        relation_type="attached_to",
        to_ref="device:antenna",
        metadata={"primary": True, "link_kind": "zigbee"},
    )
    create_relationship(
        session,
        from_ref="device:antenna",
        relation_type="attached_to",
        to_ref="device:controller",
    )

    with pytest.raises(RelationshipIntegrityError) as cycle:
        create_relationship(
            session,
            from_ref="device:controller",
            relation_type="attached_to",
            to_ref="device:sensor",
        )
    assert cycle.value.code == "relationship_cycle"

    with pytest.raises(RelationshipIntegrityError) as primary:
        create_relationship(
            session,
            from_ref="device:sensor",
            relation_type="attached_to",
            to_ref="device:controller",
            metadata={"primary": True},
        )
    assert primary.value.code == "multiple_primary_relationships"

    with pytest.raises(RelationshipIntegrityError) as delete_error:
        delete_object(session, "antenna")
    assert delete_error.value.code == "delete_referenced_object"


def test_network_uplink_graph_and_primary_use_collection_validation(
    session: Session,
) -> None:
    for object_id in ("edge", "core", "backup"):
        _add_object(
            session,
            object_id,
            "network",
            {"network": {"category": "switch"}},
        )
    session.flush()
    first = create_relationship(
        session,
        from_ref="network:edge",
        relation_type="uplinks_to",
        to_ref="network:core",
        metadata={"primary": True, "mode": "trunk"},
    )
    assert first["relation_type"] == "uplinks_to"
    edge = session.scalar(
        select(Relationship).where(
            Relationship.from_ref == "network:edge",
            Relationship.to_ref == "network:core",
        )
    )
    assert edge is not None
    assert json.loads(edge.metadata_json) == {"mode": "trunk", "primary": True}

    with pytest.raises(RelationshipIntegrityError) as primary:
        create_relationship(
            session,
            from_ref="network:edge",
            relation_type="uplinks_to",
            to_ref="network:backup",
            metadata={"primary": True},
        )
    assert primary.value.code == "multiple_primary_relationships"

    second = create_relationship(
        session,
        from_ref="network:edge",
        relation_type="uplinks_to",
        to_ref="network:backup",
    )
    assert second["to_ref"] == "network:backup"

    with pytest.raises(RelationshipIntegrityError) as cycle:
        create_relationship(
            session,
            from_ref="network:core",
            relation_type="uplinks_to",
            to_ref="network:edge",
        )
    assert cycle.value.code == "relationship_cycle"


@pytest.mark.parametrize(
    ("from_ref", "relation_type", "to_ref", "code"),
    [
        (
            "system:runtime",
            "hosts",
            "system:other-runtime",
            "invalid_relationship_direction",
        ),
        (
            "service:api",
            "depends_on",
            "service:api",
            "self_reference",
        ),
        (
            "service:api",
            "provides",
            "service:worker",
            "unsupported_relation_type",
        ),
        (
            "service:missing",
            "depends_on",
            "service:worker",
            "dangling_typed_reference",
        ),
        (
            "system:api",
            "depends_on",
            "service:worker",
            "typed_reference_kind_mismatch",
        ),
    ],
)
def test_service_rejects_invalid_relationships_with_stable_codes(
    session: Session,
    from_ref: str,
    relation_type: str,
    to_ref: str,
    code: str,
) -> None:
    _add_object(session, "runtime", "system")
    _add_object(session, "other-runtime", "system")
    _add_object(session, "api", "service")
    _add_object(session, "worker", "service")
    session.flush()

    with pytest.raises(RelationshipIntegrityError) as error:
        create_relationship(
            session,
            from_ref=from_ref,
            relation_type=relation_type,
            to_ref=to_ref,
        )

    assert error.value.code == code


def test_service_is_idempotent_but_database_prevents_duplicate_triplets(
    session: Session,
) -> None:
    _add_object(session, "api", "service")
    _add_object(session, "worker", "service")
    session.flush()

    first = create_relationship(
        session,
        from_ref="service:api",
        relation_type="depends_on",
        to_ref="service:worker",
    )
    second = create_relationship(
        session,
        from_ref="service:api",
        relation_type="depends_on",
        to_ref="service:worker",
    )

    assert first == second
    assert session.scalar(select(func.count()).select_from(Relationship)) == 1

    session.add(
        Relationship(
            from_ref="service:api",
            relation_type="depends_on",
            to_ref="service:worker",
        )
    )
    with pytest.raises(IntegrityError):
        session.flush()


def test_database_prevents_second_placement_parent_when_service_is_bypassed(
    session: Session,
) -> None:
    _add_object(session, "hardware-a", "host")
    _add_object(session, "hardware-b", "host")
    _add_object(session, "api", "service")
    session.add(
        Relationship(
            from_ref="host:hardware-a",
            relation_type="hosts",
            to_ref="service:api",
        )
    )
    session.flush()
    session.add(
        Relationship(
            from_ref="host:hardware-b",
            relation_type="hosts",
            to_ref="service:api",
        )
    )

    with pytest.raises(IntegrityError):
        session.flush()


def test_explicit_parent_assignment_clears_unassigned_state(
    session: Session,
) -> None:
    _add_object(session, "hardware", "host")
    _add_object(
        session,
        "api",
        "service",
        {
            "schema_version": 1,
            "placement": {"state": "unassigned", "reason": "Pending decision"},
        },
    )
    session.flush()

    create_relationship(
        session,
        from_ref="host:hardware",
        relation_type="hosts",
        to_ref="service:api",
    )

    assert "placement" not in json.loads(session.get(CatalogObject, "api").data_json)
    assert session.query(AuditEvent).filter_by(action="placement_assign").count() == 1


def test_object_upsert_rejects_missing_json_typed_reference(session: Session) -> None:
    with pytest.raises(RelationshipIntegrityError) as error:
        upsert_object(
            session,
            CatalogObjectIn(
                id="project",
                kind="project",
                label="Project",
                data={
                    "category": "implementation",
                    "project_status": "planned",
                    "target_refs": ["service:missing"],
                },
            ),
        )

    assert error.value.code == "dangling_typed_reference"
    assert session.get(CatalogObject, "project") is None


def test_kind_change_is_blocked_while_old_typed_reference_exists(
    session: Session,
) -> None:
    _add_object(session, "hardware", "host")
    _add_object(session, "api", "service")
    session.add(
        Relationship(
            from_ref="host:hardware",
            relation_type="hosts",
            to_ref="service:api",
        )
    )
    session.flush()

    with pytest.raises(RelationshipIntegrityError) as error:
        upsert_object(
            session,
            CatalogObjectIn(
                id="hardware",
                kind="system",
                label="Hardware",
                data={"schema_version": 1},
            ),
        )

    assert error.value.code == "kind_change_referenced"
    assert session.get(CatalogObject, "hardware").kind == "host"


def test_delete_is_blocked_by_json_typed_reference(session: Session) -> None:
    _add_object(session, "api", "service")
    _add_object(
        session,
        "runbook",
        "runbook",
        {"schema_version": 1, "target_refs": ["service:api"]},
    )
    session.flush()

    with pytest.raises(RelationshipIntegrityError) as error:
        delete_object(session, "api")

    assert error.value.code == "delete_referenced_object"
    assert session.get(CatalogObject, "api") is not None


def test_relationship_diagnostics_report_dangling_direction_and_legacy_storage(
    session: Session,
) -> None:
    _add_object(session, "runtime-a", "system")
    _add_object(session, "runtime-b", "system")
    _add_object(
        session,
        "legacy",
        "service",
        {
            "schema_version": 1,
            "dependencies": {"upstream": ["service:missing"], "downstream": []},
        },
    )
    session.add_all(
        [
            Relationship(
                from_ref="system:runtime-a",
                relation_type="hosts",
                to_ref="system:runtime-b",
            ),
            Relationship(
                from_ref="service:legacy",
                relation_type="depends_on",
                to_ref="service:missing",
            ),
        ]
    )
    session.flush()

    codes = {diagnostic.code for diagnostic in relationship_diagnostics(session)}

    assert codes == {
        "dangling_typed_reference",
        "invalid_relationship_direction",
        "obsolete_data_dependencies",
    }


def test_pure_diagnostics_find_duplicate_and_multiple_placement_parents() -> None:
    objects = [
        {"id": "hardware-a", "kind": "host", "data_json": "{}"},
        {"id": "hardware-b", "kind": "host", "data_json": "{}"},
        {"id": "api", "kind": "service", "data_json": "{}"},
    ]
    relationships = [
        {
            "id": 1,
            "from_ref": "host:hardware-a",
            "relation_type": "hosts",
            "to_ref": "service:api",
        },
        {
            "id": 2,
            "from_ref": "host:hardware-a",
            "relation_type": "hosts",
            "to_ref": "service:api",
        },
        {
            "id": 3,
            "from_ref": "host:hardware-b",
            "relation_type": "hosts",
            "to_ref": "service:api",
        },
    ]

    codes = {
        diagnostic.code
        for diagnostic in diagnose_relationship_integrity(objects, relationships)
    }

    assert codes == {"duplicate_relationship", "multiple_placement_parents"}


def test_pure_diagnostics_find_metadata_violations_and_device_cycles() -> None:
    objects = [
        {
            "id": object_id,
            "kind": "device",
            "data_json": '{"device":{"category":"other"},"schema_version":1}',
        }
        for object_id in ("sensor", "antenna", "controller")
    ]
    relationships = [
        {
            "id": 1,
            "from_ref": "device:sensor",
            "relation_type": "attached_to",
            "to_ref": "device:antenna",
            "metadata_json": "{}",
        },
        {
            "id": 2,
            "from_ref": "device:antenna",
            "relation_type": "attached_to",
            "to_ref": "device:sensor",
            "metadata_json": "{}",
        },
        {
            "id": 3,
            "from_ref": "device:controller",
            "relation_type": "attached_to",
            "to_ref": "device:antenna",
            "metadata_json": '{"note":"Bearer abcdefghijklmnopqrstuvwxyz123456"}',
        },
    ]

    codes = {
        diagnostic.code
        for diagnostic in diagnose_relationship_integrity(objects, relationships)
    }

    assert codes == {"relationship_cycle", "secret_relationship_metadata"}
