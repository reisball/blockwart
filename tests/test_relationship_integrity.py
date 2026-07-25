from __future__ import annotations

import json

import pytest
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from blockwart.domain.relationships import (
    RELATIONSHIP_TYPES,
    RelationshipIntegrityError,
    diagnose_relationship_integrity,
)
from blockwart.models import CatalogObject, Relationship
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
    session.add(
        CatalogObject(
            id=object_id,
            kind=kind,
            label=object_id,
            status="active",
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
    )


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


def test_object_upsert_rejects_missing_json_typed_reference(session: Session) -> None:
    with pytest.raises(RelationshipIntegrityError) as error:
        upsert_object(
            session,
            CatalogObjectIn(
                id="project",
                kind="project",
                label="Project",
                data={"target_refs": ["service:missing"]},
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
