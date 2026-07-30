from __future__ import annotations

import json

import pytest

from blockwart.db.session import transaction
from blockwart.models import AuditEvent, CatalogObject
from blockwart.services.interface_migration import (
    InterfaceMigrationError,
    apply_interface_migration_plan,
    build_interface_migration_plan,
)


def _legacy_service(object_id: str = "legacy") -> CatalogObject:
    return CatalogObject(
        id=object_id,
        kind="service",
        label="Legacy Service",
        status="active",
        lifecycle="active",
        health="unknown",
        data_json=json.dumps(
            {
                "schema_version": 1,
                "endpoints": [
                    {
                        "name": "Legacy",
                        "url": "http://legacy.example:8080",
                        "port": 8080,
                        "protocol": "tcp",
                        "exposure": "lan",
                    }
                ],
                "ports": [
                    {"port": 8080, "protocol": "tcp", "exposure": "lan"}
                ],
                "access_methods": [
                    {
                        "type": "web",
                        "endpoint": "http://legacy.example:8080",
                        "auth_mode": "password",
                    }
                ],
            },
            sort_keys=True,
        ),
    )


def test_interface_plan_is_pure_deterministic_and_idempotent(
    alembic_session_factory,
) -> None:
    with alembic_session_factory() as session:
        row = _legacy_service()
        session.add(row)
        session.commit()
        original = row.data_json
        original_updated_at = row.updated_at

    with alembic_session_factory() as session:
        first = build_interface_migration_plan(session)
        second = build_interface_migration_plan(session)
        assert first == second
        assert first.scanned_objects == 1
        assert first.changed_objects == 1
        assert first.diagnostic_counts == {
            "access_endpoint_deduplicated": 1,
            "access_id_added": 1,
            "endpoint_port_duplicate": 1,
        }
        assert session.get(CatalogObject, "legacy").data_json == original
        assert session.query(AuditEvent).count() == 0

        with transaction(session):
            assert apply_interface_migration_plan(session, first) == 1

    with alembic_session_factory() as session:
        row = session.get(CatalogObject, "legacy")
        applied = json.loads(row.data_json)
        assert applied["interface"] == {"state": "available"}
        assert applied["endpoints"][0]["type"] == "HTTP"
        assert applied["ports"] == []
        assert applied["access_methods"][0]["type"] == "admin_web"
        assert applied["access_methods"][0]["endpoint_id"] == (
            applied["endpoints"][0]["id"]
        )
        audit = session.query(AuditEvent).one()
        assert audit.action == "interface_normalize"
        assert audit.actor == "interface-migration"
        assert row.revision == 2
        assert row.updated_at > original_updated_at
        repeated = build_interface_migration_plan(session)
        assert repeated.changed_objects == 0
        assert repeated.diagnostics == ()


def test_interface_apply_rolls_back_earlier_changes_when_plan_is_stale(
    alembic_session_factory,
) -> None:
    with alembic_session_factory() as session:
        session.add_all([_legacy_service("first"), _legacy_service("second")])
        session.commit()

    with alembic_session_factory() as session:
        plan = build_interface_migration_plan(session)

    with alembic_session_factory() as session:
        second = session.get(CatalogObject, "second")
        second.label = "Changed concurrently"
        second.data_json = '{"schema_version":1,"interface":{"state":"incomplete"}}'
        session.commit()

    with alembic_session_factory() as session:
        with pytest.raises(InterfaceMigrationError, match="changed after planning"):
            with transaction(session):
                apply_interface_migration_plan(session, plan)

    with alembic_session_factory() as session:
        first = json.loads(session.get(CatalogObject, "first").data_json)
        assert "interface" not in first
        assert session.query(AuditEvent).count() == 0


def test_interface_plan_rejects_corrupt_data_json(
    alembic_session_factory,
) -> None:
    with alembic_session_factory() as session:
        session.add(
            CatalogObject(
                id="corrupt",
                kind="service",
                label="Corrupt",
                status="active",
                lifecycle="active",
                health="unknown",
                data_json="{broken",
            )
        )
        session.commit()

    with alembic_session_factory() as session:
        with pytest.raises(InterfaceMigrationError, match="invalid data_json"):
            build_interface_migration_plan(session)
