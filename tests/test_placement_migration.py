from __future__ import annotations

import json

import pytest

from blockwart.db.session import transaction
from blockwart.models import AuditEvent, CatalogObject, Relationship
from blockwart.services.placement_migration import (
    PlacementMigrationError,
    apply_placement_migration_plan,
    build_placement_migration_plan,
)


def _object(
    object_id: str,
    kind: str,
    *,
    placement: dict[str, str] | None = None,
) -> CatalogObject:
    data = {"schema_version": 1}
    if placement is not None:
        data["placement"] = placement
    return CatalogObject(
        id=object_id,
        kind=kind,
        label=object_id,
        status="active",
        lifecycle="active",
        health="unknown",
        data_json=json.dumps(data, sort_keys=True),
    )


def test_placement_plan_marks_missing_parent_decisions_and_is_idempotent(
    alembic_session_factory,
) -> None:
    with alembic_session_factory() as session:
        session.add_all(
            [
                _object("hardware", "host"),
                _object("runtime", "system"),
                _object("api", "service"),
            ]
        )
        session.add(
            Relationship(
                from_ref="host:hardware",
                relation_type="hosts",
                to_ref="system:runtime",
            )
        )
        session.commit()

    with alembic_session_factory() as session:
        first = build_placement_migration_plan(session)
        second = build_placement_migration_plan(session)
        assert first == second
        assert first.scanned_assets == 2
        assert first.assigned_refs == ("system:runtime",)
        assert first.unassigned_refs == ("service:api",)
        assert [(item.object_id, item.action) for item in first.changes] == [
            ("api", "mark_unassigned")
        ]
        assert first.diagnostics == ()

        with transaction(session):
            assert apply_placement_migration_plan(session, first) == 1

    with alembic_session_factory() as session:
        data = json.loads(session.get(CatalogObject, "api").data_json)
        assert data["placement"] == {
            "state": "unassigned",
            "reason": "No canonical placement parent has been assigned.",
        }
        audit = session.query(AuditEvent).one()
        assert audit.action == "placement_state_normalize"
        assert audit.actor == "placement-migration"
        repeated = build_placement_migration_plan(session)
        assert repeated.changed_objects == 0
        assert repeated.unassigned_refs == ("service:api",)


def test_placement_plan_clears_contradictory_marker_for_assigned_asset(
    alembic_session_factory,
) -> None:
    with alembic_session_factory() as session:
        session.add_all(
            [
                _object("hardware", "host"),
                _object(
                    "api",
                    "service",
                    placement={"state": "unassigned", "reason": "Pending"},
                ),
            ]
        )
        session.add(
            Relationship(
                from_ref="host:hardware",
                relation_type="hosts",
                to_ref="service:api",
            )
        )
        session.commit()

    with alembic_session_factory() as session:
        plan = build_placement_migration_plan(session)
        assert [(item.object_id, item.action) for item in plan.changes] == [
            ("api", "clear_unassigned")
        ]
        with transaction(session):
            apply_placement_migration_plan(session, plan)

    with alembic_session_factory() as session:
        assert "placement" not in json.loads(
            session.get(CatalogObject, "api").data_json
        )


def test_placement_apply_rejects_stale_plan_and_rolls_back(
    alembic_session_factory,
) -> None:
    with alembic_session_factory() as session:
        session.add_all(
            [
                _object("first", "service"),
                _object("second", "service"),
            ]
        )
        session.commit()

    with alembic_session_factory() as session:
        plan = build_placement_migration_plan(session)

    with alembic_session_factory() as session:
        second = session.get(CatalogObject, "second")
        second.label = "changed concurrently"
        second.data_json = json.dumps(
            {
                "schema_version": 1,
                "placement": {"state": "unassigned", "reason": "Manual"},
            }
        )
        session.commit()

    with alembic_session_factory() as session:
        with pytest.raises(PlacementMigrationError, match="changed after planning"):
            with transaction(session):
                apply_placement_migration_plan(session, plan)

    with alembic_session_factory() as session:
        assert "placement" not in json.loads(
            session.get(CatalogObject, "first").data_json
        )
        assert session.query(AuditEvent).count() == 0


def test_placement_plan_rejects_invalid_metadata(
    alembic_session_factory,
) -> None:
    with alembic_session_factory() as session:
        session.add(
            _object(
                "invalid",
                "service",
                placement={"state": "assigned"},
            )
        )
        session.commit()

    with alembic_session_factory() as session:
        plan = build_placement_migration_plan(session)
        assert [item.code for item in plan.diagnostics] == [
            "invalid_placement_metadata"
        ]
        with pytest.raises(PlacementMigrationError, match="contains integrity"):
            apply_placement_migration_plan(session, plan)
