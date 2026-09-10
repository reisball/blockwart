from __future__ import annotations

import argparse
import json
import os
import re
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor

import pytest
from alembic import command
from sqlalchemy import create_engine, func, select, text
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session, sessionmaker

from blockwart.cli import owner_repair as owner_repair_cli
from blockwart.config import Settings
from blockwart.db.migrations import build_alembic_config, upgrade_database
from blockwart.db.readiness import DatabaseReadinessError, check_database_readiness
from blockwart.db.session import build_engine, transaction
from blockwart.domain.auth import CatalogRole, GrantScope, Role
from blockwart.models import (
    AuditEvent,
    CatalogObject,
    ObjectGrant,
    Principal,
    Relationship,
    SecurityEvent,
)
from blockwart.services.access import create_object_grant
from blockwart.services.audit import load_audit_details
from blockwart.services.identity import create_service_account
from blockwart.services.legacy_owner_repair import (
    LEGACY_OWNER_REPAIR_ACTION,
    LegacyOwnerRepairError,
)

REASON = "Adopt legacy catalog before startup"
REQUEST_ID = "legacy-owner-repair-0001"


def _setup_repair_state(database) -> dict[str, str]:
    with database.sessions() as session:
        with transaction(session):
            actor = create_service_account(
                session,
                login="repair.actor",
                display_name="Repair Actor",
                catalog_role=CatalogRole.CATALOG_OWNER,
            )
            target = create_service_account(
                session,
                login="repair.target",
                display_name="Repair Target",
            )
            viewer = create_service_account(
                session,
                login="repair.viewer",
                display_name="Repair Viewer",
            )
            inactive = create_service_account(
                session,
                login="repair.inactive",
                display_name="Repair Inactive",
            )
            session.get(Principal, inactive.id).active = False
            session.get(Principal, inactive.id).revision += 1
            session.add_all(
                [
                    CatalogObject(
                        id="healthy-host",
                        kind="host",
                        label="Healthy Host",
                        status="active",
                        lifecycle="active",
                        health="healthy",
                        data_json='{"schema_version":1}',
                    ),
                    CatalogObject(
                        id="legacy-project",
                        kind="project",
                        label="Legacy Project",
                        status="active",
                        summary="preserve project",
                        data_json='{"schema_version":1,"marker":"project"}',
                    ),
                    CatalogObject(
                        id="legacy-service",
                        kind="service",
                        label="Legacy Service",
                        status="active",
                        lifecycle="active",
                        health="degraded",
                        summary="preserve service",
                        data_json='{"schema_version":1,"marker":"service"}',
                    ),
                ]
            )
            session.flush()
            create_object_grant(
                session,
                principal_id=actor.id,
                object_id="healthy-host",
                role=Role.OWNER,
                scope=GrantScope.SELF,
                actor_principal_id=actor.id,
            )
            create_object_grant(
                session,
                principal_id=viewer.id,
                object_id="legacy-project",
                role=Role.VIEWER,
                scope=GrantScope.SELF,
                actor_principal_id=actor.id,
            )
            session.add(
                Relationship(
                    from_ref="host:healthy-host",
                    relation_type="supports",
                    to_ref="service:legacy-service",
                    metadata_json='{"marker":"preserve"}',
                )
            )
    return {
        "actor": actor.id,
        "target": target.id,
        "viewer": viewer.id,
        "inactive": inactive.id,
    }


def _arguments(database_url: str, **overrides: str | bool) -> list[str]:
    values: dict[str, str | bool] = {
        "actor_login": "repair.actor",
        "target_login": "repair.target",
        "reason": REASON,
        "request_id": REQUEST_ID,
        **overrides,
    }
    arguments = [
        "--database-url",
        database_url,
        "--actor-login",
        str(values["actor_login"]),
        "--target-login",
        str(values["target_login"]),
        "--reason",
        str(values["reason"]),
        "--request-id",
        str(values["request_id"]),
    ]
    if values.get("apply"):
        arguments.append("--apply")
        digest = values.get("expected_plan_digest")
        if digest:
            arguments.extend(["--expected-plan-digest", str(digest)])
    return arguments


def _plan_digest(output: str) -> str:
    match = re.search(r"plan_digest=([0-9a-f]{64})", output)
    assert match is not None
    return match.group(1)


def _namespace(database_url: str, digest: str) -> argparse.Namespace:
    return argparse.Namespace(
        database_url=database_url,
        actor_login="repair.actor",
        target_login="repair.target",
        reason=REASON,
        request_id=REQUEST_ID,
        apply=True,
        expected_plan_digest=digest,
    )


def test_preview_apply_readiness_audit_and_idempotent_rerun(
    alembic_database,
    capsys,
) -> None:
    ids = _setup_repair_state(alembic_database)
    with alembic_database.sessions() as session:
        grants_before = session.scalar(select(func.count()).select_from(ObjectGrant))
        audits_before = session.scalar(select(func.count()).select_from(AuditEvent))
        objects_before = {
            row.id: (
                row.kind,
                row.label,
                row.status,
                row.lifecycle,
                row.health,
                row.summary,
                row.data_json,
                row.instance_id,
                row.revision,
            )
            for row in session.scalars(select(CatalogObject)).all()
        }
        relationships_before = [
            (row.id, row.from_ref, row.relation_type, row.to_ref, row.metadata_json)
            for row in session.scalars(select(Relationship)).all()
        ]

    assert owner_repair_cli.main(_arguments(alembic_database.database_url)) == 0
    preview = capsys.readouterr().out
    object_lines = [
        json.loads(line.removeprefix("legacy_owner_repair_object "))
        for line in preview.splitlines()
        if line.startswith("legacy_owner_repair_object ")
    ]
    assert object_lines == [
        {
            "kind": "project",
            "object_id": "legacy-project",
            "ref": "project:legacy-project",
            "revision": objects_before["legacy-project"][-1],
        },
        {
            "kind": "service",
            "object_id": "legacy-service",
            "ref": "service:legacy-service",
            "revision": objects_before["legacy-service"][-1],
        },
    ]
    assert 'ownerless=2 counts_by_kind={"project":1,"service":1}' in preview
    digest = _plan_digest(preview)

    with alembic_database.sessions() as session:
        assert session.scalar(select(func.count()).select_from(ObjectGrant)) == grants_before
        assert session.scalar(select(func.count()).select_from(AuditEvent)) == audits_before
        assert {
            row.id: row.revision for row in session.scalars(select(CatalogObject)).all()
        } == {object_id: state[-1] for object_id, state in objects_before.items()}

    with pytest.raises(DatabaseReadinessError) as blocked:
        check_database_readiness(Settings(database_url=alembic_database.database_url))
    assert blocked.value.code == "owner_coverage_incomplete"

    assert owner_repair_cli.main(
        _arguments(
            alembic_database.database_url,
            apply=True,
            expected_plan_digest=digest,
        )
    ) == 0
    applied = capsys.readouterr().out
    assert "mode=apply repaired=2 remaining=0" in applied

    with alembic_database.sessions() as session:
        owner_grants = session.scalars(
            select(ObjectGrant)
            .where(
                ObjectGrant.object_id.in_(("legacy-project", "legacy-service")),
                ObjectGrant.role == Role.OWNER,
            )
            .order_by(ObjectGrant.object_id)
        ).all()
        assert [
            (grant.object_id, grant.principal_id, grant.scope, grant.created_by_principal_id)
            for grant in owner_grants
        ] == [
            ("legacy-project", ids["target"], GrantScope.SELF, ids["actor"]),
            ("legacy-service", ids["target"], GrantScope.SELF, ids["actor"]),
        ]
        objects_after = {
            row.id: (
                row.kind,
                row.label,
                row.status,
                row.lifecycle,
                row.health,
                row.summary,
                row.data_json,
                row.instance_id,
                row.revision,
            )
            for row in session.scalars(select(CatalogObject)).all()
        }
        for object_id, before in objects_before.items():
            expected_revision = before[-1] + (object_id.startswith("legacy-"))
            assert objects_after[object_id][:-1] == before[:-1]
            assert objects_after[object_id][-1] == expected_revision
        assert [
            (row.id, row.from_ref, row.relation_type, row.to_ref, row.metadata_json)
            for row in session.scalars(select(Relationship)).all()
        ] == relationships_before
        assert session.scalar(
            select(func.count()).select_from(ObjectGrant).where(
                ObjectGrant.principal_id == ids["viewer"],
                ObjectGrant.object_id == "legacy-project",
                ObjectGrant.role == Role.VIEWER,
            )
        ) == 1
        audit = session.scalar(
            select(AuditEvent).where(AuditEvent.action == LEGACY_OWNER_REPAIR_ACTION)
        )
        assert audit is not None
        details = load_audit_details(audit)
        assert details["actor_principal_id"] == ids["actor"]
        assert details["target_principal_id"] == ids["target"]
        assert details["reason"] == REASON
        assert details["request_id"] == REQUEST_ID
        assert details["object_ids"] == ["legacy-project", "legacy-service"]
        assert details["counts_by_kind"] == {"project": 1, "service": 1}
        event = session.scalar(
            select(SecurityEvent).where(
                SecurityEvent.event_type == LEGACY_OWNER_REPAIR_ACTION
            )
        )
        assert event is not None
        assert event.principal_id == ids["actor"]
        assert event.request_id == REQUEST_ID

    readiness = check_database_readiness(Settings(database_url=alembic_database.database_url))
    assert readiness.checks["authorization"] == "ok"

    assert owner_repair_cli.main(_arguments(alembic_database.database_url)) == 0
    empty_preview = capsys.readouterr().out
    assert "ownerless=0 counts_by_kind={}" in empty_preview
    empty_digest = _plan_digest(empty_preview)
    assert owner_repair_cli.main(
        _arguments(
            alembic_database.database_url,
            apply=True,
            expected_plan_digest=empty_digest,
        )
    ) == 0
    assert "mode=apply repaired=0 remaining=0" in capsys.readouterr().out
    with alembic_database.sessions() as session:
        assert session.scalar(
            select(func.count()).select_from(AuditEvent).where(
                AuditEvent.action == LEGACY_OWNER_REPAIR_ACTION
            )
        ) == 1
        assert session.scalar(
            select(func.count()).select_from(ObjectGrant).where(
                ObjectGrant.role == Role.OWNER,
                ObjectGrant.object_id.in_(("legacy-project", "legacy-service")),
            )
        ) == 2


@pytest.mark.parametrize(
    ("overrides", "error_code"),
    [
        ({"actor_login": "!"}, "repair_actor_malformed"),
        ({"actor_login": "missing.actor"}, "repair_actor_inactive"),
        ({"actor_login": "repair.viewer"}, "repair_actor_unauthorized"),
        ({"target_login": "!"}, "repair_target_malformed"),
        ({"target_login": "missing.target"}, "repair_target_inactive"),
        ({"target_login": "repair.inactive"}, "repair_target_inactive"),
        ({"reason": "   "}, "repair_reason_invalid"),
        ({"request_id": "not allowed"}, "repair_request_id_invalid"),
    ],
)
def test_invalid_principals_and_evidence_are_rejected_without_mutation(
    alembic_database,
    capsys,
    overrides: dict[str, str],
    error_code: str,
) -> None:
    _setup_repair_state(alembic_database)
    with alembic_database.sessions() as session:
        grants_before = session.scalar(select(func.count()).select_from(ObjectGrant))
        revisions_before = dict(
            session.execute(select(CatalogObject.id, CatalogObject.revision)).all()
        )

    assert owner_repair_cli.main(
        _arguments(alembic_database.database_url, **overrides)
    ) == 1
    assert f"legacy_owner_repair_error={error_code}" in capsys.readouterr().err
    with alembic_database.sessions() as session:
        assert session.scalar(select(func.count()).select_from(ObjectGrant)) == grants_before
        assert dict(
            session.execute(select(CatalogObject.id, CatalogObject.revision)).all()
        ) == revisions_before
        assert session.scalar(
            select(func.count()).select_from(AuditEvent).where(
                AuditEvent.action == LEGACY_OWNER_REPAIR_ACTION
            )
        ) == 0


@pytest.mark.parametrize("drift", ["catalog", "ownership"])
def test_apply_fails_closed_on_reviewed_plan_drift(
    alembic_database,
    capsys,
    drift: str,
) -> None:
    ids = _setup_repair_state(alembic_database)
    assert owner_repair_cli.main(_arguments(alembic_database.database_url)) == 0
    digest = _plan_digest(capsys.readouterr().out)

    with alembic_database.sessions() as session:
        with transaction(session):
            if drift == "catalog":
                row = session.get(CatalogObject, "legacy-service")
                row.label = "Changed after preview"
                row.revision += 1
            else:
                create_object_grant(
                    session,
                    principal_id=ids["actor"],
                    object_id="legacy-service",
                    role=Role.OWNER,
                    scope=GrantScope.SELF,
                    actor_principal_id=ids["actor"],
                )

    with alembic_database.sessions() as session:
        target_grants_before = session.scalar(
            select(func.count()).select_from(ObjectGrant).where(
                ObjectGrant.principal_id == ids["target"]
            )
        )
        revisions_before = dict(
            session.execute(select(CatalogObject.id, CatalogObject.revision)).all()
        )
    assert owner_repair_cli.main(
        _arguments(
            alembic_database.database_url,
            apply=True,
            expected_plan_digest=digest,
        )
    ) == 1
    assert "legacy_owner_repair_error=repair_plan_drift" in capsys.readouterr().err
    with alembic_database.sessions() as session:
        assert session.scalar(
            select(func.count()).select_from(ObjectGrant).where(
                ObjectGrant.principal_id == ids["target"]
            )
        ) == target_grants_before
        assert dict(
            session.execute(select(CatalogObject.id, CatalogObject.revision)).all()
        ) == revisions_before
        assert session.scalar(
            select(func.count()).select_from(AuditEvent).where(
                AuditEvent.action == LEGACY_OWNER_REPAIR_ACTION
            )
        ) == 0


def test_sqlite_concurrent_apply_has_one_winner_without_duplicates(
    alembic_database,
    capsys,
) -> None:
    ids = _setup_repair_state(alembic_database)
    assert owner_repair_cli.main(_arguments(alembic_database.database_url)) == 0
    digest = _plan_digest(capsys.readouterr().out)
    barrier = threading.Barrier(2)

    def attempt() -> str:
        barrier.wait(timeout=10)
        try:
            owner_repair_cli._apply(_namespace(alembic_database.database_url, digest))
        except (LegacyOwnerRepairError, OperationalError):
            return "drift"
        return "applied"

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = sorted(
            future.result(timeout=20)
            for future in [pool.submit(attempt) for _ in range(2)]
        )
    assert results == ["applied", "drift"]
    with alembic_database.sessions() as session:
        assert session.scalar(
            select(func.count()).select_from(ObjectGrant).where(
                ObjectGrant.principal_id == ids["target"],
                ObjectGrant.role == Role.OWNER,
            )
        ) == 2
        assert session.scalar(
            select(func.count()).select_from(AuditEvent).where(
                AuditEvent.action == LEGACY_OWNER_REPAIR_ACTION
            )
        ) == 1


def test_pre_owner_invariant_database_upgrades_then_repairs_before_readiness(
    tmp_path,
    capsys,
) -> None:
    database_url = f"sqlite:///{tmp_path / 'pre-owner-invariant.sqlite3'}"
    command.upgrade(build_alembic_config(database_url), "20260825_0021")
    engine = create_engine(database_url)
    actor_id = str(uuid.uuid4())
    target_id = str(uuid.uuid4())
    try:
        with Session(engine) as session:
            with transaction(session):
                session.add_all(
                    [
                        Principal(
                            id=actor_id,
                            principal_type="service_account",
                            login="repair.actor",
                            display_name="Repair Actor",
                            active=True,
                            catalog_role=CatalogRole.CATALOG_OWNER,
                        ),
                        Principal(
                            id=target_id,
                            principal_type="service_account",
                            login="repair.target",
                            display_name="Repair Target",
                            active=True,
                        ),
                        CatalogObject(
                            id="legacy-project",
                            instance_id=uuid.uuid4().hex,
                            kind="project",
                            label="Legacy Project",
                            status="active",
                            data_json='{"schema_version":1}',
                        ),
                    ]
                )
    finally:
        engine.dispose()

    upgrade_database(database_url)
    with pytest.raises(DatabaseReadinessError) as blocked:
        check_database_readiness(Settings(database_url=database_url))
    assert blocked.value.code == "owner_coverage_incomplete"
    assert owner_repair_cli.main(_arguments(database_url)) == 0
    digest = _plan_digest(capsys.readouterr().out)
    assert owner_repair_cli.main(
        _arguments(database_url, apply=True, expected_plan_digest=digest)
    ) == 0
    capsys.readouterr()
    assert check_database_readiness(Settings(database_url=database_url)).checks[
        "authorization"
    ] == "ok"


PG_TEST_URL = os.environ.get(
    "BLOCKWART_TEST_PG_URL",
    "postgresql+psycopg2://postgres:test@127.0.0.1:5432/blockwart_test",
)


def _pg_url(database: str) -> str:
    return PG_TEST_URL.rsplit("/", 1)[0] + f"/{database}"


def _pg_available() -> bool:
    try:
        engine = create_engine(_pg_url("postgres"))
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
        engine.dispose()
    except Exception:
        return False
    return True


@pytest.mark.skipif(not _pg_available(), reason="PostgreSQL test database unreachable")
def test_postgresql_concurrent_apply_is_atomic_and_fail_closed() -> None:
    name = f"bw_legacy_owner_repair_{uuid.uuid4().hex[:10]}"
    admin = create_engine(_pg_url("postgres"), isolation_level="AUTOCOMMIT")
    with admin.connect() as connection:
        connection.execute(text(f'CREATE DATABASE "{name}"'))
    engine = None
    try:
        url = _pg_url(name)
        upgrade_database(url)
        engine = build_engine(url)
        database = argparse.Namespace(
            database_url=url,
            sessions=sessionmaker(bind=engine, autoflush=False, autocommit=False),
        )
        ids = _setup_repair_state(database)
        preview_args = argparse.Namespace(
            database_url=url,
            actor_login="repair.actor",
            target_login="repair.target",
            reason=REASON,
            request_id=REQUEST_ID,
            apply=False,
            expected_plan_digest=None,
        )
        digest = owner_repair_cli._preview(preview_args).plan_digest
        barrier = threading.Barrier(2)

        def attempt() -> str:
            barrier.wait(timeout=10)
            try:
                owner_repair_cli._apply(_namespace(url, digest))
            except (LegacyOwnerRepairError, OperationalError):
                return "drift"
            return "applied"

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = sorted(
                future.result(timeout=30)
                for future in [pool.submit(attempt) for _ in range(2)]
            )
        assert results == ["applied", "drift"]
        with database.sessions() as session:
            assert session.scalar(
                select(func.count()).select_from(ObjectGrant).where(
                    ObjectGrant.principal_id == ids["target"],
                    ObjectGrant.role == Role.OWNER,
                )
            ) == 2
            assert session.scalar(
                select(func.count()).select_from(AuditEvent).where(
                    AuditEvent.action == LEGACY_OWNER_REPAIR_ACTION
                )
            ) == 1
    finally:
        if engine is not None:
            engine.dispose()
        with admin.connect() as connection:
            connection.execute(
                text(
                    "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                    "WHERE datname = :name AND pid <> pg_backend_pid()"
                ),
                {"name": name},
            )
            connection.execute(text(f'DROP DATABASE IF EXISTS "{name}"'))
        admin.dispose()
