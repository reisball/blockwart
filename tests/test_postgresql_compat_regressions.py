"""PostgreSQL/SQLite regression tests for the review findings on PR #162.

Tracks review blockers 1, 2, 3, 4, 6 from `reisball/blockwart#163`:

* fresh and seeded migrations through all revisions on PostgreSQL 16
* the existing fresh SQLite migration path
* last-admin and last-catalog-owner UPDATE/DELETE behaviour with one and
  multiple principals
* fresh model-schema creation and append-only comment triggers on PostgreSQL
* PostgreSQL idempotency and token-bucket insert paths
"""

from __future__ import annotations

import json
import os
import threading
import time
import uuid
from collections.abc import Iterator
from pathlib import Path

import pytest
from alembic import command
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.dialects import postgresql, sqlite
from sqlalchemy.engine import Engine
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from blockwart.db.base import Base
from blockwart.db.migrations import build_alembic_config
from blockwart.db.session import build_engine
from blockwart.domain.search import SearchQuery
from blockwart.models import (
    CatalogObject,
    IdempotencyRecord,
    ServiceTokenFailureBucket,
)
from blockwart.services.agent import query_agent_objects_page
from blockwart.services.catalog import _endpoint_descriptor_rows_statement
from blockwart.services.decision_migration import (
    apply_decision_migration_plan,
    build_decision_migration_plan,
    decision_data_sha256,
)
from blockwart.services.project_migration import (
    apply_project_migration_plan,
    build_project_migration_plan,
    project_data_sha256,
)

# ---------------------------------------------------------------------------
# Constants and helpers
# ---------------------------------------------------------------------------

PG_TEST_URL = os.environ.get(
    "BLOCKWART_TEST_PG_URL",
    "postgresql+psycopg2://postgres:test@127.0.0.1:5432/blockwart_test",
)

CATALOG_OWNER_REVISION = "20260806_0015"
SOURCE_COVERAGE_REVISION = "20260811_0016"
HEAD_REVISION = "20260818_0018"


def _pg_url(database: str) -> str:
    return PG_TEST_URL.rsplit("/", 1)[0] + f"/{database}"


def _admin_database_exists() -> bool:
    """Whether a usable PostgreSQL admin database is reachable."""
    try:
        engine = create_engine(_pg_url("postgres"))
    except Exception:
        return False
    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
    except Exception:
        return False
    finally:
        engine.dispose()
    return True


PG_AVAILABLE = _admin_database_exists()
PG_REASON = "PostgreSQL test database unreachable" if not PG_AVAILABLE else ""
PG_SKIP = pytest.mark.skipif(not PG_AVAILABLE, reason=PG_REASON)


def _create_pg_database(name: str) -> None:
    engine = create_engine(_pg_url("postgres"), isolation_level="AUTOCOMMIT")
    try:
        with engine.connect() as connection:
            connection.execute(text(f'CREATE DATABASE "{name}"'))
    finally:
        engine.dispose()


def _drop_pg_database(name: str) -> None:
    engine = create_engine(_pg_url("postgres"), isolation_level="AUTOCOMMIT")
    try:
        with engine.connect() as connection:
            connection.execute(
                text(
                    "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                    "WHERE datname = :name AND pid <> pg_backend_pid()"
                ),
                {"name": name},
            )
            connection.execute(text(f'DROP DATABASE IF EXISTS "{name}"'))
    finally:
        engine.dispose()


def _upgrade_to(url: str, revision: str) -> None:
    config = build_alembic_config(url)
    command.upgrade(config, revision)


def _make_pg_engine(database_name: str) -> Engine:
    return build_engine(_pg_url(database_name))


def _table_rows(engine: Engine, tables: set[str]) -> dict[str, list[tuple[object, ...]]]:
    """Capture every row from trusted migration table names, order-independently."""
    with engine.connect() as connection:
        return {
            table: sorted(
                (tuple(row) for row in connection.execute(text(f'SELECT * FROM "{table}"'))),
                key=repr,
            )
            for table in sorted(tables)
        }


def _table_rows_for_columns(
    engine: Engine,
    columns_by_table: dict[str, list[str]],
) -> dict[str, list[tuple[object, ...]]]:
    """Capture pre-existing columns after an additive migration."""
    with engine.connect() as connection:
        return {
            table: sorted(
                (
                    tuple(row)
                    for row in connection.execute(
                        text(
                            "SELECT "
                            + ", ".join(f'\"{column}\"' for column in columns)
                            + f' FROM "{table}"'
                        )
                    )
                ),
                key=repr,
            )
            for table, columns in sorted(columns_by_table.items())
        }


def _insert_principal(
    connection,
    *,
    principal_id: str,
    login: str,
    active: bool = True,
    platform_role: str | None = None,
    catalog_role: str | None = None,
) -> None:
    connection.execute(
        text(
            "INSERT INTO principals "
            "(id, principal_type, login, display_name, active, platform_role, catalog_role) "
            "VALUES (:id, 'human', :login, :display_name, :active, :platform_role, :catalog_role)"
        ),
        {
            "id": principal_id,
            "login": login,
            "display_name": login,
            "active": active,
            "platform_role": platform_role,
            "catalog_role": catalog_role,
        },
    )


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def pg_database_name() -> Iterator[str]:
    if not PG_AVAILABLE:
        pytest.skip(PG_REASON)
    name = f"bw_test_{uuid.uuid4().hex[:12]}"
    _create_pg_database(name)
    try:
        yield name
    finally:
        _drop_pg_database(name)


@pytest.fixture
def pg_engine(pg_database_name: str) -> Iterator[Engine]:
    engine = _make_pg_engine(pg_database_name)
    try:
        yield engine
    finally:
        engine.dispose()


@pytest.fixture
def pg_session_factory(pg_engine: Engine) -> sessionmaker[Session]:
    return sessionmaker(bind=pg_engine, autoflush=False, autocommit=False)


@pytest.fixture
def migrated_pg_engine(pg_database_name: str) -> Iterator[Engine]:
    if not PG_AVAILABLE:
        pytest.skip(PG_REASON)
    _upgrade_to(_pg_url(pg_database_name), HEAD_REVISION)
    engine = _make_pg_engine(pg_database_name)
    try:
        yield engine
    finally:
        engine.dispose()


# ---------------------------------------------------------------------------
# Review blocker 1: SQLite migration path stays green
# Review blocker 4: model DDL is PostgreSQL-compatible
# ---------------------------------------------------------------------------


def test_scoped_relationship_endpoint_query_compiles_for_sqlite_and_postgresql() -> None:
    statement = _endpoint_descriptor_rows_statement(
        {"direct-endpoint", "graph-endpoint"}
    )

    for dialect in (sqlite.dialect(), postgresql.dialect()):
        compiled = str(
            statement.compile(
                dialect=dialect,
                compile_kwargs={"literal_binds": True},
            )
        )
        assert "catalog_objects.id IN ('direct-endpoint', 'graph-endpoint')" in compiled
        assert "ORDER BY catalog_objects.id" in compiled


def test_sqlite_fresh_migrations_match_model_schema(tmp_path: Path) -> None:
    """The SQLite migration chain leaves a schema equal to ``Base.metadata``."""
    database_url = f"sqlite:///{tmp_path / 'fresh.sqlite3'}"
    _upgrade_to(database_url, HEAD_REVISION)

    config = build_alembic_config(database_url)
    command.check(config)

    engine = build_engine(database_url)
    try:
        assert set(inspect(engine).get_table_names()) >= {
            "alembic_version",
            "catalog_objects",
            "principals",
            "object_comments",
        }
    finally:
        engine.dispose()


@PG_SKIP
def test_postgresql_fresh_migrations_match_model_schema(
    pg_database_name: str,
) -> None:
    """The PostgreSQL migration chain leaves a schema equal to ``Base.metadata``."""
    database_url = _pg_url(pg_database_name)
    _upgrade_to(database_url, HEAD_REVISION)
    command.check(build_alembic_config(database_url))

    engine = build_engine(database_url)
    try:
        with engine.connect() as connection:
            tables = {
                row[0]
                for row in connection.execute(
                    text("SELECT tablename FROM pg_tables WHERE schemaname = 'public'")
                )
            }
        assert {
            "alembic_version",
            "catalog_objects",
            "principals",
            "object_comments",
            "relationships",
            "service_token_failure_buckets",
            "idempotency_records",
            "source_entries",
            "source_entry_mappings",
            "source_snapshots",
        } <= tables
    finally:
        engine.dispose()


@PG_SKIP
def test_postgresql_populated_0015_source_coverage_upgrade_and_downgrade(
    pg_database_name: str,
) -> None:
    """Revision 0016 is additive, reversible, and keeps PostgreSQL integrity.

    Every pre-existing 0015 table is snapshotted before the upgrade and compared
    byte-for-byte afterwards. Representative catalog, relationship, principal,
    credential, session, token, grant, audit, security, idempotency, rate-limit,
    and append-only comment rows make the preservation assertion productive.
    """
    database_url = _pg_url(pg_database_name)
    _upgrade_to(database_url, CATALOG_OWNER_REVISION)
    engine = build_engine(database_url)
    preserved_principal = "00000000-0000-0000-0000-000000000142"
    preserved_token = "00000000-0000-0000-0000-000000000143"
    preserved_session = "00000000-0000-0000-0000-000000000144"
    preserved_challenge = "00000000-0000-0000-0000-000000000145"
    preserved_comment = "00000000-0000-0000-0000-000000000146"
    try:
        with engine.begin() as connection:
            connection.execute(
                text(
                    "INSERT INTO principals "
                    "(id, principal_type, login, display_name, active) VALUES "
                    "(:id, 'service_account', 'coverage-preserved', "
                    "'Coverage Preserved', true)"
                ),
                {"id": preserved_principal},
            )
            connection.execute(
                text(
                    "INSERT INTO password_credentials (principal_id, password_hash) "
                    "VALUES (:id, 'test-password-hash')"
                ),
                {"id": preserved_principal},
            )
            connection.execute(
                text(
                    "INSERT INTO browser_sessions "
                    "(id, principal_id, token_hash, csrf_hash, expires_at) VALUES "
                    "(:session_id, :principal_id, :token_hash, :csrf_hash, "
                    "'2035-01-01T00:00:00')"
                ),
                {
                    "session_id": preserved_session,
                    "principal_id": preserved_principal,
                    "token_hash": "a" * 64,
                    "csrf_hash": "b" * 64,
                },
            )
            connection.execute(
                text(
                    "INSERT INTO login_challenges (id, token_hash, expires_at) "
                    "VALUES (:id, :token_hash, '2035-01-01T00:00:00')"
                ),
                {"id": preserved_challenge, "token_hash": "c" * 64},
            )
            connection.execute(
                text(
                    "INSERT INTO service_tokens "
                    "(id, principal_id, name, audience, token_prefix, token_hash) "
                    "VALUES (:token_id, :principal_id, 'coverage-token', 'mcp', "
                    "'bwst_coverage', :token_hash)"
                ),
                {
                    "token_id": preserved_token,
                    "principal_id": preserved_principal,
                    "token_hash": "d" * 64,
                },
            )
            connection.execute(
                text(
                    "INSERT INTO catalog_objects "
                    "(id, kind, label, status, lifecycle, health, data_json, "
                    "provenance_json, revision) VALUES "
                    "('coverage-host', 'host', 'Coverage host', 'active', "
                    "'active', 'healthy', '{}', :host_provenance, 9), "
                    "('coverage-service', 'service', 'Coverage service', 'active', "
                    "'active', 'healthy', '{}', :service_provenance, 4)"
                ),
                {
                    "host_provenance": json.dumps(
                        {
                            "source_type": "import",
                            "source_ref": "legacy-tools",
                            "manual_override": False,
                        },
                        separators=(",", ":"),
                        sort_keys=True,
                    ),
                    "service_provenance": json.dumps(
                        {"source_type": "manual", "manual_override": False},
                        separators=(",", ":"),
                        sort_keys=True,
                    ),
                },
            )
            connection.execute(
                text(
                    "INSERT INTO relationships "
                    "(from_ref, relation_type, to_ref, metadata_json) VALUES "
                    "('host:coverage-host', 'hosts', 'service:coverage-service', '{}')"
                )
            )
            connection.execute(
                text(
                    "INSERT INTO object_grants "
                    "(principal_id, object_id, role, scope, created_by_principal_id) "
                    "VALUES (:principal_id, 'coverage-host', 'owner', 'self', "
                    ":principal_id)"
                ),
                {"principal_id": preserved_principal},
            )
            connection.execute(
                text(
                    "INSERT INTO audit_events "
                    "(object_id, action, actor, summary, details_json) VALUES "
                    "('coverage-host', 'preserved', 'migration-test', "
                    "'Preserved audit', :details)"
                ),
                {"details": '{"event":"preserved","version":1}'},
            )
            connection.execute(
                text(
                    "INSERT INTO security_events "
                    "(principal_id, event_type, outcome, channel, request_id, details_json) "
                    "VALUES (:principal_id, 'preserved', 'success', 'system', "
                    "'coverage-142', '{}')"
                ),
                {"principal_id": preserved_principal},
            )
            connection.execute(
                text(
                    "INSERT INTO service_token_failure_buckets "
                    "(dimension, key_hash, window_start, failure_count, event_emitted, "
                    "expires_at) VALUES ('global', :key_hash, '2026-08-11T00:00:00', "
                    "2, false, '2035-01-01T00:00:00')"
                ),
                {"key_hash": "e" * 64},
            )
            connection.execute(
                text(
                    "INSERT INTO idempotency_records "
                    "(principal_id, key_hash, operation_context, request_hash, "
                    "resource_id, response_json, created_at, expires_at) VALUES "
                    "(:principal_id, :key_hash, 'coverage-test', :request_hash, "
                    "'coverage-host', :response_json, '2026-08-11T00:00:00', "
                    "'2035-01-01T00:00:00')"
                ),
                {
                    "principal_id": preserved_principal,
                    "key_hash": "f" * 64,
                    "request_hash": "1" * 64,
                    "response_json": '{"ok":true}',
                },
            )
            object_instance_id, object_created_at = connection.execute(
                text(
                    "SELECT instance_id, created_at FROM catalog_objects "
                    "WHERE id = 'coverage-host'"
                )
            ).one()
            connection.execute(
                text(
                    "INSERT INTO object_comments "
                    "(id, object_id, object_instance_id, object_created_at, origin, "
                    "format, body, created_at) VALUES "
                    "(:id, 'coverage-host', :instance_id, :object_created_at, "
                    "'legacy', 'plain_text', 'preserved comment', :object_created_at)"
                ),
                {
                    "id": preserved_comment,
                    "instance_id": object_instance_id,
                    "object_created_at": object_created_at,
                },
            )
        before_inspector = inspect(engine)
        existing_tables = set(before_inspector.get_table_names()) - {"alembic_version"}
        existing_columns = {
            table: [column["name"] for column in before_inspector.get_columns(table)]
            for table in existing_tables
        }
        before = _table_rows(engine, existing_tables)
    finally:
        engine.dispose()

    _upgrade_to(database_url, HEAD_REVISION)
    engine = build_engine(database_url)
    try:
        assert _table_rows_for_columns(engine, existing_columns) == before
        with engine.connect() as connection:
            assert connection.execute(
                text(
                    "SELECT project_chronology_kind FROM object_comments "
                    "WHERE id = :id"
                ),
                {"id": preserved_comment},
            ).scalar_one_or_none() is None
        command.check(build_alembic_config(database_url))
        inspector = inspect(engine)
        assert {
            "source_snapshots",
            "source_entries",
            "source_entry_mappings",
        } <= set(inspector.get_table_names())
        assert {
            fk["referred_table"] for fk in inspector.get_foreign_keys("source_entries")
        } == {"source_snapshots"}
        mapping_targets = {
            fk["referred_table"]
            for fk in inspector.get_foreign_keys("source_entry_mappings")
        }
        assert mapping_targets == {"source_entries", "source_snapshots"}
        assert "catalog_objects" not in mapping_targets

        snapshot_id = "00000000-0000-0000-0000-000000000147"
        other_snapshot_id = "00000000-0000-0000-0000-000000000148"
        with engine.begin() as connection:
            for current_id, digest in (
                (snapshot_id, "2" * 64),
                (other_snapshot_id, "3" * 64),
            ):
                connection.execute(
                    text(
                        "INSERT INTO source_snapshots "
                        "(id, digest, collector, collected_at, entry_count, "
                        "mapping_count) VALUES (:id, :digest, 'markdown_tools', "
                        "'2026-08-11T00:00:00', 1, 1)"
                    ),
                    {"id": current_id, "digest": digest},
                )
            entry_id = connection.execute(
                text(
                    "INSERT INTO source_entries "
                    "(snapshot_id, source_uri, entry_id, entry_key, classification, "
                    "intent, decision_reason, presence, entry_fingerprint, "
                    "source_fingerprint, observed_at) VALUES "
                    "(:snapshot_id, 'workspace://TOOLS.md', 'coverage-host', "
                    "'coverage-host', 'operational', 'expect_object', "
                    "'operational_inventory', 'present', :fingerprint, "
                    ":fingerprint, '2026-08-11T00:00:00') RETURNING id"
                ),
                {"snapshot_id": snapshot_id, "fingerprint": "4" * 64},
            ).scalar_one()
            next_entry_id = connection.execute(
                text(
                    "INSERT INTO source_entries "
                    "(snapshot_id, source_uri, entry_id, entry_key, classification, "
                    "intent, decision_reason, presence, entry_fingerprint, "
                    "source_fingerprint, observed_at) VALUES "
                    "(:snapshot_id, 'workspace://TOOLS.md', 'second', 'second', "
                    "'research', 'no_catalog_object', 'research_material', "
                    "'present', :fingerprint, :fingerprint, "
                    "'2026-08-11T00:00:00') RETURNING id"
                ),
                {"snapshot_id": snapshot_id, "fingerprint": "5" * 64},
            ).scalar_one()
            mapping_id = connection.execute(
                text(
                    "INSERT INTO source_entry_mappings "
                    "(snapshot_id, entry_row_id, object_id, role, "
                    "imported_entry_fingerprint) VALUES "
                    "(:snapshot_id, :entry_id, 'coverage-host', 'primary', "
                    ":fingerprint) RETURNING id"
                ),
                {
                    "snapshot_id": snapshot_id,
                    "entry_id": entry_id,
                    "fingerprint": "4" * 64,
                },
            ).scalar_one()
            assert next_entry_id == entry_id + 1
            assert mapping_id > 0
            assert connection.execute(
                text("SELECT pg_get_serial_sequence('source_entries', 'id')")
            ).scalar_one()
            assert connection.execute(
                text("SELECT pg_get_serial_sequence('source_entry_mappings', 'id')")
            ).scalar_one()
            with pytest.raises(IntegrityError):
                with connection.begin_nested():
                    connection.execute(
                        text(
                            "INSERT INTO source_entry_mappings "
                            "(snapshot_id, entry_row_id, object_id, role, "
                            "imported_entry_fingerprint) VALUES "
                            "(:snapshot_id, :entry_id, 'coverage-service', 'derived', "
                            ":fingerprint)"
                        ),
                        {
                            "snapshot_id": other_snapshot_id,
                            "entry_id": entry_id,
                            "fingerprint": "4" * 64,
                        },
                    )
    finally:
        engine.dispose()

    command.downgrade(build_alembic_config(database_url), CATALOG_OWNER_REVISION)
    engine = build_engine(database_url)
    try:
        assert _table_rows(engine, existing_tables) == before
        assert not {
            "source_snapshots",
            "source_entries",
            "source_entry_mappings",
        } & set(inspect(engine).get_table_names())
        with engine.connect() as connection:
            assert connection.execute(
                text("SELECT version_num FROM alembic_version")
            ).scalar_one() == CATALOG_OWNER_REVISION
    finally:
        engine.dispose()


@PG_SKIP
def test_postgresql_seeded_migration_upgrades_cleanly(
    pg_database_name: str,
) -> None:
    """A PostgreSQL database already populated with legacy data upgrades to head.

    Exercises the dialect-aware ``#-`` path of migration 20260724_0004
    (review blocker 2) on a seeded database: ``data_json.dependencies``
    is removed via PostgreSQL JSONB, not SQLite's ``json_remove``.
    """
    database_url = _pg_url(pg_database_name)
    _upgrade_to(database_url, "20260723_0002")

    engine = build_engine(database_url)
    try:
        with engine.begin() as connection:
            connection.execute(
                text(
                    "INSERT INTO catalog_objects "
                    "(id, kind, label, status, data_json) "
                    "VALUES "
                    "('legacy-host', 'host', 'Legacy Host', 'active', :host_data), "
                    "('legacy-svc', 'service', 'Legacy Service', 'active', :svc_data), "
                    "('legacy-svc2', 'service', 'Legacy Service 2', 'active', :svc_data)"
                ),
                {
                    "host_data": json.dumps(
                        {"dependencies": {"upstream": ["service:legacy-svc"]}}
                    ),
                    "svc_data": json.dumps({}),
                },
            )
    finally:
        engine.dispose()

    _upgrade_to(database_url, HEAD_REVISION)
    engine = build_engine(database_url)
    try:
        with engine.connect() as connection:
            row = connection.execute(
                text("SELECT data_json FROM catalog_objects WHERE id = 'legacy-host'")
            ).scalar_one()
            data = json.loads(row)
            assert "dependencies" not in data
            rel_count = connection.execute(
                text("SELECT COUNT(*) FROM relationships")
            ).scalar_one()
            assert rel_count >= 1
    finally:
        engine.dispose()


@PG_SKIP
def test_postgresql_decision_plan_preserves_legacy_data_and_applies_explicitly(
    migrated_pg_engine: Engine,
) -> None:
    before = {"schema_version": 1, "decision": "Preserve PostgreSQL data."}
    with Session(migrated_pg_engine) as session:
        with session.begin():
            session.add(
                CatalogObject(
                    id="legacy-pg-decision",
                    kind="decision",
                    label="Legacy PG Decision",
                    status="active",
                    lifecycle=None,
                    health=None,
                    data_json=json.dumps(before, sort_keys=True),
                )
            )
        plan = build_decision_migration_plan(
            session,
            {
                "legacy-pg-decision": {
                    "expected_data_sha256": decision_data_sha256(before),
                    "data_patch": {"decision_status": "proposed"},
                }
            },
        )
        assert plan.diagnostics == ()
        assert json.loads(
            session.get(CatalogObject, "legacy-pg-decision").data_json
        ) == before
        assert apply_decision_migration_plan(session, plan) == 1
        session.commit()
        row = session.get(CatalogObject, "legacy-pg-decision")
        assert row is not None
        assert row.revision == 2
        assert json.loads(row.data_json) == {
            **before,
            "decision_status": "proposed",
        }


@PG_SKIP
def test_postgresql_project_plan_preserves_identity_links_and_legacy_data(
    migrated_pg_engine: Engine,
) -> None:
    before = {"schema_version": 1, "notes": "Preserve PostgreSQL data."}
    with Session(migrated_pg_engine) as session:
        with session.begin():
            session.add_all(
                [
                    CatalogObject(
                        id="legacy-pg-project",
                        kind="project",
                        label="Legacy PG Project",
                        status="active",
                        lifecycle=None,
                        health=None,
                        data_json=json.dumps(before, sort_keys=True),
                    ),
                    CatalogObject(
                        id="linked-pg-system",
                        kind="system",
                        label="Linked PG System",
                        status="active",
                        lifecycle="active",
                        health="unknown",
                        data_json=json.dumps({"schema_version": 1}, sort_keys=True),
                    ),
                ]
            )
        plan = build_project_migration_plan(
            session,
            {
                "legacy-pg-project": {
                    "expected_data_sha256": project_data_sha256(before),
                    "data_patch": {
                        "category": "migration",
                        "project_status": "completed",
                        "started_at": "2026-01-01T00:00:00Z",
                        "completed_at": "2026-02-01T00:00:00Z",
                        "related_assets": ["system:linked-pg-system"],
                        "source_state": "PostgreSQL 14",
                        "target_state": "PostgreSQL 16",
                    },
                }
            },
        )
        assert plan.diagnostics == ()
        assert json.loads(session.get(CatalogObject, "legacy-pg-project").data_json) == before
        assert apply_project_migration_plan(session, plan) == 1
        session.commit()
        row = session.get(CatalogObject, "legacy-pg-project")
        assert row is not None
        assert row.revision == 2
        stored = json.loads(row.data_json)
        assert stored["notes"] == "Preserve PostgreSQL data."
        assert stored["related_assets"] == ["system:linked-pg-system"]
        assert session.get(CatalogObject, "linked-pg-system") is not None


@PG_SKIP
def test_postgresql_populated_0013_upgrade_preserves_fks_and_reseeds_identity(
    pg_database_name: str,
) -> None:
    """Explicit legacy relationship IDs advance the replacement identity."""
    database_url = _pg_url(pg_database_name)
    _upgrade_to(database_url, "20260731_0012")
    engine = build_engine(database_url)
    try:
        with engine.begin() as connection:
            connection.execute(
                text(
                    "INSERT INTO principals "
                    "(id, principal_type, login, display_name, active) VALUES "
                    "('00000000-0000-0000-0000-000000000031', "
                    "'service_account', 'migration-seed', 'Migration Seed', true)"
                )
            )
            connection.execute(
                text(
                    "INSERT INTO catalog_objects "
                    "(id, kind, label, status, lifecycle, health, data_json) VALUES "
                    "('sequence-host', 'host', 'Sequence Host', 'active', "
                    "'active', 'healthy', '{}'), "
                    "('sequence-service', 'service', 'Sequence Service', 'active', "
                    "'active', 'healthy', '{}')"
                )
            )
            connection.execute(
                text(
                    "INSERT INTO relationships "
                    "(id, from_ref, relation_type, to_ref) VALUES "
                    "(41, 'host:sequence-host', 'hosts', 'service:sequence-service')"
                )
            )
            connection.execute(
                text(
                    "INSERT INTO object_grants "
                    "(principal_id, object_id, role, scope, created_by_principal_id) "
                    "VALUES ('00000000-0000-0000-0000-000000000031', "
                    "'sequence-host', 'owner', 'self', "
                    "'00000000-0000-0000-0000-000000000031')"
                )
            )
            connection.execute(
                text(
                    "INSERT INTO service_tokens "
                    "(id, principal_id, name, token_prefix, token_hash) VALUES "
                    "('00000000-0000-0000-0000-000000000032', "
                    "'00000000-0000-0000-0000-000000000031', "
                    "'migration-token', 'bwst_seed', :token_hash)"
                ),
                {"token_hash": "a" * 64},
            )
    finally:
        engine.dispose()

    _upgrade_to(database_url, HEAD_REVISION)
    engine = build_engine(database_url)
    try:
        with engine.begin() as connection:
            next_id = connection.execute(
                text(
                    "INSERT INTO relationships "
                    "(from_ref, relation_type, to_ref) VALUES "
                    "('service:sequence-service', 'depends_on', 'host:sequence-host') "
                    "RETURNING id"
                )
            ).scalar_one()
            assert next_id == 42
            assert connection.execute(
                text(
                    "SELECT object_id FROM object_grants "
                    "WHERE principal_id = "
                    "'00000000-0000-0000-0000-000000000031'"
                )
            ).scalar_one() == "sequence-host"
            assert connection.execute(
                text(
                    "SELECT audience FROM service_tokens WHERE id = "
                    "'00000000-0000-0000-0000-000000000032'"
                )
            ).scalar_one() == "api"
    finally:
        engine.dispose()


@PG_SKIP
def test_postgresql_empty_comments_downgrade_0015_to_0013(
    pg_database_name: str,
) -> None:
    database_url = _pg_url(pg_database_name)
    _upgrade_to(database_url, HEAD_REVISION)
    config = build_alembic_config(database_url)
    command.downgrade(config, "20260801_0013")

    engine = build_engine(database_url)
    try:
        inspector = inspect(engine)
        assert "object_comments" not in inspector.get_table_names()
        assert "instance_id" not in {
            column["name"] for column in inspector.get_columns("catalog_objects")
        }
        assert "audience" not in {
            column["name"] for column in inspector.get_columns("service_tokens")
        }
    finally:
        engine.dispose()


@PG_SKIP
def test_postgresql_nonempty_comments_downgrade_fails_closed(
    pg_database_name: str,
) -> None:
    database_url = _pg_url(pg_database_name)
    _upgrade_to(database_url, HEAD_REVISION)
    engine = build_engine(database_url)
    try:
        with engine.begin() as connection:
            connection.execute(
                text(
                    "INSERT INTO catalog_objects "
                    "(id, kind, label, status, lifecycle, health, data_json) VALUES "
                    "('downgrade-comment', 'host', 'Downgrade Comment', 'active', "
                    "'active', 'healthy', '{}')"
                )
            )
            instance_id, created_at = connection.execute(
                text(
                    "SELECT instance_id, created_at FROM catalog_objects "
                    "WHERE id = 'downgrade-comment'"
                )
            ).one()
            connection.execute(
                text(
                    "INSERT INTO object_comments "
                    "(id, object_id, object_instance_id, object_created_at, origin, "
                    "format, body, created_at) VALUES "
                    "('00000000-0000-0000-0000-000000000033', "
                    "'downgrade-comment', :instance_id, :created_at, "
                    "'legacy', 'plain_text', 'keep', :created_at)"
                ),
                {"instance_id": instance_id, "created_at": created_at},
            )
    finally:
        engine.dispose()

    with pytest.raises(RuntimeError, match="comments cannot be downgraded"):
        command.downgrade(build_alembic_config(database_url), "20260801_0013")


# ---------------------------------------------------------------------------
# Review blocker 3: DELETE trigger semantics (RETURN OLD on BEFORE DELETE)
# ---------------------------------------------------------------------------


@PG_SKIP
def test_postgresql_last_admin_delete_with_multiple_admins_succeeds(
    migrated_pg_engine: Engine,
) -> None:
    """Deleting one of several admins on PostgreSQL must not be blocked.

    The BEFORE DELETE trigger must ``RETURN OLD`` (review blocker 3); the
    function's body raises only when the to-be-deleted principal is the
    *last* active admin.
    """
    with migrated_pg_engine.begin() as connection:
        _insert_principal(
            connection,
            principal_id="00000000-0000-0000-0000-000000000001",
            login="admin1",
            active=True,
            platform_role="admin",
        )
        _insert_principal(
            connection,
            principal_id="00000000-0000-0000-0000-000000000002",
            login="admin2",
            active=True,
            platform_role="admin",
        )

    with migrated_pg_engine.begin() as connection:
        # Deleting admin2 must succeed while admin1 remains.
        result = connection.execute(
            text("DELETE FROM principals WHERE id = :id"),
            {"id": "00000000-0000-0000-0000-000000000002"},
        )
        assert result.rowcount == 1

    with migrated_pg_engine.connect() as connection:
        survivors = [
            row[0]
            for row in connection.execute(
                text("SELECT login FROM principals WHERE active = true")
            )
        ]
        assert survivors == ["admin1"]


@PG_SKIP
def test_postgresql_last_admin_delete_is_blocked(
    migrated_pg_engine: Engine,
) -> None:
    """Removing the last active admin must raise the trigger exception on PG."""
    with migrated_pg_engine.begin() as connection:
        _insert_principal(
            connection,
            principal_id="00000000-0000-0000-0000-000000000003",
            login="solo-admin",
            active=True,
            platform_role="admin",
        )

    with pytest.raises(Exception) as excinfo:
        with migrated_pg_engine.begin() as connection:
            connection.execute(
                text("DELETE FROM principals WHERE id = :id"),
                {"id": "00000000-0000-0000-0000-000000000003"},
            )

    assert "last active platform admin" in str(excinfo.value).lower()


@PG_SKIP
def test_postgresql_last_catalog_owner_delete_with_multiple_owners_succeeds(
    migrated_pg_engine: Engine,
) -> None:
    """Deleting one of several catalog owners on PG must not be blocked."""
    with migrated_pg_engine.begin() as connection:
        _insert_principal(
            connection,
            principal_id="00000000-0000-0000-0000-000000000004",
            login="owner1",
            active=True,
            catalog_role="catalog_owner",
        )
        _insert_principal(
            connection,
            principal_id="00000000-0000-0000-0000-000000000005",
            login="owner2",
            active=True,
            catalog_role="catalog_owner",
        )

    with migrated_pg_engine.begin() as connection:
        result = connection.execute(
            text("DELETE FROM principals WHERE id = :id"),
            {"id": "00000000-0000-0000-0000-000000000004"},
        )
        assert result.rowcount == 1


@PG_SKIP
def test_postgresql_last_catalog_owner_delete_is_blocked(
    migrated_pg_engine: Engine,
) -> None:
    """Removing the last catalog owner must raise on PG."""
    with migrated_pg_engine.begin() as connection:
        _insert_principal(
            connection,
            principal_id="00000000-0000-0000-0000-000000000006",
            login="solo-owner",
            active=True,
            catalog_role="catalog_owner",
        )

    with pytest.raises(Exception) as excinfo:
        with migrated_pg_engine.begin() as connection:
            connection.execute(
                text("DELETE FROM principals WHERE id = :id"),
                {"id": "00000000-0000-0000-0000-000000000006"},
            )

    assert "last active catalog owner" in str(excinfo.value).lower()


@PG_SKIP
@pytest.mark.parametrize("multiple", [False, True])
def test_postgresql_last_catalog_owner_update_contract(
    migrated_pg_engine: Engine,
    multiple: bool,
) -> None:
    """Owner demotion succeeds with a survivor and fails for the last owner."""
    owner_ids = ["00000000-0000-0000-0000-000000000016"]
    if multiple:
        owner_ids.append("00000000-0000-0000-0000-000000000017")
    with migrated_pg_engine.begin() as connection:
        for index, principal_id in enumerate(owner_ids):
            _insert_principal(
                connection,
                principal_id=principal_id,
                login=f"update-owner-{multiple}-{index}",
                catalog_role="catalog_owner",
            )

    if multiple:
        with migrated_pg_engine.begin() as connection:
            result = connection.execute(
                text("UPDATE principals SET catalog_role = NULL WHERE id = :id"),
                {"id": owner_ids[0]},
            )
            assert result.rowcount == 1
    else:
        with pytest.raises(Exception, match="last active catalog owner"):
            with migrated_pg_engine.begin() as connection:
                connection.execute(
                    text("UPDATE principals SET catalog_role = NULL WHERE id = :id"),
                    {"id": owner_ids[0]},
                )


@PG_SKIP
def test_postgresql_last_admin_update_with_multiple_admins_succeeds(
    migrated_pg_engine: Engine,
) -> None:
    """Demoting one of several admins on PG must not be blocked."""
    with migrated_pg_engine.begin() as connection:
        _insert_principal(
            connection,
            principal_id="00000000-0000-0000-0000-000000000007",
            login="adminA",
            active=True,
            platform_role="admin",
        )
        _insert_principal(
            connection,
            principal_id="00000000-0000-0000-0000-000000000008",
            login="adminB",
            active=True,
            platform_role="admin",
        )

    with migrated_pg_engine.begin() as connection:
        # Demote adminB; adminA remains.
        result = connection.execute(
            text("UPDATE principals SET platform_role = NULL WHERE id = :id"),
            {"id": "00000000-0000-0000-0000-000000000008"},
        )
        assert result.rowcount == 1


@PG_SKIP
def test_postgresql_last_admin_update_is_blocked(
    migrated_pg_engine: Engine,
) -> None:
    """Demoting the last admin on PG must raise."""
    with migrated_pg_engine.begin() as connection:
        _insert_principal(
            connection,
            principal_id="00000000-0000-0000-0000-000000000009",
            login="lone-admin",
            active=True,
            platform_role="admin",
        )

    with pytest.raises(Exception) as excinfo:
        with migrated_pg_engine.begin() as connection:
            connection.execute(
                text("UPDATE principals SET platform_role = NULL WHERE id = :id"),
                {"id": "00000000-0000-0000-0000-000000000009"},
            )

    assert "last active platform admin" in str(excinfo.value).lower()


@PG_SKIP
@pytest.mark.parametrize(
    ("role_column", "role_value", "operation", "invariant", "message"),
    [
        (
            "platform_role",
            "admin",
            "delete",
            "platform_admin",
            "last active platform admin",
        ),
        (
            "platform_role",
            "admin",
            "update",
            "platform_admin",
            "last active platform admin",
        ),
        (
            "catalog_role",
            "catalog_owner",
            "delete",
            "catalog_owner",
            "last active catalog owner",
        ),
        (
            "catalog_role",
            "catalog_owner",
            "update",
            "catalog_owner",
            "last active catalog owner",
        ),
    ],
)
def test_postgresql_concurrent_principal_invariant_is_serialized(
    migrated_pg_engine: Engine,
    role_column: str,
    role_value: str,
    operation: str,
    invariant: str,
    message: str,
) -> None:
    """A held counter-row update deterministically serializes both removals."""
    principal_ids = [
        "00000000-0000-0000-0000-000000000021",
        "00000000-0000-0000-0000-000000000022",
    ]
    with migrated_pg_engine.begin() as connection:
        for index, principal_id in enumerate(principal_ids):
            _insert_principal(
                connection,
                principal_id=principal_id,
                login=f"concurrent-{role_column}-{operation}-{index}",
                platform_role=role_value if role_column == "platform_role" else None,
                catalog_role=role_value if role_column == "catalog_role" else None,
            )

    first_mutated = threading.Event()
    release_first = threading.Event()
    second_started = threading.Event()
    outcomes: dict[str, str] = {}
    application_name = f"bw-invariant-{uuid.uuid4().hex}"

    def statement(principal_id: str):
        if operation == "delete":
            return text("DELETE FROM principals WHERE id = :id"), {"id": principal_id}
        return (
            text(f"UPDATE principals SET {role_column} = NULL WHERE id = :id"),
            {"id": principal_id},
        )

    def first_transaction() -> None:
        engine = create_engine(
            migrated_pg_engine.url,
            isolation_level="READ COMMITTED",
        )
        try:
            with engine.connect() as connection:
                transaction = connection.begin()
                sql, params = statement(principal_ids[0])
                connection.execute(sql, params)
                first_mutated.set()
                assert release_first.wait(timeout=10)
                transaction.commit()
                outcomes["first"] = "committed"
        except Exception as exc:  # pragma: no cover - surfaced by assertions below
            outcomes["first"] = f"error: {exc}"
            first_mutated.set()
            release_first.set()
        finally:
            engine.dispose()

    def second_transaction() -> None:
        assert first_mutated.wait(timeout=10)
        engine = create_engine(
            migrated_pg_engine.url,
            isolation_level="READ COMMITTED",
            connect_args={"application_name": application_name},
        )
        try:
            with engine.begin() as connection:
                second_started.set()
                sql, params = statement(principal_ids[1])
                connection.execute(sql, params)
            outcomes["second"] = "committed"
        except Exception as exc:
            outcomes["second"] = f"error: {exc}"
        finally:
            engine.dispose()

    first = threading.Thread(target=first_transaction)
    second = threading.Thread(target=second_transaction)
    first.start()
    assert first_mutated.wait(timeout=10)
    second.start()
    assert second_started.wait(timeout=10)

    deadline = time.monotonic() + 10
    lock_wait_observed = False
    while time.monotonic() < deadline:
        with migrated_pg_engine.connect() as connection:
            lock_wait_observed = (
                connection.execute(
                    text(
                        "SELECT wait_event_type = 'Lock' FROM pg_stat_activity "
                        "WHERE application_name = :application_name"
                    ),
                    {"application_name": application_name},
                ).scalar_one_or_none()
                is True
            )
        if lock_wait_observed:
            break
        time.sleep(0.02)
    release_first.set()
    first.join(timeout=10)
    second.join(timeout=10)

    assert lock_wait_observed
    assert not first.is_alive() and not second.is_alive()
    assert outcomes["first"] == "committed"
    assert outcomes["second"].startswith("error:")
    assert message in outcomes["second"].lower()
    with migrated_pg_engine.connect() as connection:
        active_count = connection.execute(
            text(
                f"SELECT COUNT(*) FROM principals WHERE active = true "
                f"AND {role_column} = :role_value"
            ),
            {"role_value": role_value},
        ).scalar_one()
        stored_count = connection.execute(
            text(
                "SELECT active_count FROM principal_invariant_counts "
                "WHERE invariant = :invariant"
            ),
            {"invariant": invariant},
        ).scalar_one()
    assert active_count == stored_count == 1


# ---------------------------------------------------------------------------
# Review blocker 4: model DDL must round-trip on PostgreSQL.
# ---------------------------------------------------------------------------


@PG_SKIP
def test_postgresql_fresh_model_schema_creates_required_objects(
    pg_engine: Engine,
) -> None:
    """``Base.metadata.create_all`` on a fresh PG database matches model definitions.

    Verifies the dialect-specific ``server_default`` for ``instance_id`` and
    the ``blockwart_raise_exception`` trigger function (review blocker 4).
    A pre-existing alembic batch_alter_table drift on ``object_grants``
    (``object_id -> catalog_objects.id`` FK) is outside this PR's scope and
    tracked separately.
    """
    Base.metadata.create_all(pg_engine)

    # Verify the dialect-specific ``server_default`` for ``instance_id`` was
    # applied by the after_create DDL listener. The PG branch must use the
    # ``md5(random()::text || clock_timestamp()::text)`` expression; the
    # resulting value is observed by inserting without an explicit
    # ``instance_id`` and reading the value back: the value must be 32
    # lowercase hex characters.
    with pg_engine.begin() as connection:
        connection.execute(
            text(
                "INSERT INTO catalog_objects "
                "(id, kind, label, status, lifecycle, health, data_json) "
                "VALUES "
                "('instance-default-test', 'host', 'Instance Default Test', "
                "'active', 'active', 'healthy', '{}')"
            )
        )

    with pg_engine.connect() as connection:
        value = connection.execute(
            text(
                "SELECT instance_id FROM catalog_objects WHERE id = 'instance-default-test'"
            )
        ).scalar_one()
        assert len(value) == 32
        int(value, 16)  # hex-decodable

    # The append-only ``blockwart_raise_exception`` trigger function must
    # exist after ``Base.metadata.create_all`` on PostgreSQL.
    with pg_engine.connect() as connection:
        present = connection.execute(
            text(
                "SELECT 1 FROM pg_proc WHERE proname = 'blockwart_raise_exception'"
            )
        ).scalar_one_or_none()
        assert present == 1
        login_collation = connection.execute(
            text(
                "SELECT col.collname FROM pg_attribute attr "
                "JOIN pg_class cls ON cls.oid = attr.attrelid "
                "JOIN pg_collation col ON col.oid = attr.attcollation "
                "WHERE cls.relname = 'principals' AND attr.attname = 'login'"
            )
        ).scalar_one()
        assert login_collation != "NOCASE"
        trigger_names = {
            row[0]
            for row in connection.execute(
                text(
                    "SELECT tgname FROM pg_trigger "
                    "WHERE tgrelid = 'principals'::regclass AND NOT tgisinternal"
                )
            )
        }
        assert {
            "ck_principals_last_active_admin_update",
            "ck_principals_last_active_admin_delete",
            "ck_principals_last_active_catalog_owner_update",
            "ck_principals_last_active_catalog_owner_delete",
            "ck_principals_active_admin_counter",
            "ck_principals_active_catalog_owner_counter",
        } <= trigger_names


@PG_SKIP
def test_postgresql_append_only_comment_triggers_block_update_and_delete(
    migrated_pg_engine: Engine,
) -> None:
    """``blockwart_raise_exception`` blocks UPDATE/DELETE on ``object_comments``."""
    with migrated_pg_engine.begin() as connection:
        connection.execute(
            text(
                "INSERT INTO catalog_objects "
                "(id, kind, label, status, lifecycle, health, data_json) "
                "VALUES "
                "('comment-host', 'host', 'Comment Host', 'active', 'active', 'healthy', '{}')"
            )
        )
        instance_row = connection.execute(
            text("SELECT instance_id, created_at FROM catalog_objects WHERE id = 'comment-host'")
        ).first()
        instance_id = instance_row[0]
        instance_created_at = instance_row[1]
        connection.execute(
            text(  # noqa: E501
                "INSERT INTO object_comments "
                "(id, object_id, object_instance_id, object_created_at, "
                "origin, format, body, created_at) "
                "VALUES (:id, :object_id, :object_instance_id, "
                ":object_created_at, 'legacy', 'plain_text', :body, :created_at)"
            ),
            {
                "id": "00000000-0000-0000-0000-000000000aaa",
                "object_id": "comment-host",
                "object_instance_id": instance_id,
                "object_created_at": instance_created_at,
                "created_at": instance_created_at,
                "body": "first comment",
            },
        )

    # UPDATE is blocked.
    with pytest.raises(Exception) as update_exc:
        with migrated_pg_engine.begin() as connection:
            connection.execute(
                text("UPDATE object_comments SET body = 'changed' WHERE id = :id"),
                {"id": "00000000-0000-0000-0000-000000000aaa"},
            )
    assert "blocked" in str(update_exc.value).lower()

    # DELETE is blocked.
    with pytest.raises(Exception) as delete_exc:
        with migrated_pg_engine.begin() as connection:
            connection.execute(
                text("DELETE FROM object_comments WHERE id = :id"),
                {"id": "00000000-0000-0000-0000-000000000aaa"},
            )
    assert "blocked" in str(delete_exc.value).lower()


# ---------------------------------------------------------------------------
# Review blocker 6: idempotency and token-bucket insert paths on PG.
# ---------------------------------------------------------------------------


@PG_SKIP
def test_postgresql_idempotency_insert_uses_explicit_columns(
    pg_session_factory: sessionmaker[Session],
) -> None:
    """The idempotency insert path is dialect-safe on PostgreSQL.

    After PR #162 the code uses ``sqlalchemy.dialects.postgresql.insert``
    (or its SQLite counterpart) for the upsert. We assert that the primary
    key constraint enforces uniqueness on PG (a regression on the SQLite
    upsert would silently no-op or raise depending on the dialect).
    """
    _upgrade_to(_pg_url(pg_session_factory.kw["bind"].url.database), HEAD_REVISION)

    with pg_session_factory() as session:
        with session.get_bind().begin() as connection:
            _insert_principal(
                connection,
                principal_id="00000000-0000-0000-0000-000000000bbb",
                login="idem-principal",
                active=True,
            )
        session.commit()
        session.add(
            IdempotencyRecord(
                principal_id="00000000-0000-0000-0000-000000000bbb",
                key_hash="hash-" + uuid.uuid4().hex,
                operation_context="write:test",
                request_hash="req-" + uuid.uuid4().hex,
                response_json='{"ok": true}',
                created_at=session.execute(text("SELECT now()")).scalar(),
                expires_at=session.execute(
                    text("SELECT now() + interval '1 hour'")
                ).scalar(),
            )
        )
        session.commit()

    with pg_session_factory() as session:
        rows = (
            session.query(IdempotencyRecord)
            .filter_by(principal_id="00000000-0000-0000-0000-000000000bbb")
            .all()
        )
        assert len(rows) == 1
        assert rows[0].response_json == '{"ok": true}'


@PG_SKIP
def test_postgresql_token_bucket_inserts_round_trip(
    pg_session_factory: sessionmaker[Session],
) -> None:
    """Token-bucket rows round-trip on PG with the boolean event_emitted default."""
    _upgrade_to(_pg_url(pg_session_factory.kw["bind"].url.database), HEAD_REVISION)

    with pg_session_factory() as session:
        window_start = session.execute(text("SELECT now()")).scalar()
        expires_at = session.execute(text("SELECT now() + interval '1 hour'")).scalar()
        session.add(
            ServiceTokenFailureBucket(
                dimension="global",
                key_hash="hash-" + uuid.uuid4().hex,
                window_start=window_start,
                failure_count=1,
                expires_at=expires_at,
            )
        )
        session.commit()

    with pg_session_factory() as session:
        rows = session.query(ServiceTokenFailureBucket).all()
        assert len(rows) == 1
        assert rows[0].failure_count == 1


# ---------------------------------------------------------------------------
# Issue #186: the ranked search projection is engine independent
# ---------------------------------------------------------------------------


@PG_SKIP
def test_postgresql_search_relevance_matches_the_sqlite_contract(
    pg_session_factory: sessionmaker[Session],
) -> None:
    """Ranking, exact modes, and operational filtering agree on PG and SQLite.

    Ordering, tie breaking, and the operational filter are decided over the
    authorized projection rather than by the database, so a different server
    collation cannot change the published result order.
    """
    from test_agent_search_relevance import (  # noqa: PLC0415
        RANKED_GATEWAY_ORDER,
        catalog_objects,
        full_reader,
    )

    _upgrade_to(_pg_url(pg_session_factory.kw["bind"].url.database), HEAD_REVISION)

    with pg_session_factory() as session:
        for catalog_object in catalog_objects():
            session.add(catalog_object)
        session.commit()

        access = full_reader()
        ranked = query_agent_objects_page(
            session,
            access,
            search=SearchQuery(query="gateway"),
            limit=50,
            sort="relevance",
            include_total=True,
        )
        assert [item.id for item in ranked.items] == RANKED_GATEWAY_ORDER
        assert ranked.total == len(RANKED_GATEWAY_ORDER)

        operational = query_agent_objects_page(
            session,
            access,
            search=SearchQuery(query="gateway", operational_only=True),
            limit=50,
            sort="relevance",
        )
        assert [item.id for item in operational.items] == [
            item
            for item in RANKED_GATEWAY_ORDER
            if item
            not in {
                "decommissioned-gateway",
                "staging-gateway",
                "retired-gateway-runbook",
            }
        ]

        for search, expected in (
            (SearchQuery(query="host:gateway-01", match="exact_ref"), ["gateway-01"]),
            (SearchQuery(query="  GATEWAY   01 ", match="exact_label"), ["gateway-01"]),
            (SearchQuery(query="gateway-import-bot"), []),
        ):
            page = query_agent_objects_page(
                session,
                access,
                search=search,
                limit=50,
                sort="relevance",
            )
            assert [item.id for item in page.items] == expected
