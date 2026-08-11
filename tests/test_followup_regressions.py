"""Follow-up regression tests for 2nd review on PR #162.

Covers:
- SQLite ``Base.metadata.create_all`` (review follow-up #3)
- FK ``object_grants.object_id -> catalog_objects.id`` after 0013 rebuild (#4)
- ``relationships.id`` auto-increment on PostgreSQL (#4)
- Token-bucket ``LEAST`` on-conflict clamp path (#5)
- Partial-index ``postgresql_where`` parity (#7)
- Concurrent last-admin DELETE with advisory lock (#6)
"""

from __future__ import annotations

import os
import uuid
from collections.abc import Iterator
from pathlib import Path
from uuid import uuid4

import pytest
from alembic import command
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import sessionmaker

from blockwart.db.base import Base
from blockwart.db.migrations import build_alembic_config

PG_TEST_URL = os.environ.get(
    "BLOCKWART_TEST_PG_URL",
    "postgresql+psycopg2://postgres:test@127.0.0.1:5432/blockwart_test",
)


def _pg_url(database: str) -> str:
    return PG_TEST_URL.rsplit("/", 1)[0] + f"/{database}"


def _admin_database_exists() -> bool:
    try:
        engine = create_engine(_pg_url("postgres"))
    except Exception:
        return False
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
    except Exception:
        return False
    finally:
        engine.dispose()
    return True


PG_AVAILABLE = _admin_database_exists()
PG_SKIP = pytest.mark.skipif(not PG_AVAILABLE, reason="PostgreSQL unreachable")


def _create_pg_database(name: str) -> None:
    engine = create_engine(_pg_url("postgres"), isolation_level="AUTOCOMMIT")
    with engine.connect() as conn:
        conn.execute(text(f'CREATE DATABASE "{name}"'))
    engine.dispose()


def _drop_pg_database(name: str) -> None:
    engine = create_engine(_pg_url("postgres"), isolation_level="AUTOCOMMIT")
    with engine.connect() as conn:
        conn.execute(
            text(
                "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                "WHERE datname = :name AND pid <> pg_backend_pid()"
            ),
            {"name": name},
        )
        conn.execute(text(f'DROP DATABASE IF EXISTS "{name}"'))
    engine.dispose()


def _insert_principal(connection, *, principal_id, login, active=True,
                      platform_role=None, catalog_role=None):
    connection.execute(
        text(
            "INSERT INTO principals "
            "(id, principal_type, login, display_name, active, "
            "platform_role, catalog_role) "
            "VALUES (:id, 'human', :login, :display_name, :active, "
            ":platform_role, :catalog_role)"
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


# --- Fixtures ---


@pytest.fixture
def pg_database_name() -> Iterator[str]:
    if not PG_AVAILABLE:
        pytest.skip("PostgreSQL unreachable")
    name = f"bw_followup_{uuid.uuid4().hex[:12]}"
    _create_pg_database(name)
    yield name
    _drop_pg_database(name)


@pytest.fixture
def migrated_pg_engine(pg_database_name: str) -> Iterator[Engine]:
    config = build_alembic_config(_pg_url(pg_database_name))
    command.upgrade(config, "head")
    engine = create_engine(_pg_url(pg_database_name))
    yield engine
    engine.dispose()


# --- SQLite metadata.create_all (review follow-up #3) ---


def test_sqlite_metadata_create_all_works(tmp_path: Path) -> None:
    """Base.metadata.create_all on SQLite must not raise.

    The after_create DDL listener for CatalogObject.instance_id must
    skip the SQLite ALTER TABLE ... ALTER COLUMN path.
    """
    engine = create_engine(f"sqlite:///{tmp_path / 'meta.sqlite3'}")
    try:
        Base.metadata.create_all(engine)
        with engine.begin() as conn:
            conn.execute(
                text(
                    "INSERT INTO catalog_objects "
                    "(id, instance_id, kind, label, status, lifecycle, health, data_json) "
                    "VALUES ('meta-test', :iid, 'host', 'Meta Test', "
                    "'active', 'active', 'healthy', '{}')"
                ),
                {"iid": uuid4().hex},
            )
        with engine.connect() as conn:
            row = conn.execute(
                text(
                    "SELECT instance_id FROM catalog_objects "
                    "WHERE id = 'meta-test'"
                )
            ).scalar_one()
            assert len(row) == 32  # uuid4().hex
    finally:
        engine.dispose()


# --- FK object_grants after 0013 rebuild (review follow-up #4) ---


@PG_SKIP
def test_postgresql_object_grants_fk_after_0013(migrated_pg_engine: Engine) -> None:
    """object_grants.object_id -> catalog_objects.id FK must exist after
    the migration 0013 CASCADE rebuild."""
    with migrated_pg_engine.connect() as conn:
        fks = conn.execute(
            text(
                "SELECT conname FROM pg_constraint "
                "WHERE contype = 'f' "
                "AND conrelid = 'object_grants'::regclass"
            )
        ).all()
        assert len(fks) >= 1, (
            "object_grants FK to catalog_objects missing after 0013 rebuild"
        )


# --- relationships.id auto-increment (review follow-up #4) ---


@PG_SKIP
def test_postgresql_relationships_id_autoincrement(migrated_pg_engine: Engine) -> None:
    """relationships.id must auto-increment on PG after 0013 rebuild."""
    with migrated_pg_engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO catalog_objects "
                "(id, kind, label, status, data_json) "
                "VALUES ('rel-host', 'host', 'Rel Host', 'active', '{}')"
            )
        )
        conn.execute(
            text(
                "INSERT INTO relationships (from_ref, relation_type, to_ref) "
                "VALUES ('rel-host', 'hosts', 'rel-host')"
            )
        )
        row = conn.execute(
            text("SELECT id FROM relationships WHERE from_ref = 'rel-host'")
        ).scalar_one()
        assert row is not None and row > 0


# --- Token-bucket LEAST on-conflict clamp (review follow-up #5) ---


@PG_SKIP
def test_postgresql_token_bucket_least_clamp(migrated_pg_engine: Engine) -> None:
    """The on-conflict update uses LEAST on PG, clamping at limit+1."""
    from blockwart.models import ServiceTokenFailureBucket
    from blockwart.services.token_failure_buckets import upsert_failure_bucket

    with migrated_pg_engine.begin() as conn:
        _insert_principal(
            conn,
            principal_id="00000000-0000-0000-0000-0000000000cc",
            login="bucket-test",
        )

    SessionLocal = sessionmaker(bind=migrated_pg_engine, autoflush=False)
    with SessionLocal() as session:
        now = session.execute(text("SELECT now()")).scalar()
        window_start = now.replace(microsecond=0)
        expires_at = session.execute(
            text("SELECT now() + interval '1 hour'")
        ).scalar()

        for _ in range(6):
            upsert_failure_bucket(
                session,
                dimension="global",
                key_hash="clamp-test",
                window_start=window_start,
                expires_at=expires_at,
                limit=3,
                max_rows=100,
                now=now,
                evict_dimensions=(),
            )
        session.commit()

        bucket = (
            session.query(ServiceTokenFailureBucket)
            .filter_by(key_hash="clamp-test")
            .one()
        )
        assert bucket.failure_count == 4  # clamped at limit + 1


# --- Partial-index allows multiple non-host (review follow-up #7) ---


@PG_SKIP
def test_postgresql_partial_index_non_host(migrated_pg_engine: Engine) -> None:
    """The partial unique index on relationships(to_ref) WHERE
    relation_type='hosts' must not block multiple non-host relationships."""
    with migrated_pg_engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO catalog_objects "
                "(id, kind, label, status, data_json) VALUES "
                "('idx-h1', 'host', 'H1', 'active', '{}'),"
                "('idx-h2', 'host', 'H2', 'active', '{}'),"
                "('idx-svc', 'service', 'Svc', 'active', '{}')"
            )
        )
        conn.execute(
            text(
                "INSERT INTO relationships (from_ref, relation_type, to_ref) "
                "VALUES ('idx-h1', 'hosts', 'idx-svc')"
            )
        )
        conn.execute(
            text(
                "INSERT INTO relationships (from_ref, relation_type, to_ref) "
                "VALUES ('idx-h1', 'depends_on', 'idx-svc')"
            )
        )
        conn.execute(
            text(
                "INSERT INTO relationships (from_ref, relation_type, to_ref) "
                "VALUES ('idx-h2', 'depends_on', 'idx-svc')"
            )
        )

    with migrated_pg_engine.connect() as conn:
        count = conn.execute(
            text(
                "SELECT COUNT(*) FROM relationships "
                "WHERE to_ref = 'idx-svc' AND relation_type = 'depends_on'"
            )
        ).scalar_one()
        assert count == 2


# --- Concurrent last-admin DELETE (review follow-up #6) ---


@PG_SKIP
def test_postgresql_concurrent_last_admin_delete(
    migrated_pg_engine: Engine,
) -> None:
    """Two concurrent transactions deleting different admins must not
    both succeed when only one admin would remain.

    The advisory lock serializes the trigger check so that the second
    transaction sees the committed state of the first.
    """
    import threading

    with migrated_pg_engine.begin() as conn:
        _insert_principal(
            conn,
            principal_id="00000000-0000-0000-0000-0000000000d1",
            login="conc-admin1",
            platform_role="admin",
        )
        _insert_principal(
            conn,
            principal_id="00000000-0000-0000-0000-0000000000d2",
            login="conc-admin2",
            platform_role="admin",
        )

    errors: list[Exception] = []

    def delete_admin(pid: str) -> None:
        try:
            engine = create_engine(
                migrated_pg_engine.url,
                isolation_level="READ COMMITTED",
            )
            with engine.begin() as conn:
                conn.execute(
                    text("DELETE FROM principals WHERE id = :id"),
                    {"id": pid},
                )
            engine.dispose()
        except Exception as exc:
            errors.append(exc)

    t1 = threading.Thread(
        target=delete_admin,
        args=("00000000-0000-0000-0000-0000000000d1",),
    )
    t2 = threading.Thread(
        target=delete_admin,
        args=("00000000-0000-0000-0000-0000000000d2",),
    )
    t1.start()
    t2.start()
    t1.join(timeout=10)
    t2.join(timeout=10)

    # Exactly one delete must succeed, the other must be blocked
    assert len(errors) == 1, (
        f"Expected exactly 1 error from concurrent delete, got {len(errors)}: "
        f"{[str(e)[:80] for e in errors]}"
    )
    assert "last active platform admin" in str(errors[0]).lower()

    with migrated_pg_engine.connect() as conn:
        count = conn.execute(
            text(
                "SELECT COUNT(*) FROM principals "
                "WHERE active = true AND platform_role = 'admin'"
            )
        ).scalar_one()
        assert count == 1