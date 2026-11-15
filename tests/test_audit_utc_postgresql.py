"""Native audit-clock regression for the explicit disposable PostgreSQL CI fixture.

Only BLOCKWART_TEST_PG_URL opts in; there is no default or ambient app DSN.
The configured database/user must be disposable and permit CREATE SCHEMA.
Each case uses a random schema in an outer transaction, rolled back even when
application helpers commit. No existing audit table or row is read or modified.
"""

import os
from collections.abc import Iterator
from datetime import UTC, datetime
from uuid import uuid4
from zoneinfo import ZoneInfo

import pytest
from sqlalchemy import create_engine, select, text
from sqlalchemy.engine import Connection, make_url
from sqlalchemy.orm import Session
from test_audit_utc import MOMENTS, _freeze, _write_paths

from blockwart.domain.timestamps import format_rfc3339_utc
from blockwart.models import AuditEvent


@pytest.fixture
def audit_pg_connection() -> Iterator[Connection]:
    """Open an explicitly configured disposable database with per-case isolation.

    Yields:
        Connection with a unique transactional audit schema and model mapping.
    """
    configured_url = os.environ.get("BLOCKWART_TEST_PG_URL")
    if configured_url is None:
        pytest.skip("BLOCKWART_TEST_PG_URL disposable PostgreSQL fixture not configured")
    assert configured_url, "An explicitly supplied PostgreSQL fixture URL must not be empty"
    url = make_url(configured_url)
    assert url.get_backend_name() == "postgresql"
    assert url.database and url.username, "Explicit fixture database and user required"
    host = url.query.get("host") or url.host
    assert isinstance(host, str) and host, "Explicit fixture host or Unix socket required"
    assert "service" not in url.query, "Ambient PostgreSQL service profiles are not a fixture"
    port = int(url.query.get("port") or url.port or 5432)
    engine = create_engine(url, connect_args={"host": host, "port": port})
    schema = "audit_utc_test_" + uuid4().hex
    try:
        with engine.connect() as connection:
            outer = connection.begin()
            try:
                assert connection.execute(
                    text("SELECT current_database(), current_user")
                ).one() == (url.database, url.username)
                connection.execute(text(f'CREATE SCHEMA "{schema}"'))
                connection.execute(text(f'SET LOCAL search_path TO "{schema}"'))
                assert connection.scalar(text("SELECT current_schema()")) == schema
                connection.execution_options(schema_translate_map={None: schema})
                AuditEvent.__table__.create(connection)
                yield connection
                assert outer.is_active, "Application commits must remain inside savepoints"
            finally:
                outer.rollback()
            assert (
                connection.scalar(
                    text("SELECT count(*) FROM pg_namespace WHERE nspname=:schema"),
                    {"schema": schema},
                )
                == 0
            )
            connection.rollback()
    finally:
        engine.dispose()


@pytest.mark.parametrize("timezone", ["UTC", "Europe/Berlin"])
@pytest.mark.parametrize("stamp,berlin", MOMENTS)
def test_pg_audit_writers_ignore_session_timezone(
    audit_pg_connection, monkeypatch, timezone, stamp, berlin
):
    """Preserve UTC instants and explicit history across native session timezones.

    Args:
        audit_pg_connection: Explicit disposable database with a private schema.
        monkeypatch: Deterministic application clock override.
        timezone: PostgreSQL session timezone, not a database/global setting.
        stamp: UTC winter, summer or DST-boundary instant.
        berlin: Expected Berlin local time and offset from the unchanged formatter.
    """
    connection = audit_pg_connection
    connection.execute(text("SELECT set_config('TimeZone', :zone, true)"), {"zone": timezone})
    assert connection.scalar(text("SHOW TimeZone")) == timezone
    old = datetime(2001, 1, 1, 9)
    moment = datetime.fromisoformat(stamp)
    _freeze(monkeypatch, moment)
    with Session(connection, join_transaction_mode="create_savepoint") as session:
        session.add(AuditEvent(action="historical", summary="kept", created_at=old))
        session.commit()
        historical = tuple(
            session.execute(
                select(AuditEvent.__table__).where(AuditEvent.action == "historical")
            ).one()
        )
        rows = _write_paths(session)
        assert len(rows) == 6
        assert {row.action for row in rows} == {
            "normal",
            "direct",
            "bulk-one",
            "bulk-two",
            "core",
            "legacy-bulk",
        }
        for row in rows:
            assert row.created_at.tzinfo is None
            assert row.created_at == moment
            formatted = format_rfc3339_utc(row.created_at)
            assert formatted == moment.isoformat(timespec="microseconds") + "Z"
            instant = datetime.fromisoformat(formatted)
            assert instant == moment.replace(tzinfo=UTC)
            assert instant.astimezone(ZoneInfo("Europe/Berlin")).strftime("%H:%M%z") == berlin
        session.expire_all()
        kept = session.scalar(select(AuditEvent).where(AuditEvent.action == "historical"))
        assert (
            tuple(
                session.execute(
                    select(AuditEvent.__table__).where(AuditEvent.action == "historical")
                ).one()
            )
            == historical
        )
        assert kept.created_at == old
        assert format_rfc3339_utc(kept.created_at) == "2001-01-01T09:00:00.000000Z"


def test_pg_fixture_skips_without_explicit_url(monkeypatch):
    """Refuse ambient app DSNs before any engine construction.

    Args:
        monkeypatch: Remove explicit opt-in and poison the connection entrypoint.
    """
    monkeypatch.delenv("BLOCKWART_TEST_PG_URL", raising=False)
    monkeypatch.setenv("BLOCKWART_DATABASE_URL", "postgresql://ambient.invalid/catalog")

    def unexpected_engine(*args, **kwargs):
        pytest.fail("No PostgreSQL engine may be created without explicit opt-in")

    monkeypatch.setitem(
        audit_pg_connection.__wrapped__.__globals__, "create_engine", unexpected_engine
    )
    with pytest.raises(pytest.skip.Exception, match="not configured"):
        next(audit_pg_connection.__wrapped__())


@pytest.mark.parametrize("url", ["", "sqlite:///:memory:", "postgresql:///missing_identity"])
def test_pg_fixture_rejects_invalid_explicit_url(monkeypatch, url):
    """Fail, rather than silently skip or use defaults, for invalid opt-in URLs.

    Args:
        monkeypatch: Set the explicit test-only URL and poison engine construction.
        url: Empty, non-PostgreSQL or incomplete fixture configuration.
    """
    monkeypatch.setenv("BLOCKWART_TEST_PG_URL", url)

    def unexpected_engine(*args, **kwargs):
        pytest.fail("Invalid fixture URL must be rejected before opening a connection")

    monkeypatch.setitem(
        audit_pg_connection.__wrapped__.__globals__, "create_engine", unexpected_engine
    )
    with pytest.raises(AssertionError):
        next(audit_pg_connection.__wrapped__())
