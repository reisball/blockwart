"""Future audit timestamps are UTC-naive on every application insert path."""

from datetime import UTC, datetime
from zoneinfo import ZoneInfo

import pytest
from sqlalchemy import insert, select

import blockwart.models.catalog as catalog_models
import blockwart.services.knowledge_apply as knowledge_apply
from blockwart.domain.timestamps import format_rfc3339_utc
from blockwart.models import AuditEvent
from blockwart.services.audit import add_audit_event

MOMENTS = [
    ("2026-01-15T12:34:56.123456", "13:34+0100"),
    ("2026-07-15T12:34:56.123456", "14:34+0200"),
    ("2026-03-29T00:59:00", "01:59+0100"),
    ("2026-03-29T01:01:00", "03:01+0200"),
    ("2026-10-25T00:59:00", "02:59+0200"),
    ("2026-10-25T01:01:00", "02:01+0100"),
]


def _freeze(monkeypatch, value):
    class Frozen(datetime):
        @classmethod
        def now(cls, tz=None):
            assert tz is UTC
            return value.replace(tzinfo=UTC)

    monkeypatch.setattr(catalog_models, "datetime", Frozen)
    monkeypatch.setattr(knowledge_apply, "datetime", Frozen, raising=False)


def _write_paths(session):
    add_audit_event(session, object_id="visible", action="normal", actor="tester")
    session.add(AuditEvent(object_id="hidden", action="direct", summary="direct"))
    session.flush()
    session.execute(
        insert(AuditEvent),
        [
            {"object_id": "visible", "action": "bulk-one", "summary": "bulk"},
            {"object_id": "hidden", "action": "bulk-two", "summary": "bulk"},
        ],
    )
    session.execute(AuditEvent.__table__.insert().values(action="core", summary="core"))
    session.bulk_insert_mappings(AuditEvent, [{"action": "legacy-bulk", "summary": "bulk"}])
    session.commit()
    return session.scalars(select(AuditEvent).where(AuditEvent.action != "historical")).all()


@pytest.mark.parametrize("stamp,berlin", MOMENTS)
def test_sqlite_audit_writers_use_utc_without_rewriting_history(
    alembic_session_factory, monkeypatch, stamp, berlin
):
    """Check generated instants, explicit history and Berlin DST conversion.

    Args:
        alembic_session_factory: Owned migrated SQLite fixture.
        monkeypatch: Test clock override.
        stamp: Deterministic UTC wall time.
        berlin: Expected local time and offset.
    """
    moment = datetime.fromisoformat(stamp)
    old = datetime(2001, 1, 1, 9)
    with alembic_session_factory() as session:
        session.add(AuditEvent(action="historical", summary="kept", created_at=old))
        session.commit()
        _freeze(monkeypatch, moment)
        rows = _write_paths(session)
        assert len(rows) == 6
        assert all(row.created_at == moment and row.created_at.tzinfo is None for row in rows)
        assert (
            session.scalar(select(AuditEvent.created_at).where(AuditEvent.action == "historical"))
            == old
        )
        for row in rows:
            instant = datetime.fromisoformat(format_rfc3339_utc(row.created_at))
            assert instant == moment.replace(tzinfo=UTC)
            assert instant.astimezone(ZoneInfo("Europe/Berlin")).strftime("%H:%M%z") == berlin


def test_raw_candidate_rollback_supplies_utc(alembic_database, monkeypatch):
    """Exercise the SQLite-only raw rollback writer without touching real backups.

    Args:
        alembic_database: Owned migrated SQLite fixture.
        monkeypatch: Test clock override.
    """
    import sqlite3

    moment = datetime(2026, 7, 15, 12, 34, 56, 123456)
    _freeze(monkeypatch, moment)
    with sqlite3.connect(alembic_database.database_url.removeprefix("sqlite:///")) as conn:
        audit_id = knowledge_apply._insert_candidate_rollback_audit(conn, "fixture", {})
        value = conn.execute(
            "SELECT created_at FROM audit_events WHERE id=?", (audit_id,)
        ).fetchone()
    assert datetime.fromisoformat(value[0]) == moment
