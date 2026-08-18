from __future__ import annotations

import io
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Event

import pytest
from alembic import command
from sqlalchemy import event, text

from blockwart.cli import auth as auth_cli
from blockwart.config import Settings
from blockwart.db.migrations import BASELINE_REVISION, build_alembic_config, upgrade_database
from blockwart.db.readiness import DatabaseReadinessError, check_database_readiness
from blockwart.db.session import build_engine


def _database_url(path: Path) -> str:
    return f"sqlite:///{path}"


def test_sqlite_pragmas_apply_to_every_connection(tmp_path: Path) -> None:
    database_url = _database_url(tmp_path / "runtime.sqlite3")
    engine = build_engine(
        database_url,
        sqlite_busy_timeout_ms=750,
        sqlite_wal_enabled=True,
    )

    try:
        for _ in range(2):
            with engine.connect() as connection:
                assert connection.exec_driver_sql("PRAGMA foreign_keys").scalar_one() == 1
                assert connection.exec_driver_sql("PRAGMA busy_timeout").scalar_one() == 750
                assert connection.exec_driver_sql("PRAGMA journal_mode").scalar_one() == "wal"
    finally:
        engine.dispose()


def test_in_memory_sqlite_keeps_compatible_journal_mode() -> None:
    engine = build_engine(
        "sqlite:///:memory:",
        sqlite_busy_timeout_ms=600,
        sqlite_wal_enabled=True,
    )

    try:
        with engine.connect() as connection:
            assert connection.exec_driver_sql("PRAGMA foreign_keys").scalar_one() == 1
            assert connection.exec_driver_sql("PRAGMA busy_timeout").scalar_one() == 600
            assert connection.exec_driver_sql("PRAGMA journal_mode").scalar_one() == "memory"
    finally:
        engine.dispose()


def test_persistent_sqlite_can_explicitly_disable_wal(tmp_path: Path) -> None:
    database_url = _database_url(tmp_path / "delete-journal.sqlite3")
    engine = build_engine(
        database_url,
        sqlite_busy_timeout_ms=600,
        sqlite_wal_enabled=False,
    )

    try:
        with engine.connect() as connection:
            assert connection.exec_driver_sql("PRAGMA journal_mode").scalar_one() == "delete"
    finally:
        engine.dispose()


def test_wal_allows_reader_and_bounded_competing_writer(tmp_path: Path) -> None:
    database_url = _database_url(tmp_path / "concurrent.sqlite3")
    upgrade_database(database_url)
    engine = build_engine(
        database_url,
        sqlite_busy_timeout_ms=5000,
        sqlite_wal_enabled=True,
    )
    first_writer = engine.connect()
    first_writer.exec_driver_sql("BEGIN IMMEDIATE")
    first_writer.execute(
        text(
            "INSERT INTO audit_events (object_id, action, actor, summary) "
            "VALUES (NULL, 'first', 'test', 'first writer')"
        )
    )
    competing_writer_started = Event()

    @event.listens_for(engine, "before_cursor_execute")
    def mark_competing_writer_attempt(
        _connection,
        _cursor,
        statement,
        _parameters,
        _context,
        _executemany,
    ) -> None:
        if statement == "BEGIN IMMEDIATE":
            competing_writer_started.set()

    def competing_writer() -> None:
        with engine.connect() as connection:
            connection.exec_driver_sql("BEGIN IMMEDIATE")
            connection.execute(
                text(
                    "INSERT INTO audit_events (object_id, action, actor, summary) "
                    "VALUES (NULL, 'second', 'test', 'second writer')"
                )
            )
            connection.commit()

    try:
        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(competing_writer)
            assert competing_writer_started.wait(timeout=10)

            with engine.connect() as reader:
                assert reader.scalar(text("SELECT count(*) FROM audit_events")) == 0
            assert not future.done()

            first_writer.commit()
            future.result(timeout=10)

        with engine.connect() as connection:
            assert connection.scalar(text("SELECT count(*) FROM audit_events")) == 2
    finally:
        first_writer.close()
        engine.dispose()


def test_backup_restore_remains_readable_and_migratable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source_path = tmp_path / "source.sqlite3"
    restored_path = tmp_path / "restored.sqlite3"
    source_url = _database_url(source_path)
    restored_url = _database_url(restored_path)
    command.upgrade(build_alembic_config(source_url), BASELINE_REVISION)

    source_engine = build_engine(source_url)
    try:
        with source_engine.begin() as connection:
            connection.execute(
                text(
                    "INSERT INTO catalog_objects "
                    "(id, kind, label, status, data_json) "
                    "VALUES ('preserved', 'system', 'Preserved', 'active', :data_json)"
                ),
                {"data_json": '{"future_field":{"keep":true}}'},
            )
    finally:
        source_engine.dispose()

    with (
        sqlite3.connect(source_path) as source_connection,
        sqlite3.connect(restored_path) as restored_connection,
    ):
        source_connection.backup(restored_connection)

    assert upgrade_database(restored_url) == "20260818_0017"
    with pytest.raises(DatabaseReadinessError) as exc_info:
        check_database_readiness(Settings(database_url=restored_url))
    assert exc_info.value.code == "owner_coverage_incomplete"

    monkeypatch.setattr("sys.stdin", io.StringIO("restore bootstrap passphrase\n"))
    assert auth_cli.main(
        [
            "--database-url",
            restored_url,
            "bootstrap-owner",
            "--login",
            "restore.owner",
            "--display-name",
            "Restore Owner",
            "--object-id",
            "preserved",
            "--scope",
            "self",
            "--password-stdin",
            "--catalog-owner",
        ]
    ) == 0
    readiness = check_database_readiness(Settings(database_url=restored_url))
    restored_engine = build_engine(restored_url)
    try:
        with restored_engine.connect() as connection:
            assert connection.execute(
                text("SELECT data_json FROM catalog_objects WHERE id = 'preserved'")
            ).scalar_one() == '{"future_field":{"keep":true}}'
    finally:
        restored_engine.dispose()

    assert readiness.revision == "20260818_0017"
    assert set(readiness.checks.values()) == {"ok"}
