from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from alembic.migration import MigrationContext
from alembic.script import ScriptDirectory
from sqlalchemy import make_url, text

from blockwart.config import Settings
from blockwart.db.migrations import build_alembic_config
from blockwart.db.session import build_engine

CHECK_NAMES = ("database", "schema", "writable", "sqlite")


@dataclass(frozen=True)
class DatabaseReadiness:
    revision: str
    checks: dict[str, str]


class DatabaseReadinessError(RuntimeError):
    def __init__(
        self,
        code: str,
        *,
        checks: dict[str, str],
        revision: str | None = None,
    ) -> None:
        super().__init__("Database readiness check failed")
        self.code = code
        self.checks = checks
        self.revision = revision


def check_database_readiness(settings: Settings) -> DatabaseReadiness:
    checks = {name: "unknown" for name in CHECK_NAMES}
    missing_path = _missing_sqlite_path(settings.database_url)
    if missing_path is not None:
        checks["database"] = "error"
        raise DatabaseReadinessError("database_missing", checks=checks)

    engine = None
    revision: str | None = None
    try:
        config = build_alembic_config(settings.database_url)
        expected_heads = set(ScriptDirectory.from_config(config).get_heads())
        engine = build_engine(
            settings.database_url,
            sqlite_busy_timeout_ms=settings.sqlite_busy_timeout_ms,
            sqlite_wal_enabled=settings.sqlite_wal_enabled,
        )
        with engine.connect() as connection:
            if connection.scalar(text("SELECT 1")) != 1:
                raise RuntimeError("Database SELECT probe failed")
            checks["database"] = "ok"

            current_heads = set(MigrationContext.configure(connection).get_current_heads())
            revision = ",".join(sorted(current_heads)) or None
            if current_heads != expected_heads:
                checks["schema"] = "error"
                raise DatabaseReadinessError(
                    "schema_revision_mismatch",
                    checks=checks,
                    revision=revision,
                )
            checks["schema"] = "ok"

            parsed_url = make_url(settings.database_url)
            if parsed_url.get_backend_name() == "sqlite":
                _verify_sqlite_runtime(connection, settings, checks)
            else:
                checks["sqlite"] = "not_applicable"

            connection.rollback()
            try:
                connection.exec_driver_sql("BEGIN IMMEDIATE")
                write_probe = connection.execute(
                    text(
                        "UPDATE alembic_version "
                        "SET version_num = :probe_revision "
                        "WHERE version_num = :current_revision"
                    ),
                    {
                        "probe_revision": "__blockwart_readiness_probe__",
                        "current_revision": revision,
                    },
                )
                if write_probe.rowcount != 1:
                    raise RuntimeError("Database write probe did not update the schema revision")
                connection.exec_driver_sql("ROLLBACK")
            except Exception as exc:
                connection.rollback()
                checks["writable"] = "error"
                raise DatabaseReadinessError(
                    "database_not_writable",
                    checks=checks,
                    revision=revision,
                ) from exc
            checks["writable"] = "ok"
    except DatabaseReadinessError:
        raise
    except Exception as exc:
        if checks["database"] == "unknown":
            checks["database"] = "error"
        raise DatabaseReadinessError(
            "database_unavailable",
            checks=checks,
            revision=revision,
        ) from exc
    finally:
        if engine is not None:
            engine.dispose()

    return DatabaseReadiness(revision=revision or "", checks=checks)


def _verify_sqlite_runtime(connection, settings: Settings, checks: dict[str, str]) -> None:
    foreign_keys = int(connection.exec_driver_sql("PRAGMA foreign_keys").scalar_one())
    busy_timeout_ms = int(connection.exec_driver_sql("PRAGMA busy_timeout").scalar_one())
    journal_mode = str(connection.exec_driver_sql("PRAGMA journal_mode").scalar_one()).lower()
    parsed_url = make_url(settings.database_url)
    persistent = _is_persistent_sqlite_database(parsed_url.database)

    expected_journal_mode = (
        ("wal" if settings.sqlite_wal_enabled else "delete") if persistent else None
    )
    configured = (
        foreign_keys == 1
        and busy_timeout_ms == settings.sqlite_busy_timeout_ms
        and (expected_journal_mode is None or journal_mode == expected_journal_mode)
    )
    if not configured:
        checks["sqlite"] = "error"
        raise DatabaseReadinessError("sqlite_configuration_invalid", checks=checks)
    checks["sqlite"] = "ok"


def _missing_sqlite_path(database_url: str) -> Path | None:
    parsed_url = make_url(database_url)
    if parsed_url.get_backend_name() != "sqlite":
        return None
    if not _is_persistent_sqlite_database(parsed_url.database):
        return None
    database_path = Path(str(parsed_url.database))
    return database_path if not database_path.exists() else None


def _is_persistent_sqlite_database(database: str | None) -> bool:
    if not database:
        return False
    normalized = database.lower()
    return normalized != ":memory:" and not normalized.startswith("file::memory:")
