from __future__ import annotations

from pathlib import Path

from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.config import Config
from alembic.migration import MigrationContext
from alembic.script import ScriptDirectory
from sqlalchemy import inspect

from blockwart import models  # noqa: F401
from blockwart.config import get_settings
from blockwart.db.base import Base
from blockwart.db.session import build_engine

BASELINE_REVISION = "20260516_0001"
MIGRATIONS_DIR = Path(__file__).resolve().parents[1] / "migrations"
PROJECT_ALEMBIC_CONFIG = Path(__file__).resolve().parents[3] / "alembic.ini"


class DatabaseMigrationError(RuntimeError):
    """Stable public error for migration or revision failures."""


def build_alembic_config(database_url: str | None = None) -> Config:
    effective_url = database_url or get_settings().database_url
    config = Config(str(PROJECT_ALEMBIC_CONFIG) if PROJECT_ALEMBIC_CONFIG.exists() else None)
    config.set_main_option("script_location", str(MIGRATIONS_DIR))
    config.set_main_option("sqlalchemy.url", effective_url.replace("%", "%%"))
    config.attributes["database_url"] = effective_url
    return config


def upgrade_database(database_url: str | None = None) -> str:
    engine = None

    try:
        config = build_alembic_config(database_url)
        effective_url = str(config.attributes["database_url"])
        engine = build_engine(effective_url)
        with engine.connect() as connection:
            tables = set(inspect(connection).get_table_names())
            current_heads = set(MigrationContext.configure(connection).get_current_heads())

        user_tables = tables - {"alembic_version"}
        if user_tables and not current_heads:
            _adopt_unversioned_baseline(engine, config)

        command.upgrade(config, "head")
        return check_database_revision(effective_url)
    except DatabaseMigrationError:
        raise
    except Exception as exc:
        raise DatabaseMigrationError("Database migration failed") from exc
    finally:
        if engine is not None:
            engine.dispose()


def check_database_revision(database_url: str | None = None) -> str:
    engine = None

    try:
        config = build_alembic_config(database_url)
        effective_url = str(config.attributes["database_url"])
        expected_heads = set(ScriptDirectory.from_config(config).get_heads())
        engine = build_engine(effective_url)
        with engine.connect() as connection:
            current_heads = set(MigrationContext.configure(connection).get_current_heads())
    except DatabaseMigrationError:
        raise
    except Exception as exc:
        raise DatabaseMigrationError("Database revision check failed") from exc
    finally:
        if engine is not None:
            engine.dispose()

    if current_heads != expected_heads:
        raise DatabaseMigrationError("Database revision does not match the application")
    return next(iter(current_heads))


def _adopt_unversioned_baseline(engine, config: Config) -> None:
    with engine.connect() as connection:
        migration_context = MigrationContext.configure(
            connection,
            opts={"compare_type": True},
        )
        schema_differences = compare_metadata(migration_context, Base.metadata)

    if schema_differences:
        raise DatabaseMigrationError(
            "Unversioned database schema does not match the Blockwart baseline"
        )

    command.stamp(config, BASELINE_REVISION)
