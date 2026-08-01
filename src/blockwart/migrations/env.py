from contextlib import nullcontext
from logging.config import fileConfig
from os import environ

from alembic import context

from blockwart import models  # noqa: F401
from blockwart.db.base import Base
from blockwart.db.session import build_engine

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)


def _effective_database_url() -> str:
    explicit_url = config.attributes.get("database_url")
    if explicit_url:
        return str(explicit_url)
    return environ.get("BLOCKWART_DATABASE_URL") or config.get_main_option("sqlalchemy.url")


config.set_main_option("sqlalchemy.url", _effective_database_url().replace("%", "%%"))
target_metadata = Base.metadata


def run_migrations_offline() -> None:
    context.configure(
        url=_effective_database_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        compare_type=True,
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connectable = build_engine(_effective_database_url())

    try:
        with connectable.connect() as connection:
            sqlite_connection = (
                connection.connection.driver_connection
                if connection.dialect.name == "sqlite"
                else None
            )
            original_error: BaseException | None = None
            try:
                if sqlite_connection is not None:
                    # SQLite cannot batch-rebuild a referenced table while foreign
                    # key enforcement is active. Disable it only on this migration
                    # connection and validate the complete graph before commit.
                    if (
                        sqlite_connection.execute("PRAGMA foreign_key_check").fetchone()
                        is not None
                    ):
                        raise RuntimeError("SQLite foreign key validation failed")
                    sqlite_connection.execute("PRAGMA foreign_keys=OFF")
                    if sqlite_connection.execute("PRAGMA foreign_keys").fetchone() != (0,):
                        raise RuntimeError("failed to suspend SQLite foreign key enforcement")
                transaction_scope = (
                    connection.begin() if sqlite_connection is not None else nullcontext()
                )
                with transaction_scope:
                    if (
                        sqlite_connection is not None
                        and not sqlite_connection.in_transaction
                    ):
                        # pysqlite may not begin a real transaction for DDL. The
                        # SQLAlchemy transaction still owns the matching commit
                        # or rollback, while this BEGIN makes DDL transactional.
                        sqlite_connection.execute("BEGIN")
                    context.configure(
                        connection=connection,
                        target_metadata=target_metadata,
                        compare_type=True,
                    )
                    with context.begin_transaction():
                        context.run_migrations()
                        if (
                            sqlite_connection is not None
                            and sqlite_connection.execute(
                                "PRAGMA foreign_key_check"
                            ).fetchone()
                            is not None
                        ):
                            raise RuntimeError("SQLite foreign key validation failed")
            except BaseException as exc:
                original_error = exc
                raise
            finally:
                if sqlite_connection is not None:
                    try:
                        sqlite_connection.execute("PRAGMA foreign_keys=ON")
                        if sqlite_connection.execute("PRAGMA foreign_keys").fetchone() != (
                            1,
                        ):
                            raise RuntimeError("failed to restore SQLite foreign key enforcement")
                    except BaseException as restore_error:
                        if original_error is None:
                            raise
                        original_error.add_note(
                            "SQLite foreign key enforcement restoration also failed: "
                            f"{restore_error}"
                        )
    finally:
        connectable.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
