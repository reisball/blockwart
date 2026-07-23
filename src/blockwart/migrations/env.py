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
            context.configure(
                connection=connection,
                target_metadata=target_metadata,
                compare_type=True,
            )
            with context.begin_transaction():
                context.run_migrations()
    finally:
        connectable.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
