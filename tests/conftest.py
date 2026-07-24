from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

import pytest
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from blockwart.db.migrations import upgrade_database
from blockwart.db.session import build_engine


@dataclass(frozen=True)
class AlembicTestDatabase:
    database_url: str
    engine: Engine
    sessions: sessionmaker[Session]


class AlembicDatabaseFactory(Protocol):
    def __call__(
        self,
        name: str = "blockwart.sqlite3",
        *,
        session_class: type[Session] = Session,
    ) -> AlembicTestDatabase: ...


@pytest.fixture
def alembic_database_factory(tmp_path: Path) -> Iterator[AlembicDatabaseFactory]:
    databases: list[AlembicTestDatabase] = []

    def create_database(
        name: str = "blockwart.sqlite3",
        *,
        session_class: type[Session] = Session,
    ) -> AlembicTestDatabase:
        database_path = tmp_path / name
        database_path.parent.mkdir(parents=True, exist_ok=True)
        database_url = f"sqlite:///{database_path}"
        upgrade_database(database_url)
        engine = build_engine(database_url)
        database = AlembicTestDatabase(
            database_url=database_url,
            engine=engine,
            sessions=sessionmaker(
                bind=engine,
                class_=session_class,
                autoflush=False,
                autocommit=False,
            ),
        )
        databases.append(database)
        return database

    yield create_database

    for database in reversed(databases):
        database.engine.dispose()


@pytest.fixture
def alembic_database(
    alembic_database_factory: AlembicDatabaseFactory,
) -> AlembicTestDatabase:
    return alembic_database_factory()


@pytest.fixture
def alembic_session_factory(
    alembic_database: AlembicTestDatabase,
) -> sessionmaker[Session]:
    return alembic_database.sessions
