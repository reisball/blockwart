from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, Protocol

import pytest
from fastapi import Depends, FastAPI, Request
from sqlalchemy import select
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from blockwart.api.deps import get_session
from blockwart.api.security import require_api_read_access
from blockwart.db.migrations import upgrade_database
from blockwart.db.session import build_engine
from blockwart.domain.auth import Permission, PrincipalContext, PrincipalType
from blockwart.models import CatalogObject
from blockwart.services.policy import PolicySnapshot
from blockwart.services.read_access import ReadAccess
from blockwart.ui.security import require_browser_read_access


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


def _unrestricted_read_access(session: Session) -> ReadAccess:
    object_ids = session.scalars(select(CatalogObject.id)).all()
    return ReadAccess(
        principal=PrincipalContext(
            id="test-unrestricted-principal",
            principal_type=PrincipalType.HUMAN,
            login="test-unrestricted",
            display_name="Test Unrestricted",
        ),
        policy=PolicySnapshot(
            principal_id="test-unrestricted-principal",
            _permissions={
                object_id: frozenset(Permission)
                for object_id in object_ids
            },
            _grants={},
        ),
    )


@pytest.fixture
def unrestricted_read_access():
    return _unrestricted_read_access


@pytest.fixture
def install_unrestricted_read_access():
    def install(app: FastAPI) -> None:
        def api_access(
            session: Annotated[Session, Depends(get_session)],
        ) -> ReadAccess:
            return _unrestricted_read_access(session)

        def browser_access(
            request: Request,
            session: Annotated[Session, Depends(get_session)],
        ) -> ReadAccess:
            access = _unrestricted_read_access(session)
            request.state.read_access = access
            return access

        app.dependency_overrides[require_api_read_access] = api_access
        app.dependency_overrides[require_browser_read_access] = browser_access

    return install
