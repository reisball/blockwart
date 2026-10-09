"""Shared fixtures for access request tests (Issue #100).

``seed_access_world`` builds one small catalog with a principal for every role
the access request flow distinguishes. ``DualBackend`` runs a test body on
SQLite and, when ``BLOCKWART_TEST_PG_URL`` is reachable, on a throwaway
PostgreSQL database. ``snapshot_database`` captures every row of every table so
"a read changed nothing" can be asserted on the whole database, not only on the
tables a reader is expected to touch.
"""

from __future__ import annotations

import os
import uuid
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from datetime import datetime

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import MetaData, create_engine, make_url, select, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from blockwart.api.deps import get_session
from blockwart.config import Settings
from blockwart.db.migrations import upgrade_database
from blockwart.db.session import build_engine, transaction
from blockwart.domain.auth import GrantScope, Role
from blockwart.main import create_app
from blockwart.models import Principal
from blockwart.schemas.catalog import CatalogObjectIn
from blockwart.services import clock
from blockwart.services.access import create_object_grant
from blockwart.services.catalog import create_relationship, upsert_object
from blockwart.services.commands import WriteContext
from blockwart.services.identity import create_service_account, issue_service_token
from blockwart.services.read_access import read_access_for_principal

PG_BASE_URL = os.environ.get("BLOCKWART_TEST_PG_URL", "")


def asset(object_id: str, *, kind: str, label: str | None = None) -> CatalogObjectIn:
    return CatalogObjectIn(
        id=object_id,
        kind=kind,
        label=label or object_id,
        lifecycle="active",
        health="healthy",
        data={"schema_version": 1},
    )


def seed_access_world(session: Session) -> dict[str, dict[str, str]]:
    """Seed objects, principals with their grants and tokens; the caller commits."""
    root = upsert_object(session, asset("ar-root", kind="host", label="Access Root"))
    upsert_object(session, asset("ar-child", kind="system", label="Access Child"))
    create_relationship(
        session,
        from_ref="host:ar-root",
        relation_type="hosts",
        to_ref="system:ar-child",
    )
    roles = {
        "owner": (Role.OWNER, GrantScope.SUBTREE),
        "manager": (Role.ACCESS_MANAGER, GrantScope.SELF),
        "discoverer": (Role.DISCOVERER, GrantScope.SELF),
        "reader": (Role.VIEWER, GrantScope.SELF),
        "outsider": (None, None),
    }
    principals: dict[str, str] = {}
    tokens: dict[str, str] = {}
    for name, (role, scope) in roles.items():
        account = create_service_account(
            session,
            login=f"ar.{name}",
            display_name=f"Access {name.title()}",
        )
        principals[name] = account.id
        if role is not None:
            create_object_grant(
                session,
                principal_id=account.id,
                object_id=root.id,
                role=role,
                scope=scope,
            )
        tokens[name] = issue_service_token(
            session,
            principal_id=account.id,
            name="access-requests",
        ).value
    return {"principals": principals, "tokens": tokens}


def write_context(session: Session, principal_id: str, channel: str = "api") -> WriteContext:
    """A command context for ``principal_id`` as authentication would build it."""
    principal = session.get(Principal, principal_id)
    access = read_access_for_principal(session, principal)
    return WriteContext.from_read_access(access, channel=channel)


def authorization(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


@dataclass
class DualBackend:
    name: str
    url: str
    engine: Engine
    sessions: sessionmaker[Session]
    principals: dict[str, str]
    tokens: dict[str, str]
    extras: dict = field(default_factory=dict)

    def session(self) -> Session:
        return self.sessions()

    def app(self, settings: Settings | None = None) -> FastAPI:
        app = create_app(settings)

        def override_get_session() -> Iterator[Session]:
            with self.sessions() as session:
                yield session

        app.dependency_overrides[get_session] = override_get_session
        return app

    def client(self) -> TestClient:
        return TestClient(self.app())

    def app_client(self, settings: Settings | None = None) -> TestClient:
        """A client whose app (and lifespan) is built from explicit settings."""
        return TestClient(self.app(settings))


def _pg_url_for(database: str) -> str:
    return make_url(PG_BASE_URL).set(database=database).render_as_string(hide_password=False)


def make_backend_fixture(*, seed: Callable[[Session], dict] | None = None):
    """Return a pytest fixture running every dependent test on both backends."""

    @pytest.fixture(params=["sqlite", "postgresql"])
    def backend(request: pytest.FixtureRequest, tmp_path) -> Iterator[DualBackend]:
        created: str | None = None
        if request.param == "sqlite":
            url = f"sqlite:///{tmp_path / 'access-requests.sqlite3'}"
        else:
            if not PG_BASE_URL:
                pytest.skip("BLOCKWART_TEST_PG_URL is not configured")
            created = f"bw_accreq_{uuid.uuid4().hex[:12]}"
            admin = create_engine(_pg_url_for("postgres"), isolation_level="AUTOCOMMIT")
            try:
                with admin.connect() as connection:
                    connection.execute(text(f'CREATE DATABASE "{created}"'))
            finally:
                admin.dispose()
            url = _pg_url_for(created)
        upgrade_database(url)
        engine = build_engine(url)
        sessions = sessionmaker(bind=engine, autoflush=False, autocommit=False)
        with sessions() as session:
            with transaction(session):
                world = (seed or seed_access_world)(session)
        try:
            yield DualBackend(
                name=request.param,
                url=url,
                engine=engine,
                sessions=sessions,
                principals=world["principals"],
                tokens=world["tokens"],
                extras=world.get("extras", {}),
            )
        finally:
            engine.dispose()
            if created is not None:
                admin = create_engine(_pg_url_for("postgres"), isolation_level="AUTOCOMMIT")
                try:
                    with admin.connect() as connection:
                        connection.execute(
                            text(
                                "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                                "WHERE datname = :name AND pid <> pg_backend_pid()"
                            ),
                            {"name": created},
                        )
                        connection.execute(text(f'DROP DATABASE IF EXISTS "{created}"'))
                finally:
                    admin.dispose()

    return backend


def snapshot_database(engine: Engine) -> dict[str, list[tuple]]:
    """Every row of every table, for exact before/after comparison."""
    metadata = MetaData()
    metadata.reflect(bind=engine)
    snapshot: dict[str, list[tuple]] = {}
    with engine.connect() as connection:
        for name, table in sorted(metadata.tables.items()):
            order = [column for column in table.columns]
            rows = connection.execute(select(table).order_by(*order)).all()
            snapshot[name] = [tuple(row) for row in rows]
        connection.rollback()
    return snapshot


def changed_tables(
    before: dict[str, list[tuple]],
    after: dict[str, list[tuple]],
) -> list[str]:
    return sorted(name for name in before if before[name] != after.get(name))


class FrozenClock:
    """Moves the access-time seam across expiry boundaries without editing rows."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch, start: datetime | None = None) -> None:
        self._monkeypatch = monkeypatch
        self.now = start or clock.utcnow()
        monkeypatch.setattr(clock, "utcnow", lambda: self.now)

    def set(self, moment: datetime) -> None:
        self.now = moment

    def advance(self, **delta) -> datetime:
        from datetime import timedelta

        self.now = self.now + timedelta(**delta)
        return self.now
