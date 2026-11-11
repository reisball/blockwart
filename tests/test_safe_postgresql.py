"""Optional real PostgreSQL route regressions, never pointed at a live catalog.

BLOCKWART_TEST_PG_URL must name a disposable test server whose user may
create databases. Each test creates and removes its own random database.
"""
# ruff: noqa: F811
import os
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url
from sqlalchemy.orm import sessionmaker
from test_credential_safe import (  # noqa: F401
    REF_ID,
    VALUE,
    boundary_state,
    document,
    safe_client,
)
from test_reference_content_boundary import write_for

from blockwart.db.migrations import upgrade_database
from blockwart.db.session import build_engine, transaction
from blockwart.domain.auth import GrantScope, Role
from blockwart.models import CatalogObject, ObjectGrant
from blockwart.schemas.catalog import CatalogObjectIn
from blockwart.services.access import create_object_grant
from blockwart.services.catalog import upsert_object
from blockwart.services.commands import update_catalog_object
from blockwart.services.credential_safe import Bao
from blockwart.services.identity import create_human_principal, issue_browser_session
from blockwart.ui.security import AUTH_CSRF_COOKIE_NAME, AUTH_SESSION_COOKIE_NAME


@pytest.fixture
def alembic_session_factory():
    url = os.environ.get("BLOCKWART_TEST_PG_URL")
    if not url:
        pytest.skip("disposable PostgreSQL server not configured")
    name = "safe_test_" + uuid.uuid4().hex
    admin = create_engine(url, isolation_level="AUTOCOMMIT")
    with admin.connect() as connection:
        connection.execute(text(f'CREATE DATABASE "{name}"'))
    db_url = make_url(url).set(database=name).render_as_string(hide_password=False)
    engine = None
    try:
        upgrade_database(db_url)
        engine = build_engine(db_url)
        yield sessionmaker(bind=engine, autoflush=False, autocommit=False)
    finally:
        if engine is not None:
            engine.dispose()
        with admin.connect() as connection:
            connection.execute(text(f'DROP DATABASE "{name}" WITH (FORCE)'))
        admin.dispose()


@pytest.mark.parametrize("channel", ["api", "mcp", "ui"])
@pytest.mark.parametrize("revoke", [False, True])
def test_network_gap_releases_locks_and_rechecks_policy(
    safe_client, alembic_session_factory, monkeypatch, channel, revoke,  # noqa: F811
):
    client, actors, _ = safe_client
    with alembic_session_factory() as session, transaction(session):
        upsert_object(session, CatalogObjectIn(id="unrelated", kind="credential_reference",
            label="Unrelated", data={"schema_version": 1, "provider": "external",
                                      "secret_value_stored": False}))
        create_object_grant(session, principal_id=actors["editor"][0], object_id="unrelated",
                            role=Role.EDITOR, scope=GrantScope.SELF)
        if channel == "ui":
            principal = create_human_principal(session, login="safe.browser",
                display_name="Synthetic browser", password="synthetic-test-password")
            principal_id = principal.id
            create_object_grant(session, principal_id=principal_id, object_id=REF_ID,
                                role=Role.REFERENCE_CONTENT_READER, scope=GrantScope.SELF)
            browser = issue_browser_session(session, principal_id=principal_id, ttl_seconds=3600)
        else:
            principal_id = actors["reader"][0]
    entered, release = threading.Event(), threading.Event()

    def backend(self, method, path, body=None):
        entered.set()
        assert release.wait(10), "test did not release synthetic backend"
        return {"data": {"data": {"fields": {"token": VALUE}, "deleted": False},
                         "metadata": {"version": 1}}}

    monkeypatch.setattr(Bao, "request", backend)
    if channel == "ui":
        client.cookies.set(AUTH_SESSION_COOKIE_NAME, browser.value)
        client.cookies.set(AUTH_CSRF_COOKIE_NAME, browser.csrf_token)

    def request():
        if channel == "ui":
            return client.post(f"/objects/{REF_ID}/safe",
                               data={"action": "read", "csrf_token": browser.csrf_token})
        return client.post(f"/api/v1/objects/{REF_ID}/safe", json={"action": "read"},
            headers={"Authorization": "Bearer " + actors["reader"][1],
                     "X-Blockwart-Channel": channel})

    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(request)
        try:
            assert entered.wait(5)
            with alembic_session_factory() as session, transaction(session):
                session.execute(text("SET LOCAL lock_timeout = '500ms'"))
                row = session.get(CatalogObject, "unrelated")
                payload = CatalogObjectIn(id=row.id, kind=row.kind, label=row.label,
                    summary="unrelated edit completes while backend is blocked",
                    data={"schema_version": 1, "provider": "external",
                          "secret_value_stored": False})
                update_catalog_object(session, write_for(session, actors, "editor"),
                    object_id=row.id, payload=payload, expected_revision=row.revision)
                if revoke:
                    session.query(ObjectGrant).filter_by(principal_id=principal_id).delete()
            assert not future.done()  # the DB write finished before backend release
        finally:
            release.set()
        response = future.result(timeout=5)
    assert response.status_code in ({403, 404} if revoke else {200})
    assert (VALUE in response.text) is not revoke


def test_pg_conditional_dispatch_has_one_winner(safe_client, monkeypatch,
                                                alembic_session_factory):  # noqa: F811
    from test_credential_safe import invoke

    from blockwart.models import SafeOperation
    client, actors, versions = safe_client
    barrier = threading.Barrier(2)
    original = Bao.request
    def simultaneous(self, method, path, body=None):
        if method == "POST":
            barrier.wait(timeout=10)
        return original(self, method, path, body)
    monkeypatch.setattr(Bao, "request", simultaneous)
    command = dict(action="write", cas=0, fields={"token": VALUE})
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: invoke(client, actors, "writer", **command), range(2)))
    assert sorted(r.status_code for r in results) == [200, 409]
    assert len(versions) == 1
    with alembic_session_factory() as session:
        row = session.query(SafeOperation).one()
        assert (row.state, row.result_version) == ("succeeded", 1)


def test_pg_first_admission_race_is_not_outage(safe_client, monkeypatch,
                                               alembic_session_factory):  # noqa: F811
    from test_safe_retry_binding import test_concurrent_admission_is_pending_not_database_outage
    test_concurrent_admission_is_pending_not_database_outage(
        safe_client, monkeypatch, alembic_session_factory)


def test_pg_lost_response_recovers_from_ledger(safe_client, monkeypatch,
                                               alembic_session_factory):  # noqa: F811
    from test_safe_reconciliation import test_lost_write_response_reconciles_without_replay
    test_lost_write_response_reconciles_without_replay(
        safe_client, monkeypatch, alembic_session_factory)


def test_pg_terminal_rejection_can_retry(safe_client, alembic_session_factory):  # noqa: F811
    from test_safe_retry_binding import test_future_cas_rejection_does_not_poison_legacy_retry
    test_future_cas_rejection_does_not_poison_legacy_retry(safe_client, alembic_session_factory)
