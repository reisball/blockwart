# ruff: noqa: F811 -- imported PostgreSQL pytest fixtures.
"""R2 independent review repro (not product code): a manual release check keeps
the global authorization locks (and SQLite's write lock) across the provider call,
stalling unrelated writes by unrelated principals on unrelated objects."""

import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor

from sqlalchemy import create_engine, text  # noqa: E402
from sqlalchemy.orm import Session, sessionmaker  # noqa: E402
from test_postgresql_compat_regressions import (  # noqa: F401,E402
    migrated_pg_engine,
    pg_database_name,
)
from test_rbac_boundaries_297 import context, seed  # noqa: E402
from test_release_monitoring import _observed, _service  # noqa: E402

from blockwart.db.session import DatabaseTransactionError, build_engine, transaction  # noqa: E402
from blockwart.domain.auth import GrantScope, Role  # noqa: E402
from blockwart.services import release_monitoring as releases  # noqa: E402
from blockwart.services.access import create_object_grant  # noqa: E402
from blockwart.services.catalog import upsert_object  # noqa: E402
from blockwart.services.comments import add_object_comment  # noqa: E402
from blockwart.services.identity import create_service_account  # noqa: E402


def _seed(s):
    actor_id, owner_id = seed(s)
    upsert_object(s, _service("checked"))
    create_object_grant(
        s, principal_id=owner_id, object_id="checked", role=Role.OWNER, scope=GrantScope.SELF
    )
    create_object_grant(
        s, principal_id=actor_id, object_id="checked", role=Role.EDITOR, scope=GrantScope.SELF
    )
    bystander = create_service_account(s, login="bystander", display_name="Bystander")
    create_object_grant(
        s, principal_id=bystander.id, object_id="project", role=Role.EDITOR, scope=GrantScope.SELF
    )
    return actor_id, bystander.id


def test_pg_unrelated_comment_waits_for_manual_release_provider(migrated_pg_engine, monkeypatch):
    factory = sessionmaker(bind=migrated_pg_engine, autoflush=False)
    with factory() as s, transaction(s):
        actor_id, bystander_id = _seed(s)
        actor_ctx, bystander_ctx = context(s, actor_id), context(s, bystander_id)
    entered, release = threading.Event(), threading.Event()

    def provider(request):
        entered.set()
        assert release.wait(15)
        return _observed()

    monkeypatch.setattr(releases, "fetch_latest_github_release", provider)
    app_name = "r2-bystander-" + uuid.uuid4().hex
    bystander_engine = create_engine(
        migrated_pg_engine.url, connect_args={"application_name": app_name}
    )

    def check():
        with factory() as s, transaction(s):
            return releases.check_authorized_service_release(
                s,
                actor_ctx,
                object_id="checked",
                settings=releases.ReleaseMonitoringSettings(enabled=True),
            ).outcome

    def comment():
        started = time.monotonic()
        with Session(bystander_engine) as s, transaction(s):
            add_object_comment(
                s,
                bystander_ctx,
                object_id="project",
                body="Unrelated note",
                idempotency_key="r2-unrelated-comment-0001",
                idempotency_ttl_seconds=3600,
            )
        return time.monotonic() - started

    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            checker = pool.submit(check)
            assert entered.wait(10)
            commenter = pool.submit(comment)
            waiting_on = None
            deadline = time.monotonic() + 3
            while time.monotonic() < deadline and not commenter.done():
                with migrated_pg_engine.connect() as c:
                    waiting_on = c.execute(
                        text(
                            "SELECT wait_event_type || ':' || coalesce(wait_event, '') "
                            "FROM pg_stat_activity "
                            "WHERE application_name = :n"
                        ),
                        {"n": app_name},
                    ).scalar_one_or_none()
                if waiting_on and waiting_on.startswith("Lock"):
                    break
                time.sleep(0.05)
            finished_before_release = commenter.done()
            time.sleep(2.0)  # simulate a slow provider (default total timeout is 5 s)
            release.set()
            elapsed = commenter.result(15)
            assert checker.result(15) == "observed"
    finally:
        release.set()
        bystander_engine.dispose()
    assert finished_before_release, (
        f"unrelated comment on another object by another principal blocked on {waiting_on} "
        f"for {elapsed:.2f}s while the release provider call was in flight"
    )


def test_sqlite_unrelated_comment_fails_while_manual_release_provider_runs(
    alembic_database, monkeypatch
):
    with alembic_database.sessions() as s, transaction(s):
        actor_id, bystander_id = _seed(s)
    with alembic_database.sessions() as s:
        actor_ctx, bystander_ctx = context(s, actor_id), context(s, bystander_id)
    # Production defaults: sqlite_busy_timeout_ms=5000, release total timeout 5000 (max 30000).
    # Scaled down here: busy timeout 300 ms, provider takes 1.5 s.
    engine = build_engine(alembic_database.database_url, sqlite_busy_timeout_ms=300)
    factory = sessionmaker(bind=engine, autoflush=False)
    entered, release = threading.Event(), threading.Event()

    def provider(request):
        entered.set()
        release.wait(1.5)
        return _observed()

    monkeypatch.setattr(releases, "fetch_latest_github_release", provider)

    def check():
        with factory() as s, transaction(s):
            return releases.check_authorized_service_release(
                s,
                actor_ctx,
                object_id="checked",
                settings=releases.ReleaseMonitoringSettings(enabled=True),
            ).outcome

    def comment():
        try:
            with factory() as s, transaction(s):
                add_object_comment(
                    s,
                    bystander_ctx,
                    object_id="project",
                    body="Unrelated note",
                    idempotency_key="r2-unrelated-comment-0002",
                    idempotency_ttl_seconds=3600,
                )
            return "ok"
        except DatabaseTransactionError as exc:
            return f"DatabaseTransactionError: {exc.__cause__}"

    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            checker = pool.submit(check)
            assert entered.wait(10)
            result = pool.submit(comment).result(10)
            release.set()
            assert checker.result(10) == "observed"
    finally:
        release.set()
        engine.dispose()
    assert result == "ok", result
