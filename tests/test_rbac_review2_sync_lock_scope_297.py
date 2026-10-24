# ruff: noqa: F811 -- imported PostgreSQL pytest fixtures.
"""R2 independent review repro (not product code): a Project sync_github action
runs its outbound GitHub phase inside save_record's refreshed global lock set."""

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

from blockwart.db.session import transaction  # noqa: E402
from blockwart.domain.auth import GrantScope, Role  # noqa: E402
from blockwart.models import CatalogObject  # noqa: E402
from blockwart.schemas.catalog import CatalogObjectIn  # noqa: E402
from blockwart.schemas.project_workspace import ProjectActionIn, ProjectItemIn  # noqa: E402
from blockwart.services import project_github  # noqa: E402
from blockwart.services.access import create_object_grant  # noqa: E402
from blockwart.services.catalog import upsert_object  # noqa: E402
from blockwart.services.comments import add_object_comment  # noqa: E402
from blockwart.services.identity import create_service_account  # noqa: E402
from blockwart.services.project_management import apply_action  # noqa: E402
from blockwart.services.project_workspace import save_record  # noqa: E402


def test_pg_unrelated_comment_waits_for_project_sync_network_phase(migrated_pg_engine, monkeypatch):
    factory = sessionmaker(bind=migrated_pg_engine, autoflush=False)
    with factory() as s, transaction(s):
        actor_id, owner_id = seed(s)
        upsert_object(
            s,
            CatalogObjectIn(
                id="project-b",
                kind="project",
                label="B",
                data={
                    "category": "implementation",
                    "project_status": "active",
                    "started_at": "2026-10-23T00:00:00Z",
                },
            ),
        )
        create_object_grant(
            s, principal_id=owner_id, object_id="project-b", role=Role.OWNER, scope=GrantScope.SELF
        )
        bystander = create_service_account(s, login="bystander", display_name="Bystander")
        create_object_grant(
            s,
            principal_id=bystander.id,
            object_id="project-b",
            role=Role.EDITOR,
            scope=GrantScope.SELF,
        )
        bystander_id = bystander.id
    with factory() as s:
        actor_ctx, bystander_ctx = context(s, actor_id), context(s, bystander_id)
        with transaction(s):
            record = save_record(
                s,
                actor_ctx,
                object_id="project",
                record_id=None,
                payload=ProjectItemIn(kind="item", title="Sync task"),
                expected_revision=f'"rev-{s.get(CatalogObject, "project").revision}"',
                idempotency_key="r2-sync-record-000001",
                idempotency_ttl_seconds=3600,
            ).record
    entered, release = threading.Event(), threading.Event()

    def slow_github_phase(session, ctx, project, row):
        entered.set()  # real sync_record performs credential read + GitHub GETs here (8 s budget)
        assert release.wait(15)
        return {"observed_at": "2026-10-23T00:00:00Z", "observations": []}

    monkeypatch.setattr(project_github, "sync_record", slow_github_phase)
    app_name = "r2-sync-bystander-" + uuid.uuid4().hex
    bystander_engine = create_engine(
        migrated_pg_engine.url, connect_args={"application_name": app_name}
    )

    def sync():
        with factory() as s, transaction(s):
            return apply_action(
                s,
                actor_ctx,
                object_id="project",
                record_id=record.id,
                payload=ProjectActionIn(action="sync_github"),
                expected_record=record.record_etag,
                idempotency_key="r2-sync-action-000001",
                idempotency_ttl_seconds=3600,
            )

    def comment():
        started = time.monotonic()
        with Session(bystander_engine) as s, transaction(s):
            add_object_comment(
                s,
                bystander_ctx,
                object_id="project-b",
                body="Unrelated note",
                idempotency_key="r2-sync-unrelated-001",
                idempotency_ttl_seconds=3600,
            )
        return time.monotonic() - started

    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            syncer = pool.submit(sync)
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
            time.sleep(1.5)
            release.set()
            elapsed = commenter.result(15)
            syncer.result(15)
    finally:
        release.set()
        bystander_engine.dispose()
    assert finished_before_release, f"unrelated comment blocked on {waiting_on} for {elapsed:.2f}s"
