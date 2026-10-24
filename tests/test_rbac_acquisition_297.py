"""Current-authority completion without a transaction across external I/O. Refs #297."""

# ruff: noqa: F811 -- imported PostgreSQL fixtures.
import json

import pytest
from sqlalchemy import func, select, update
from sqlalchemy.orm import sessionmaker
from test_postgresql_compat_regressions import migrated_pg_engine, pg_database_name  # noqa: F401
from test_rbac_boundaries_297 import context, seed
from test_release_monitoring import _observed, _service

from blockwart.db.session import transaction
from blockwart.domain.auth import GrantScope, Role
from blockwart.models import (
    CatalogObject,
    IdempotencyRecord,
    ObjectGrant,
    Principal,
    ProjectRecord,
    ProjectRecordEvent,
    ServiceReleaseCheckLease,
    ServiceReleaseObservation,
)
from blockwart.schemas.project_workspace import ProjectActionIn, ProjectItemIn
from blockwart.services import project_github, release_monitoring
from blockwart.services.access import create_object_grant, revoke_object_grant
from blockwart.services.catalog import upsert_object
from blockwart.services.commands import (
    CommandAuthorizationDenied,
    CommandNotFound,
    CommandPreconditionFailed,
)
from blockwart.services.project_management import apply_action
from blockwart.services.project_workspace import save_record


@pytest.fixture(params=["sqlite", "postgresql"])
def acquisition_factory(request):
    if request.param == "sqlite":
        return request.getfixturevalue("alembic_session_factory")
    return sessionmaker(bind=request.getfixturevalue("migrated_pg_engine"), autoflush=False)


@pytest.mark.parametrize("operation", ["release", "sync"])
@pytest.mark.parametrize("change", ["revoke", "deactivate", "source", "none"])
def test_acquisition_is_unlocked_and_completion_is_current(
    acquisition_factory,
    monkeypatch,
    operation,
    change,
):
    factory = acquisition_factory
    with factory() as s, transaction(s):
        actor_id, owner_id = seed(s)
        if operation == "release":
            upsert_object(s, _service("checked"))
            for identity, role in [(owner_id, Role.OWNER), (actor_id, Role.EDITOR)]:
                create_object_grant(
                    s,
                    principal_id=identity,
                    object_id="checked",
                    role=role,
                    scope=GrantScope.SELF,
                )
        ctx = context(s, actor_id)
        item = save_record(
            s,
            ctx,
            object_id="project",
            record_id=None,
            payload=ProjectItemIn(kind="item", title="Source task"),
            expected_revision=f'"rev-{s.get(CatalogObject, "project").revision}"',
            idempotency_key="acquisition-seed-record",
            idempotency_ttl_seconds=3600,
        ).record
    target = "checked" if operation == "release" else "project"
    with factory() as s:
        version = s.get(ProjectRecord, item.id).version
        revision = s.get(CatalogObject, "project").revision
        cached = s.scalar(select(func.count()).select_from(IdempotencyRecord))
        events = s.scalar(select(func.count()).select_from(ProjectRecordEvent))
    calls = []

    def acquisition(session=None):
        if session is not None:
            assert not session.in_transaction()
        calls.append("get")
        # Another connection can revoke/deactivate/change the source BEFORE
        # acquisition returns. No partial record/key/event has been committed.
        with factory() as other, transaction(other):
            assert other.get(ProjectRecord, item.id).version == version
            assert other.get(CatalogObject, "project").revision == revision
            assert other.scalar(select(func.count()).select_from(IdempotencyRecord)) == cached
            assert other.scalar(select(func.count()).select_from(ProjectRecordEvent)) == events
            if change == "revoke":
                grant = other.scalar(
                    select(ObjectGrant.id).where(
                        ObjectGrant.principal_id == actor_id,
                        ObjectGrant.object_id == target,
                        ObjectGrant.role == Role.EDITOR,
                    )
                )
                assert revoke_object_grant(other, grant_id=grant)
            elif change == "deactivate":
                other.execute(
                    update(Principal).where(Principal.id == actor_id).values(active=False)
                )
            elif change == "source":
                live = other.get(CatalogObject, target)
                if operation == "release":
                    data = json.loads(live.data_json)
                    data["release_monitoring"]["enabled"] = False
                    live.data_json = json.dumps(data)
                live.revision += 1
        if operation == "release":
            return _observed()
        return {"observations": [], "observed_at": "2026-10-23T00:00:00Z"}

    if operation == "release":
        monkeypatch.setattr(
            release_monitoring, "fetch_latest_github_release", lambda r: acquisition()
        )
    else:
        monkeypatch.setattr(project_github, "sync_record", lambda s, c, p, r: acquisition(s))

    def run():
        with factory() as s, transaction(s):
            if operation == "release":
                return release_monitoring.check_authorized_service_release(
                    s,
                    ctx,
                    object_id=target,
                    settings=release_monitoring.ReleaseMonitoringSettings(enabled=True),
                )
            return apply_action(
                s,
                ctx,
                object_id=target,
                record_id=item.id,
                payload=ProjectActionIn(action="sync_github"),
                expected_record=item.record_etag,
                idempotency_key="acquisition-sync-request",
                idempotency_ttl_seconds=3600,
            )

    if change in {"revoke", "deactivate"}:
        with pytest.raises((CommandAuthorizationDenied, CommandNotFound)):
            run()
    elif change == "source" and operation == "sync":
        with pytest.raises(CommandPreconditionFailed):
            run()
    else:
        result = run()
        if operation == "release" and change == "source":
            assert result.outcome == "skipped"
        elif operation == "sync":
            assert not result.replayed
            assert run().replayed
            assert calls == ["get"]  # cached action never repeats external work
    with factory() as s:
        if change != "none":
            assert s.get(ProjectRecord, item.id).version == version
            assert s.scalar(select(func.count()).select_from(ProjectRecordEvent)) == events
            assert s.scalar(select(func.count()).select_from(IdempotencyRecord)) == cached
            assert s.scalar(select(func.count()).select_from(ServiceReleaseObservation)) == 0
        assert (
            s.scalar(
                select(func.count())
                .select_from(ServiceReleaseCheckLease)
                .where(
                    ServiceReleaseCheckLease.lease_owner.is_not(None),
                )
            )
            == 0
        )
