"""Independent review regressions for issue #297; synthetic data only."""

# ruff: noqa: F811 -- imported PostgreSQL pytest fixtures.
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, func, select, text, update
from sqlalchemy.orm import Session, sessionmaker
from test_postgresql_compat_regressions import migrated_pg_engine, pg_database_name  # noqa: F401
from test_rbac_boundaries_297 import context, seed
from test_release_monitoring import _observed, _service

from blockwart.db.session import DatabaseTransactionError, transaction
from blockwart.domain.auth import CatalogRole, GrantScope, Permission, PlatformRole, Role
from blockwart.models import CatalogObject, ObjectGrant, Principal, ServiceReleaseObservation
from blockwart.schemas.catalog import CatalogObjectIn
from blockwart.services import principal_management as pm
from blockwart.services.access import create_object_grant, revoke_object_grant
from blockwart.services.catalog import upsert_object
from blockwart.services.commands import WriteContext, create_child_object
from blockwart.services.comments import add_object_comment
from blockwart.services.identity import create_human_principal, principal_context
from blockwart.services.policy import policy_for_principal
from blockwart.services.read_access import ReadAccess


@pytest.mark.parametrize("transport", ["api", "ui"])
@pytest.mark.parametrize("change", ["revoke", "deactivate", "global_revoke"])
def test_release_check_denies_stale_authenticated_policy(
    alembic_session_factory, monkeypatch, change, transport
):
    from fastapi import Request

    from blockwart.api.deps import get_session
    from blockwart.api.security import require_api_read_access
    from blockwart.main import create_app
    from blockwart.services import release_monitoring
    from blockwart.services.identity import create_service_account, deactivate_principal
    from blockwart.ui.security import require_browser_read_access, require_browser_write_csrf

    with alembic_session_factory() as s:
        with transaction(s):
            actor_id, owner_id = seed(s, global_owner=change == "global_revoke")
            upsert_object(s, _service("checked"))
            create_object_grant(
                s,
                principal_id=owner_id,
                object_id="checked",
                role=Role.OWNER,
                scope=GrantScope.SELF,
            )
            if change != "global_revoke":
                grant = create_object_grant(
                    s,
                    principal_id=actor_id,
                    object_id="checked",
                    role=Role.EDITOR,
                    scope=GrantScope.SELF,
                )
                grant_id = grant.id
            else:
                create_service_account(
                    s,
                    login="standby",
                    display_name="Standby",
                    catalog_role=CatalogRole.CATALOG_OWNER,
                )
        stale = context(s, actor_id)
        with transaction(s):
            if change == "revoke":
                revoke_object_grant(s, grant_id=grant_id)
            elif change == "deactivate":
                deactivate_principal(s, principal_id=actor_id)
            else:
                s.execute(
                    update(Principal).where(Principal.id == actor_id).values(catalog_role=None)
                )
        assert not policy_for_principal(s, actor_id).can(Permission.WRITE, "checked")
    app = create_app()
    app.state.settings = app.state.settings.model_copy(update={"release_monitoring_enabled": True})

    def sessions():
        with alembic_session_factory() as s:
            yield s

    app.dependency_overrides[get_session] = sessions
    # Retain the access snapshot that a real request acquired before revocation.
    app.dependency_overrides[require_api_read_access] = lambda: ReadAccess(
        stale.principal, stale.policy
    )

    def browser_access(request: Request):
        request.state.read_access = ReadAccess(stale.principal, stale.policy)
        return request.state.read_access

    app.dependency_overrides[require_browser_read_access] = browser_access
    app.dependency_overrides[require_browser_write_csrf] = lambda: None
    calls = []

    def fake_provider(request):
        calls.append("provider")
        return _observed()

    monkeypatch.setattr(release_monitoring, "fetch_latest_github_release", fake_provider)
    with TestClient(app) as client:
        response = client.post(
            "/api/v1/objects/checked/release-check"
            if transport == "api"
            else "/objects/checked/release-check",
            follow_redirects=False,
        )
    with alembic_session_factory() as s:
        observations = s.scalar(select(func.count()).select_from(ServiceReleaseObservation))
    assert (response.status_code, calls, observations) == (404, [], 0)


def test_child_creation_replay_conceals_revoked_child(alembic_session_factory):
    with alembic_session_factory() as s:
        with transaction(s):
            actor_id, owner_id = seed(s)
            actor_host_grant = s.scalar(
                select(ObjectGrant).where(
                    ObjectGrant.principal_id == actor_id, ObjectGrant.object_id == "host"
                )
            )
            actor_host_grant.role = Role.CREATOR
            actor_host_grant.scope = GrantScope.SELF
        stale = context(s, actor_id)

        def create():
            return create_child_object(
                s,
                stale,
                parent_id="host",
                payload=CatalogObjectIn(
                    id="new-system", kind="system", label="New system", data={}
                ),
                idempotency_key="independent-297-replay",
                idempotency_ttl_seconds=3600,
            )

        with transaction(s):
            create()
        with transaction(s):
            create_object_grant(
                s,
                principal_id=owner_id,
                object_id="new-system",
                role=Role.OWNER,
                scope=GrantScope.SELF,
            )
            grant_id = s.scalar(
                select(ObjectGrant.id).where(
                    ObjectGrant.principal_id == actor_id, ObjectGrant.object_id == "new-system"
                )
            )
            revoke_object_grant(s, grant_id=grant_id)
        assert not policy_for_principal(s, actor_id).can(Permission.DISCOVER, "new-system")
        from blockwart.services.commands import CommandAuthorizationDenied, CommandNotFound

        with pytest.raises((CommandNotFound, CommandAuthorizationDenied)):
            with transaction(s):
                create()


@pytest.mark.parametrize("operation", ["role", "project_creator", "password"])
def test_catalog_role_revocation_and_comment_have_no_deadlock(
    migrated_pg_engine,
    monkeypatch,
    operation,
):
    factory = sessionmaker(bind=migrated_pg_engine, autoflush=False)
    password = "synthetic-review-only-password"
    with factory() as s, transaction(s):
        people = [
            create_human_principal(
                s,
                login=f"review-{i}",
                display_name=f"Review {i}",
                password=password,
                platform_role=PlatformRole.ADMIN,
                catalog_role=CatalogRole.CATALOG_OWNER,
            )
            for i in range(2)
        ]
        writer, admin = sorted(people, key=lambda p: p.id)
        s.get(Principal, writer.id).project_creator = True
        upsert_object(
            s,
            CatalogObjectIn(
                id="project",
                kind="project",
                label="Project",
                data={
                    "category": "implementation",
                    "project_status": "active",
                    "started_at": "2026-10-23T00:00:00Z",
                },
            ),
        )
        create_object_grant(
            s, principal_id=admin.id, object_id="project", role=Role.OWNER, scope=GrantScope.SELF
        )
        writer_ctx = WriteContext(
            principal=principal_context(writer),
            policy=policy_for_principal(s, writer.id),
            channel="ui",
            request_id="review-comment",
        )
        admin_access = ReadAccess(principal_context(admin), policy_for_principal(s, admin.id))
    reauthenticated = threading.Event()
    writer_waiting = threading.Event()
    original = pm._reauthenticate_catalog_owner_admin

    def pause_after_reauth(*args, **kwargs):
        original(*args, **kwargs)
        reauthenticated.set()
        assert writer_waiting.wait(10)

    monkeypatch.setattr(pm, "_reauthenticate_catalog_owner_admin", pause_after_reauth)
    application = "review-297-" + uuid.uuid4().hex
    writer_engine = create_engine(
        migrated_pg_engine.url, connect_args={"application_name": application}
    )

    def outcome(fn):
        try:
            fn()
            return "ok"
        except DatabaseTransactionError as exc:
            return getattr(
                getattr(exc.__cause__, "orig", None), "pgcode", type(exc.__cause__).__name__
            )
        except Exception as exc:
            return type(exc).__name__

    def revoke():
        with factory() as s, transaction(s):
            common = dict(
                principal_id=writer.id, expected_revision=1, actor_password=password, channel="ui"
            )
            if operation == "role":
                pm.set_managed_catalog_role(s, admin_access, catalog_role=None, **common)
            elif operation == "project_creator":
                pm.set_managed_project_creator(s, admin_access, project_creator=False, **common)
            else:
                pm.reset_managed_human_password(
                    s, admin_access, new_password="new-fixture-password", **common
                )

    def comment():
        with Session(writer_engine) as s, transaction(s):
            add_object_comment(
                s,
                writer_ctx,
                object_id="project",
                body="Concurrent note",
                idempotency_key="review-lock-order-297",
                idempotency_ttl_seconds=3600,
            )

    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            revoker = pool.submit(outcome, revoke)
            assert reauthenticated.wait(10)
            commenter = pool.submit(outcome, comment)
            observed = False
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                with migrated_pg_engine.connect() as c:
                    observed = (
                        c.execute(
                            text(
                                "SELECT wait_event_type = 'Lock' FROM pg_stat_activity "
                                "WHERE application_name = :name"
                            ),
                            {"name": application},
                        ).scalar_one_or_none()
                        is True
                    )
                if observed or commenter.done():
                    break
                time.sleep(0.02)
            writer_waiting.set()
            results = [revoker.result(timeout=15), commenter.result(timeout=15)]
            assert observed
            assert results == ["ok", "CommandNotFound" if operation == "role" else "ok"], results
    finally:
        writer_waiting.set()
        writer_engine.dispose()


@pytest.mark.parametrize("creation", ["child", "root", "device", "credential_reference"])
@pytest.mark.parametrize("retained_role", [None, Role.VIEWER])
def test_every_creation_replay_uses_current_result_authority(
    alembic_session_factory,
    creation,
    retained_role,
):
    from blockwart.services.commands import (
        CommandAuthorizationDenied,
        CommandNotFound,
        create_attached_device,
        create_catalog_root,
        create_service_credential_reference,
    )

    with alembic_session_factory() as s:
        with transaction(s):
            actor_id, owner_id = seed(s)
            actor = s.get(Principal, actor_id)
            actor.project_creator = creation == "root"
            host_grant = s.scalar(
                select(ObjectGrant).where(
                    ObjectGrant.principal_id == actor_id, ObjectGrant.object_id == "host"
                )
            )
            host_grant.role, host_grant.scope = Role.CREATOR, GrantScope.SELF
            if creation == "credential_reference":
                upsert_object(
                    s,
                    CatalogObjectIn(
                        id="binding",
                        kind="service",
                        label="Binding",
                        data={
                            "endpoints": [
                                {
                                    "id": "api",
                                    "type": "REST API",
                                    "url": "https://example.invalid/api",
                                    "exposure": "internal",
                                }
                            ],
                            "access_methods": [
                                {"type": "admin_api", "endpoint_id": "api", "auth_mode": "key"}
                            ],
                        },
                    ),
                )
                for principal_id, role in [
                    (owner_id, Role.OWNER),
                    (actor_id, Role.CREDENTIAL_REFERENCE_CREATOR),
                ]:
                    create_object_grant(
                        s,
                        principal_id=principal_id,
                        object_id="binding",
                        role=role,
                        scope=GrantScope.SELF,
                    )
        ctx = context(s, actor_id)
        service_revision = (
            s.get(CatalogObject, "binding").revision if creation == "credential_reference" else None
        )
        kind = {
            "child": "system",
            "root": "project",
            "device": "device",
            "credential_reference": "credential_reference",
        }[creation]
        data = {
            "system": {},
            "project": {
                "category": "implementation",
                "project_status": "active",
                "started_at": "2026-10-23T00:00:00Z",
            },
            "device": {"device": {"category": "other"}},
            "credential_reference": {
                "provider": "vaultwarden",
                "reference": {"item_hint": "Fixture"},
            },
        }[kind]
        args = dict(
            payload=CatalogObjectIn(id="created-result", kind=kind, label="Result", data=data),
            idempotency_key="all-creation-replay-297",
            idempotency_ttl_seconds=3600,
        )

        def create():
            if creation == "child":
                return create_child_object(s, ctx, parent_id="host", **args)
            if creation == "root":
                return create_catalog_root(s, ctx, **args)
            if creation == "device":
                return create_attached_device(s, ctx, parent_id="host", metadata=None, **args)
            return create_service_credential_reference(
                s,
                ctx,
                service_id="binding",
                access_method_index=0,
                expected_revision=service_revision,
                **args,
            )

        with transaction(s):
            first = create()
        with transaction(s):
            create_object_grant(
                s,
                principal_id=owner_id,
                object_id="created-result",
                role=Role.OWNER,
                scope=GrantScope.SELF,
            )
            grant = s.scalar(
                select(ObjectGrant.id).where(
                    ObjectGrant.principal_id == actor_id,
                    ObjectGrant.object_id == "created-result",
                    ObjectGrant.role == Role.OWNER,
                )
            )
            revoke_object_grant(s, grant_id=grant)
            if retained_role:
                create_object_grant(
                    s,
                    principal_id=actor_id,
                    object_id="created-result",
                    role=retained_role,
                    scope=GrantScope.SELF,
                )
        if retained_role:
            with transaction(s):
                result = create()
                obj = (
                    result.credential_reference
                    if creation == "credential_reference"
                    else result.catalog_object
                )
                assert result.replayed
                assert obj.capabilities == [Permission.DISCOVER, Permission.READ]
                assert result.etag != first.etag
        else:
            with pytest.raises((CommandNotFound, CommandAuthorizationDenied)):
                with transaction(s):
                    create()


def test_manual_release_check_reauthorizes_after_unlocked_acquisition(
    migrated_pg_engine,
    monkeypatch,
):
    from blockwart.services import release_monitoring as releases

    factory = sessionmaker(bind=migrated_pg_engine, autoflush=False)
    with factory() as s, transaction(s):
        actor_id, owner_id = seed(s)
        upsert_object(s, _service("guarded-check"))
        create_object_grant(
            s,
            principal_id=owner_id,
            object_id="guarded-check",
            role=Role.OWNER,
            scope=GrantScope.SELF,
        )
        grant = create_object_grant(
            s,
            principal_id=actor_id,
            object_id="guarded-check",
            role=Role.EDITOR,
            scope=GrantScope.SELF,
        )
        grant_id = grant.id
        ctx = context(s, actor_id)
    provider_entered, release_provider = threading.Event(), threading.Event()

    def provider(request):
        provider_entered.set()
        assert release_provider.wait(10)
        return _observed()

    monkeypatch.setattr(releases, "fetch_latest_github_release", provider)

    def check():
        with factory() as s, transaction(s):
            return releases.check_authorized_service_release(
                s,
                ctx,
                object_id="guarded-check",
                settings=releases.ReleaseMonitoringSettings(enabled=True),
            ).outcome

    application = "release-297-" + uuid.uuid4().hex
    revoker_engine = create_engine(
        migrated_pg_engine.url, connect_args={"application_name": application}
    )

    def revoke():
        with Session(revoker_engine) as s, transaction(s):
            return revoke_object_grant(s, grant_id=grant_id)

    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            checker = pool.submit(check)
            assert provider_entered.wait(10)
            revoker = pool.submit(revoke)
            # Revocation is not delayed by acquisition; the completed response
            # must not be stored under the former authorization snapshot.
            assert revoker.result(5) is True
            release_provider.set()
            from blockwart.services.commands import CommandAuthorizationDenied, CommandNotFound

            with pytest.raises((CommandAuthorizationDenied, CommandNotFound)):
                checker.result(10)
    finally:
        release_provider.set()
        revoker_engine.dispose()
    with factory() as s:
        assert s.scalar(select(func.count()).select_from(ServiceReleaseObservation)) == 0
        assert not policy_for_principal(s, actor_id).can(Permission.WRITE, "guarded-check")
