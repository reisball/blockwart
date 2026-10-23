"""Security boundaries and explicit global authority. Refs #297."""

from __future__ import annotations

import pytest
from sqlalchemy import delete, func, select, update

from blockwart.db.session import transaction
from blockwart.domain.auth import CatalogRole, GrantScope, Permission, Role
from blockwart.models import CatalogObject, ObjectComment, ObjectGrant, Principal, Relationship
from blockwart.schemas.catalog import CatalogObjectIn
from blockwart.services.access import create_object_grant
from blockwart.services.catalog import upsert_object
from blockwart.services.commands import (
    CommandAuthorizationDenied,
    CommandNotFound,
    WriteContext,
    create_object_relationship,
)
from blockwart.services.comments import add_object_comment
from blockwart.services.grant_management import create_managed_grant, query_object_access
from blockwart.services.identity import create_service_account, principal_context
from blockwart.services.policy import policy_for_principal
from blockwart.services.project_chronology import add_project_chronology_entry


def seed(session, *, global_owner=False):
    for object_id, kind in [("host", "host"), ("system", "system"), ("project", "project")]:
        upsert_object(
            session,
            CatalogObjectIn(
                id=object_id,
                kind=kind,
                label=object_id,
                data=(
                    {
                        "category": "implementation",
                        "project_status": "active",
                        "started_at": "2026-10-23T00:00:00Z",
                    }
                    if kind == "project"
                    else {}
                ),
            ),
        )
    actor = create_service_account(
        session,
        login="actor",
        display_name="Actor",
        catalog_role=CatalogRole.CATALOG_OWNER if global_owner else None,
    )
    owner = create_service_account(session, login="owner", display_name="Owner")
    for object_id in ["host", "system", "project"]:
        create_object_grant(
            session,
            principal_id=owner.id,
            object_id=object_id,
            role=Role.OWNER,
            scope=GrantScope.SELF,
        )
    create_object_grant(
        session, principal_id=actor.id, object_id="host", role=Role.OWNER, scope=GrantScope.SUBTREE
    )
    create_object_grant(
        session, principal_id=actor.id, object_id="system", role=Role.VIEWER, scope=GrantScope.SELF
    )
    create_object_grant(
        session, principal_id=actor.id, object_id="project", role=Role.EDITOR, scope=GrantScope.SELF
    )
    return actor.id, owner.id


def context(session, actor_id):
    actor = session.get(Principal, actor_id)
    return WriteContext(
        principal=principal_context(actor, service_token_audience="api"),
        policy=policy_for_principal(session, actor_id),
        channel="api",
        request_id="rbac-297",
    )


@pytest.mark.parametrize("anchor", ["host", "system"])
def test_cannot_acquire_ownership_by_placing_foreign_system(alembic_session_factory, anchor):
    with alembic_session_factory() as session:
        with transaction(session):
            actor_id, _ = seed(session)
            if anchor == "system":
                create_object_grant(
                    session,
                    principal_id=actor_id,
                    object_id="system",
                    role=Role.EDITOR,
                    scope=GrantScope.SELF,
                )
        ctx = context(session, actor_id)
        revision = session.get(CatalogObject, anchor).revision
        with pytest.raises(CommandAuthorizationDenied):
            with transaction(session):
                create_object_relationship(
                    session,
                    ctx,
                    object_id=anchor,
                    from_ref="host:host",
                    relation_type="hosts",
                    to_ref="system:system",
                    expected_revision=revision,
                )
        assert session.scalar(select(func.count()).select_from(Relationship)) == 0
        assert not policy_for_principal(session, actor_id).can(Permission.DELETE, "system")
        assert session.get(CatalogObject, anchor).revision == revision


@pytest.mark.parametrize("change", ["revoke", "deactivate", "global_revoke"])
@pytest.mark.parametrize("chronology", [False, True])
@pytest.mark.parametrize("replay", [False, True])
def test_comment_and_chronology_reauthorize_before_write_and_replay(
    alembic_session_factory,
    change,
    chronology,
    replay,
):
    with alembic_session_factory() as session:
        with transaction(session):
            actor_id, _ = seed(session, global_owner=change == "global_revoke")
        ctx = context(session, actor_id)

        def append():
            args = dict(
                object_id="project",
                body="Authorized progress",
                idempotency_key="comment-297-security-case",
                idempotency_ttl_seconds=3600,
            )
            if chronology:
                return add_project_chronology_entry(session, ctx, kind="note", **args)
            return add_object_comment(session, ctx, **args)

        if replay:
            with transaction(session):
                append()
        with transaction(session):
            if change in {"revoke", "global_revoke"}:
                session.execute(delete(ObjectGrant).where(ObjectGrant.principal_id == actor_id))
                if change == "global_revoke":
                    # Retain an active catalog owner so the database guard permits revocation.
                    create_service_account(
                        session,
                        login="standby",
                        display_name="Standby",
                        catalog_role=CatalogRole.CATALOG_OWNER,
                    )
                    session.execute(
                        update(Principal).where(Principal.id == actor_id).values(catalog_role=None)
                    )
            else:
                session.execute(
                    update(Principal).where(Principal.id == actor_id).values(active=False)
                )
        before = session.get(CatalogObject, "project").revision
        with pytest.raises((CommandNotFound, CommandAuthorizationDenied)):
            with transaction(session):
                append()
        assert session.get(CatalogObject, "project").revision == before
        assert session.scalar(select(func.count()).select_from(ObjectComment)) == int(replay)


def test_global_owner_manages_foreign_ownership_without_local_grant(alembic_session_factory):
    with alembic_session_factory() as session:
        with transaction(session):
            actor_id, owner_id = seed(session, global_owner=True)
        with transaction(session):
            result = create_managed_grant(
                session,
                context(session, actor_id),
                object_id="system",
                principal_id=actor_id,
                role=Role.OWNER,
                scope=GrantScope.SELF,
                expected_revision=session.get(CatalogObject, "system").revision,
            )
            assert result.changed
        view = query_object_access(session, context(session, actor_id), object_id="project")
        entry = next(e for e in view.effective_access if e.principal.id == actor_id)
        assert [s.source for s in entry.global_authorities] == ["catalog_owner"]
        assert view.owner_coverage.actor_has_global_authority
        assert not view.owner_coverage.actor_has_owner_source


@pytest.mark.parametrize("global_owner", [False, True])
@pytest.mark.parametrize("parent_role", [Role.CREATOR, Role.EDITOR])
def test_placement_requires_old_child_owner_and_destination_create_child(
    alembic_session_factory,
    global_owner,
    parent_role,
):
    with alembic_session_factory() as session:
        with transaction(session):
            actor_id, _ = seed(session, global_owner=global_owner)
            session.execute(delete(ObjectGrant).where(ObjectGrant.principal_id == actor_id))
            create_object_grant(
                session,
                principal_id=actor_id,
                object_id="host",
                role=parent_role,
                scope=GrantScope.SELF,
            )
            create_object_grant(
                session,
                principal_id=actor_id,
                object_id="system",
                role=Role.OWNER,
                scope=GrantScope.SELF,
            )
        ctx = context(session, actor_id)
        if global_owner or parent_role == Role.CREATOR:
            with transaction(session):
                result = create_object_relationship(
                    session,
                    ctx,
                    object_id="system",
                    from_ref="host:host",
                    relation_type="hosts",
                    to_ref="system:system",
                    expected_revision=session.get(CatalogObject, "system").revision,
                )
                assert result.changed
        else:
            with pytest.raises(CommandAuthorizationDenied):
                with transaction(session):
                    create_object_relationship(
                        session,
                        ctx,
                        object_id="system",
                        from_ref="host:host",
                        relation_type="hosts",
                        to_ref="system:system",
                        expected_revision=session.get(CatalogObject, "system").revision,
                    )


@pytest.mark.parametrize("principal_type", ["human", "service"])
@pytest.mark.parametrize("catalog_role", [None, CatalogRole.CATALOG_VIEWER])
def test_global_reader_explicit_additive_and_no_implicit_root_creation(
    alembic_session_factory,
    principal_type,
    catalog_role,
):
    from blockwart.services.commands import create_catalog_root
    from blockwart.services.identity import create_human_principal

    with alembic_session_factory() as session:
        with transaction(session):
            seed(session)
            args = dict(login="reader", display_name="Reader", catalog_role=catalog_role)
            actor = (
                create_human_principal(session, password="reader-fixture-password", **args)
                if principal_type == "human"
                else create_service_account(session, **args)
            )
            assert actor.project_creator is False
            assert actor.platform_role is None
        policy = policy_for_principal(session, actor.id)
        assert policy.authorized_ids(Permission.READ) == (
            {"host", "system", "project"} if catalog_role else set()
        )
        assert not policy.creatable_root_kinds()
        assert not policy.authorized_ids(Permission.WRITE)
        with pytest.raises(CommandAuthorizationDenied):
            with transaction(session):
                ctx = context(session, actor.id)
                create_catalog_root(
                    session,
                    ctx,
                    payload=CatalogObjectIn(id="new-root", kind="host", label="Root", data={}),
                    idempotency_key="reader-cannot-create-root",
                    idempotency_ttl_seconds=3600,
                )
        with transaction(session):
            create_object_grant(
                session,
                principal_id=actor.id,
                object_id="project",
                role=Role.EDITOR,
                scope=GrantScope.SELF,
            )
        policy = policy_for_principal(session, actor.id)
        assert policy.authorized_ids(Permission.WRITE) == {"project"}
        with transaction(session):
            ctx = context(session, actor.id)
            if principal_type == "human":
                from dataclasses import replace

                ctx = replace(ctx, channel="ui", principal=principal_context(actor))
            result = add_object_comment(
                session,
                ctx,
                object_id="project",
                body="Editor update",
                idempotency_key="reader-editor-can-comment",
                idempotency_ttl_seconds=3600,
            )
            assert not result.replayed


@pytest.mark.parametrize("channel", ["api", "mcp", "ui"])
def test_global_owner_transport_manages_local_grants_and_shows_global_source(
    alembic_session_factory,
    channel,
):
    import json

    from fastapi.testclient import TestClient

    from blockwart.api.deps import get_session
    from blockwart.main import create_app
    from blockwart.mcp.server import call_tool
    from blockwart.services.identity import (
        create_human_principal,
        issue_browser_session,
        issue_service_token,
    )
    from blockwart.ui.security import AUTH_CSRF_COOKIE_NAME, AUTH_SESSION_COOKIE_NAME

    with alembic_session_factory() as session, transaction(session):
        actor_id, _ = seed(session, global_owner=True)
        if channel == "ui":
            human = create_human_principal(
                session,
                login="global-human",
                display_name="Global human",
                password="fixture-human-password",
                catalog_role=CatalogRole.CATALOG_OWNER,
            )
            browser = issue_browser_session(session, principal_id=human.id, ttl_seconds=3600)
            target_id = human.id
        else:
            token = issue_service_token(
                session, principal_id=actor_id, name="global", audience=channel
            )
            target_id = actor_id
    app = create_app()

    def get_test_session():
        with alembic_session_factory() as session:
            yield session

    app.dependency_overrides[get_session] = get_test_session
    with TestClient(app) as client:
        path = "/api/v1/objects/system/access"
        if channel == "ui":
            client.cookies.set(AUTH_SESSION_COOKIE_NAME, browser.value)
            client.cookies.set(AUTH_CSRF_COOKIE_NAME, browser.csrf_token)
            page = client.get("/objects/system?edit=permissions")
            assert page.status_code == 200, page.text
            assert "Global Catalog Owner" in page.text
            with alembic_session_factory() as session:
                revision = session.get(CatalogObject, "system").revision
            response = client.post(
                "/objects/system/permissions/grants",
                data={
                    "csrf_token": browser.csrf_token,
                    "if_match": f'"rev-{revision}"',
                    "principal_id": target_id,
                    "role": "owner",
                    "scope": "self",
                },
                follow_redirects=False,
            )
            assert response.status_code == 303, response.text
        else:
            auth = {"Authorization": "Bearer " + token.value}
            access = client.get(path, headers=auth).json()
            entry = next(e for e in access["effective_access"] if e["principal"]["id"] == actor_id)
            assert entry["global_authorities"][0]["source"] == "catalog_owner"

            def fetch(path, params):
                response = client.get(path, params=params, headers=auth)
                assert response.status_code == 200, response.text
                return response.json()

            def request(method, path, payload, headers):
                response = client.request(method, path, json=payload, headers={**auth, **headers})
                assert response.status_code == 201, response.text
                return response.json()

            if channel == "mcp":
                result = call_tool(
                    "blockwart.create_grant",
                    {
                        "object_id": "system",
                        "principal_id": target_id,
                        "role": "owner",
                        "scope": "self",
                        "if_match": access["etag"],
                    },
                    fetcher=fetch,
                    requester=request,
                )
                assert json.loads(result["content"][0]["text"])["changed"]
                result = call_tool(
                    "blockwart.get_object_access", {"object_id": "system"}, fetcher=fetch
                )
                assert "catalog_owner" in result["content"][0]["text"]
            else:
                response = client.post(
                    path + "/grants",
                    headers={**auth, "If-Match": access["etag"]},
                    json={"principal_id": target_id, "role": "owner", "scope": "self"},
                )
                assert response.status_code == 201, response.text


@pytest.mark.parametrize("kind", ["system", "project"])
@pytest.mark.parametrize("scope", [GrantScope.SELF, GrantScope.SUBTREE])
def test_global_owner_updates_and_revokes_foreign_ownership_without_local_owner(
    alembic_session_factory,
    kind,
    scope,
):
    from blockwart.services.grant_management import revoke_managed_grant, update_managed_grant

    with alembic_session_factory() as session:
        with transaction(session):
            actor_id, owner_id = seed(session, global_owner=True)
            recipient = create_service_account(session, login="recipient", display_name="Recipient")
        ctx = context(session, actor_id)
        assert not any(g.role == Role.OWNER for g in ctx.policy.grants_for(kind))
        original = session.scalar(
            select(ObjectGrant.id).where(
                ObjectGrant.object_id == kind,
                ObjectGrant.principal_id == owner_id,
            )
        )
        with transaction(session):
            result = create_managed_grant(
                session,
                ctx,
                object_id=kind,
                principal_id=recipient.id,
                role=Role.OWNER,
                scope=scope,
                expected_revision=session.get(CatalogObject, kind).revision,
            )
        with transaction(session):
            updated = update_managed_grant(
                session,
                ctx,
                object_id=kind,
                grant_id=result.grant.id,
                role=Role.OWNER,
                scope=GrantScope.SUBTREE if scope == GrantScope.SELF else GrantScope.SELF,
                expected_revision=result.revision,
            )
            assert updated.changed
        with transaction(session):
            removed = revoke_managed_grant(
                session, ctx, object_id=kind, grant_id=original, expected_revision=updated.revision
            )
            assert removed.changed
        assert not any(
            g.role == Role.OWNER for g in policy_for_principal(session, actor_id).grants_for(kind)
        )


@pytest.mark.parametrize("replay", [False, True])
def test_denied_stale_sync_never_reaches_credentials_or_github(
    alembic_session_factory,
    monkeypatch,
    replay,
):
    from blockwart.models import ProjectRecord, ProjectRecordEvent
    from blockwart.schemas.project_workspace import ProjectActionIn, ProjectItemIn
    from blockwart.services import project_github
    from blockwart.services.project_management import apply_action
    from blockwart.services.project_workspace import save_record

    calls = []

    def synthetic_sync(*args, **kwargs):
        calls.append("sync")
        return {"observed_at": "2026-10-23T00:00:00Z", "observations": []}

    monkeypatch.setattr(project_github, "sync_record", synthetic_sync)

    def forbidden(*args, **kwargs):
        raise AssertionError("Denied sync must not access credentials/network")

    monkeypatch.setattr(project_github, "_credential", forbidden)
    monkeypatch.setattr(project_github, "_github_get", forbidden)
    with alembic_session_factory() as session:
        with transaction(session):
            actor_id, _ = seed(session)
            ctx = context(session, actor_id)
            result = save_record(
                session,
                ctx,
                object_id="project",
                record_id=None,
                payload=ProjectItemIn(kind="item", title="Sync task"),
                expected_revision=f'"rev-{session.get(CatalogObject, "project").revision}"',
                idempotency_key="stale-sync-new-record-297",
                idempotency_ttl_seconds=3600,
            )

        def sync():
            return apply_action(
                session,
                ctx,
                object_id="project",
                record_id=result.record.id,
                payload=ProjectActionIn(action="sync_github"),
                expected_record=result.record.record_etag,
                idempotency_key="stale-sync-action-297-key",
                idempotency_ttl_seconds=3600,
            )

        if replay:
            with transaction(session):
                sync()
            assert calls == ["sync"]
        calls.clear()
        with transaction(session):
            session.execute(
                delete(ObjectGrant).where(
                    ObjectGrant.principal_id == actor_id, ObjectGrant.object_id == "project"
                )
            )
        before = (
            session.get(CatalogObject, "project").revision,
            session.get(ProjectRecord, result.record.id).version,
            session.scalar(select(func.count()).select_from(ProjectRecordEvent)),
        )
        with pytest.raises((CommandNotFound, CommandAuthorizationDenied)):
            with transaction(session):
                sync()
        assert calls == []
        assert before == (
            session.get(CatalogObject, "project").revision,
            session.get(ProjectRecord, result.record.id).version,
            session.scalar(select(func.count()).select_from(ProjectRecordEvent)),
        )
