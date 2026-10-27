"""Role/grant/migration contracts for independently delegated reference content."""

from __future__ import annotations

import json

import pytest
from alembic import command
from fastapi.testclient import TestClient
from sqlalchemy import inspect, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from blockwart.api.deps import get_session
from blockwart.db.migrations import build_alembic_config
from blockwart.db.session import build_engine, transaction
from blockwart.domain.auth import (
    CatalogRole,
    GrantScope,
    Permission,
    Role,
    permissions_for_catalog_role,
    permissions_for_role,
    roles_for_permission,
)
from blockwart.main import create_app
from blockwart.mcp.server import call_tool, describe_schema_payload
from blockwart.models import AuditEvent, CatalogObject, ObjectGrant, Principal, Relationship
from blockwart.services.access import AccessGrantError, create_object_grant
from blockwart.services.commands import CommandConflict, WriteContext
from blockwart.services.grant_management import (
    create_managed_grant,
    preview_grant_scope,
    query_object_access,
    revoke_managed_grant,
    update_managed_grant,
)
from blockwart.services.identity import (
    create_service_account,
    issue_service_token,
    principal_context,
)
from blockwart.services.policy import policy_for_principal

CONTENT_ROLES = (Role.REFERENCE_CONTENT_READER, Role.REFERENCE_CONTENT_EDITOR)
PREVIOUS_REVISION = "20261023_0030"
CONTENT_REVISION = "20261026_0031"


def _object(identity: str, kind: str) -> CatalogObject:
    return CatalogObject(
        id=identity,
        kind=kind,
        label=identity,
        status="active",
        lifecycle="active" if kind == "service" else None,
        health="healthy" if kind == "service" else None,
        data_json="{}",
        provenance_json="{}",
    )


@pytest.fixture
def content_grant_state(alembic_session_factory):
    with alembic_session_factory() as session, transaction(session):
        session.add_all([
            _object("content-ref", "credential_reference"),
            _object("other-ref", "credential_reference"),
            _object("linked-service", "service"),
        ])
        session.flush()
        session.add(Relationship(
            from_ref="service:linked-service",
            relation_type="related_to",
            to_ref="credential_reference:content-ref",
        ))
        manager = create_service_account(
            session, login="content.manager", display_name="Content Manager",
        )
        candidate = create_service_account(
            session, login="content.candidate", display_name="Content Candidate",
        )
        owner = create_service_account(
            session, login="content.owner", display_name="Content Owner",
        )
        for object_id in ("content-ref", "linked-service"):
            create_object_grant(
                session, principal_id=owner.id, object_id=object_id,
                role=Role.OWNER, scope=GrantScope.SELF,
            )
            create_object_grant(
                session, principal_id=manager.id, object_id=object_id,
                role=Role.ACCESS_MANAGER, scope=GrantScope.SELF,
            )
        return manager.id, candidate.id, owner.id


def _context(session: Session, identity: str) -> WriteContext:
    principal = session.get(Principal, identity)
    assert principal is not None
    return WriteContext(
        principal=principal_context(principal),
        policy=policy_for_principal(session, identity),
        channel="api",
    )


def test_content_role_matrix_is_independent_and_existing_roles_are_not_widened():
    read = Permission.READ_REFERENCE_CONTENT
    write = Permission.WRITE_REFERENCE_CONTENT
    assert permissions_for_role(CONTENT_ROLES[0]) == {
        Permission.DISCOVER, Permission.READ, read,
    }
    assert permissions_for_role(CONTENT_ROLES[1]) == {
        Permission.DISCOVER, Permission.READ, write,
    }
    assert roles_for_permission(read) == {Role.OWNER, CONTENT_ROLES[0]}
    assert roles_for_permission(write) == {Role.OWNER, CONTENT_ROLES[1]}
    for role in set(Role) - {*CONTENT_ROLES, Role.OWNER}:
        assert {read, write}.isdisjoint(permissions_for_role(role))
    assert permissions_for_role(Role.OWNER) == set(Permission)
    assert permissions_for_catalog_role(CatalogRole.CATALOG_OWNER) == set(Permission)
    assert permissions_for_catalog_role(CatalogRole.CATALOG_VIEWER) == {
        Permission.DISCOVER, Permission.READ,
    }
    assert permissions_for_catalog_role(CatalogRole.PROJECT_CREATOR) == set()


def test_content_grants_are_additive_inspectable_and_independently_revocable(
    alembic_session_factory, content_grant_state,
):
    manager_id, candidate_id, _ = content_grant_state
    with alembic_session_factory() as session, transaction(session):
        context = _context(session, manager_id)
        initial_revision = session.get(CatalogObject, "content-ref").revision
        grants = []
        for role in CONTENT_ROLES:
            preview = preview_grant_scope(
                session, context, object_id="content-ref", role=role, scope="self",
            )
            assert preview.role == role
            assert set(preview.permissions) == permissions_for_role(role)
            assert [row.id for row in preview.affected_objects] == ["content-ref"]
            result = create_managed_grant(
                session, context, object_id="content-ref", principal_id=candidate_id,
                role=role, scope="self",
                expected_revision=session.get(CatalogObject, "content-ref").revision,
            )
            assert result.changed
            grants.append(result.grant.id)
            policy = policy_for_principal(session, candidate_id)
            assert policy.can(Permission.READ, "content-ref")
            assert not policy.can(Permission.WRITE, "content-ref")
            assert not policy.can(Permission.MANAGE_ACCESS, "content-ref")
            if role == Role.REFERENCE_CONTENT_READER:
                assert policy.can(Permission.READ_REFERENCE_CONTENT, "content-ref")
                assert not policy.can(Permission.WRITE_REFERENCE_CONTENT, "content-ref")
        assert session.get(CatalogObject, "content-ref").revision == initial_revision + 2
        access = query_object_access(session, context, object_id="content-ref")
        effective = next(row for row in access.effective_access if row.principal.id == candidate_id)
        assert set(effective.permissions) == {
            Permission.DISCOVER, Permission.READ,
            Permission.READ_REFERENCE_CONTENT, Permission.WRITE_REFERENCE_CONTENT,
        }
        assert {source.role for source in effective.sources} == set(CONTENT_ROLES)
        assert not policy_for_principal(session, candidate_id).permissions_for("linked-service")
        assert not policy_for_principal(session, candidate_id).permissions_for("other-ref")

        revoke_managed_grant(
            session, context, object_id="content-ref", grant_id=grants[0],
            expected_revision=session.get(CatalogObject, "content-ref").revision,
        )
        policy = policy_for_principal(session, candidate_id)
        assert not policy.can(Permission.READ_REFERENCE_CONTENT, "content-ref")
        assert policy.can(Permission.WRITE_REFERENCE_CONTENT, "content-ref")
        # Updating to another additive role follows the existing grant/ETag path.
        result = update_managed_grant(
            session, context, object_id="content-ref", grant_id=grants[1],
            role=Role.REFERENCE_CONTENT_READER, scope="self",
            expected_revision=session.get(CatalogObject, "content-ref").revision,
        )
        assert result.changed
        policy = policy_for_principal(session, candidate_id)
        assert policy.can(Permission.READ_REFERENCE_CONTENT, "content-ref")
        assert not policy.can(Permission.WRITE_REFERENCE_CONTENT, "content-ref")
        revoke_managed_grant(
            session, context, object_id="content-ref", grant_id=grants[1],
            expected_revision=session.get(CatalogObject, "content-ref").revision,
        )
        assert not policy_for_principal(session, candidate_id).permissions_for("content-ref")
        actions = session.scalars(select(AuditEvent.action).where(
            AuditEvent.object_id == "content-ref",
        )).all()
        assert actions.count("grant_create") == 4  # Owner, manager, reader, editor
        assert actions.count("grant_update") == 1
        assert actions.count("grant_revoke") == 2


@pytest.mark.parametrize("role", CONTENT_ROLES)
@pytest.mark.parametrize("object_id,scope", [
    ("content-ref", "subtree"),
    ("linked-service", "self"),
    ("linked-service", "subtree"),
])
def test_create_update_and_preview_reject_invalid_content_role_targets_without_writes(
    alembic_session_factory, content_grant_state, role, object_id, scope,
):
    manager_id, candidate_id, _ = content_grant_state
    with alembic_session_factory() as session, transaction(session):
        context = _context(session, manager_id)
        grant = create_object_grant(
            session, principal_id=candidate_id, object_id=object_id,
            role=Role.VIEWER, scope="self",
        )
        revision = session.get(CatalogObject, object_id).revision
        for operation in (
            lambda: preview_grant_scope(
                session, context, object_id=object_id, role=role, scope=scope,
            ),
            lambda: create_managed_grant(
                session, context, object_id=object_id, principal_id=candidate_id,
                role=role, scope=scope, expected_revision=revision,
            ),
            lambda: update_managed_grant(
                session, context, object_id=object_id, grant_id=grant.id,
                role=role, scope=scope, expected_revision=revision,
            ),
        ):
            with pytest.raises(CommandConflict, match="credential_reference.*self scope") as exc:
                operation()
            assert exc.value.code == "invalid_reference_content_grant"
            assert session.get(CatalogObject, object_id).revision == revision
            assert session.get(ObjectGrant, grant.id).role == Role.VIEWER
        with pytest.raises(AccessGrantError, match="credential_reference.*self scope"):
            create_object_grant(
                session, principal_id=candidate_id, object_id=object_id,
                role=role, scope=scope,
            )
        assert session.get(CatalogObject, object_id).revision == revision
        assert not session.scalar(select(ObjectGrant).where(ObjectGrant.role == role))


def test_linked_service_owner_has_no_reference_content_authority(
    alembic_session_factory, content_grant_state,
):
    _, candidate_id, owner_id = content_grant_state
    with alembic_session_factory() as session, transaction(session):
        create_object_grant(
            session, principal_id=candidate_id, object_id="linked-service",
            role=Role.OWNER, scope="subtree",
        )
        policy = policy_for_principal(session, candidate_id)
        assert not policy.permissions_for("content-ref")
        # Full control still belongs to a direct reference Owner.
        owner_policy = policy_for_principal(session, owner_id)
        assert owner_policy.can(Permission.READ_REFERENCE_CONTENT, "content-ref")
        assert owner_policy.can(Permission.WRITE_REFERENCE_CONTENT, "content-ref")


def test_reference_content_migration_preserves_grants_and_refuses_lossy_downgrade(tmp_path):
    database_url = f"sqlite:///{tmp_path / 'reference-content.sqlite3'}"
    config = build_alembic_config(database_url)
    command.upgrade(config, PREVIOUS_REVISION)
    engine = build_engine(database_url)
    try:
        with engine.begin() as connection:
            connection.execute(text(
                "INSERT INTO principals (id,principal_type,login,display_name,active,revision) "
                "VALUES ('kept','service_account','kept','Kept',0,7)"
            ))
            connection.execute(text(
                "INSERT INTO catalog_objects "
                "(id,kind,label,status,data_json,provenance_json,revision) "
                "VALUES ('kept-ref','credential_reference','Kept','active','{}','{}',9)"
            ))
            for role in ("owner", "viewer", "editor", "credential_reference_creator"):
                connection.execute(text(
                    "INSERT INTO object_grants "
                    "(principal_id,object_id,role,scope,created_by_principal_id,"
                    "created_at,updated_at) "
                    "VALUES ('kept','kept-ref',:role,'self','kept',"
                    "'2026-01-02 03:04:05','2026-02-03 04:05:06')"
                ), {"role": role})
            before = {
                table: connection.execute(text(f"SELECT * FROM {table}")).all()
                for table in ("principals", "catalog_objects", "object_grants")
            }
            before_indexes = inspect(connection).get_indexes("object_grants")
        command.upgrade(config, CONTENT_REVISION)
        with engine.begin() as connection:
            for table, rows in before.items():
                assert connection.execute(text(f"SELECT * FROM {table}")).all() == rows
            assert inspect(connection).get_indexes("object_grants") == before_indexes
            for role in CONTENT_ROLES:
                connection.execute(text(
                    "INSERT INTO object_grants (principal_id,object_id,role,scope) "
                    "VALUES ('kept','kept-ref',:role,'self')"
                ), {"role": role.value})
        for remaining_role in CONTENT_ROLES:
            with pytest.raises(RuntimeError, match="explicitly revoked before downgrade"):
                command.downgrade(config, PREVIOUS_REVISION)
            with engine.begin() as connection:
                assert connection.scalar(text("SELECT version_num FROM alembic_version")) == (
                    CONTENT_REVISION
                )
                assert connection.scalar(text(
                    "SELECT COUNT(*) FROM object_grants WHERE role=:role"
                ), {"role": remaining_role.value}) == 1
                connection.execute(text("DELETE FROM object_grants WHERE role=:role"), {
                    "role": remaining_role.value,
                })
        command.downgrade(config, PREVIOUS_REVISION)
        with engine.connect() as connection:
            for table, rows in before.items():
                assert connection.execute(text(f"SELECT * FROM {table}")).all() == rows
            assert connection.execute(text("PRAGMA foreign_key_check")).all() == []
        for role in CONTENT_ROLES:
            with engine.begin() as connection, pytest.raises(IntegrityError):
                connection.execute(text(
                    "INSERT INTO object_grants (principal_id,object_id,role,scope) "
                    "VALUES ('kept','kept-ref',:role,'self')"
                ), {"role": role.value})
    finally:
        engine.dispose()


@pytest.mark.parametrize("role", CONTENT_ROLES)
@pytest.mark.parametrize("object_id,scope", [
    ("content-ref", "subtree"),
    ("linked-service", "self"),
    ("linked-service", "subtree"),
])
def test_policy_ignores_malformed_raw_content_grants(
    alembic_session_factory, content_grant_state, role, object_id, scope,
):
    _, candidate_id, _ = content_grant_state
    with alembic_session_factory() as session, transaction(session):
        session.add(ObjectGrant(
            principal_id=candidate_id, object_id=object_id, role=role, scope=scope,
        ))
        session.flush()
        policy = policy_for_principal(session, candidate_id)
        assert not policy.permissions_for("content-ref")
        assert not policy.permissions_for("linked-service")
        assert not policy.grants_for(object_id)
        assert not policy.grants_for("other-ref")


@pytest.mark.parametrize("role", CONTENT_ROLES)
def test_rest_and_mcp_role_aware_preview_publish_permissions_and_enforce_scope(
    alembic_session_factory, content_grant_state, role,
):
    manager_id, _, _ = content_grant_state
    with alembic_session_factory() as session, transaction(session):
        token = issue_service_token(
            session, principal_id=manager_id, name="preview",
        ).value

    app = create_app()

    def override_session():
        with alembic_session_factory() as session:
            yield session

    app.dependency_overrides[get_session] = override_session
    with TestClient(app) as client:
        headers = {"Authorization": f"Bearer {token}"}
        preview_path = "/api/v1/objects/content-ref/access/preview"
        response = client.get(preview_path, params={"role": role, "scope": "self"}, headers=headers)
        assert response.status_code == 200, response.text
        assert response.json()["role"] == role
        assert set(response.json()["permissions"]) == {
            p.value for p in permissions_for_role(role)
        }
        assert [row["id"] for row in response.json()["affected_objects"]] == ["content-ref"]
        legacy = client.get(preview_path, params={"scope": "self"}, headers=headers)
        assert legacy.status_code == 200
        assert legacy.json()["role"] is None
        assert legacy.json()["permissions"] == []
        for object_id, scope in (("content-ref", "subtree"), ("linked-service", "self")):
            denied = client.get(
                f"/api/v1/objects/{object_id}/access/preview",
                params={"role": role, "scope": scope}, headers=headers,
            )
            assert denied.status_code == 409
            assert denied.json()["error"]["code"] == "invalid_reference_content_grant"

        def fetch_preview(path, params):
            result = client.get(path, params=params, headers=headers)
            assert result.status_code == 200, result.text
            return result.json()

        result = call_tool(
            "blockwart.preview_grant_scope",
            {"object_id": "content-ref", "role": role.value, "scope": "self"},
            fetcher=fetch_preview,
        )
        payload = json.loads(result["content"][0]["text"])
        assert payload["role"] == role
        assert set(payload["permissions"]) == {p.value for p in permissions_for_role(role)}


def test_mcp_update_intent_preserves_generic_authorization_and_explains_content_override():
    payload = describe_schema_payload(
        kind="credential_reference", write_intent="blockwart.update_object",
        sections=["write_intents"],
    )
    intent, = payload["write_intents"]
    assert intent["authorization"]["permission"] == "write"
    assert intent["authorization"]["object_roles"] == ["editor", "owner"]
    fields = intent["field_permissions"]
    assert fields["kind"] == "credential_reference"
    assert fields["protected_path"] == "data.reference"
    assert fields["metadata_read"] == "read"
    assert fields["metadata_write"] == "write"
    assert fields["content_read"] == "read_reference_content"
    assert fields["content_write"] == "write_reference_content"
    assert "unchanged metadata" in fields["content_only_update"]
    assert "does not imply" in fields["response_visibility"]
    generic = describe_schema_payload(
        kind="service", write_intent="blockwart.update_object", sections=["write_intents"],
    )
    assert "field_permissions" not in generic["write_intents"][0]
