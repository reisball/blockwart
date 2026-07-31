from __future__ import annotations

import json
from collections.abc import Generator
from concurrent.futures import ThreadPoolExecutor

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from blockwart.api.deps import get_session
from blockwart.db.session import transaction
from blockwart.domain.auth import GrantScope, Permission, Role
from blockwart.main import create_app
from blockwart.models import (
    AuditEvent,
    CatalogObject,
    ObjectGrant,
    Principal,
    Relationship,
    SecurityEvent,
)
from blockwart.schemas.catalog import CatalogObjectIn
from blockwart.services.access import create_object_grant
from blockwart.services.catalog import create_relationship, upsert_object
from blockwart.services.identity import (
    create_human_principal,
    create_service_account,
    deactivate_principal,
    issue_browser_session,
    issue_service_token,
)
from blockwart.ui.security import (
    AUTH_CSRF_COOKIE_NAME,
    AUTH_SESSION_COOKIE_NAME,
)


def _asset(
    object_id: str,
    *,
    kind: str,
    label: str | None = None,
    data: dict[str, object] | None = None,
) -> CatalogObjectIn:
    return CatalogObjectIn(
        id=object_id,
        kind=kind,
        label=label or object_id,
        lifecycle="active",
        health="healthy",
        data=data or {"schema_version": 1},
    )


@pytest.fixture
def grant_management_state(alembic_session_factory):
    with alembic_session_factory() as session:
        with transaction(session):
            root = upsert_object(
                session,
                _asset("grant-root", kind="host", label="Grant Root"),
            )
            child = upsert_object(
                session,
                _asset("grant-child", kind="system", label="Grant Child"),
            )
            upsert_object(
                session,
                _asset("grant-leaf", kind="service", label="Grant Leaf"),
            )
            upsert_object(
                session,
                _asset("grant-unrelated", kind="service", label="Grant Unrelated"),
            )
            create_relationship(
                session,
                from_ref="host:grant-root",
                relation_type="hosts",
                to_ref="system:grant-child",
            )
            create_relationship(
                session,
                from_ref="system:grant-child",
                relation_type="hosts",
                to_ref="service:grant-leaf",
            )
            create_relationship(
                session,
                from_ref="host:grant-root",
                relation_type="related_to",
                to_ref="service:grant-unrelated",
            )

            owner = create_service_account(
                session,
                login="grant.owner",
                display_name="Grant Owner",
            )
            manager = create_service_account(
                session,
                login="grant.manager",
                display_name="Grant Manager",
            )
            viewer = create_service_account(
                session,
                login="grant.viewer",
                display_name="Grant Viewer",
            )
            candidate_a = create_service_account(
                session,
                login="candidate.alpha",
                display_name="Candidate Alpha",
            )
            candidate_b = create_service_account(
                session,
                login="candidate.beta",
                display_name="Candidate Beta",
            )
            inactive = create_service_account(
                session,
                login="candidate.inactive",
                display_name="Candidate Inactive",
            )
            outsider = create_service_account(
                session,
                login="grant.outsider",
                display_name="Grant Outsider",
            )
            deactivate_principal(session, principal_id=inactive.id)

            owner_grant = create_object_grant(
                session,
                principal_id=owner.id,
                object_id=root.id,
                role=Role.OWNER,
                scope=GrantScope.SUBTREE,
            )
            manager_grant = create_object_grant(
                session,
                principal_id=manager.id,
                object_id=root.id,
                role=Role.ACCESS_MANAGER,
                scope=GrantScope.SUBTREE,
            )
            create_object_grant(
                session,
                principal_id=viewer.id,
                object_id=root.id,
                role=Role.VIEWER,
                scope=GrantScope.SELF,
            )
            create_object_grant(
                session,
                principal_id=inactive.id,
                object_id=child.id,
                role=Role.VIEWER,
                scope=GrantScope.SELF,
            )
            tokens = {
                "owner": issue_service_token(
                    session,
                    principal_id=owner.id,
                    name="grant-management",
                ).value,
                "manager": issue_service_token(
                    session,
                    principal_id=manager.id,
                    name="grant-management",
                ).value,
                "viewer": issue_service_token(
                    session,
                    principal_id=viewer.id,
                    name="grant-management",
                ).value,
                "candidate_a": issue_service_token(
                    session,
                    principal_id=candidate_a.id,
                    name="grant-management",
                ).value,
                "candidate_b": issue_service_token(
                    session,
                    principal_id=candidate_b.id,
                    name="grant-management",
                ).value,
                "outsider": issue_service_token(
                    session,
                    principal_id=outsider.id,
                    name="grant-management",
                ).value,
            }
            principal_ids = {
                "owner": owner.id,
                "manager": manager.id,
                "viewer": viewer.id,
                "candidate_a": candidate_a.id,
                "candidate_b": candidate_b.id,
                "inactive": inactive.id,
                "outsider": outsider.id,
            }
            grant_ids = {
                "owner": owner_grant.id,
                "manager": manager_grant.id,
            }
    return {
        "session_factory": alembic_session_factory,
        "principals": principal_ids,
        "grants": grant_ids,
        "tokens": tokens,
    }


@pytest.fixture
def grant_management_client(
    grant_management_state,
) -> Generator[TestClient, None, None]:
    session_factory = grant_management_state["session_factory"]
    app = create_app()

    def override_get_session() -> Generator[Session, None, None]:
        with session_factory() as session:
            yield session

    app.dependency_overrides[get_session] = override_get_session
    with TestClient(app) as client:
        yield client


def _authorization(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def test_access_view_is_minimized_and_preview_uses_only_canonical_placement(
    grant_management_client: TestClient,
    grant_management_state,
) -> None:
    tokens = grant_management_state["tokens"]
    root_access = grant_management_client.get(
        "/api/v1/objects/grant-root/access",
        headers=_authorization(tokens["owner"]),
    )
    child_access = grant_management_client.get(
        "/api/v1/objects/grant-child/access",
        headers=_authorization(tokens["owner"]),
    )
    preview = grant_management_client.get(
        "/api/v1/objects/grant-root/access/preview?scope=subtree",
        headers=_authorization(tokens["owner"]),
    )

    assert root_access.status_code == 200, root_access.text
    assert root_access.headers["etag"] == root_access.json()["etag"]
    direct = root_access.json()["direct_grants"]
    assert {item["principal"]["login"] for item in direct} == {
        "grant.manager",
        "grant.owner",
        "grant.viewer",
    }
    assert set(direct[0]["principal"]) == {
        "id",
        "login",
        "display_name",
        "principal_type",
        "active",
    }
    assert all(
        grant[timestamp].endswith("Z")
        for grant in direct
        for timestamp in ("created_at", "updated_at")
    )
    serialized = root_access.text.casefold()
    assert all(
        forbidden not in serialized
        for forbidden in ("password_hash", "token_hash", "csrf_hash", "credential")
    )
    assert child_access.status_code == 200
    inactive_direct = next(
        grant
        for grant in child_access.json()["direct_grants"]
        if grant["principal"]["login"] == "candidate.inactive"
    )
    assert inactive_direct["principal"]["active"] is False
    assert "candidate.inactive" not in {
        item["principal"]["login"]
        for item in child_access.json()["effective_access"]
    }
    inherited_owner = next(
        item
        for item in child_access.json()["effective_access"]
        if item["principal"]["login"] == "grant.owner"
    )
    assert set(inherited_owner["permissions"]) == {
        permission.value for permission in Permission
    }
    assert inherited_owner["sources"] == [
        {
            "grant_id": grant_management_state["grants"]["owner"],
            "anchor_object_id": "grant-root",
            "anchor_object_kind": "host",
            "anchor_object_label": "Grant Root",
            "role": "owner",
            "scope": "subtree",
            "direct": False,
        }
    ]
    assert preview.status_code == 200
    assert {
        item["id"] for item in preview.json()["affected_objects"]
    } == {"grant-root", "grant-child", "grant-leaf"}
    assert "grant-unrelated" not in preview.text


def test_principal_search_is_bounded_active_only_and_manage_access_protected(
    grant_management_client: TestClient,
    grant_management_state,
) -> None:
    tokens = grant_management_state["tokens"]
    found = grant_management_client.get(
        "/api/v1/objects/grant-root/access/principals?q=candidate&limit=2",
        headers=_authorization(tokens["manager"]),
    )
    too_short = grant_management_client.get(
        "/api/v1/objects/grant-root/access/principals?q=c",
        headers=_authorization(tokens["manager"]),
    )
    viewer_denied = grant_management_client.get(
        "/api/v1/objects/grant-root/access",
        headers=_authorization(tokens["viewer"]),
    )
    outsider_concealed = grant_management_client.get(
        "/api/v1/objects/grant-root/access",
        headers=_authorization(tokens["outsider"]),
    )

    assert found.status_code == 200
    assert [item["login"] for item in found.json()["items"]] == [
        "candidate.alpha",
        "candidate.beta",
    ]
    assert "candidate.inactive" not in found.text
    assert too_short.status_code == 422
    assert viewer_denied.status_code == 403
    assert outsider_concealed.status_code == 404


def test_access_manager_cannot_manage_owner_grants_but_owner_can(
    grant_management_client: TestClient,
    grant_management_state,
) -> None:
    tokens = grant_management_state["tokens"]
    principals = grant_management_state["principals"]
    manager_auth = _authorization(tokens["manager"])
    access = grant_management_client.get(
        "/api/v1/objects/grant-root/access",
        headers=manager_auth,
    )
    created = grant_management_client.post(
        "/api/v1/objects/grant-root/access/grants",
        headers={**manager_auth, "If-Match": access.headers["etag"]},
        json={
            "principal_id": principals["candidate_a"],
            "role": "editor",
            "scope": "self",
        },
    )
    updated = grant_management_client.put(
        (
            "/api/v1/objects/grant-root/access/grants/"
            f"{created.json()['grant']['id']}"
        ),
        headers={**manager_auth, "If-Match": created.headers["etag"]},
        json={"role": "viewer", "scope": "subtree"},
    )
    revoked = grant_management_client.delete(
        (
            "/api/v1/objects/grant-root/access/grants/"
            f"{created.json()['grant']['id']}"
        ),
        headers={**manager_auth, "If-Match": updated.headers["etag"]},
    )
    denied_owner = grant_management_client.post(
        "/api/v1/objects/grant-root/access/grants",
        headers={**manager_auth, "If-Match": revoked.headers["etag"]},
        json={
            "principal_id": principals["candidate_b"],
            "role": "owner",
            "scope": "self",
        },
    )
    owner_auth = _authorization(tokens["owner"])
    owner_created = grant_management_client.post(
        "/api/v1/objects/grant-root/access/grants",
        headers={**owner_auth, "If-Match": revoked.headers["etag"]},
        json={
            "principal_id": principals["candidate_b"],
            "role": "owner",
            "scope": "subtree",
        },
    )

    assert created.status_code == 201, created.text
    assert created.json()["grant"]["role"] == "editor"
    assert updated.status_code == 200, updated.text
    assert updated.json()["grant"]["role"] == "viewer"
    assert updated.json()["grant"]["scope"] == "subtree"
    assert revoked.status_code == 200, revoked.text
    assert denied_owner.status_code == 403
    assert owner_created.status_code == 201, owner_created.text
    assert owner_created.json()["grant"]["role"] == "owner"
    with grant_management_state["session_factory"]() as session:
        root = session.get(CatalogObject, "grant-root")
        assert root is not None
        assert root.revision == int(owner_created.json()["revision"])
        denied_owner_count = session.scalar(
            select(func.count())
            .select_from(ObjectGrant)
            .where(
                ObjectGrant.object_id == "grant-root",
                ObjectGrant.principal_id == principals["candidate_b"],
                ObjectGrant.role == Role.OWNER,
            )
        )
        assert denied_owner_count == 1
        denial = session.scalar(
            select(SecurityEvent)
            .where(
                SecurityEvent.principal_id == principals["manager"],
                SecurityEvent.event_type == "object_command_authorization",
            )
            .order_by(SecurityEvent.id.desc())
        )
        assert denial is not None
        assert json.loads(denial.details_json)["permission"] == "manage_access"


def test_only_access_manager_and_owner_may_open_grant_management(
    grant_management_client: TestClient,
    grant_management_state,
) -> None:
    tokens = grant_management_state["tokens"]
    principals = grant_management_state["principals"]
    with grant_management_state["session_factory"]() as session:
        with transaction(session):
            create_object_grant(
                session,
                principal_id=principals["candidate_a"],
                object_id="grant-root",
                role=Role.DISCOVERER,
                scope=GrantScope.SELF,
            )
            create_object_grant(
                session,
                principal_id=principals["candidate_b"],
                object_id="grant-root",
                role=Role.EDITOR,
                scope=GrantScope.SELF,
            )
            create_object_grant(
                session,
                principal_id=principals["outsider"],
                object_id="grant-root",
                role=Role.CREATOR,
                scope=GrantScope.SELF,
            )

    statuses = {
        name: grant_management_client.get(
            "/api/v1/objects/grant-root/access",
            headers=_authorization(tokens[name]),
        ).status_code
        for name in (
            "candidate_a",
            "candidate_b",
            "outsider",
            "viewer",
            "manager",
            "owner",
        )
    }

    assert statuses == {
        "candidate_a": 403,
        "candidate_b": 403,
        "outsider": 403,
        "viewer": 403,
        "manager": 200,
        "owner": 200,
    }


def test_self_lockout_and_last_owner_fail_closed(
    grant_management_client: TestClient,
    grant_management_state,
) -> None:
    tokens = grant_management_state["tokens"]
    manager_access = grant_management_client.get(
        "/api/v1/objects/grant-root/access",
        headers=_authorization(tokens["manager"]),
    )
    manager_lockout = grant_management_client.delete(
        (
            "/api/v1/objects/grant-root/access/grants/"
            f"{grant_management_state['grants']['manager']}"
        ),
        headers={
            **_authorization(tokens["manager"]),
            "If-Match": manager_access.headers["etag"],
        },
    )
    owner_access = grant_management_client.get(
        "/api/v1/objects/grant-root/access",
        headers=_authorization(tokens["owner"]),
    )
    last_owner = grant_management_client.delete(
        (
            "/api/v1/objects/grant-root/access/grants/"
            f"{grant_management_state['grants']['owner']}"
        ),
        headers={
            **_authorization(tokens["owner"]),
            "If-Match": owner_access.headers["etag"],
        },
    )

    assert manager_lockout.status_code == 409
    assert last_owner.status_code == 409
    with grant_management_state["session_factory"]() as session:
        assert session.get(
            ObjectGrant,
            grant_management_state["grants"]["manager"],
        ) is not None
        assert session.get(
            ObjectGrant,
            grant_management_state["grants"]["owner"],
        ) is not None


def test_owner_scope_cannot_abandon_descendants_and_owner_transfer_is_safe(
    grant_management_client: TestClient,
    grant_management_state,
) -> None:
    tokens = grant_management_state["tokens"]
    principals = grant_management_state["principals"]
    owner_auth = _authorization(tokens["owner"])
    access = grant_management_client.get(
        "/api/v1/objects/grant-root/access",
        headers=owner_auth,
    )
    second_owner = grant_management_client.post(
        "/api/v1/objects/grant-root/access/grants",
        headers={**owner_auth, "If-Match": access.headers["etag"]},
        json={
            "principal_id": principals["candidate_b"],
            "role": "owner",
            "scope": "self",
        },
    )
    abandoned_descendants = grant_management_client.put(
        (
            "/api/v1/objects/grant-root/access/grants/"
            f"{grant_management_state['grants']['owner']}"
        ),
        headers={**owner_auth, "If-Match": second_owner.headers["etag"]},
        json={"role": "owner", "scope": "self"},
    )
    expanded_second_owner = grant_management_client.put(
        (
            "/api/v1/objects/grant-root/access/grants/"
            f"{second_owner.json()['grant']['id']}"
        ),
        headers={**owner_auth, "If-Match": second_owner.headers["etag"]},
        json={"role": "owner", "scope": "subtree"},
    )
    transferred = grant_management_client.delete(
        (
            "/api/v1/objects/grant-root/access/grants/"
            f"{grant_management_state['grants']['owner']}"
        ),
        headers={
            **_authorization(tokens["candidate_b"]),
            "If-Match": expanded_second_owner.headers["etag"],
        },
    )
    former_owner = grant_management_client.get(
        "/api/v1/objects/grant-root/access",
        headers=owner_auth,
    )

    assert second_owner.status_code == 201, second_owner.text
    assert abandoned_descendants.status_code == 409
    assert expanded_second_owner.status_code == 200, expanded_second_owner.text
    assert transferred.status_code == 200, transferred.text
    assert former_owner.status_code == 404


def test_exact_duplicate_grant_is_a_revision_preserving_noop(
    grant_management_client: TestClient,
    grant_management_state,
) -> None:
    tokens = grant_management_state["tokens"]
    principals = grant_management_state["principals"]
    owner_auth = _authorization(tokens["owner"])
    access = grant_management_client.get(
        "/api/v1/objects/grant-root/access",
        headers=owner_auth,
    )
    payload = {
        "principal_id": principals["candidate_a"],
        "role": "viewer",
        "scope": "self",
    }
    created = grant_management_client.post(
        "/api/v1/objects/grant-root/access/grants",
        headers={**owner_auth, "If-Match": access.headers["etag"]},
        json=payload,
    )
    duplicate = grant_management_client.post(
        "/api/v1/objects/grant-root/access/grants",
        headers={**owner_auth, "If-Match": created.headers["etag"]},
        json=payload,
    )

    assert created.status_code == 201
    assert duplicate.status_code == 201
    assert duplicate.json()["changed"] is False
    assert duplicate.headers["etag"] == created.headers["etag"]
    with grant_management_state["session_factory"]() as session:
        assert session.scalar(
            select(func.count())
            .select_from(AuditEvent)
            .where(
                AuditEvent.object_id == "grant-root",
                AuditEvent.action == "grant_create",
                AuditEvent.actor == principals["owner"],
            )
        ) == 1


def test_grant_changes_are_cas_atomic_audited_and_revocation_is_immediate(
    grant_management_client: TestClient,
    grant_management_state,
) -> None:
    tokens = grant_management_state["tokens"]
    principals = grant_management_state["principals"]
    owner_auth = _authorization(tokens["owner"])
    access = grant_management_client.get(
        "/api/v1/objects/grant-child/access",
        headers=owner_auth,
    )
    created = grant_management_client.post(
        "/api/v1/objects/grant-child/access/grants",
        headers={
            **owner_auth,
            "If-Match": access.headers["etag"],
            "X-Correlation-ID": "grant-api-create",
            "X-Blockwart-Channel": "mcp",
        },
        json={
            "principal_id": principals["candidate_a"],
            "role": "viewer",
            "scope": "self",
        },
    )
    candidate_read = grant_management_client.get(
        "/api/v1/objects/grant-child",
        headers=_authorization(tokens["candidate_a"]),
    )
    stale = grant_management_client.put(
        (
            "/api/v1/objects/grant-child/access/grants/"
            f"{created.json()['grant']['id']}"
        ),
        headers={**owner_auth, "If-Match": access.headers["etag"]},
        json={"role": "editor", "scope": "self"},
    )
    revoked = grant_management_client.delete(
        (
            "/api/v1/objects/grant-child/access/grants/"
            f"{created.json()['grant']['id']}"
        ),
        headers={**owner_auth, "If-Match": created.headers["etag"]},
    )
    candidate_after_revoke = grant_management_client.get(
        "/api/v1/objects/grant-child",
        headers=_authorization(tokens["candidate_a"]),
    )
    audit_page = grant_management_client.get(
        "/api/v1/objects/grant-child/audit-events",
        headers=owner_auth,
    )

    assert created.status_code == 201, created.text
    assert candidate_read.status_code == 200
    assert stale.status_code == 412
    assert revoked.status_code == 200, revoked.text
    assert candidate_after_revoke.status_code == 404
    assert audit_page.status_code == 200
    assert {
        item["summary"]
        for item in audit_page.json()["items"]
        if item["action"] in {"grant_create", "grant_revoke"}
    } >= {
        f"Granted access to principal {principals['candidate_a']}",
        f"Revoked access from principal {principals['candidate_a']}",
    }
    with grant_management_state["session_factory"]() as session:
        events = session.scalars(
            select(AuditEvent)
            .where(
                AuditEvent.object_id == "grant-child",
                AuditEvent.action.in_(("grant_create", "grant_revoke")),
                AuditEvent.actor == principals["owner"],
            )
            .order_by(AuditEvent.id)
        ).all()
        assert [event.action for event in events] == [
            "grant_create",
            "grant_revoke",
        ]
        create_details = json.loads(events[0].details_json)
        assert create_details["channel"] == "mcp"
        assert create_details["request_id"] == "grant-api-create"
        assert create_details["before"] is None
        assert create_details["after"]["role"] == "viewer"
        assert json.loads(events[1].details_json)["after"] is None


def test_parallel_grant_changes_have_one_revision_winner(
    grant_management_state,
) -> None:
    session_factory = grant_management_state["session_factory"]
    principals = grant_management_state["principals"]
    token = grant_management_state["tokens"]["owner"]
    app = create_app()

    def override_get_session() -> Generator[Session, None, None]:
        with session_factory() as session:
            yield session

    app.dependency_overrides[get_session] = override_get_session
    auth = _authorization(token)
    with TestClient(app) as client:
        etag = client.get(
            "/api/v1/objects/grant-root/access",
            headers=auth,
        ).headers["etag"]

        def create(principal_id: str) -> int:
            return client.post(
                "/api/v1/objects/grant-root/access/grants",
                headers={**auth, "If-Match": etag},
                json={
                    "principal_id": principal_id,
                    "role": "viewer",
                    "scope": "self",
                },
            ).status_code

        with ThreadPoolExecutor(max_workers=2) as pool:
            statuses = list(
                pool.map(
                    create,
                    (principals["candidate_a"], principals["candidate_b"]),
                )
            )

    assert sorted(statuses) == [201, 412]
    with session_factory() as session:
        assert session.scalar(
            select(func.count())
            .select_from(ObjectGrant)
            .where(
                ObjectGrant.object_id == "grant-root",
                ObjectGrant.principal_id.in_(
                    (principals["candidate_a"], principals["candidate_b"])
                ),
            )
        ) == 1


def test_catalog_write_payload_cannot_smuggle_acl_state(
    grant_management_client: TestClient,
    grant_management_state,
) -> None:
    token = grant_management_state["tokens"]["owner"]
    auth = _authorization(token)
    detail = grant_management_client.get(
        "/api/v1/objects/grant-root",
        headers=auth,
    )
    with grant_management_state["session_factory"]() as session:
        before = session.scalar(
            select(func.count())
            .select_from(ObjectGrant)
            .where(ObjectGrant.object_id == "grant-root")
        )
    response = grant_management_client.put(
        "/api/v1/objects/grant-root",
        headers={**auth, "If-Match": detail.headers["etag"]},
        json={
            "id": "grant-root",
            "kind": "host",
            "label": "Grant Root",
            "lifecycle": "active",
            "health": "healthy",
            "data": {
                "schema_version": 1,
                "acl": [
                    {
                        "principal_id": grant_management_state["principals"]["outsider"],
                        "role": "owner",
                    }
                ],
            },
        },
    )

    assert response.status_code == 422
    with grant_management_state["session_factory"]() as session:
        assert session.scalar(
            select(func.count())
            .select_from(ObjectGrant)
            .where(ObjectGrant.object_id == "grant-root")
        ) == before
        row = session.get(CatalogObject, "grant-root")
        assert row is not None
        assert "acl" not in row.data_json
        assert session.scalar(
            select(Principal).where(
                Principal.id == grant_management_state["principals"]["outsider"]
            )
        ) is not None
        assert session.scalar(
            select(Relationship).where(
                Relationship.to_ref == "service:grant-unrelated"
            )
        ) is not None


def test_import_schema_rejects_nested_acl_shaped_data() -> None:
    with pytest.raises(ValueError, match="object grant API"):
        CatalogObjectIn(
            id="acl-import-attempt",
            kind="service",
            label="ACL Import Attempt",
            data={
                "schema_version": 1,
                "extension": {
                    "access_grants": [
                        {
                            "principal_id": "not-a-real-principal",
                            "role": "owner",
                        }
                    ]
                },
            },
        )


def test_ui_manages_grants_with_csrf_owner_controls_and_localized_audit(
    alembic_session_factory,
) -> None:
    with alembic_session_factory() as session:
        with transaction(session):
            root = upsert_object(
                session,
                _asset("grant-ui-root", kind="host", label="Grant UI Root"),
            )
            upsert_object(
                session,
                _asset("grant-ui-child", kind="service", label="Grant UI Child"),
            )
            create_relationship(
                session,
                from_ref="host:grant-ui-root",
                relation_type="hosts",
                to_ref="service:grant-ui-child",
            )
            owner = create_human_principal(
                session,
                login="grant.ui.owner",
                display_name="Grant UI Owner",
                password="grant-ui-owner-password-safe-length",
            )
            manager = create_human_principal(
                session,
                login="grant.ui.manager",
                display_name="Grant UI Manager",
                password="grant-ui-manager-password-safe-length",
            )
            viewer = create_human_principal(
                session,
                login="grant.ui.viewer",
                display_name="Grant UI Viewer",
                password="grant-ui-viewer-password-safe-length",
            )
            candidate = create_service_account(
                session,
                login="grant.ui.candidate",
                display_name="Grant UI Candidate",
            )
            owner_grant = create_object_grant(
                session,
                principal_id=owner.id,
                object_id=root.id,
                role=Role.OWNER,
                scope=GrantScope.SUBTREE,
            )
            owner_grant_id = owner_grant.id
            create_object_grant(
                session,
                principal_id=manager.id,
                object_id=root.id,
                role=Role.ACCESS_MANAGER,
                scope=GrantScope.SELF,
            )
            create_object_grant(
                session,
                principal_id=viewer.id,
                object_id=root.id,
                role=Role.VIEWER,
                scope=GrantScope.SELF,
            )
            owner_browser = issue_browser_session(
                session,
                principal_id=owner.id,
                ttl_seconds=3600,
            )
            manager_browser = issue_browser_session(
                session,
                principal_id=manager.id,
                ttl_seconds=3600,
            )
            viewer_browser = issue_browser_session(
                session,
                principal_id=viewer.id,
                ttl_seconds=3600,
            )

    app = create_app()

    def override_get_session() -> Generator[Session, None, None]:
        with alembic_session_factory() as session:
            yield session

    app.dependency_overrides[get_session] = override_get_session
    with TestClient(app) as client:
        client.cookies.set(AUTH_SESSION_COOKIE_NAME, owner_browser.value)
        client.cookies.set(AUTH_CSRF_COOKIE_NAME, owner_browser.csrf_token)
        page = client.get(
            "/objects/grant-ui-root?edit=permissions&principal_q=candidate"
        )
        assert page.status_code == 200, page.text
        assert "Access control" in page.text
        assert "Direct grants" in page.text
        assert "Effective access" in page.text
        assert "Grant UI Child" in page.text
        assert "Grant UI Candidate" in page.text
        assert all(
            secret_field not in page.text
            for secret_field in ("password_hash", "token_hash", "csrf_hash")
        )

        wrong_csrf = client.post(
            "/objects/grant-ui-root/permissions/grants",
            data={
                "csrf_token": "wrong",
                "if_match": page.headers["etag"],
                "principal_id": candidate.id,
                "role": "viewer",
                "scope": "subtree",
            },
            follow_redirects=False,
        )
        created = client.post(
            "/objects/grant-ui-root/permissions/grants",
            data={
                "csrf_token": owner_browser.csrf_token,
                "if_match": page.headers["etag"],
                "principal_id": candidate.id,
                "role": "viewer",
                "scope": "subtree",
            },
            follow_redirects=False,
        )
        assert wrong_csrf.status_code == 403
        assert created.status_code == 303, created.text

        with alembic_session_factory() as session:
            candidate_grant = session.scalar(
                select(ObjectGrant).where(
                    ObjectGrant.object_id == root.id,
                    ObjectGrant.principal_id == candidate.id,
                )
            )
            assert candidate_grant is not None
            candidate_grant_id = candidate_grant.id

        after_create = client.get("/objects/grant-ui-root?edit=permissions")
        updated = client.post(
            f"/objects/grant-ui-root/permissions/grants/{candidate_grant_id}",
            data={
                "csrf_token": owner_browser.csrf_token,
                "if_match": after_create.headers["etag"],
                "role": "editor",
                "scope": "self",
            },
            follow_redirects=False,
        )
        assert updated.status_code == 303, updated.text
        after_update = client.get("/objects/grant-ui-root?edit=permissions")
        revoked = client.post(
            (
                "/objects/grant-ui-root/permissions/grants/"
                f"{candidate_grant_id}/revoke"
            ),
            data={
                "csrf_token": owner_browser.csrf_token,
                "if_match": after_update.headers["etag"],
            },
            follow_redirects=False,
        )
        assert revoked.status_code == 303, revoked.text

        client.cookies.set(AUTH_SESSION_COOKIE_NAME, manager_browser.value)
        client.cookies.set(AUTH_CSRF_COOKIE_NAME, manager_browser.csrf_token)
        manager_page = client.get(
            "/objects/grant-ui-root?edit=permissions&lang=de"
        )
        owner_update_action = (
            f"/objects/grant-ui-root/permissions/grants/{owner_grant_id}?"
        )
        assert manager_page.status_code == 200
        assert "Berechtigungen" in manager_page.text
        assert owner_update_action not in manager_page.text
        assert "Nur ein Owner darf Owner-Freigaben ändern." in manager_page.text
        forged_owner = client.post(
            "/objects/grant-ui-root/permissions/grants",
            data={
                "csrf_token": manager_browser.csrf_token,
                "if_match": manager_page.headers["etag"],
                "principal_id": candidate.id,
                "role": "owner",
                "scope": "self",
            },
            follow_redirects=False,
        )
        assert forged_owner.status_code == 403

        client.cookies.set(AUTH_SESSION_COOKIE_NAME, viewer_browser.value)
        client.cookies.set(AUTH_CSRF_COOKIE_NAME, viewer_browser.csrf_token)
        viewer_page = client.get("/objects/grant-ui-root?edit=permissions&lang=en")
        assert viewer_page.status_code == 200
        assert "Access control" not in viewer_page.text
        assert "/permissions/grants" not in viewer_page.text

    with alembic_session_factory() as session:
        events = session.scalars(
            select(AuditEvent)
            .where(
                AuditEvent.object_id == root.id,
                AuditEvent.actor == owner.id,
                AuditEvent.action.in_(
                    ("grant_create", "grant_update", "grant_revoke")
                ),
            )
            .order_by(AuditEvent.id)
        ).all()
        assert [event.action for event in events] == [
            "grant_create",
            "grant_update",
            "grant_revoke",
        ]
        assert all('"channel":"ui"' in event.details_json for event in events)
        assert session.get(ObjectGrant, candidate_grant_id) is None
        csrf_denial = session.scalar(
            select(SecurityEvent).where(
                SecurityEvent.event_type == "browser_write_csrf",
                SecurityEvent.principal_id == owner.id,
            )
        )
        assert csrf_denial is not None
