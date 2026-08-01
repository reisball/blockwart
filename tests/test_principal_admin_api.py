from __future__ import annotations

from collections.abc import Generator
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from blockwart.api.deps import get_session
from blockwart.cli import auth as auth_cli
from blockwart.db.session import transaction
from blockwart.domain.auth import GrantScope, PlatformRole, Role
from blockwart.main import create_app
from blockwart.models import (
    BrowserSession,
    ObjectGrant,
    PasswordCredential,
    Principal,
    SecurityEvent,
    ServiceToken,
)
from blockwart.schemas.catalog import CatalogObjectIn
from blockwart.services.access import create_object_grant
from blockwart.services.catalog import upsert_object
from blockwart.services.identity import (
    create_human_principal,
    create_service_account,
    issue_service_token,
)

PASSWORD = "api-platform-admin-password"


def _object(object_id: str) -> CatalogObjectIn:
    return CatalogObjectIn(
        id=object_id,
        kind="host",
        label=object_id,
        lifecycle="active",
        health="healthy",
        data={"schema_version": 1},
    )


@pytest.fixture
def principal_admin_api_state(alembic_session_factory):
    with alembic_session_factory() as session:
        with transaction(session):
            visible = upsert_object(session, _object("api-visible"))
            hidden = upsert_object(session, _object("api-hidden"))
            owner = create_human_principal(
                session,
                login="api.human.admin",
                display_name="API Human Admin",
                password=PASSWORD,
                platform_role=PlatformRole.ADMIN,
            )
            api_admin = create_service_account(
                session,
                login="api.platform.admin",
                display_name="API Platform Admin",
                platform_role=PlatformRole.ADMIN,
            )
            non_admin = create_service_account(
                session,
                login="api.non.admin",
                display_name="API Non Admin",
            )
            target = create_service_account(
                session,
                login="api.target",
                display_name="API Target",
            )
            for object_id in (visible.id, hidden.id):
                create_object_grant(
                    session,
                    principal_id=owner.id,
                    object_id=object_id,
                    role=Role.OWNER,
                    scope=GrantScope.SELF,
                )
            api_admin_grant = create_object_grant(
                session,
                principal_id=api_admin.id,
                object_id=visible.id,
                role=Role.ACCESS_MANAGER,
                scope=GrantScope.SELF,
            )
            target_visible_grant = create_object_grant(
                session,
                principal_id=target.id,
                object_id=visible.id,
                role=Role.VIEWER,
                scope=GrantScope.SELF,
            )
            create_object_grant(
                session,
                principal_id=target.id,
                object_id=hidden.id,
                role=Role.VIEWER,
                scope=GrantScope.SELF,
            )
            tokens = {
                "admin": issue_service_token(
                    session, principal_id=api_admin.id, name="admin-api"
                ).value,
                "non_admin": issue_service_token(
                    session, principal_id=non_admin.id, name="ordinary-api"
                ).value,
            }
            api_admin_grant_id = api_admin_grant.id
            target_visible_grant_id = target_visible_grant.id
    return {
        "session_factory": alembic_session_factory,
        "database_url": str(alembic_session_factory.kw["bind"].url),
        "api_admin_id": api_admin.id,
        "api_admin_grant_id": api_admin_grant_id,
        "human_admin_id": owner.id,
        "target_id": target.id,
        "target_visible_grant_id": target_visible_grant_id,
        "tokens": tokens,
    }


@pytest.fixture
def principal_admin_api_client(principal_admin_api_state) -> Generator[TestClient, None, None]:
    app = create_app()
    sessions = principal_admin_api_state["session_factory"]

    def override_get_session() -> Generator[Session, None, None]:
        with sessions() as session:
            yield session

    app.dependency_overrides[get_session] = override_get_session
    with TestClient(app) as client:
        yield client


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _api_principal_snapshot(state, principal_id: str) -> tuple[object, ...]:
    with state["session_factory"]() as session:
        principal = session.get(Principal, principal_id)
        assert principal is not None
        passwords = tuple(
            (row.password_hash, row.updated_at)
            for row in session.scalars(
                select(PasswordCredential).where(
                    PasswordCredential.principal_id == principal_id
                )
            )
        )
        browser_sessions = tuple(
            (row.id, row.revoked_at, row.last_seen_at)
            for row in session.scalars(
                select(BrowserSession).where(BrowserSession.principal_id == principal_id)
            )
        )
        service_tokens = tuple(
            (row.id, row.revoked_at, row.rotated_at, row.last_used_at)
            for row in session.scalars(
                select(ServiceToken).where(ServiceToken.principal_id == principal_id)
            )
        )
        security_events = tuple(
            (row.id, row.event_type, row.outcome, row.details_json)
            for row in session.scalars(
                select(SecurityEvent).where(SecurityEvent.principal_id == principal_id)
            )
        )
        return (
            principal.display_name,
            principal.active,
            principal.platform_role,
            principal.revision,
            passwords,
            browser_sessions,
            service_tokens,
            security_events,
        )


def test_admin_api_is_admin_only_and_reverse_view_does_not_leak_hidden_objects(
    principal_admin_api_client: TestClient,
    principal_admin_api_state,
) -> None:
    tokens = principal_admin_api_state["tokens"]
    target_id = principal_admin_api_state["target_id"]

    denied = principal_admin_api_client.get(
        "/api/v1/admin/principals",
        headers=_auth(tokens["non_admin"]),
    )
    listed = principal_admin_api_client.get(
        "/api/v1/admin/principals",
        headers=_auth(tokens["admin"]),
    )
    detail = principal_admin_api_client.get(
        f"/api/v1/admin/principals/{target_id}",
        headers=_auth(tokens["admin"]),
    )

    assert denied.status_code == 403
    assert listed.status_code == 200
    assert all("password" not in str(item).casefold() for item in listed.json()["items"])
    assert detail.status_code == 200
    assert [item["object_id"] for item in detail.json()["direct_grants"]] == [
        "api-visible"
    ]
    assert "api-hidden" not in detail.text
    assert detail.headers["etag"] == '"rev-1"'


def test_admin_api_creates_principal_without_implicit_catalog_access(
    principal_admin_api_client: TestClient,
    principal_admin_api_state,
) -> None:
    token = principal_admin_api_state["tokens"]["admin"]
    response = principal_admin_api_client.post(
        "/api/v1/admin/principals",
        headers=_auth(token),
        json={
            "principal_type": "service_account",
            "login": "created.agent",
            "display_name": "Created Agent",
            "platform_role": None,
        },
    )
    assert response.status_code == 201
    principal_id = response.json()["principal"]["id"]

    detail = principal_admin_api_client.get(
        f"/api/v1/admin/principals/{principal_id}",
        headers=_auth(token),
    )
    assert detail.status_code == 200
    assert detail.json()["direct_grants"] == []
    assert detail.json()["effective_access"] == []


def test_service_token_secret_is_returned_once_with_no_store(
    principal_admin_api_client: TestClient,
    principal_admin_api_state,
) -> None:
    sessions = principal_admin_api_state["session_factory"]
    admin_token = principal_admin_api_state["tokens"]["admin"]
    target_id = principal_admin_api_state["target_id"]
    headers = {
        **_auth(admin_token),
        "If-Match": '"rev-1"',
        "Idempotency-Key": "admin-api-token-issue-0001",
    }
    payload = {"name": "one-time", "expires_in_seconds": 3600}

    first = principal_admin_api_client.post(
        f"/api/v1/admin/principals/{target_id}/tokens",
        headers=headers,
        json=payload,
    )
    replay = principal_admin_api_client.post(
        f"/api/v1/admin/principals/{target_id}/tokens",
        headers=headers,
        json=payload,
    )

    assert first.status_code == 200
    assert first.json()["disclosure"] == "one_time"
    assert first.json()["token"].startswith("bwst_")
    assert first.headers["cache-control"] == "private, no-store"
    assert replay.status_code == 200
    assert replay.json()["token"] is None
    assert replay.json()["disclosure"] == "none"
    with sessions() as session:
        assert len(
            session.scalars(
                select(ServiceToken).where(
                    ServiceToken.principal_id == target_id,
                    ServiceToken.name == "one-time",
                )
            ).all()
        ) == 1
        serialized_events = " ".join(
            event.details_json for event in session.scalars(select(SecurityEvent)).all()
        )
        assert first.json()["token"] not in serialized_events


def test_principal_update_requires_current_etag(
    principal_admin_api_client: TestClient,
    principal_admin_api_state,
) -> None:
    admin_token = principal_admin_api_state["tokens"]["admin"]
    target_id = principal_admin_api_state["target_id"]
    payload = {
        "display_name": "Renamed Target",
        "active": True,
        "platform_role": None,
    }
    missing = principal_admin_api_client.put(
        f"/api/v1/admin/principals/{target_id}",
        headers=_auth(admin_token),
        json=payload,
    )
    current = principal_admin_api_client.put(
        f"/api/v1/admin/principals/{target_id}",
        headers={**_auth(admin_token), "If-Match": '"rev-1"'},
        json=payload,
    )
    stale = principal_admin_api_client.put(
        f"/api/v1/admin/principals/{target_id}",
        headers={**_auth(admin_token), "If-Match": '"rev-1"'},
        json={**payload, "display_name": "Stale"},
    )

    assert missing.status_code == 428
    assert current.status_code == 200
    assert current.headers["etag"] == '"rev-2"'
    assert stale.status_code == 412


def test_principal_update_requires_explicit_nullable_platform_role(
    principal_admin_api_client: TestClient,
    principal_admin_api_state,
) -> None:
    principal_id = principal_admin_api_state["human_admin_id"]
    before = _api_principal_snapshot(principal_admin_api_state, principal_id)

    response = principal_admin_api_client.put(
        f"/api/v1/admin/principals/{principal_id}",
        headers={
            **_auth(principal_admin_api_state["tokens"]["admin"]),
            "If-Match": '"rev-1"',
        },
        json={"display_name": "API Human Admin", "active": True},
    )

    assert response.status_code == 422
    assert _api_principal_snapshot(principal_admin_api_state, principal_id) == before


@pytest.mark.parametrize(
    ("method", "path_suffix", "payload"),
    (
        (
            "put",
            "",
            {
                "display_name": "   ",
                "active": True,
                "platform_role": None,
            },
        ),
        (
            "post",
            "/password",
            {
                "new_password": "🧪" * 300,
                "current_admin_password": None,
            },
        ),
    ),
)
def test_admin_api_maps_identity_validation_failures_to_safe_client_errors(
    principal_admin_api_client: TestClient,
    principal_admin_api_state,
    method: str,
    path_suffix: str,
    payload: dict[str, object],
) -> None:
    token = principal_admin_api_state["tokens"]["admin"]
    principal_id = (
        principal_admin_api_state["human_admin_id"]
        if path_suffix
        else principal_admin_api_state["target_id"]
    )

    response = principal_admin_api_client.request(
        method,
        f"/api/v1/admin/principals/{principal_id}{path_suffix}",
        headers={**_auth(token), "If-Match": '"rev-1"'},
        json=payload,
    )

    assert response.status_code == 422
    assert response.json()["error"]["message"] == "Invalid identity data"
    assert "🧪" not in response.text


def test_parallel_last_admin_demotions_have_exactly_one_winner(
    alembic_session_factory,
) -> None:
    with alembic_session_factory() as session:
        with transaction(session):
            admins = [
                create_service_account(
                    session,
                    login=f"parallel.admin.{index}",
                    display_name=f"Parallel Admin {index}",
                    platform_role=PlatformRole.ADMIN,
                )
                for index in range(2)
            ]
            tokens = [
                issue_service_token(
                    session,
                    principal_id=admin.id,
                    name=f"parallel-admin-{index}",
                ).value
                for index, admin in enumerate(admins)
            ]

    app = create_app()

    def override_get_session() -> Generator[Session, None, None]:
        with alembic_session_factory() as session:
            yield session

    app.dependency_overrides[get_session] = override_get_session
    with TestClient(app) as client:
        def demote(index: int) -> int:
            return client.put(
                f"/api/v1/admin/principals/{admins[index].id}",
                headers={**_auth(tokens[index]), "If-Match": '"rev-1"'},
                json={
                    "display_name": f"Parallel Admin {index}",
                    "active": True,
                    "platform_role": None,
                },
            ).status_code

        with ThreadPoolExecutor(max_workers=2) as pool:
            statuses = list(pool.map(demote, range(2)))

    assert sorted(statuses) == [200, 409]
    with alembic_session_factory() as session:
        assert sum(
            session.get(Principal, admin.id).platform_role == PlatformRole.ADMIN
            for admin in admins
        ) == 1


@pytest.mark.parametrize("operation", ("password", "token", "deactivate"))
def test_protected_cli_mutations_invalidate_stale_admin_api_etags(
    principal_admin_api_client: TestClient,
    principal_admin_api_state,
    operation: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    admin_token = principal_admin_api_state["tokens"]["admin"]
    principal_id = (
        principal_admin_api_state["human_admin_id"]
        if operation == "password"
        else principal_admin_api_state["target_id"]
    )
    detail = principal_admin_api_client.get(
        f"/api/v1/admin/principals/{principal_id}",
        headers=_auth(admin_token),
    )
    stale_etag = detail.headers["etag"]
    login = detail.json()["principal"]["login"]
    database_args = [
        "--database-url",
        principal_admin_api_state["database_url"],
    ]
    if operation == "password":
        monkeypatch.setattr("sys.stdin", __import__("io").StringIO("new-cli-password-value\n"))
        cli_args = [*database_args, "set-password", "--login", login, "--password-stdin"]
    elif operation == "token":
        cli_args = [
            *database_args,
            "issue-token",
            "--login",
            login,
            "--name",
            "cli-issued",
            "--output-file",
            str(tmp_path / "cli-issued.token"),
        ]
    else:
        cli_args = [*database_args, "deactivate-principal", "--login", login]

    assert auth_cli.main(cli_args) == 0
    capsys.readouterr()
    stale = principal_admin_api_client.put(
        f"/api/v1/admin/principals/{principal_id}",
        headers={**_auth(admin_token), "If-Match": stale_etag},
        json={
            "display_name": "Stale Cross-Channel Mutation",
            "active": operation != "deactivate",
            "platform_role": "admin" if operation == "password" else None,
        },
    )

    assert stale.status_code == 412


def test_admin_principal_list_uses_filter_bound_opaque_cursor_pagination(
    principal_admin_api_client: TestClient,
    principal_admin_api_state,
) -> None:
    headers = _auth(principal_admin_api_state["tokens"]["admin"])
    first = principal_admin_api_client.get(
        "/api/v1/admin/principals?limit=2",
        headers=headers,
    )

    assert first.status_code == 200
    first_payload = first.json()
    assert len(first_payload["items"]) == 2
    assert first_payload["next_cursor"]
    assert "total" not in first_payload

    second = principal_admin_api_client.get(
        "/api/v1/admin/principals",
        headers=headers,
        params={"limit": 2, "cursor": first_payload["next_cursor"]},
    )
    assert second.status_code == 200
    all_ids = [item["id"] for item in first_payload["items"] + second.json()["items"]]
    assert len(all_ids) == len(set(all_ids)) == 4

    mismatched = principal_admin_api_client.get(
        "/api/v1/admin/principals",
        headers=headers,
        params={"limit": 2, "q": "different", "cursor": first_payload["next_cursor"]},
    )
    assert mismatched.status_code == 400


def test_principal_targeted_grant_aliases_match_object_command_policy_and_cas(
    principal_admin_api_client: TestClient,
    principal_admin_api_state,
) -> None:
    headers = _auth(principal_admin_api_state["tokens"]["admin"])
    target_id = principal_admin_api_state["target_id"]
    detail = principal_admin_api_client.get(
        f"/api/v1/admin/principals/{target_id}",
        headers=headers,
    )
    object_etag = detail.json()["direct_grants"][0]["object_etag"]

    created = principal_admin_api_client.post(
        f"/api/v1/admin/principals/{target_id}/grants",
        headers={**headers, "If-Match": object_etag},
        json={"object_id": "api-visible", "role": "editor", "scope": "self"},
    )
    assert created.status_code == 201
    assert created.json()["grant"]["principal"]["id"] == target_id

    grant_id = created.json()["grant"]["id"]
    updated = principal_admin_api_client.put(
        f"/api/v1/admin/principals/{target_id}/grants/{grant_id}",
        headers={**headers, "If-Match": created.headers["etag"]},
        json={"object_id": "api-visible", "role": "viewer", "scope": "subtree"},
    )
    assert updated.status_code == 200
    assert updated.json()["grant"]["scope"] == "subtree"

    revoked = principal_admin_api_client.delete(
        f"/api/v1/admin/principals/{target_id}/grants/{grant_id}",
        headers={**headers, "If-Match": updated.headers["etag"]},
        params={"object_id": "api-visible"},
    )
    assert revoked.status_code == 200
    assert revoked.json()["revoked_grant_id"] == grant_id


def test_principal_targeted_grant_alias_rejects_cross_principal_grant_id(
    principal_admin_api_client: TestClient,
    principal_admin_api_state,
) -> None:
    headers = _auth(principal_admin_api_state["tokens"]["admin"])
    target_id = principal_admin_api_state["target_id"]
    detail = principal_admin_api_client.get(
        f"/api/v1/admin/principals/{target_id}",
        headers=headers,
    )
    object_etag = detail.json()["direct_grants"][0]["object_etag"]

    response = principal_admin_api_client.put(
        (
            f"/api/v1/admin/principals/{target_id}/grants/"
            f"{principal_admin_api_state['api_admin_grant_id']}"
        ),
        headers={**headers, "If-Match": object_etag},
        json={"object_id": "api-visible", "role": "viewer", "scope": "self"},
    )

    assert response.status_code == 404


@pytest.mark.parametrize("method", ("put", "delete"))
def test_principal_grant_alias_does_not_leak_binding_before_object_authorization(
    principal_admin_api_client: TestClient,
    principal_admin_api_state,
    method: str,
) -> None:
    headers = {
        **_auth(principal_admin_api_state["tokens"]["admin"]),
        "If-Match": '"rev-4"',
        "X-Correlation-ID": "principal-grant-alias-no-leak",
    }
    sessions = principal_admin_api_state["session_factory"]
    with sessions() as session:
        with transaction(session):
            actor_grant = session.get(
                ObjectGrant,
                principal_admin_api_state["api_admin_grant_id"],
            )
            assert actor_grant is not None
            actor_grant.role = Role.VIEWER

    responses = []
    for grant_id in (
        principal_admin_api_state["target_visible_grant_id"],
        principal_admin_api_state["api_admin_grant_id"],
        999_999,
    ):
        path = (
            f"/api/v1/admin/principals/{principal_admin_api_state['target_id']}"
            f"/grants/{grant_id}"
        )
        if method == "put":
            response = principal_admin_api_client.put(
                path,
                headers=headers,
                json={
                    "object_id": "api-visible",
                    "role": "viewer",
                    "scope": "self",
                },
            )
        else:
            response = principal_admin_api_client.delete(
                path,
                headers=headers,
                params={"object_id": "api-visible"},
            )
        responses.append(response)

    assert {response.status_code for response in responses} == {403}
    assert len({response.text for response in responses}) == 1
