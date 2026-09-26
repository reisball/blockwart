from __future__ import annotations

import base64
import json
from collections.abc import Generator

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from blockwart.api.deps import get_session
from blockwart.db.session import transaction
from blockwart.domain.auth import GrantScope, PlatformRole, Role
from blockwart.main import create_app
from blockwart.mcp.server import TOOLS, ToolInputError, call_tool
from blockwart.models import ObjectGrant, Principal
from blockwart.schemas.catalog import CatalogObjectIn
from blockwart.services.access import create_object_grant, revoke_object_grant
from blockwart.services.catalog import upsert_object
from blockwart.services.identity import create_service_account, issue_service_token

URL = "/api/v1/auth/me/direct-grants"


def _object(object_id: str, kind: str) -> CatalogObjectIn:
    data: dict[str, object] = {"schema_version": 1}
    if kind == "project":
        data.update(category="other", project_status="planned")
    return CatalogObjectIn(
        id=object_id,
        kind=kind,
        label=object_id,
        lifecycle=None if kind == "project" else "active",
        health=None if kind == "project" else "healthy",
        data=data,
    )


@pytest.fixture
def state(alembic_session_factory):
    with alembic_session_factory() as session:
        with transaction(session):
            for object_id in ("host-a", "host-b", "host-c"):
                upsert_object(session, _object(object_id, "host"))
            for object_id in ("proj-a", "proj-b"):
                upsert_object(session, _object(object_id, "project"))
            agent = create_service_account(session, login="own.agent", display_name="Own Agent")
            other = create_service_account(session, login="other.agent", display_name="Other")
            admin = create_service_account(
                session,
                login="own.admin",
                display_name="Admin",
                platform_role=PlatformRole.ADMIN,
            )
            for object_id in ("host-a", "host-b", "proj-a", "proj-b"):
                create_object_grant(
                    session,
                    principal_id=agent.id,
                    object_id=object_id,
                    role=Role.OWNER,
                    scope=GrantScope.SELF,
                )
            create_object_grant(
                session,
                principal_id=agent.id,
                object_id="host-a",
                role=Role.OWNER,
                scope=GrantScope.SUBTREE,
            )
            create_object_grant(
                session,
                principal_id=agent.id,
                object_id="host-c",
                role=Role.VIEWER,
                scope=GrantScope.SELF,
            )
            create_object_grant(
                session,
                principal_id=other.id,
                object_id="host-c",
                role=Role.OWNER,
                scope=GrantScope.SELF,
            )
            tokens = {
                name: issue_service_token(session, principal_id=p.id, name=name).value
                for name, p in (("agent", agent), ("other", other), ("admin", admin))
            }
            ids = {"agent": agent.id, "other": other.id}
    return {"sessions": alembic_session_factory, "tokens": tokens, "ids": ids}


@pytest.fixture
def client(state) -> Generator[TestClient, None, None]:
    app = create_app()

    def override() -> Generator[Session, None, None]:
        with state["sessions"]() as session:
            yield session

    app.dependency_overrides[get_session] = override
    with TestClient(app) as test_client:
        yield test_client


def _auth(state, name: str = "agent") -> dict[str, str]:
    return {"Authorization": f"Bearer {state['tokens'][name]}"}


def _collect(client, state, limit: int, **params) -> list[dict]:
    items: list[dict] = []
    cursor = None
    for _ in range(50):
        query = {"limit": limit, **params, **({"cursor": cursor} if cursor else {})}
        response = client.get(URL, params=query, headers=_auth(state))
        assert response.status_code == 200, response.text
        body = response.json()
        assert set(body) == {"items", "next_cursor"}
        items.extend(body["items"])
        cursor = body["next_cursor"]
        if cursor is None:
            return items
    raise AssertionError("pagination did not terminate")


OWNER_INVENTORY = [
    {"target_kind": "catalog_object", "target_id": "host-a", "role": "owner", "scope": "self"},
    {"target_kind": "catalog_object", "target_id": "host-a", "role": "owner", "scope": "subtree"},
    {"target_kind": "catalog_object", "target_id": "host-b", "role": "owner", "scope": "self"},
    {"target_kind": "project", "target_id": "proj-a", "role": "owner", "scope": "self"},
    {"target_kind": "project", "target_id": "proj-b", "role": "owner", "scope": "self"},
]


@pytest.mark.parametrize("limit", [1, 2, 3, 200])
def test_owner_inventory_is_complete_across_pages_without_platform_role(
    client, state, limit
) -> None:
    assert _collect(client, state, limit, role="owner") == OWNER_INVENTORY


def test_unfiltered_includes_viewer_and_role_filter_excludes_it(client, state) -> None:
    everything = _collect(client, state, 2)
    assert len(everything) == 6
    assert {"target_kind": "catalog_object", "target_id": "host-c",
            "role": "viewer", "scope": "self"} in everything
    assert all(item["role"] == "owner" for item in _collect(client, state, 2, role="owner"))
    assert _collect(client, state, 5, role="viewer") == [
        {"target_kind": "catalog_object", "target_id": "host-c",
         "role": "viewer", "scope": "self"}
    ]


def test_caller_identity_only_from_authentication(client, state) -> None:
    rejected = client.get(
        URL,
        params={"principal_id": state["ids"]["agent"], "role": "owner"},
        headers=_auth(state, "other"),
    )
    assert rejected.status_code == 400
    other = client.get(URL, params={"role": "owner"}, headers=_auth(state, "other"))
    assert other.status_code == 200
    assert other.json()["items"] == [
        {"target_kind": "catalog_object", "target_id": "host-c",
         "role": "owner", "scope": "self"}
    ]
    assert "own.agent" not in other.text and state["ids"]["agent"] not in other.text
    # A platform admin without grants sees nothing of anyone else's.
    admin = client.get(URL, headers=_auth(state, "admin"))
    assert admin.status_code == 200 and admin.json() == {"items": [], "next_cursor": None}


def test_unauthenticated_and_inactive_are_rejected(client, state) -> None:
    assert client.get(URL).status_code == 401
    assert client.get(URL, headers={"Authorization": "Bearer nope"}).status_code == 401
    with state["sessions"]() as session:
        with transaction(session):
            session.get(Principal, state["ids"]["agent"]).active = False
    assert client.get(URL, headers=_auth(state)).status_code == 401


@pytest.mark.parametrize("params", [{"limit": 0}, {"limit": 201}, {"limit": "x"}, {"role": "root"}])
def test_invalid_limit_or_role_is_rejected(client, state, params) -> None:
    assert client.get(URL, params=params, headers=_auth(state)).status_code in {400, 422}


def test_invalid_cursors_are_rejected(client, state) -> None:
    first = client.get(URL, params={"limit": 1, "role": "owner"}, headers=_auth(state)).json()
    cursor = first["next_cursor"]
    assert cursor
    foreign = base64.urlsafe_b64encode(json.dumps({"v": 1}).encode()).decode().rstrip("=")
    for bad in ("", "!!!", foreign, "a" * 3000):
        response = client.get(URL, params={"cursor": bad}, headers=_auth(state))
        assert response.status_code in {400, 422}
    # A cursor is bound to its role filter.
    mismatched = client.get(
        URL, params={"cursor": cursor, "role": "viewer"}, headers=_auth(state)
    )
    assert mismatched.status_code == 400
    foreign_principal = client.get(
        URL,
        params={"cursor": cursor, "role": "owner", "limit": 1},
        headers=_auth(state, "other"),
    )
    assert foreign_principal.status_code == 400


def test_mutation_during_traversal_never_duplicates(client, state) -> None:
    first = client.get(URL, params={"limit": 2, "role": "owner"}, headers=_auth(state)).json()
    with state["sessions"]() as session:
        with transaction(session):
            upsert_object(session, _object("host-0", "host"))
            create_object_grant(
                session,
                principal_id=state["ids"]["agent"],
                object_id="host-0",
                role=Role.OWNER,
                scope=GrantScope.SELF,
            )
            upsert_object(session, _object("host-z", "host"))
            create_object_grant(
                session,
                principal_id=state["ids"]["agent"],
                object_id="host-z",
                role=Role.OWNER,
                scope=GrantScope.SELF,
            )
            create_object_grant(  # keep host-b owned so the revoke is allowed
                session,
                principal_id=state["ids"]["other"],
                object_id="host-b",
                role=Role.OWNER,
                scope=GrantScope.SELF,
            )
            grant = session.scalar(
                select(ObjectGrant).where(
                    ObjectGrant.object_id == "host-b",
                    ObjectGrant.principal_id == state["ids"]["agent"],
                    ObjectGrant.role == "owner",
                )
            )
            revoke_object_grant(session, grant_id=grant.id)
    items = list(first["items"])
    cursor = first["next_cursor"]
    while cursor:
        page = client.get(
            URL, params={"limit": 2, "role": "owner", "cursor": cursor}, headers=_auth(state)
        ).json()
        items.extend(page["items"])
        cursor = page["next_cursor"]
    keys = [(i["target_id"], i["scope"]) for i in items]
    assert len(keys) == len(set(keys))
    assert ("host-z", "self") in keys  # added after the cursor: appears
    assert ("host-0", "self") not in keys  # added before the cursor: not visible
    assert ("host-b", "self") not in keys  # revoked ahead of the cursor: gone



def test_mcp_owner_inventory_traverses_rest_pages(client, state) -> None:
    def fetcher(path, params):
        response = client.get(
            path,
            params={key: value for key, value in params.items() if value is not None},
            headers=_auth(state),
        )
        assert response.status_code == 200, response.text
        return response.json()

    items: list[dict] = []
    cursor = None
    for _ in range(10):
        args = {"role": "owner", "limit": 2}
        if cursor is not None:
            args["cursor"] = cursor
        response = call_tool("blockwart.list_own_direct_grants", args, fetcher=fetcher)
        assert response["isError"] is False
        page = json.loads(response["content"][0]["text"])
        items.extend(page["items"])
        cursor = page["next_cursor"]
        if cursor is None:
            break
    else:
        raise AssertionError("MCP pagination did not terminate")
    assert items == OWNER_INVENTORY


def test_mcp_tool_is_self_scoped_read_only_and_forwards_pagination() -> None:
    tool = next(t for t in TOOLS if t["name"] == "blockwart.list_own_direct_grants")
    assert tool["annotations"]["readOnlyHint"]
    assert "principal_id" not in tool["inputSchema"]["properties"]
    assert tool["inputSchema"]["additionalProperties"] is False
    calls = []

    def fetcher(path, params):
        calls.append((path, params))
        return {"items": [], "next_cursor": None}

    call_tool(
        "blockwart.list_own_direct_grants",
        {"role": "owner", "limit": 2, "cursor": "abc"},
        fetcher=fetcher,
    )
    assert calls == [(URL, {"role": "owner", "limit": 2, "cursor": "abc"})]
    with pytest.raises(ToolInputError):
        call_tool(
            "blockwart.list_own_direct_grants",
            {"principal_id": "someone"},
            fetcher=fetcher,
        )
    assert len(calls) == 1


def test_endpoint_is_read_only_and_admin_endpoint_unchanged(client, state) -> None:
    assert client.post(URL, headers=_auth(state)).status_code == 405
    denied = client.get("/api/v1/admin/principals", headers=_auth(state))
    assert denied.status_code == 403
