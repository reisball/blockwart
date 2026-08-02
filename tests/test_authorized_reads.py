from __future__ import annotations

import json
import re
from collections.abc import Generator
from dataclasses import dataclass
from datetime import datetime

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from blockwart.api.deps import get_session
from blockwart.db.session import transaction
from blockwart.domain.auth import GrantScope, Role
from blockwart.main import create_app
from blockwart.mcp.server import call_tool
from blockwart.models import CatalogObject
from blockwart.schemas.catalog import CatalogObjectIn
from blockwart.services.access import create_object_grant
from blockwart.services.audit import add_audit_event
from blockwart.services.catalog import create_relationship, upsert_object
from blockwart.services.identity import (
    create_human_principal,
    create_service_account,
    issue_browser_session,
    issue_service_token,
)
from blockwart.ui.security import AUTH_SESSION_COOKIE_NAME

PRIVATE_MARKER = "UNRELEASED-DETAIL-9d5b"
PRIVATE_ENDPOINT = "https://blockwart.internal:9443/private"
HIDDEN_LABEL = "Hidden Database"


@dataclass(frozen=True)
class AuthorizedReadState:
    api_principal_id: str
    api_token: str
    other_api_token: str
    placement_gap_token: str
    browser_session: str


def _grant_fabrik_scenario(
    session: Session,
    *,
    principal_id: str,
    include_lxc_detail: bool,
) -> None:
    create_object_grant(
        session,
        principal_id=principal_id,
        object_id="fabrik",
        role=Role.VIEWER,
        scope=GrantScope.SELF,
    )
    create_object_grant(
        session,
        principal_id=principal_id,
        object_id="fabrik",
        role=Role.DISCOVERER,
        scope=GrantScope.SUBTREE,
    )
    if include_lxc_detail:
        create_object_grant(
            session,
            principal_id=principal_id,
            object_id="lxc-137",
            role=Role.VIEWER,
            scope=GrantScope.SELF,
        )


@pytest.fixture
def authorized_read_state(
    alembic_session_factory,
) -> tuple[object, AuthorizedReadState]:
    with alembic_session_factory() as session:
        with transaction(session):
            for payload in (
                CatalogObjectIn(
                    id="fabrik",
                    kind="host",
                    label="Fabrik",
                    lifecycle="active",
                    health="healthy",
                    summary="Visible Fabrik details",
                    data={
                        "schema_version": 1,
                        "network": {
                            "hostnames": ["fabrik.internal"],
                            "addresses": [
                                {
                                    "ip": "192.168.50.20",
                                    "family": "ipv4",
                                    "interface": "vmbr0",
                                    "network": "192.168.50.0/24",
                                    "scope": "lan",
                                }
                            ],
                        },
                    },
                ),
                CatalogObjectIn(
                    id="lxc-137",
                    kind="system",
                    label="LXC 137",
                    lifecycle="active",
                    health="degraded",
                    summary="Visible LXC details",
                    data={"schema_version": 1, "type": "lxc"},
                ),
                CatalogObjectIn(
                    id="blockwart",
                    kind="service",
                    label="Blockwart",
                    lifecycle="active",
                    health="down",
                    summary=PRIVATE_MARKER,
                    data={
                        "schema_version": 1,
                        "endpoints": [
                            {
                                "type": "REST API",
                                "url": PRIVATE_ENDPOINT,
                                "host": "blockwart.internal",
                                "port": 9443,
                                "protocol": "https",
                            }
                        ],
                    },
                ),
                CatalogObjectIn(
                    id="hidden-db",
                    kind="service",
                    label=HIDDEN_LABEL,
                    lifecycle="active",
                    health="healthy",
                    summary="Completely hidden object",
                    data={"schema_version": 1},
                ),
                CatalogObjectIn(
                    id="gap-root",
                    kind="host",
                    label="Gap Root",
                    lifecycle="active",
                    health="healthy",
                    data={
                        "schema_version": 1,
                        "network": {
                            "addresses": [
                                {
                                    "ip": "10.99.0.1",
                                    "family": "ipv4",
                                    "interface": "eth0",
                                    "network": "10.99.0.0/24",
                                    "scope": "lan",
                                }
                            ]
                        },
                    },
                ),
                CatalogObjectIn(
                    id="gap-middle",
                    kind="system",
                    label="Gap Middle",
                    lifecycle="active",
                    health="healthy",
                    data={"schema_version": 1},
                ),
                CatalogObjectIn(
                    id="gap-leaf",
                    kind="service",
                    label="Gap Leaf",
                    lifecycle="active",
                    health="healthy",
                    data={"schema_version": 1},
                ),
            ):
                upsert_object(session, payload)
            create_relationship(
                session,
                from_ref="host:fabrik",
                relation_type="hosts",
                to_ref="system:lxc-137",
            )
            create_relationship(
                session,
                from_ref="system:lxc-137",
                relation_type="hosts",
                to_ref="service:blockwart",
            )
            create_relationship(
                session,
                from_ref="service:blockwart",
                relation_type="depends_on",
                to_ref="service:hidden-db",
            )
            create_relationship(
                session,
                from_ref="host:gap-root",
                relation_type="hosts",
                to_ref="system:gap-middle",
            )
            create_relationship(
                session,
                from_ref="system:gap-middle",
                relation_type="hosts",
                to_ref="service:gap-leaf",
            )
            add_audit_event(
                session,
                object_id="blockwart",
                action="update",
                actor="test",
                details={"changes": [{"new": PRIVATE_MARKER, "old": "old"}]},
            )

            api_principal = create_service_account(
                session,
                login="authorized.reader",
                display_name="Authorized Reader",
            )
            _grant_fabrik_scenario(
                session,
                principal_id=api_principal.id,
                include_lxc_detail=True,
            )
            api_token = issue_service_token(
                session,
                principal_id=api_principal.id,
                name="api",
            )

            other_principal = create_service_account(
                session,
                login="other.reader",
                display_name="Other Reader",
            )
            _grant_fabrik_scenario(
                session,
                principal_id=other_principal.id,
                include_lxc_detail=False,
            )
            other_token = issue_service_token(
                session,
                principal_id=other_principal.id,
                name="api",
            )

            gap_principal = create_service_account(
                session,
                login="placement-gap.reader",
                display_name="Placement Gap Reader",
            )
            create_object_grant(
                session,
                principal_id=gap_principal.id,
                object_id="gap-root",
                role=Role.VIEWER,
                scope=GrantScope.SELF,
            )
            create_object_grant(
                session,
                principal_id=gap_principal.id,
                object_id="gap-leaf",
                role=Role.VIEWER,
                scope=GrantScope.SELF,
            )
            gap_token = issue_service_token(
                session,
                principal_id=gap_principal.id,
                name="api",
            )

            browser_principal = create_human_principal(
                session,
                login="browser.reader",
                display_name="Browser Reader",
                password="browser-test-password-with-safe-length",
            )
            _grant_fabrik_scenario(
                session,
                principal_id=browser_principal.id,
                include_lxc_detail=True,
            )
            browser_session = issue_browser_session(
                session,
                principal_id=browser_principal.id,
                ttl_seconds=3600,
            )
    return (
        alembic_session_factory,
        AuthorizedReadState(
            api_principal_id=api_principal.id,
            api_token=api_token.value,
            other_api_token=other_token.value,
            placement_gap_token=gap_token.value,
            browser_session=browser_session.value,
        ),
    )


@pytest.fixture
def authorized_client(
    authorized_read_state,
) -> Generator[tuple[TestClient, AuthorizedReadState], None, None]:
    session_factory, state = authorized_read_state
    app = create_app()

    def override_get_session() -> Generator[Session, None, None]:
        with session_factory() as session:
            yield session

    app.dependency_overrides[get_session] = override_get_session
    with TestClient(app) as client:
        yield client, state


def _authorization(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def test_api_requires_authentication_and_conceals_undiscoverable_objects(
    authorized_client,
) -> None:
    client, state = authorized_client

    unauthenticated = client.get("/api/objects")
    invalid = client.get(
        "/api/v1/objects",
        headers=_authorization("invalid-token"),
    )
    hidden = client.get(
        "/api/v1/objects/hidden-db",
        headers=_authorization(state.api_token),
    )
    hidden_audit = client.get(
        "/api/v1/objects/hidden-db/audit-events",
        headers=_authorization(state.api_token),
    )

    assert unauthenticated.status_code == 401
    assert unauthenticated.headers["www-authenticate"] == "Bearer"
    assert invalid.status_code == 401
    assert hidden.status_code == 404
    assert hidden_audit.status_code == 404
    assert HIDDEN_LABEL not in hidden.text

    gap_headers = _authorization(state.placement_gap_token)
    gap_leaf = client.get("/api/v1/objects/gap-leaf", headers=gap_headers)
    gap_parent_filter = client.get(
        "/api/v1/objects",
        params={"parent": "host:gap-root"},
        headers=gap_headers,
    )
    gap_ip_filter = client.get(
        "/api/v1/objects",
        params={"ip": "10.99.0.1"},
        headers=gap_headers,
    )
    gap_topology = client.get(
        "/api/v1/objects/gap-leaf/topology",
        headers=gap_headers,
    )
    assert gap_leaf.status_code == 200
    assert gap_leaf.json()["parent"] is None
    assert gap_leaf.json()["parent_path"] == []
    assert gap_leaf.json()["placement_state"] == "unknown"
    assert gap_leaf.json()["ips"] == []
    assert gap_parent_filter.json()["items"] == []
    assert [item["id"] for item in gap_ip_filter.json()["items"]] == [
        "gap-root"
    ]
    assert gap_topology.json()["chains"][0]["hosts"] == []
    assert gap_topology.json()["chains"][0]["systems"] == []


def test_fabrik_projection_is_identical_and_stubs_are_strict_across_apis_and_mcp(
    authorized_client,
) -> None:
    client, state = authorized_client
    headers = _authorization(state.api_token)

    catalog_stub = client.get("/api/objects/blockwart", headers=headers)
    agent_stub = client.get("/api/agent/objects/blockwart", headers=headers)
    v1_stub = client.get("/api/v1/objects/blockwart", headers=headers)
    v1_search = client.get(
        "/api/v1/objects",
        params={"q": "Blockwart", "include_total": "true"},
        headers=headers,
    )

    def authenticated_fetch(path: str, params: dict) -> dict:
        response = client.get(
            path,
            params={
                key: value
                for key, value in params.items()
                if value is not None
            },
            headers=headers,
        )
        response.raise_for_status()
        return response.json()

    mcp_search = call_tool(
        "blockwart.search",
        {"q": "Blockwart", "include_total": True},
        fetcher=authenticated_fetch,
    )
    mcp_context = call_tool(
        "blockwart.get_object_context",
        {"object_id": "blockwart"},
        fetcher=authenticated_fetch,
    )

    assert catalog_stub.status_code == 200
    assert "private, no-store" in catalog_stub.headers["cache-control"]
    assert set(catalog_stub.headers["vary"].split(", ")) >= {
        "Authorization",
        "Cookie",
    }
    assert catalog_stub.json() == {
        "visibility": "stub",
        "capabilities": ["discover"],
        "id": "blockwart",
        "kind": "service",
        "label": "Blockwart",
        "parent_path": [
            {
                "visibility": "detail",
                "capabilities": ["discover", "read"],
                "ref": "host:fabrik",
                "id": "fabrik",
                "kind": "host",
                "label": "Fabrik",
                "status": "active",
            },
            {
                "visibility": "detail",
                "capabilities": ["discover", "read"],
                "ref": "system:lxc-137",
                "id": "lxc-137",
                "kind": "system",
                "label": "LXC 137",
                "status": "active",
            },
        ],
        "placement_state": "assigned",
    }
    expected_agent_keys = {
        "capabilities",
        "id",
        "kind",
        "label",
        "parent",
        "parent_path",
        "placement_state",
        "ref",
        "visibility",
    }
    assert set(agent_stub.json()["objects"][0]) == expected_agent_keys
    assert set(v1_stub.json()) == expected_agent_keys
    assert v1_stub.json()["visibility"] == "stub"
    assert v1_search.json()["items"] == [v1_stub.json()]
    assert v1_search.json()["total"] == 1

    mcp_search_payload = json.loads(mcp_search["content"][0]["text"])
    mcp_context_payload = json.loads(mcp_context["content"][0]["text"])
    assert mcp_search_payload["results"] == v1_search.json()["items"]
    assert mcp_context_payload["objects"] == [v1_stub.json()]
    for payload in (
        catalog_stub.text,
        agent_stub.text,
        v1_stub.text,
        json.dumps(mcp_search_payload),
        json.dumps(mcp_context_payload),
    ):
        assert PRIVATE_MARKER not in payload
        assert PRIVATE_ENDPOINT not in payload

    other_catalog_stub = client.get(
        "/api/objects/blockwart",
        headers=_authorization(state.other_api_token),
    ).json()
    assert other_catalog_stub["parent_path"][1] == {
        "visibility": "stub",
        "capabilities": ["discover"],
        "ref": "system:lxc-137",
        "id": "lxc-137",
        "kind": "system",
        "label": "LXC 137",
    }


def test_filters_counts_relationships_audit_and_cursor_do_not_leak_details(
    authorized_client,
    authorized_read_state,
) -> None:
    client, state = authorized_client
    headers = _authorization(state.api_token)

    page = client.get(
        "/api/v1/objects",
        params={"limit": 2, "include_total": "true"},
        headers=headers,
    )
    down_v1 = client.get(
        "/api/v1/objects",
        params={"health": "down", "include_total": "true"},
        headers=headers,
    )
    down_catalog = client.get(
        "/api/objects",
        params={"health": "down"},
        headers=headers,
    )
    private_search = client.get(
        "/api/v1/objects",
        params={"q": PRIVATE_MARKER, "include_total": "true"},
        headers=headers,
    )
    private_port = client.get(
        "/api/v1/objects",
        params={"port": 9443, "include_total": "true"},
        headers=headers,
    )
    relationships = client.get(
        "/api/v1/objects/blockwart/relationships",
        params={"include_total": "true"},
        headers=headers,
    )
    audit = client.get(
        "/api/v1/objects/blockwart/audit-events",
        headers=headers,
    )

    assert page.status_code == 200
    assert page.json()["total"] == 3
    assert page.json()["next_cursor"]
    assert down_v1.json()["items"] == []
    assert down_v1.json()["total"] == 0
    assert down_catalog.json() == []
    assert private_search.json()["items"] == []
    assert private_search.json()["total"] == 0
    assert private_port.json()["items"] == []
    assert private_port.json()["total"] == 0
    assert relationships.json()["items"] == [
        {
            "from_ref": "system:lxc-137",
            "relation_type": "hosts",
            "to_ref": "service:blockwart",
            "metadata": {},
        }
    ]
    assert relationships.json()["total"] == 1
    assert HIDDEN_LABEL not in relationships.text
    assert audit.status_code == 404
    assert PRIVATE_MARKER not in audit.text

    foreign_cursor = client.get(
        "/api/v1/objects",
        params={"limit": 2, "cursor": page.json()["next_cursor"]},
        headers=_authorization(state.other_api_token),
    )
    assert foreign_cursor.status_code == 400
    assert foreign_cursor.json()["error"]["code"] == "invalid_request"

    session_factory, _ = authorized_read_state
    with session_factory() as session:
        with transaction(session):
            create_object_grant(
                session,
                principal_id=state.api_principal_id,
                object_id="hidden-db",
                role=Role.DISCOVERER,
                scope=GrantScope.SELF,
            )
    changed_policy_cursor = client.get(
        "/api/v1/objects",
        params={"limit": 2, "cursor": page.json()["next_cursor"]},
        headers=headers,
    )
    assert changed_policy_cursor.status_code == 400
    assert changed_policy_cursor.json()["error"]["code"] == "invalid_request"


def test_updated_at_sort_does_not_reveal_stub_timestamp(
    authorized_client,
    authorized_read_state,
) -> None:
    client, state = authorized_client
    session_factory, _ = authorized_read_state
    with session_factory() as session:
        with transaction(session):
            session.get(CatalogObject, "fabrik").updated_at = datetime(2021, 1, 1)
            session.get(CatalogObject, "lxc-137").updated_at = datetime(2022, 1, 1)
            session.get(CatalogObject, "blockwart").updated_at = datetime(2099, 1, 1)

    headers = _authorization(state.api_token)
    ascending = client.get(
        "/api/v1/objects",
        params={"sort": "updated_at", "direction": "asc"},
        headers=headers,
    )
    descending = client.get(
        "/api/v1/objects",
        params={"sort": "updated_at", "direction": "desc"},
        headers=headers,
    )

    assert ascending.status_code == 200
    assert descending.status_code == 200
    assert [item["id"] for item in ascending.json()["items"]] == [
        "blockwart",
        "fabrik",
        "lxc-137",
    ]
    assert [item["id"] for item in descending.json()["items"]] == [
        "lxc-137",
        "fabrik",
        "blockwart",
    ]
    assert ascending.json()["items"][0]["visibility"] == "stub"
    assert descending.json()["items"][-1]["visibility"] == "stub"


@pytest.mark.parametrize("language", ["en", "de"])
def test_ui_uses_same_projection_and_principal_scoped_cache_headers(
    authorized_client,
    language: str,
) -> None:
    client, state = authorized_client
    unauthenticated = client.get("/", follow_redirects=False)
    assert unauthenticated.status_code == 303
    assert unauthenticated.headers["location"] == "/auth"

    client.cookies.set(AUTH_SESSION_COOKIE_NAME, state.browser_session)
    index = client.get("/", params={"lang": language})
    stub_detail = client.get("/objects/blockwart", params={"lang": language})
    hidden_detail = client.get("/objects/hidden-db", follow_redirects=False)

    assert index.status_code == 200
    assert stub_detail.status_code == 200
    assert hidden_detail.status_code == 404
    assert "Blockwart" in index.text
    assert "Blockwart" in stub_detail.text
    assert ("Assigned" if language == "en" else "Zugeordnet") in stub_detail.text
    assert 'name="viewport"' in stub_detail.text
    assert "blockwart-theme" in stub_detail.text
    assert PRIVATE_MARKER not in index.text
    assert PRIVATE_ENDPOINT not in index.text
    assert PRIVATE_MARKER not in stub_detail.text
    assert PRIVATE_ENDPOINT not in stub_detail.text
    assets_match = re.search(
        r"window\.BLOCKWART_EXPLORER_ASSETS = (.+);",
        index.text,
    )
    assert assets_match is not None
    stub_asset = json.loads(assets_match.group(1))["service:blockwart"]
    assert set(stub_asset) == {
        "capabilities",
        "id",
        "kind",
        "label",
        "ref",
        "visibility",
    }
    assert "private, no-store" in stub_detail.headers["cache-control"]
    assert stub_detail.headers["pragma"] == "no-cache"
    assert set(stub_detail.headers["vary"].split(", ")) >= {
        "Authorization",
        "Cookie",
    }
