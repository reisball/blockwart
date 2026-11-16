"""Derived access previews preserve Project/metadata/content boundaries."""

# ruff: noqa: F811 -- imported fixtures are injected by pytest.
from __future__ import annotations

import json
from datetime import datetime

import pytest
from sqlalchemy import event, select
from test_catalog_root_creation import root_client, root_state  # noqa: F401
from test_project_records import _browser, _save
from test_project_workspace import _auth, _create_project

from blockwart.db.session import transaction
from blockwart.domain.auth import GrantScope, Role
from blockwart.mcp.server import call_tool
from blockwart.models import CatalogObject, ProjectRecord
from blockwart.schemas.catalog import CatalogObjectIn
from blockwart.services.access import create_object_grant
from blockwart.services.catalog import upsert_object
from blockwart.services.credential_safe import Bao


@pytest.fixture
def project(root_client, root_state):
    _create_project(root_client, root_state["owner_token"], "work")
    return "work"


def _read(client, state, *, token=None):
    response = client.get("/api/v1/objects/work", headers=_auth(token or state["owner_token"]))
    assert response.status_code == 200, response.text
    return response


def test_empty_profiles_masks_and_unchanged_search(project, root_client, root_state):
    client, state = root_client, root_state
    full = _read(client, state).json()["external_access"]
    assert full["items"] == [] and full["has_more"] is False and full["limit"] == 5
    for profile in ["compact", "context", "full"]:
        response = client.post(
            "/api/v1/object-contexts",
            headers=_auth(state["owner_token"]),
            json={"object_ids": ["work"], "projection": profile},
        )
        assert response.status_code == 200, response.text
        assert response.json()["objects"][0]["external_access"] == full
        context = client.get(
            "/api/v1/context",
            headers=_auth(state["owner_token"]),
            params={"q": "work", "projection": profile},
        ).json()
        assert context["items"][0]["external_access"] == full
    search = client.get(
        "/api/v1/objects", headers=_auth(state["owner_token"]), params={"q": "work"}
    ).json()
    assert "external_access" not in json.dumps(search)
    sql = []
    with state["session_factory"]() as session:
        engine = session.get_bind()

    def capture(conn, cursor, statement, parameters, context, executemany):
        if "project_records" in statement.lower():
            sql.append(statement)

    event.listen(engine, "before_cursor_execute", capture)
    try:
        for endpoint in ["/api/v1/context", "/api/v1/object-contexts"]:
            if endpoint.endswith("context"):
                response = client.get(
                    endpoint,
                    headers=_auth(state["owner_token"]),
                    params={"q": "work", "fields": "orientation"},
                )
            else:
                response = client.post(
                    endpoint,
                    headers=_auth(state["owner_token"]),
                    json={"object_ids": ["work"], "fields": ["orientation"]},
                )
            assert response.status_code == 200, response.text
            assert "external_access" not in response.text
        assert not sql
    finally:
        event.remove(engine, "before_cursor_execute", capture)


@pytest.mark.parametrize("count", [1, 5, 6])
def test_order_limit_navigation_etag_and_cross_project(project, root_client, root_state, count):
    client, state = root_client, root_state
    _create_project(client, state["owner_token"], "other")
    before = _read(client, state).headers["etag"]
    records = []
    for index in range(count):
        response = _save(
            client,
            state,
            {
                "kind": "access",
                "title": f"Environment {index}",
                "purpose": "Testing",
                "url": "https://example.test",
            },
        )
        assert response.status_code == 201, response.text
        records.append(response.json()["record"]["id"])
    _save(client, state, {"kind": "access", "title": "OTHER-PROJECT"}, project="other")
    # Force timestamp ties: stable secondary ordering is the record identity.
    with state["session_factory"]() as session, transaction(session):
        for row in session.scalars(select(ProjectRecord).where(ProjectRecord.id.in_(records))):
            row.created_at = datetime(2026, 1, 1)
    response = _read(client, state)
    assert response.headers["etag"] != before  # record writes already advance Project revision
    etag = response.headers["etag"]
    preview = response.json()["external_access"]
    assert [item["id"] for item in preview["items"]] == sorted(records)[:5]
    assert preview["has_more"] is (count > 5)
    assert "OTHER-PROJECT" not in response.text
    collection = client.get(
        preview["collection_api_path"], headers=_auth(state["owner_token"]), params={"limit": 5}
    ).json()
    assert [item["id"] for item in collection["items"]] == sorted(records)[:5]
    assert bool(collection["next_cursor"]) is (count > 5)
    assert _read(client, state).headers["etag"] == etag
    _browser(client, state)
    for path in ["/objects/work", "/projects/work"]:
        html = client.get(path)
        assert html.status_code == 200, html.text
        assert "project-external-access-title" in html.text
        assert preview["collection_href"].replace("&", "&amp;") in html.text
        assert ("More access records are available." in html.text) is (count > 5)
    result = call_tool(
        "blockwart.get_object_context",
        {"object_id": "work"},
        fetcher=lambda path, params: client.get(
            path, params=params, headers=_auth(state["owner_token"])
        ).json(),
    )
    assert json.loads(result["content"][0]["text"])["objects"][0]["external_access"] == preview


@pytest.mark.parametrize("provider", ["vaultwarden", "safe"])
@pytest.mark.parametrize(
    "credential_role", [None, Role.DISCOVERER, Role.VIEWER, Role.REFERENCE_CONTENT_READER]
)
def test_credential_metadata_never_content(
    project, root_client, root_state, monkeypatch, credential_role, provider
):
    client, state = root_client, root_state

    def forbidden(*args, **kwargs):
        pytest.fail("Preview must never construct the secret backend")

    monkeypatch.setattr(Bao, "__init__", forbidden)
    with state["session_factory"]() as session, transaction(session):
        upsert_object(
            session,
            CatalogObjectIn(
                id="private-ref",
                kind="credential_reference",
                label="Metadata label",
                data={
                    "schema_version": 1,
                    "provider": provider,
                    "reference": {}
                    if provider == "safe"
                    else {"path": "STORAGE-LOCATION-NEVER-PUBLISH"},
                    "scope": {"access_type": "api"},
                },
            ),
        )
        create_object_grant(
            session,
            principal_id=state["scoped_id"],
            object_id="work",
            role=Role.VIEWER,
            scope=GrantScope.SELF,
        )
        if credential_role:
            create_object_grant(
                session,
                principal_id=state["scoped_id"],
                object_id="private-ref",
                role=credential_role,
                scope=GrantScope.SELF,
            )
    made = _save(
        client,
        state,
        {
            "kind": "access",
            "title": "Test environment",
            "credential_reference": "credential_reference:private-ref",
        },
    )
    assert made.status_code == 201, made.text
    response = _read(client, state, token=state["scoped_token"])
    preview = response.json()["external_access"]
    credential = preview["items"][0]["credential"]
    if credential_role in (Role.VIEWER, Role.REFERENCE_CONTENT_READER):
        assert credential == {
            "ref": "credential_reference:private-ref",
            "label": "Metadata label",
            "href": "/objects/private-ref",
            "access_type": "api",
        }
    else:
        assert credential is None
        assert "private-ref" not in response.text and "Metadata label" not in response.text
    assert "STORAGE-LOCATION" not in response.text
    # Derived metadata changes are not Project mutations or write validators.
    etag = response.headers["etag"]
    with state["session_factory"]() as session, transaction(session):
        session.get(CatalogObject, "private-ref").label = "Changed metadata label"
    changed = _read(client, state, token=state["scoped_token"])
    assert changed.headers["etag"] == etag
    if credential:
        assert changed.json()["external_access"]["items"][0]["credential"]["label"] == (
            "Changed metadata label"
        )


def test_stub_concealed_and_batch_query_count(project, root_client, root_state):
    client, state = root_client, root_state
    _create_project(client, state["owner_token"], "other")
    with state["session_factory"]() as session, transaction(session):
        create_object_grant(
            session,
            principal_id=state["scoped_id"],
            object_id="work",
            role=Role.DISCOVERER,
            scope=GrantScope.SELF,
        )
        engine = session.get_bind()
    response = client.post(
        "/api/v1/object-contexts",
        headers=_auth(state["scoped_token"]),
        json={"object_ids": ["work", "other", "missing"], "projection": "compact"},
    )
    assert response.status_code == 200, response.text
    objects = response.json()["objects"]
    assert objects[0]["visibility"] == "stub" and "external_access" not in response.text
    for profile in ["compact", "context", "full"]:
        response = client.get(
            "/api/v1/context",
            headers=_auth(state["scoped_token"]),
            params={"q": "work", "projection": profile},
        )
        assert response.status_code == 200, response.text
        assert response.json()["items"][0]["visibility"] == "stub"
        assert "external_access" not in response.text
    assert objects[1] == {"id": "other", "visibility": "concealed"}
    statements = []

    def capture(conn, cursor, statement, parameters, context, executemany):
        if "project_records" in statement.lower():
            statements.append(statement)

    event.listen(engine, "before_cursor_execute", capture)
    try:
        response = client.post(
            "/api/v1/object-contexts",
            headers=_auth(state["owner_token"]),
            json={"object_ids": ["work", "other", "work"], "projection": "compact"},
        )
        assert response.status_code == 200, response.text
        assert len(statements) == 1 and "row_number()" in statements[0]
        assert len(response.json()["objects"]) == 2
    finally:
        event.remove(engine, "before_cursor_execute", capture)
