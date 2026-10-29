"""Issue #311: global workspace search, permission isolation and direct links."""

from __future__ import annotations

import json
from datetime import timedelta
from uuid import uuid4

from sqlalchemy import select
from test_catalog_root_creation import root_client, root_state  # noqa: F401
from test_project_records import _browser, _save
from test_project_workspace import _auth, _create_project

from blockwart.db.session import transaction
from blockwart.domain.auth import GrantScope, Role
from blockwart.mcp.server import call_tool
from blockwart.models import CatalogObject, ObjectComment, ObjectGrant, ProjectRecord
from blockwart.services.access import create_object_grant
from blockwart.ui.security import AUTH_SESSION_COOKIE_NAME

SEARCH = "/api/v1/workspace/search"


def _find(client, state, q="Needle", *, token=None, **filters):
    response = client.get(
        SEARCH, params={"q": q, **filters}, headers=_auth(token or state["owner_token"])
    )
    assert response.status_code == 200, response.text
    return response.json()


def _made(client, state, project, kind, **fields):
    response = _save(client, state, {"kind": kind, "title": "Reviewed", **fields}, project=project)
    assert response.status_code == 201, response.text
    return response.json()["record"]


def test_cross_project_current_content_and_real_mcp_api(root_client, root_state):  # noqa: F811
    client, state = root_client, root_state
    for project in ("alpha", "beta"):
        _create_project(client, state["owner_token"], project)
    item = _made(client, state, "alpha", "item", title="Needle task", description="Task context")
    page = _made(client, state, "beta", "page", body="Useful Needle knowledge")
    chronology = client.post(
        "/api/v1/projects/beta/chronology",
        headers=_auth(state["owner_token"], key="global-search-chronology"),
        json={"kind": "milestone", "body": "Needle rollout verified"},
    )
    assert chronology.status_code == 201, chronology.text
    entry = chronology.json()["entry"]
    found = _find(client, state)
    assert found["total"] == 3
    assert {(hit["project_id"], hit["kind"], hit["id"]) for hit in found["items"]} == {
        ("alpha", "item", item["id"]),
        ("beta", "page", page["id"]),
        ("beta", "chronology", entry["id"]),
    }
    assert all(
        hit["project_label"] and "Needle" in hit["excerpt"] and hit["url"].startswith("/projects/")
        for hit in found["items"]
    )
    assert _find(client, state, project_id="beta", kind="page")["total"] == 1
    assert _find(client, state, project_id="missing")["total"] == 0
    # The ranked catalog projection must not suddenly index project workspace prose.
    assert (
        client.get(
            "/api/v1/objects", params={"q": "Needle"}, headers=_auth(state["owner_token"])
        ).json()["items"]
        == []
    )

    def fetch(path, params):
        assert path == SEARCH
        response = client.get(
            path,
            params=params,
            headers={**_auth(state["owner_mcp_token"]), "X-Blockwart-Channel": "mcp"},
        )
        assert response.status_code == 200, response.text
        return response.json()

    result = call_tool(
        "blockwart.search_workspaces", {"q": "Needle", "kind": "page", "limit": 1}, fetcher=fetch
    )
    assert json.loads(result["content"][0]["text"])["items"][0]["id"] == page["id"]


def test_authorization_before_matches_counts_and_cursor_reuse(root_client, root_state):  # noqa: F811
    client, state = root_client, root_state
    for project in ("visible", "discover-only", "hidden"):
        _create_project(client, state["owner_token"], project)
        _made(client, state, project, "page", body="Needle " + project)
    _made(client, state, "visible", "item", description="Needle visible task")
    with state["session_factory"]() as session, transaction(session):
        for project, role in (("visible", Role.VIEWER), ("discover-only", Role.DISCOVERER)):
            create_object_grant(
                session,
                principal_id=state["scoped_id"],
                object_id=project,
                role=role,
                scope=GrantScope.SELF,
            )
    scoped = state["scoped_token"]
    found = _find(client, state, token=scoped, limit=1)
    assert found["total"] == 2 and found["next_cursor"]
    assert {hit["project_id"] for hit in found["items"]} == {"visible"}
    assert _find(client, state, "hidden", token=scoped)["total"] == 0
    assert _find(client, state, "discover-only", token=scoped)["total"] == 0
    for project in ("hidden", "discover-only", "missing"):
        assert _find(client, state, token=scoped, project_id=project) == {
            "items": [],
            "total": 0,
            "next_cursor": None,
        }
    # Cursors carry both caller and current effective authorization, not just q.
    cursor = found["next_cursor"]
    assert (
        client.get(
            SEARCH, params={"q": "Needle", "cursor": cursor}, headers=_auth(state["owner_token"])
        ).status_code
        == 400
    )
    with state["session_factory"]() as session, transaction(session):
        grant = session.scalar(
            select(ObjectGrant).where(
                ObjectGrant.principal_id == state["scoped_id"], ObjectGrant.object_id == "visible"
            )
        )
        session.delete(grant)
    assert (
        client.get(
            SEARCH, params={"q": "Needle", "cursor": cursor}, headers=_auth(scoped)
        ).status_code
        == 400
    )
    assert _find(client, state, token=scoped)["total"] == 0


def test_closed_projection_and_historical_versions_excluded(root_client, root_state):  # noqa: F811
    client, state = root_client, root_state
    _create_project(client, state["owner_token"], "work")
    page = _made(client, state, "work", "page", body="HistoricalOnly")
    updated = _save(
        client,
        state,
        {"kind": "page", "title": "Current", "body": "Needle " + "padding " * 400 + "Straße final"},
        project="work",
        record_id=page["id"],
    )
    assert updated.status_code == 200, updated.text
    _made(client, state, "work", "access", title="AccessOnly", purpose="AccessPurpose")
    _made(client, state, "work", "repository", title="RepoOnly", owner="example", name="repository")
    # Explicit, nested canonical item prose is searchable, arbitrary nested keys are not.
    _made(
        client,
        state,
        "work",
        "item",
        item_type="requirement",
        requirement={"original": "OriginalOnly"},
        criteria=[{"id": "c1", "description": "CriterionOnly"}],
    )
    with state["session_factory"]() as session, transaction(session):
        row = session.get(ProjectRecord, page["id"])
        data = json.loads(row.data_json)
        data.update(
            {
                "credential_reference": "credential_reference:CredentialOnly",
                "secret_location": "vaultwarden:LocationOnly",
                "extensions": {"body": "ExtensionOnly"},
                "related_objects": ["host:ReferenceOnly"],
                "description": "UnknownDescriptionOnly",
                "evidence": {"scope": "UnknownNestedOnly"},
            }
        )
        row.data_json = json.dumps(data)
        project = session.get(CatalogObject, "work")
        canonical = json.loads(project.data_json)
        canonical["extension_payload"] = "CatalogExtensionOnly"
        project.data_json = json.dumps(canonical)
    for term in (
        "HistoricalOnly",
        "CredentialOnly",
        "LocationOnly",
        "ExtensionOnly",
        "ReferenceOnly",
        "AccessOnly",
        "AccessPurpose",
        "RepoOnly",
        "CatalogExtensionOnly",
        "UnknownDescriptionOnly",
        "UnknownNestedOnly",
    ):
        assert _find(client, state, term)["total"] == 0, term
    hit = _find(client, state, "STRASSE")["items"][0]
    assert "Straße final" in hit["excerpt"] and len(hit["excerpt"]) <= 300
    assert not any(
        word in hit["excerpt"] for word in ("CredentialOnly", "LocationOnly", "ExtensionOnly")
    )
    assert _find(client, state, "OriginalOnly")["total"] == 1
    assert _find(client, state, "CriterionOnly")["total"] == 1


def test_deterministic_bounded_pagination_and_filter_binding(root_client, root_state):  # noqa: F811
    client, state = root_client, root_state
    for project in ("z-last", "a-first"):
        _create_project(client, state["owner_token"], project)
        for kind in ("page", "item", "page"):
            _made(client, state, project, kind, title="Needle")
    complete = _find(client, state)
    expected = complete["items"]
    assert expected == sorted(expected, key=lambda hit: (hit["project_id"], hit["kind"], hit["id"]))
    walked, cursor = [], None
    while True:
        page = _find(client, state, limit=2, **({"cursor": cursor} if cursor else {}))
        assert page["total"] == 6 and len(page["items"]) <= 2
        walked.extend(page["items"])
        cursor = page["next_cursor"]
        if not cursor:
            break
    assert walked == expected
    cursor = _find(client, state, limit=1)["next_cursor"]
    for changed in ({"q": "changed"}, {"kind": "page"}, {"project_id": "a-first"}):
        params = {"q": "Needle", "cursor": cursor, **changed}
        assert (
            client.get(SEARCH, params=params, headers=_auth(state["owner_token"])).status_code
            == 400
        )
    for invalid in (
        {"q": " "},
        {"q": "x" * 201},
        {"limit": 0},
        {"limit": 101},
        {"kind": "access"},
        {"cursor": "broken"},
    ):
        response = client.get(
            SEARCH, params={"q": "Needle", **invalid}, headers=_auth(state["owner_token"])
        )
        assert response.status_code == (400 if "cursor" in invalid else 422), response.text


def test_browser_search_escaped_links_and_old_chronology_deep_link(root_client, root_state):  # noqa: F811
    client, state = root_client, root_state
    _create_project(client, state["owner_token"], "work")
    _made(client, state, "work", "item", title="Needle <script>not code</script>")
    response = client.post(
        "/api/v1/projects/work/chronology",
        headers=_auth(state["owner_token"], key="deep-link-chronology"),
        json={"kind": "note", "body": "Needle **old entry** <script>not code</script>"},
    )
    assert response.status_code == 201, response.text
    entry = response.json()["entry"]
    with state["session_factory"]() as session, transaction(session):
        original = session.get(ObjectComment, entry["id"])
        for index in range(101):
            session.add(
                ObjectComment(
                    id=str(uuid4()),
                    object_id=original.object_id,
                    object_instance_id=original.object_instance_id,
                    object_created_at=original.object_created_at,
                    body="Later unrelated entry",
                    origin="legacy",
                    format="plain_text",
                    created_at=original.created_at + timedelta(seconds=index + 1),
                )
            )
    _browser(client, state)
    assert client.get("/").status_code == 200
    assert 'href="/workspace/search"' in client.get("/projects").text
    assert client.get("/workspace/search").status_code == 200
    found = client.get("/workspace/search", params={"q": "Needle", "kind": "", "limit": 1})
    assert found.status_code == 200, found.text
    assert "&lt;script&gt;" in found.text and "<script>not code</script>" not in found.text
    assert "cursor=" in found.text
    assert client.get("/workspace/search?kind=access&q=Needle").status_code == 422
    chronology = next(hit for hit in _find(client, state)["items"] if hit["kind"] == "chronology")
    opened = client.get(chronology["url"])
    assert opened.status_code == 200, opened.text
    assert (
        "<strong>old entry</strong>" in opened.text and f"chronology-{entry['id']}" in opened.text
    )
    assert "<script>not code</script>" not in opened.text
    assert client.get(chronology["url"].replace("/work/", "/existing-object/")).status_code == 404
    client.cookies.clear()
    assert client.get(chronology["url"], follow_redirects=False).status_code == 303
    client.cookies.set(AUTH_SESSION_COOKIE_NAME, state["admin_session"].value)
    assert client.get(chronology["url"]).status_code == 404
    assert client.get("/workspace/search?q=Needle").status_code == 200
    assert "Needle" not in client.get("/workspace/search?q=old").text


def test_project_incarnation_and_chronology_entry_identity(root_client, root_state):  # noqa: F811
    client, state = root_client, root_state
    _create_project(client, state["owner_token"], "work")
    _made(client, state, "work", "page", body="Needle old project")
    response = client.post(
        "/api/v1/projects/work/chronology",
        headers=_auth(state["owner_token"], key="incarnation-chronology"),
        json={"kind": "note", "body": "Needle old chronology"},
    )
    assert response.status_code == 201, response.text
    initial = _find(client, state, limit=1)
    assert initial["total"] == 2 and initial["next_cursor"]
    entry_id = response.json()["entry"]["id"]
    with state["session_factory"]() as session, transaction(session):
        # Simulate a replacement catalog incarnation while old persisted rows remain.
        project = session.get(CatalogObject, "work")
        project.instance_id = uuid4().hex
    assert _find(client, state)["total"] == 0
    rejected = client.get(
        SEARCH,
        params={"q": "Needle", "cursor": initial["next_cursor"]},
        headers=_auth(state["owner_token"]),
    )
    assert rejected.status_code == 400
    _browser(client, state)
    assert client.get(f"/projects/work/chronology/{entry_id}").status_code == 404
