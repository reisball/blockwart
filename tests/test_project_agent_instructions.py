"""Project context is user data, never an authorization or search primitive."""

from __future__ import annotations

import json
from html import unescape

import pytest
from pydantic import ValidationError
from test_catalog_root_creation import root_client, root_state  # noqa: F401
from test_project_objects import _browser_session, _project
from test_project_workspace import _auth

from blockwart.db.session import transaction
from blockwart.domain.auth import GrantScope, Role
from blockwart.domain.schema_projection import kind_schema_projection
from blockwart.mcp.server import call_tool
from blockwart.models import CatalogObject
from blockwart.services.access import create_object_grant
from blockwart.services.identity import create_service_account, issue_service_token
from blockwart.ui.project_forms import (
    ProjectForm,
    apply_project_form_data,
    apply_project_workspace_form_data,
)

INSTRUCTIONS = (
    "Fictional PoC: use mocks.\nProportional checks. <script>alert('example')</script>"
    + "\n"
    + "Full user context. " * 300
).strip()


def test_optional_bounded_common_instructions():
    for category in (
        "implementation",
        "migration",
        "research",
        "experiment",
        "incident_review",
        "other",
    ):
        assert "agent_instructions" not in _project("old", category).data
        assert (
            _project("new", category, agent_instructions="x" * 16000).data["agent_instructions"]
            == "x" * 16000
        )
        with pytest.raises(ValidationError, match="agent_instructions"):
            _project("long", category, agent_instructions="x" * 16001)
        with pytest.raises(ValidationError, match="agent_instructions"):
            _project("wrong", category, agent_instructions=["not text"])
    fields = {f["path"]: f for f in kind_schema_projection("project")["data"]["fields"]}
    assert fields["agent_instructions"]["max_length"] == 16000


def test_form_omission_preserves_and_explicit_clear_removes():
    data = {"agent_instructions": INSTRUCTIONS, "extension": "keep"}
    apply_project_form_data(data, ProjectForm(category="implementation", project_status="planned"))
    assert data["agent_instructions"] == INSTRUCTIONS
    apply_project_form_data(data, ProjectForm(category="implementation", agent_instructions=""))
    assert "agent_instructions" not in data
    data["agent_instructions"] = INSTRUCTIONS
    apply_project_workspace_form_data(data, ProjectForm(), submitted_controls=frozenset())
    assert data["agent_instructions"] == INSTRUCTIONS
    apply_project_workspace_form_data(
        data, ProjectForm(), submitted_controls=frozenset({"agent_instructions"})
    )
    assert "agent_instructions" not in data
    assert data["extension"] == "keep"


def _create(client, state):
    response = client.post(
        "/api/v1/roots",
        headers=_auth(state["owner_token"], key="instructions-create-0001"),
        json={
            "id": "instructions",
            "kind": "project",
            "label": "Fictional prototype",
            "data": {
                "schema_version": 1,
                "category": "experiment",
                "project_status": "planned",
                "agent_instructions": INSTRUCTIONS,
            },
        },
    )
    assert response.status_code == 201, response.text


def test_rest_mcp_read_surfaces_masks_and_no_search_index(root_client, root_state):  # noqa: F811
    _create(root_client, root_state)
    headers = _auth(root_state["owner_mcp_token"])

    def fetch(path, params):
        response = root_client.get(
            path, headers=headers, params={k: v for k, v in params.items() if v is not None}
        )
        assert response.status_code == 200, response.text
        return response.json()

    def request(method, path, body, extra):
        response = root_client.request(method, path, json=body, headers={**headers, **extra})
        assert response.status_code == 200, response.text
        return response.json()

    def invoke(tool, args, **kwargs):
        response = call_tool(tool, args, **kwargs)
        return json.loads(response["content"][0]["text"])

    for profile in ("compact", "context", "full"):
        for tool, args, key in (
            ("blockwart.search", {"q": "instructions"}, "results"),
            ("blockwart.get_context", {"q": "instructions"}, "objects"),
            ("blockwart.get_object_contexts", {"object_ids": ["instructions"]}, "objects"),
        ):
            result = invoke(tool, {**args, "projection": profile}, fetcher=fetch, requester=request)
            assert result[key][0]["agent_instructions"] == INSTRUCTIONS
            masked = invoke(
                tool,
                {**args, "projection": profile, "fields": ["orientation"]},
                fetcher=fetch,
                requester=request,
            )
            assert "agent_instructions" not in masked[key][0]
            assert INSTRUCTIONS not in json.dumps(masked)
    detail = invoke("blockwart.get_object_context", {"object_id": "instructions"}, fetcher=fetch)
    assert detail["objects"][0]["data"]["agent_instructions"] == INSTRUCTIONS
    assert detail["objects"][0]["agent_instructions"] == INSTRUCTIONS
    projects = invoke("blockwart.list_projects", {}, fetcher=fetch)
    assert projects["items"][0]["agent_instructions"] == INSTRUCTIONS
    overview = invoke(
        "blockwart.get_project_overview", {"object_id": "instructions"}, fetcher=fetch
    )
    assert overview["agent_instructions"] == INSTRUCTIONS
    assert fetch("/api/v1/objects", {"q": "Proportional"})["items"] == []
    for path, key in (("/api/agent/search", "results"), ("/api/agent/context", "objects")):
        assert (
            fetch(path, {"q": "instructions", "projection": "compact"})[key][0][
                "agent_instructions"
            ]
            == INSTRUCTIONS
        )


def test_instruction_authorization_stubs_and_concealment(root_client, root_state):  # noqa: F811
    _create(root_client, root_state)
    with root_state["session_factory"]() as session:
        with transaction(session):
            account = create_service_account(
                session, login="instructions.reader", display_name="Reader"
            )
            token = issue_service_token(session, principal_id=account.id, name="api").value
            create_object_grant(
                session,
                principal_id=account.id,
                object_id="instructions",
                role=Role.DISCOVERER,
                scope=GrantScope.SELF,
            )
    for profile in ("compact", "context", "full"):
        response = root_client.post(
            "/api/v1/object-contexts",
            headers=_auth(token),
            json={
                "object_ids": ["instructions", "existing-object", "missing"],
                "projection": profile,
            },
        )
        assert response.status_code == 200, response.text
        objects = response.json()["objects"]
        assert objects[0]["visibility"] == "stub"
        assert "agent_instructions" not in json.dumps(objects)
        assert objects[1]["visibility"] == objects[2]["visibility"] == "concealed"
        assert INSTRUCTIONS not in response.text
    page = root_client.get("/api/v1/projects", headers=_auth(token))
    assert page.json()["items"] == []
    overview = root_client.get(
        "/api/v1/projects/instructions/workspace/overview", headers=_auth(token)
    )
    assert overview.status_code == 404


def test_workspace_safe_display_edit_preserve_and_clear(root_client, root_state):  # noqa: F811
    _create(root_client, root_state)
    _browser_session(root_client, root_state)
    for path in ("/projects/instructions", "/objects/instructions"):
        response = root_client.get(path)
        assert 'id="project-instructions-title"' in response.text
        assert "&lt;script&gt;" in response.text
        assert "<script>alert(" not in response.text
    for path in ("/projects/instructions?edit=true", "/objects/instructions?edit=project"):
        response = root_client.get(path)
        assert 'name="agent_instructions" maxlength="16000"' in response.text
        assert INSTRUCTIONS in unescape(response.text)
    for value in ("Updated PoC\nUse a mock", ""):
        current = root_client.get(
            "/api/v1/objects/instructions", headers=_auth(root_state["owner_token"])
        ).json()
        response = root_client.post(
            "/projects/instructions/work",
            data={
                "csrf_token": root_state["owner_session"].csrf_token,
                "if_match": current["etag"],
                "agent_instructions": value,
            },
            follow_redirects=False,
        )
        assert response.status_code == 303, response.text
        with root_state["session_factory"]() as session:
            data = json.loads(session.get(CatalogObject, "instructions").data_json)
        assert data.get("agent_instructions", "") == value

    # The full editor uses the same explicit-empty semantics as the workspace.
    for value in ("Full editor instructions", ""):
        current = root_client.get(
            "/api/v1/objects/instructions", headers=_auth(root_state["owner_token"])
        ).json()
        response = root_client.post(
            "/objects/instructions",
            data={
                "csrf_token": root_state["owner_session"].csrf_token,
                "if_match": current["etag"],
                "category": "experiment",
                "project_status": "planned",
                "agent_instructions": value,
            },
            follow_redirects=False,
        )
        assert response.status_code == 303, response.text
        with root_state["session_factory"]() as session:
            data = json.loads(session.get(CatalogObject, "instructions").data_json)
        assert data.get("agent_instructions", "") == value
