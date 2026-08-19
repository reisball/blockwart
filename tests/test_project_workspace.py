from __future__ import annotations

import json
import re
from collections.abc import Generator
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from html.parser import HTMLParser

from fastapi.testclient import TestClient
from sqlalchemy import func, select
from sqlalchemy.orm import Session
from test_catalog_root_creation import root_client, root_state  # noqa: F401

from blockwart.api.deps import get_session
from blockwart.db.session import transaction
from blockwart.domain.auth import GrantScope, Role
from blockwart.main import create_app
from blockwart.mcp.server import call_tool
from blockwart.models import AuditEvent, CatalogObject, ObjectComment
from blockwart.services.access import create_object_grant
from blockwart.services.identity import (
    create_human_principal,
    create_service_account,
    issue_browser_session,
    issue_service_token,
)
from blockwart.ui.security import AUTH_CSRF_COOKIE_NAME, AUTH_SESSION_COOKIE_NAME

KINDS = (
    "intent",
    "implementation",
    "result",
    "decision",
    "milestone",
    "blocker",
    "note",
)


@dataclass(frozen=True)
class _FilterForm:
    """The rendered `/projects` filter form."""

    action: str
    method: str
    controls: dict[str, tuple[str, ...]]


class _FilterFormParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.action = ""
        self.method = ""
        self.controls: dict[str, list[str]] = {}
        self._seen_form = False
        self._in_form = False
        self._control = ""

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = dict(attrs)
        if tag == "form" and not self._seen_form:
            self._seen_form = True
            self._in_form = True
            self.action = attributes.get("action") or ""
            self.method = (attributes.get("method") or "get").lower()
        elif tag == "select" and self._in_form:
            self._control = attributes.get("name") or ""
            self.controls.setdefault(self._control, [])
        elif tag == "option" and self._control:
            self.controls[self._control].append(attributes.get("value") or "")

    def handle_endtag(self, tag: str) -> None:
        if tag == "select":
            self._control = ""
        elif tag == "form":
            self._in_form = False


def _parse_project_filter_form(html: str) -> _FilterForm:
    parser = _FilterFormParser()
    parser.feed(html)
    return _FilterForm(
        action=parser.action,
        method=parser.method,
        controls={name: tuple(values) for name, values in parser.controls.items()},
    )


def _auth(token: str, *, key: str | None = None) -> dict[str, str]:
    headers = {"Authorization": f"Bearer {token}"}
    if key is not None:
        headers["Idempotency-Key"] = key
    return headers


def _create_project(
    client: TestClient,
    token: str,
    object_id: str,
    *,
    category: str = "implementation",
    status: str = "planned",
    summary: str = "Reviewed public-safe state.",
) -> dict:
    data: dict[str, object] = {
        "schema_version": 1,
        "category": category,
        "project_status": status,
        "current_summary": summary,
        "next_actions": ["Review the fictional rollout plan."],
    }
    if status in {"active", "paused", "completed"}:
        data["started_at"] = "2026-08-18T09:00:00Z"
    if status == "completed":
        data["completed_at"] = "2026-08-18T10:00:00Z"
    response = client.post(
        "/api/v1/roots",
        headers=_auth(token, key=f"create-{object_id}-0001"),
        json={
            "id": object_id,
            "kind": "project",
            "label": object_id.replace("-", " ").title(),
            "data": data,
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def test_standalone_project_workspace_and_seven_kind_flow(
    root_client: TestClient,  # noqa: F811
    root_state,  # noqa: F811
) -> None:
    created = _create_project(root_client, root_state["owner_token"], "standalone-work")
    assert created["catalog_object"]["kind"] == "project"
    context_before_work = root_client.get(
        "/api/v1/objects/standalone-work",
        headers=_auth(root_state["owner_token"]),
    )
    assert context_before_work.json()["parent"] is None

    for index, kind in enumerate(KINDS):
        response = root_client.post(
            "/api/v1/projects/standalone-work/chronology",
            headers=_auth(root_state["owner_token"], key=f"chronology-{kind}-0001"),
            json={"kind": kind, "body": f"{kind.title()} entry {index}."},
        )
        assert response.status_code == 201, response.text
        assert response.json()["entry"]["kind"] == kind

    # The existing generic comment path remains compatible and projects as a note
    # only in the dedicated Project chronology.
    generic = root_client.post(
        "/api/v1/objects/standalone-work/comments",
        headers=_auth(root_state["owner_token"], key="generic-project-note-0001"),
        json={"body": "Legacy-compatible generic Project comment."},
    )
    assert generic.status_code == 201
    assert "kind" not in generic.json()["comment"]

    chronology = root_client.get(
        "/api/v1/projects/standalone-work/chronology?include_total=true",
        headers=_auth(root_state["owner_token"]),
    )
    assert chronology.status_code == 200
    payload = chronology.json()
    assert payload["total"] == 8
    assert {entry["kind"] for entry in payload["items"]} == set(KINDS)
    generic_entry = next(
        entry for entry in payload["items"] if entry["body"].startswith("Legacy-compatible")
    )
    assert generic_entry["kind"] == "note"

    context = root_client.get(
        "/api/agent/objects/standalone-work",
        headers=_auth(root_state["owner_token"]),
    )
    assert context.status_code == 200
    recent = context.json()["objects"][0]["recent_project_chronology"]
    assert recent and all(entry["kind"] in KINDS for entry in recent)

    root_client.cookies.set(AUTH_SESSION_COOKIE_NAME, root_state["owner_session"].value)
    root_client.cookies.set(
        AUTH_CSRF_COOKIE_NAME,
        root_state["owner_session"].csrf_token,
    )
    overview = root_client.get("/projects")
    workspace = root_client.get("/projects/standalone-work")
    assert overview.status_code == 200 and "Standalone Work" in overview.text
    assert workspace.status_code == 200
    assert "Intent → Implementation → Result" in workspace.text
    assert "Professional chronology" in workspace.text


def test_workspace_edit_preserves_other_results_and_uses_safe_deduplicated_links(
    root_client: TestClient,  # noqa: F811
    root_state,  # noqa: F811
) -> None:
    _create_project(
        root_client,
        root_state["owner_token"],
        "workspace-edit",
        category="research",
    )
    with root_state["session_factory"]() as session:
        with transaction(session):
            row = session.get(CatalogObject, "workspace-edit")
            assert row is not None
            data = json.loads(row.data_json)
            data["research_questions"] = ["Does the fictional change help?"]
            row.data_json = json.dumps(data, sort_keys=True, separators=(",", ":"))

    root_client.cookies.set(AUTH_SESSION_COOKIE_NAME, root_state["owner_session"].value)
    root_client.cookies.set(
        AUTH_CSRF_COOKIE_NAME,
        root_state["owner_session"].csrf_token,
    )
    etag = root_client.get("/projects/workspace-edit").headers["etag"]
    saved = root_client.post(
        "/projects/workspace-edit/work",
        data={
            "csrf_token": root_state["owner_session"].csrf_token,
            "if_match": etag,
            "objective": "Keep one canonical Project.",
            "in_scope": "Workspace UI\nWorkspace UI",
            "out_of_scope": "Provisioning",
            "current_summary": "Reviewed through the focused workspace.",
            "open_questions": "What is the fictional review date?",
            "blockers": "Awaiting a fictional approval.",
            "next_actions": "Record the review result.",
            "source_id": "public-issue",
            "source_source_type": "reference",
            "source_reference_kind": "issue",
            "source_title": "Fictional public issue",
            "source_url": "https://example.invalid/issues/42",
        },
        follow_redirects=False,
    )
    assert saved.status_code == 303, saved.text
    with root_state["session_factory"]() as session:
        stored = json.loads(session.get(CatalogObject, "workspace-edit").data_json)
    assert stored["research_questions"] == ["Does the fictional change help?"]
    assert stored["in_scope"] == ["Workspace UI"]
    assert stored["blockers"] == ["Awaiting a fictional approval."]
    assert stored["sources"][0]["reference_kind"] == "issue"


def test_project_overview_authorization_filter_and_activity_do_not_leak(
    root_client: TestClient,  # noqa: F811
    root_state,  # noqa: F811
) -> None:
    _create_project(root_client, root_state["owner_token"], "visible-project")
    _create_project(
        root_client,
        root_state["owner_token"],
        "hidden-project",
        category="migration",
        summary="CONCEALED-PROJECT-SUMMARY",
    )
    hidden_activity = root_client.post(
        "/api/v1/projects/hidden-project/chronology",
        headers=_auth(root_state["owner_token"], key="hidden-activity-0001"),
        json={"kind": "milestone", "body": "CONCEALED-PROJECT-ACTIVITY"},
    )
    assert hidden_activity.status_code == 201

    with root_state["session_factory"]() as session:
        with transaction(session):
            viewer = create_service_account(
                session,
                login="project.viewer",
                display_name="Project Viewer",
            )
            discoverer = create_human_principal(
                session,
                login="project.discoverer",
                display_name="Project Discoverer",
                password="project-discoverer-password-safe-length",
            )
            concealed = create_service_account(
                session,
                login="project.concealed",
                display_name="Project Concealed",
            )
            agent_discoverer = create_service_account(
                session,
                login="project.agent-discoverer",
                display_name="Project Agent Discoverer",
            )
            create_object_grant(
                session,
                principal_id=viewer.id,
                object_id="visible-project",
                role=Role.VIEWER,
                scope=GrantScope.SELF,
            )
            create_object_grant(
                session,
                principal_id=discoverer.id,
                object_id="hidden-project",
                role=Role.DISCOVERER,
                scope=GrantScope.SELF,
            )
            create_object_grant(
                session,
                principal_id=agent_discoverer.id,
                object_id="hidden-project",
                role=Role.DISCOVERER,
                scope=GrantScope.SELF,
            )
            viewer_token = issue_service_token(
                session,
                principal_id=viewer.id,
                name="api",
            )
            concealed_token = issue_service_token(
                session,
                principal_id=concealed.id,
                name="api",
            )
            agent_discoverer_token = issue_service_token(
                session,
                principal_id=agent_discoverer.id,
                name="api",
            )
            discover_session = issue_browser_session(
                session,
                principal_id=discoverer.id,
                ttl_seconds=3600,
            )

    page = root_client.get(
        "/api/v1/projects?include_total=true",
        headers=_auth(viewer_token.value),
    )
    assert page.status_code == 200
    assert page.json()["total"] == 1
    assert [item["id"] for item in page.json()["items"]] == ["visible-project"]
    assert "CONCEALED" not in page.text

    concealed_page = root_client.get(
        "/api/v1/projects?project_category=migration&include_total=true",
        headers=_auth(concealed_token.value),
    )
    assert concealed_page.json() == {
        "items": [],
        "next_cursor": None,
        "total": 0,
        "sort": "last_activity",
        "direction": "desc",
    }
    assert root_client.get(
        "/api/v1/projects/hidden-project/chronology?include_total=true",
        headers=_auth(concealed_token.value),
    ).status_code == 404

    agent_stub = root_client.get(
        "/api/agent/objects/hidden-project",
        headers=_auth(agent_discoverer_token.value),
    )
    assert agent_stub.status_code == 200
    assert "recent_project_chronology" not in agent_stub.text
    assert "CONCEALED" not in agent_stub.text
    agent_filter = root_client.get(
        "/api/agent/context?kind=project&project_category=migration",
        headers=_auth(agent_discoverer_token.value),
    )
    assert agent_filter.status_code == 200
    assert agent_filter.json()["objects"] == []
    assert "CONCEALED" not in agent_filter.text

    root_client.cookies.set(AUTH_SESSION_COOKIE_NAME, discover_session.value)
    stub = root_client.get("/projects/hidden-project")
    filtered_ui = root_client.get("/projects?project_category=migration")
    assert stub.status_code == 200
    assert "CONCEALED-PROJECT" not in stub.text
    assert "CONCEALED-PROJECT" not in filtered_ui.text


def test_chronology_idempotency_secret_rejection_and_audit_minimization(
    root_client: TestClient,  # noqa: F811
    root_state,  # noqa: F811
) -> None:
    _create_project(root_client, root_state["owner_token"], "safe-chronology")
    headers = _auth(root_state["owner_token"], key="same-chronology-key-0001")
    first = root_client.post(
        "/api/v1/projects/safe-chronology/chronology",
        headers=headers,
        json={
            "kind": "implementation",
            "body": "**Rendered** safely.<script>alert('no')</script>",
        },
    )
    replay = root_client.post(
        "/api/v1/projects/safe-chronology/chronology",
        headers=headers,
        json={
            "kind": "implementation",
            "body": "**Rendered** safely.<script>alert('no')</script>",
        },
    )
    conflict = root_client.post(
        "/api/v1/projects/safe-chronology/chronology",
        headers=headers,
        json={"kind": "result", "body": "Different semantics."},
    )
    secret = root_client.post(
        "/api/v1/projects/safe-chronology/chronology",
        headers=_auth(root_state["owner_token"], key="secret-chronology-0001"),
        json={
            "kind": "note",
            "body": "-----BEGIN PRIVATE KEY-----\nfictional",
        },
    )
    assert first.status_code == 201
    assert replay.status_code == 200 and replay.json()["replayed"] is True
    assert conflict.status_code == 409
    assert secret.status_code == 409

    root_client.cookies.set(AUTH_SESSION_COOKIE_NAME, root_state["owner_session"].value)
    rendered = root_client.get("/projects/safe-chronology")
    assert rendered.status_code == 200
    assert "<strong>Rendered</strong>" in rendered.text
    assert "<script>alert('no')</script>" not in rendered.text

    with root_state["session_factory"]() as session:
        assert session.scalar(
            select(func.count(ObjectComment.id)).where(
                ObjectComment.object_id == "safe-chronology"
            )
        ) == 1
        audit = session.scalars(
            select(AuditEvent).where(
                AuditEvent.object_id == "safe-chronology",
                AuditEvent.action == "comment_create",
            )
        ).one()
    assert "Rendered" not in audit.details_json
    assert json.loads(audit.details_json)["project_chronology_kind"] == "implementation"


def test_project_overview_orders_activity_and_binds_filter_cursor(
    root_client: TestClient,  # noqa: F811
    root_state,  # noqa: F811
) -> None:
    _create_project(
        root_client,
        root_state["owner_token"],
        "older-migration",
        category="migration",
        status="active",
    )
    _create_project(
        root_client,
        root_state["owner_token"],
        "newer-implementation",
        category="implementation",
        status="active",
    )
    for object_id in ("older-migration", "newer-implementation"):
        response = root_client.post(
            f"/api/v1/projects/{object_id}/chronology",
            headers=_auth(root_state["owner_token"], key=f"activity-{object_id}-0001"),
            json={"kind": "result", "body": f"Reviewed result for {object_id}."},
        )
        assert response.status_code == 201

    page = root_client.get(
        "/api/v1/projects?limit=1&include_total=true",
        headers=_auth(root_state["owner_token"]),
    )
    assert page.status_code == 200
    payload = page.json()
    assert payload["total"] == 2
    assert payload["items"][0]["id"] == "newer-implementation"
    assert payload["items"][0]["last_professional_activity"]["kind"] == "result"
    assert payload["next_cursor"]

    filtered = root_client.get(
        "/api/v1/projects?project_category=migration&project_status=active",
        headers=_auth(root_state["owner_token"]),
    )
    assert [item["id"] for item in filtered.json()["items"]] == ["older-migration"]
    rebound = root_client.get(
        "/api/v1/projects",
        params={"project_category": "migration", "cursor": payload["next_cursor"]},
        headers=_auth(root_state["owner_token"]),
    )
    assert rebound.status_code == 400


def test_project_overview_filter_form_normalizes_empty_query_parameters(
    root_client: TestClient,  # noqa: F811
    root_state,  # noqa: F811
) -> None:
    owner_token = root_state["owner_token"]
    _create_project(
        root_client,
        owner_token,
        "filter-migration-active",
        category="migration",
        status="active",
    )
    _create_project(
        root_client,
        owner_token,
        "filter-research-active",
        category="research",
        status="active",
    )
    _create_project(
        root_client,
        owner_token,
        "filter-migration-paused",
        category="migration",
        status="paused",
    )
    root_client.cookies.set(AUTH_SESSION_COOKIE_NAME, root_state["owner_session"].value)

    overview = root_client.get("/projects")
    assert overview.status_code == 200
    form = _parse_project_filter_form(overview.text)
    assert (form.action, form.method) == ("/projects/filters/normalize", "get")
    assert list(form.controls) == ["project_category", "project_status"]
    assert form.controls["project_category"][0] == ""
    assert form.controls["project_status"][0] == ""
    assert {"migration", "research"} <= set(form.controls["project_category"])
    assert {"active", "paused"} <= set(form.controls["project_status"])
    assert "projects.js" not in overview.text
    assert '<a class="button button-muted" href="/projects">' in overview.text

    migration_active = "Filter Migration Active"
    research_active = "Filter Research Active"
    migration_paused = "Filter Migration Paused"
    rendered_labels = {migration_active, research_active, migration_paused}
    cases = (
        (
            {"project_category": "", "project_status": "active"},
            "/projects?project_status=active",
            {migration_active, research_active},
        ),
        (
            {"project_category": "migration", "project_status": ""},
            "/projects?project_category=migration",
            {migration_active, migration_paused},
        ),
        (
            {"project_category": "migration", "project_status": "active"},
            "/projects?project_category=migration&project_status=active",
            {migration_active},
        ),
        ({"project_category": "", "project_status": ""}, "/projects", rendered_labels),
    )
    canonical_urls: dict[str, str] = {}
    for selection, expected_target, expected_labels in cases:
        for name, value in selection.items():
            assert value in form.controls[name]
        submitted = root_client.request(
            form.method.upper(),
            form.action,
            params=[(name, selection[name]) for name in form.controls],
            follow_redirects=False,
        )
        assert submitted.status_code == 303
        assert submitted.headers["location"] == expected_target
        canonical_urls[expected_target] = submitted.headers["location"]

        response = root_client.get(submitted.headers["location"])
        assert response.status_code == 200
        for label in rendered_labels:
            assert (label in response.text) is (label in expected_labels)

    # A changed submission gets its own canonical URL; returning to the earlier URL
    # restores its previous result set.
    changed = root_client.request(
        form.method.upper(),
        form.action,
        params=[("project_category", "migration"), ("project_status", "")],
        follow_redirects=False,
    )
    assert changed.headers["location"] == canonical_urls["/projects?project_category=migration"]
    earlier = root_client.get(canonical_urls["/projects?project_status=active"])
    assert earlier.status_code == 200
    assert migration_active in earlier.text
    assert research_active in earlier.text
    assert migration_paused not in earlier.text

    # The typed overview contract still rejects direct empty or invalid values.
    empty_category = root_client.get("/projects?project_category=&project_status=active")
    empty_status = root_client.get("/projects?project_category=migration&project_status=")
    invalid = root_client.get("/projects?project_category=not-a-category")
    assert (empty_category.status_code, empty_status.status_code, invalid.status_code) == (
        422,
        422,
        422,
    )

    # The normalizer forwards nonempty invalid input rather than silently dropping it.
    invalid_submission = root_client.get(
        form.action,
        params={"project_category": "not-a-category", "project_status": ""},
        follow_redirects=False,
    )
    assert invalid_submission.headers["location"] == "/projects?project_category=not-a-category"
    assert root_client.get(invalid_submission.headers["location"]).status_code == 422


def test_project_workspace_filter_id_remains_detail_and_editable(
    root_client: TestClient,  # noqa: F811
    root_state,  # noqa: F811
) -> None:
    _create_project(root_client, root_state["owner_token"], "filter")
    root_client.cookies.set(AUTH_SESSION_COOKIE_NAME, root_state["owner_session"].value)

    detail = root_client.get("/projects/filter")
    assert detail.status_code == 200
    assert "<h1>Filter</h1>" in detail.text
    assert 'href="/projects/filter?edit=true"' in detail.text

    edit = root_client.get("/projects/filter?edit=true")
    assert edit.status_code == 200
    assert '<form class="form-grid" method="post" action="/projects/filter/work">' in edit.text


def test_parallel_same_key_project_chronology_appends_once(root_state) -> None:  # noqa: F811
    session_factory = root_state["session_factory"]
    app = create_app()

    def override_get_session() -> Generator[Session, None, None]:
        with session_factory() as session:
            yield session

    app.dependency_overrides[get_session] = override_get_session
    with TestClient(app) as client:
        _create_project(client, root_state["owner_token"], "parallel-chronology")
        headers = _auth(root_state["owner_token"], key="parallel-chronology-key-0001")
        payload = {"kind": "milestone", "body": "One concurrent milestone."}
        with ThreadPoolExecutor(max_workers=2) as pool:
            responses = list(
                pool.map(
                    lambda _: client.post(
                        "/api/v1/projects/parallel-chronology/chronology",
                        headers=headers,
                        json=payload,
                    ),
                    range(2),
                )
            )

    assert sorted(response.status_code for response in responses) == [200, 201]
    assert sorted(response.json()["replayed"] for response in responses) == [False, True]
    with session_factory() as session:
        assert session.scalar(
            select(func.count(ObjectComment.id)).where(
                ObjectComment.object_id == "parallel-chronology"
            )
        ) == 1
        assert session.scalar(
            select(func.count(AuditEvent.id)).where(
                AuditEvent.object_id == "parallel-chronology",
                AuditEvent.action == "comment_create",
            )
        ) == 1


def test_mcp_project_tools_map_to_the_reviewed_rest_contract(
    root_client: TestClient,  # noqa: F811
    root_state,  # noqa: F811
) -> None:
    _create_project(root_client, root_state["owner_token"], "mcp-project")
    token = root_state["owner_mcp_token"]
    calls: list[tuple[str, str, dict, dict[str, str]]] = []

    def fetch(path: str, params: dict) -> dict:
        response = root_client.get(
            path,
            params={key: value for key, value in params.items() if value is not None},
            headers=_auth(token),
        )
        assert response.status_code == 200, response.text
        return response.json()

    def request(method: str, path: str, body: dict, headers: dict[str, str]) -> dict:
        calls.append((method, path, body, headers))
        response = root_client.request(
            method,
            path,
            json=body,
            headers={**_auth(token), **headers},
        )
        assert response.status_code in {200, 201}, response.text
        return response.json()

    entries = (
        ("intent", "Define the agent-only chronology intent."),
        ("implementation", "Implement the canonical REST wrapper."),
        ("result", "Verify the Project chronology result."),
    )
    created_payloads = []
    for index, (kind, body) in enumerate(entries, start=1):
        created = call_tool(
            "blockwart.append_project_chronology",
            {
                "object_id": "mcp-project",
                "kind": kind,
                "body": body,
                "idempotency_key": f"mcp-project-entry-{index:04d}",
            },
            fetcher=fetch,
            requester=request,
        )
        created_payloads.append(json.loads(created["content"][0]["text"]))

    replay = call_tool(
        "blockwart.append_project_chronology",
        {
            "object_id": "mcp-project",
            "kind": "result",
            "body": "Verify the Project chronology result.",
            "idempotency_key": "mcp-project-entry-0003",
        },
        fetcher=fetch,
        requester=request,
    )
    replay_payload = json.loads(replay["content"][0]["text"])

    rest_page = root_client.get(
        "/api/v1/projects/mcp-project/chronology",
        params={"limit": 1, "include_total": True},
        headers=_auth(token),
    )
    assert rest_page.status_code == 200
    mcp_page = call_tool(
        "blockwart.list_project_chronology",
        {"object_id": "mcp-project", "limit": 1, "include_total": True},
        fetcher=fetch,
    )
    listed_payload = json.loads(mcp_page["content"][0]["text"])
    assert listed_payload == rest_page.json()
    assert listed_payload["total"] == len(entries)
    assert replay_payload == {**created_payloads[-1], "replayed": True}
    assert all(payload["entry"]["origin"] == "mcp" for payload in created_payloads)
    assert all(
        payload["entry"]["author_principal_id"] == root_state["owner_id"]
        and payload["entry"]["author_principal_type"] == "service_account"
        for payload in created_payloads
    )

    # The cursor stays opaque to MCP: each page is forwarded unchanged and
    # together they reproduce the REST/UI chronology entries exactly.
    pages = [listed_payload]
    while pages[-1]["next_cursor"]:
        cursor = pages[-1]["next_cursor"]
        rest_following = root_client.get(
            "/api/v1/projects/mcp-project/chronology",
            params={"limit": 1, "cursor": cursor, "include_total": True},
            headers=_auth(token),
        )
        mcp_following = call_tool(
            "blockwart.list_project_chronology",
            {
                "object_id": "mcp-project",
                "limit": 1,
                "cursor": cursor,
                "include_total": True,
            },
            fetcher=fetch,
        )
        payload = json.loads(mcp_following["content"][0]["text"])
        assert rest_following.status_code == 200
        assert payload == rest_following.json()
        pages.append(payload)
    assert [entry for page in pages for entry in page["items"]] == list(
        reversed([payload["entry"] for payload in created_payloads])
    )
    assert all(page["total"] == len(entries) for page in pages)

    root_client.cookies.set(AUTH_SESSION_COOKIE_NAME, root_state["owner_session"].value)
    workspace = root_client.get("/projects/mcp-project")
    assert workspace.status_code == 200
    assert all(body in workspace.text for _, body in entries)
    assert all(kind.title() in workspace.text for kind, _ in entries)
    assert [
        (
            method,
            path,
            body,
            {
                key: value
                for key, value in headers.items()
                if key != "X-Correlation-ID"
            },
        )
        for method, path, body, headers in calls
    ] == [
        (
            "POST",
            "/api/v1/projects/mcp-project/chronology",
            {"kind": kind, "body": body},
            {
                "Idempotency-Key": f"mcp-project-entry-{index:04d}",
                "X-Blockwart-Channel": "mcp",
            },
        )
        for index, (kind, body) in enumerate(entries, start=1)
    ] + [
        (
            "POST",
            "/api/v1/projects/mcp-project/chronology",
            {"kind": "result", "body": "Verify the Project chronology result."},
            {
                "Idempotency-Key": "mcp-project-entry-0003",
                "X-Blockwart-Channel": "mcp",
            },
        )
    ]
    assert all(
        re.match(r"^[A-Za-z0-9._-]{1,64}$", headers["X-Correlation-ID"])
        for *_, headers in calls
    )

    projects = call_tool(
        "blockwart.list_projects",
        {"project_status": "planned", "include_total": True},
        fetcher=fetch,
    )
    projects_payload = json.loads(projects["content"][0]["text"])
    assert any(item["id"] == "mcp-project" for item in projects_payload["items"])
