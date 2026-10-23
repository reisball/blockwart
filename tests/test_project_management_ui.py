"""Browser workflows for epic #287: structured controls and protected commands."""

from __future__ import annotations

import html
import json
import re
from datetime import datetime, timedelta
from html.parser import HTMLParser
from uuid import uuid4

# Reuse the real migrated databases and authenticated browser fixtures.
# ruff: noqa: F401, F811
from test_project_records import (
    _browser,
    _etag,
    _save,
    alembic_session_factory,
    migrated_pg_engine,
    pg_database_name,
    project,
    root_client,
    root_state,
)
from test_project_workspace import _create_project

from blockwart.db.session import transaction
from blockwart.models import CatalogObject, ProjectRecordEvent
from blockwart.ui.i18n import validate_locale_catalogs


class BrowserForm(HTMLParser):
    """Submit the actual rendered controls, including repeated structured rows."""

    def __init__(self, source):
        super().__init__()
        self.values = {}
        self.selected = False
        self.control = None
        self.options = []
        self.feed(source)

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "form":
            self.selected = attrs.get("action") == "/projects/work/workspace"
        if not self.selected:
            return
        name = attrs.get("name")
        if (
            tag == "input"
            and name
            and (attrs.get("type") not in {"checkbox", "radio"} or "checked" in attrs)
        ):
            self.add(name, attrs.get("value", ""))
        if tag in {"select", "textarea"}:
            self.control = (tag, name)
            self.options = []
        if tag == "option":
            self.options.append((attrs.get("value", ""), "selected" in attrs))
        if tag == "textarea":
            self.add(name, "")

    def handle_endtag(self, tag):
        if tag == "form":
            self.selected = False
        if self.selected and self.control and tag == self.control[0]:
            if tag == "select":
                chosen = next((v for v, selected in self.options if selected), self.options[0][0])
                self.add(self.control[1], chosen)
            self.control = None

    def handle_data(self, data):
        if self.selected and self.control and self.control[0] == "textarea":
            self.values[self.control[1]][-1] += data

    def add(self, name, value):
        self.values.setdefault(name, []).append(value)

    def data(self):
        return {
            key: values if len(values) > 1 else values[0] for key, values in self.values.items()
        }


def _record(client, state, data, **kwargs):
    response = _save(client, state, data, **kwargs)
    assert response.is_success, response.text
    return response.json()["record"]


def _action(client, state, record, **data):
    return client.post(
        f"/projects/work/workspace/record/{record['id']}",
        data={
            "csrf_token": state["owner_session"].csrf_token,
            "record_etag": record["record_etag"],
            "idempotency_key": f"ui-test-{uuid4().hex}",
            **data,
        },
        follow_redirects=False,
    )


def test_hierarchy_named_parent_filtered_branch_and_deep_link(project, root_client, root_state):
    client, state = root_client, root_state
    parent = _record(
        client, state, {"kind": "item", "title": "Named use case", "item_type": "use_case"}
    )
    child = _record(
        client,
        state,
        {"kind": "item", "title": "Nested task", "parent_id": parent["id"], "priority": "urgent"},
    )
    _browser(client, state)
    page = client.get("/projects/work/workspace?item_type=task&priority=urgent")
    assert page.status_code == 200, page.text
    assert "Outside current filter/page" in page.text
    assert "<details open><summary>Subitems" in page.text
    assert parent["short_code"] in page.text and child["short_code"] in page.text
    assert f"/workspace/record/{child['id']}" in page.text
    form = client.get(f"/projects/work/workspace?parent_id={parent['id']}")
    assert (
        f'<option value="{parent["id"]}" selected>{parent["short_code"]} · Named use case'
        in form.text
    )
    detail = client.get(f"/projects/work/workspace/record/{child['short_code']}")
    assert detail.status_code == 200, detail.text
    assert "Named use case" in detail.text


def test_real_structured_browser_roundtrip_and_old_editor_preserve_metadata(
    project, root_client, root_state
):
    client, state = root_client, root_state
    requirement = _record(
        client,
        state,
        {
            "kind": "item",
            "title": "Exact requirement",
            "item_type": "requirement",
            "priority": "high",
            "mandatory": False,
            "requirement": {
                "original": "Original wording",
                "source_url": "https://example.com/spec",
                "change_reason": "Clarification",
            },
            "criteria": [{"id": "C1", "description": "Exact acceptance", "required": True}],
        },
    )
    _browser(client, state)
    page = client.get(f"/projects/work/workspace?edit_id={requirement['id']}")
    assert page.status_code == 200, page.text
    assert 'name="criterion_id"' in page.text and 'name="requirement_original"' in page.text
    data = BrowserForm(page.text).data()
    result = client.post("/projects/work/workspace", data=data, follow_redirects=False)
    assert result.status_code == 303, result.text
    old_edit = client.post(
        "/projects/work/workspace",
        data={
            "csrf_token": state["owner_session"].csrf_token,
            "kind": "item",
            "record_id": requirement["id"],
            "title": "Renamed in old browser",
            "if_match": _etag(client, state),
            "idempotency_key": f"old-browser-{uuid4().hex}",
        },
        follow_redirects=False,
    )
    assert old_edit.status_code == 303, old_edit.text
    from test_project_workspace import _auth

    stored = client.get(
        "/api/v1/projects/work/workspace/item", headers=_auth(state["owner_token"])
    ).json()["items"][0]
    assert stored["data"]["criteria"] == requirement["data"]["criteria"]
    assert stored["data"]["requirement"] == requirement["data"]["requirement"]
    assert stored["data"]["priority"] == "high" and not stored["data"]["mandatory"]
    assert stored["requirement_revision"] == 2  # title changed, not a lossy form roundtrip


def test_structured_evidence_relations_repository_and_explicit_sync_controls(
    project, root_client, root_state
):
    client, state = root_client, root_state
    requirement = _record(
        client,
        state,
        {
            "kind": "item",
            "title": "Requirement",
            "item_type": "requirement",
            "criteria": [{"id": "C1", "description": "Verified"}],
        },
    )
    repo = _record(
        client,
        state,
        {
            "kind": "repository",
            "title": "Example repository",
            "owner": "example",
            "name": "project",
        },
    )
    task = _record(
        client,
        state,
        {
            "kind": "item",
            "title": "Implementation",
            "relations": [{"relation": "implements", "target_id": requirement["id"]}],
            "github_references": [{"repository_id": repo["id"], "kind": "issue", "number": 12}],
        },
    )
    _browser(client, state)
    page = client.get("/projects/work/workspace?kind=repository")
    assert 'name="sync_enabled" value="true" checked' not in page.text
    assert 'name="owner"' in page.text and 'name="github_id"' in page.text
    detail = client.get(f"/projects/work/workspace/record/{task['id']}")
    assert "https://github.com/example/project/issues/12" in detail.text
    assert 'name="action" value="sync_github"' in detail.text
    assert requirement["short_code"] in detail.text
    form = client.get("/projects/work/workspace")
    data = BrowserForm(form.text).data()
    data.update(
        title="Verified evidence",
        item_type="evidence",
        evidence_requirement_id=requirement["id"],
        evidence_requirement_revision="1",
        evidence_criteria="C1",
        evidence_outcome="pass",
        evidence_subject="revision abc",
        evidence_scope="Focused check",
        evidence_source_url="https://example.com/check",
        evidence_observed_at="2026-10-23T10:00:00Z",
    )
    saved = client.post("/projects/work/workspace", data=data, follow_redirects=False)
    assert saved.status_code == 303, saved.text
    overview = client.get("/projects/work/workspace")
    assert "Verified evidence" in overview.text
    assert "Not assessed for this revision" in overview.text


def test_comments_activity_pagination_markdown_and_stale_cas(project, root_client, root_state):
    client, state = root_client, root_state
    task = _record(client, state, {"kind": "item", "title": "Discussion"})
    _browser(client, state)
    commented = _action(
        client,
        state,
        task,
        action="comment",
        body="**Reviewed** <script>alert(1)</script> [bad](javascript:alert(1))",
    )
    assert commented.status_code == 303, commented.text
    stale = _action(client, state, task, action="patch", status="done")
    assert stale.status_code == 412, stale.text
    malformed = _action(client, state, task, action="patch", status="invalid-status")
    assert malformed.status_code == 422, malformed.text
    bad_archive = _action(client, state, task, action="patch", archived="invalid-boolean")
    assert bad_archive.status_code == 422, bad_archive.text
    with state["session_factory"]() as session, transaction(session):
        instance = session.get(CatalogObject, project).instance_id
        for index in range(51):
            session.add(
                ProjectRecordEvent(
                    id=str(uuid4()),
                    project_instance_id=instance,
                    record_id=task["id"],
                    kind="comment",
                    data_json=json.dumps({"body": f"ActivityMarker{index:03d}"}),
                    author_id=state["human_owner_id"],
                    author_label="Reviewer",
                    origin="ui",
                    created_at=datetime(2030, 1, 1) + timedelta(seconds=index),
                )
            )
    detail = client.get(commented.headers["location"] + "?event_kind=comment")
    assert detail.status_code == 200, detail.text
    assert "<strong>Reviewed</strong>" in detail.text
    assert "<script>alert(1)</script>" not in detail.text and 'href="javascript:' not in detail.text
    next_url = html.unescape(re.search(r'href="([^"]*event_cursor=[^"]+)"', detail.text)[1])
    next_page = client.get(commented.headers["location"] + next_url)
    assert next_page.status_code == 200, next_page.text
    assert "ActivityMarker050" in next_page.text and "ActivityMarker000" not in next_page.text


def test_work_completion_not_acceptance_assessment_and_archive_actions(
    project, root_client, root_state
):
    client, state = root_client, root_state
    requirement = _record(
        client, state, {"kind": "item", "title": "Requirement", "item_type": "requirement"}
    )
    _browser(client, state)
    detail = client.get(f"/projects/work/workspace/record/{requirement['id']}")
    assert 'name="action" value="assess"' in detail.text
    assert "Work state (not requirement acceptance)" in detail.text
    assessment = _action(
        client,
        state,
        requirement,
        action="assess",
        result="exception",
        reason="Scoped exception for an untestable requirement",
    )
    assert assessment.status_code == 303, assessment.text
    assert "Reasoned exception" in client.get(assessment.headers["location"]).text
    from test_project_workspace import _auth

    current = client.get(
        "/api/v1/projects/work/workspace/item", headers=_auth(state["owner_token"])
    ).json()["items"][0]
    archived = _action(client, state, current, action="patch", archived="true")
    assert archived.status_code == 303, archived.text
    active = client.get("/projects/work/workspace")
    assert f'id="record-{requirement["id"]}"' not in active.text
    archive = client.get("/projects/work/workspace?archived=archived")
    assert f'id="record-{requirement["id"]}"' in archive.text


def test_legacy_import_is_explicit_and_preserves_source(project, root_client, root_state):
    client, state = root_client, root_state
    with state["session_factory"]() as session, transaction(session):
        row = session.get(CatalogObject, project)
        source = json.loads(row.data_json)
        source["open_questions"] = ["Legacy question"]
        row.data_json = json.dumps(source)
    _browser(client, state)
    page = client.get("/projects/work/workspace")
    assert "Import this entry explicitly" in page.text
    assert "Imported record is authoritative" not in page.text
    imported = client.post(
        "/projects/work/workspace/import-legacy",
        data={
            "csrf_token": state["owner_session"].csrf_token,
            "if_match": page.headers["etag"],
            "idempotency_key": f"legacy-ui-{uuid4().hex}",
            "field": "open_questions",
            "index": "0",
            "text": "Legacy question",
        },
        follow_redirects=False,
    )
    assert imported.status_code == 303, imported.text
    assert "Imported record is authoritative" in client.get(imported.headers["location"]).text
    from test_project_workspace import _auth

    record = client.get(
        "/api/v1/projects/work/workspace/item", headers=_auth(state["owner_token"])
    ).json()["items"][0]
    activity = client.get(
        f"/projects/work/workspace/record/{record['id']}?event_kind=import_legacy"
    )
    assert activity.status_code == 200, activity.text
    assert "Legacy entry imported" in activity.text
    assert "Source revision" in activity.text and "Source fingerprint" in activity.text
    assert "Structured records" in activity.text
    german = client.get(
        f"/projects/work/workspace/record/{record['id']}?lang=de&event_kind=import_legacy"
    )
    assert "Alteintrag importiert" in german.text
    with state["session_factory"]() as session:
        assert json.loads(session.get(CatalogObject, project).data_json)["open_questions"] == [
            "Legacy question"
        ]


def test_detail_authorization_csrf_concealment_and_german(project, root_client, root_state):
    from blockwart.domain.auth import GrantScope, Role
    from blockwart.services.access import create_object_grant
    from blockwart.services.identity import create_human_principal, issue_browser_session
    from blockwart.ui.security import AUTH_CSRF_COOKIE_NAME, AUTH_SESSION_COOKIE_NAME

    client, state = root_client, root_state
    task = _record(client, state, {"kind": "item", "title": "Protected task"})
    _create_project(client, state["owner_token"], "other")
    _browser(client, state)
    assert client.get(f"/projects/other/workspace/record/{task['id']}").status_code == 404
    assert (
        _action(client, state, task, action="comment", body="Denied", csrf_token="bad").status_code
        == 403
    )
    german = client.get(f"/projects/work/workspace/record/{task['id']}?lang=de")
    assert german.status_code == 200 and "Kommentare und Aktivitäten" in german.text
    with state["session_factory"]() as session, transaction(session):
        reader = create_human_principal(
            session,
            login="pm.viewer",
            display_name="PM Viewer",
            password="viewer-password-unique-12",
        )
        create_object_grant(
            session,
            principal_id=reader.id,
            object_id=project,
            role=Role.VIEWER,
            scope=GrantScope.SELF,
        )
        issued = issue_browser_session(session, principal_id=reader.id, ttl_seconds=3600)
    client.cookies.set(AUTH_SESSION_COOKIE_NAME, issued.value)
    client.cookies.set(AUTH_CSRF_COOKIE_NAME, issued.csrf_token)
    readonly = client.get(f"/projects/work/workspace/record/{task['id']}")
    assert readonly.status_code == 200 and 'name="action"' not in readonly.text
    denied = _action(
        client,
        state,
        task,
        action="comment",
        body="No write permission",
        csrf_token=issued.csrf_token,
    )
    assert denied.status_code == 403, denied.text
    validate_locale_catalogs()


def test_noop_browser_save_preserves_absent_requirement_baseline(project, root_client, root_state):
    client, state = root_client, root_state
    requirement = _record(
        client, state, {"kind": "item", "title": "No baseline yet", "item_type": "requirement"}
    )
    _browser(client, state)
    editor = client.get(f"/projects/work/workspace?edit_id={requirement['id']}")
    saved = client.post(
        "/projects/work/workspace", data=BrowserForm(editor.text).data(), follow_redirects=False
    )
    assert saved.status_code == 303, saved.text
    from test_project_workspace import _auth

    result = client.get(
        "/api/v1/projects/work/workspace/item", headers=_auth(state["owner_token"])
    ).json()["items"][0]
    assert result["requirement_revision"] == requirement["requirement_revision"]
    assert result["data"]["requirement"] is None


def test_document_version_roundtrip_archived_blocker_and_disabled_external_state(
    project, root_client, root_state
):
    client, state = root_client, root_state
    blocker = _record(
        client,
        state,
        {
            "kind": "item",
            "item_type": "blocker",
            "title": "Archived unresolved blocker",
            "archived": True,
        },
    )
    repo = _record(
        client,
        state,
        {"kind": "repository", "title": "Opt out", "owner": "example", "name": "project"},
    )
    task_data = {
        "kind": "item",
        "title": "Documented task",
        "relations": [{"relation": "blocked_by", "target_id": blocker["id"]}],
        "github_references": [{"repository_id": repo["id"], "kind": "issue", "number": 12}],
    }
    task = _record(client, state, task_data)
    page = _record(
        client,
        state,
        {
            "kind": "page",
            "title": "Pinned documentation",
            "relations": [{"relation": "documents", "target_id": task["id"]}],
        },
    )
    _record(client, state, {**task_data, "description": "New content"}, record_id=task["id"])
    _browser(client, state)
    editor = client.get(f"/projects/work/workspace?kind=page&edit_id={page['id']}")
    assert 'name="relation_version" value="1"' in editor.text
    saved = client.post(
        "/projects/work/workspace", data=BrowserForm(editor.text).data(), follow_redirects=False
    )
    assert saved.status_code == 303, saved.text
    detail = client.get(f"/projects/work/workspace/record/{page['id']}")
    assert detail.status_code == 200, detail.text
    assert "Referenced content has changed" in detail.text
    task_detail = client.get(f"/projects/work/workspace/record/{task['id']}")
    assert "Archived, but still blocking" in task_detail.text
    assert "External state unavailable or stale" in task_detail.text
    from test_project_workspace import _auth

    current = next(
        r
        for r in client.get(
            "/api/v1/projects/work/workspace/item", headers=_auth(state["owner_token"])
        ).json()["items"]
        if r["id"] == task["id"]
    )
    observed = _action(client, state, current, action="sync_github")
    assert observed.status_code == 303, observed.text
    observation = client.get(observed.headers["location"])
    assert observation.status_code == 200, observation.text
    assert "Synchronization is not enabled" in observation.text
    assert "Last synchronization attempt" in observation.text
    assert "Last successful observation (retained on failures)" in observation.text
    assert (
        "&#39;observations&#39;:" not in observation.text
    )  # Rendered fields, not Python/JSON dumps.


def test_effective_status_and_local_editor_remain_distinct(
    project, root_client, root_state, monkeypatch
):
    from test_project_workspace import _auth

    from blockwart.services.project_github import ObservationError

    client, state = root_client, root_state
    repo = _record(
        client,
        state,
        {
            "kind": "repository",
            "title": "Observed repository",
            "owner": "example",
            "name": "project",
            "github_id": 123,
            "sync_enabled": True,
        },
    )
    reference = {"repository_id": repo["id"], "kind": "issue", "number": 7}
    task = _record(
        client,
        state,
        {
            "kind": "item",
            "title": "Locally done, externally open",
            "status": "done",
            "due_at": "2020-01-01T00:00:00Z",
            "github_references": [reference],
            "leading_reference": reference,
            "status_authority": "github",
        },
    )
    _browser(client, state)

    def read():
        response = client.get(
            f"/api/v1/projects/work/workspace/record/{task['id']}",
            headers=_auth(state["owner_token"]),
        )
        assert response.status_code == 200, response.text
        return response.json()

    def check_status(effective):
        listing = client.get("/projects/work/workspace")
        assert listing.status_code == 200, listing.text
        assert f"Effective work status: {effective} · Local stored status: Done" in listing.text
        detail = client.get(f"/projects/work/workspace/record/{task['id']}")
        assert detail.status_code == 200, detail.text
        assert f"<dt>Effective work status</dt><dd>{effective}</dd>" in detail.text
        assert "<dt>Local stored status</dt><dd>Done</dd>" in detail.text
        assert '<label>Local stored status<select name="status">' in detail.text
        editor = client.get(f"/projects/work/workspace?edit_id={task['id']}")
        assert BrowserForm(editor.text).data()["status"] == "done"
        assert '<label>Effective work status<select name="status">' in listing.text
        # Filtered records, not hierarchy ancestors, reflect the effective status.
        done = client.get("/projects/work/workspace?status=done")
        assert f'id="record-{task["id"]}"' not in done.text

    check_status("Unknown")
    assert read()["effective_status"] is None

    def observe(path, token, timeout):
        if path == "/repositories/123":
            return {"id": 123, "full_name": "example/project", "private": False}
        return {"number": 7, "state": "open"}

    monkeypatch.setenv("BLOCKWART_PROJECT_GITHUB_SYNC_ENABLED", "true")
    monkeypatch.setattr("blockwart.services.project_github._github_get", observe)
    synced = _action(client, state, read(), action="sync_github")
    assert synced.status_code == 303, synced.text
    check_status("Open")
    overdue = client.get("/projects/work/workspace?status=open&overdue=true")
    assert f'id="record-{task["id"]}"' in overdue.text
    current = read()
    assert current["data"]["status"] == "done" and current["effective_status"] == "open"

    def fail(*args, **kwargs):
        raise ObservationError("rate_limited")

    monkeypatch.setattr("blockwart.services.project_github._github_get", fail)
    failed = _action(client, state, current, action="sync_github")
    assert failed.status_code == 303, failed.text
    check_status("Unknown")
    assert read()["effective_status"] is None
    german = client.get(f"/projects/work/workspace/record/{task['id']}?lang=de")
    assert "<dt>Lokal gespeicherter Status</dt><dd>Erledigt</dd>" in german.text
    assert "<dt>Maßgeblicher Arbeitsstatus</dt><dd>Unbekannt</dd>" in german.text


def test_fulfillment_criteria_and_assessment_are_separate(project, root_client, root_state):
    client, state = root_client, root_state
    requirement = _record(
        client,
        state,
        {
            "kind": "item",
            "title": "Verified, not accepted",
            "item_type": "requirement",
            "criteria": [
                {"id": "C1", "description": "Required check", "required": True},
                {"id": "C2", "description": "Optional check", "required": False},
            ],
        },
    )
    _browser(client, state)
    listing = client.get("/projects/work/workspace")
    assert "No implementation linked" in listing.text
    assert "No verification evidence for this revision" in listing.text
    empty = client.get(f"/projects/work/workspace/record/{requirement['id']}")
    assert "<strong>Unverified</strong>" in empty.text
    assert "Required criteria passed: 0/1" in empty.text
    evidence = _record(
        client,
        state,
        {
            "kind": "item",
            "title": "Current verification",
            "item_type": "evidence",
            "evidence": {
                "requirement_id": requirement["id"],
                "requirement_revision": 1,
                "criteria": ["C1"],
                "outcome": "pass",
                "subject": "revision abc",
                "scope": "Required check",
                "source_url": "https://example.com/check",
                "observed_at": "2026-10-23T10:00:00Z",
            },
        },
    )
    detail = client.get(f"/projects/work/workspace/record/{requirement['id']}")
    assert detail.status_code == 200, detail.text
    assert "<h3>Requirement fulfillment</h3>" in detail.text
    assert "<strong>Verified</strong>" in detail.text
    assert "Required criteria passed: 1/1" in detail.text
    assert '<th scope="row">C1</th><td>Required check</td><td>Yes</td><td>Pass</td>' in detail.text
    assert (
        '<th scope="row">C2</th><td>Optional check</td><td>No</td><td>Unverified</td>'
        in detail.text
    )
    assert f"/workspace/record/{evidence['id']}" in detail.text
    assert "Not assessed for this revision" in detail.text
    overview = client.get("/projects/work/workspace")
    assert "Requirement fulfillment: Verified" in overview.text
    assert "No verification evidence for this revision" not in overview.text
    german = client.get(f"/projects/work/workspace/record/{requirement['id']}?lang=de")
    assert (
        "Anforderungserfüllung" in german.text and "Erfüllte Pflichtkriterien: 1/1" in german.text
    )


def test_informed_by_browser_pin_drift_and_successor_links(project, root_client, root_state):
    client, state = root_client, root_state
    page = _record(client, state, {"kind": "page", "title": "Original design", "body": "v1"})
    _browser(client, state)
    editor = client.get("/projects/work/workspace")
    assert '<option value="informed_by">Informed by</option>' in editor.text
    data = BrowserForm(editor.text).data()
    data.update(
        title="Informed task",
        relation_type=["informed_by"] * 3,
        relation_target=[page["id"], "", ""],
    )
    saved = client.post("/projects/work/workspace", data=data, follow_redirects=False)
    assert saved.status_code == 303, saved.text
    from test_project_workspace import _auth

    task = next(
        r
        for r in client.get(
            "/api/v1/projects/work/workspace/item", headers=_auth(state["owner_token"])
        ).json()["items"]
        if r["data"]["title"] == "Informed task"
    )
    assert task["data"]["relations"][0]["target_version"] == 1
    _record(
        client,
        state,
        {"kind": "page", "title": "Original design", "body": "v2"},
        record_id=page["id"],
    )
    detail = client.get(f"/projects/work/workspace/record/{task['id']}")
    assert "Informed by:" in detail.text
    assert "Linked version 1 / Current version 2" in detail.text
    assert "Referenced content has changed" in detail.text
    editor = client.get(f"/projects/work/workspace?edit_id={task['id']}")
    saved = client.post(
        "/projects/work/workspace", data=BrowserForm(editor.text).data(), follow_redirects=False
    )
    assert saved.status_code == 303, saved.text
    assert (
        "Referenced content has changed"
        in client.get(f"/projects/work/workspace/record/{task['id']}").text
    )
    replacement = _record(
        client,
        state,
        {
            "kind": "page",
            "title": "Replacement design",
            "relations": [{"relation": "supersedes", "target_id": page["id"]}],
        },
    )
    original = client.get(f"/projects/work/workspace/record/{page['id']}")
    assert "<h3>Superseded by</h3>" in original.text
    assert f"/workspace/record/{replacement['id']}" in original.text
    german = client.get(f"/projects/work/workspace/record/{page['id']}?lang=de")
    assert "Abgelöst durch" in german.text
    german_editor = client.get(f"/projects/work/workspace?edit_id={task['id']}&lang=de")
    assert '<option value="informed_by" selected>Basiert auf</option>' in german_editor.text
