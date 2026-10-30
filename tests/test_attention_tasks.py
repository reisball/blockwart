"""Overdue project tasks through the shared, authorization-first attention pipeline (#312)."""

from __future__ import annotations

import json
from dataclasses import asdict, replace
from datetime import timedelta
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import event
from test_attention_view import NOW, _access, _knowledge
from test_catalog_root_creation import root_client, root_state  # noqa: F401
from test_project_records import _auth, _save
from test_project_workspace import _create_project

from blockwart.api.deps import get_session
from blockwart.db.session import transaction
from blockwart.domain.attention import (
    AttentionObjectInput,
    AttentionTaskInput,
    build_attention_derivation,
)
from blockwart.main import create_app
from blockwart.mcp.server import call_tool
from blockwart.models import CatalogObject, ProjectRecord, ProjectRecordEvent
from blockwart.schemas.project_workspace import ProjectItemIn, ProjectRepositoryIn
from blockwart.services.attention import query_attention_page
from blockwart.services.catalog import upsert_object
from blockwart.services.pagination import InvalidCursor


def _project(session, identity="work", *, status="planned"):
    data = {"category": "implementation", "project_status": status}
    if status in {"active", "paused", "completed"}:
        data["started_at"] = "2026-08-01T00:00:00Z"
    if status == "completed":
        data["completed_at"] = "2026-08-02T00:00:00Z"
    upsert_object(session, _knowledge(identity, "project", data=data))
    return session.get(CatalogObject, identity)


def _record(session, project, *, payload=None, **data):
    payload = payload or ProjectItemIn(
        kind="item", title="Synthetic task", due_at="2020-01-01T00:00:00Z", **data
    )
    row = ProjectRecord(
        id=str(uuid4()),
        project_instance_id=project.instance_id,
        kind=payload.kind,
        data_json=payload.model_dump_json(),
        version=1,
        requirement_revision=1,
        created_at=NOW.replace(tzinfo=None),
        updated_at=NOW.replace(tzinfo=None),
    )
    session.add(row)
    session.flush()
    return row


def _page(session, access=None, **filters):
    return query_attention_page(
        session,
        access or _access(readable={"work"}),
        channel="ui",
        now=NOW,
        include_total=True,
        category="task_deadline",
        **filters,
    )


@pytest.mark.parametrize(
    ("due_at", "status", "archived", "item_type", "expected"),
    [
        ("2026-08-20T11:59:59.999999Z", "open", False, "task", 1),
        ("2026-08-20T12:00:00Z", "open", False, "task", 0),
        ("2026-08-20T14:00:00+02:00", "open", False, "task", 0),
        ("2026-08-20T12:00:00.000001Z", "open", False, "task", 0),
        (None, "open", False, "task", 0),
        ("2020-01-01T00:00:00Z", "done", False, "task", 0),
        ("2020-01-01T00:00:00Z", "open", True, "task", 0),
        ("2020-01-01T00:00:00Z", "blocked", False, "task", 1),
        ("2020-01-01T00:00:00Z", "deferred", False, "task", 1),
        ("2020-01-01T00:00:00Z", "open", False, "question", 0),
    ],
)
def test_deadline_boundary_and_task_lifecycle(
    alembic_session_factory, due_at, status, archived, item_type, expected
):
    with alembic_session_factory() as session, transaction(session):
        project = _project(session)
        _record(
            session,
            project,
            payload=ProjectItemIn(
                kind="item",
                title="Boundary task",
                due_at=due_at,
                status=status,
                archived=archived,
                item_type=item_type,
            ),
        )
    with alembic_session_factory() as session:
        page = _page(session)
        assert page.total == page.summary.total == len(page.items) == expected
        if expected:
            assert page.items[0].reason_code == "task_deadline_overdue"
            assert page.items[0].severity == "warning"
            assert page.items[0].signal_state == "current"


def test_multiple_tasks_deduplicate_by_record_not_project():
    project = AttentionObjectInput(
        object_id="work",
        kind="project",
        label="Synthetic project",
        lifecycle=None,
        health=None,
        record_state="valid",
        placement_state=None,
        provenance_source_type="manual",
        provenance_observed_at=None,
        provenance_verified_at=None,
        provenance_stale_after=None,
        data={"project_status": "active"},
    )
    task = AttentionTaskInput("work", "first", "First", "2020-01-01T00:00:00Z", "open")
    tasks = [task, task, replace(task, record_id="second", label="Second")]

    def derive(values):
        return build_attention_derivation(
            objects=[project],
            tasks=values,
            coverage=[],
            coverage_collected=False,
            now=NOW,
        )

    forward, reverse = derive(tasks), derive(list(reversed(tasks)))
    assert forward.items == reverse.items
    deadlines = [i for i in forward.items if i.category == "task_deadline"]
    assert [i.target.ref for i in deadlines] == ["project_record:first", "project_record:second"]
    assert all(i.target.object_id == "work" for i in deadlines)
    assert all(i.target.project_label == "Synthetic project" for i in deadlines)
    assert any(i.reason_code == "knowledge_review_unscheduled" for i in forward.items)


@pytest.mark.parametrize("status", ["completed", "cancelled", "archived"])
def test_finished_projects_suppress_deadlines(alembic_session_factory, status):
    with alembic_session_factory() as session, transaction(session):
        _record(session, _project(session, status=status))
    with alembic_session_factory() as session:
        assert _page(session).total == 0


def test_authorization_instances_summary_filters_and_pagination(alembic_session_factory):
    with alembic_session_factory() as session, transaction(session):
        visible = _project(session)
        tasks = [_record(session, visible) for _ in range(3)]
        hidden = _project(session, "hidden")
        _record(session, hidden)
        discovered = _project(session, "discovered")
        _record(session, discovered)
        # A deleted/recreated object's old instance must never regain visibility.
        old = _record(session, visible)
        old.project_instance_id = uuid4().hex
        ids = sorted(row.id for row in tasks)
    access = _access(readable={"work"}, discoverable={"discovered"})
    with alembic_session_factory() as session:
        first = _page(
            session,
            access,
            limit=1,
            kind="project",
            severity="warning",
            signal_state="current",
            reason_code="task_deadline_overdue",
        )
        assert first.total == first.summary.total == 3
        assert first.summary.by_category["task_deadline"] == 3
        assert first.summary.by_reason["task_deadline_overdue"] == 3
        assert first.summary.signals["task_deadline"].evaluated == 3
        assert first.items[0].target.record_id == ids[0]
        assert first.next_cursor
        cursor = first.next_cursor
        found = [first.items[0].target.record_id]
        while cursor:
            page = _page(
                session,
                access,
                limit=1,
                kind="project",
                severity="warning",
                signal_state="current",
                reason_code="task_deadline_overdue",
                cursor=cursor,
            )
            assert page.summary == first.summary
            found.extend(i.target.record_id for i in page.items)
            cursor = page.next_cursor
        assert found == ids
        assert _page(session, access, kind="host").total == 0
        assert _page(session, access, severity="critical").total == 0
        assert _page(session, access, signal_state="stale").total == 0
        assert _page(session, _access(discoverable={"work"})).total == 0
        assert _page(session, _access()).summary.signals["task_deadline"].evaluated == 0
    # Concealed changes cannot alter visible counts, items, cursor or signal states.
    with alembic_session_factory() as session, transaction(session):
        _record(session, session.get(CatalogObject, "hidden"), status="blocked")
    with alembic_session_factory() as session:
        unchanged = _page(
            session,
            access,
            limit=1,
            kind="project",
            severity="warning",
            signal_state="current",
            reason_code="task_deadline_overdue",
        )
        assert asdict(first) == asdict(unchanged)
        reverse = _page(session, access, direction="desc")
        assert [i.target.record_id for i in reverse.items] == ids[::-1]


def test_task_change_invalidates_cursor_for_previous_derived_view(alembic_session_factory):
    with alembic_session_factory() as session, transaction(session):
        project = _project(session)
        identities = [_record(session, project).id for _ in range(2)]
    with alembic_session_factory() as session:
        previous = _page(session, limit=1)
        assert previous.next_cursor
    with alembic_session_factory() as session, transaction(session):
        row = session.get(ProjectRecord, identities[1])
        data = json.loads(row.data_json)
        data["due_at"] = "2099-01-01T00:00:00Z"
        row.data_json = json.dumps(data)
    with alembic_session_factory() as session:
        assert _page(session).summary.total == 1
        with pytest.raises(InvalidCursor):
            _page(session, limit=1, cursor=previous.next_cursor)


@pytest.mark.parametrize(
    ("authority", "local", "observed", "age", "repo_version", "ok", "expected"),
    [
        ("local", "done", "open", 0, 1, True, 0),
        ("local", "open", "closed", 0, 1, True, 1),
        ("github", "done", "open", 0, 1, True, 1),
        ("github", "open", "closed", 0, 1, True, 0),
        ("github", "open", "closed", 900, 1, True, 0),
        ("github", "done", "closed", 901, 1, True, 1),
        ("github", "done", "closed", 0, 2, True, 1),
        ("github", "done", "closed", 0, 1, False, 1),
    ],
)
def test_canonical_effective_status_not_local_status_or_completed_at(
    alembic_session_factory, authority, local, observed, age, repo_version, ok, expected
):
    with alembic_session_factory() as session, transaction(session):
        project = _project(session)
        repo = _record(
            session,
            project,
            payload=ProjectRepositoryIn(
                kind="repository",
                title="Example repository",
                owner="example",
                name="example",
            ),
        )
        ref = {"repository_id": repo.id, "kind": "issue", "number": 42}
        payload = ProjectItemIn(
            kind="item",
            title="External task",
            due_at="2020-01-01T00:00:00Z",
            status=local,
            status_authority=authority,
            github_references=[ref],
            leading_reference=ref,
        )
        task = _record(session, project, payload=payload)
        task.completed_at = NOW.replace(tzinfo=None) if local == "done" else None
        repo.version = repo_version
        session.add(
            ProjectRecordEvent(
                id=str(uuid4()),
                project_instance_id=project.instance_id,
                record_id=task.id,
                kind="sync_github",
                data_json=json.dumps(
                    {
                        "observed_at": (NOW - timedelta(seconds=age)).isoformat(),
                        "observations": [
                            {
                                "reference": payload.leading_reference.model_dump(),
                                "ok": ok,
                                "state": observed,
                                "repository_record_version": 1,
                            }
                        ],
                    }
                ),
                author_id="synthetic",
                author_label="Synthetic",
                origin="api",
                created_at=NOW.replace(tzinfo=None),
            )
        )
    with alembic_session_factory() as session:
        assert _page(session).total == expected


def test_lifecycle_writes_reflect_on_next_query(root_client, root_state):  # noqa: F811
    _create_project(root_client, root_state["owner_token"], "work")
    data = {"kind": "item", "title": "Update deadline", "due_at": "2020-01-01T00:00:00Z"}
    made = _save(root_client, root_state, data)
    assert made.status_code == 201, made.text
    identity = made.json()["record"]["id"]

    def attention():
        response = root_client.get(
            "/api/v1/attention?category=task_deadline&include_total=true",
            headers=_auth(root_state["owner_token"]),
        )
        assert response.status_code == 200, response.text
        return response.json()

    assert attention()["total"] == 1
    for changes, expected in [
        ({"status": "done"}, 0),
        ({"status": "open"}, 1),
        ({"archived": True}, 0),
        ({"archived": False}, 1),
        ({"due_at": "2099-01-01T00:00:00Z"}, 0),
        ({"due_at": "2020-01-01T00:00:00Z"}, 1),
        ({"due_at": None}, 0),
    ]:
        data.update(changes)
        response = _save(root_client, root_state, data, record_id=identity)
        assert response.status_code == 200, response.text
        assert attention()["total"] == expected


def test_task_targets_on_rest_mcp_and_both_browser_locales(
    alembic_session_factory,
    install_unrestricted_read_access,
):
    with alembic_session_factory() as session, transaction(session):
        task = _record(session, _project(session, status="active"))
        identity = task.id
    app = create_app()
    install_unrestricted_read_access(app)

    def sessions():
        with alembic_session_factory() as session:
            yield session

    app.dependency_overrides[get_session] = sessions
    with TestClient(app) as client:
        params = {"category": "task_deadline", "include_total": True, "kind": "project"}
        response = client.get("/api/v1/attention", params=params)
        assert response.status_code == 200, response.text
        rest = response.json()

        def fetch(path, params):
            result = client.get(path, params={k: v for k, v in params.items() if v is not None})
            result.raise_for_status()
            return result.json()

        mcp = json.loads(
            call_tool("blockwart.get_attention", params, fetcher=fetch)["content"][0]["text"]
        )
        assert {k: v for k, v in rest.items() if k != "generated_at"} == {
            k: v for k, v in mcp.items() if k != "generated_at"
        }
        target = rest["items"][0]["target"]
        assert target == {
            "scope": "project_record",
            "ref": f"project_record:{identity}",
            "object_id": "work",
            "kind": "project",
            "label": "Synthetic task",
            "detail_path": f"/projects/work/workspace/record/{identity}",
            "record_id": identity,
            "project_label": "Work",
        }
        for locale, reason in [("en", "Project task overdue"), ("de", "Projektaufgabe überfällig")]:
            html = client.get(f"/attention?category=task_deadline&lang={locale}")
            assert html.status_code == 200
            assert reason in html.text
            assert f'href="{target["detail_path"]}"' in html.text
            assert '<a href="/objects/work">Work</a>' in html.text
            assert "Synthetic task" in html.text
        detail = client.get(target["detail_path"])
        assert detail.status_code == 200, detail.text
        assert "Synthetic task" in detail.text


def test_task_reads_are_batched_and_read_only(alembic_session_factory):
    with alembic_session_factory() as session, transaction(session):
        _record(session, _project(session))

    def count():
        statements = []

        def listener(_conn, _cursor, sql, _parameters, _context, _many):
            statements.append(sql)

        with alembic_session_factory() as session:
            event.listen(session.bind, "before_cursor_execute", listener)
            try:
                page = _page(session)
                assert not session.new and not session.dirty and not session.deleted
            finally:
                event.remove(session.bind, "before_cursor_execute", listener)
        assert all(sql.lstrip().upper().startswith(("SELECT", "WITH")) for sql in statements)
        return page, len(statements)

    first, before = count()
    assert first.total == 1
    with alembic_session_factory() as session, transaction(session):
        for _ in range(30):
            _record(session, session.get(CatalogObject, "work"))
    after, selects = count()
    assert after.total == 31
    assert selects == before
