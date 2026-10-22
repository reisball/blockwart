"""Issue #273: real workflows, access boundaries and non-destructive upgrades."""

from __future__ import annotations

# ruff: noqa: F811 -- imported pytest fixtures are intentionally injected by name.
import json
import re
from concurrent.futures import ThreadPoolExecutor
from uuid import uuid4

import pytest
from alembic import command
from sqlalchemy import select, text
from test_catalog_root_creation import root_client, root_state  # noqa: F401
from test_postgresql_compat_regressions import migrated_pg_engine, pg_database_name  # noqa: F401
from test_project_workspace import _auth, _create_project

from blockwart.db.migrations import build_alembic_config
from blockwart.db.session import transaction
from blockwart.domain.auth import GrantScope, Role
from blockwart.mcp.server import call_tool
from blockwart.models import CatalogObject, ObjectGrant
from blockwart.services.access import create_object_grant
from blockwart.ui.security import AUTH_CSRF_COOKIE_NAME, AUTH_SESSION_COOKIE_NAME


@pytest.fixture(params=["sqlite", "postgres"])
def alembic_session_factory(request, alembic_database_factory):
    if request.param == "sqlite":
        return alembic_database_factory().sessions
    from sqlalchemy.orm import sessionmaker

    engine = request.getfixturevalue("migrated_pg_engine")
    return sessionmaker(bind=engine, autoflush=False, autocommit=False)


@pytest.fixture
def project(root_client, root_state):  # noqa: F811
    _create_project(root_client, root_state["owner_token"], "work")
    return "work"


def _etag(client, state, project="work", token=None):
    result = client.get(
        f"/api/v1/projects/{project}/workspace/item", headers=_auth(token or state["owner_token"])
    )
    assert result.status_code == 200, result.text
    return result.headers["etag"]


def _save(client, state, data, *, project="work", record_id=None, token=None, etag=None, key=None):
    token = token or state["owner_token"]
    headers = {
        **_auth(token),
        "If-Match": etag or _etag(client, state, project, token),
        "Idempotency-Key": key or f"record-test-{uuid4().hex}",
    }
    path = f"/api/v1/projects/{project}/workspace/{data['kind']}"
    return client.request(
        "PUT" if record_id else "POST",
        path + (f"/{record_id}" if record_id else ""),
        headers=headers,
        json=data,
    )


def _browser(client, state):
    client.cookies.set(AUTH_SESSION_COOKIE_NAME, state["owner_session"].value)
    client.cookies.set(AUTH_CSRF_COOKIE_NAME, state["owner_session"].csrf_token)


def test_item_lifecycle_history_filters_and_old_lists(project, root_client, root_state):
    client, state = root_client, root_state
    with state["session_factory"]() as session:
        before = session.get(CatalogObject, project).data_json
    data = {
        "kind": "item",
        "title": "Check upgrade",
        "item_type": "question",
        "description": "Keep old lists",
        "assignee": "Example team",
        "due_at": "2020-01-01T00:00:00Z",
    }
    made = _save(client, state, data)
    assert made.status_code == 201, made.text
    record = made.json()["record"]
    assert record["overdue"] and record["version"] == 1
    for status in ("in_progress", "blocked", "done", "open"):
        data["status"] = status
        response = _save(client, state, data, record_id=record["id"])
        assert response.status_code == 200, response.text
        item = response.json()["record"]
        assert item["id"] == record["id"]
        assert bool(item["completed_at"]) == (status == "done")
        assert item["overdue"] == (status != "done")
    history = client.get(
        f"/api/v1/projects/work/workspace/history/{record['id']}",
        headers=_auth(state["owner_token"]),
    ).json()
    assert [v["data"]["status"] for v in history["items"]] == [
        "open",
        "done",
        "blocked",
        "in_progress",
        "open",
    ]
    assert all(v["author_label"] and v["origin"] == "api" for v in history["items"])
    assert (
        client.get(
            "/api/v1/projects/work/workspace/item?item_type=question&overdue=true",
            headers=_auth(state["owner_token"]),
        ).json()["total"]
        == 1
    )
    assert (
        client.get(
            "/api/v1/projects/work/workspace/item?status=done", headers=_auth(state["owner_token"])
        ).json()["total"]
        == 0
    )
    with state["session_factory"]() as session:
        assert session.get(CatalogObject, project).data_json == before
        with pytest.raises(Exception, match="append-only|operation blocked by trigger"):
            session.execute(text("DELETE FROM project_record_versions"))


def test_hierarchy_rejects_cycles_cross_project_and_wrong_kinds(project, root_client, root_state):
    client, state = root_client, root_state
    _create_project(client, state["owner_token"], "other")
    parent = _save(client, state, {"kind": "item", "title": "Parent"}).json()["record"]
    child = _save(
        client, state, {"kind": "item", "title": "Child", "parent_id": parent["id"]}
    ).json()["record"]
    assert (
        _save(
            client,
            state,
            {"kind": "item", "title": "Cycle", "parent_id": child["id"]},
            record_id=parent["id"],
        ).status_code
        == 409
    )
    assert (
        _save(
            client,
            state,
            {"kind": "item", "title": "Foreign", "parent_id": parent["id"]},
            project="other",
        ).status_code
        == 404
    )
    page = _save(client, state, {"kind": "page", "title": "Knowledge"}).json()["record"]
    assert (
        _save(
            client, state, {"kind": "item", "title": "Invalid parent", "parent_id": page["id"]}
        ).status_code
        == 422
    )
    assert (
        _save(
            client,
            state,
            {"kind": "page", "title": "Foreign update"},
            project="other",
            record_id=page["id"],
        ).status_code
        == 404
    )


def test_pages_versions_search_and_cursor_binding(project, root_client, root_state):
    client, state = root_client, root_state
    data = {
        "kind": "page",
        "title": "Operations",
        "body": "UniqueCuratedWord",
        "review_after": "2027-01-01T01:00:00+01:00",
    }
    result = _save(client, state, data)
    assert result.status_code == 201, result.text
    record = result.json()["record"]
    assert record["data"]["review_after"] == "2027-01-01T00:00:00.000000Z"
    data["body"] = "UpdatedCuratedWord"
    assert _save(client, state, data, record_id=record["id"]).status_code == 200
    history = client.get(
        f"/api/v1/projects/work/workspace/history/{record['id']}?limit=1",
        headers=_auth(state["owner_token"]),
    ).json()
    assert history["total"] == 2 and history["items"][0]["data"]["body"] == data["body"]
    older = client.get(
        f"/api/v1/projects/work/workspace/history/{record['id']}",
        params={"limit": 1, "cursor": history["next_cursor"]},
        headers=_auth(state["owner_token"]),
    ).json()
    assert older["items"][0]["data"]["body"] == "UniqueCuratedWord"
    for term, count in (("updatedcuratedword", 1), ("uniquecuratedword", 0)):
        response = client.get(
            "/api/v1/projects/work/workspace/search",
            params={"q": term},
            headers=_auth(state["owner_token"]),
        )
        assert response.status_code == 200, response.text
        assert response.json()["total"] == count
    _save(client, state, {"kind": "page", "title": "Second"})
    first = client.get(
        "/api/v1/projects/work/workspace/page?limit=1", headers=_auth(state["owner_token"])
    ).json()
    assert first["next_cursor"]
    assert (
        client.get(
            "/api/v1/projects/work/workspace/item",
            params={"cursor": first["next_cursor"]},
            headers=_auth(state["owner_token"]),
        ).status_code
        == 400
    )


def test_optimistic_concurrency_and_idempotency(project, root_client, root_state):
    client, state = root_client, root_state
    etag = _etag(client, state)
    key = "same-idempotent-create-0001"
    data = {"kind": "item", "title": "Only once"}
    made = _save(client, state, data, etag=etag, key=key)
    replay = _save(client, state, data, etag=etag, key=key)
    assert made.status_code == 201 and replay.status_code == 200
    assert replay.json()["replayed"] and replay.json()["record"] == made.json()["record"]
    assert (
        _save(client, state, {**data, "title": "Different"}, etag=etag, key=key).status_code == 409
    )
    assert _save(client, state, data, etag=etag).status_code == 412
    etag = _etag(client, state)
    with ThreadPoolExecutor(max_workers=2) as pool:
        responses = list(
            pool.map(
                lambda index: _save(
                    client, state, {"kind": "item", "title": f"Concurrent {index}"}, etag=etag
                ),
                range(2),
            )
        )
    assert sorted(response.status_code for response in responses) == [201, 412]


def test_project_editor_can_work_without_global_rights_and_no_credential_escalation(
    project, root_client, root_state
):
    client, state = root_client, root_state
    with state["session_factory"]() as session:
        with transaction(session):
            create_object_grant(
                session,
                principal_id=state["scoped_id"],
                object_id=project,
                role=Role.EDITOR,
                scope=GrantScope.SELF,
            )
    token = state["scoped_token"]
    assert (
        _save(client, state, {"kind": "item", "title": "Delegated"}, token=token).status_code == 201
    )
    assert (
        _save(client, state, {"kind": "page", "title": "Delegated page"}, token=token).status_code
        == 201
    )
    access = {
        "kind": "access",
        "title": "External",
        "url": "https://external.example.test",
        "account": "Read-only account",
        "new_credential_reference": {
            "id": "external-reference",
            "kind": "credential_reference",
            "label": "External",
            "data": {
                "schema_version": 1,
                "provider": "vaultwarden",
                "reference": {"item_hint": "External item"},
            },
        },
    }
    assert _save(client, state, access, token=token).status_code == 403
    with state["session_factory"]() as session:
        assert session.get(CatalogObject, "external-reference") is None
        with transaction(session):
            create_object_grant(
                session,
                principal_id=state["scoped_id"],
                object_id=project,
                role=Role.CREDENTIAL_REFERENCE_CREATOR,
                scope=GrantScope.SELF,
            )
    response = _save(client, state, access, token=token)
    assert response.status_code == 201, response.text
    assert (
        response.json()["record"]["data"]["credential_reference"]
        == "credential_reference:external-reference"
    )
    with state["session_factory"]() as session:
        grants = session.scalars(
            select(ObjectGrant).where(ObjectGrant.object_id == "external-reference")
        ).all()
        assert len(grants) == 1 and grants[0].principal_id == state["scoped_id"]
    _create_project(client, state["owner_token"], "hidden")
    hidden = _save(client, state, {"kind": "page", "title": "HiddenWord"}, project="hidden")
    assert hidden.status_code == 201
    for path in ("page", "search?q=HiddenWord", "history/" + hidden.json()["record"]["id"]):
        assert (
            client.get(
                "/api/v1/projects/hidden/workspace/" + path, headers=_auth(token)
            ).status_code
            == 404
        )
    assert (
        _save(
            client,
            state,
            {
                "kind": "access",
                "title": "Unauthorized link",
                "credential_reference": "credential_reference:hidden",
            },
            token=token,
        ).status_code
        == 404
    )


@pytest.mark.parametrize(
    "data",
    [
        {"kind": "item", "title": "", "description": "Required title"},
        {"kind": "page", "title": "Secret", "body": "-----BEGIN PRIVATE KEY-----"},
        {"kind": "item", "title": "Bad date", "due_at": "2027-01-01"},
        {"kind": "access", "title": "Bad URL", "url": "https://user:pass@example.test"},
        {"kind": "page", "title": "Unknown", "password": "not-accepted"},
    ],
)
def test_rejected_metadata_does_not_mutate(project, root_client, root_state, data):
    etag = _etag(root_client, root_state)
    assert _save(root_client, root_state, data).status_code == 422
    assert _etag(root_client, root_state) == etag


def test_ui_create_edit_history_and_safe_markdown(project, root_client, root_state):
    client, state = root_client, root_state
    _browser(client, state)
    response = client.get("/projects/work/workspace?kind=page")
    assert response.status_code == 200, response.text
    key = re.search('name="idempotency_key" value="([^"]+)"', response.text)[1]
    saved = client.post(
        "/projects/work/workspace",
        data={
            "csrf_token": state["owner_session"].csrf_token,
            "kind": "page",
            "title": "UI knowledge",
            "body": "**Reviewed** <script>alert(1)</script>",
            "review_after": "2027-01-01T00:00:00Z",
            "if_match": response.headers["etag"],
            "idempotency_key": key,
        },
        follow_redirects=False,
    )
    assert saved.status_code == 303, saved.text
    listing = client.get(saved.headers["location"])
    assert (
        "<strong>Reviewed</strong>" in listing.text
        and "<script>alert(1)</script>" not in listing.text
    )
    assert "edit_id=" in listing.text and "history_id=" in listing.text
    assert client.get("/projects/work/workspace?kind=item&status=&item_type=").status_code == 200
    assert client.get("/projects/work?edit=true").text.count('name="project_status"') == 1
    no_csrf = client.post(
        "/projects/work/workspace",
        data={"csrf_token": "invalid", "kind": "item", "title": "Denied"},
    )
    assert no_csrf.status_code == 403


def test_mcp_real_api_flow_and_history(project, root_client, root_state):
    client, state = root_client, root_state

    def request(method, path, payload, headers):
        result = client.request(
            method, path, json=payload, headers={**headers, **_auth(state["owner_mcp_token"])}
        )
        assert result.is_success, result.text
        return result.json()

    def fetch(path, params):
        response = client.get(
            path,
            params={k: v for k, v in params.items() if v is not None},
            headers={**_auth(state["owner_mcp_token"]), "X-Blockwart-Channel": "mcp"},
        )
        assert response.is_success, response.text
        return response.json()

    made = call_tool(
        "blockwart.save_project_record",
        {
            "object_id": "work",
            "record": {"kind": "page", "title": "MCP page", "body": "McpFindWord"},
            "if_match": _etag(client, state),
            "idempotency_key": "mcp-record-test-0001",
        },
        requester=request,
    )
    made = json.loads(made["content"][0]["text"])
    record_id = made["record"]["id"]

    def read_tool(name, args):
        result = call_tool(name, args, fetcher=fetch)
        return json.loads(result["content"][0]["text"])

    assert (
        read_tool("blockwart.list_project_records", {"object_id": "work", "kind": "page"})["total"]
        == 1
    )
    history = read_tool(
        "blockwart.list_project_record_history", {"object_id": "work", "record_id": record_id}
    )
    assert history["items"][0]["origin"] == "mcp"
    assert (
        read_tool("blockwart.search_project_workspace", {"object_id": "work", "q": "McpFindWord"})[
            "total"
        ]
        == 1
    )


def test_additive_migration_preserves_every_existing_row(alembic_database_factory):
    db = alembic_database_factory("upgrade.sqlite")
    config = build_alembic_config(db.database_url)
    command.downgrade(config, "20260926_0026")
    with db.engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO catalog_objects (id, instance_id, kind, label, status, "
                "data_json, revision) VALUES ('old-project', 'legacy-instance', "
                "'project', 'Legacy', 'active', :data, 7)"
            ),
            {"data": json.dumps({"legacy": ["untouched"], "open_questions": ["Old question"]})},
        )
        tables = [
            row[0]
            for row in conn.execute(
                text(
                    "SELECT name FROM sqlite_master WHERE type='table' "
                    "AND name NOT LIKE 'sqlite_%' "
                    "AND name != 'alembic_version' ORDER BY name"
                )
            )
        ]
        snapshot = {
            table: conn.execute(text(f'SELECT * FROM "{table}"')).fetchall() for table in tables
        }
    command.upgrade(config, "head")
    command.check(config)
    with db.engine.connect() as conn:
        assert snapshot == {
            table: conn.execute(text(f'SELECT * FROM "{table}"')).fetchall() for table in tables
        }


def test_chronology_over_100_entries_remains_reachable_and_searchable(
    project, root_client, root_state
):
    from datetime import datetime, timedelta
    from urllib.parse import parse_qs, urlsplit

    from blockwart.models import ObjectComment

    client, state = root_client, root_state
    with state["session_factory"]() as session, transaction(session):
        row = session.get(CatalogObject, project)
        for index in range(105):
            session.add(
                ObjectComment(
                    id=str(uuid4()),
                    object_id=project,
                    object_instance_id=row.instance_id,
                    object_created_at=row.created_at,
                    author_principal_id=state["owner_id"],
                    author_login="catalog.owner",
                    author_display_name="Catalog Owner",
                    author_principal_type="service_account",
                    origin="api",
                    format="markdown",
                    body=f"ChronologyMarker{index:03d}",
                    created_at=datetime(2026, 1, 1) + timedelta(seconds=index),
                )
            )
    _browser(client, state)
    first = client.get("/projects/work")
    assert first.status_code == 200
    assert "ChronologyMarker104" in first.text and "ChronologyMarker000" not in first.text
    next_url = re.search(r'href="([^\"]*chronology_cursor=[^\"]*)"', first.text)[1]
    next_url = next_url.replace("&amp;", "&")
    second = client.get("/projects/work" + next_url)
    assert second.status_code == 200, second.text
    assert "ChronologyMarker000" in second.text and "ChronologyMarker005" not in second.text
    first_ids = set(re.findall(r'id="chronology-([^\"]+)"', first.text))
    second_ids = set(re.findall(r'id="chronology-([^\"]+)"', second.text))
    assert len(first_ids) == 100 and len(second_ids) == 5 and not first_ids & second_ids
    cursor = parse_qs(urlsplit(next_url).query)["chronology_cursor"][0]
    assert cursor
    assert client.get("/projects/work?chronology_cursor=broken").status_code == 400
    found = client.get(
        "/api/v1/projects/work/workspace/search?q=ChronologyMarker000",
        headers=_auth(state["owner_token"]),
    )
    assert found.json()["total"] == 1


def test_deleted_project_id_does_not_resurrect_records(project, root_client, root_state):
    client, state = root_client, root_state
    record = _save(client, state, {"kind": "page", "title": "FormerInstance"}).json()["record"]
    deleted = client.delete(
        "/api/v1/objects/work",
        headers={**_auth(state["owner_token"]), "If-Match": _etag(client, state)},
    )
    assert deleted.status_code == 200, deleted.text
    recreated = client.post(
        "/api/v1/roots",
        headers=_auth(state["owner_token"], key=f"recreate-work-{uuid4().hex}"),
        json={
            "id": "work",
            "kind": "project",
            "label": "New Work",
            "data": {
                "schema_version": 1,
                "category": "implementation",
                "project_status": "planned",
            },
        },
    )
    assert recreated.status_code == 201, recreated.text
    assert (
        client.get(
            "/api/v1/projects/work/workspace/page", headers=_auth(state["owner_token"])
        ).json()["total"]
        == 0
    )
    assert (
        client.get(
            f"/api/v1/projects/work/workspace/history/{record['id']}",
            headers=_auth(state["owner_token"]),
        ).status_code
        == 404
    )


def test_existing_reference_visibility_history_and_deletion_guard(project, root_client, root_state):
    client, state = root_client, root_state
    from blockwart.schemas.catalog import CatalogObjectIn
    from blockwart.services.catalog import upsert_object

    with state["session_factory"]() as session, transaction(session):
        upsert_object(
            session,
            CatalogObjectIn(
                id="private-ref",
                kind="credential_reference",
                label="PRIVATE-LOCATION",
                data={
                    "schema_version": 1,
                    "provider": "vaultwarden",
                    "reference": {"item_hint": "PRIVATE-LOCATION"},
                },
            ),
        )
        create_object_grant(
            session,
            principal_id=state["owner_id"],
            object_id="private-ref",
            role=Role.OWNER,
            scope=GrantScope.SELF,
        )
        create_object_grant(
            session,
            principal_id=state["scoped_id"],
            object_id="work",
            role=Role.EDITOR,
            scope=GrantScope.SELF,
        )
    made = _save(
        client,
        state,
        {
            "kind": "access",
            "title": "External",
            "credential_reference": "credential_reference:private-ref",
        },
    )
    assert made.status_code == 201, made.text
    record = made.json()["record"]
    ref = client.get("/api/v1/objects/private-ref", headers=_auth(state["owner_token"]))
    denied = client.delete(
        "/api/v1/objects/private-ref",
        headers={**_auth(state["owner_token"]), "If-Match": ref.headers["etag"]},
    )
    assert denied.status_code == 409
    token = state["scoped_token"]
    listed = client.get("/api/v1/projects/work/workspace/access", headers=_auth(token))
    assert "private-ref" not in listed.text and "PRIVATE-LOCATION" not in listed.text
    history = client.get(
        f"/api/v1/projects/work/workspace/history/{record['id']}", headers=_auth(token)
    )
    assert "private-ref" not in history.text
    changed = _save(
        client,
        state,
        {"kind": "access", "title": "Updated external"},
        record_id=record["id"],
        token=token,
    )
    assert changed.status_code == 200, changed.text
    # A projected edit preserves the concealed credential link without granting access.
    owner_read = client.get(
        "/api/v1/projects/work/workspace/access", headers=_auth(state["owner_token"])
    )
    assert (
        owner_read.json()["items"][0]["data"]["credential_reference"]
        == "credential_reference:private-ref"
    )
    found = client.get(
        "/api/v1/projects/work/workspace/search?q=PRIVATE-LOCATION", headers=_auth(token)
    )
    assert found.json()["total"] == 0


def test_workspace_status_responsibility_dates_preserve_extensions(
    project, root_client, root_state
):
    client, state = root_client, root_state
    _browser(client, state)
    with state["session_factory"]() as session, transaction(session):
        row = session.get(CatalogObject, project)
        old = json.loads(row.data_json)
        old["extension"] = {"preserved": True}
        row.data_json = json.dumps(old)
    form = {
        "csrf_token": state["owner_session"].csrf_token,
        "if_match": _etag(client, state),
        "project_status": "active",
        "started_at": "2026-10-22T09:00:00Z",
        "managed_by_kind": "team",
        "managed_by_label": "Example team",
    }
    result = client.post("/projects/work/work", data=form, follow_redirects=False)
    assert result.status_code == 303, result.text
    with state["session_factory"]() as session:
        stored = json.loads(session.get(CatalogObject, project).data_json)
        assert stored["extension"] == {"preserved": True}
        assert stored["managed_by"] == {"kind": "team", "label": "Example team"}
        assert stored["project_status"] == "active"


def test_reference_creation_rolls_back_if_history_write_fails(project, root_client, root_state):
    from sqlalchemy import event, func

    from blockwart.models import AuditEvent, IdempotencyRecord, ProjectRecord, ProjectRecordVersion

    client, state = root_client, root_state

    def snapshot():
        with state["session_factory"]() as session:
            return {
                model.__name__: session.scalar(select(func.count()).select_from(model))
                for model in (
                    CatalogObject,
                    ObjectGrant,
                    ProjectRecord,
                    ProjectRecordVersion,
                    AuditEvent,
                    IdempotencyRecord,
                )
            }

    before = snapshot()
    etag = _etag(client, state)

    def fail_insert(*args):
        raise RuntimeError("injected history write failure")

    event.listen(ProjectRecordVersion, "before_insert", fail_insert)
    try:
        with pytest.raises(RuntimeError, match="injected history"):
            _save(
                client,
                state,
                {
                    "kind": "access",
                    "title": "Atomic external",
                    "new_credential_reference": {
                        "id": "atomic-ref",
                        "kind": "credential_reference",
                        "label": "Atomic",
                        "data": {
                            "schema_version": 1,
                            "provider": "vaultwarden",
                            "reference": {"item_hint": "Fictional item"},
                        },
                    },
                },
            )
    finally:
        event.remove(ProjectRecordVersion, "before_insert", fail_insert)
    assert snapshot() == before
    assert _etag(client, state) == etag
