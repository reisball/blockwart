"""Dependency filters share REST, MCP and browser semantics (F13/#287)."""

# ruff: noqa: F811 -- shared migrated SQLite/PostgreSQL fixture injection.
import json
import re
from html import unescape
from urllib.parse import parse_qs, urlsplit
from uuid import uuid4

import pytest
from test_project_management import (  # noqa: F401
    act,
    alembic_session_factory,
    make,
    migrated_pg_engine,
    pg_database_name,
    project,
    root_client,
    root_state,
)
from test_project_records import _auth, _browser, _create_project, _save

from blockwart.mcp.server import ToolInputError, UpstreamError, call_tool

API = "/api/v1/projects/work/workspace/item"
UI = "/projects/work/workspace"


def _mcp(client, state, **filters):
    def fetch(path, params):
        response = client.get(path, params=params, headers=_auth(state["owner_mcp_token"]))
        if response.status_code != 200:
            error = response.json()["error"]
            raise UpstreamError(error["code"], error["message"])
        return response.json()

    result = call_tool(
        "blockwart.list_project_records",
        {"object_id": "work", "kind": "item", **filters},
        fetcher=fetch,
    )
    return json.loads(result["content"][0]["text"])


def _parity(client, state, expected, **filters):
    response = client.get(API, params=filters, headers=_auth(state["owner_token"]))
    assert response.status_code == 200, response.text
    api = response.json()
    assert {r["id"] for r in api["items"]} == expected
    mcp = _mcp(client, state, **filters)
    assert mcp == api
    _browser(client, state)
    ui_filters = {
        key: str(value).lower() if isinstance(value, bool) else value
        for key, value in filters.items()
    }
    if "archived" in filters:
        ui_filters["archived"] = "archived" if filters["archived"] else "active"
    response = client.get(UI, params=ui_filters)
    assert response.status_code == 200, response.text
    assert {r.id for r in response.context["page"].items} == expected
    assert response.context["page"].total == api["total"]
    return response


def test_direct_dependency_and_effective_blocker_filters_match_all_surfaces(
    project, root_client, root_state
):
    c, s = root_client, root_state
    target = make(c, s, "Open prerequisite")
    first = make(
        c, s, "Direct dependant", relations=[{"relation": "depends_on", "target_id": target["id"]}]
    )
    transitive = make(
        c, s, "Indirect dependant", relations=[{"relation": "depends_on", "target_id": first["id"]}]
    )
    ordering = make(
        c, s, "Ordering only", relations=[{"relation": "precedes", "target_id": target["id"]}]
    )
    blocker = make(c, s, "Explicit blocker", item_type="blocker")
    blocked_by = make(
        c,
        s,
        "Blocked by relation",
        relations=[{"relation": "blocked_by", "target_id": blocker["id"]}],
    )
    local = make(c, s, "Blocked status", status="blocked")
    reason = make(c, s, "Blocked reason", blocked_reason="Waiting for another team")
    done = make(c, s, "Resolved prerequisite", status="done")
    resolved = make(
        c, s, "Resolved dependency", relations=[{"relation": "depends_on", "target_id": done["id"]}]
    )
    _parity(c, s, {first["id"]}, depends_on=target["short_code"])
    _parity(c, s, {first["id"]}, depends_on=target["id"], blocked=True)
    blocked_ids = {r["id"] for r in [first, transitive, blocked_by, local, reason]}
    _parity(c, s, blocked_ids, blocked=True)
    ui = _parity(
        c, s, {r["id"] for r in [target, ordering, blocker, done, resolved]}, blocked=False
    )
    selector = re.search(r'<select name="depends_on">(.*?)</select>', ui.text)
    assert selector and f"{target['short_code']} · {target['data']['title']}" in selector[1]
    assert '<select name="blocked"><option value="">' in ui.text  # explicit clear/all
    assert '<option value="false" selected>' in ui.text
    assert act(c, s, target, changes={"status": "done"}).status_code == 200
    _parity(c, s, set(), depends_on=target["id"], blocked=True)
    _parity(c, s, {first["id"]}, depends_on=target["short_code"], blocked=False)


def test_dependency_pagination_is_canonical_and_query_bound_across_surfaces(
    project, root_client, root_state, monkeypatch
):
    c, s = root_client, root_state
    target = make(c, s, "Target")
    other = make(c, s, "Other target")
    dependants = [
        make(
            c,
            s,
            f"Dependant {i}",
            relations=[{"relation": "depends_on", "target_id": target["id"]}],
        )
        for i in range(3)
    ]
    filters = {"depends_on": target["short_code"], "blocked": True, "archived": False}
    first = _mcp(c, s, **filters, limit=1)
    assert first["total"] == 3 and first["next_cursor"]
    cursor = first["next_cursor"]
    # Canonical target identity permits equivalent UUID/short-code continuation.
    remaining = {r["id"] for r in dependants} - {first["items"][0]["id"]}
    continuation = {**filters, "depends_on": target["id"], "cursor": cursor}
    api = c.get(API, params=continuation, headers=_auth(s["owner_token"]))
    assert api.status_code == 200, api.text
    assert {r["id"] for r in api.json()["items"]} == remaining
    assert _mcp(c, s, **continuation) == api.json()
    _browser(c, s)
    # Browser and service fixtures are different principals, even though both
    # own the catalog. Their query-bound cursors must not be interchangeable.
    assert s["owner_id"] != s["human_owner_id"]
    assert c.get(UI, params={**continuation, "archived": "active"}).status_code == 400
    for changed in ({"depends_on": other["id"]}, {"blocked": False}, {"blocked": None}):
        query = {**filters, "cursor": cursor, **changed}
        query = {key: value for key, value in query.items() if value is not None}
        response = c.get(API, params=query, headers=_auth(s["owner_token"]))
        assert response.status_code == 400
        with pytest.raises(UpstreamError, match="Invalid cursor"):
            _mcp(c, s, **query)

    # Exercise actual browser next-page URL construction with a smaller page
    # window, leaving the real service filtering and cursor binding untouched.
    from blockwart.ui import project_workspace as ui_module

    real_list = ui_module.list_records

    def small_page(*args, **kwargs):
        return real_list(*args, **kwargs, limit=1)

    monkeypatch.setattr(ui_module, "list_records", small_page)
    browser_filters = {"depends_on": target["short_code"], "blocked": "true", "archived": "active"}
    browser = c.get(UI, params=browser_filters)
    assert browser.status_code == 200, browser.text
    more = next(
        unescape(href)
        for href in re.findall(r'href="([^"]+)"', browser.text)
        if "&amp;cursor=" in href
    )
    query = parse_qs(urlsplit(more).query)
    assert query["depends_on"] == [target["short_code"]] and query["blocked"] == ["true"]
    assert query["archived"] == ["active"]
    next_page = c.get(UI + more)
    assert next_page.status_code == 200, next_page.text
    assert len(next_page.context["page"].items) == 1
    assert next_page.context["page"].items[0].id != browser.context["page"].items[0].id
    browser_continuation = {key: values[0] for key, values in query.items()}
    canonical_page = c.get(UI, params={**browser_continuation, "depends_on": target["id"]})
    assert canonical_page.status_code == 200, canonical_page.text
    assert canonical_page.context["page"] == next_page.context["page"]
    # Use this browser principal's own valid cursor so each rejection proves a
    # changed filter was detected, rather than merely a principal mismatch.
    for changed in (
        {"depends_on": other["id"]},
        {"blocked": "false"},
        {"blocked": ""},
        {"archived": "all"},
    ):
        rejected = c.get(UI, params={**browser_continuation, **changed})
        assert rejected.status_code == 400, rejected.text


def test_unknown_and_foreign_dependency_targets_are_concealed(project, root_client, root_state):
    c, s = root_client, root_state
    _create_project(c, s["owner_token"], "foreign")
    foreign = _save(
        c, s, {"kind": "item", "title": "Concealed target metadata"}, project="foreign"
    ).json()["record"]
    _browser(c, s)
    bodies = []
    for identity in (uuid4().hex, foreign["id"], foreign["short_code"]):
        response = c.get(API, params={"depends_on": identity}, headers=_auth(s["owner_token"]))
        assert response.status_code == 404, response.text
        error = response.json()["error"]
        assert error["correlation_id"]
        bodies.append({key: value for key, value in error.items() if key != "correlation_id"})
        with pytest.raises(UpstreamError, match="Resource not found"):
            _mcp(c, s, depends_on=identity)
        ui = c.get(UI, params={"depends_on": identity})
        assert ui.status_code == 404 and foreign["data"]["title"] not in ui.text
    assert bodies == [{"code": "not_found", "message": "Resource not found"}] * 3
    ui = c.get(UI)
    assert foreign["id"] not in ui.text and foreign["data"]["title"] not in ui.text


def test_invalid_dependency_filters_have_controlled_errors(project, root_client, root_state):
    c, s = root_client, root_state
    _browser(c, s)
    for params in ({"blocked": "maybe"}, {"depends_on": "x" * 37}):
        response = c.get(API, params=params, headers=_auth(s["owner_token"]))
        assert response.status_code == 422
        with pytest.raises(ToolInputError):
            _mcp(c, s, **params)
    assert c.get(UI, params={"blocked": "maybe"}).status_code == 422
    assert c.get(UI, params={"depends_on": "x" * 37}).status_code == 422
    # Empty browser controls clear both filters, rather than becoming invalid IDs.
    assert c.get(UI, params={"depends_on": "", "blocked": ""}).status_code == 200
