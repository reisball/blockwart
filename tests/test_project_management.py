"""Synthetic POC acceptance and lossless targeted actions for #287–#296."""

# ruff: noqa: F811
import json
from uuid import uuid4

import pytest
from sqlalchemy import text
from test_catalog_root_creation import root_client, root_state  # noqa: F401
from test_project_records import (  # noqa: F401  # noqa: F401
    _auth,
    _create_project,
    _etag,
    _save,
    alembic_session_factory,
    migrated_pg_engine,
    pg_database_name,
    project,
)

from blockwart.mcp.server import call_tool
from blockwart.models import CatalogObject


def make(client, state, title, **kw):
    response = _save(client, state, {"kind": "item", "title": title, **kw})
    assert response.status_code == 201, response.text
    return response.json()["record"]


def act(client, state, record, action="patch", *, changes=None, etag=None, key=None, **kw):
    return client.post(
        f"/api/v1/projects/work/workspace/actions/{record['id']}",
        headers={
            **_auth(state["owner_token"]),
            "If-Match": etag or record["record_etag"],
            "Idempotency-Key": key or f"pm-test-{uuid4().hex}",
        },
        json={"action": action, **({"changes": changes} if changes is not None else {}), **kw},
    )


def read(client, state, record):
    r = client.get(
        f"/api/v1/projects/work/workspace/record/{record['id']}",
        headers=_auth(state["owner_token"]),
    )
    assert r.status_code == 200, r.text
    return r.json()


def overview(client, state):
    r = client.get("/api/v1/projects/work/workspace/overview", headers=_auth(state["owner_token"]))
    assert r.status_code == 200, r.text
    return r.json()


def requirement(client, state, title="Requirement", **kw):
    return make(
        client,
        state,
        title,
        item_type="requirement",
        requirement={"original": "Customer baseline"},
        criteria=[
            {"id": "component", "description": "Component verified"},
            {"id": "e2e", "description": "Whole path verified"},
        ],
        **kw,
    )


def evidence(client, state, req, criteria=None, **kw):
    return make(
        client,
        state,
        "Scoped proof",
        item_type="evidence",
        evidence={
            "requirement_id": req["id"],
            "requirement_revision": req["requirement_revision"],
            "criteria": criteria or ["component"],
            "outcome": "pass",
            "subject": "Build 42 / run 7",
            "scope": "Component only",
            "source_url": "https://example.org/runs/7",
            "observed_at": "2026-10-23T10:00:00Z",
            **kw,
        },
    )


def test_typed_shared_requirements_stable_codes_and_invalid_graphs(
    project, root_client, root_state
):
    c, s = root_client, root_state
    a = make(c, s, "UC A", item_type="use_case")
    b = make(c, s, "UC B", item_type="use_case")
    req = requirement(
        c,
        s,
        relations=[
            {"relation": "applies_to", "target_id": a["id"]},
            {"relation": "applies_to", "target_id": b["id"]},
        ],
    )
    req2 = requirement(c, s, title="Second requirement")
    task = make(
        c,
        s,
        "One shared task",
        relations=[
            {"relation": "implements", "target_id": req["id"]},
            {"relation": "implements", "target_id": req2["id"]},
        ],
    )
    renamed = act(c, s, task, changes={"title": "Renamed", "parent_id": a["id"]})
    assert renamed.status_code == 200, renamed.text
    assert renamed.json()["record"]["short_code"] == task["short_code"]
    resolved = c.get(
        f"/api/v1/projects/work/workspace/record/{task['short_code']}",
        headers=_auth(s["owner_token"]),
    )
    assert resolved.json()["id"] == task["id"]
    assert len(overview(c, s)["requirements"][0]["implementations"]) == 1
    invalid = act(
        c, s, req, changes={"relations": [{"relation": "implements", "target_id": task["id"]}]}
    )
    assert invalid.status_code == 422
    task = read(c, s, task)
    assert (
        act(
            c, s, task, changes={"relations": [{"relation": "depends_on", "target_id": task["id"]}]}
        ).status_code
        == 409
    )
    other = make(c, s, "Other")
    assert (
        act(
            c,
            s,
            task,
            changes={"relations": [{"relation": "depends_on", "target_id": other["id"]}]},
        ).status_code
        == 200
    )
    assert (
        act(
            c,
            s,
            other,
            changes={"relations": [{"relation": "depends_on", "target_id": task["id"]}]},
        ).status_code
        == 409
    )
    _create_project(c, s["owner_token"], "foreign")
    foreign = _save(c, s, {"kind": "item", "title": "Foreign"}, project="foreign").json()["record"]
    assert (
        act(
            c,
            s,
            other,
            changes={"relations": [{"relation": "depends_on", "target_id": foreign["id"]}]},
        ).status_code
        == 404
    )


def test_record_cas_independent_edits_omitted_empty_and_idempotent_comments(
    project, root_client, root_state
):
    c, s = root_client, root_state
    a = make(c, s, "A", description="Preserve", assignee="Team", due_at="2026-11-01T00:00:00Z")
    b = make(c, s, "B")
    for r in (a, b):
        result = act(c, s, r, changes={"status": "done"})
        assert result.status_code == 200, result.text
    updated = read(c, s, a)
    assert updated["data"]["description"] == "Preserve" and updated["data"]["assignee"] == "Team"
    assert updated["data"]["due_at"] == a["data"]["due_at"]
    assert act(c, s, a, changes={"status": "open"}).status_code == 412
    assert act(c, s, updated, changes={"due_at": None, "assignee": ""}).status_code == 200
    updated = read(c, s, a)
    key = f"pm-comment-{uuid4().hex}"
    first = act(c, s, updated, "comment", body="Discussion **only A**", key=key)
    assert first.status_code == 200, first.text
    replay = act(c, s, updated, "comment", body="Discussion **only A**", key=key)
    assert replay.status_code == 200 and replay.json()["replayed"], replay.text
    assert act(c, s, updated, "comment", body="Changed content", key=key).status_code == 409
    path = f"/api/v1/projects/work/workspace/events/{a['id']}"
    events = c.get(path, headers=_auth(s["owner_token"])).json()
    assert sum(e["kind"] == "comment" for e in events["items"]) == 1
    assert all(e["author_id"] and e["origin"] == "api" for e in events["items"])
    assert (
        c.get(
            f"/api/v1/projects/work/workspace/events/{b['id']}?kind=comment",
            headers=_auth(s["owner_token"]),
        ).json()["total"]
        == 0
    )
    with s["session_factory"]() as session:
        with pytest.raises(Exception, match="append-only|operation blocked by trigger"):
            session.execute(text("DELETE FROM project_record_events"))


def test_decision_done_partial_evidence_and_explicit_acceptance_exception(
    project, root_client, root_state
):
    c, s = root_client, root_state
    uc = make(c, s, "Use case", item_type="use_case")
    req = requirement(c, s, parent_id=uc["id"])
    decision = make(c, s, "Decision made", item_type="decision", status="done", parent_id=req["id"])
    task = make(c, s, "Implementation", parent_id=req["id"])
    ev = evidence(c, s, req)
    assert overview(c, s)["coverage"] == {"denominator": 1, "accepted": 0, "exceptions": 0}
    no = act(
        c, s, req, "assess", result="accepted", reason="Component passed", evidence_ids=[ev["id"]]
    )
    assert no.status_code == 409, no.text
    # A reasoned exception is a separate counted outcome, not complete acceptance.
    yes = act(
        c,
        s,
        req,
        "assess",
        result="exception",
        reason="E2E explicitly deferred",
        evidence_ids=[ev["id"]],
    )
    assert yes.status_code == 200, yes.text
    assert overview(c, s)["coverage"] == {"denominator": 1, "accepted": 0, "exceptions": 1}
    assert read(c, s, task)["data"]["status"] == "open"
    req = read(c, s, req)
    assert act(c, s, req, "assess", result="reopened", reason="Resume E2E").status_code == 200
    assert overview(c, s)["coverage"]["exceptions"] == 0
    assert read(c, s, decision)["data"]["status"] == "done"


def test_requirement_change_keeps_original_old_evidence_needs_explicit_reuse(
    project, root_client, root_state
):
    c, s = root_client, root_state
    req = requirement(c, s)
    ev = evidence(c, s, req, criteria=["component", "e2e"])
    yes = act(
        c,
        s,
        req,
        "assess",
        result="accepted",
        reason="All criteria proven",
        evidence_ids=[ev["id"]],
    )
    assert yes.status_code == 200, yes.text
    req = read(c, s, req)
    changed = act(
        c,
        s,
        req,
        changes={
            "description": "Automatic approval target",
            "requirement": {
                "original": "Customer baseline",
                "change_reason": "Approved scope change",
            },
        },
    )
    assert changed.status_code == 200, changed.text
    new = changed.json()["record"]
    assert new["requirement_revision"] == 2 and overview(c, s)["coverage"]["accepted"] == 0
    assert read(c, s, ev)["data"]["evidence"]["requirement_revision"] == 1
    assert (
        act(
            c,
            s,
            new,
            "assess",
            result="accepted",
            reason="Reuse implicitly",
            evidence_ids=[ev["id"]],
        ).status_code
        == 422
    )
    assert (
        act(
            c,
            s,
            new,
            "reuse_evidence",
            reason="Reviewed unaffected criteria",
            evidence_ids=[ev["id"]],
        ).status_code
        == 200
    )
    new = read(c, s, new)
    assert (
        act(
            c,
            s,
            new,
            "assess",
            result="accepted",
            reason="Revalidated same test scope",
            evidence_ids=[ev["id"]],
        ).status_code
        == 200
    )


def test_legacy_import_explicit_no_duplicate_no_source_overwrite(project, root_client, root_state):
    c, s = root_client, root_state
    with s["session_factory"]() as session:
        p = session.get(CatalogObject, "work")
        data = json.loads(p.data_json)
        data["next_actions"] = ["Preserve the source"]
        p.data_json = json.dumps(data)
        session.commit()
        before = p.data_json
    path = "/api/v1/projects/work/workspace/import-legacy"

    def do():
        return c.post(
            path,
            headers={
                **_auth(s["owner_token"]),
                "If-Match": _etag(c, s),
                "Idempotency-Key": f"pm-legacy-{uuid4().hex}",
            },
            json={"field": "next_actions", "index": 0, "text": "Preserve the source"},
        )

    first = do()
    second = do()
    assert first.status_code == 200 and second.status_code == 200, (first.text, second.text)
    assert first.json()["record"]["id"] == second.json()["record"]["id"]
    legacy = overview(c, s)["legacy"][0]
    assert legacy["authority"] == "record" and legacy["text"] == "Preserve the source"
    with s["session_factory"]() as session:
        assert session.get(CatalogObject, "work").data_json == before


def test_priority_archive_preserves_identity_history_and_discussion(
    project, root_client, root_state
):
    c, s = root_client, root_state
    a = make(
        c,
        s,
        "Deferred task",
        status="deferred",
        priority="urgent",
        blocked_reason="External prerequisite",
    )
    result = act(c, s, a, "comment", body="Keep this discussion")
    a = result.json()["record"]
    archived = act(c, s, a, changes={"archived": True})
    assert archived.status_code == 200, archived.text
    assert (
        c.get(
            "/api/v1/projects/work/workspace/item?archived=false", headers=_auth(s["owner_token"])
        ).json()["total"]
        == 0
    )
    assert (
        c.get(
            "/api/v1/projects/work/workspace/item?archived=true&priority=urgent",
            headers=_auth(s["owner_token"]),
        ).json()["total"]
        == 1
    )
    a = archived.json()["record"]
    restored = act(c, s, a, changes={"archived": False})
    assert restored.json()["record"]["id"] == a["id"]
    assert restored.json()["record"]["data"]["status"] == "deferred"
    assert (
        c.get(
            f"/api/v1/projects/work/workspace/events/{a['id']}?kind=comment",
            headers=_auth(s["owner_token"]),
        ).json()["total"]
        == 1
    )


def test_reopening_shared_work_invalidates_acceptance_without_erasing_history(
    project, root_client, root_state
):
    c, s = root_client, root_state
    req = requirement(c, s)
    task = make(
        c,
        s,
        "Shared implementation",
        status="done",
        relations=[{"relation": "implements", "target_id": req["id"]}],
    )
    ev = evidence(c, s, req, criteria=["component", "e2e"])
    ok = act(c, s, req, "assess", result="accepted", reason="Complete run", evidence_ids=[ev["id"]])
    assert ok.status_code == 200, ok.text
    assert overview(c, s)["coverage"]["accepted"] == 1
    assert act(c, s, task, changes={"status": "open"}).status_code == 200
    view = overview(c, s)
    assert view["coverage"]["accepted"] == 0
    assert view["requirements"][0]["assessment"]["stale"]
    req = read(c, s, req)
    assert req["context"]["assessment"]["stale"]
    no = act(
        c,
        s,
        req,
        "assess",
        result="accepted",
        reason="Ignore reopened task",
        evidence_ids=[ev["id"]],
    )
    assert no.status_code == 409, no.text
    events = c.get(
        f"/api/v1/projects/work/workspace/events/{req['id']}?kind=assess",
        headers=_auth(s["owner_token"]),
    ).json()
    assert events["total"] == 1 and events["items"][0]["data"]["result"] == "accepted"


def test_requirement_original_immutable_and_documented_pages_detect_drift(
    project, root_client, root_state
):
    c, s = root_client, root_state
    req = requirement(c, s)
    bad = act(
        c,
        s,
        req,
        changes={"requirement": {"original": "Rewritten history", "change_reason": "Not allowed"}},
    )
    assert bad.status_code == 422, bad.text
    page = _save(
        c,
        s,
        {
            "kind": "page",
            "title": "Current result",
            "body": "Curated text",
            "relations": [{"relation": "documents", "target_id": req["id"]}],
        },
    ).json()["record"]
    assert page["data"]["relations"][0]["target_version"] == req["version"]
    assert (
        act(
            c,
            s,
            req,
            changes={
                "description": "New target",
                "requirement": {
                    "original": "Customer baseline",
                    "change_reason": "Reviewed change",
                },
            },
        ).status_code
        == 200
    )
    current = read(c, s, page)
    assert current["data"]["body"] == "Curated text"
    assert current["context"]["stale_relations"] == [req["id"]]
    archived = act(c, s, current, changes={"lifecycle": "historical"})
    assert (
        archived.status_code == 200 and archived.json()["record"]["data"]["body"] == "Curated text"
    )


def test_comments_pagination_access_and_new_instance_concealment(project, root_client, root_state):
    c, s = root_client, root_state
    task = make(c, s, "Discussion")
    for body in ("One", "Two", "Three"):
        response = act(c, s, task, "comment", body=body)
        assert response.status_code == 200, response.text
        task = response.json()["record"]
    base = f"/api/v1/projects/work/workspace/events/{task['id']}?kind=comment&limit=2"
    first = c.get(base, headers=_auth(s["owner_token"])).json()
    assert first["total"] == 3 and len(first["items"]) == 2
    second = c.get(base + "&cursor=" + first["next_cursor"], headers=_auth(s["owner_token"])).json()
    assert len(second["items"]) == 1
    assert c.get(base, headers=_auth(s["scoped_token"])).status_code == 404
    assert c.post(
        f"/api/v1/projects/work/workspace/actions/{task['id']}",
        headers={
            **_auth(s["scoped_token"]),
            "If-Match": task["record_etag"],
            "Idempotency-Key": f"pm-denied-{uuid4().hex}",
        },
        json={"action": "comment", "body": "Denied"},
    ).status_code in {403, 404}
    with s["session_factory"]() as session:
        obj = session.get(CatalogObject, "work")
        obj.instance_id = uuid4().hex
        session.commit()
    assert c.get(base, headers=_auth(s["owner_token"])).status_code == 404


def test_repository_link_validation_and_optin_observations_are_not_acceptance(
    project, root_client, root_state, monkeypatch
):
    c, s = root_client, root_state
    repo_data = {
        "kind": "repository",
        "title": "Code",
        "owner": "example",
        "name": "original",
        "github_id": 123,
        "sync_enabled": True,
    }
    created = _save(c, s, repo_data)
    assert created.status_code == 201, created.text
    repo = created.json()["record"]
    assert _save(c, s, repo_data).status_code == 409
    ref = {"repository_id": repo["id"], "kind": "issue", "number": 7}
    task = make(
        c,
        s,
        "Local status",
        github_references=[ref],
        status_authority="github",
        leading_reference=ref,
    )
    calls = []

    def get(path, token, timeout):
        calls.append(path)
        if path == "/repositories/123":
            return {"id": 123, "full_name": "new-owner/renamed", "private": True}
        return {"number": 7, "state": "closed"}

    monkeypatch.setenv("BLOCKWART_PROJECT_GITHUB_SYNC_ENABLED", "true")
    monkeypatch.setattr("blockwart.services.project_github._github_get", get)
    result = act(c, s, task, "sync_github")
    assert result.status_code == 200, result.text
    task = result.json()["record"]
    assert calls == ["/repositories/123", "/repos/new-owner/renamed/issues/7"]
    assert task["context"]["external"]["effective_status"] == "done"
    assert task["data"]["status"] == "open" and task["completed_at"] is None
    assert task["context"]["assessment"] is None
    from blockwart.services.project_github import ObservationError

    def fail(*args, **kw):
        raise ObservationError("rate_limited")

    monkeypatch.setattr("blockwart.services.project_github._github_get", fail)
    result = act(c, s, task, "sync_github")
    assert result.status_code == 200, result.text
    ext = result.json()["record"]["context"]["external"]
    assert not ext["fresh"] and ext["last_success"] and ext["effective_status"] is None
    assert ext["last_attempt"]["observations"][0]["error"] == "rate_limited"


def test_mcp_targeted_action_and_record_resolution_match_rest(project, root_client, root_state):
    c, s = root_client, root_state
    record = make(c, s, "MCP item", description="Keep details")
    seen = []

    def fetch(path, params):
        response = c.get(path, params=params, headers=_auth(s["owner_token"]))
        assert response.status_code == 200, response.text
        return response.json()

    def request(method, path, payload, headers):
        seen.append((method, path, headers))
        response = c.request(
            method, path, json=payload, headers={**_auth(s["owner_mcp_token"]), **headers}
        )
        assert response.status_code == 200, response.text
        return response.json()

    resolved = call_tool(
        "blockwart.get_project_record",
        {"object_id": "work", "record_id": record["short_code"]},
        fetcher=fetch,
    )
    resolved = json.loads(resolved["content"][0]["text"])
    assert resolved["id"] == record["id"]
    changed = call_tool(
        "blockwart.act_on_project_record",
        {
            "object_id": "work",
            "record_id": record["id"],
            "action": {"action": "patch", "changes": {"priority": "high"}},
            "if_match": record["record_etag"],
            "idempotency_key": f"pm-mcp-{uuid4().hex}",
        },
        fetcher=fetch,
        requester=request,
    )
    changed = json.loads(changed["content"][0]["text"])
    assert changed["record"]["data"]["description"] == "Keep details"
    assert seen[0][2]["X-Blockwart-Channel"] == "mcp"


def test_parallel_record_updates_and_global_cycle_invariant(project, root_client, root_state):
    from concurrent.futures import ThreadPoolExecutor

    c, s = root_client, root_state
    a = make(c, s, "Concurrent A", description="Keep A")
    b = make(c, s, "Concurrent B", description="Keep B")
    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(
            pool.map(lambda r: act(c, s, r, changes={"status": "done"}).status_code, [a, b])
        )
    assert outcomes == [200, 200]
    a = read(c, s, a)
    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(
            pool.map(
                lambda value: act(c, s, a, changes={"priority": value}).status_code,
                ["high", "urgent"],
            )
        )
    assert sorted(outcomes) == [200, 412]
    a, b = read(c, s, a), read(c, s, b)
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [
            pool.submit(
                act,
                c,
                s,
                source,
                changes={"relations": [{"relation": "depends_on", "target_id": target["id"]}]},
            )
            for source, target in [(a, b), (b, a)]
        ]
        outcomes = [f.result().status_code for f in futures]
    assert sorted(outcomes) == [200, 409]


def test_scoped_requirement_variant_does_not_change_other_use_case(
    project, root_client, root_state
):
    c, s = root_client, root_state
    a = make(c, s, "UC-A", item_type="use_case")
    b = make(c, s, "UC-B", item_type="use_case")
    old = requirement(
        c,
        s,
        "Original manual approval",
        relations=[
            {"relation": "applies_to", "target_id": a["id"]},
            {"relation": "applies_to", "target_id": b["id"]},
        ],
    )
    original = dict(old["data"])
    new = requirement(
        c,
        s,
        "Automatic approval for UC-A",
        relations=[
            {"relation": "applies_to", "target_id": a["id"]},
            {"relation": "supersedes", "target_id": old["id"]},
        ],
    )
    changed = act(
        c, s, old, changes={"relations": [{"relation": "applies_to", "target_id": b["id"]}]}
    )
    assert changed.status_code == 200, changed.text
    old = changed.json()["record"]
    assert old["data"]["requirement"] == original["requirement"]
    assert old["requirement_revision"] == 1
    assert new["data"]["relations"][0]["target_id"] == a["id"]
    assert read(c, s, b)["data"]["title"] == "UC-B"


def test_populated_0029_upgrade_preserves_all_original_columns(alembic_database_factory):
    from alembic import command

    from blockwart.db.migrations import build_alembic_config

    db = alembic_database_factory("pm-populated.sqlite3")
    cfg = build_alembic_config(db.database_url)
    command.downgrade(cfg, "20261022_0029")
    raw = '{"kind":"item","title":"Preserve exact JSON","item_type":"task","status":"done"}'
    with db.engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO project_records (id,project_instance_id,kind,data_json,version,"
                "created_at,updated_at,completed_at) VALUES ('old-id','old-instance','item',"
                ":raw,1,'2026-10-22 10:00:00','2026-10-22 10:00:00','2026-10-22 10:00:00')"
            ),
            {"raw": raw},
        )
        conn.execute(
            text(
                "INSERT INTO project_record_versions (entry_id,version,data_json,author_id,"
                "author_label,"
                "origin,created_at,completed_at) VALUES ('old-id',1,:raw,'original-author',"
                "'Original author','api','2026-10-22 10:00:00','2026-10-22 10:00:00')"
            ),
            {"raw": raw},
        )
        tables = [
            r[0]
            for r in conn.execute(
                text(
                    "SELECT name FROM sqlite_master WHERE type='table' "
                    "AND name NOT LIKE 'sqlite_%' AND name!='alembic_version'"
                )
            )
        ]
        cols = {t: [r[1] for r in conn.execute(text(f'PRAGMA table_info("{t}")'))] for t in tables}

        def snap():
            return {
                t: conn.execute(
                    text("SELECT " + ",".join('"' + f + '"' for f in fields) + ' FROM "' + t + '"')
                ).fetchall()
                for t, fields in cols.items()
            }

        before = snap()
    command.upgrade(cfg, "head")
    command.check(cfg)
    with db.engine.connect() as conn:
        assert before == snap()
        assert conn.execute(
            text("SELECT short_code,requirement_revision FROM project_records WHERE id='old-id'")
        ).one() == ("REC-00001", 1)
        assert conn.execute(text("pragma integrity_check")).one() == ("ok",)
    with pytest.raises(RuntimeError, match="Refusing PM downgrade"):
        command.downgrade(cfg, "20261022_0029")


def test_github_transport_rejects_private_or_mixed_dns_without_connecting(monkeypatch):
    from blockwart.services import project_github as github

    def unexpected(**kw):
        raise AssertionError("Must not connect")

    monkeypatch.setattr(github, "_request", unexpected)
    for addresses in [("127.0.0.1",), ("8.8.8.8", "169.254.169.254")]:
        monkeypatch.setattr(
            github,
            "_resolve",
            lambda *a, addresses=addresses, **k: tuple(
                __import__("ipaddress").ip_address(v) for v in addresses
            ),
        )
        with pytest.raises(github.ObservationError, match="policy_denied"):
            github._github_get("/repositories/123", None, timeout=1)
