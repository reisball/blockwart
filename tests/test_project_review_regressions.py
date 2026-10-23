"""Regressions independently reproduced at e8254b63. Refs #287–#296."""

# ruff: noqa: F401, F811
import json
from uuid import uuid4

import pytest
from conftest import alembic_database_factory
from test_project_management import (
    act,
    alembic_session_factory,
    evidence,
    make,
    migrated_pg_engine,
    overview,
    pg_database_name,
    project,
    read,
    requirement,
    root_client,
    root_state,
)
from test_project_records import _auth, _etag, _save

from blockwart.db.session import transaction
from blockwart.domain.auth import GrantScope, Role
from blockwart.models import CatalogObject
from blockwart.schemas.catalog import CatalogObjectIn
from blockwart.services.access import create_object_grant
from blockwart.services.catalog import upsert_object


def accept(c, s, r, proofs=()):
    response = act(
        c,
        s,
        read(c, s, r),
        "assess",
        result="accepted",
        reason="Review accepted",
        evidence_ids=[p["id"] for p in proofs],
    )
    assert response.status_code == 200, response.text
    return response.json()["record"]


def test_review_child_proof_staleness_does_not_propagate(project, root_client, root_state):
    c, s = root_client, root_state
    uc = make(c, s, "UC", item_type="use_case")
    req = requirement(c, s, parent_id=uc["id"])
    ev = evidence(c, s, req, criteria=["component", "e2e"])
    req = accept(c, s, req, [ev])
    uc = accept(c, s, uc)
    result = act(c, s, ev, changes={"evidence": {**ev["data"]["evidence"], "outcome": "fail"}})
    assert result.status_code == 200, result.text
    assert read(c, s, req)["context"]["assessment"]["stale"] is True
    assert read(c, s, uc)["context"]["assessment"]["stale"] is True


def test_review_acceptance_ignores_dependencies_and_effective_status(
    project, root_client, root_state
):
    c, s = root_client, root_state
    req = requirement(c, s)
    ev = evidence(c, s, req, criteria=["component", "e2e"])
    predecessor = make(c, s, "Open predecessor")
    task = make(
        c,
        s,
        "Done dependent",
        status="done",
        relations=[
            {"relation": "implements", "target_id": req["id"]},
            {"relation": "depends_on", "target_id": predecessor["id"]},
        ],
    )
    assert read(c, s, task)["context"]["blockers"]
    blocked = act(
        c,
        s,
        req,
        "assess",
        result="accepted",
        reason="Must reject blocked work",
        evidence_ids=[ev["id"]],
    )
    assert blocked.status_code == 409, blocked.text
    done = act(c, s, predecessor, changes={"status": "done"})
    assert done.status_code == 200, done.text
    accept(c, s, req, [ev])
    repo = _save(
        c, s, {"kind": "repository", "title": "Repo", "owner": "example", "name": "example"}
    ).json()["record"]
    ref = {"repository_id": repo["id"], "kind": "issue", "number": 7}
    response = act(
        c,
        s,
        task,
        changes={
            "github_references": [ref],
            "leading_reference": ref,
            "status_authority": "github",
        },
    )
    assert response.status_code == 200, response.text
    assert read(c, s, task)["effective_status"] is None
    assert read(c, s, req)["context"]["assessment"]["stale"] is True
    blocked = act(
        c,
        s,
        read(c, s, req),
        "assess",
        result="accepted",
        reason="Unknown upstream is not done",
        evidence_ids=[ev["id"]],
    )
    assert blocked.status_code == 409, blocked.text


def test_review_legacy_put_can_persist_invalid_model(project, root_client, root_state):
    c, s = root_client, root_state
    req = requirement(c, s)
    response = _save(c, s, {"kind": "item", "title": req["data"]["title"]}, record_id=req["id"])
    assert response.status_code == 200, response.text
    record = response.json()["record"]
    assert record["data"]["item_type"] == "requirement" and record["data"]["criteria"]
    response = act(c, s, record, "comment", body="Discussion")
    assert response.status_code == 200, response.text


def test_review_reclassification_revision_lookup(project, root_client, root_state):
    c, s = root_client, root_state
    task = make(c, s, "Historical task title")
    task = act(c, s, task, changes={"title": "Updated task title"}).json()["record"]
    response = act(
        c,
        s,
        task,
        changes={
            "item_type": "requirement",
            "criteria": [{"id": "new", "description": "New requirement criterion"}],
            "requirement": {"original": "Explicit classification"},
        },
    )
    assert response.status_code == 200, response.text
    req = response.json()["record"]
    assert req["requirement_revision"] == 2
    response = _save(
        c,
        s,
        {
            "kind": "item",
            "item_type": "evidence",
            "title": "New proof",
            "evidence": {
                "requirement_id": req["id"],
                "requirement_revision": 2,
                "criteria": ["new"],
                "outcome": "pass",
                "subject": "Build",
                "scope": "Whole requirement",
                "source_url": "https://example.org/run",
                "observed_at": "2026-10-23T00:00:00Z",
            },
        },
    )
    assert response.status_code == 201, response.text


def test_review_nonleading_failure_discards_leading_success(
    project, root_client, root_state, monkeypatch
):
    c, s = root_client, root_state
    repo = _save(
        c,
        s,
        {
            "kind": "repository",
            "title": "Repo",
            "owner": "example",
            "name": "example",
            "github_id": 123,
            "sync_enabled": True,
        },
    ).json()["record"]
    leading = {"repository_id": repo["id"], "kind": "issue", "number": 7}
    secondary = {"repository_id": repo["id"], "kind": "pull", "number": 8}
    task = make(
        c,
        s,
        "Multiple refs",
        github_references=[leading, secondary],
        leading_reference=leading,
        status_authority="github",
    )
    from blockwart.services.project_github import ObservationError

    def get(path, token, timeout):
        if path == "/repositories/123":
            return {"id": 123, "full_name": "example/example"}
        if path.endswith("/issues/7"):
            return {"number": 7, "state": "closed"}
        raise ObservationError("not_found_or_concealed")

    monkeypatch.setenv("BLOCKWART_PROJECT_GITHUB_SYNC_ENABLED", "true")
    monkeypatch.setattr("blockwart.services.project_github._github_get", get)
    response = act(c, s, task, "sync_github")
    assert response.status_code == 200, response.text
    record = response.json()["record"]
    assert record["context"]["external"]["last_attempt"]["observations"][0]["ok"]
    assert record["effective_status"] == "done"


def test_review_decision_counts_as_implementation(project, root_client, root_state):
    c, s = root_client, root_state
    req = requirement(c, s)
    make(
        c,
        s,
        "Architecture decision",
        item_type="decision",
        status="done",
        relations=[{"relation": "implements", "target_id": req["id"]}],
    )
    entry = next(r for r in overview(c, s)["requirements"] if r["record"]["id"] == req["id"])
    assert entry["without_implementation"] is True


def test_review_stale_policy_used_for_credential_fetch(
    project, root_client, root_state, monkeypatch
):
    from uuid import uuid4

    from sqlalchemy import delete

    from blockwart.config import Settings
    from blockwart.models import ObjectGrant, Principal
    from blockwart.schemas.project_workspace import ProjectActionIn
    from blockwart.services.commands import WriteContext
    from blockwart.services.identity import principal_context
    from blockwart.services.project_management import apply_action
    from blockwart.services.read_access import read_access_for_principal

    c, s = root_client, root_state
    with s["session_factory"]() as session, transaction(session):
        upsert_object(
            session,
            CatalogObjectIn(
                id="race-review-ref",
                kind="credential_reference",
                label="Protected",
                data={
                    "schema_version": 1,
                    "provider": "vaultwarden",
                    "reference": {"item_hint": "private"},
                },
            ),
        )
        create_object_grant(
            session,
            principal_id=s["scoped_id"],
            object_id="work",
            role=Role.EDITOR,
            scope=GrantScope.SELF,
        )
        create_object_grant(
            session,
            principal_id=s["scoped_id"],
            object_id="race-review-ref",
            role=Role.VIEWER,
            scope=GrantScope.SELF,
        )
    repo = _save(
        c,
        s,
        {
            "kind": "repository",
            "title": "Repo",
            "owner": "example",
            "name": "example",
            "github_id": 123,
            "sync_enabled": True,
            "credential_reference": "credential_reference:race-review-ref",
        },
    ).json()["record"]
    ref = {"repository_id": repo["id"], "kind": "issue", "number": 7}
    task = make(
        c,
        s,
        "Race target",
        github_references=[ref],
        leading_reference=ref,
        status_authority="github",
    )
    with s["session_factory"]() as session:
        principal = principal_context(
            session.get(Principal, s["scoped_id"]), service_token_audience="api"
        )
        access = read_access_for_principal(session, principal)
        context = WriteContext.from_read_access(access, channel="api")
    # Schedule the competing grant revocation after request authorization but before the write lock.
    with s["session_factory"]() as session, transaction(session):
        session.execute(
            delete(ObjectGrant).where(
                ObjectGrant.principal_id == s["scoped_id"],
                ObjectGrant.object_id == "race-review-ref",
            )
        )
    with s["session_factory"]() as session:
        project_instance = session.get(CatalogObject, "work").instance_id
    reads = []
    monkeypatch.setattr(
        "blockwart.services.project_github.Settings",
        lambda: Settings(
            project_github_sync_enabled=True,
            project_github_credential_files={
                f"{project_instance}/{repo['id']}/123/"
                "credential_reference:race-review-ref": "synthetic-not-a-real-file"
            },
        ),
    )
    monkeypatch.setattr(
        "blockwart.services.project_github._read_credential",
        lambda filename, timeout: reads.append(filename) or "synthetic-token",
    )
    monkeypatch.setattr(
        "blockwart.services.project_github._github_get",
        lambda path, token, timeout: (
            {"id": 123, "full_name": "example/example"}
            if path == "/repositories/123"
            else {"number": 7, "state": "closed"}
        ),
    )
    with s["session_factory"]() as session, transaction(session):
        result = apply_action(
            session,
            context,
            object_id="work",
            record_id=task["id"],
            payload=ProjectActionIn(action="sync_github"),
            expected_record=task["record_etag"],
            idempotency_key="review-race-" + uuid4().hex,
            idempotency_ttl_seconds=3600,
        )
        assert not read_access_for_principal(session, principal).policy.permissions_for(
            "race-review-ref"
        )
    assert reads == [] and result.record.effective_status is None
    assert (
        result.record.context["external"]["last_attempt"]["observations"][0]["error"]
        == "credential_not_accessible"
    )


def test_review_legacy_reorder_loses_adoption_and_duplicates(project, root_client, root_state):
    from uuid import uuid4

    from test_project_records import _etag

    c, s = root_client, root_state

    def source(values):
        with s["session_factory"]() as session, transaction(session):
            row = session.get(CatalogObject, "work")
            data = json.loads(row.data_json)
            data["next_actions"] = values
            row.data_json = json.dumps(data)
            row.revision += 1

    def adopt(index):
        response = c.post(
            "/api/v1/projects/work/workspace/import-legacy",
            headers={
                **_auth(s["owner_token"]),
                "If-Match": _etag(c, s),
                "Idempotency-Key": "review-legacy-" + uuid4().hex,
            },
            json={"field": "next_actions", "index": index, "text": "Adopt me"},
        )
        assert response.status_code == 200, response.text
        return response.json()["record"]

    source(["Adopt me", "Keep legacy"])
    first = adopt(0)
    source(["Keep legacy", "Adopt me"])
    entry = next(e for e in overview(c, s)["legacy"] if e["text"] == "Adopt me")
    assert entry["authority"] == "record"
    second = adopt(1)
    assert first["id"] == second["id"]
    assert read(c, s, second)["data"]["legacy_origin"]["index"] == 0


def test_legacy_duplicate_occurrences_require_reconciliation_after_source_change(
    project, root_client, root_state
):
    c, s = root_client, root_state

    def source(values):
        with s["session_factory"]() as session, transaction(session):
            row = session.get(CatalogObject, "work")
            data = json.loads(row.data_json)
            data["next_actions"] = values
            row.data_json = json.dumps(data)
            row.revision += 1

    def adopt(index):
        from uuid import uuid4

        from test_project_records import _etag

        return c.post(
            "/api/v1/projects/work/workspace/import-legacy",
            headers={
                **_auth(s["owner_token"]),
                "If-Match": _etag(c, s),
                "Idempotency-Key": "duplicate-legacy-" + uuid4().hex,
            },
            json={"field": "next_actions", "index": index, "text": "Same words"},
        )

    source(["Same words", "Same words", "Other"])
    first, second = adopt(0), adopt(1)
    assert first.status_code == second.status_code == 200
    assert first.json()["record"]["id"] != second.json()["record"]["id"]
    source(["Other", "Same words", "Same words"])
    entries = [e for e in overview(c, s)["legacy"] if e["text"] == "Same words"]
    assert all(e["reconciliation_required"] and not e["record_id"] for e in entries)
    assert adopt(1).status_code == 409
    assert adopt(2).status_code == 409
    response = c.get("/api/v1/projects/work/workspace/item", headers=_auth(s["owner_token"]))
    assert response.json()["total"] == 2


def source(s, values):
    with s["session_factory"]() as session, transaction(session):
        row = session.get(CatalogObject, "work")
        data = json.loads(row.data_json)
        data["next_actions"] = values
        row.data_json = json.dumps(data)
        row.revision += 1


def adopt(c, s, index):
    return c.post(
        "/api/v1/projects/work/workspace/import-legacy",
        headers={
            **_auth(s["owner_token"]),
            "If-Match": _etag(c, s),
            "Idempotency-Key": "r2-" + uuid4().hex,
        },
        json={"field": "next_actions", "index": index, "text": "Same words"},
    )


def test_duplicate_removal_requires_reconciliation(project, root_client, root_state):
    c, s = root_client, root_state
    source(s, ["Same words", "Same words"])
    first = adopt(c, s, 0)
    assert first.status_code == 200, first.text
    source(s, ["Same words"])
    entry = next(e for e in overview(c, s)["legacy"] if e["text"] == "Same words")
    repeated = adopt(c, s, 0)
    assert entry["authority"] == "reconciliation_required" and repeated.status_code == 409, (
        entry,
        repeated.status_code,
        repeated.json()["record"]["id"] == first.json()["record"]["id"],
    )


def test_requirement_overview_exposes_implementation_blocker(project, root_client, root_state):
    c, s = root_client, root_state
    req = requirement(c, s)
    blocker = make(c, s, "Missing external prerequisite", item_type="blocker")
    task = make(
        c,
        s,
        "Implementation",
        status="done",
        relations=[
            {"relation": "implements", "target_id": req["id"]},
            {"relation": "blocked_by", "target_id": blocker["id"]},
        ],
    )
    assert read(c, s, task)["context"]["blockers"]
    proof = evidence(c, s, req, criteria=["component", "e2e"])
    blocked = act(
        c,
        s,
        req,
        "assess",
        result="accepted",
        reason="Synthetic review",
        evidence_ids=[proof["id"]],
    )
    assert blocked.status_code == 409, blocked.text
    entry = next(r for r in overview(c, s)["requirements"] if r["record"]["id"] == req["id"])
    assert blocker["id"] in entry["blocked_by"], entry


def test_overview_marks_stale_acceptance_in_browser(project, root_client, root_state):
    from test_project_records import _browser

    c, s = root_client, root_state
    req = requirement(c, s)
    proof = evidence(c, s, req, criteria=["component", "e2e"])
    accepted = act(
        c,
        s,
        req,
        "assess",
        result="accepted",
        reason="Synthetic review",
        evidence_ids=[proof["id"]],
    )
    assert accepted.status_code == 200, accepted.text
    updated = act(
        c, s, proof, changes={"evidence": {**proof["data"]["evidence"], "outcome": "fail"}}
    )
    assert updated.status_code == 200, updated.text
    assert read(c, s, req)["context"]["assessment"]["stale"]
    _browser(c, s)
    page = c.get("/projects/work/workspace", headers={"Accept-Language": "en"})
    assert page.status_code == 200, page.text
    section = page.text.split('id="overview"', 1)[1].split("</section>", 1)[0]
    assert "Assessment needs review after changes" in section, section
