"""Completion rechecks credential access for all acquired references. Refs #297."""

# ruff: noqa: F401, F811 -- imported SQLite/PostgreSQL pytest fixtures.
import json
from uuid import uuid4

import pytest
from conftest import alembic_database_factory
from test_project_management import (
    alembic_session_factory,
    make,
    migrated_pg_engine,
    pg_database_name,
    project,
    root_client,
    root_state,
)
from test_project_records import _save

from blockwart.db.session import transaction
from blockwart.domain.auth import GrantScope, Role
from blockwart.models import CatalogObject
from blockwart.schemas.catalog import CatalogObjectIn
from blockwart.services.access import create_object_grant
from blockwart.services.catalog import upsert_object


@pytest.mark.parametrize("phase", ["metadata", "object", "none"])
@pytest.mark.parametrize("reference_count", [1, 2])
def test_credential_revocation_during_final_get(
    project, root_client, root_state, monkeypatch, phase, reference_count
):
    from sqlalchemy import select

    from blockwart.config import Settings
    from blockwart.models import ObjectGrant, Principal
    from blockwart.schemas.project_workspace import ProjectActionIn
    from blockwart.services.access import revoke_object_grant
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
    refs = [{**ref, "number": 7 + i} for i in range(reference_count)]
    task = make(
        c,
        s,
        "Race target",
        github_references=refs,
        leading_reference=ref,
        status_authority="github",
    )
    with s["session_factory"]() as session:
        principal = principal_context(
            session.get(Principal, s["scoped_id"]), service_token_audience="api"
        )
        access = read_access_for_principal(session, principal)
        context = WriteContext.from_read_access(access, channel="api")
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
    paths = []

    def get(path, token, timeout):
        paths.append(path)
        revoke = (phase == "metadata" and path == "/repositories/123") or (
            phase == "object" and path.endswith(f"/issues/{6 + reference_count}")
        )
        if revoke:
            with s["session_factory"]() as other, transaction(other):
                grant_id = other.scalar(
                    select(ObjectGrant.id).where(
                        ObjectGrant.principal_id == s["scoped_id"],
                        ObjectGrant.object_id == "race-review-ref",
                    )
                )
                assert revoke_object_grant(other, grant_id=grant_id)
        if path == "/repositories/123":
            return {"id": 123, "full_name": "example/example", "private": True}
        return {"number": int(path.rsplit("/", 1)[-1]), "state": "closed"}

    monkeypatch.setattr("blockwart.services.project_github._github_get", get)
    key = "review-race-" + uuid4().hex
    with s["session_factory"]() as session, transaction(session):
        result = apply_action(
            session,
            context,
            object_id="work",
            record_id=task["id"],
            payload=ProjectActionIn(action="sync_github"),
            expected_record=task["record_etag"],
            idempotency_key=key,
            idempotency_ttl_seconds=3600,
        )
        assert not result.replayed
        assert bool(
            read_access_for_principal(session, principal).policy.permissions_for("race-review-ref")
        ) == (phase == "none")
    from sqlalchemy import select

    from blockwart.models import IdempotencyRecord, ProjectRecordEvent

    with s["session_factory"]() as verify:
        events = verify.scalars(
            select(ProjectRecordEvent).where(
                ProjectRecordEvent.record_id == task["id"],
                ProjectRecordEvent.kind == "sync_github",
            )
        ).all()
        persisted = [json.loads(e.data_json) for e in events]
    refs = task["data"]["github_references"]
    assert len(persisted) == 1
    observations = persisted[0]["observations"]
    assert len(observations) == reference_count
    if phase == "none":
        assert all(o["ok"] and o["private"] for o in observations)
        assert len(paths) == 1 + reference_count
    else:
        assert observations == [
            {"reference": r, "ok": False, "error": "credential_not_accessible"} for r in refs
        ]
        assert (
            paths == ["/repositories/123"]
            if phase == "metadata"
            else len(paths) == 1 + reference_count
        )
    assert len(reads) == 1
    assert "synthetic-token" not in json.dumps(persisted)
    with s["session_factory"]() as session, transaction(session):
        replay = apply_action(
            session,
            context,
            object_id="work",
            record_id=task["id"],
            payload=ProjectActionIn(action="sync_github"),
            expected_record=task["record_etag"],
            idempotency_key=key,
            idempotency_ttl_seconds=3600,
        )
        assert replay.replayed
        cached = session.scalars(
            select(IdempotencyRecord).where(
                IdempotencyRecord.principal_id == s["scoped_id"],
            )
        ).all()
        if phase != "none":
            assert all("example/example" not in row.response_json for row in cached)
    assert len(reads) == 1
