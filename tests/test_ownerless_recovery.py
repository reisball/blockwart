"""Catalog ownership invariant and audited ownerless-object recovery (#232).

The central regression fixture mirrors ``project:coding-orchestrator-project``:
an imported, top-level Project at revision 4 whose only direct grants are two
viewer grants (plus one access-manager grant here), with no Owner at all, in a
catalog whose service principal is a global catalog owner. No live catalog is
touched; every database is a temporary test database.
"""

from __future__ import annotations

import io
import json
import os
import threading
import uuid
from collections.abc import Generator, Iterable
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, func, select, text, update
from sqlalchemy.orm import Session, sessionmaker

from blockwart.api.deps import get_session
from blockwart.api.errors import CodedHTTPException
from blockwart.cli import auth as auth_cli
from blockwart.cli import database as database_cli
from blockwart.cli import import_markdown as import_markdown_cli
from blockwart.cli import seed as seed_cli
from blockwart.db.migrations import upgrade_database
from blockwart.db.session import build_engine, transaction
from blockwart.domain.auth import CatalogRole, GrantScope, Permission, PlatformRole, Role
from blockwart.main import create_app
from blockwart.mcp.server import TOOL_DEFINITIONS, UpstreamError, call_tool
from blockwart.models import (
    AuditEvent,
    CatalogObject,
    ObjectGrant,
    Principal,
    Relationship,
    SecurityEvent,
)
from blockwart.schemas.catalog import CatalogObjectIn
from blockwart.services import commands as commands_module
from blockwart.services import grant_management as grant_management_module
from blockwart.services import identity as identity_module
from blockwart.services import markdown_import as markdown_import_module
from blockwart.services import seeds as seeds_module
from blockwart.services.access import (
    LastOwnerError,
    OwnerCoverageError,
    create_object_grant,
    ensure_complete_owner_coverage,
)
from blockwart.services.audit import load_audit_details
from blockwart.services.catalog import create_relationship, upsert_object
from blockwart.services.commands import (
    CommandAuthorizationDenied,
    CommandConflict,
    CommandPreconditionFailed,
    WriteContext,
    create_catalog_root,
    create_child_object,
)
from blockwart.services.grant_management import (
    adopt_ownerless_object,
    create_managed_grant,
    update_managed_grant,
)
from blockwart.services.identity import (
    create_human_principal,
    create_service_account,
    deactivate_principal,
    issue_browser_session,
    issue_service_token,
    principal_context,
)
from blockwart.services.markdown_import import import_tools_markdown
from blockwart.services.ownership import (
    InitialOwnerError,
    find_ownerless_objects,
    object_owner_coverage,
    ownerless_object_ids,
)
from blockwart.services.policy import policy_for_principal
from blockwart.services.read_access import read_access_for_principal
from blockwart.services.seeds import import_seed_file
from blockwart.ui.security import AUTH_CSRF_COOKIE_NAME, AUTH_SESSION_COOKIE_NAME

LEGACY_ID = "coding-orchestrator-project"
LEGACY_REF = f"project:{LEGACY_ID}"
LEGACY_SOURCE_REF = "/workspace/references/coding-orchestrator.md"
SEED_PATH = Path("seeds/pilot_objects.yaml")
TOOLS_MARKDOWN = "\n".join(
    [
        "| System | Typ | IP:Port | Status | Access | Auth | Nutzung | Ref | Skill |",
        "|--------|-----|---------|--------|--------|------|---------|-----|-------|",
        "| Owned Demo | Service | 192.0.2.10:443 | ✅ | Web | none | Demo | - | - |",
    ]
)


def _asset(
    object_id: str,
    *,
    kind: str = "host",
    label: str | None = None,
    data: dict | None = None,
    provenance: dict | None = None,
) -> CatalogObjectIn:
    payload: dict = {
        "id": object_id,
        "kind": kind,
        "label": label or object_id,
        "data": data or {"schema_version": 1},
    }
    if provenance is not None:
        payload["provenance"] = provenance
    return CatalogObjectIn.model_validate(payload)


def _device(object_id: str) -> CatalogObjectIn:
    return CatalogObjectIn(
        id=object_id,
        kind="device",
        label=object_id,
        lifecycle="active",
        health="healthy",
        data={
            "schema_version": 1,
            "device": {"category": "sensor", "manufacturer": "acme", "model": "x1"},
        },
    )


def _legacy_project() -> CatalogObjectIn:
    return _asset(
        LEGACY_ID,
        kind="project",
        label="Coding Orchestrator",
        data={
            "schema_version": 1,
            "category": "implementation",
            "project_status": "active",
            "started_at": "2026-09-10T07:47:00Z",
        },
        provenance={
            "source_type": "import",
            "source_ref": LEGACY_SOURCE_REF,
            "managed_by": None,
            "observed_at": None,
            "verified_at": None,
            "stale_after": None,
            "manual_override": False,
        },
    )


@pytest.fixture
def ownerless_state(alembic_session_factory):
    with alembic_session_factory() as session:
        with transaction(session):
            zoe = create_service_account(
                session,
                login="zoe.service",
                display_name="Zoe Service",
                catalog_role=CatalogRole.CATALOG_OWNER,
            )
            nova = create_service_account(session, login="nova.agent", display_name="Nova Agent")
            sunday = create_service_account(
                session,
                login="sunday.agent",
                display_name="Sunday Agent",
            )
            manager = create_service_account(
                session,
                login="access.manager",
                display_name="Access Manager",
            )
            healthy_owner = create_service_account(
                session,
                login="healthy.owner",
                display_name="Healthy Owner",
            )
            admin = create_service_account(
                session,
                login="platform.admin",
                display_name="Platform Admin",
                platform_role=PlatformRole.ADMIN,
            )
            creator = create_service_account(
                session,
                login="project.creator",
                display_name="Project Creator",
                catalog_role=CatalogRole.PROJECT_CREATOR,
            )
            retired = create_service_account(
                session,
                login="retired.owner",
                display_name="Retired Owner",
            )
            human = create_human_principal(
                session,
                login="human.catalog.owner",
                display_name="Human Catalog Owner",
                password="human-catalog-owner-password",
                catalog_role=CatalogRole.CATALOG_OWNER,
            )
            ui_manager = create_human_principal(
                session,
                login="ui.access.manager",
                display_name="UI Access Manager",
                password="ui-access-manager-password",
            )

            # Imported top-level Project: two viewer grants, one access
            # manager, and no Owner anywhere. Three grant writes leave it at
            # revision 4, exactly like the reported catalog object.
            upsert_object(session, _legacy_project())
            for principal_id, role in (
                (nova.id, Role.VIEWER),
                (sunday.id, Role.VIEWER),
                (manager.id, Role.ACCESS_MANAGER),
            ):
                create_object_grant(
                    session,
                    principal_id=principal_id,
                    object_id=LEGACY_ID,
                    role=role,
                    scope=GrantScope.SELF,
                )

            # A healthy placed subtree: direct Owner on the host, inherited
            # Owner on the service it hosts.
            upsert_object(session, _asset("healthy-host"))
            upsert_object(session, _asset("healthy-service", kind="service"))
            create_relationship(
                session,
                from_ref="host:healthy-host",
                relation_type="hosts",
                to_ref="service:healthy-service",
            )
            for principal_id, role, scope in (
                (healthy_owner.id, Role.OWNER, GrantScope.SUBTREE),
                (manager.id, Role.ACCESS_MANAGER, GrantScope.SUBTREE),
                (ui_manager.id, Role.ACCESS_MANAGER, GrantScope.SELF),
            ):
                create_object_grant(
                    session,
                    principal_id=principal_id,
                    object_id="healthy-host",
                    role=role,
                    scope=scope,
                )

            # Preserve one historical ownerless row without exercising the
            # current mutation service, which now rejects this transition.
            upsert_object(session, _asset("retired-owner-host"))
            create_object_grant(
                session,
                principal_id=retired.id,
                object_id="retired-owner-host",
                role=Role.OWNER,
                scope=GrantScope.SELF,
            )
            retired_row = session.get(Principal, retired.id)
            assert retired_row is not None
            retired_row.active = False
            session.flush()

            ids = {
                "zoe": zoe.id,
                "nova": nova.id,
                "sunday": sunday.id,
                "manager": manager.id,
                "healthy_owner": healthy_owner.id,
                "admin": admin.id,
                "creator": creator.id,
                "retired": retired.id,
                "human": human.id,
                "ui_manager": ui_manager.id,
            }
            tokens = {
                name: issue_service_token(
                    session,
                    principal_id=ids[name],
                    name="ownership",
                ).value
                for name in (
                    "zoe",
                    "nova",
                    "manager",
                    "healthy_owner",
                    "admin",
                    "creator",
                )
            }
            tokens["zoe_mcp"] = issue_service_token(
                session,
                principal_id=zoe.id,
                name="ownership-mcp",
                audience="mcp",
            ).value
            browsers = {
                name: issue_browser_session(
                    session,
                    principal_id=ids[name],
                    ttl_seconds=3600,
                )
                for name in ("human", "ui_manager")
            }
    return {
        "session_factory": alembic_session_factory,
        "ids": ids,
        "tokens": tokens,
        "browsers": browsers,
    }


@pytest.fixture
def client(ownerless_state) -> Generator[TestClient, None, None]:
    session_factory = ownerless_state["session_factory"]
    app = create_app()

    def override_get_session() -> Generator[Session, None, None]:
        with session_factory() as session:
            yield session

    app.dependency_overrides[get_session] = override_get_session
    with TestClient(app) as test_client:
        yield test_client


def _auth(token: str, **headers: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}", **headers}


def _access(client: TestClient, token: str, object_id: str) -> dict:
    response = client.get(f"/api/v1/objects/{object_id}/access", headers=_auth(token))
    assert response.status_code == 200, response.text
    return response.json()


def _adopt(
    client: TestClient,
    token: str,
    object_id: str,
    principal_id: str,
    etag: str | None,
    *,
    channel: str | None = None,
):
    headers = _auth(token)
    if etag is not None:
        headers["If-Match"] = etag
    if channel is not None:
        headers["X-Blockwart-Channel"] = channel
    return client.post(
        f"/api/v1/objects/{object_id}/access/adoption",
        headers=headers,
        json={"principal_id": principal_id},
    )


def _error_code(response) -> str:
    return response.json()["error"]["code"]


def _owner_grants(session: Session, object_id: str) -> list[ObjectGrant]:
    return list(
        session.scalars(
            select(ObjectGrant)
            .where(ObjectGrant.object_id == object_id, ObjectGrant.role == Role.OWNER)
            .order_by(ObjectGrant.id)
        )
    )


def _revision(session: Session, object_id: str) -> int:
    row = session.get(CatalogObject, object_id)
    assert row is not None
    return row.revision


def _adoption_audits(session: Session, object_id: str) -> list[dict]:
    return [
        load_audit_details(row)
        for row in session.scalars(
            select(AuditEvent)
            .where(AuditEvent.object_id == object_id, AuditEvent.action == "owner_adopt")
            .order_by(AuditEvent.id)
        )
    ]


def _security_events(session: Session, event_type: str) -> list[dict]:
    return [
        {"outcome": row.outcome, "channel": row.channel, **json.loads(row.details_json)}
        for row in session.scalars(
            select(SecurityEvent)
            .where(SecurityEvent.event_type == event_type)
            .order_by(SecurityEvent.id)
        )
    ]


def _write_context(session: Session, principal_id: str) -> WriteContext:
    principal = session.get(Principal, principal_id)
    assert principal is not None
    return WriteContext.from_read_access(
        read_access_for_principal(session, principal_context(principal)),
        channel="ui",
    )


# --- detection ---------------------------------------------------------------


def test_legacy_import_fixture_is_reported_without_guessing_an_owner(ownerless_state) -> None:
    with ownerless_state["session_factory"]() as session:
        grants_before = session.scalar(select(func.count(ObjectGrant.id)))
        reports = {report.ref: report for report in find_ownerless_objects(session)}

        assert set(reports) == {LEGACY_REF, "host:retired-owner-host"}
        legacy = reports[LEGACY_REF]
        assert (legacy.label, legacy.revision, legacy.placement) == (
            "Coding Orchestrator",
            4,
            "top_level",
        )
        assert (legacy.provenance_source_type, legacy.provenance_source_ref) == (
            "import",
            LEGACY_SOURCE_REF,
        )
        assert legacy.direct_active_owner_grants == 0
        assert legacy.inherited_active_owner_grants == 0
        assert legacy.inactive_direct_owner_grants == 0
        assert legacy.adoption_possible is True
        assert legacy.adoption_blocker is None
        assert reports["host:retired-owner-host"].inactive_direct_owner_grants == 1

        inherited = object_owner_coverage(session, "healthy-service", lock=False)
        assert inherited.direct_active_owner_grants == 0
        assert inherited.inherited_active_owner_grants == 1
        assert not inherited.ownerless

        # The report is read-only, and global authority neither hides nor
        # repairs missing per-object Owner-grant coverage.
        assert session.scalar(select(func.count(ObjectGrant.id))) == grants_before
        with pytest.raises(OwnerCoverageError) as incomplete:
            ensure_complete_owner_coverage(session)
        assert incomplete.value.code == "owner_coverage_incomplete"


def test_report_marks_adoption_impossible_without_an_active_catalog_owner(
    alembic_session_factory,
) -> None:
    with alembic_session_factory() as session:
        with transaction(session):
            upsert_object(session, _legacy_project())
        reports = find_ownerless_objects(session)
    report_states = [
        (report.ref, report.adoption_possible, report.adoption_blocker)
        for report in reports
    ]
    assert report_states == [(LEGACY_REF, False, "catalog_owner_missing")]


def test_owner_report_cli_lists_legacy_objects_and_integrity_only_warns(
    ownerless_state,
    alembic_database,
    client: TestClient,
    capsys,
) -> None:
    url = alembic_database.database_url

    assert database_cli.main(["--database-url", url, "owners"]) == 1
    output = capsys.readouterr().out
    rows = {
        row["ref"]: row
        for row in (
            json.loads(line.split(" ", 1)[1])
            for line in output.splitlines()
            if line.startswith("ownerless_object ")
        )
    }
    assert set(rows) == {LEGACY_REF, "host:retired-owner-host"}
    assert rows[LEGACY_REF] == {
        "ref": LEGACY_REF,
        "object_id": LEGACY_ID,
        "kind": "project",
        "label": "Coding Orchestrator",
        "revision": 4,
        "etag": '"rev-4"',
        "placement": "top_level",
        "direct_active_owner_grants": 0,
        "inherited_active_owner_grants": 0,
        "inactive_direct_owner_grants": 0,
        "provenance": {"source_type": "import", "source_ref": LEGACY_SOURCE_REF},
        "adoption_possible": True,
        "adoption_blocker": None,
    }
    assert "database_owners_attention" in output
    assert "ownerless=2 adoptable=2" in output

    assert database_cli.main(["--database-url", url, "--apply", "owners"]) == 1
    assert "owner_report_error=apply_not_available" in capsys.readouterr().err

    assert database_cli.main(["--database-url", url, "integrity"]) == 0
    captured = capsys.readouterr()
    assert (
        "owner_integrity_warning code=access_owner_missing "
        f"ref={LEGACY_REF} placement=top_level adoption_possible=1"
    ) in captured.err
    assert "database_integrity_ok" in captured.out

    tokens, ids = ownerless_state["tokens"], ownerless_state["ids"]
    for object_id, target in ((LEGACY_ID, "nova"), ("retired-owner-host", "healthy_owner")):
        etag = _access(client, tokens["zoe"], object_id)["etag"]
        assert _adopt(client, tokens["zoe"], object_id, ids[target], etag).status_code == 201
    assert database_cli.main(["--database-url", url, "owners"]) == 0
    assert "database_owners_ok" in capsys.readouterr().out


def test_attention_lists_ownerless_objects_only_for_access_managers(
    client: TestClient,
    ownerless_state,
) -> None:
    tokens, ids = ownerless_state["tokens"], ownerless_state["ids"]

    def attention(token: str) -> dict:
        response = client.get(
            "/api/v1/attention",
            params={"reason_code": "access_owner_missing", "limit": 100},
            headers=_auth(token),
        )
        assert response.status_code == 200, response.text
        return response.json()

    zoe_items = {item["target"]["ref"]: item for item in attention(tokens["zoe"])["items"]}
    assert set(zoe_items) == {LEGACY_REF, "host:retired-owner-host"}
    legacy = zoe_items[LEGACY_REF]
    assert (legacy["category"], legacy["severity"], legacy["signal_state"]) == (
        "access",
        "warning",
        "current",
    )
    assert legacy["detail_code"] == "adoption_available"
    assert legacy["target"]["label"] == "Coding Orchestrator"
    assert legacy["target"]["detail_path"] == f"/objects/{LEGACY_ID}"

    # An access manager without catalog authority learns only about objects
    # it administers, and that a catalog owner must adopt them.
    manager_items = attention(tokens["manager"])["items"]
    assert [(item["target"]["ref"], item["detail_code"]) for item in manager_items] == [
        (LEGACY_REF, "catalog_owner_adoption_required")
    ]

    # A plain reader never learns whether an object has an Owner.
    viewer = attention(tokens["nova"])
    assert viewer["items"] == []
    assert viewer["summary"]["by_reason"]["access_owner_missing"] == 0
    assert viewer["summary"]["signals"]["access"]["state"] == "not_applicable"

    etag = _access(client, tokens["zoe"], LEGACY_ID)["etag"]
    assert _adopt(client, tokens["zoe"], LEGACY_ID, ids["nova"], etag).status_code == 201
    assert {item["target"]["ref"] for item in attention(tokens["zoe"])["items"]} == {
        "host:retired-owner-host"
    }


def test_attention_adoption_availability_matches_token_audience(
    client: TestClient,
    ownerless_state,
) -> None:
    token = ownerless_state["tokens"]["zoe_mcp"]

    api_response = client.get(
        "/api/v1/attention",
        params={"reason_code": "access_owner_missing", "limit": 100},
        headers=_auth(token),
    )
    mcp_response = client.get(
        "/api/v1/attention",
        params={"reason_code": "access_owner_missing", "limit": 100},
        headers=_auth(token, **{"X-Blockwart-Channel": "mcp"}),
    )

    assert api_response.status_code == 200, api_response.text
    assert mcp_response.status_code == 200, mcp_response.text
    assert {item["detail_code"] for item in api_response.json()["items"]} == {
        "catalog_owner_adoption_required"
    }
    assert {item["detail_code"] for item in mcp_response.json()["items"]} == {
        "adoption_available"
    }


# --- the deadlock and its structured reasons -----------------------------------


def test_catalog_owner_cannot_mint_the_first_owner_and_gets_the_adoption_reason(
    client: TestClient,
    ownerless_state,
) -> None:
    tokens, ids = ownerless_state["tokens"], ownerless_state["ids"]
    access = _access(client, tokens["zoe"], LEGACY_ID)
    assert access["revision"] == 4
    assert access["etag"] == '"rev-4"'
    assert access["owner_coverage"] == {
        "state": "ownerless",
        "direct_active_owner_grants": 0,
        "inherited_active_owner_grants": 0,
        "inactive_direct_owner_grants": 0,
        "actor_has_owner_source": False,
        "adoption_available": True,
    }
    nova_grant = next(
        grant for grant in access["direct_grants"] if grant["principal"]["id"] == ids["nova"]
    )

    promoted = client.put(
        f"/api/v1/objects/{LEGACY_ID}/access/grants/{nova_grant['id']}",
        headers=_auth(tokens["zoe"], **{"If-Match": access["etag"]}),
        json={"role": "owner", "scope": "self"},
    )
    created = client.post(
        f"/api/v1/objects/{LEGACY_ID}/access/grants",
        headers=_auth(tokens["zoe"], **{"If-Match": access["etag"]}),
        json={"principal_id": ids["sunday"], "role": "owner", "scope": "self"},
    )

    for response in (promoted, created):
        assert response.status_code == 403
        assert _error_code(response) == "object_has_no_owner_use_adoption_flow"
        assert "adoption" in response.json()["error"]["message"]
    with ownerless_state["session_factory"]() as session:
        assert _revision(session, LEGACY_ID) == 4
        assert _owner_grants(session, LEGACY_ID) == []
        assert session.get(ObjectGrant, nova_grant["id"]).role == Role.VIEWER
        denials = [
            event
            for event in _security_events(session, "object_command_authorization")
            if event.get("reason") == "object_has_no_owner_use_adoption_flow"
        ]
        assert len(denials) == 2
        assert all(event["outcome"] == "denied" for event in denials)


def test_manage_access_without_owner_keeps_the_owner_only_rule_on_healthy_objects(
    client: TestClient,
    ownerless_state,
) -> None:
    tokens, ids = ownerless_state["tokens"], ownerless_state["ids"]
    access = _access(client, tokens["manager"], "healthy-host")
    assert access["owner_coverage"]["state"] == "owned"
    assert access["owner_coverage"]["direct_active_owner_grants"] == 1
    assert access["owner_coverage"]["actor_has_owner_source"] is False
    assert access["owner_coverage"]["adoption_available"] is False
    owner_grant = next(grant for grant in access["direct_grants"] if grant["role"] == "owner")
    headers = _auth(tokens["manager"], **{"If-Match": access["etag"]})

    attempts = [
        client.post(
            "/api/v1/objects/healthy-host/access/grants",
            headers=headers,
            json={"principal_id": ids["nova"], "role": "owner", "scope": "self"},
        ),
        client.put(
            f"/api/v1/objects/healthy-host/access/grants/{owner_grant['id']}",
            headers=headers,
            json={"role": "viewer", "scope": "self"},
        ),
        client.delete(
            f"/api/v1/objects/healthy-host/access/grants/{owner_grant['id']}",
            headers=headers,
        ),
    ]
    for response in attempts:
        assert response.status_code == 403
        assert _error_code(response) == "owner_required_to_manage_owner_grants"

    # The inherited-only object answers the same way: it is not ownerless.
    service_access = _access(client, tokens["manager"], "healthy-service")
    assert service_access["owner_coverage"]["inherited_active_owner_grants"] == 1
    inherited = client.post(
        "/api/v1/objects/healthy-service/access/grants",
        headers=_auth(tokens["manager"], **{"If-Match": service_access["etag"]}),
        json={"principal_id": ids["nova"], "role": "owner", "scope": "self"},
    )
    assert _error_code(inherited) == "owner_required_to_manage_owner_grants"

    ordinary = client.post(
        "/api/v1/objects/healthy-host/access/grants",
        headers=headers,
        json={"principal_id": ids["nova"], "role": "viewer", "scope": "self"},
    )
    assert ordinary.status_code == 201, ordinary.text
    with ownerless_state["session_factory"]() as session:
        assert [grant.principal_id for grant in _owner_grants(session, "healthy-host")] == [
            ids["healthy_owner"]
        ]


def test_coded_http_exception_accepts_only_closed_reason_codes() -> None:
    assert CodedHTTPException(409, error_code="object_has_owner_coverage", detail="x")
    with pytest.raises(ValueError):
        CodedHTTPException(409, error_code="Not A Code!", detail="x")


# --- adoption ------------------------------------------------------------------


def test_adoption_assigns_exactly_one_owner_atomically_with_full_audit(
    client: TestClient,
    ownerless_state,
) -> None:
    tokens, ids = ownerless_state["tokens"], ownerless_state["ids"]
    response = _adopt(client, tokens["zoe"], LEGACY_ID, ids["nova"], '"rev-4"')

    assert response.status_code == 201, response.text
    assert response.headers["ETag"] == '"rev-5"'
    body = response.json()
    assert {key: body[key] for key in ("object_id", "revision", "etag", "changed")} == {
        "object_id": LEGACY_ID,
        "revision": 5,
        "etag": '"rev-5"',
        "changed": True,
    }
    assert body["previous_owner_count"] == 0
    assert body["inactive_direct_owner_grants"] == 0
    assert body["grant"]["principal"]["id"] == ids["nova"]
    assert (body["grant"]["role"], body["grant"]["scope"]) == ("owner", "self")

    with ownerless_state["session_factory"]() as session:
        owner_grants = _owner_grants(session, LEGACY_ID)
        assert [
            (grant.principal_id, grant.scope, grant.created_by_principal_id)
            for grant in owner_grants
        ] == [(ids["nova"], GrantScope.SELF, ids["zoe"])]
        # The pre-existing viewer grant is untouched; nothing else was guessed.
        assert session.scalar(
            select(func.count(ObjectGrant.id)).where(ObjectGrant.object_id == LEGACY_ID)
        ) == 4
        assert LEGACY_ID not in ownerless_object_ids(session)

        audits = _adoption_audits(session, LEGACY_ID)
        assert len(audits) == 1
        audit = audits[0]
        assert {
            key: audit[key]
            for key in (
                "actor_principal_id",
                "actor_login",
                "catalog_authority",
                "target_principal_id",
                "target_login",
                "channel",
                "object_ref",
                "old_revision",
                "new_revision",
                "previous_owner_count",
                "previous_direct_owner_count",
                "previous_inherited_owner_count",
                "inactive_direct_owner_grants",
                "before",
            )
        } == {
            "actor_principal_id": ids["zoe"],
            "actor_login": "zoe.service",
            "catalog_authority": "catalog_owner",
            "target_principal_id": ids["nova"],
            "target_login": "nova.agent",
            "channel": "api",
            "object_ref": LEGACY_REF,
            "old_revision": 4,
            "new_revision": 5,
            "previous_owner_count": 0,
            "previous_direct_owner_count": 0,
            "previous_inherited_owner_count": 0,
            "inactive_direct_owner_grants": 0,
            "before": None,
        }
        assert audit["request_id"] == response.headers["X-Correlation-ID"]
        assert audit["after"] == {
            "grant_id": owner_grants[0].id,
            "principal_id": ids["nova"],
            "object_id": LEGACY_ID,
            "role": "owner",
            "scope": "self",
        }
        events = _security_events(session, "ownerless_object_adoption")
        assert [(event["outcome"], event["object_id"]) for event in events] == [
            ("success", LEGACY_ID)
        ]

        policy = policy_for_principal(session, ids["nova"])
        assert Role.OWNER in {grant.role for grant in policy.grants_for(LEGACY_ID)}
        assert policy.permissions_for(LEGACY_ID) == frozenset(Permission)

    after = _access(client, tokens["zoe"], LEGACY_ID)
    assert after["owner_coverage"]["state"] == "owned"
    assert after["owner_coverage"]["direct_active_owner_grants"] == 1
    assert after["owner_coverage"]["adoption_available"] is False


def test_adoption_refuses_existing_direct_or_inherited_owner_coverage(
    client: TestClient,
    ownerless_state,
) -> None:
    tokens, ids = ownerless_state["tokens"], ownerless_state["ids"]
    first = _adopt(client, tokens["zoe"], LEGACY_ID, ids["nova"], '"rev-4"')
    assert first.status_code == 201

    again = _adopt(client, tokens["zoe"], LEGACY_ID, ids["sunday"], first.json()["etag"])
    assert again.status_code == 409
    assert _error_code(again) == "object_has_owner_coverage"

    for object_id in ("healthy-host", "healthy-service"):
        etag = _access(client, tokens["zoe"], object_id)["etag"]
        refused = _adopt(client, tokens["zoe"], object_id, ids["nova"], etag)
        assert refused.status_code == 409
        assert _error_code(refused) == "object_has_owner_coverage"

    with ownerless_state["session_factory"]() as session:
        assert _revision(session, LEGACY_ID) == 5
        assert len(_owner_grants(session, LEGACY_ID)) == 1
        assert _owner_grants(session, "healthy-service") == []
        assert len(_adoption_audits(session, LEGACY_ID)) == 1


@pytest.mark.parametrize(
    ("if_match", "status", "code"),
    [
        ('"rev-3"', 412, "precondition_failed"),
        ('W/"rev-4"', 412, "precondition_failed"),
        ("rev-4", 412, "precondition_failed"),
        (None, 428, "precondition_required"),
    ],
)
def test_adoption_requires_the_current_strong_etag(
    client: TestClient,
    ownerless_state,
    if_match: str | None,
    status: int,
    code: str,
) -> None:
    tokens, ids = ownerless_state["tokens"], ownerless_state["ids"]
    response = _adopt(client, tokens["zoe"], LEGACY_ID, ids["nova"], if_match)

    assert response.status_code == status
    assert _error_code(response) == code
    with ownerless_state["session_factory"]() as session:
        assert _revision(session, LEGACY_ID) == 4
        assert _owner_grants(session, LEGACY_ID) == []


@pytest.mark.parametrize("target", ["retired", "unknown"])
def test_adoption_requires_an_existing_active_target_principal(
    client: TestClient,
    ownerless_state,
    target: str,
) -> None:
    tokens, ids = ownerless_state["tokens"], ownerless_state["ids"]
    principal_id = ids["retired"] if target == "retired" else str(uuid.uuid4())
    response = _adopt(client, tokens["zoe"], LEGACY_ID, principal_id, '"rev-4"')

    assert response.status_code == 409
    assert _error_code(response) == "owner_principal_inactive"
    with ownerless_state["session_factory"]() as session:
        assert _revision(session, LEGACY_ID) == 4
        assert _owner_grants(session, LEGACY_ID) == []
        assert _adoption_audits(session, LEGACY_ID) == []


def test_only_an_active_catalog_owner_on_a_trusted_channel_may_adopt(
    client: TestClient,
    ownerless_state,
) -> None:
    tokens, ids = ownerless_state["tokens"], ownerless_state["ids"]
    attempts = [
        _adopt(client, tokens[name], LEGACY_ID, ids["nova"], '"rev-4"')
        for name in ("manager", "admin", "creator", "nova", "healthy_owner")
    ]
    # A catalog owner's token must still match the channel it arrives on.
    attempts.append(
        _adopt(client, tokens["zoe"], LEGACY_ID, ids["nova"], '"rev-4"', channel="mcp")
    )
    attempts.append(_adopt(client, tokens["zoe_mcp"], LEGACY_ID, ids["nova"], '"rev-4"'))
    # The authority gate runs before the object is inspected, so a missing
    # object is indistinguishable from an existing one for these callers.
    attempts.append(_adopt(client, tokens["manager"], "no-such-object", ids["nova"], '"rev-1"'))

    for response in attempts:
        assert response.status_code == 403
        assert _error_code(response) == "adoption_requires_catalog_owner"
    with ownerless_state["session_factory"]() as session:
        assert _revision(session, LEGACY_ID) == 4
        assert _owner_grants(session, LEGACY_ID) == []
        denials = [
            event
            for event in _security_events(session, "object_command_authorization")
            if event.get("reason") == "adoption_requires_catalog_owner"
        ]
        assert len(denials) == len(attempts)


def test_an_object_whose_only_owner_is_inactive_is_ownerless_and_adoptable(
    client: TestClient,
    ownerless_state,
) -> None:
    tokens, ids = ownerless_state["tokens"], ownerless_state["ids"]
    access = _access(client, tokens["zoe"], "retired-owner-host")
    assert access["owner_coverage"]["state"] == "ownerless"
    assert access["owner_coverage"]["inactive_direct_owner_grants"] == 1

    response = _adopt(
        client,
        tokens["zoe"],
        "retired-owner-host",
        ids["healthy_owner"],
        access["etag"],
    )
    assert response.status_code == 201, response.text
    assert response.json()["inactive_direct_owner_grants"] == 1
    with ownerless_state["session_factory"]() as session:
        assert [
            grant.principal_id for grant in _owner_grants(session, "retired-owner-host")
        ] == [ids["retired"], ids["healthy_owner"]]
        assert _adoption_audits(session, "retired-owner-host")[0][
            "inactive_direct_owner_grants"
        ] == 1


def test_concurrent_adoptions_have_one_winner_and_one_deterministic_conflict(
    client: TestClient,
    ownerless_state,
) -> None:
    tokens, ids = ownerless_state["tokens"], ownerless_state["ids"]

    def attempt(target: str):
        return _adopt(client, tokens["zoe"], LEGACY_ID, ids[target], '"rev-4"')

    with ThreadPoolExecutor(max_workers=2) as pool:
        responses = list(pool.map(attempt, ["nova", "sunday"]))

    assert sorted(response.status_code for response in responses) == [201, 412]
    loser = next(response for response in responses if response.status_code == 412)
    assert _error_code(loser) == "precondition_failed"
    with ownerless_state["session_factory"]() as session:
        assert len(_owner_grants(session, LEGACY_ID)) == 1
        assert _revision(session, LEGACY_ID) == 5
        assert len(_adoption_audits(session, LEGACY_ID)) == 1

    retry = _adopt(client, tokens["zoe"], LEGACY_ID, ids["sunday"], '"rev-5"')
    assert retry.status_code == 409
    assert _error_code(retry) == "object_has_owner_coverage"


def test_last_owner_and_self_lockout_protections_are_unchanged_after_adoption(
    client: TestClient,
    ownerless_state,
) -> None:
    tokens, ids = ownerless_state["tokens"], ownerless_state["ids"]
    adopted = _adopt(client, tokens["zoe"], LEGACY_ID, ids["nova"], '"rev-4"')
    assert adopted.status_code == 201
    grant_id = adopted.json()["grant"]["id"]
    etag = adopted.json()["etag"]
    path = f"/api/v1/objects/{LEGACY_ID}/access/grants"

    last_owner_revoke = client.delete(
        f"{path}/{grant_id}",
        headers=_auth(tokens["nova"], **{"If-Match": etag}),
    )
    last_owner_downgrade = client.put(
        f"{path}/{grant_id}",
        headers=_auth(tokens["nova"], **{"If-Match": etag}),
        json={"role": "editor", "scope": "self"},
    )
    for response in (last_owner_revoke, last_owner_downgrade):
        assert response.status_code == 409
        assert _error_code(response) == "conflict"

    # Now that an Owner exists, the catalog owner is back on the healthy rule.
    catalog_owner_revoke = client.delete(
        f"{path}/{grant_id}",
        headers=_auth(tokens["zoe"], **{"If-Match": etag}),
    )
    assert catalog_owner_revoke.status_code == 403
    assert _error_code(catalog_owner_revoke) == "owner_required_to_manage_owner_grants"

    second_owner = client.post(
        path,
        headers=_auth(tokens["nova"], **{"If-Match": etag}),
        json={"principal_id": ids["sunday"], "role": "owner", "scope": "self"},
    )
    assert second_owner.status_code == 201, second_owner.text
    self_lockout = client.delete(
        f"{path}/{grant_id}",
        headers=_auth(tokens["nova"], **{"If-Match": second_owner.json()["etag"]}),
    )
    assert self_lockout.status_code == 409
    assert "access management" in self_lockout.json()["error"]["message"]
    with ownerless_state["session_factory"]() as session:
        assert {grant.principal_id for grant in _owner_grants(session, LEGACY_ID)} == {
            ids["nova"],
            ids["sunday"],
        }


# --- creation paths ------------------------------------------------------------


def test_every_command_create_path_commits_the_creator_as_owner(
    client: TestClient,
    ownerless_state,
) -> None:
    tokens, ids = ownerless_state["tokens"], ownerless_state["ids"]
    zoe = tokens["zoe"]
    created = [
        client.post(
            "/api/v1/roots",
            headers=_auth(zoe, **{"Idempotency-Key": "ownership-root-0001"}),
            json=_asset("owned-root").model_dump(mode="json"),
        ),
        client.post(
            "/api/v1/objects/owned-root/children",
            headers=_auth(zoe, **{"Idempotency-Key": "ownership-child-0001"}),
            json=_asset("owned-child", kind="service").model_dump(mode="json"),
        ),
        client.post(
            "/api/v1/objects/owned-root/attached-devices",
            headers=_auth(zoe, **{"Idempotency-Key": "ownership-device-0001"}),
            json={"device": _device("owned-device").model_dump(mode="json")},
        ),
    ]
    for response in created:
        assert response.status_code == 201, response.text

    def requester(method, path, body, headers):
        response = client.request(
            method,
            path,
            json=body,
            headers={**headers, **_auth(tokens["zoe_mcp"])},
        )
        assert response.status_code < 400, response.text
        return response.json()

    call_tool(
        "blockwart.create_root",
        {
            "idempotency_key": "ownership-mcp-root-01",
            "object": {"id": "owned-mcp-root", "kind": "host", "label": "Owned MCP Root"},
        },
        requester=requester,
    )

    browser = ownerless_state["browsers"]["human"]
    client.cookies.set(AUTH_SESSION_COOKIE_NAME, browser.value)
    client.cookies.set(AUTH_CSRF_COOKIE_NAME, browser.csrf_token)
    ui_created = client.post(
        "/roots",
        data={
            "csrf_token": browser.csrf_token,
            "idempotency_key": "ownership-ui-root-01",
            "object_id": "owned-ui-root",
            "kind": "host",
            "label": "",
            "primary_name": "Owned UI Root",
            "labels": "",
            "platform": "VM",
            "status": "active",
            "summary": "",
        },
        follow_redirects=False,
    )
    assert ui_created.status_code == 303, ui_created.text

    expected_owner = {
        "owned-root": ids["zoe"],
        "owned-child": ids["zoe"],
        "owned-device": ids["zoe"],
        "owned-mcp-root": ids["zoe"],
        "owned-ui-root": ids["human"],
    }
    with ownerless_state["session_factory"]() as session:
        for object_id, owner_id in expected_owner.items():
            assert [
                (grant.principal_id, grant.scope) for grant in _owner_grants(session, object_id)
            ] == [(owner_id, GrantScope.SELF)], object_id
        assert not set(expected_owner) & ownerless_object_ids(session)


def test_create_is_rejected_and_rolled_back_when_the_creator_can_no_longer_own(
    ownerless_state,
) -> None:
    ids = ownerless_state["ids"]
    session_factory = ownerless_state["session_factory"]
    with session_factory() as session:
        with pytest.raises(CommandConflict) as exc_info:
            with transaction(session):
                context = _write_context(session, ids["healthy_owner"])
                # The creator is deactivated after its policy snapshot was
                # taken; the shared primitive re-reads it before commit.
                session.execute(
                    update(Principal)
                    .where(Principal.id == ids["healthy_owner"])
                    .values(active=False)
                )
                create_child_object(
                    session,
                    context,
                    parent_id="healthy-host",
                    payload=_asset("orphan-child", kind="service"),
                    idempotency_key="ownership-orphan-0001",
                    idempotency_ttl_seconds=3600,
                )
    assert exc_info.value.code == "owner_principal_inactive"
    with session_factory() as session:
        assert session.get(CatalogObject, "orphan-child") is None
        assert session.get(Principal, ids["healthy_owner"]).active is True
        assert session.scalar(
            select(func.count(Relationship.id)).where(
                Relationship.to_ref == "service:orphan-child"
            )
        ) == 0


def test_owner_grant_write_failure_rolls_back_the_created_object(
    client: TestClient,
    ownerless_state,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_owner_grant(*_args, **_kwargs):
        raise RuntimeError("simulated owner grant failure")

    monkeypatch.setattr(commands_module, "assign_initial_owner", fail_owner_grant)
    with ownerless_state["session_factory"]() as session:
        parent_revision = _revision(session, "healthy-host")

    response = client.post(
        "/api/v1/objects/healthy-host/children",
        headers=_auth(
            ownerless_state["tokens"]["healthy_owner"],
            **{"Idempotency-Key": "ownership-fail-0001"},
        ),
        json=_asset("failed-child", kind="service").model_dump(mode="json"),
    )

    assert response.status_code == 500
    with ownerless_state["session_factory"]() as session:
        assert session.get(CatalogObject, "failed-child") is None
        assert _revision(session, "healthy-host") == parent_revision
        assert session.scalar(
            select(func.count(Relationship.id)).where(
                Relationship.to_ref == "service:failed-child"
            )
        ) == 0


def test_seed_rejects_a_missing_or_inactive_owner_before_any_write(
    alembic_session_factory,
) -> None:
    with alembic_session_factory() as session:
        with pytest.raises(InitialOwnerError) as missing:
            import_seed_file(session, SEED_PATH, owner_principal_id=None)
        assert missing.value.code == "owner_principal_required"

        inactive = create_service_account(
            session,
            login="seed.inactive",
            display_name="Seed Inactive",
        )
        deactivate_principal(session, principal_id=inactive.id)
        for principal_id in (inactive.id, str(uuid.uuid4())):
            with pytest.raises(InitialOwnerError) as rejected:
                import_seed_file(session, SEED_PATH, owner_principal_id=principal_id)
            assert rejected.value.code == "owner_principal_inactive"
        assert session.scalar(select(func.count(CatalogObject.id))) == 0


def test_seed_gives_every_created_object_exactly_one_direct_owner(
    alembic_session_factory,
) -> None:
    with alembic_session_factory() as session:
        with transaction(session):
            owner_id = create_service_account(
                session,
                login="seed.explicit.owner",
                display_name="Seed Explicit Owner",
            ).id
            result = import_seed_file(session, SEED_PATH, owner_principal_id=owner_id)

        object_ids = set(session.scalars(select(CatalogObject.id)).all())
        assert len(object_ids) == result.objects_imported
        grants = session.execute(
            select(ObjectGrant.object_id, ObjectGrant.principal_id, ObjectGrant.role)
        ).all()
        assert sorted(row.object_id for row in grants) == sorted(object_ids)
        assert {(row.principal_id, row.role) for row in grants} == {(owner_id, Role.OWNER)}
        assert ownerless_object_ids(session) == set()
        seed_audits = [
            load_audit_details(row)
            for row in session.scalars(
                select(AuditEvent).where(AuditEvent.action == "seed_create")
            )
        ]
        assert {audit["initial_owner_principal_id"] for audit in seed_audits} == {owner_id}

        # A re-run updates in place and never adds or re-guesses a grant.
        with transaction(session):
            import_seed_file(session, SEED_PATH, owner_principal_id=owner_id)
        assert session.scalar(select(func.count(ObjectGrant.id))) == len(object_ids)


def test_seed_owner_grant_failure_rolls_back_every_seeded_object(
    alembic_session_factory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_owner_grant(*_args, **_kwargs):
        raise RuntimeError("simulated owner grant failure")

    with alembic_session_factory() as session:
        with transaction(session):
            owner_id = create_service_account(
                session,
                login="seed.failing.owner",
                display_name="Seed Failing Owner",
            ).id
    monkeypatch.setattr(seeds_module, "assign_initial_owner", fail_owner_grant)
    with alembic_session_factory() as session:
        with pytest.raises(RuntimeError):
            with transaction(session):
                import_seed_file(session, SEED_PATH, owner_principal_id=owner_id)
        assert session.scalar(select(func.count(CatalogObject.id))) == 0
        assert session.scalar(select(func.count(AuditEvent.id))) == 0


def test_seed_cli_requires_an_explicit_active_owner(tmp_path: Path, capsys) -> None:
    url = f"sqlite:///{tmp_path / 'seed-owner.sqlite3'}"
    base = ["--database-url", url, "--seed", str(SEED_PATH), "--create-schema"]

    assert seed_cli.main(base) == 2
    assert "seed_error=owner_principal_required" in capsys.readouterr().err
    assert seed_cli.main([*base, "--owner-login", "nobody.here"]) == 2
    assert "seed_error=owner_principal_inactive" in capsys.readouterr().err

    engine = build_engine(url)
    try:
        with Session(engine) as session:
            assert session.scalar(select(func.count(CatalogObject.id))) == 0
    finally:
        engine.dispose()


def test_anchor_free_bootstrap_then_owner_seed_satisfies_the_startup_invariant(
    tmp_path: Path,
    capsys,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    url = f"sqlite:///{tmp_path / 'first-install.sqlite3'}"
    upgrade_database(url)
    bootstrap = [
        "--database-url",
        url,
        "bootstrap-owner",
        "--login",
        "kai.owner",
        "--display-name",
        "Kai Owner",
        "--password-stdin",
    ]

    def run_bootstrap(*extra: str) -> int:
        monkeypatch.setattr("sys.stdin", io.StringIO("first-install-owner-password\n"))
        return auth_cli.main([*bootstrap, *extra])

    # Without the catalog-owner choice an anchor-free bootstrap would leave
    # the identity with nothing to own.
    assert run_bootstrap() == 1
    capsys.readouterr()
    assert run_bootstrap("--catalog-owner") == 0
    assert "auth_bootstrap_owner_ok mode=created" in capsys.readouterr().out
    assert run_bootstrap("--catalog-owner") == 0
    assert "mode=unchanged" in capsys.readouterr().out

    assert seed_cli.main(
        ["--database-url", url, "--seed", str(SEED_PATH), "--owner-login", "kai.owner"]
    ) == 0
    capsys.readouterr()
    engine = build_engine(url)
    try:
        with Session(engine) as session:
            ensure_complete_owner_coverage(session)
            assert ownerless_object_ids(session) == set()
    finally:
        engine.dispose()
    assert database_cli.main(["--database-url", url, "owners"]) == 0
    assert "database_owners_ok" in capsys.readouterr().out

    # An anchor-free bootstrap never applies to a catalog that already exists.
    populated = f"sqlite:///{tmp_path / 'populated.sqlite3'}"
    upgrade_database(populated)
    engine = build_engine(populated)
    try:
        with Session(engine) as session:
            with transaction(session):
                upsert_object(session, _asset("existing-root"))
    finally:
        engine.dispose()
    monkeypatch.setattr("sys.stdin", io.StringIO("first-install-owner-password\n"))
    assert auth_cli.main([*bootstrap[:1], populated, *bootstrap[2:], "--catalog-owner"]) == 1


def test_markdown_import_requires_an_explicit_owner_and_owns_created_objects(
    tmp_path: Path,
    alembic_session_factory,
) -> None:
    tools_path = tmp_path / "TOOLS.md"
    tools_path.write_text(TOOLS_MARKDOWN, encoding="utf-8")

    with alembic_session_factory() as session:
        with pytest.raises(InitialOwnerError) as missing:
            import_tools_markdown(
                session,
                tools_path,
                owner_principal_id=None,
                references_root=tmp_path,
            )
        assert missing.value.code == "owner_principal_required"
        assert session.scalar(select(func.count(CatalogObject.id))) == 0

    with alembic_session_factory() as session:
        with transaction(session):
            owner_id = create_service_account(
                session,
                login="markdown.owner",
                display_name="Markdown Owner",
            ).id
            import_tools_markdown(
                session,
                tools_path,
                owner_principal_id=owner_id,
                references_root=tmp_path,
            )
        object_ids = set(session.scalars(select(CatalogObject.id)).all())
        assert object_ids
        for object_id in object_ids:
            assert [
                (grant.principal_id, grant.scope) for grant in _owner_grants(session, object_id)
            ] == [(owner_id, GrantScope.SELF)]
        assert ownerless_object_ids(session) == set()


def test_markdown_cli_apply_requires_an_owner_login(tmp_path: Path, capsys) -> None:
    tools_path = tmp_path / "TOOLS.md"
    tools_path.write_text(TOOLS_MARKDOWN, encoding="utf-8")
    url = f"sqlite:///{tmp_path / 'markdown-owner.sqlite3'}"

    exit_code = import_markdown_cli.main(
        [
            "--database-url",
            url,
            "--tools",
            str(tools_path),
            "--references-root",
            str(tmp_path),
            "--create-schema",
            "--apply",
        ]
    )

    assert exit_code == 2
    assert "markdown_import_error=owner_principal_required" in capsys.readouterr().err
    engine = build_engine(url)
    try:
        with Session(engine) as session:
            assert session.scalar(select(func.count(CatalogObject.id))) == 0
    finally:
        engine.dispose()


# --- UI and MCP parity ---------------------------------------------------------


def test_ui_shows_the_ownerless_state_and_adopts_with_csrf_and_etag(
    client: TestClient,
    ownerless_state,
) -> None:
    ids = ownerless_state["ids"]
    browser = ownerless_state["browsers"]["human"]
    client.cookies.set(AUTH_SESSION_COOKIE_NAME, browser.value)
    client.cookies.set(AUTH_CSRF_COOKIE_NAME, browser.csrf_token)

    page = client.get(f"/objects/{LEGACY_ID}?edit=permissions&principal_q=nova")
    assert page.status_code == 200, page.text
    assert 'data-owner-state="ownerless"' in page.text
    assert "This object has no active Owner." in page.text
    assert "data-owner-adoption" in page.text
    assert f"/objects/{LEGACY_ID}/permissions/adopt" in page.text
    assert "Nova Agent" in page.text

    def adopt(etag: str, csrf: str = browser.csrf_token):
        return client.post(
            f"/objects/{LEGACY_ID}/permissions/adopt",
            data={"csrf_token": csrf, "principal_id": ids["nova"], "if_match": etag},
            follow_redirects=False,
        )

    assert adopt('"rev-4"', csrf="wrong").status_code == 403
    stale = adopt('"rev-3"')
    assert stale.status_code == 412
    adopted = adopt('"rev-4"')
    assert adopted.status_code == 303, adopted.text

    with ownerless_state["session_factory"]() as session:
        assert [grant.principal_id for grant in _owner_grants(session, LEGACY_ID)] == [
            ids["nova"]
        ]
        audits = _adoption_audits(session, LEGACY_ID)
        assert [(audit["channel"], audit["actor_principal_id"]) for audit in audits] == [
            ("ui", ids["human"])
        ]

    owned = client.get(f"/objects/{LEGACY_ID}?edit=permissions")
    assert 'data-owner-state="owned"' in owned.text
    assert "Active Owner sources: 1 direct, 0 inherited." in owned.text
    assert "data-owner-adoption" not in owned.text


def test_ui_localizes_the_structured_owner_reasons(
    client: TestClient,
    ownerless_state,
) -> None:
    ids = ownerless_state["ids"]
    browser = ownerless_state["browsers"]["ui_manager"]
    client.cookies.set(AUTH_SESSION_COOKIE_NAME, browser.value)
    client.cookies.set(AUTH_CSRF_COOKIE_NAME, browser.csrf_token)
    with ownerless_state["session_factory"]() as session:
        etag = f'"rev-{_revision(session, "healthy-host")}"'

    page = client.get("/objects/healthy-host?edit=permissions")
    assert 'data-owner-state="owned"' in page.text
    assert "data-owner-adoption" not in page.text

    form = {
        "csrf_token": browser.csrf_token,
        "principal_id": ids["nova"],
        "role": "owner",
        "scope": "self",
        "if_match": etag,
    }
    english = client.post(
        "/objects/healthy-host/permissions/grants",
        data=form,
        follow_redirects=False,
    )
    german = client.post(
        "/objects/healthy-host/permissions/grants?lang=de",
        data=form,
        follow_redirects=False,
    )
    adoption = client.post(
        "/objects/healthy-host/permissions/adopt?lang=en",
        data={"csrf_token": browser.csrf_token, "principal_id": ids["nova"], "if_match": etag},
        follow_redirects=False,
    )

    assert english.status_code == german.status_code == adoption.status_code == 403
    assert (
        "Only an effective Owner of this object can add, change, or remove Owner grants."
        in english.text
    )
    assert (
        "Nur ein effektiver Owner dieses Objekts darf Owner-Freigaben hinzufügen, "
        "ändern oder entfernen."
    ) in german.text
    assert "Only an active catalog owner can adopt an ownerless object." in adoption.text
    with ownerless_state["session_factory"]() as session:
        assert f'"rev-{_revision(session, "healthy-host")}"' == etag


def test_mcp_exposes_the_same_adoption_semantics_and_reasons(
    client: TestClient,
    ownerless_state,
) -> None:
    tokens, ids = ownerless_state["tokens"], ownerless_state["ids"]

    def fetcher(path, params):
        response = client.get(
            path,
            params={key: value for key, value in params.items() if value is not None},
            headers=_auth(tokens["zoe_mcp"]),
        )
        assert response.status_code == 200, response.text
        return response.json()

    def requester(method, path, body, headers):
        response = client.request(
            method,
            path,
            json=body,
            headers={**headers, **_auth(tokens["zoe_mcp"])},
        )
        if response.status_code >= 400:
            error = response.json()["error"]
            raise UpstreamError(error["code"], error["message"])
        return response.json()

    def payload(result) -> dict:
        return json.loads(result["content"][0]["text"])

    tool = TOOL_DEFINITIONS["blockwart.adopt_ownerless_object"]
    assert tool["annotations"]["readOnlyHint"] is False
    assert tool["annotations"]["destructiveHint"] is False
    assert tool["inputSchema"]["required"] == ["object_id", "principal_id", "if_match"]

    access = payload(
        call_tool("blockwart.get_object_access", {"object_id": LEGACY_ID}, fetcher=fetcher)
    )
    assert access["owner_coverage"]["state"] == "ownerless"
    nova_grant = next(
        grant for grant in access["direct_grants"] if grant["principal"]["id"] == ids["nova"]
    )
    with pytest.raises(UpstreamError) as denied:
        call_tool(
            "blockwart.update_grant",
            {
                "object_id": LEGACY_ID,
                "grant_id": nova_grant["id"],
                "role": "owner",
                "scope": "self",
                "if_match": access["etag"],
            },
            requester=requester,
        )
    assert denied.value.code == "object_has_no_owner_use_adoption_flow"

    adopted = payload(
        call_tool(
            "blockwart.adopt_ownerless_object",
            {"object_id": LEGACY_ID, "principal_id": ids["nova"], "if_match": access["etag"]},
            requester=requester,
        )
    )
    assert adopted["previous_owner_count"] == 0
    assert adopted["grant"]["principal"]["id"] == ids["nova"]
    assert adopted["etag"] == '"rev-5"'

    with pytest.raises(UpstreamError) as refused:
        call_tool(
            "blockwart.adopt_ownerless_object",
            {"object_id": LEGACY_ID, "principal_id": ids["sunday"], "if_match": adopted["etag"]},
            requester=requester,
        )
    assert refused.value.code == "object_has_owner_coverage"

    verified = payload(
        call_tool("blockwart.get_object_access", {"object_id": LEGACY_ID}, fetcher=fetcher)
    )
    assert verified["owner_coverage"]["state"] == "owned"
    nova_effective = next(
        entry
        for entry in verified["effective_access"]
        if entry["principal"]["id"] == ids["nova"]
    )
    assert any(source["role"] == "owner" for source in nova_effective["sources"])
    with ownerless_state["session_factory"]() as session:
        assert [audit["channel"] for audit in _adoption_audits(session, LEGACY_ID)] == ["mcp"]


# --- PostgreSQL concurrency ----------------------------------------------------

PG_TEST_URL = os.environ.get(
    "BLOCKWART_TEST_PG_URL",
    "postgresql+psycopg2://postgres:test@127.0.0.1:5432/blockwart_test",
)


def _pg_url(database: str) -> str:
    return PG_TEST_URL.rsplit("/", 1)[0] + f"/{database}"


def _pg_available() -> bool:
    try:
        engine = create_engine(_pg_url("postgres"))
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
        engine.dispose()
    except Exception:  # noqa: BLE001 - any connection failure means "skip"
        return False
    return True


@pytest.mark.parametrize(
    "operation",
    ["adoption", "adoption_actor", "command_creation", "managed_grant_target"],
)
@pytest.mark.skipif(not _pg_available(), reason="PostgreSQL test database unreachable")
def test_postgresql_owner_assignment_rechecks_a_concurrently_deactivated_target(
    operation: str,
) -> None:
    name = f"bw_owner_target_{uuid.uuid4().hex[:12]}"
    admin = create_engine(_pg_url("postgres"), isolation_level="AUTOCOMMIT")
    with admin.connect() as connection:
        connection.execute(text(f'CREATE DATABASE "{name}"'))
    engine = None
    try:
        url = _pg_url(name)
        upgrade_database(url)
        engine = build_engine(url)
        factory = sessionmaker(bind=engine, autoflush=False, autocommit=False)
        with factory() as session:
            with transaction(session):
                actor_id = create_service_account(
                    session,
                    login=f"pg.{operation}.actor",
                    display_name="PG Catalog Owner",
                    catalog_role=CatalogRole.CATALOG_OWNER,
                ).id
                target_id = create_service_account(
                    session,
                    login=f"pg.{operation}.target",
                    display_name="PG Owner Target",
                    catalog_role=(
                        CatalogRole.CATALOG_OWNER
                        if operation == "command_creation"
                        else None
                    ),
                ).id
                if operation.startswith("adoption"):
                    upsert_object(session, _legacy_project())
                elif operation == "managed_grant_target":
                    upsert_object(session, _asset("managed-grant-race"))
                    create_object_grant(
                        session,
                        principal_id=actor_id,
                        object_id="managed-grant-race",
                        role=Role.OWNER,
                        scope=GrantScope.SELF,
                    )
                if operation == "adoption_actor":
                    create_service_account(
                        session,
                        login="pg.adoption.standby",
                        display_name="PG Standby Catalog Owner",
                        catalog_role=CatalogRole.CATALOG_OWNER,
                    )
                managed_revision = (
                    _revision(session, "managed-grant-race")
                    if operation == "managed_grant_target"
                    else None
                )
                managed_audits = (
                    session.scalar(
                        select(func.count(AuditEvent.id)).where(
                            AuditEvent.object_id == "managed-grant-race",
                            AuditEvent.action == "grant_create",
                        )
                    )
                    if operation == "managed_grant_target"
                    else None
                )

        deactivated_id = actor_id if operation == "adoption_actor" else target_id
        deactivation_holds_lock = threading.Event()
        operation_context_ready = threading.Event()

        def deactivate_target() -> str:
            with factory() as session:
                with transaction(session):
                    assert deactivate_principal(session, principal_id=deactivated_id)
                    deactivation_holds_lock.set()
                    assert operation_context_ready.wait(timeout=10)
            return "deactivated"

        def assign_owner() -> str:
            try:
                with factory() as session:
                    with transaction(session):
                        assert deactivation_holds_lock.wait(timeout=10)
                        context = _write_context(
                            session,
                            target_id if operation == "command_creation" else actor_id,
                        )
                        operation_context_ready.set()
                        if operation.startswith("adoption"):
                            adopt_ownerless_object(
                                session,
                                context,
                                object_id=LEGACY_ID,
                                principal_id=target_id,
                                expected_revision='"rev-1"',
                            )
                        elif operation == "managed_grant_target":
                            create_managed_grant(
                                session,
                                context,
                                object_id="managed-grant-race",
                                principal_id=target_id,
                                role=Role.VIEWER,
                                scope=GrantScope.SELF,
                                expected_revision=managed_revision,
                            )
                        else:
                            create_catalog_root(
                                session,
                                context,
                                payload=_asset("deactivation-race-root"),
                                idempotency_key="deactivation-race-root-01",
                                idempotency_ttl_seconds=3600,
                            )
            except (CommandAuthorizationDenied, CommandConflict) as exc:
                return exc.code or "conflict"
            return "unexpected_success"

        expected_error = {
            "adoption": "owner_principal_inactive",
            "adoption_actor": "adoption_requires_catalog_owner",
            "command_creation": "owner_principal_inactive",
            "managed_grant_target": "conflict",
        }[operation]
        with ThreadPoolExecutor(max_workers=2) as pool:
            deactivation = pool.submit(deactivate_target)
            assignment = pool.submit(assign_owner)
            assert deactivation.result(timeout=20) == "deactivated"
            assert assignment.result(timeout=20) == expected_error

        with factory() as session:
            deactivated = session.get(Principal, deactivated_id)
            assert deactivated is not None
            assert deactivated.active is False
            if operation.startswith("adoption"):
                assert _revision(session, LEGACY_ID) == 1
                assert _owner_grants(session, LEGACY_ID) == []
                assert _adoption_audits(session, LEGACY_ID) == []
            elif operation == "managed_grant_target":
                assert _revision(session, "managed-grant-race") == managed_revision
                assert session.scalar(
                    select(func.count(ObjectGrant.id)).where(
                        ObjectGrant.object_id == "managed-grant-race",
                        ObjectGrant.principal_id == target_id,
                    )
                ) == 0
                assert session.scalar(
                    select(func.count(AuditEvent.id)).where(
                        AuditEvent.object_id == "managed-grant-race",
                        AuditEvent.action == "grant_create",
                    )
                ) == managed_audits
            else:
                assert session.get(CatalogObject, "deactivation-race-root") is None
    finally:
        if engine is not None:
            engine.dispose()
        with admin.connect() as connection:
            connection.execute(
                text(
                    "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                    "WHERE datname = :name AND pid <> pg_backend_pid()"
                ),
                {"name": name},
            )
            connection.execute(text(f'DROP DATABASE IF EXISTS "{name}"'))
        admin.dispose()


@pytest.mark.skipif(not _pg_available(), reason="PostgreSQL test database unreachable")
def test_postgresql_adoption_then_deactivation_uses_one_principal_lock_order(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    name = f"bw_owner_order_{uuid.uuid4().hex[:12]}"
    admin = create_engine(_pg_url("postgres"), isolation_level="AUTOCOMMIT")
    with admin.connect() as connection:
        connection.execute(text(f'CREATE DATABASE "{name}"'))
    engine = None
    try:
        url = _pg_url(name)
        upgrade_database(url)
        engine = build_engine(url)
        factory = sessionmaker(bind=engine, autoflush=False, autocommit=False)
        with factory() as session:
            with transaction(session):
                actor_id = create_service_account(
                    session,
                    login="pg.lock.order.actor",
                    display_name="PG Lock Order Actor",
                    catalog_role=CatalogRole.CATALOG_OWNER,
                ).id
                target_id = create_service_account(
                    session,
                    login="pg.lock.order.target",
                    display_name="PG Lock Order Target",
                ).id
                upsert_object(session, _legacy_project())
                upsert_object(session, _asset("lock-order-owned"))
                create_object_grant(
                    session,
                    principal_id=actor_id,
                    object_id="lock-order-owned",
                    role=Role.OWNER,
                    scope=GrantScope.SELF,
                )

        target_locked = threading.Event()
        deactivation_lock_started = threading.Event()
        original_resolve = grant_management_module.resolve_owner_principal
        original_lock = identity_module.lock_owner_coverage_state

        def pause_after_target_lock(
            session: Session,
            principal_id: str,
        ) -> Principal:
            principal = original_resolve(session, principal_id)
            target_locked.set()
            assert deactivation_lock_started.wait(timeout=10)
            return principal

        def observe_deactivation_lock(
            session: Session,
            *,
            extra_principal_ids: Iterable[str] = (),
        ) -> None:
            deactivation_lock_started.set()
            original_lock(
                session,
                extra_principal_ids=extra_principal_ids,
            )

        monkeypatch.setattr(
            grant_management_module,
            "resolve_owner_principal",
            pause_after_target_lock,
        )
        monkeypatch.setattr(
            identity_module,
            "lock_owner_coverage_state",
            observe_deactivation_lock,
        )

        def adopt() -> str:
            with factory() as session:
                with transaction(session):
                    context = _write_context(session, actor_id)
                    adopt_ownerless_object(
                        session,
                        context,
                        object_id=LEGACY_ID,
                        principal_id=target_id,
                        expected_revision='"rev-1"',
                    )
            return "adopted"

        def deactivate_target() -> str:
            assert target_locked.wait(timeout=10)
            try:
                with factory() as session:
                    with transaction(session):
                        deactivate_principal(session, principal_id=target_id)
            except LastOwnerError:
                return "blocked"
            return "deactivated"

        with ThreadPoolExecutor(max_workers=2) as pool:
            adoption = pool.submit(adopt)
            deactivation = pool.submit(deactivate_target)
            assert adoption.result(timeout=20) == "adopted"
            assert deactivation.result(timeout=20) == "blocked"

        with factory() as session:
            target = session.get(Principal, target_id)
            assert target is not None
            assert target.active is True
            assert [grant.principal_id for grant in _owner_grants(session, LEGACY_ID)] == [
                target_id
            ]
            assert len(_adoption_audits(session, LEGACY_ID)) == 1
    finally:
        if engine is not None:
            engine.dispose()
        with admin.connect() as connection:
            connection.execute(
                text(
                    "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                    "WHERE datname = :name AND pid <> pg_backend_pid()"
                ),
                {"name": name},
            )
            connection.execute(text(f'DROP DATABASE IF EXISTS "{name}"'))
        admin.dispose()


@pytest.mark.skipif(not _pg_available(), reason="PostgreSQL test database unreachable")
def test_postgresql_markdown_import_and_deactivation_share_principal_lock_order(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    name = f"bw_import_order_{uuid.uuid4().hex[:12]}"
    admin = create_engine(_pg_url("postgres"), isolation_level="AUTOCOMMIT")
    with admin.connect() as connection:
        connection.execute(text(f'CREATE DATABASE "{name}"'))
    engine = None
    try:
        url = _pg_url(name)
        upgrade_database(url)
        engine = build_engine(url)
        factory = sessionmaker(bind=engine, autoflush=False, autocommit=False)
        catalog_owner_id = "00000000-0000-0000-0000-000000000001"
        import_owner_id = "ffffffff-ffff-ffff-ffff-ffffffffffff"
        with factory() as session:
            with transaction(session):
                session.add_all(
                    [
                        Principal(
                            id=catalog_owner_id,
                            principal_type="service_account",
                            login="pg.import.catalog.owner",
                            display_name="PG Import Catalog Owner",
                            active=True,
                            catalog_role=CatalogRole.CATALOG_OWNER,
                        ),
                        Principal(
                            id=import_owner_id,
                            principal_type="service_account",
                            login="pg.import.object.owner",
                            display_name="PG Import Object Owner",
                            active=True,
                        ),
                    ]
                )

        tools_path = tmp_path / "TOOLS.md"
        tools_path.write_text(TOOLS_MARKDOWN, encoding="utf-8")
        owner_locked = threading.Event()
        deactivation_lock_started = threading.Event()
        original_resolve = markdown_import_module.resolve_owner_principal
        original_lock = identity_module.lock_owner_coverage_state

        def pause_after_import_locks(
            session: Session,
            principal_id: str | None,
            *,
            include_owner_coverage_locks: bool = False,
        ) -> Principal:
            principal = original_resolve(
                session,
                principal_id,
                include_owner_coverage_locks=include_owner_coverage_locks,
            )
            owner_locked.set()
            assert deactivation_lock_started.wait(timeout=10)
            return principal

        def observe_deactivation_lock(
            session: Session,
            *,
            extra_principal_ids: Iterable[str] = (),
        ) -> None:
            deactivation_lock_started.set()
            original_lock(
                session,
                extra_principal_ids=extra_principal_ids,
            )

        monkeypatch.setattr(
            markdown_import_module,
            "resolve_owner_principal",
            pause_after_import_locks,
        )
        monkeypatch.setattr(
            identity_module,
            "lock_owner_coverage_state",
            observe_deactivation_lock,
        )

        def run_import() -> str:
            with factory() as session:
                with transaction(session):
                    import_tools_markdown(
                        session,
                        tools_path,
                        owner_principal_id=import_owner_id,
                    )
            return "imported"

        def deactivate_target() -> str:
            assert owner_locked.wait(timeout=10)
            try:
                with factory() as session:
                    with transaction(session):
                        deactivate_principal(
                            session,
                            principal_id=import_owner_id,
                        )
            except LastOwnerError:
                return "blocked"
            return "deactivated"

        with ThreadPoolExecutor(max_workers=2) as pool:
            imported = pool.submit(run_import)
            deactivated = pool.submit(deactivate_target)
            assert imported.result(timeout=20) == "imported"
            assert deactivated.result(timeout=20) == "blocked"

        with factory() as session:
            owner = session.get(Principal, import_owner_id)
            assert owner is not None
            assert owner.active is True
            imported_objects = session.scalars(select(CatalogObject)).all()
            assert len(imported_objects) == 1
            assert [
                grant.principal_id
                for grant in _owner_grants(session, imported_objects[0].id)
            ] == [import_owner_id]
    finally:
        if engine is not None:
            engine.dispose()
        with admin.connect() as connection:
            connection.execute(
                text(
                    "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                    "WHERE datname = :name AND pid <> pg_backend_pid()"
                ),
                {"name": name},
            )
            connection.execute(text(f'DROP DATABASE IF EXISTS "{name}"'))
        admin.dispose()


@pytest.mark.skipif(not _pg_available(), reason="PostgreSQL test database unreachable")
def test_postgresql_owner_scope_update_and_deactivation_share_coverage_lock_order(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    name = f"bw_scope_order_{uuid.uuid4().hex[:12]}"
    admin = create_engine(_pg_url("postgres"), isolation_level="AUTOCOMMIT")
    with admin.connect() as connection:
        connection.execute(text(f'CREATE DATABASE "{name}"'))
    engine = None
    try:
        url = _pg_url(name)
        upgrade_database(url)
        engine = build_engine(url)
        factory = sessionmaker(bind=engine, autoflush=False, autocommit=False)
        actor_id = "00000000-0000-0000-0000-000000000001"
        target_id = "ffffffff-ffff-ffff-ffff-ffffffffffff"
        with factory() as session:
            with transaction(session):
                session.add_all(
                    [
                        Principal(
                            id=actor_id,
                            principal_type="service_account",
                            login="pg.scope.actor",
                            display_name="PG Scope Actor",
                            active=True,
                            catalog_role=CatalogRole.CATALOG_OWNER,
                        ),
                        Principal(
                            id=target_id,
                            principal_type="service_account",
                            login="pg.scope.target",
                            display_name="PG Scope Target",
                            active=True,
                        ),
                    ]
                )
                upsert_object(session, _asset("scope-order-root"))
                create_object_grant(
                    session,
                    principal_id=actor_id,
                    object_id="scope-order-root",
                    role=Role.OWNER,
                    scope=GrantScope.SELF,
                )
                target_grant = create_object_grant(
                    session,
                    principal_id=target_id,
                    object_id="scope-order-root",
                    role=Role.OWNER,
                    scope=GrantScope.SELF,
                )
                expected_revision = _revision(session, "scope-order-root")
                target_grant_id = target_grant.id

        grant_updated = threading.Event()
        deactivation_lock_started = threading.Event()
        original_coverage_check = (
            grant_management_module.ensure_owner_coverage_preserved
        )
        original_deactivation_lock = identity_module.lock_owner_coverage_state

        def pause_after_grant_update(
            session: Session,
            *,
            previously_covered_ids: Iterable[str],
        ) -> None:
            grant_updated.set()
            assert deactivation_lock_started.wait(timeout=10)
            original_coverage_check(
                session,
                previously_covered_ids=previously_covered_ids,
            )

        def observe_deactivation_lock(
            session: Session,
            *,
            extra_principal_ids: Iterable[str] = (),
        ) -> None:
            deactivation_lock_started.set()
            original_deactivation_lock(
                session,
                extra_principal_ids=extra_principal_ids,
            )

        monkeypatch.setattr(
            grant_management_module,
            "ensure_owner_coverage_preserved",
            pause_after_grant_update,
        )
        monkeypatch.setattr(
            identity_module,
            "lock_owner_coverage_state",
            observe_deactivation_lock,
        )

        def update_scope() -> str:
            with factory() as session:
                with transaction(session):
                    result = update_managed_grant(
                        session,
                        _write_context(session, actor_id),
                        object_id="scope-order-root",
                        grant_id=target_grant_id,
                        role=Role.OWNER,
                        scope=GrantScope.SUBTREE,
                        expected_revision=expected_revision,
                    )
                    assert result.changed
            return "updated"

        def deactivate_target() -> str:
            assert grant_updated.wait(timeout=10)
            with factory() as session:
                with transaction(session):
                    assert deactivate_principal(session, principal_id=target_id)
            return "deactivated"

        with ThreadPoolExecutor(max_workers=2) as pool:
            updated = pool.submit(update_scope)
            deactivated = pool.submit(deactivate_target)
            assert updated.result(timeout=20) == "updated"
            assert deactivated.result(timeout=20) == "deactivated"

        with factory() as session:
            target = session.get(Principal, target_id)
            grant = session.get(ObjectGrant, target_grant_id)
            assert target is not None
            assert target.active is False
            assert grant is not None
            assert grant.scope == GrantScope.SUBTREE
            assert _revision(session, "scope-order-root") == expected_revision + 1
            assert session.scalar(
                select(func.count(AuditEvent.id)).where(
                    AuditEvent.object_id == "scope-order-root",
                    AuditEvent.action == "grant_update",
                )
            ) == 1
    finally:
        if engine is not None:
            engine.dispose()
        with admin.connect() as connection:
            connection.execute(
                text(
                    "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                    "WHERE datname = :name AND pid <> pg_backend_pid()"
                ),
                {"name": name},
            )
            connection.execute(text(f'DROP DATABASE IF EXISTS "{name}"'))
        admin.dispose()


@pytest.mark.skipif(not _pg_available(), reason="PostgreSQL test database unreachable")
def test_postgresql_placement_delete_and_owner_update_share_coverage_lock_order(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    name = f"bw_placement_order_{uuid.uuid4().hex[:12]}"
    admin = create_engine(_pg_url("postgres"), isolation_level="AUTOCOMMIT")
    with admin.connect() as connection:
        connection.execute(text(f'CREATE DATABASE "{name}"'))
    engine = None
    try:
        url = _pg_url(name)
        upgrade_database(url)
        engine = build_engine(url)
        factory = sessionmaker(bind=engine, autoflush=False, autocommit=False)
        actor_id = "00000000-0000-0000-0000-000000000001"
        target_id = "ffffffff-ffff-ffff-ffff-ffffffffffff"
        with factory() as session:
            with transaction(session):
                session.add_all(
                    [
                        Principal(
                            id=actor_id,
                            principal_type="service_account",
                            login="pg.placement.actor",
                            display_name="PG Placement Actor",
                            active=True,
                        ),
                        Principal(
                            id=target_id,
                            principal_type="service_account",
                            login="pg.placement.target",
                            display_name="PG Placement Target",
                            active=True,
                        ),
                    ]
                )
                upsert_object(session, _asset("placement-order-parent"))
                upsert_object(
                    session,
                    _asset("placement-order-child", kind="service"),
                )
                create_relationship(
                    session,
                    from_ref="host:placement-order-parent",
                    relation_type="hosts",
                    to_ref="service:placement-order-child",
                )
                create_object_grant(
                    session,
                    principal_id=actor_id,
                    object_id="placement-order-parent",
                    role=Role.VIEWER,
                    scope=GrantScope.SELF,
                )
                create_object_grant(
                    session,
                    principal_id=actor_id,
                    object_id="placement-order-child",
                    role=Role.OWNER,
                    scope=GrantScope.SELF,
                )
                target_grant = create_object_grant(
                    session,
                    principal_id=target_id,
                    object_id="placement-order-child",
                    role=Role.OWNER,
                    scope=GrantScope.SELF,
                )
                expected_revision = _revision(session, "placement-order-child")
                target_grant_id = target_grant.id

        delete_coverage_locked = threading.Event()
        grant_update_started = threading.Event()
        original_lock = commands_module.lock_owner_coverage_state

        def pause_after_delete_coverage_lock(
            session: Session,
            *,
            extra_principal_ids: Iterable[str] = (),
        ) -> None:
            original_lock(
                session,
                extra_principal_ids=extra_principal_ids,
            )
            delete_coverage_locked.set()
            assert grant_update_started.wait(timeout=10)

        monkeypatch.setattr(
            commands_module,
            "lock_owner_coverage_state",
            pause_after_delete_coverage_lock,
        )

        def delete_placement() -> str:
            with factory() as session:
                with transaction(session):
                    result = commands_module.delete_object_relationship(
                        session,
                        _write_context(session, actor_id),
                        object_id="placement-order-child",
                        from_ref="host:placement-order-parent",
                        relation_type="hosts",
                        to_ref="service:placement-order-child",
                        expected_revision=expected_revision,
                    )
                    assert result.changed
            return "deleted"

        def update_owner_scope() -> str:
            assert delete_coverage_locked.wait(timeout=10)
            try:
                with factory() as session:
                    with transaction(session):
                        context = _write_context(session, actor_id)
                        grant_update_started.set()
                        update_managed_grant(
                            session,
                            context,
                            object_id="placement-order-child",
                            grant_id=target_grant_id,
                            role=Role.OWNER,
                            scope=GrantScope.SUBTREE,
                            expected_revision=expected_revision,
                        )
            except CommandPreconditionFailed:
                return "stale"
            return "updated"

        with ThreadPoolExecutor(max_workers=2) as pool:
            deleted = pool.submit(delete_placement)
            updated = pool.submit(update_owner_scope)
            assert deleted.result(timeout=20) == "deleted"
            assert updated.result(timeout=20) == "stale"

        with factory() as session:
            assert session.scalar(
                select(func.count(Relationship.id)).where(
                    Relationship.from_ref == "host:placement-order-parent",
                    Relationship.relation_type == "hosts",
                    Relationship.to_ref == "service:placement-order-child",
                )
            ) == 0
            grant = session.get(ObjectGrant, target_grant_id)
            assert grant is not None
            assert grant.scope == GrantScope.SELF
            assert _revision(session, "placement-order-child") == expected_revision + 1
            assert session.scalar(
                select(func.count(AuditEvent.id)).where(
                    AuditEvent.object_id == "placement-order-child",
                    AuditEvent.action == "relationship_delete",
                )
            ) == 1
            assert session.scalar(
                select(func.count(AuditEvent.id)).where(
                    AuditEvent.object_id == "placement-order-child",
                    AuditEvent.action == "grant_update",
                )
            ) == 0
    finally:
        if engine is not None:
            engine.dispose()
        with admin.connect() as connection:
            connection.execute(
                text(
                    "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                    "WHERE datname = :name AND pid <> pg_backend_pid()"
                ),
                {"name": name},
            )
            connection.execute(text(f'DROP DATABASE IF EXISTS "{name}"'))
        admin.dispose()


@pytest.mark.skipif(not _pg_available(), reason="PostgreSQL test database unreachable")
def test_postgresql_concurrent_adoptions_have_exactly_one_winner() -> None:
    name = f"bw_ownerless_{uuid.uuid4().hex[:12]}"
    admin = create_engine(_pg_url("postgres"), isolation_level="AUTOCOMMIT")
    with admin.connect() as connection:
        connection.execute(text(f'CREATE DATABASE "{name}"'))
    engine = None
    try:
        url = _pg_url(name)
        upgrade_database(url)
        engine = build_engine(url)
        factory = sessionmaker(bind=engine, autoflush=False, autocommit=False)
        with factory() as session:
            with transaction(session):
                zoe_id = create_service_account(
                    session,
                    login="pg.catalog.owner",
                    display_name="PG Catalog Owner",
                    catalog_role=CatalogRole.CATALOG_OWNER,
                ).id
                targets = [
                    create_service_account(
                        session,
                        login=f"pg.target.{index}",
                        display_name=f"PG Target {index}",
                    ).id
                    for index in range(2)
                ]
                upsert_object(session, _legacy_project())

        barrier = threading.Barrier(2)

        def attempt(target_id: str) -> str:
            with factory() as session:
                try:
                    with transaction(session):
                        context = _write_context(session, zoe_id)
                        barrier.wait(timeout=10)
                        adopt_ownerless_object(
                            session,
                            context,
                            object_id=LEGACY_ID,
                            principal_id=target_id,
                            expected_revision='"rev-1"',
                        )
                except CommandPreconditionFailed:
                    return "precondition_failed"
            return "adopted"

        with ThreadPoolExecutor(max_workers=2) as pool:
            outcomes = sorted(pool.map(attempt, targets))

        assert outcomes == ["adopted", "precondition_failed"]
        with factory() as session:
            assert len(_owner_grants(session, LEGACY_ID)) == 1
            assert _revision(session, LEGACY_ID) == 2
            assert len(_adoption_audits(session, LEGACY_ID)) == 1
    finally:
        if engine is not None:
            engine.dispose()
        with admin.connect() as connection:
            connection.execute(
                text(
                    "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                    "WHERE datname = :name AND pid <> pg_backend_pid()"
                ),
                {"name": name},
            )
            connection.execute(text(f'DROP DATABASE IF EXISTS "{name}"'))
        admin.dispose()
