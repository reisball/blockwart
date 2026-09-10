"""Contract coverage for the delegable root-project-creation authority (#237).

The narrow global catalog role ``project_creator`` exists so an agent can open
its own top-level Projects without ``catalog_owner``, which would additionally
hand out catalog-wide write, delete, and access-management authority. These
tests pin all four parts of that bargain:

* the positive path — a project creator creates a valid root Project through
  API, MCP, and the browser UI, and atomically receives ``owner/self`` on it;
* the negative path — the same principal creates no other root kind, and a
  principal without the role creates no root Project at all;
* the absence of escalation — the role adds no catalog-wide read, write,
  rename, delete, create-child, access-management, identity-administration, or
  reviewed-Knowledge-apply authority anywhere; and
* lifecycle — the role is assigned and revoked independently of
  ``catalog_owner``, whose own behavior is unchanged.
"""

from __future__ import annotations

import json
from collections.abc import Generator
from dataclasses import replace

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from blockwart.api.deps import get_session
from blockwart.db.session import transaction
from blockwart.domain.auth import (
    CatalogRole,
    GrantScope,
    Permission,
    PlatformRole,
    Role,
)
from blockwart.main import create_app
from blockwart.mcp.server import UpstreamError, call_tool
from blockwart.models import (
    AuditEvent,
    CatalogObject,
    ObjectGrant,
    Principal,
    Relationship,
    SecurityEvent,
)
from blockwart.schemas.catalog import OBJECT_KINDS, CatalogObjectIn
from blockwart.services.access import create_object_grant
from blockwart.services.catalog import upsert_object
from blockwart.services.commands import (
    CommandAuthorizationDenied,
    WriteContext,
    create_catalog_root,
)
from blockwart.services.identity import (
    create_human_principal,
    create_service_account,
    issue_browser_session,
    issue_service_token,
    principal_context,
)
from blockwart.services.knowledge_apply import (
    ApplyContract,
    ApplyTarget,
    KnowledgeApplyError,
    _require_authorization,
)
from blockwart.services.policy import GlobalPolicySource, policy_for_principal
from blockwart.services.principal_management import set_managed_catalog_role
from blockwart.services.read_access import read_access_for_principal
from blockwart.ui.security import AUTH_CSRF_COOKIE_NAME, AUTH_SESSION_COOKIE_NAME

PASSWORD = "root-project-creator-password"
PROJECT_DATA = {
    "schema_version": 1,
    "category": "implementation",
    "project_status": "planned",
}
# One minimal valid payload per non-project root kind, so a denial is proven to
# come from authorization rather than from schema validation.
DENIED_ROOT_KIND_DATA = {
    "host": {"schema_version": 1},
    "system": {"schema_version": 1},
    "network": {"schema_version": 1, "network": {"category": "access_point"}},
    "device": {"schema_version": 1, "device": {"category": "adapter"}},
    "service": {"schema_version": 1},
    "credential_reference": {"schema_version": 1},
    "runbook": {
        "schema_version": 1,
        "runbook_status": "draft",
        "approval_required": False,
    },
    "decision": {"schema_version": 1, "decision_status": "proposed"},
}


def test_denied_root_kind_data_covers_every_non_project_kind() -> None:
    assert set(DENIED_ROOT_KIND_DATA) | {"project"} == set(OBJECT_KINDS)


def _project(object_id: str, *, label: str | None = None) -> CatalogObjectIn:
    return CatalogObjectIn(
        id=object_id,
        kind="project",
        label=label or object_id,
        data=dict(PROJECT_DATA),
    )


def _root_of_kind(object_id: str, kind: str) -> CatalogObjectIn:
    return CatalogObjectIn(
        id=object_id,
        kind=kind,
        label=object_id,
        data=dict(DENIED_ROOT_KIND_DATA[kind]),
    )


@pytest.fixture
def creator_state(alembic_session_factory):
    with alembic_session_factory() as session:
        with transaction(session):
            upsert_object(
                session,
                CatalogObjectIn(
                    id="existing-host",
                    kind="host",
                    label="Existing Host",
                    lifecycle="active",
                    health="healthy",
                    data={"schema_version": 1},
                ),
            )
            upsert_object(
                session,
                CatalogObjectIn(
                    id="existing-project",
                    kind="project",
                    label="Existing Project",
                    data=dict(PROJECT_DATA),
                ),
            )
            creator = create_service_account(
                session,
                login="dagobert.agent",
                display_name="Dagobert Agent",
                catalog_role=CatalogRole.PROJECT_CREATOR,
            )
            creator_token = issue_service_token(
                session,
                principal_id=creator.id,
                name="api-writes",
            )
            creator_mcp_token = issue_service_token(
                session,
                principal_id=creator.id,
                name="mcp-writes",
                audience="mcp",
            )
            owner = create_service_account(
                session,
                login="catalog.owner",
                display_name="Catalog Owner",
                catalog_role=CatalogRole.CATALOG_OWNER,
            )
            owner_token = issue_service_token(
                session,
                principal_id=owner.id,
                name="api-writes",
            )
            viewer = create_service_account(
                session,
                login="catalog.viewer",
                display_name="Catalog Viewer",
                catalog_role=CatalogRole.CATALOG_VIEWER,
            )
            viewer_token = issue_service_token(
                session,
                principal_id=viewer.id,
                name="api-writes",
            )
            plain = create_service_account(
                session,
                login="plain.agent",
                display_name="Plain Agent",
            )
            create_object_grant(
                session,
                principal_id=plain.id,
                object_id="existing-host",
                role=Role.OWNER,
                scope=GrantScope.SELF,
            )
            plain_token = issue_service_token(
                session,
                principal_id=plain.id,
                name="api-writes",
            )
            human_creator = create_human_principal(
                session,
                login="human.creator",
                display_name="Human Creator",
                password=PASSWORD,
                catalog_role=CatalogRole.PROJECT_CREATOR,
            )
            creator_session = issue_browser_session(
                session,
                principal_id=human_creator.id,
                ttl_seconds=3600,
            )
    return {
        "session_factory": alembic_session_factory,
        "creator_id": creator.id,
        "creator_token": creator_token.value,
        "creator_mcp_token": creator_mcp_token.value,
        "owner_id": owner.id,
        "owner_token": owner_token.value,
        "viewer_id": viewer.id,
        "viewer_token": viewer_token.value,
        "plain_id": plain.id,
        "plain_token": plain_token.value,
        "human_creator_id": human_creator.id,
        "creator_session": creator_session,
    }


@pytest.fixture
def creator_client(creator_state) -> Generator[TestClient, None, None]:
    session_factory = creator_state["session_factory"]
    app = create_app()

    def override_get_session() -> Generator[Session, None, None]:
        with session_factory() as session:
            yield session

    app.dependency_overrides[get_session] = override_get_session
    with TestClient(app, base_url="https://testserver") as client:
        yield client


def _authorization(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _login(client: TestClient, issued) -> None:
    client.cookies.set(AUTH_SESSION_COOKIE_NAME, issued.value)
    client.cookies.set(AUTH_CSRF_COOKIE_NAME, issued.csrf_token)


def _context(
    session: Session,
    principal_id: str,
    *,
    channel: str = "api",
    audience: str | None = "api",
) -> WriteContext:
    row = session.get(Principal, principal_id)
    assert row is not None
    access = read_access_for_principal(session, principal_context(row))
    return WriteContext(
        principal=replace(access.principal, service_token_audience=audience),
        policy=access.policy,
        channel=channel,
        request_id="creator-test-request",
    )


def _grants_for(session: Session, object_id: str) -> list[ObjectGrant]:
    return list(
        session.scalars(
            select(ObjectGrant).where(ObjectGrant.object_id == object_id)
        )
    )


def _root_facts(session: Session, object_id: str, principal_id: str) -> None:
    """The creator-ownership invariant: exactly one real Owner/self grant."""
    grants = _grants_for(session, object_id)
    assert len(grants) == 1
    grant = grants[0]
    assert grant.principal_id == principal_id
    assert grant.created_by_principal_id == principal_id
    assert grant.role == Role.OWNER
    assert grant.scope == GrantScope.SELF
    assert session.scalar(
        select(func.count())
        .select_from(Relationship)
        .where(
            (Relationship.from_ref.contains(f":{object_id}"))
            | (Relationship.to_ref.contains(f":{object_id}"))
        )
    ) == 0


def _create_root_events(session: Session, object_id: str) -> list[AuditEvent]:
    return list(
        session.scalars(
            select(AuditEvent).where(
                AuditEvent.object_id == object_id,
                AuditEvent.action == "create_root",
            )
        )
    )


# ---------------------------------------------------------------------------
# Service layer: the authority itself
# ---------------------------------------------------------------------------


def test_service_project_creator_creates_root_project_with_owner_self(
    creator_state,
) -> None:
    session_factory = creator_state["session_factory"]
    with session_factory() as session:
        context = _context(session, creator_state["creator_id"])
        with transaction(session):
            result = create_catalog_root(
                session,
                context,
                payload=_project("service-project", label="Service Project"),
                idempotency_key="service-project-key-01",
                idempotency_ttl_seconds=86400,
            )

    assert result.changed is True
    assert result.replayed is False
    assert result.etag == '"rev-1"'
    assert result.catalog_object.kind == "project"
    assert result.catalog_object.parent_path == []
    assert result.catalog_object.capabilities == [
        "create_child",
        "delete",
        "discover",
        "manage_access",
        "read",
        "rename",
        "write",
    ]
    with session_factory() as session:
        _root_facts(session, "service-project", creator_state["creator_id"])
        events = _create_root_events(session, "service-project")
        assert len(events) == 1
        details = events[0].details_json
        assert events[0].actor == creator_state["creator_id"]
        # The audit trail names the delegated authority, not just the actor.
        assert '"catalog_authority":"project_creator"' in details
        assert '"parent_ref":null' in details
        assert '"role":"owner"' in details
        assert '"scope":"self"' in details


def test_service_catalog_owner_root_creation_is_unchanged(creator_state) -> None:
    session_factory = creator_state["session_factory"]
    for index, kind in enumerate(OBJECT_KINDS):
        payload = (
            _project(f"owner-root-{kind}")
            if kind == "project"
            else _root_of_kind(f"owner-root-{kind}", kind)
        )
        with session_factory() as session:
            context = _context(session, creator_state["owner_id"])
            with transaction(session):
                result = create_catalog_root(
                    session,
                    context,
                    payload=payload,
                    idempotency_key=f"owner-root-key-{index:04d}",
                    idempotency_ttl_seconds=86400,
                )
        assert result.changed is True
        with session_factory() as session:
            _root_facts(session, f"owner-root-{kind}", creator_state["owner_id"])
            events = _create_root_events(session, f"owner-root-{kind}")
            assert len(events) == 1
            assert '"catalog_authority":"catalog_owner"' in events[0].details_json


@pytest.mark.parametrize("kind", sorted(DENIED_ROOT_KIND_DATA))
def test_service_project_creator_cannot_create_any_other_root_kind(
    creator_state,
    kind: str,
) -> None:
    session_factory = creator_state["session_factory"]
    with session_factory() as session:
        context = _context(session, creator_state["creator_id"])
        with (
            transaction(session),
            pytest.raises(CommandAuthorizationDenied) as denial,
        ):
            create_catalog_root(
                session,
                context,
                payload=_root_of_kind(f"denied-{kind}", kind),
                idempotency_key=f"denied-{kind}-key-0001",
                idempotency_ttl_seconds=86400,
            )

    # The same indistinguishable denial as holding no catalog role at all.
    assert denial.value.object_id == "<catalog-root>"
    assert denial.value.permission == Permission.CREATE_CHILD
    with session_factory() as session:
        assert session.get(CatalogObject, f"denied-{kind}") is None
        assert _grants_for(session, f"denied-{kind}") == []


@pytest.mark.parametrize("principal_key", ["viewer_id", "plain_id"])
def test_service_root_project_stays_denied_without_the_authority(
    creator_state,
    principal_key: str,
) -> None:
    session_factory = creator_state["session_factory"]
    with session_factory() as session:
        context = _context(session, creator_state[principal_key])
        with (
            transaction(session),
            pytest.raises(CommandAuthorizationDenied),
        ):
            create_catalog_root(
                session,
                context,
                payload=_project(f"unauthorized-{principal_key}"),
                idempotency_key=f"unauthorized-{principal_key}-key",
                idempotency_ttl_seconds=86400,
            )
    with session_factory() as session:
        assert session.get(CatalogObject, f"unauthorized-{principal_key}") is None


def test_service_inactive_project_creator_is_denied(creator_state) -> None:
    session_factory = creator_state["session_factory"]
    with session_factory() as session:
        context = _context(session, creator_state["creator_id"])
        with transaction(session):
            row = session.get(Principal, creator_state["creator_id"])
            assert row is not None
            row.active = False
        with (
            transaction(session),
            pytest.raises(CommandAuthorizationDenied),
        ):
            create_catalog_root(
                session,
                context,
                payload=_project("inactive-creator-project"),
                idempotency_key="inactive-creator-key-01",
                idempotency_ttl_seconds=86400,
            )
    with session_factory() as session:
        assert session.get(CatalogObject, "inactive-creator-project") is None


@pytest.mark.parametrize(
    ("channel", "audience"),
    [("api", "mcp"), ("mcp", "api"), ("api", None), ("ui", "api")],
)
def test_service_project_creator_still_requires_a_matching_channel(
    creator_state,
    channel: str,
    audience: str | None,
) -> None:
    session_factory = creator_state["session_factory"]
    with session_factory() as session:
        context = _context(
            session,
            creator_state["creator_id"],
            channel=channel,
            audience=audience,
        )
        with (
            transaction(session),
            pytest.raises(CommandAuthorizationDenied),
        ):
            create_catalog_root(
                session,
                context,
                payload=_project("mismatched-channel-project"),
                idempotency_key=f"channel-{channel}-{audience}-key",
                idempotency_ttl_seconds=86400,
            )
    with session_factory() as session:
        assert session.get(CatalogObject, "mismatched-channel-project") is None


# ---------------------------------------------------------------------------
# Policy projection
# ---------------------------------------------------------------------------


def test_project_creator_policy_carries_authority_without_object_permissions(
    creator_state,
) -> None:
    session_factory = creator_state["session_factory"]
    with session_factory() as session:
        row = session.get(Principal, creator_state["creator_id"])
        assert row is not None
        creator = principal_context(row)
        policy = policy_for_principal(session, creator_state["creator_id"])
        owner_policy = policy_for_principal(session, creator_state["owner_id"])

    assert creator.is_project_creator
    assert not creator.is_catalog_owner
    assert not creator.is_catalog_viewer
    assert creator.may_create_root_kind("project")
    assert not any(creator.may_create_root_kind(kind) for kind in DENIED_ROOT_KIND_DATA)

    assert policy.has_global_authority(GlobalPolicySource.PROJECT_CREATOR)
    assert policy.creatable_root_kinds() == {"project"}
    assert not policy.has_global_authority(GlobalPolicySource.CATALOG_OWNER)
    assert not policy.has_global_authority(GlobalPolicySource.CATALOG_VIEWER)
    assert [authority.permissions for authority in policy.global_authorities] == [
        frozenset()
    ]
    # No object gains an entry, not even an empty one, from this role.
    for object_id in ("existing-host", "existing-project"):
        assert policy.permissions_for(object_id) == frozenset()
        assert policy.visibility_for(object_id) == "none"
        assert policy.grants_for(object_id) == ()
    for permission in Permission:
        assert policy.authorized_ids(permission) == frozenset()

    assert owner_policy.creatable_root_kinds() == set(OBJECT_KINDS)


def test_assigning_or_revoking_the_role_changes_the_policy_fingerprint(
    creator_state,
) -> None:
    session_factory = creator_state["session_factory"]
    with session_factory() as session:
        with_role = policy_for_principal(session, creator_state["creator_id"]).fingerprint()
        with transaction(session):
            row = session.get(Principal, creator_state["creator_id"])
            assert row is not None
            row.catalog_role = None
        without_role = policy_for_principal(
            session, creator_state["creator_id"]
        ).fingerprint()

    assert with_role != without_role


# ---------------------------------------------------------------------------
# REST v1
# ---------------------------------------------------------------------------


def test_rest_project_creator_creates_root_project(
    creator_client: TestClient,
    creator_state,
) -> None:
    response = creator_client.post(
        "/api/v1/roots",
        headers={
            **_authorization(creator_state["creator_token"]),
            "Idempotency-Key": "rest-project-key-00001",
            "X-Correlation-ID": "creator-correlation-01",
        },
        json=_project("rest-project", label="REST Project").model_dump(mode="json"),
    )

    assert response.status_code == 201
    assert response.headers["etag"] == '"rev-1"'
    assert response.headers["location"] == "/api/v1/objects/rest-project"
    body = response.json()
    assert body["changed"] is True
    assert body["replayed"] is False
    assert body["catalog_object"]["kind"] == "project"
    assert body["catalog_object"]["parent_path"] == []

    reread = creator_client.get(
        response.headers["location"],
        headers=_authorization(creator_state["creator_token"]),
    )
    assert reread.status_code == 200
    assert reread.headers["etag"] == '"rev-1"'

    session_factory = creator_state["session_factory"]
    with session_factory() as session:
        _root_facts(session, "rest-project", creator_state["creator_id"])
        events = _create_root_events(session, "rest-project")
        assert len(events) == 1
        assert '"channel":"api"' in events[0].details_json
        assert '"catalog_authority":"project_creator"' in events[0].details_json


def test_rest_project_creator_replay_never_duplicates_object_or_grant(
    creator_client: TestClient,
    creator_state,
) -> None:
    headers = {
        **_authorization(creator_state["creator_token"]),
        "Idempotency-Key": "rest-project-replay-001",
    }
    payload = _project("rest-replay-project").model_dump(mode="json")
    first = creator_client.post("/api/v1/roots", headers=headers, json=payload)
    second = creator_client.post("/api/v1/roots", headers=headers, json=payload)

    assert first.status_code == 201
    assert second.status_code == 201
    assert first.json()["replayed"] is False
    assert second.json()["replayed"] is True
    assert second.json()["catalog_object"] == first.json()["catalog_object"]
    session_factory = creator_state["session_factory"]
    with session_factory() as session:
        _root_facts(session, "rest-replay-project", creator_state["creator_id"])
        assert len(_create_root_events(session, "rest-replay-project")) == 1


@pytest.mark.parametrize("kind", sorted(DENIED_ROOT_KIND_DATA))
def test_rest_project_creator_is_denied_every_other_root_kind(
    creator_client: TestClient,
    creator_state,
    kind: str,
) -> None:
    response = creator_client.post(
        "/api/v1/roots",
        headers={
            **_authorization(creator_state["creator_token"]),
            "Idempotency-Key": f"rest-denied-{kind}-key-01",
        },
        json=_root_of_kind(f"rest-denied-{kind}", kind).model_dump(mode="json"),
    )

    assert response.status_code == 403
    assert response.json()["error"]["code"] == "forbidden"
    session_factory = creator_state["session_factory"]
    with session_factory() as session:
        assert session.get(CatalogObject, f"rest-denied-{kind}") is None
        assert _grants_for(session, f"rest-denied-{kind}") == []
        event = session.scalar(
            select(SecurityEvent).where(
                SecurityEvent.event_type == "object_command_authorization",
                SecurityEvent.principal_id == creator_state["creator_id"],
            )
        )
        assert event is not None
        assert event.outcome == "denied"
        assert '"permission":"create_child"' in event.details_json


@pytest.mark.parametrize("token_key", ["viewer_token", "plain_token"])
def test_rest_root_project_stays_denied_without_the_authority(
    creator_client: TestClient,
    creator_state,
    token_key: str,
) -> None:
    response = creator_client.post(
        "/api/v1/roots",
        headers={
            **_authorization(creator_state[token_key]),
            "Idempotency-Key": f"rest-{token_key}-denied-01",
        },
        json=_project(f"rest-{token_key}-project").model_dump(mode="json"),
    )

    assert response.status_code == 403
    assert response.json()["error"]["code"] == "forbidden"
    session_factory = creator_state["session_factory"]
    with session_factory() as session:
        assert session.get(CatalogObject, f"rest-{token_key}-project") is None


# ---------------------------------------------------------------------------
# No privilege escalation
# ---------------------------------------------------------------------------


def test_rest_project_creator_holds_no_catalog_wide_read_or_write_authority(
    creator_client: TestClient,
    creator_state,
) -> None:
    headers = _authorization(creator_state["creator_token"])

    # Reads: the role reveals nothing, not even a stub.
    listing = creator_client.get("/api/v1/objects", headers=headers)
    assert listing.status_code == 200
    assert listing.json()["items"] == []
    for object_id in ("existing-host", "existing-project"):
        assert creator_client.get(
            f"/api/v1/objects/{object_id}", headers=headers
        ).status_code == 404

    # Writes, deletes, renames, children, and grants on an existing object.
    assert creator_client.put(
        "/api/v1/objects/existing-project",
        headers={**headers, "If-Match": '"rev-1"'},
        json=_project("existing-project", label="Hijacked").model_dump(mode="json"),
    ).status_code == 404
    assert creator_client.post(
        "/api/v1/objects/existing-project/rename",
        headers={**headers, "If-Match": '"rev-1"'},
        json={"new_label": "Hijacked"},
    ).status_code == 404
    assert creator_client.delete(
        "/api/v1/objects/existing-project",
        headers={**headers, "If-Match": '"rev-1"'},
    ).status_code == 404
    assert creator_client.post(
        "/api/v1/objects/existing-host/children",
        headers={**headers, "Idempotency-Key": "escalation-child-key-01"},
        json=CatalogObjectIn(
            id="escalated-child",
            kind="system",
            label="Escalated Child",
            data={"schema_version": 1},
        ).model_dump(mode="json"),
    ).status_code == 404
    assert creator_client.post(
        "/api/v1/objects/existing-project/access/grants",
        headers={**headers, "If-Match": '"rev-1"'},
        json={
            "principal_id": creator_state["creator_id"],
            "role": "owner",
            "scope": "self",
        },
    ).status_code == 404

    # Identity administration is a separate axis and stays closed.
    assert creator_client.get(
        "/api/v1/admin/principals", headers=headers
    ).status_code == 403

    session_factory = creator_state["session_factory"]
    with session_factory() as session:
        stored = session.get(CatalogObject, "existing-project")
        assert stored is not None
        assert stored.label == "Existing Project"
        assert stored.revision == 1
        assert session.get(CatalogObject, "escalated-child") is None
        assert _grants_for(session, "existing-project") == []


def test_project_creator_cannot_widen_its_own_authority_through_its_new_root(
    creator_client: TestClient,
    creator_state,
) -> None:
    created = creator_client.post(
        "/api/v1/roots",
        headers={
            **_authorization(creator_state["creator_token"]),
            "Idempotency-Key": "own-root-scope-key-0001",
        },
        json=_project("own-project").model_dump(mode="json"),
    )
    assert created.status_code == 201

    headers = _authorization(creator_state["creator_token"])
    # Owner on its own root, and only there.
    own = creator_client.get("/api/v1/objects/own-project", headers=headers)
    assert own.status_code == 200
    assert sorted(own.json()["capabilities"]) == [
        "create_child",
        "delete",
        "discover",
        "manage_access",
        "read",
        "rename",
        "write",
    ]
    assert creator_client.get(
        "/api/v1/objects/existing-project", headers=headers
    ).status_code == 404
    assert {item["id"] for item in creator_client.get(
        "/api/v1/objects", headers=headers
    ).json()["items"]} == {"own-project"}

    session_factory = creator_state["session_factory"]
    with session_factory() as session:
        stored = session.get(Principal, creator_state["creator_id"])
        assert stored is not None
        # The catalog write never touched the role axis.
        assert stored.catalog_role == CatalogRole.PROJECT_CREATOR


def test_project_creator_cannot_create_objects_through_knowledge_apply(
    creator_state,
) -> None:
    """The reviewed-Knowledge-apply creation gate stays catalog-owner only."""
    contract = ApplyContract(
        targets=(
            ApplyTarget(
                target_ref="project:knowledge-project",
                object_id="knowledge-project",
                kind="project",
                action="create",
                expected_revision=None,
                candidate=_project("knowledge-project"),
                source_entry_ids=(),
            ),
        ),
        relations=(),
        source_entry_keys=(),
    )
    session_factory = creator_state["session_factory"]
    with session_factory() as session:
        with pytest.raises(KnowledgeApplyError) as denial:
            _require_authorization(session, creator_state["creator_id"], contract)
        # The catalog owner remains the only principal this gate accepts.
        _require_authorization(session, creator_state["owner_id"], contract)

    assert str(denial.value) == "authorization_failed"


# ---------------------------------------------------------------------------
# MCP
# ---------------------------------------------------------------------------


def _mcp_requester(client: TestClient, token: str):
    def requester(method, path, body, headers):
        response = client.request(
            method,
            path,
            json=body,
            headers={**headers, **_authorization(token)},
        )
        if response.status_code >= 400:
            error = response.json().get("error", {})
            raise UpstreamError(
                str(error.get("code", "upstream_http_error")),
                str(error.get("message", "Blockwart Agent API returned an error.")),
            )
        return response.json()

    return requester


def test_mcp_project_creator_creates_root_project_end_to_end(
    creator_client: TestClient,
    creator_state,
) -> None:
    result = call_tool(
        "blockwart.create_root",
        {
            "idempotency_key": "mcp-project-key-00001",
            "object": {
                "id": "mcp-project",
                "kind": "project",
                "label": "MCP Project",
                "data": dict(PROJECT_DATA),
            },
        },
        requester=_mcp_requester(creator_client, creator_state["creator_mcp_token"]),
    )
    payload = json.loads(result["content"][0]["text"])

    assert payload["catalog_object"]["id"] == "mcp-project"
    assert payload["catalog_object"]["kind"] == "project"
    assert payload["revision"] == 1
    assert payload["etag"] == '"rev-1"'
    assert payload["parent_ref"] is None
    assert payload["owner_assignment"] == {
        "principal": "authenticated_caller",
        "role": "owner",
        "scope": "self",
    }

    session_factory = creator_state["session_factory"]
    with session_factory() as session:
        _root_facts(session, "mcp-project", creator_state["creator_id"])
        events = _create_root_events(session, "mcp-project")
        assert len(events) == 1
        assert '"channel":"mcp"' in events[0].details_json
        assert '"catalog_authority":"project_creator"' in events[0].details_json


@pytest.mark.parametrize("kind", sorted(DENIED_ROOT_KIND_DATA))
def test_mcp_project_creator_is_denied_every_other_root_kind(
    creator_client: TestClient,
    creator_state,
    kind: str,
) -> None:
    with pytest.raises(UpstreamError) as denial:
        call_tool(
            "blockwart.create_root",
            {
                "idempotency_key": f"mcp-denied-{kind}-key-01",
                "object": {
                    "id": f"mcp-denied-{kind}",
                    "kind": kind,
                    "label": f"MCP Denied {kind}",
                    "data": dict(DENIED_ROOT_KIND_DATA[kind]),
                },
            },
            requester=_mcp_requester(
                creator_client, creator_state["creator_mcp_token"]
            ),
        )

    assert denial.value.code == "forbidden"
    session_factory = creator_state["session_factory"]
    with session_factory() as session:
        assert session.get(CatalogObject, f"mcp-denied-{kind}") is None


def test_mcp_create_root_contract_names_the_delegable_authority() -> None:
    from blockwart.mcp.server import TOOL_DEFINITIONS

    description = TOOL_DEFINITIONS["blockwart.create_root"]["description"]
    assert "project_creator" in description
    assert "catalog_owner" in description
    assert "object.kind=project" in description


# ---------------------------------------------------------------------------
# Browser UI
# ---------------------------------------------------------------------------


def test_ui_create_root_form_offers_only_the_authorized_kind(
    creator_client: TestClient,
    creator_state,
) -> None:
    _login(creator_client, creator_state["creator_session"])
    index = creator_client.get("/")
    modal = creator_client.get("/?create_root=1")

    assert index.status_code == 200
    assert "create_root=1" in index.text
    assert modal.status_code == 200
    assert 'action="/roots"' in modal.text
    kind_select = modal.text.split("data-kind-select", 1)[1].split("</select>", 1)[0]
    assert 'value="project"' in kind_select
    for kind in DENIED_ROOT_KIND_DATA:
        assert f'value="{kind}"' not in kind_select
    # Opening the form on a kind the principal cannot create snaps to project.
    host_modal = creator_client.get("/?kind=host&create_root=1")
    assert host_modal.status_code == 200
    host_select = host_modal.text.split("data-kind-select", 1)[1].split("</select>", 1)[0]
    assert 'value="project" selected' in host_select
    for kind in DENIED_ROOT_KIND_DATA:
        assert f'value="{kind}"' not in host_select


def test_ui_project_creator_creates_root_project(
    creator_client: TestClient,
    creator_state,
) -> None:
    issued = creator_state["creator_session"]
    _login(creator_client, issued)
    response = creator_client.post(
        "/roots",
        data={
            "csrf_token": issued.csrf_token,
            "idempotency_key": "ui-project-key-000001",
            "object_id": "ui-project",
            "kind": "project",
            "primary_name": "UI Project",
            "category": "implementation",
            "project_status": "planned",
            "status": "active",
        },
        follow_redirects=False,
    )

    assert response.status_code == 303
    session_factory = creator_state["session_factory"]
    with session_factory() as session:
        stored = session.get(CatalogObject, "ui-project")
        assert stored is not None
        assert stored.kind == "project"
        _root_facts(session, "ui-project", creator_state["human_creator_id"])
        events = _create_root_events(session, "ui-project")
        assert len(events) == 1
        assert '"channel":"ui"' in events[0].details_json
        assert '"catalog_authority":"project_creator"' in events[0].details_json


@pytest.mark.parametrize("kind", sorted(DENIED_ROOT_KIND_DATA))
def test_ui_project_creator_cannot_post_another_root_kind(
    creator_client: TestClient,
    creator_state,
    kind: str,
) -> None:
    issued = creator_state["creator_session"]
    _login(creator_client, issued)
    response = creator_client.post(
        "/roots",
        data={
            "csrf_token": issued.csrf_token,
            "idempotency_key": f"ui-denied-{kind}-000001",
            "object_id": f"ui-denied-{kind}",
            "kind": kind,
            "primary_name": f"UI Denied {kind}",
            "device_category": "adapter",
            "network_category": "access_point",
            "runbook_status": "draft",
            "decision_status": "proposed",
            "status": "active",
        },
        follow_redirects=False,
    )

    assert response.status_code == 403
    session_factory = creator_state["session_factory"]
    with session_factory() as session:
        assert session.get(CatalogObject, f"ui-denied-{kind}") is None


# ---------------------------------------------------------------------------
# Administration and revocation
# ---------------------------------------------------------------------------


def test_rest_admin_assigns_and_revokes_the_role_independently_of_catalog_owner(
    alembic_session_factory,
) -> None:
    with alembic_session_factory() as session:
        with transaction(session):
            dual = create_human_principal(
                session,
                login="dual.admin",
                display_name="Dual Admin",
                password=PASSWORD,
                platform_role=PlatformRole.ADMIN,
                catalog_role=CatalogRole.CATALOG_OWNER,
            )
            target = create_service_account(
                session,
                login="creator.target",
                display_name="Creator Target",
            )
        access = read_access_for_principal(session, dual)

        with transaction(session):
            assigned = set_managed_catalog_role(
                session,
                access,
                principal_id=target.id,
                expected_revision='"rev-1"',
                catalog_role=CatalogRole.PROJECT_CREATOR,
                actor_password=PASSWORD,
                channel="api",
                request_id="project-creator-assign-01",
            )
        with transaction(session):
            unchanged = set_managed_catalog_role(
                session,
                access,
                principal_id=target.id,
                expected_revision='"rev-2"',
                catalog_role=CatalogRole.PROJECT_CREATOR,
                actor_password=PASSWORD,
                channel="api",
                request_id="project-creator-noop-01",
            )
        with transaction(session):
            removed = set_managed_catalog_role(
                session,
                access,
                principal_id=target.id,
                expected_revision='"rev-2"',
                catalog_role=None,
                actor_password=PASSWORD,
                channel="api",
                request_id="project-creator-remove-01",
            )
        events = session.scalars(
            select(SecurityEvent)
            .where(
                SecurityEvent.event_type == "catalog_role_changed",
                SecurityEvent.principal_id == target.id,
            )
            .order_by(SecurityEvent.created_at, SecurityEvent.id)
        ).all()

    assert assigned.changed is True
    assert assigned.principal.catalog_role == CatalogRole.PROJECT_CREATOR
    assert assigned.principal.revision == 2
    assert unchanged.changed is False
    assert unchanged.principal.revision == 2
    assert removed.changed is True
    assert removed.principal.catalog_role is None
    assert removed.principal.revision == 3
    assert [json.loads(event.details_json)["after_catalog_role"] for event in events] == [
        "project_creator",
        "none",
    ]
    assert all(PASSWORD not in event.details_json for event in events)


def test_revoking_the_role_stops_new_roots_and_keeps_existing_owner_grants(
    creator_client: TestClient,
    creator_state,
) -> None:
    headers = _authorization(creator_state["creator_token"])
    first = creator_client.post(
        "/api/v1/roots",
        headers={**headers, "Idempotency-Key": "revocation-first-key-01"},
        json=_project("kept-project").model_dump(mode="json"),
    )
    assert first.status_code == 201

    session_factory = creator_state["session_factory"]
    with session_factory() as session:
        with transaction(session):
            row = session.get(Principal, creator_state["creator_id"])
            assert row is not None
            row.catalog_role = None

    denied = creator_client.post(
        "/api/v1/roots",
        headers={**headers, "Idempotency-Key": "revocation-second-key-1"},
        json=_project("refused-project").model_dump(mode="json"),
    )
    assert denied.status_code == 403

    # The Owner/self grant is a real, independently revocable object grant, so
    # revoking the catalog role does not take the already created project away.
    kept = creator_client.get("/api/v1/objects/kept-project", headers=headers)
    assert kept.status_code == 200
    with session_factory() as session:
        _root_facts(session, "kept-project", creator_state["creator_id"])
        assert session.get(CatalogObject, "refused-project") is None


def test_rest_admin_projection_explains_the_role_and_its_root_kinds(
    alembic_session_factory,
) -> None:
    with alembic_session_factory() as session:
        with transaction(session):
            admin = create_service_account(
                session,
                login="admin.reader",
                display_name="Admin Reader",
                platform_role=PlatformRole.ADMIN,
            )
            admin_token = issue_service_token(
                session,
                principal_id=admin.id,
                name="api-reads",
            )
            target = create_service_account(
                session,
                login="projection.creator",
                display_name="Projection Creator",
                catalog_role=CatalogRole.PROJECT_CREATOR,
            )

    app = create_app()

    def override_get_session() -> Generator[Session, None, None]:
        with alembic_session_factory() as session:
            yield session

    app.dependency_overrides[get_session] = override_get_session
    with TestClient(app) as client:
        detail = client.get(
            f"/api/v1/admin/principals/{target.id}",
            headers=_authorization(admin_token.value),
        )

    assert detail.status_code == 200
    body = detail.json()
    assert body["principal"]["catalog_role"] == "project_creator"
    assert body["global_authorities"] == [
        {
            "source": "project_creator",
            "permissions": [],
            "root_kinds": ["project"],
        }
    ]


def test_ui_project_creator_option_and_german_label_are_distinct(
    alembic_session_factory,
) -> None:
    with alembic_session_factory() as session:
        with transaction(session):
            upsert_object(
                session,
                CatalogObjectIn(
                    id="ui-anchor",
                    kind="host",
                    label="UI Anchor",
                    lifecycle="active",
                    health="healthy",
                    data={"schema_version": 1},
                ),
            )
            dual = create_human_principal(
                session,
                login="ui.dual.admin",
                display_name="UI Dual Admin",
                password=PASSWORD,
                platform_role=PlatformRole.ADMIN,
                catalog_role=CatalogRole.CATALOG_OWNER,
            )
            create_object_grant(
                session,
                principal_id=dual.id,
                object_id="ui-anchor",
                role=Role.OWNER,
                scope=GrantScope.SELF,
            )
            target = create_service_account(
                session,
                login="ui.creator.target",
                display_name="UI Creator Target",
            )
            issued = issue_browser_session(
                session,
                principal_id=dual.id,
                ttl_seconds=3600,
            )

    app = create_app()

    def override_get_session() -> Generator[Session, None, None]:
        with alembic_session_factory() as session:
            yield session

    app.dependency_overrides[get_session] = override_get_session
    with TestClient(app, base_url="https://testserver") as client:
        _login(client, issued)
        initial = client.get(f"/admin/principals/{target.id}")
        response = client.post(
            f"/admin/principals/{target.id}/catalog-role",
            data={
                "csrf_token": issued.csrf_token,
                "if_match": '"rev-1"',
                "catalog_role": "project_creator",
                "current_admin_password": PASSWORD,
            },
            follow_redirects=False,
        )
        english = client.get(f"/admin/principals/{target.id}")
        german = client.get(
            f"/admin/principals/{target.id}", params={"lang": "de"}
        )

    assert initial.status_code == 200
    assert 'value="project_creator"' in initial.text
    assert response.status_code == 303
    assert "Project creator" in english.text
    assert "Projekt-Ersteller" in german.text


def test_project_creator_carries_no_last_active_holder_invariant(
    alembic_session_factory,
) -> None:
    """Unlike the catalog owner, the sole project creator is freely revocable."""
    with alembic_session_factory() as session:
        with transaction(session):
            target = create_service_account(
                session,
                login="only.creator",
                display_name="Only Creator",
                catalog_role=CatalogRole.PROJECT_CREATOR,
            )
        assert session.scalar(
            select(func.count())
            .select_from(Principal)
            .where(Principal.catalog_role == CatalogRole.PROJECT_CREATOR)
        ) == 1
        with transaction(session):
            row = session.get(Principal, target.id)
            assert row is not None
            row.active = False
        with transaction(session):
            session.delete(session.get(Principal, target.id))
        assert session.get(Principal, target.id) is None
