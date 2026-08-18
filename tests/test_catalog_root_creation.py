from __future__ import annotations

import json
import re
from collections.abc import Generator
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import event as sqlalchemy_event
from sqlalchemy import func, select, update
from sqlalchemy.orm import Session

from blockwart.api.deps import get_session
from blockwart.db.session import transaction
from blockwart.domain.auth import (
    CatalogRole,
    GrantScope,
    PlatformRole,
    Role,
)
from blockwart.main import create_app
from blockwart.mcp.server import TOOL_DEFINITIONS, UpstreamError, call_tool
from blockwart.models import (
    AuditEvent,
    CatalogObject,
    IdempotencyRecord,
    ObjectGrant,
    Principal,
    Relationship,
    SecurityEvent,
)
from blockwart.schemas.catalog import CatalogObjectIn
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
from blockwart.services.read_access import read_access_for_principal
from blockwart.ui.security import (
    AUTH_CSRF_COOKIE_NAME,
    AUTH_SESSION_COOKIE_NAME,
)


def _asset(
    object_id: str,
    *,
    kind: str = "host",
    label: str | None = None,
    summary: str | None = None,
    data: dict | None = None,
) -> CatalogObjectIn:
    return CatalogObjectIn(
        id=object_id,
        kind=kind,
        label=label or object_id,
        summary=summary,
        data={"schema_version": 1} if data is None else data,
    )


@pytest.fixture
def root_state(alembic_session_factory):
    with alembic_session_factory() as session:
        with transaction(session):
            upsert_object(session, _asset("existing-object"))
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
            owner_mcp_token = issue_service_token(
                session,
                principal_id=owner.id,
                name="mcp-writes",
                audience="mcp",
            )
            admin = create_service_account(
                session,
                login="platform.admin",
                display_name="Platform Admin",
                platform_role=PlatformRole.ADMIN,
            )
            admin_token = issue_service_token(
                session,
                principal_id=admin.id,
                name="api-writes",
            )
            scoped = create_service_account(
                session,
                login="scoped.owner",
                display_name="Scoped Owner",
            )
            create_object_grant(
                session,
                principal_id=scoped.id,
                object_id="existing-object",
                role=Role.OWNER,
                scope=GrantScope.SELF,
            )
            scoped_token = issue_service_token(
                session,
                principal_id=scoped.id,
                name="api-writes",
            )
            human_owner = create_human_principal(
                session,
                login="human.owner",
                display_name="Human Owner",
                password="root-owner-password-1",
                catalog_role=CatalogRole.CATALOG_OWNER,
            )
            owner_session = issue_browser_session(
                session,
                principal_id=human_owner.id,
                ttl_seconds=3600,
            )
            human_admin = create_human_principal(
                session,
                login="human.admin",
                display_name="Human Admin",
                password="root-admin-password-1",
                platform_role=PlatformRole.ADMIN,
            )
            admin_session = issue_browser_session(
                session,
                principal_id=human_admin.id,
                ttl_seconds=3600,
            )
    return {
        "session_factory": alembic_session_factory,
        "owner_id": owner.id,
        "owner_token": owner_token.value,
        "owner_mcp_token": owner_mcp_token.value,
        "admin_id": admin.id,
        "admin_token": admin_token.value,
        "scoped_id": scoped.id,
        "scoped_token": scoped_token.value,
        "human_owner_id": human_owner.id,
        "owner_session": owner_session,
        "human_admin_id": human_admin.id,
        "admin_session": admin_session,
    }


@pytest.fixture
def root_client(root_state) -> Generator[TestClient, None, None]:
    session_factory = root_state["session_factory"]
    app = create_app()

    def override_get_session() -> Generator[Session, None, None]:
        with session_factory() as session:
            yield session

    app.dependency_overrides[get_session] = override_get_session
    with TestClient(app) as client:
        yield client


def _authorization(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _service_context(
    session: Session,
    principal_id: str,
    *,
    channel: str,
    audience: str | None = "api",
) -> WriteContext:
    row = session.get(Principal, principal_id)
    assert row is not None
    access = read_access_for_principal(session, principal_context(row))
    return WriteContext(
        principal=replace(access.principal, service_token_audience=audience),
        policy=access.policy,
        channel=channel,
        request_id="root-test-request",
    )


def _login(client: TestClient, issued) -> None:
    client.cookies.set(AUTH_SESSION_COOKIE_NAME, issued.value)
    client.cookies.set(AUTH_CSRF_COOKIE_NAME, issued.csrf_token)


def _ui_root_form(root_state, **overrides) -> dict[str, str]:
    form = {
        "csrf_token": root_state["owner_session"].csrf_token,
        "idempotency_key": "ui-root-key-000001",
        "object_id": "ui-root",
        "kind": "host",
        "label": "",
        "primary_name": "UI Root",
        "labels": "edge, core",
        "platform": "VM",
        "status": "active",
        "summary": "browser created root",
    }
    form.update(overrides)
    return form


def _grants_for(session: Session, object_id: str) -> list[ObjectGrant]:
    return list(
        session.scalars(
            select(ObjectGrant).where(ObjectGrant.object_id == object_id)
        )
    )


def _root_facts(session: Session, object_id: str) -> None:
    """Assert the root invariants: one real Owner/self grant, nothing else."""
    grants = _grants_for(session, object_id)
    assert len(grants) == 1
    grant = grants[0]
    assert grant.role == Role.OWNER
    assert grant.scope == GrantScope.SELF
    assert grant.principal_id == grant.created_by_principal_id
    assert session.scalar(
        select(func.count())
        .select_from(Relationship)
        .where(
            (Relationship.from_ref.contains(f":{object_id}"))
            | (Relationship.to_ref.contains(f":{object_id}"))
        )
    ) == 0


def _create_root_audit_events(session: Session, object_id: str) -> list[AuditEvent]:
    return list(
        session.scalars(
            select(AuditEvent).where(
                AuditEvent.object_id == object_id,
                AuditEvent.action == "create_root",
            )
        )
    )


# ---------------------------------------------------------------------------
# Service layer: authorization resolved from current DB state
# ---------------------------------------------------------------------------


def test_service_catalog_owner_creates_root_with_real_owner_grant(
    root_state,
) -> None:
    session_factory = root_state["session_factory"]
    with session_factory() as session:
        context = _service_context(session, root_state["owner_id"], channel="api")
        with transaction(session):
            result = create_catalog_root(
                session,
                context,
                payload=_asset("service-root", label="Service Root"),
                idempotency_key="service-root-key-01",
                idempotency_ttl_seconds=86400,
            )

    assert result.changed is True
    assert result.replayed is False
    assert result.etag == '"rev-1"'
    assert result.catalog_object.revision == 1
    assert result.catalog_object.parent_path == []
    assert result.catalog_object.placement_state == "root"
    assert result.catalog_object.capabilities == [
        "create_child",
        "delete",
        "discover",
        "manage_access",
        "read",
        "write",
    ]
    with session_factory() as session:
        _root_facts(session, "service-root")
        grant = _grants_for(session, "service-root")[0]
        assert grant.principal_id == root_state["owner_id"]
        events = _create_root_audit_events(session, "service-root")
        assert len(events) == 1
        details = events[0].details_json
        assert events[0].actor == root_state["owner_id"]
        assert '"channel":"api"' in details
        assert '"request_id":"root-test-request"' in details
        assert '"old_revision":0' in details
        assert '"new_revision":1' in details
        assert '"parent_ref":null' in details
        assert '"affected_revisions":{}' in details
        assert '"creator_owner_grant":{' in details
        assert f'"principal_id":"{root_state["owner_id"]}"' in details
        assert '"role":"owner"' in details
        assert '"scope":"self"' in details


def test_service_platform_admin_alone_is_denied(root_state) -> None:
    session_factory = root_state["session_factory"]
    with session_factory() as session:
        context = _service_context(session, root_state["admin_id"], channel="api")
        with (
            transaction(session),
            pytest.raises(CommandAuthorizationDenied),
        ):
            create_catalog_root(
                session,
                context,
                payload=_asset("denied-root"),
                idempotency_key="denied-root-key-01",
                idempotency_ttl_seconds=86400,
            )
    with session_factory() as session:
        assert session.get(CatalogObject, "denied-root") is None
        assert _grants_for(session, "denied-root") == []


def test_service_scoped_owner_alone_is_denied(root_state) -> None:
    session_factory = root_state["session_factory"]
    with session_factory() as session:
        context = _service_context(session, root_state["scoped_id"], channel="api")
        with (
            transaction(session),
            pytest.raises(CommandAuthorizationDenied),
        ):
            create_catalog_root(
                session,
                context,
                payload=_asset("denied-root"),
                idempotency_key="denied-root-key-02",
                idempotency_ttl_seconds=86400,
            )
    with session_factory() as session:
        assert session.get(CatalogObject, "denied-root") is None


def test_service_inactive_catalog_owner_is_denied(root_state) -> None:
    session_factory = root_state["session_factory"]
    with session_factory() as session:
        with transaction(session):
            create_service_account(
                session,
                login="standby.owner",
                display_name="Standby Owner",
                catalog_role=CatalogRole.CATALOG_OWNER,
            )
            session.execute(
                update(Principal)
                .where(Principal.id == root_state["owner_id"])
                .values(active=False)
            )
        context = _service_context(session, root_state["owner_id"], channel="api")
        with (
            transaction(session),
            pytest.raises(CommandAuthorizationDenied),
        ):
            create_catalog_root(
                session,
                context,
                payload=_asset("denied-root"),
                idempotency_key="denied-root-key-03",
                idempotency_ttl_seconds=86400,
            )
    with session_factory() as session:
        assert session.get(CatalogObject, "denied-root") is None


@pytest.mark.parametrize(
    ("channel", "audience", "allowed"),
    [
        ("api", "api", True),
        ("mcp", "mcp", True),
        ("ui", None, True),
        ("api", "mcp", False),
        ("mcp", "api", False),
        ("ui", "api", False),
    ],
)
def test_service_trusted_channel_requires_matching_token_audience(
    root_state,
    channel: str,
    audience: str | None,
    allowed: bool,
) -> None:
    session_factory = root_state["session_factory"]
    object_id = f"audience-root-{channel}-{audience or 'none'}"
    with session_factory() as session:
        context = _service_context(
            session,
            root_state["owner_id"],
            channel=channel,
            audience=audience,
        )
        if allowed:
            with transaction(session):
                result = create_catalog_root(
                    session,
                    context,
                    payload=_asset(object_id),
                    idempotency_key=f"audience-key-{object_id}",
                    idempotency_ttl_seconds=86400,
                )
            assert result.catalog_object.id == object_id
        else:
            with (
                transaction(session),
                pytest.raises(CommandAuthorizationDenied),
            ):
                create_catalog_root(
                    session,
                    context,
                    payload=_asset(object_id),
                    idempotency_key=f"audience-key-{object_id}",
                    idempotency_ttl_seconds=86400,
                )
    with session_factory() as session:
        assert (session.get(CatalogObject, object_id) is not None) is allowed


def test_service_replay_never_duplicates_object_or_grant(root_state) -> None:
    session_factory = root_state["session_factory"]
    with session_factory() as session:
        context = _service_context(session, root_state["owner_id"], channel="api")
        with transaction(session):
            first = create_catalog_root(
                session,
                context,
                payload=_asset("replay-root"),
                idempotency_key="replay-root-key-01",
                idempotency_ttl_seconds=86400,
            )
        with transaction(session):
            replay = create_catalog_root(
                session,
                context,
                payload=_asset("replay-root"),
                idempotency_key="replay-root-key-01",
                idempotency_ttl_seconds=86400,
            )

    assert first.replayed is False
    assert replay.replayed is True
    assert replay.catalog_object == first.catalog_object
    assert replay.etag == first.etag
    with session_factory() as session:
        _root_facts(session, "replay-root")
        assert len(_create_root_audit_events(session, "replay-root")) == 1
        assert session.scalar(
            select(func.count())
            .select_from(IdempotencyRecord)
            .where(IdempotencyRecord.principal_id == root_state["owner_id"])
        ) == 1


# ---------------------------------------------------------------------------
# REST v1 endpoint
# ---------------------------------------------------------------------------


def test_rest_create_root_returns_canonical_projection_and_strong_etag(
    root_client: TestClient,
    root_state,
) -> None:
    response = root_client.post(
        "/api/v1/roots",
        headers={
            **_authorization(root_state["owner_token"]),
            "Idempotency-Key": "rest-root-key-00001",
            "X-Correlation-ID": "root-correlation-0001",
        },
        json=_asset("rest-root", label="REST Root").model_dump(mode="json"),
    )

    assert response.status_code == 201
    assert response.headers["etag"] == '"rev-1"'
    assert response.headers["location"] == "/api/v1/objects/rest-root"
    body = response.json()
    assert body["etag"] == response.headers["etag"]
    assert body["changed"] is True
    assert body["replayed"] is False
    assert body["catalog_object"]["id"] == "rest-root"
    assert body["catalog_object"]["kind"] == "host"
    assert body["catalog_object"]["revision"] == 1
    assert body["catalog_object"]["parent_path"] == []
    assert body["catalog_object"]["placement_state"] == "root"
    assert "password" not in json.dumps(body)

    reread = root_client.get(
        response.headers["location"],
        headers=_authorization(root_state["owner_token"]),
    )
    assert reread.status_code == 200
    assert reread.headers["etag"] == '"rev-1"'
    assert reread.json()["revision"] == 1

    session_factory = root_state["session_factory"]
    with session_factory() as session:
        _root_facts(session, "rest-root")
        grant = _grants_for(session, "rest-root")[0]
        assert grant.principal_id == root_state["owner_id"]
        events = _create_root_audit_events(session, "rest-root")
        assert len(events) == 1
        assert '"channel":"api"' in events[0].details_json
        assert '"request_id":"root-correlation-0001"' in events[0].details_json


def test_rest_create_root_replay_is_idempotent(
    root_client: TestClient,
    root_state,
) -> None:
    headers = {
        **_authorization(root_state["owner_token"]),
        "Idempotency-Key": "rest-replay-key-001",
    }
    payload = _asset("rest-replay-root").model_dump(mode="json")
    first = root_client.post("/api/v1/roots", headers=headers, json=payload)
    second = root_client.post("/api/v1/roots", headers=headers, json=payload)

    assert first.status_code == 201
    assert second.status_code == 201
    assert first.json()["replayed"] is False
    assert second.json()["replayed"] is True
    assert second.json()["catalog_object"] == first.json()["catalog_object"]
    assert second.headers["etag"] == first.headers["etag"]
    session_factory = root_state["session_factory"]
    with session_factory() as session:
        _root_facts(session, "rest-replay-root")
        assert len(_create_root_audit_events(session, "rest-replay-root")) == 1


def test_rest_create_root_key_reuse_with_changed_payload_conflicts(
    root_client: TestClient,
    root_state,
) -> None:
    headers = {
        **_authorization(root_state["owner_token"]),
        "Idempotency-Key": "rest-changed-key-001",
    }
    first = root_client.post(
        "/api/v1/roots",
        headers=headers,
        json=_asset("changed-root-a").model_dump(mode="json"),
    )
    conflict = root_client.post(
        "/api/v1/roots",
        headers=headers,
        json=_asset("changed-root-b").model_dump(mode="json"),
    )

    assert first.status_code == 201
    assert conflict.status_code == 409
    assert conflict.json()["error"]["code"] == "conflict"
    session_factory = root_state["session_factory"]
    with session_factory() as session:
        assert session.get(CatalogObject, "changed-root-b") is None
        assert _grants_for(session, "changed-root-b") == []
        assert _create_root_audit_events(session, "changed-root-b") == []


def test_rest_create_root_duplicate_id_conflicts(
    root_client: TestClient,
    root_state,
) -> None:
    auth = _authorization(root_state["owner_token"])
    payload = _asset("duplicate-root").model_dump(mode="json")
    first = root_client.post(
        "/api/v1/roots",
        headers={**auth, "Idempotency-Key": "duplicate-key-0001"},
        json=payload,
    )
    duplicate = root_client.post(
        "/api/v1/roots",
        headers={**auth, "Idempotency-Key": "duplicate-key-0002"},
        json=payload,
    )
    existing = root_client.post(
        "/api/v1/roots",
        headers={**auth, "Idempotency-Key": "duplicate-key-0003"},
        json=_asset("existing-object").model_dump(mode="json"),
    )

    assert first.status_code == 201
    assert duplicate.status_code == 409
    assert duplicate.json()["error"]["code"] == "conflict"
    assert existing.status_code == 409
    session_factory = root_state["session_factory"]
    with session_factory() as session:
        _root_facts(session, "duplicate-root")
        assert len(_create_root_audit_events(session, "duplicate-root")) == 1
        existing_grants = _grants_for(session, "existing-object")
        assert len(existing_grants) == 1
        assert existing_grants[0].principal_id == root_state["scoped_id"]


def test_rest_create_root_requires_idempotency_key(
    root_client: TestClient,
    root_state,
) -> None:
    response = root_client.post(
        "/api/v1/roots",
        headers=_authorization(root_state["owner_token"]),
        json=_asset("no-key-root").model_dump(mode="json"),
    )

    assert response.status_code == 400
    assert response.json()["error"]["code"] == "invalid_request"
    session_factory = root_state["session_factory"]
    with session_factory() as session:
        assert session.get(CatalogObject, "no-key-root") is None


@pytest.mark.parametrize(
    "payload",
    [
        pytest.param(
            {
                "id": "Invalid Root ID!",
                "kind": "host",
                "label": "bad id",
                "data": {"schema_version": 1},
            },
            id="invalid-object-id",
        ),
        pytest.param(
            {
                "id": "secret-root",
                "kind": "host",
                "label": "secret",
                "data": {"schema_version": 1, "password": "hunter2-secret"},
            },
            id="secret-shaped-data",
        ),
        pytest.param(
            {
                "id": "acl-root",
                "kind": "host",
                "label": "acl",
                "data": {"schema_version": 1, "acl": {"readers": ["*"]}},
            },
            id="acl-shaped-key",
        ),
        pytest.param(
            {
                "id": "kind-root",
                "kind": "not-a-kind",
                "label": "kind",
                "data": {"schema_version": 1},
            },
            id="unknown-kind",
        ),
    ],
)
def test_rest_create_root_schema_data_secret_and_acl_validation(
    root_client: TestClient,
    root_state,
    payload: dict,
) -> None:
    response = root_client.post(
        "/api/v1/roots",
        headers={
            **_authorization(root_state["owner_token"]),
            "Idempotency-Key": f"invalid-{payload['id']}-key",
        },
        json=payload,
    )

    assert response.status_code == 422
    assert response.json()["error"]["code"] == "validation_error"
    session_factory = root_state["session_factory"]
    with session_factory() as session:
        assert session.get(CatalogObject, payload["id"]) is None
        assert _grants_for(session, payload["id"]) == []
        assert _create_root_audit_events(session, payload["id"]) == []


def test_rest_create_root_dangling_reference_conflicts(
    root_client: TestClient,
    root_state,
) -> None:
    response = root_client.post(
        "/api/v1/roots",
        headers={
            **_authorization(root_state["owner_token"]),
            "Idempotency-Key": "test-test-test-one",
        },
        json=_asset(
            "dangling-root",
            data={"schema_version": 1, "note": "service:missing-upstream"},
        ).model_dump(mode="json"),
    )

    assert response.status_code == 409
    assert response.json()["error"]["code"] == "conflict"
    session_factory = root_state["session_factory"]
    with session_factory() as session:
        assert session.get(CatalogObject, "dangling-root") is None
        assert _grants_for(session, "dangling-root") == []


def test_rest_create_root_denied_actors_record_stable_events(
    root_client: TestClient,
    root_state,
) -> None:
    for token_name in ("admin_token", "scoped_token"):
        response = root_client.post(
            "/api/v1/roots",
            headers={
                **_authorization(root_state[token_name]),
                "Idempotency-Key": f"denied-{token_name}-key",
            },
            json=_asset(f"denied-{token_name}").model_dump(mode="json"),
        )
        assert response.status_code == 403
        assert response.json()["error"]["code"] == "forbidden"

    session_factory = root_state["session_factory"]
    with session_factory() as session:
        for token_name, principal_key in (
            ("admin_token", "admin_id"),
            ("scoped_token", "scoped_id"),
        ):
            assert session.get(CatalogObject, f"denied-{token_name}") is None
            assert _grants_for(session, f"denied-{token_name}") == []
            event = session.scalar(
                select(SecurityEvent).where(
                    SecurityEvent.event_type == "object_command_authorization",
                    SecurityEvent.principal_id == root_state[principal_key],
                )
            )
            assert event is not None
            assert event.outcome == "denied"
            assert '"permission":"create_child"' in event.details_json


def test_rest_create_root_anonymous_and_inactive_are_denied(
    root_client: TestClient,
    root_state,
) -> None:
    anonymous = root_client.post(
        "/api/v1/roots",
        headers={"Idempotency-Key": "anonymous-key-0001"},
        json=_asset("anonymous-root").model_dump(mode="json"),
    )
    assert anonymous.status_code == 401
    assert anonymous.json()["error"]["code"] == "unauthorized"
    assert "www-authenticate" in {
        name.lower() for name in anonymous.headers.keys()
    }

    session_factory = root_state["session_factory"]
    with session_factory() as session:
        with transaction(session):
            create_service_account(
                session,
                login="standby.owner",
                display_name="Standby Owner",
                catalog_role=CatalogRole.CATALOG_OWNER,
            )
            session.execute(
                update(Principal)
                .where(Principal.id == root_state["owner_id"])
                .values(active=False)
            )
    inactive = root_client.post(
        "/api/v1/roots",
        headers={
            **_authorization(root_state["owner_token"]),
            "Idempotency-Key": "inactive-key-00001",
        },
        json=_asset("inactive-root").model_dump(mode="json"),
    )
    assert inactive.status_code == 401
    with session_factory() as session:
        assert session.get(CatalogObject, "anonymous-root") is None
        assert session.get(CatalogObject, "inactive-root") is None


def test_rest_create_root_channel_and_audience_must_match(
    root_client: TestClient,
    root_state,
) -> None:
    api_token_on_mcp_channel = root_client.post(
        "/api/v1/roots",
        headers={
            **_authorization(root_state["owner_token"]),
            "Idempotency-Key": "test-test-test-two",
            "X-Blockwart-Channel": "mcp",
        },
        json=_asset("audience-mismatch-root").model_dump(mode="json"),
    )
    assert api_token_on_mcp_channel.status_code == 403

    mcp_token_without_channel = root_client.post(
        "/api/v1/roots",
        headers={
            **_authorization(root_state["owner_mcp_token"]),
            "Idempotency-Key": "test-test-test-three",
        },
        json=_asset("audience-mismatch-root").model_dump(mode="json"),
    )
    assert mcp_token_without_channel.status_code == 403

    mcp_token_on_mcp_channel = root_client.post(
        "/api/v1/roots",
        headers={
            **_authorization(root_state["owner_mcp_token"]),
            "Idempotency-Key": "test-test-test-four",
            "X-Blockwart-Channel": "mcp",
        },
        json=_asset("mcp-channel-root").model_dump(mode="json"),
    )
    assert mcp_token_on_mcp_channel.status_code == 201

    session_factory = root_state["session_factory"]
    with session_factory() as session:
        assert session.get(CatalogObject, "audience-mismatch-root") is None
        _root_facts(session, "mcp-channel-root")
        events = _create_root_audit_events(session, "mcp-channel-root")
        assert len(events) == 1
        assert '"channel":"mcp"' in events[0].details_json


def test_rest_parallel_create_root_same_key_creates_exactly_once(root_state) -> None:
    session_factory = root_state["session_factory"]
    app = create_app()

    def override_get_session() -> Generator[Session, None, None]:
        with session_factory() as session:
            yield session

    app.dependency_overrides[get_session] = override_get_session
    headers = {
        **_authorization(root_state["owner_token"]),
        "Idempotency-Key": "parallel-root-key-01",
    }
    payload = _asset("parallel-root").model_dump(mode="json")
    with TestClient(app) as client:
        with ThreadPoolExecutor(max_workers=2) as pool:
            responses = list(
                pool.map(
                    lambda _: client.post("/api/v1/roots", headers=headers, json=payload),
                    range(2),
                )
            )

    assert [response.status_code for response in responses] == [201, 201]
    assert sorted(response.json()["replayed"] for response in responses) == [
        False,
        True,
    ]
    with session_factory() as session:
        _root_facts(session, "parallel-root")
        assert len(_create_root_audit_events(session, "parallel-root")) == 1


def test_rest_create_root_rolls_back_when_grant_write_fails(
    root_client: TestClient,
    root_state,
) -> None:
    def fail_grant_flush(session, _flush_context, _instances) -> None:
        for instance in session.new:
            if isinstance(instance, ObjectGrant) and instance.object_id == "grant-fail-root":
                raise RuntimeError("simulated grant write failure")

    sqlalchemy_event.listen(Session, "before_flush", fail_grant_flush)
    try:
        response = root_client.post(
            "/api/v1/roots",
            headers={
                **_authorization(root_state["owner_token"]),
                "Idempotency-Key": "grant-fail-key-0001",
            },
            json=_asset("grant-fail-root").model_dump(mode="json"),
        )
    finally:
        sqlalchemy_event.remove(Session, "before_flush", fail_grant_flush)

    assert response.status_code == 500
    assert response.json()["error"]["code"] == "internal_error"
    session_factory = root_state["session_factory"]
    with session_factory() as session:
        assert session.get(CatalogObject, "grant-fail-root") is None
        assert _grants_for(session, "grant-fail-root") == []
        assert _create_root_audit_events(session, "grant-fail-root") == []
        assert session.scalar(
            select(func.count())
            .select_from(IdempotencyRecord)
            .where(IdempotencyRecord.principal_id == root_state["owner_id"])
        ) == 0


def test_rest_create_root_rolls_back_when_audit_write_fails(
    root_client: TestClient,
    root_state,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_audit(*_args, **_kwargs) -> None:
        raise RuntimeError("simulated audit write failure")

    monkeypatch.setattr(
        "blockwart.services.commands.add_audit_event",
        fail_audit,
    )
    response = root_client.post(
        "/api/v1/roots",
        headers={
            **_authorization(root_state["owner_token"]),
            "Idempotency-Key": "audit-fail-key-0001",
        },
        json=_asset("audit-fail-root").model_dump(mode="json"),
    )

    assert response.status_code == 500
    assert response.json()["error"]["code"] == "internal_error"
    session_factory = root_state["session_factory"]
    with session_factory() as session:
        assert session.get(CatalogObject, "audit-fail-root") is None
        assert _grants_for(session, "audit-fail-root") == []
        assert _create_root_audit_events(session, "audit-fail-root") == []
        assert session.scalar(
            select(func.count())
            .select_from(IdempotencyRecord)
            .where(IdempotencyRecord.principal_id == root_state["owner_id"])
        ) == 0


def test_rest_create_root_does_not_mutate_catalog_role(
    root_client: TestClient,
    root_state,
) -> None:
    response = root_client.post(
        "/api/v1/roots",
        headers={
            **_authorization(root_state["scoped_token"]),
            "Idempotency-Key": "role-mutation-key-01",
        },
        json=_asset("role-mutation-root").model_dump(mode="json"),
    )

    assert response.status_code == 403
    session_factory = root_state["session_factory"]
    with session_factory() as session:
        row = session.get(Principal, root_state["scoped_id"])
        assert row is not None
        assert row.catalog_role is None
        assert session.get(CatalogObject, "role-mutation-root") is None


# ---------------------------------------------------------------------------
# Human UI
# ---------------------------------------------------------------------------


def test_ui_create_root_control_is_only_visible_to_catalog_owner(
    root_client: TestClient,
    root_state,
) -> None:
    _login(root_client, root_state["owner_session"])
    owner_index = root_client.get("/")
    owner_modal = root_client.get("/?create_root=1")

    assert owner_index.status_code == 200
    assert "create_root=1" in owner_index.text
    assert 'action="/roots"' not in owner_index.text
    assert owner_modal.status_code == 200
    assert 'action="/roots"' in owner_modal.text
    assert 'role="dialog"' in owner_modal.text
    assert 'name="object_id"' in owner_modal.text
    assert 'name="primary_name"' in owner_modal.text
    assert 'name="labels"' in owner_modal.text
    assert 'name="platform"' in owner_modal.text
    assert 'name="summary"' in owner_modal.text
    assert 'name="data_json"' not in owner_modal.text
    decision_modal = root_client.get("/?kind=decision&create_root=1")
    assert decision_modal.status_code == 200
    assert 'name="data_json"' not in decision_modal.text
    assert 'name="decision_status"' in decision_modal.text
    assert 'name="context"' in decision_modal.text
    assert 'name="doc_url"' in decision_modal.text
    assert 'name="relation_target_ref"' not in owner_modal.text
    assert 'name="catalog_role"' not in owner_modal.text

    _login(root_client, root_state["admin_session"])
    admin_index = root_client.get("/")
    admin_modal = root_client.get("/?create_root=1")

    assert admin_index.status_code == 200
    assert "create_root=1" not in admin_index.text
    assert 'action="/roots"' not in admin_modal.text


def test_ui_create_root_success_creates_object_grant_and_ui_audit(
    root_client: TestClient,
    root_state,
) -> None:
    _login(root_client, root_state["owner_session"])
    response = root_client.post(
        "/roots",
        data=_ui_root_form(root_state),
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert response.headers["location"].startswith("/objects/ui-root")
    session_factory = root_state["session_factory"]
    with session_factory() as session:
        _root_facts(session, "ui-root")
        grant = _grants_for(session, "ui-root")[0]
        assert grant.principal_id == root_state["human_owner_id"]
        row = session.get(CatalogObject, "ui-root")
        assert row is not None
        assert row.kind == "host"
        assert row.revision == 1
        data = json.loads(row.data_json)
        assert data["labels"] == ["edge", "core"]
        assert "platform" not in data
        events = _create_root_audit_events(session, "ui-root")
        assert len(events) == 1
        assert '"channel":"ui"' in events[0].details_json
        assert f'"principal_id":"{root_state["human_owner_id"]}"' in (
            events[0].details_json
        )


def test_ui_create_root_replay_redirects_without_duplicates(
    root_client: TestClient,
    root_state,
) -> None:
    _login(root_client, root_state["owner_session"])
    form = _ui_root_form(root_state, idempotency_key="ui-replay-key-0001")
    first = root_client.post("/roots", data=form, follow_redirects=False)
    second = root_client.post("/roots", data=form, follow_redirects=False)

    assert first.status_code == 303
    assert second.status_code == 303
    assert first.headers["location"] == second.headers["location"]
    session_factory = root_state["session_factory"]
    with session_factory() as session:
        _root_facts(session, "ui-root")
        assert len(_create_root_audit_events(session, "ui-root")) == 1


def test_ui_create_root_requires_browser_session_and_csrf(
    root_client: TestClient,
    root_state,
) -> None:
    anonymous = root_client.post(
        "/roots",
        data=_ui_root_form(root_state),
        follow_redirects=False,
    )
    assert anonymous.status_code == 303
    assert anonymous.headers["location"] == "/auth"

    _login(root_client, root_state["owner_session"])
    bad_csrf = root_client.post(
        "/roots",
        data=_ui_root_form(root_state, csrf_token="invalid-csrf"),
        follow_redirects=False,
    )
    assert bad_csrf.status_code == 403

    session_factory = root_state["session_factory"]
    with session_factory() as session:
        assert session.get(CatalogObject, "ui-root") is None


def test_ui_create_root_platform_admin_is_denied(
    root_client: TestClient,
    root_state,
) -> None:
    _login(root_client, root_state["admin_session"])
    response = root_client.post(
        "/roots",
        data=_ui_root_form(
            root_state,
            csrf_token=root_state["admin_session"].csrf_token,
        ),
        follow_redirects=False,
    )

    assert response.status_code == 403
    session_factory = root_state["session_factory"]
    with session_factory() as session:
        assert session.get(CatalogObject, "ui-root") is None
        assert _grants_for(session, "ui-root") == []
        event = session.scalar(
            select(SecurityEvent).where(
                SecurityEvent.event_type == "object_command_authorization",
                SecurityEvent.principal_id == root_state["human_admin_id"],
            )
        )
        assert event is not None
        assert event.outcome == "denied"
        assert event.channel == "ui"


def test_ui_create_root_validation_error_rerenders_typed_form(
    root_client: TestClient,
    root_state,
) -> None:
    _login(root_client, root_state["owner_session"])
    response = root_client.post(
        "/roots",
        data=_ui_root_form(root_state, object_id="Invalid Root ID!"),
        follow_redirects=False,
    )

    assert response.status_code == 422
    assert 'role="dialog"' in response.text
    assert 'role="alert"' in response.text
    assert 'value="Invalid Root ID!"' in response.text
    session_factory = root_state["session_factory"]
    with session_factory() as session:
        assert session.get(CatalogObject, "Invalid Root ID!") is None


def test_ui_create_root_conflict_error_is_rendered_safely(
    root_client: TestClient,
    root_state,
) -> None:
    _login(root_client, root_state["owner_session"])
    form = _ui_root_form(root_state, object_id="existing-object")
    response = root_client.post("/roots", data=form, follow_redirects=False)

    assert response.status_code == 409
    assert 'role="alert"' in response.text
    session_factory = root_state["session_factory"]
    with session_factory() as session:
        existing_grants = _grants_for(session, "existing-object")
        assert len(existing_grants) == 1
        assert existing_grants[0].principal_id == root_state["scoped_id"]
        assert _create_root_audit_events(session, "existing-object") == []


def test_ui_create_root_has_no_json_escape_hatch(
    root_client: TestClient,
    root_state,
) -> None:
    _login(root_client, root_state["owner_session"])
    response = root_client.post(
        "/roots",
        data=_ui_root_form(
            root_state,
            kind="system",
            platform="VM",
            data_json=json.dumps({"acl": {"readers": ["*"]}, "password": "x"}),
            idempotency_key="ui-escape-key-0001",
        ),
        follow_redirects=False,
    )

    assert response.status_code == 303
    session_factory = root_state["session_factory"]
    with session_factory() as session:
        row = session.get(CatalogObject, "ui-root")
        assert row is not None
        data = json.loads(row.data_json)
        assert data["platform"] == "VM"
        assert "acl" not in data
        assert "password" not in data
        _root_facts(session, "ui-root")


# ---------------------------------------------------------------------------
# MCP tool surface
# ---------------------------------------------------------------------------


def test_mcp_create_root_tool_contract() -> None:
    tool = TOOL_DEFINITIONS["blockwart.create_root"]
    assert tool["annotations"]["readOnlyHint"] is False
    assert tool["annotations"]["destructiveHint"] is False
    properties = tool["inputSchema"]["properties"]
    assert set(properties) == {"idempotency_key", "object"}
    assert set(tool["inputSchema"]["required"]) == {"idempotency_key", "object"}
    assert "catalog" not in tool["name"]
    assert "catalog_role" not in json.dumps(tool["inputSchema"])


def test_mcp_create_root_forwards_headers_and_proves_response() -> None:
    calls = []
    requested = {
        "id": "mcp-root",
        "kind": "host",
        "label": "MCP Root",
        "data": {"schema_version": 1},
    }

    def requester(method, path, body, headers):
        calls.append((method, path, body, headers))
        return {
            "catalog_object": {**body, "revision": 1, "parent_path": []},
            "etag": '"rev-1"',
            "changed": True,
            "replayed": False,
        }

    result = call_tool(
        "blockwart.create_root",
        {"idempotency_key": "mcp-root-key-00001", "object": requested},
        requester=requester,
    )

    normalized_calls = [
        (
            method,
            path,
            body,
            {key: value for key, value in headers.items() if key != "X-Correlation-ID"},
        )
        for method, path, body, headers in calls
    ]
    assert normalized_calls == [
        (
            "POST",
            "/api/v1/roots",
            requested,
            {
                "Idempotency-Key": "mcp-root-key-00001",
                "X-Blockwart-Channel": "mcp",
            },
        )
    ]
    assert all(
        re.fullmatch(r"[A-Za-z0-9._-]{1,64}", headers["X-Correlation-ID"])
        for _, _, _, headers in calls
    )
    payload = json.loads(result["content"][0]["text"])
    assert payload == {
        "catalog_object": {**requested, "revision": 1, "parent_path": []},
        "changed": True,
        "etag": '"rev-1"',
        "owner_assignment": {
            "principal": "authenticated_caller",
            "role": "owner",
            "scope": "self",
        },
        "parent_ref": None,
        "replayed": False,
        "revision": 1,
    }
    assert "relationship" not in payload
    assert "catalog_role" not in json.dumps(payload)


@pytest.mark.parametrize(
    "upstream",
    [
        pytest.param(
            {
                "catalog_object": {"id": "mcp-root", "kind": "host", "revision": 1},
                "etag": '"rev-1"',
                "changed": True,
                "replayed": False,
            },
            id="missing-parent-path",
        ),
        pytest.param(
            {
                "catalog_object": {
                    "id": "mcp-root",
                    "kind": "host",
                    "revision": 1,
                    "parent_path": [{"id": "parent"}],
                },
                "etag": '"rev-1"',
                "changed": True,
                "replayed": False,
            },
            id="unexpected-placement-parent",
        ),
        pytest.param(
            {
                "catalog_object": {
                    "id": "mcp-root",
                    "kind": "host",
                    "revision": 2,
                    "parent_path": [],
                },
                "etag": '"rev-1"',
                "changed": True,
                "replayed": False,
            },
            id="etag-revision-mismatch",
        ),
    ],
)
def test_mcp_create_root_rejects_invalid_upstream_proof(upstream: dict) -> None:
    def requester(_method, _path, _body, _headers):
        return upstream

    with pytest.raises(UpstreamError) as exc_info:
        call_tool(
            "blockwart.create_root",
            {
                "idempotency_key": "mcp-root-key-00002",
                "object": {
                    "id": "mcp-root",
                    "kind": "host",
                    "label": "MCP Root",
                },
            },
            requester=requester,
        )
    assert exc_info.value.code == "upstream_invalid_response"


def test_mcp_create_root_translates_stable_denial_envelope() -> None:
    def denying_requester(_method, _path, _body, _headers):
        raise UpstreamError(
            "forbidden",
            "Object permission denied.",
            "root-correlation-denied",
        )

    with pytest.raises(UpstreamError) as exc_info:
        call_tool(
            "blockwart.create_root",
            {
                "idempotency_key": "mcp-root-key-00003",
                "object": {"id": "mcp-root", "kind": "host", "label": "MCP Root"},
            },
            requester=denying_requester,
        )
    assert exc_info.value.code == "forbidden"
    assert exc_info.value.correlation_id == "root-correlation-denied"


def test_mcp_create_root_end_to_end_with_mcp_audience_token(
    root_client: TestClient,
    root_state,
) -> None:
    def requester(method, path, body, headers):
        response = root_client.request(
            method,
            path,
            json=body,
            headers={
                **headers,
                **_authorization(root_state["owner_mcp_token"]),
            },
        )
        if response.status_code >= 400:
            error = response.json().get("error", {})
            raise UpstreamError(
                str(error.get("code", "upstream_http_error")),
                str(error.get("message", "Blockwart Agent API returned an error.")),
            )
        return response.json()

    result = call_tool(
        "blockwart.create_root",
        {
            "idempotency_key": "mcp-e2e-root-key-01",
            "object": {
                "id": "mcp-e2e-root",
                "kind": "host",
                "label": "MCP Root",
                "data": {"schema_version": 1},
            },
        },
        requester=requester,
    )
    payload = json.loads(result["content"][0]["text"])

    assert payload["catalog_object"]["id"] == "mcp-e2e-root"
    assert payload["catalog_object"]["revision"] == 1
    assert payload["etag"] == '"rev-1"'
    assert payload["revision"] == 1
    assert payload["parent_ref"] is None
    assert payload["owner_assignment"] == {
        "principal": "authenticated_caller",
        "role": "owner",
        "scope": "self",
    }
    assert "relationship" not in payload

    session_factory = root_state["session_factory"]
    with session_factory() as session:
        _root_facts(session, "mcp-e2e-root")
        grant = _grants_for(session, "mcp-e2e-root")[0]
        assert grant.principal_id == root_state["owner_id"]
        events = _create_root_audit_events(session, "mcp-e2e-root")
        assert len(events) == 1
        assert '"channel":"mcp"' in events[0].details_json

    denied = root_client.post(
        "/api/v1/roots",
        headers={
            **_authorization(root_state["admin_token"]),
            "Idempotency-Key": "mcp-denied-key-0001",
            "X-Blockwart-Channel": "mcp",
        },
        json=_asset("mcp-denied-root").model_dump(mode="json"),
    )
    assert denied.status_code == 403
    assert denied.json()["error"]["code"] == "forbidden"


def test_mcp_root_write_never_adds_catalog_role_mutation_surface() -> None:
    write_tools = {
        name
        for name, tool in TOOL_DEFINITIONS.items()
        if tool.get("annotations", {}).get("readOnlyHint") is False
    }
    assert "blockwart.create_root" in write_tools
    assert not any("role" in name for name in TOOL_DEFINITIONS)
    assert not any(
        "catalog_role" in json.dumps(tool.get("inputSchema", {}))
        for tool in TOOL_DEFINITIONS.values()
    )
    assert not any(
        tool["inputSchema"].get("properties", {}).get("catalog_role")
        for tool in TOOL_DEFINITIONS.values()
    )


# ---------------------------------------------------------------------------
# REST/UI/MCP parity
# ---------------------------------------------------------------------------


def test_rest_ui_mcp_create_root_channels_produce_equal_outcomes(
    root_client: TestClient,
    root_state,
) -> None:
    rest_response = root_client.post(
        "/api/v1/roots",
        headers={
            **_authorization(root_state["owner_token"]),
            "Idempotency-Key": "parity-rest-key-001",
        },
        json=_asset("parity-rest", label="Parity Root").model_dump(mode="json"),
    )
    assert rest_response.status_code == 201

    _login(root_client, root_state["owner_session"])
    ui_response = root_client.post(
        "/roots",
        data=_ui_root_form(
            root_state,
            object_id="parity-ui",
            primary_name="Parity Root",
            labels="",
            platform="",
            summary="",
            idempotency_key="parity-ui-key-0001",
        ),
        follow_redirects=False,
    )
    assert ui_response.status_code == 303

    def requester(method, path, body, headers):
        response = root_client.request(
            method,
            path,
            json=body,
            headers={**headers, **_authorization(root_state["owner_mcp_token"])},
        )
        response.raise_for_status()
        return response.json()

    mcp_result = call_tool(
        "blockwart.create_root",
        {
            "idempotency_key": "test-test-test-five",
            "object": {
                "id": "parity-mcp",
                "kind": "host",
                "label": "Parity Root",
                "data": {"schema_version": 1},
            },
        },
        requester=requester,
    )
    mcp_payload = json.loads(mcp_result["content"][0]["text"])
    assert mcp_payload["etag"] == '"rev-1"'

    session_factory = root_state["session_factory"]
    expected_channels = {
        "parity-rest": "api",
        "parity-ui": "ui",
        "parity-mcp": "mcp",
    }
    expected_creators = {
        "parity-rest": root_state["owner_id"],
        "parity-ui": root_state["human_owner_id"],
        "parity-mcp": root_state["owner_id"],
    }
    with session_factory() as session:
        for object_id, channel in expected_channels.items():
            row = session.get(CatalogObject, object_id)
            assert row is not None
            assert row.kind == "host"
            assert row.revision == 1
            _root_facts(session, object_id)
            grant = _grants_for(session, object_id)[0]
            assert grant.principal_id == expected_creators[object_id]
            events = _create_root_audit_events(session, object_id)
            assert len(events) == 1
            assert f'"channel":"{channel}"' in events[0].details_json
            assert '"old_revision":0' in events[0].details_json
            assert '"new_revision":1' in events[0].details_json

        total_grants = session.scalar(
            select(func.count())
            .select_from(ObjectGrant)
            .where(
                ObjectGrant.object_id.in_(
                    ["parity-rest", "parity-ui", "parity-mcp"]
                )
            )
        )
        assert total_grants == 3
