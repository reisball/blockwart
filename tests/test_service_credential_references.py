"""Delegable, service-bound credential-reference creation (issue #236).

A credential reference is catalog metadata naming where a credential lives. It
is never a placement child, and linking it changes the data of the service that
uses it. Before this capability, ``creator/self`` on a service could create only
placement children, ``create_root`` needed ``catalog_owner``, and the link needed
unrestricted ``write`` on the service. These tests pin the narrow delegation
that closes that gap:

* the positive path — a principal holding only ``credential_reference_creator``
  on one service creates the reference and its single access-method link in one
  atomic, idempotent call through REST and MCP, and becomes its explicit Owner;
* the boundary — other services, unrelated fields, other access methods,
  existing references, relationships, and grants stay unchanged, and no role
  without the dedicated capability can use the command;
* the failure contract — stale ETags, missing access methods, reused IDs,
  unreadable reference targets, secret values, retries, concurrency, and
  injected write failures are deterministic and leave no partial link, orphan
  object, grant, idempotency record, or audit event; and
* the published contract — capabilities, describe_schema, and the grant-role
  vocabulary name the capability instead of leaving a caller to probe for it.
"""

from __future__ import annotations

import json
from collections.abc import Generator
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import event as sqlalchemy_event
from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from blockwart.api.deps import get_session
from blockwart.db.session import transaction
from blockwart.domain.auth import (
    CatalogRole,
    GrantScope,
    Permission,
    Role,
    permissions_for_catalog_role,
    permissions_for_role,
)
from blockwart.main import create_app
from blockwart.mcp.server import (
    GRANT_ROLE_SCHEMA,
    SERVICE_CREDENTIAL_REFERENCE_TOOL,
    TOOL_DEFINITIONS,
    TOOL_INPUT_VALIDATORS,
    ToolInputError,
    UpstreamError,
    call_tool,
    describe_schema_payload,
)
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
from blockwart.services.catalog import create_relationship, upsert_object
from blockwart.services.identity import create_service_account, issue_service_token
from blockwart.services.policy import policy_for_principal

CREATE_PATH = "/api/v1/objects/{service_id}/credential-references"
SERVICE_ID = "billing-api"
OTHER_SERVICE_ID = "ledger-api"
HIDDEN_SERVICE_ID = "hidden-api"
HOST_ID = "billing-host"
EXISTING_REFERENCE_ID = "billing-ssh-key"
HIDDEN_REFERENCE_ID = "hidden-vault-entry"
NEW_REFERENCE_ID = "billing-api-operator"
EXISTING_REFERENCE_REF = f"credential_reference:{EXISTING_REFERENCE_ID}"
OWNER_PERMISSIONS = sorted(permission.value for permission in Permission)
# Every grant role that is not supposed to authorize the command, including
# the one the original report tried first.
ROLES_WITHOUT_THE_CAPABILITY = (
    Role.DISCOVERER,
    Role.VIEWER,
    Role.RENAMER,
    Role.EDITOR,
    Role.CREATOR,
    Role.ACCESS_MANAGER,
)


def _service_data() -> dict:
    return {
        "schema_version": 1,
        "owner": "Billing team",
        "criticality": "critical",
        "endpoints": [
            {
                "id": "api",
                "type": "REST API",
                "url": "https://billing.example.test/api",
                "exposure": "internal",
            }
        ],
        "access_methods": [
            # Stored the way the browser UI and imports write them: no stable
            # id and no reference list yet.
            {"type": "admin_api", "endpoint_id": "api", "auth_mode": "key"},
            {
                "id": "ssh-admin",
                "type": "ssh",
                "endpoint": "ssh://billing.example.test:22",
                "auth_mode": "key",
                "credential_references": [EXISTING_REFERENCE_REF],
            },
        ],
        "credential_references": [EXISTING_REFERENCE_REF],
    }


def _reference_payload(
    object_id: str = NEW_REFERENCE_ID,
    *,
    data: dict | None = None,
    **overrides: object,
) -> dict:
    payload: dict = {
        "id": object_id,
        "kind": "credential_reference",
        "label": "Billing API operator credential",
        "summary": "Where the billing admin API operator credential is kept",
        "data": data
        if data is not None
        else {
            "schema_version": 1,
            "provider": "infisical",
            "reference": {"path": "/apps/billing", "key": "API_KEY"},
            "scope": {"access_type": "api", "services": [f"service:{SERVICE_ID}"]},
            "used_by": {"services": [f"service:{SERVICE_ID}"]},
            "handling_rules": {"telegram_allowed": False},
            "secret_value_stored": False,
        },
    }
    payload.update(overrides)
    return payload


def _asset(object_id: str, kind: str, data: dict | None = None) -> CatalogObjectIn:
    return CatalogObjectIn(
        id=object_id,
        kind=kind,
        label=object_id,
        lifecycle="active",
        health="healthy",
        data=data if data is not None else {"schema_version": 1},
    )


def _credential_reference(object_id: str) -> CatalogObjectIn:
    return CatalogObjectIn(
        id=object_id,
        kind="credential_reference",
        label=object_id,
        data={"schema_version": 1, "provider": "vaultwarden"},
    )


@pytest.fixture
def link_state(alembic_session_factory):
    """One placed service, neighbours, and one principal per authority under test."""
    principals: dict[str, str] = {}
    tokens: dict[str, str] = {}
    with alembic_session_factory() as session:
        with transaction(session):
            upsert_object(session, _asset(HOST_ID, "host"))
            upsert_object(session, _credential_reference(EXISTING_REFERENCE_ID))
            upsert_object(session, _credential_reference(HIDDEN_REFERENCE_ID))
            upsert_object(session, _asset(SERVICE_ID, "service", _service_data()))
            upsert_object(session, _asset(OTHER_SERVICE_ID, "service", _service_data()))
            upsert_object(session, _asset(HIDDEN_SERVICE_ID, "service"))
            create_relationship(
                session,
                from_ref=f"host:{HOST_ID}",
                relation_type="hosts",
                to_ref=f"service:{SERVICE_ID}",
            )

            def principal(key: str, **kwargs: object) -> str:
                created = create_service_account(
                    session,
                    login=f"{key.replace('_', '-')}.agent",
                    display_name=key,
                    **kwargs,
                )
                principals[key] = created.id
                tokens[key] = issue_service_token(
                    session,
                    principal_id=created.id,
                    name="api-writes",
                ).value
                return created.id

            def grant(key: str, object_id: str, role: Role, scope=GrantScope.SELF) -> None:
                create_object_grant(
                    session,
                    principal_id=principals[key],
                    object_id=object_id,
                    role=role,
                    scope=scope,
                )

            principal("service_owner")
            grant("service_owner", SERVICE_ID, Role.OWNER)
            grant("service_owner", OTHER_SERVICE_ID, Role.OWNER)
            principal("delegate")
            grant("delegate", SERVICE_ID, Role.CREDENTIAL_REFERENCE_CREATOR)
            # Readable elsewhere without the capability: the cross-service case.
            grant("delegate", OTHER_SERVICE_ID, Role.VIEWER)
            grant("delegate", EXISTING_REFERENCE_ID, Role.VIEWER)
            tokens["delegate_mcp"] = issue_service_token(
                session,
                principal_id=principals["delegate"],
                name="mcp-writes",
                audience="mcp",
            ).value
            principal("subtree_delegate")
            grant(
                "subtree_delegate",
                HOST_ID,
                Role.CREDENTIAL_REFERENCE_CREATOR,
                GrantScope.SUBTREE,
            )
            for role in ROLES_WITHOUT_THE_CAPABILITY:
                principal(role.value)
                grant(role.value, SERVICE_ID, role)
            principal("catalog_owner", catalog_role=CatalogRole.CATALOG_OWNER)
            principal("catalog_viewer", catalog_role=CatalogRole.CATALOG_VIEWER)
            principal("outsider")
    return {
        "session_factory": alembic_session_factory,
        "principals": principals,
        "tokens": tokens,
    }


@pytest.fixture
def link_client(link_state) -> Generator[TestClient, None, None]:
    session_factory = link_state["session_factory"]
    app = create_app()

    def override_get_session() -> Generator[Session, None, None]:
        with session_factory() as session:
            yield session

    app.dependency_overrides[get_session] = override_get_session
    with TestClient(app, base_url="https://testserver") as client:
        yield client


def _authorization(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _etag(client: TestClient, token: str, object_id: str = SERVICE_ID) -> str:
    response = client.get(f"/api/v1/objects/{object_id}", headers=_authorization(token))
    assert response.status_code == 200, response.text
    return response.headers["etag"]


def _create(
    client: TestClient,
    token: str,
    *,
    key: str,
    etag: str | None,
    service_id: str = SERVICE_ID,
    index: object = 0,
    reference: dict | None = None,
    channel: str | None = None,
):
    headers = {**_authorization(token), "Idempotency-Key": key}
    if etag is not None:
        headers["If-Match"] = etag
    if channel is not None:
        headers["X-Blockwart-Channel"] = channel
    return client.post(
        CREATE_PATH.format(service_id=service_id),
        headers=headers,
        json={
            "access_method_index": index,
            "credential_reference": reference or _reference_payload(),
        },
    )


def _object_rows(session: Session) -> dict[str, tuple]:
    return {
        row.id: (
            row.kind,
            row.label,
            row.status,
            row.lifecycle,
            row.health,
            row.summary,
            json.loads(row.data_json),
            row.provenance_json,
            row.revision,
            row.updated_at,
        )
        for row in session.scalars(select(CatalogObject)).all()
    }


def _grant_rows(session: Session) -> set[tuple]:
    return {
        (
            row.id,
            row.principal_id,
            row.object_id,
            row.role,
            row.scope,
            row.created_by_principal_id,
        )
        for row in session.scalars(select(ObjectGrant)).all()
    }


def _relationship_rows(session: Session) -> set[tuple]:
    return {
        (row.from_ref, row.relation_type, row.to_ref, row.metadata_json)
        for row in session.scalars(select(Relationship)).all()
    }


def _count(session: Session, model) -> int:
    return int(session.scalar(select(func.count()).select_from(model)) or 0)


def _snapshot(link_state) -> dict:
    with link_state["session_factory"]() as session:
        return {
            "objects": _object_rows(session),
            "grants": _grant_rows(session),
            "relationships": _relationship_rows(session),
            "audit_events": _count(session, AuditEvent),
            "idempotency_records": _count(session, IdempotencyRecord),
        }


def _assert_nothing_changed(link_state, before: dict) -> None:
    after = _snapshot(link_state)
    assert after == before
    with link_state["session_factory"]() as session:
        assert session.get(CatalogObject, NEW_REFERENCE_ID) is None


def _audit_events(session: Session, object_id: str) -> list[AuditEvent]:
    return list(
        session.scalars(
            select(AuditEvent)
            .where(AuditEvent.object_id == object_id)
            .order_by(AuditEvent.id)
        ).all()
    )


# ---------------------------------------------------------------------------
# The capability itself
# ---------------------------------------------------------------------------


def test_the_role_carries_only_the_dedicated_capability() -> None:
    assert permissions_for_role(Role.CREDENTIAL_REFERENCE_CREATOR) == {
        Permission.DISCOVER,
        Permission.READ,
        Permission.CREATE_CREDENTIAL_REFERENCE,
    }
    # Owner and the global catalog owner carry every permission, as before.
    assert Permission.CREATE_CREDENTIAL_REFERENCE in permissions_for_role(Role.OWNER)
    assert Permission.CREATE_CREDENTIAL_REFERENCE in permissions_for_catalog_role(
        CatalogRole.CATALOG_OWNER
    )
    # No existing role is silently widened, and the new role implies neither
    # placement-child creation nor general write.
    for role in ROLES_WITHOUT_THE_CAPABILITY:
        assert Permission.CREATE_CREDENTIAL_REFERENCE not in permissions_for_role(role)
    for catalog_role in (CatalogRole.CATALOG_VIEWER, CatalogRole.PROJECT_CREATOR):
        assert Permission.CREATE_CREDENTIAL_REFERENCE not in permissions_for_catalog_role(
            catalog_role
        )
    assert Permission.CREATE_CHILD not in permissions_for_role(
        Role.CREDENTIAL_REFERENCE_CREATOR
    )
    assert Permission.WRITE not in permissions_for_role(Role.CREDENTIAL_REFERENCE_CREATOR)


def test_capabilities_distinguish_service_bound_creation_from_placement(
    link_client: TestClient,
    link_state,
) -> None:
    tokens = link_state["tokens"]
    delegate = link_client.get(
        f"/api/v1/objects/{SERVICE_ID}", headers=_authorization(tokens["delegate"])
    )
    creator = link_client.get(
        f"/api/v1/objects/{SERVICE_ID}", headers=_authorization(tokens["creator"])
    )
    subtree = link_client.get(
        f"/api/v1/objects/{SERVICE_ID}",
        headers=_authorization(tokens["subtree_delegate"]),
    )

    assert delegate.json()["capabilities"] == [
        "discover",
        "read",
        "create_credential_reference",
    ]
    # The role in the original report creates placement children only.
    assert creator.json()["capabilities"] == ["discover", "read", "create_child"]
    assert subtree.json()["capabilities"] == [
        "discover",
        "read",
        "create_credential_reference",
    ]


# ---------------------------------------------------------------------------
# Positive path
# ---------------------------------------------------------------------------


def test_delegate_creates_and_links_one_reference_atomically(
    link_client: TestClient,
    link_state,
) -> None:
    tokens = link_state["tokens"]
    delegate_id = link_state["principals"]["delegate"]
    etag = _etag(link_client, tokens["delegate"])
    before = _snapshot(link_state)

    response = _create(
        link_client,
        tokens["delegate"],
        key="delegate-create-key-0001",
        etag=etag,
        index=0,
    )

    assert response.status_code == 201, response.text
    body = response.json()
    service_revision = before["objects"][SERVICE_ID][8] + 1
    assert body["credential_reference"]["id"] == NEW_REFERENCE_ID
    assert body["credential_reference"]["kind"] == "credential_reference"
    assert body["credential_reference"]["parent_path"] == []
    assert body["credential_reference"]["capabilities"] == OWNER_PERMISSIONS
    assert body["etag"] == '"rev-1"'
    assert body["service_id"] == SERVICE_ID
    assert body["service_revision"] == service_revision
    assert body["service_etag"] == f'"rev-{service_revision}"'
    assert body["access_method_index"] == 0
    assert body["link_path"] == "data.access_methods[0].credential_references"
    assert body["owner_grant"] == {
        "principal_id": delegate_id,
        "role": "owner",
        "scope": "self",
    }
    assert body["changed"] is True
    assert body["replayed"] is False
    assert response.headers["etag"] == '"rev-1"'
    assert response.headers["location"] == f"/api/v1/objects/{NEW_REFERENCE_ID}"

    after = _snapshot(link_state)
    new_ref = f"credential_reference:{NEW_REFERENCE_ID}"
    # Exactly the one list changed on the service; its revision advanced once.
    expected_service_data = _service_data()
    expected_service_data["access_methods"][0]["credential_references"] = [new_ref]
    service_before = before["objects"][SERVICE_ID]
    service_after = after["objects"][SERVICE_ID]
    assert service_after[6] == expected_service_data
    assert service_after[:6] == service_before[:6]
    assert service_after[7] == service_before[7]
    assert service_after[8] == service_revision
    # Every other object, including the neighbouring service that shares the
    # same data, is untouched; only the new reference was added.
    unchanged = {
        object_id: row
        for object_id, row in after["objects"].items()
        if object_id not in {SERVICE_ID, NEW_REFERENCE_ID}
    }
    assert unchanged == {
        object_id: row
        for object_id, row in before["objects"].items()
        if object_id != SERVICE_ID
    }
    reference = after["objects"][NEW_REFERENCE_ID]
    assert reference[0] == "credential_reference"
    assert reference[6] == _reference_payload()["data"]
    assert reference[8] == 1
    # Exactly one new grant: the creator's direct Owner/self on the new object.
    new_grants = after["grants"] - before["grants"]
    assert before["grants"] <= after["grants"]
    assert {grant[1:] for grant in new_grants} == {
        (delegate_id, NEW_REFERENCE_ID, "owner", "self", delegate_id)
    }
    # No placement parent, no relationship: the link is a typed data reference.
    assert after["relationships"] == before["relationships"]
    assert after["audit_events"] == before["audit_events"] + 2
    assert after["idempotency_records"] == before["idempotency_records"] + 1

    with link_state["session_factory"]() as session:
        created_events = _audit_events(session, NEW_REFERENCE_ID)
        link_events = _audit_events(session, SERVICE_ID)
    assert [event.action for event in created_events] == [
        "create_service_credential_reference"
    ]
    created = json.loads(created_events[0].details_json)
    assert created_events[0].actor == delegate_id
    assert created["channel"] == "api"
    assert created["object_ref"] == new_ref
    assert created["parent_ref"] is None
    assert created["service_ref"] == f"service:{SERVICE_ID}"
    assert created["link_path"] == "data.access_methods[0].credential_references"
    assert created["creator_owner_grant"] == {
        "principal_id": delegate_id,
        "role": "owner",
        "scope": "self",
    }
    assert created["affected_revisions"] == {SERVICE_ID: service_revision}
    link = json.loads(link_events[-1].details_json)
    assert link_events[-1].action == "credential_reference_link"
    assert link_events[-1].actor == delegate_id
    assert link["old_revision"] == service_before[8]
    assert link["new_revision"] == service_revision
    assert link["credential_reference_ref"] == new_ref
    assert link["access_method_index"] == 0
    assert link["changes"] == [
        {
            "field": "data.access_methods[0].credential_references",
            "before": [],
            "after": [new_ref],
            "old": "",
            "new": "",
            "value_change": False,
        }
    ]
    assert link["before"]["data"] == _service_data()
    assert link["after"]["data"] == expected_service_data


def test_appending_keeps_existing_references_of_the_access_method(
    link_client: TestClient,
    link_state,
) -> None:
    tokens = link_state["tokens"]
    response = _create(
        link_client,
        tokens["delegate"],
        key="delegate-append-key-0001",
        etag=_etag(link_client, tokens["delegate"]),
        index=1,
    )

    assert response.status_code == 201, response.text
    assert response.json()["link_path"] == "data.access_methods[1].credential_references"
    with link_state["session_factory"]() as session:
        data = json.loads(session.get(CatalogObject, SERVICE_ID).data_json)
    assert data["access_methods"][1]["credential_references"] == [
        EXISTING_REFERENCE_REF,
        f"credential_reference:{NEW_REFERENCE_ID}",
    ]
    # The other access method and the service-level list are untouched.
    assert data["access_methods"][0] == _service_data()["access_methods"][0]
    assert data["credential_references"] == [EXISTING_REFERENCE_REF]


def test_new_ownership_grants_maintenance_of_the_reference_only(
    link_client: TestClient,
    link_state,
) -> None:
    tokens = link_state["tokens"]
    delegate = _authorization(tokens["delegate"])
    created = _create(
        link_client,
        tokens["delegate"],
        key="delegate-maintain-key-01",
        etag=_etag(link_client, tokens["delegate"]),
    )
    assert created.status_code == 201, created.text
    reference_etag = created.json()["etag"]
    service_etag = created.json()["service_etag"]

    read = link_client.get(f"/api/v1/objects/{NEW_REFERENCE_ID}", headers=delegate)
    assert read.status_code == 200
    assert read.json()["visibility"] == "detail"
    assert read.json()["capabilities"] == [permission.value for permission in Permission]

    maintained = _reference_payload(summary="Rotated to the new vault path")
    maintained["data"]["reference"]["path"] = "/apps/billing-v2"
    update = link_client.put(
        f"/api/v1/objects/{NEW_REFERENCE_ID}",
        headers={**delegate, "If-Match": reference_etag},
        json=maintained,
    )
    assert update.status_code == 200, update.text
    renamed = link_client.post(
        f"/api/v1/objects/{NEW_REFERENCE_ID}/rename",
        headers={**delegate, "If-Match": update.json()["etag"]},
        json={"new_label": "Billing API operator credential v2"},
    )
    assert renamed.status_code == 200, renamed.text

    # The delegation still grants no service editing and cannot unlink: the
    # linked reference cannot be deleted from under the service either.
    service_update = link_client.put(
        f"/api/v1/objects/{SERVICE_ID}",
        headers={**delegate, "If-Match": service_etag},
        json=_asset(SERVICE_ID, "service", _service_data()).model_dump(mode="json"),
    )
    assert service_update.status_code == 403
    delete = link_client.delete(
        f"/api/v1/objects/{NEW_REFERENCE_ID}",
        headers={**delegate, "If-Match": renamed.json()["etag"]},
    )
    assert delete.status_code == 409

    with link_state["session_factory"]() as session:
        policy = policy_for_principal(session, link_state["principals"]["delegate"])
        assert policy.permissions_for(SERVICE_ID) == {
            Permission.DISCOVER,
            Permission.READ,
            Permission.CREATE_CREDENTIAL_REFERENCE,
        }
        assert policy.permissions_for(NEW_REFERENCE_ID) == set(Permission)
        # The service owner still sees and controls its own link.
        service = session.get(CatalogObject, SERVICE_ID)
        assert f"credential_reference:{NEW_REFERENCE_ID}" in service.data_json


@pytest.mark.parametrize("principal_key", ["service_owner", "catalog_owner"])
def test_owners_hold_the_capability_through_their_existing_authority(
    link_client: TestClient,
    link_state,
    principal_key: str,
) -> None:
    token = link_state["tokens"][principal_key]
    response = _create(
        link_client,
        token,
        key=f"{principal_key}-create-key-0001",
        etag=_etag(link_client, token),
    )

    assert response.status_code == 201, response.text
    assert response.json()["owner_grant"]["principal_id"] == (
        link_state["principals"][principal_key]
    )


def test_subtree_grant_reaches_only_services_placed_below_its_anchor(
    link_client: TestClient,
    link_state,
) -> None:
    token = link_state["tokens"]["subtree_delegate"]
    placed = _create(
        link_client,
        token,
        key="subtree-create-key-0001",
        etag=_etag(link_client, token),
    )
    unplaced = _create(
        link_client,
        token,
        key="subtree-create-key-0002",
        etag='"rev-1"',
        service_id=OTHER_SERVICE_ID,
        reference=_reference_payload("ledger-api-operator"),
    )

    assert placed.status_code == 201, placed.text
    assert unplaced.status_code == 404


def test_mcp_tool_creates_and_links_through_the_same_command(
    link_client: TestClient,
    link_state,
) -> None:
    tokens = link_state["tokens"]
    etag = _etag(link_client, tokens["delegate"])

    def requester(method, path, body, headers):
        response = link_client.request(
            method,
            path,
            json=body,
            headers={**headers, **_authorization(tokens["delegate_mcp"])},
        )
        if response.status_code >= 400:
            error = response.json().get("error", {})
            raise UpstreamError(str(error.get("code")), str(error.get("message")))
        return response.json()

    arguments = {
        "service_id": SERVICE_ID,
        "access_method_index": 0,
        "if_match": etag,
        "idempotency_key": "mcp-service-reference-01",
        "credential_reference": _reference_payload(),
    }
    result = call_tool(SERVICE_CREDENTIAL_REFERENCE_TOOL, arguments, requester=requester)
    payload = json.loads(result["content"][0]["text"])

    assert result["isError"] is False
    assert payload["credential_reference"]["id"] == NEW_REFERENCE_ID
    assert payload["service_ref"] == f"service:{SERVICE_ID}"
    assert payload["link_path"] == "data.access_methods[0].credential_references"
    assert payload["revision"] == 1
    assert payload["owner_assignment"] == {
        "principal": "authenticated_caller",
        "role": "owner",
        "scope": "self",
    }
    replay = json.loads(
        call_tool(SERVICE_CREDENTIAL_REFERENCE_TOOL, arguments, requester=requester)[
            "content"
        ][0]["text"]
    )
    assert replay["replayed"] is True
    assert replay["credential_reference"] == payload["credential_reference"]
    with link_state["session_factory"]() as session:
        events = _audit_events(session, NEW_REFERENCE_ID)
        assert len(events) == 1
        assert '"channel":"mcp"' in events[0].details_json

    with pytest.raises(UpstreamError) as denial:
        call_tool(
            SERVICE_CREDENTIAL_REFERENCE_TOOL,
            {
                **arguments,
                "service_id": OTHER_SERVICE_ID,
                "idempotency_key": "mcp-service-reference-02",
                "credential_reference": _reference_payload("ledger-api-operator"),
            },
            requester=requester,
        )
    assert denial.value.code == "create_credential_reference_required"


@pytest.mark.parametrize("granting_key", ["service_owner", "access_manager"])
def test_the_supported_delegation_path_uses_only_the_normal_grant_commands(
    link_client: TestClient,
    link_state,
    granting_key: str,
) -> None:
    tokens = link_state["tokens"]
    principals = link_state["principals"]
    grantor = _authorization(tokens[granting_key])
    agent = _authorization(tokens["outsider"])
    access = link_client.get(f"/api/v1/objects/{SERVICE_ID}/access", headers=grantor)
    assert access.status_code == 200, access.text

    granted = link_client.post(
        f"/api/v1/objects/{SERVICE_ID}/access/grants",
        headers={**grantor, "If-Match": access.json()["etag"]},
        json={
            "principal_id": principals["outsider"],
            "role": "credential_reference_creator",
            "scope": "self",
        },
    )
    assert granted.status_code == 201, granted.text
    service = link_client.get(f"/api/v1/objects/{SERVICE_ID}", headers=agent)
    assert service.json()["capabilities"] == [
        "discover",
        "read",
        "create_credential_reference",
    ]

    created = _create(
        link_client,
        tokens["outsider"],
        key=f"delegated-by-{granting_key}-01",
        etag=service.headers["etag"],
    )

    assert created.status_code == 201, created.text
    with link_state["session_factory"]() as session:
        agent_row = session.get(Principal, principals["outsider"])
        # No catalog role or root-creation capability was assigned on the way.
        assert agent_row.catalog_role is None
        assert agent_row.project_creator is False
        assert {
            (grant.object_id, grant.role)
            for grant in session.scalars(
                select(ObjectGrant).where(ObjectGrant.principal_id == principals["outsider"])
            )
        } == {
            (SERVICE_ID, "credential_reference_creator"),
            (NEW_REFERENCE_ID, "owner"),
        }


def test_mcp_arguments_are_validated_field_accurately() -> None:
    def no_upstream(*_args, **_kwargs):
        raise AssertionError("rejected arguments must not reach the API")

    with pytest.raises(ToolInputError) as rejected:
        call_tool(
            SERVICE_CREDENTIAL_REFERENCE_TOOL,
            {
                "service_id": SERVICE_ID,
                "access_method_index": -1,
                "if_match": '"rev-1"',
                "idempotency_key": "mcp-invalid-arguments-1",
                "credential_reference": {**_reference_payload(), "kind": "service"},
            },
            requester=no_upstream,
            fetcher=no_upstream,
        )

    details = {(detail["location"], detail["code"]) for detail in rejected.value.details}
    assert ("access_method_index", "value_out_of_range") in details
    assert ("credential_reference.kind", "value_not_constant") in details
    with pytest.raises(ToolInputError) as missing:
        call_tool(
            SERVICE_CREDENTIAL_REFERENCE_TOOL,
            {"service_id": SERVICE_ID, "credential_reference": _reference_payload()},
            requester=no_upstream,
            fetcher=no_upstream,
        )
    missing_arguments = {
        detail["location"]
        for detail in missing.value.details
        if detail["code"] == "required_field_missing"
    }
    assert missing_arguments == {"access_method_index", "if_match", "idempotency_key"}


# ---------------------------------------------------------------------------
# Authorization boundary
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "principal_key",
    [role.value for role in ROLES_WITHOUT_THE_CAPABILITY] + ["catalog_viewer"],
)
def test_roles_without_the_capability_are_denied_with_its_name(
    link_client: TestClient,
    link_state,
    principal_key: str,
) -> None:
    token = link_state["tokens"][principal_key]
    # A discover-only stub carries no ETag, so use the current one; the
    # capability is decided before the precondition either way.
    etag = _etag(link_client, link_state["tokens"]["service_owner"])
    before = _snapshot(link_state)

    response = _create(
        link_client,
        token,
        key=f"{principal_key}-denied-key-0001",
        etag=etag,
    )

    assert response.status_code == 403
    error = response.json()["error"]
    assert error["code"] == "create_credential_reference_required"
    assert "create_credential_reference" in error["message"]
    _assert_nothing_changed(link_state, before)
    with link_state["session_factory"]() as session:
        denial = session.scalar(
            select(SecurityEvent)
            .where(
                SecurityEvent.event_type == "object_command_authorization",
                SecurityEvent.principal_id == link_state["principals"][principal_key],
            )
            .order_by(SecurityEvent.id.desc())
        )
    assert denial is not None
    assert denial.outcome == "denied"
    details = json.loads(denial.details_json)
    assert details["object_id"] == SERVICE_ID
    assert details["permission"] == "create_credential_reference"
    assert details["reason"] == "create_credential_reference_required"


def test_undiscoverable_service_is_indistinguishable_from_a_missing_one(
    link_client: TestClient,
    link_state,
) -> None:
    token = link_state["tokens"]["outsider"]
    before = _snapshot(link_state)

    concealed = _create(link_client, token, key="outsider-key-000001", etag='"rev-1"')
    missing = _create(
        link_client,
        token,
        key="outsider-key-000002",
        etag='"rev-1"',
        service_id="no-such-service",
    )

    assert concealed.status_code == missing.status_code == 404
    assert concealed.json()["error"]["code"] == missing.json()["error"]["code"]
    assert concealed.json()["error"]["message"] == missing.json()["error"]["message"]
    _assert_nothing_changed(link_state, before)


def test_delegation_on_one_service_does_not_reach_another(
    link_client: TestClient,
    link_state,
) -> None:
    token = link_state["tokens"]["delegate"]
    before = _snapshot(link_state)

    readable_other = _create(
        link_client,
        token,
        key="cross-service-key-0001",
        etag=_etag(link_client, token, OTHER_SERVICE_ID),
        service_id=OTHER_SERVICE_ID,
    )
    concealed_other = _create(
        link_client,
        token,
        key="cross-service-key-0002",
        etag='"rev-1"',
        service_id=HIDDEN_SERVICE_ID,
    )

    assert readable_other.status_code == 403
    assert readable_other.json()["error"]["code"] == "create_credential_reference_required"
    assert concealed_other.status_code == 404
    _assert_nothing_changed(link_state, before)


def test_only_services_accept_a_bound_credential_reference(
    link_client: TestClient,
    link_state,
) -> None:
    # The subtree grant carries the capability on its host anchor as well, but
    # the command binds references to services only.
    token = link_state["tokens"]["subtree_delegate"]
    before = _snapshot(link_state)

    response = _create(
        link_client,
        token,
        key="host-target-key-00001",
        etag=_etag(link_client, token, HOST_ID),
        service_id=HOST_ID,
    )

    assert response.status_code == 409
    assert response.json()["error"]["code"] == "credential_reference_requires_service"
    _assert_nothing_changed(link_state, before)


# ---------------------------------------------------------------------------
# References: no reuse, readable targets only, secrets rejected
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "reused_id",
    [EXISTING_REFERENCE_ID, HIDDEN_REFERENCE_ID, SERVICE_ID, HOST_ID],
)
def test_existing_ids_are_refused_and_never_linked(
    link_client: TestClient,
    link_state,
    reused_id: str,
) -> None:
    token = link_state["tokens"]["delegate"]
    before = _snapshot(link_state)

    response = _create(
        link_client,
        token,
        key=f"reuse-{reused_id}-key-01"[:64],
        etag=_etag(link_client, token),
        reference=_reference_payload(reused_id),
    )

    assert response.status_code == 409
    assert response.json()["error"]["code"] == "credential_reference_id_unavailable"
    # The existing object is neither linked, re-owned, nor changed.
    assert _snapshot(link_state) == before


def test_an_id_already_held_by_a_dangling_reference_is_refused(
    link_client: TestClient,
    link_state,
) -> None:
    dangling = f"credential_reference:{NEW_REFERENCE_ID}"
    with link_state["session_factory"]() as session:
        with transaction(session):
            data = _service_data()
            data["access_methods"][0]["credential_references"] = [dangling]
            session.execute(
                text("UPDATE catalog_objects SET data_json = :data WHERE id = :id"),
                {"data": json.dumps(data, sort_keys=True), "id": HIDDEN_SERVICE_ID},
            )
    token = link_state["tokens"]["delegate"]
    before = _snapshot(link_state)

    response = _create(
        link_client,
        token,
        key="dangling-holder-key-01",
        etag=_etag(link_client, token),
    )

    # Creating the object would silently bind the concealed service's legacy
    # reference to it, so the ID is unavailable instead.
    assert response.status_code == 409
    assert response.json()["error"]["code"] == "credential_reference_id_unavailable"
    _assert_nothing_changed(link_state, before)


@pytest.mark.parametrize(
    "target",
    [f"service:{HIDDEN_SERVICE_ID}", "service:no-such-service", f"system:{SERVICE_ID}"],
)
def test_reference_data_may_only_name_objects_the_caller_can_read(
    link_client: TestClient,
    link_state,
    target: str,
) -> None:
    token = link_state["tokens"]["delegate"]
    payload = _reference_payload()
    payload["data"]["used_by"] = {"services": [target]}
    before = _snapshot(link_state)

    response = _create(
        link_client,
        token,
        key="unreadable-target-key-1",
        etag=_etag(link_client, token),
        reference=payload,
    )

    # A concealed, a missing, and a kind-mismatched target are not told apart.
    assert response.status_code in {404, 422}
    if target.startswith("service:"):
        assert response.status_code == 404
        assert response.json()["error"]["code"] == "not_found"
    _assert_nothing_changed(link_state, before)


@pytest.mark.parametrize(
    ("path", "value"),
    [
        (("reference", "password"), "correct-horse-battery-staple"),
        (("reference", "name"), "Bearer abcdefghijklmnopqrstuvwxyz0123456789"),
        (("reference", "value"), "raw credential value"),
        (("reference", "path"), "postgres://billing:hunter2@db.example.test/billing"),
    ],
)
def test_secret_values_are_rejected_before_anything_is_written(
    link_client: TestClient,
    link_state,
    path: tuple[str, str],
    value: str,
) -> None:
    token = link_state["tokens"]["delegate"]
    payload = _reference_payload()
    payload["data"][path[0]][path[1]] = value
    before = _snapshot(link_state)

    response = _create(
        link_client,
        token,
        key="secret-value-key-000001",
        etag=_etag(link_client, token),
        reference=payload,
    )

    assert response.status_code == 422
    assert response.json()["error"]["code"] == "validation_error"
    assert value not in response.text
    _assert_nothing_changed(link_state, before)


def test_the_body_accepts_only_a_credential_reference_and_the_index(
    link_client: TestClient,
    link_state,
) -> None:
    token = link_state["tokens"]["delegate"]
    etag = _etag(link_client, token)
    before = _snapshot(link_state)
    headers = {
        **_authorization(token),
        "Idempotency-Key": "closed-body-key-00001",
        "If-Match": etag,
    }

    wrong_kind = _create(
        link_client,
        token,
        key="closed-body-key-00002",
        etag=etag,
        reference={**_reference_payload(), "kind": "service", "data": {"schema_version": 1}},
    )
    smuggled = link_client.post(
        CREATE_PATH.format(service_id=SERVICE_ID),
        headers=headers,
        json={
            "access_method_index": 0,
            "credential_reference": _reference_payload(),
            "service": {"data": {"owner": "attacker"}},
        },
    )
    negative = _create(link_client, token, key="closed-body-key-00003", etag=etag, index=-1)
    boolean = _create(link_client, token, key="closed-body-key-00004", etag=etag, index=True)
    textual = _create(link_client, token, key="closed-body-key-00005", etag=etag, index="0")

    for response in (wrong_kind, smuggled, negative, boolean, textual):
        assert response.status_code == 422, response.text
        assert response.json()["error"]["code"] == "validation_error"
    locations = {
        detail["location"] for detail in wrong_kind.json()["error"]["details"]
    }
    assert "body.credential_reference.kind" in locations
    _assert_nothing_changed(link_state, before)


# ---------------------------------------------------------------------------
# ETags and access methods
# ---------------------------------------------------------------------------


def test_missing_malformed_and_stale_etags_are_deterministic(
    link_client: TestClient,
    link_state,
) -> None:
    tokens = link_state["tokens"]
    token = tokens["delegate"]
    stale = _etag(link_client, token)
    # An unrelated service edit by its owner makes the delegate's ETag stale.
    edited = _service_data()
    edited["owner"] = "Billing platform team"
    changed = link_client.put(
        f"/api/v1/objects/{SERVICE_ID}",
        headers={**_authorization(tokens["service_owner"]), "If-Match": stale},
        json=_asset(SERVICE_ID, "service", edited).model_dump(mode="json"),
    )
    assert changed.status_code == 200, changed.text
    before = _snapshot(link_state)

    missing = _create(link_client, token, key="etag-missing-key-0001", etag=None)
    malformed = _create(link_client, token, key="etag-malform-key-0001", etag="rev-2")
    weak = _create(link_client, token, key="etag-weak-key-000001", etag='W/"rev-2"')
    outdated = _create(link_client, token, key="etag-stale-key-000001", etag=stale)

    assert missing.status_code == 428
    assert missing.json()["error"]["code"] == "precondition_required"
    for response in (malformed, weak, outdated):
        assert response.status_code == 412
        assert response.json()["error"]["code"] == "precondition_failed"
    # A failed precondition releases its idempotency reservation.
    _assert_nothing_changed(link_state, before)
    retried = _create(
        link_client,
        token,
        key="etag-stale-key-000001",
        etag=changed.json()["etag"],
    )
    assert retried.status_code == 201, retried.text


@pytest.mark.parametrize("index", [2, 99])
def test_a_missing_access_method_is_a_stable_conflict(
    link_client: TestClient,
    link_state,
    index: int,
) -> None:
    token = link_state["tokens"]["delegate"]
    before = _snapshot(link_state)

    response = _create(
        link_client,
        token,
        key=f"missing-method-key-{index:04d}",
        etag=_etag(link_client, token),
        index=index,
    )

    assert response.status_code == 409
    assert response.json()["error"]["code"] == "access_method_not_found"
    _assert_nothing_changed(link_state, before)


def test_a_service_without_access_methods_has_no_link_target(
    link_client: TestClient,
    link_state,
) -> None:
    token = link_state["tokens"]["catalog_owner"]
    before = _snapshot(link_state)

    response = _create(
        link_client,
        token,
        key="no-methods-key-000001",
        etag=_etag(link_client, token, HIDDEN_SERVICE_ID),
        service_id=HIDDEN_SERVICE_ID,
    )

    assert response.status_code == 409
    assert response.json()["error"]["code"] == "access_method_not_found"
    _assert_nothing_changed(link_state, before)


@pytest.mark.parametrize(
    "corruption",
    [
        {"credential_references": "credential_reference:billing-ssh-key"},
        {"endpoint_id": "no-such-endpoint"},
        {"credential_references": ["credential_reference:no-such-reference"]},
    ],
)
def test_an_invalid_stored_service_record_blocks_the_link(
    link_client: TestClient,
    link_state,
    corruption: dict,
) -> None:
    data = _service_data()
    data["access_methods"][0].update(corruption)
    with link_state["session_factory"]() as session:
        with transaction(session):
            session.execute(
                text("UPDATE catalog_objects SET data_json = :data WHERE id = :id"),
                {"data": json.dumps(data, sort_keys=True), "id": SERVICE_ID},
            )
    token = link_state["tokens"]["delegate"]
    before = _snapshot(link_state)

    response = _create(
        link_client,
        token,
        key="invalid-record-key-0001",
        etag=_etag(link_client, token),
    )

    # The link is never a hidden repair of an unrelated field.
    assert response.status_code == 409
    assert response.json()["error"]["code"] == "service_record_invalid"
    _assert_nothing_changed(link_state, before)


# ---------------------------------------------------------------------------
# Idempotency and concurrency
# ---------------------------------------------------------------------------


def test_a_retry_with_the_same_key_replays_without_a_second_effect(
    link_client: TestClient,
    link_state,
) -> None:
    token = link_state["tokens"]["delegate"]
    etag = _etag(link_client, token)
    first = _create(link_client, token, key="replay-key-0000000001", etag=etag)
    assert first.status_code == 201, first.text
    after_first = _snapshot(link_state)

    # The same request replays even though its ETag is now stale.
    second = _create(link_client, token, key="replay-key-0000000001", etag=etag)

    assert second.status_code == 201, second.text
    assert second.json() == {**first.json(), "replayed": True}
    assert _snapshot(link_state) == after_first


@pytest.mark.parametrize(
    "variation",
    ["payload", "index", "etag", "service"],
)
def test_a_reused_key_for_another_request_conflicts(
    link_client: TestClient,
    link_state,
    variation: str,
) -> None:
    token = link_state["tokens"]["service_owner"]
    etag = _etag(link_client, token)
    first = _create(link_client, token, key="reused-key-000000001", etag=etag)
    assert first.status_code == 201, first.text
    after_first = _snapshot(link_state)

    arguments: dict = {"key": "reused-key-000000001", "etag": etag}
    if variation == "payload":
        arguments["reference"] = _reference_payload(label="Another label")
    elif variation == "index":
        arguments["index"] = 1
    elif variation == "etag":
        arguments["etag"] = first.json()["service_etag"]
    else:
        arguments["service_id"] = OTHER_SERVICE_ID
        arguments["etag"] = _etag(link_client, token, OTHER_SERVICE_ID)
    second = _create(link_client, token, **arguments)

    assert second.status_code == 409
    assert second.json()["error"]["code"] == "conflict"
    assert _snapshot(link_state) == after_first


def test_a_new_key_for_an_already_created_reference_is_refused(
    link_client: TestClient,
    link_state,
) -> None:
    token = link_state["tokens"]["delegate"]
    first = _create(
        link_client,
        token,
        key="retry-new-key-0000001",
        etag=_etag(link_client, token),
    )
    assert first.status_code == 201, first.text
    after_first = _snapshot(link_state)

    second = _create(
        link_client,
        token,
        key="retry-new-key-0000002",
        etag=first.json()["service_etag"],
        index=1,
    )

    assert second.status_code == 409
    assert second.json()["error"]["code"] == "credential_reference_id_unavailable"
    assert _snapshot(link_state) == after_first


def test_a_missing_idempotency_key_is_rejected(
    link_client: TestClient,
    link_state,
) -> None:
    token = link_state["tokens"]["delegate"]
    before = _snapshot(link_state)

    response = link_client.post(
        CREATE_PATH.format(service_id=SERVICE_ID),
        headers={**_authorization(token), "If-Match": _etag(link_client, token)},
        json={"access_method_index": 0, "credential_reference": _reference_payload()},
    )

    assert response.status_code == 400
    _assert_nothing_changed(link_state, before)


def _parallel_client(link_state) -> TestClient:
    session_factory = link_state["session_factory"]
    app = create_app()

    def override_get_session() -> Generator[Session, None, None]:
        with session_factory() as session:
            yield session

    app.dependency_overrides[get_session] = override_get_session
    return TestClient(app, base_url="https://testserver")


def test_parallel_creations_on_one_service_revision_have_exactly_one_winner(
    link_state,
) -> None:
    token = link_state["tokens"]["delegate"]
    with _parallel_client(link_state) as client:
        etag = _etag(client, token)
        before = _snapshot(link_state)

        def create(suffix: str):
            return _create(
                client,
                token,
                key=f"parallel-winner-key-{suffix}",
                etag=etag,
                reference=_reference_payload(f"parallel-reference-{suffix}"),
            )

        with ThreadPoolExecutor(max_workers=2) as pool:
            responses = list(pool.map(create, ("a", "b")))

    assert sorted(response.status_code for response in responses) == [201, 412]
    winner = next(response for response in responses if response.status_code == 201)
    after = _snapshot(link_state)
    created = set(after["objects"]) - set(before["objects"])
    assert created == {winner.json()["credential_reference"]["id"]}
    assert after["objects"][SERVICE_ID][8] == before["objects"][SERVICE_ID][8] + 1
    assert after["objects"][SERVICE_ID][6]["access_methods"][0][
        "credential_references"
    ] == [f"credential_reference:{winner.json()['credential_reference']['id']}"]
    assert len(after["grants"] - before["grants"]) == 1
    assert after["audit_events"] == before["audit_events"] + 2


def test_parallel_retries_with_one_key_create_exactly_once(link_state) -> None:
    token = link_state["tokens"]["delegate"]
    with _parallel_client(link_state) as client:
        etag = _etag(client, token)
        before = _snapshot(link_state)
        with ThreadPoolExecutor(max_workers=2) as pool:
            responses = list(
                pool.map(
                    lambda _: _create(
                        client,
                        token,
                        key="parallel-same-key-00001",
                        etag=etag,
                    ),
                    range(2),
                )
            )

    assert [response.status_code for response in responses] == [201, 201]
    assert sorted(response.json()["replayed"] for response in responses) == [False, True]
    after = _snapshot(link_state)
    assert set(after["objects"]) - set(before["objects"]) == {NEW_REFERENCE_ID}
    assert len(after["grants"] - before["grants"]) == 1
    assert after["audit_events"] == before["audit_events"] + 2


# ---------------------------------------------------------------------------
# Atomicity
# ---------------------------------------------------------------------------


def test_a_failed_owner_grant_write_rolls_back_the_object_and_the_link(
    link_client: TestClient,
    link_state,
) -> None:
    def fail_grant_flush(session, _flush_context, _instances) -> None:
        for instance in session.new:
            if isinstance(instance, ObjectGrant) and instance.object_id == NEW_REFERENCE_ID:
                raise RuntimeError("simulated grant write failure")

    token = link_state["tokens"]["delegate"]
    etag = _etag(link_client, token)
    before = _snapshot(link_state)
    sqlalchemy_event.listen(Session, "before_flush", fail_grant_flush)
    try:
        response = _create(link_client, token, key="grant-fail-key-000001", etag=etag)
    finally:
        sqlalchemy_event.remove(Session, "before_flush", fail_grant_flush)

    assert response.status_code == 500
    assert response.json()["error"]["code"] == "internal_error"
    _assert_nothing_changed(link_state, before)


@pytest.mark.parametrize(
    "failing_action",
    ["create_service_credential_reference", "credential_reference_link"],
)
def test_a_failed_audit_write_rolls_back_the_object_grant_and_link(
    link_client: TestClient,
    link_state,
    monkeypatch: pytest.MonkeyPatch,
    failing_action: str,
) -> None:
    from blockwart.services import commands

    original = commands.add_audit_event

    def fail_one_audit(session, **kwargs) -> None:
        if kwargs.get("action") == failing_action:
            raise RuntimeError("simulated audit write failure")
        original(session, **kwargs)

    monkeypatch.setattr(commands, "add_audit_event", fail_one_audit)
    token = link_state["tokens"]["delegate"]
    etag = _etag(link_client, token)
    before = _snapshot(link_state)

    response = _create(link_client, token, key="audit-fail-key-000001", etag=etag)

    assert response.status_code == 500
    # The service link was already written when the second audit event failed;
    # it is rolled back with the object, its grant, and the reservation.
    _assert_nothing_changed(link_state, before)
    monkeypatch.setattr(commands, "add_audit_event", original)
    retried = _create(link_client, token, key="audit-fail-key-000001", etag=etag)
    assert retried.status_code == 201, retried.text
    assert retried.json()["replayed"] is False


# ---------------------------------------------------------------------------
# Published contract
# ---------------------------------------------------------------------------


def test_describe_schema_distinguishes_the_three_creation_paths() -> None:
    reference_intents = {
        intent["tool"]: intent
        for intent in describe_schema_payload("credential_reference")["write_intents"]
    }
    service_intents = {
        intent["tool"]: intent for intent in describe_schema_payload("service")["write_intents"]
    }

    # A credential reference is never a placement child.
    assert "blockwart.create_child" not in reference_intents
    assert set(reference_intents) == {
        "blockwart.create_root",
        "blockwart.update_object",
        SERVICE_CREDENTIAL_REFERENCE_TOOL,
    }
    root = reference_intents["blockwart.create_root"]
    assert root["creation_path"] == "disconnected_root"
    assert root["authorization"] == {
        "permission": None,
        "object_argument": None,
        "object_roles": [],
        "catalog_roles": ["catalog_owner"],
        "root_kinds": {"catalog_owner": ["credential_reference"]},
    }
    bound = reference_intents[SERVICE_CREDENTIAL_REFERENCE_TOOL]
    assert bound["creation_path"] == "service_bound_reference"
    assert bound["relation_type"] is None
    assert bound["parent_kinds"] == []
    assert bound["authorization"] == {
        "permission": "create_credential_reference",
        "object_argument": "service_id",
        "object_roles": ["credential_reference_creator", "owner"],
        "catalog_roles": ["catalog_owner"],
        "root_kinds": None,
    }
    assert bound["reference_link"] == {
        "object_argument": "service_id",
        "object_kinds": ["service"],
        "selector_argument": "access_method_index",
        "path": "access_methods[].credential_references",
    }
    TOOL_INPUT_VALIDATORS[SERVICE_CREDENTIAL_REFERENCE_TOOL].validate(bound["example"])
    CatalogObjectIn(**bound["example"]["credential_reference"])

    child = service_intents["blockwart.create_child"]
    assert child["creation_path"] == "placement_child"
    assert child["relation_type"] == "hosts"
    assert child["authorization"]["permission"] == "create_child"
    assert child["authorization"]["object_roles"] == ["creator", "owner"]
    assert SERVICE_CREDENTIAL_REFERENCE_TOOL not in service_intents
    project_root = next(
        intent
        for intent in describe_schema_payload("project")["write_intents"]
        if intent["tool"] == "blockwart.create_root"
    )
    assert project_root["authorization"]["root_kinds"] == {
        "catalog_owner": ["project"],
        "project_creator": ["project"],
    }


def test_the_tool_and_grant_vocabulary_publish_the_capability() -> None:
    tool = TOOL_DEFINITIONS[SERVICE_CREDENTIAL_REFERENCE_TOOL]
    schema = tool["inputSchema"]

    assert "credential_reference_creator" in GRANT_ROLE_SCHEMA["enum"]
    assert set(GRANT_ROLE_SCHEMA["enum"]) == {role.value for role in Role}
    assert schema["properties"]["credential_reference"]["properties"]["kind"] == {
        "type": "string",
        "const": "credential_reference",
    }
    assert schema["required"] == [
        "service_id",
        "access_method_index",
        "if_match",
        "idempotency_key",
        "credential_reference",
    ]
    assert tool["annotations"]["readOnlyHint"] is False
    for phrase in ("create_credential_reference", "credential_reference_creator", "create_child"):
        assert phrase in tool["description"]


def test_the_published_documentation_describes_the_delegation() -> None:
    docs = Path(__file__).resolve().parents[1] / "docs"
    rbac = (docs / "auth-rbac.md").read_text()
    api = (docs / "api-v1.md").read_text()
    mcp = (docs / "mcp.md").read_text()

    assert (
        "| `credential_reference_creator` | `discover`, `read`, "
        "`create_credential_reference` |" in rbac
    )
    assert "## Service-bound credential-reference creation" in rbac
    assert "Owner-mediated workaround" in rbac
    assert "### `POST /api/v1/objects/{service_id}/credential-references`" in api
    assert (
        "blockwart.create_service_credential_reference -> "
        "POST /api/v1/objects/{service_id}/credential-references" in mcp
    )
