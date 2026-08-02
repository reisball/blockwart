from __future__ import annotations

import json
from collections.abc import Generator
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from blockwart.api.deps import get_session
from blockwart.db.session import transaction
from blockwart.domain.auth import GrantScope, Permission, Role
from blockwart.main import create_app
from blockwart.models import AuditEvent, CatalogObject, IdempotencyRecord, ObjectGrant, Relationship
from blockwart.schemas.catalog import CatalogObjectIn
from blockwart.services.access import create_object_grant
from blockwart.services.catalog import create_relationship, upsert_object
from blockwart.services.commands import create_attached_device
from blockwart.services.identity import create_service_account, issue_service_token


def _device(object_id: str, **data_overrides: Any) -> CatalogObjectIn:
    data: dict[str, Any] = {
        "schema_version": 1,
        "device": {"category": "sensor", "manufacturer": "acme", "model": "x1"},
    }
    data.update(data_overrides)
    return CatalogObjectIn(
        id=object_id,
        kind="device",
        label=object_id.replace("-", " ").title(),
        lifecycle="active",
        health="healthy",
        data=data,
    )


def _host(object_id: str) -> CatalogObjectIn:
    return CatalogObjectIn(
        id=object_id,
        kind="host",
        label=object_id.replace("-", " ").title(),
        lifecycle="active",
        health="healthy",
        data={
            "schema_version": 1,
            "network": {"addresses": [{"ip": "10.0.0.1"}]},
        },
    )


def _network_device(object_id: str) -> CatalogObjectIn:
    return CatalogObjectIn(
        id=object_id,
        kind="network",
        label=object_id.replace("-", " ").title(),
        lifecycle="active",
        health="healthy",
        data={
            "schema_version": 1,
            "network": {"category": "switch"},
        },
    )


def _network_segment(object_id: str) -> CatalogObjectIn:
    return CatalogObjectIn(
        id=object_id,
        kind="network",
        label=object_id.replace("-", " ").title(),
        lifecycle="active",
        health="healthy",
        data={
            "schema_version": 1,
            "network": {"category": "segment"},
        },
    )


def _system(object_id: str) -> CatalogObjectIn:
    return CatalogObjectIn(
        id=object_id,
        kind="system",
        label=object_id.replace("-", " ").title(),
        lifecycle="active",
        health="healthy",
        data={"schema_version": 1},
    )


@pytest.fixture
def device_command_state(alembic_session_factory):
    with alembic_session_factory() as session:
        with transaction(session):
            parent = upsert_object(session, _host("host-device-parent"))
            switch = upsert_object(session, _network_device("net-device-parent"))
            segment = upsert_object(session, _network_segment("net-segment-parent"))
            system = upsert_object(session, _system("system-device-parent"))
            service = upsert_object(
                session,
                CatalogObjectIn(
                    id="service-device-parent",
                    kind="service",
                    label="Service Device Parent",
                    lifecycle="active",
                    health="healthy",
                    data={"schema_version": 1},
                ),
            )
            upsert_object(session, _device("existing-device"))
            create_relationship(
                session,
                from_ref="device:existing-device",
                relation_type="attached_to",
                to_ref="host:host-device-parent",
            )
            principal = create_service_account(
                session,
                login="device.writer",
                display_name="Device Writer",
            )
            for object_id, role in (
                (parent.id, Role.OWNER),
                ("existing-device", Role.OWNER),
                (switch.id, Role.VIEWER),
                (segment.id, Role.OWNER),
                (system.id, Role.DISCOVERER),
                (service.id, Role.OWNER),
            ):
                create_object_grant(
                    session,
                    principal_id=principal.id,
                    object_id=object_id,
                    role=role,
                    scope=GrantScope.SELF,
                )
            token = issue_service_token(session, principal_id=principal.id, name="devices")
    return alembic_session_factory, principal.id, token.value


@pytest.fixture
def device_command_client(device_command_state) -> Generator[TestClient, None, None]:
    session_factory, _, _ = device_command_state
    app = create_app()

    def override_get_session() -> Generator[Session, None, None]:
        with session_factory() as session:
            yield session

    app.dependency_overrides[get_session] = override_get_session
    with TestClient(app) as client:
        yield client


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def test_create_attached_device_is_atomic_audited_idempotent_and_bumps_parent(
    device_command_client: TestClient,
    device_command_state,
) -> None:
    session_factory, principal_id, token = device_command_state
    headers = {
        **_auth(token),
        "Idempotency-Key": "attach-device-0001",
    }
    body = {
        "device": _device("child-device-01").model_dump(mode="json"),
        "metadata": {
            "source_interface": "eth0",
            "link_kind": "ethernet",
            "primary": True,
        },
    }
    with session_factory() as session:
        parent_before = session.get(CatalogObject, "host-device-parent")
        assert parent_before is not None
        parent_revision_before = parent_before.revision

    first = device_command_client.post(
        "/api/v1/objects/host-device-parent/attached-devices",
        headers=headers,
        json=body,
    )
    replay = device_command_client.post(
        "/api/v1/objects/host-device-parent/attached-devices",
        headers=headers,
        json=body,
    )

    assert first.status_code == 201, first.text
    assert replay.status_code == 201, replay.text
    assert first.headers["etag"] == '"rev-1"'
    assert replay.json() == {**first.json(), "replayed": True}

    with session_factory() as session:
        row = session.get(CatalogObject, "child-device-01")
        assert row is not None
        assert row.kind == "device"
        parent = session.get(CatalogObject, "host-device-parent")
        assert parent is not None
        assert parent.revision == parent_revision_before + 1
        rel = session.scalar(
            select(Relationship).where(
                Relationship.from_ref == "device:child-device-01",
                Relationship.relation_type == "attached_to",
                Relationship.to_ref == "host:host-device-parent",
            )
        )
        assert rel is not None
        assert rel.metadata_json == (
            '{"link_kind":"ethernet","primary":true,"source_interface":"eth0"}'
        )
        owner = session.scalar(
            select(ObjectGrant).where(ObjectGrant.object_id == "child-device-01")
        )
        assert owner is not None
        assert owner.principal_id == principal_id
        assert (owner.role, owner.scope) == ("owner", "self")
        events = session.scalars(
            select(AuditEvent).where(AuditEvent.object_id == "child-device-01")
        ).all()
        assert len(events) == 1
        assert events[0].action == "create_attached_device"
        record = session.scalar(select(IdempotencyRecord))
        assert record is not None
        assert record.resource_id == "child-device-01"


def test_create_attached_device_requires_device_kind(
    device_command_client: TestClient,
    device_command_state,
) -> None:
    _, _, token = device_command_state
    body = {
        "device": CatalogObjectIn(
            id="not-a-device",
            kind="service",
            label="Not a Device",
            lifecycle="active",
            health="healthy",
            data={"schema_version": 1},
        ).model_dump(mode="json"),
    }
    response = device_command_client.post(
        "/api/v1/objects/host-device-parent/attached-devices",
        headers={**_auth(token), "Idempotency-Key": "attach-device-0002"},
        json=body,
    )
    assert response.status_code == 409
    assert "kind=device" in response.json()["error"]["message"]


def test_create_attached_device_rejects_unauthorized_parent(
    alembic_session_factory,
) -> None:
    with alembic_session_factory() as session:
        with transaction(session):
            upsert_object(session, _host("other-parent"))
            principal = create_service_account(
                session,
                login="device.stranger",
                display_name="Device Stranger",
            )
            create_object_grant(
                session,
                principal_id=principal.id,
                object_id="other-parent",
                role=Role.VIEWER,
                scope=GrantScope.SELF,
            )
            token = issue_service_token(session, principal_id=principal.id, name="devices")

    app = create_app()

    def override_get_session() -> Generator[Session, None, None]:
        with alembic_session_factory() as session:
            yield session

    app.dependency_overrides[get_session] = override_get_session

    with TestClient(app) as client:
        response = client.post(
            "/api/v1/objects/other-parent/attached-devices",
            headers={
                "Authorization": f"Bearer {token.value}",
                "Idempotency-Key": "attach-device-0003",
            },
            json={"device": _device("unauthorized-device").model_dump(mode="json")},
        )
        assert response.status_code == 403


@pytest.mark.parametrize(
    ("parent_id", "device_id"),
    [
        ("service-device-parent", "service-child-rejected"),
        ("net-segment-parent", "segment-child-rejected"),
    ],
)
def test_create_attached_device_rolls_back_invalid_endpoint_atomically(
    device_command_client: TestClient,
    device_command_state,
    parent_id: str,
    device_id: str,
) -> None:
    session_factory, _, token = device_command_state
    response = device_command_client.post(
        f"/api/v1/objects/{parent_id}/attached-devices",
        headers={
            **_auth(token),
            "Idempotency-Key": f"invalid-parent-{device_id}",
        },
        json={"device": _device(device_id).model_dump(mode="json")},
    )

    assert response.status_code == 409
    with session_factory() as session:
        assert session.get(CatalogObject, device_id) is None
        assert (
            session.scalar(
                select(func.count())
                .select_from(ObjectGrant)
                .where(ObjectGrant.object_id == device_id)
            )
            == 0
        )
        assert (
            session.scalar(
                select(func.count())
                .select_from(AuditEvent)
                .where(AuditEvent.object_id == device_id)
            )
            == 0
        )
        assert (
            session.scalar(
                select(func.count())
                .select_from(IdempotencyRecord)
                .where(IdempotencyRecord.resource_id == device_id)
            )
            == 0
        )


def test_relationship_create_and_metadata_replace_bump_endpoints(
    device_command_client: TestClient,
    device_command_state,
) -> None:
    _, _, token = device_command_state
    auth = _auth(token)
    parent = device_command_client.get("/api/v1/objects/host-device-parent", headers=auth)
    assert parent.status_code == 200
    etag = parent.headers["etag"]

    create = device_command_client.post(
        "/api/v1/objects/host-device-parent/relationships",
        headers={**auth, "If-Match": etag},
        json={
            "from_ref": "host:host-device-parent",
            "relation_type": "attached_to",
            "to_ref": "network:net-device-parent",
            "metadata": {"link_kind": "ethernet", "primary": True},
        },
    )
    assert create.status_code == 200, create.text
    assert create.json()["changed"] is True
    returned_metadata = create.json()["metadata"]
    assert returned_metadata == {"link_kind": "ethernet", "primary": True}

    relationships = device_command_client.get(
        "/api/v1/objects/host-device-parent/relationships",
        headers=auth,
    )
    assert relationships.status_code == 200, relationships.text
    created_edge = next(
        edge
        for edge in relationships.json()["items"]
        if edge["to_ref"] == "network:net-device-parent"
    )
    assert created_edge["metadata"] == {
        "link_kind": "ethernet",
        "primary": True,
    }

    updated_parent = device_command_client.get("/api/v1/objects/host-device-parent", headers=auth)
    assert updated_parent.status_code == 200
    new_etag = updated_parent.headers["etag"]
    assert new_etag != etag

    replace = device_command_client.post(
        "/api/v1/objects/host-device-parent/relationships",
        headers={**auth, "If-Match": new_etag},
        json={
            "from_ref": "host:host-device-parent",
            "relation_type": "attached_to",
            "to_ref": "network:net-device-parent",
            "metadata": {"link_kind": "wifi", "primary": True},
        },
    )
    assert replace.status_code == 200, replace.text
    assert replace.json()["changed"] is True

    no_op = device_command_client.post(
        "/api/v1/objects/host-device-parent/relationships",
        headers={**auth, "If-Match": replace.headers["etag"]},
        json={
            "from_ref": "host:host-device-parent",
            "relation_type": "attached_to",
            "to_ref": "network:net-device-parent",
            "metadata": {"link_kind": "wifi", "primary": True},
        },
    )
    assert no_op.status_code == 200, no_op.text
    assert no_op.json()["changed"] is False
    assert no_op.json()["metadata"] == {"link_kind": "wifi", "primary": True}

    with device_command_state[0]() as session:
        events = session.scalars(
            select(AuditEvent)
            .where(AuditEvent.object_id == "host-device-parent")
            .order_by(AuditEvent.id)
        ).all()
        replacements = [
            event for event in events if event.action == "relationship_metadata_replace"
        ]
        assert len(replacements) == 1
        details = json.loads(replacements[0].details_json)
        assert details["before"]["metadata"] == {
            "link_kind": "ethernet",
            "primary": True,
        }
        assert details["after"]["metadata"] == {
            "link_kind": "wifi",
            "primary": True,
        }


def test_relationship_metadata_replace_revalidates_primary_and_rolls_back(
    device_command_client: TestClient,
    device_command_state,
) -> None:
    session_factory, _, token = device_command_state
    auth = _auth(token)
    detail = device_command_client.get(
        "/api/v1/objects/existing-device",
        headers=auth,
    )
    second_parent = device_command_client.post(
        "/api/v1/objects/existing-device/relationships",
        headers={**auth, "If-Match": detail.headers["etag"]},
        json={
            "from_ref": "device:existing-device",
            "relation_type": "attached_to",
            "to_ref": "network:net-device-parent",
            "metadata": {"primary": True},
        },
    )
    assert second_parent.status_code == 200, second_parent.text

    before = device_command_client.get(
        "/api/v1/objects/existing-device",
        headers=auth,
    )
    rejected = device_command_client.post(
        "/api/v1/objects/existing-device/relationships",
        headers={**auth, "If-Match": before.headers["etag"]},
        json={
            "from_ref": "device:existing-device",
            "relation_type": "attached_to",
            "to_ref": "host:host-device-parent",
            "metadata": {"primary": True},
        },
    )

    assert rejected.status_code == 409
    after = device_command_client.get(
        "/api/v1/objects/existing-device",
        headers=auth,
    )
    assert after.headers["etag"] == before.headers["etag"]
    with session_factory() as session:
        relationship = session.scalar(
            select(Relationship).where(
                Relationship.from_ref == "device:existing-device",
                Relationship.to_ref == "host:host-device-parent",
            )
        )
        assert relationship is not None
        assert relationship.metadata_json == "{}"
        assert (
            session.scalar(
                select(func.count())
                .select_from(AuditEvent)
                .where(
                    AuditEvent.object_id == "existing-device",
                    AuditEvent.action == "relationship_metadata_replace",
                )
            )
            == 0
        )


def test_relationship_create_revalidates_device_cycles_and_rolls_back(
    device_command_client: TestClient,
    device_command_state,
) -> None:
    session_factory, _, token = device_command_state
    auth = _auth(token)

    first = device_command_client.post(
        "/api/v1/objects/existing-device/attached-devices",
        headers={**auth, "Idempotency-Key": "chain-device-first-0001"},
        json={"device": _device("chain-device-first").model_dump(mode="json")},
    )
    second = device_command_client.post(
        "/api/v1/objects/chain-device-first/attached-devices",
        headers={**auth, "Idempotency-Key": "chain-device-second-0001"},
        json={"device": _device("chain-device-second").model_dump(mode="json")},
    )
    assert first.status_code == second.status_code == 201

    current = device_command_client.get(
        "/api/v1/objects/existing-device",
        headers=auth,
    )
    rejected = device_command_client.post(
        "/api/v1/objects/existing-device/relationships",
        headers={**auth, "If-Match": current.headers["etag"]},
        json={
            "from_ref": "device:existing-device",
            "relation_type": "attached_to",
            "to_ref": "device:chain-device-second",
        },
    )

    assert rejected.status_code == 409
    after = device_command_client.get(
        "/api/v1/objects/existing-device",
        headers=auth,
    )
    assert after.headers["etag"] == current.headers["etag"]
    with session_factory() as session:
        assert (
            session.scalar(
                select(func.count())
                .select_from(Relationship)
                .where(
                    Relationship.from_ref == "device:existing-device",
                    Relationship.to_ref == "device:chain-device-second",
                )
            )
            == 0
        )


def test_device_graph_resolves_upstream_and_downstream(
    device_command_client: TestClient,
    device_command_state,
) -> None:
    _, _, token = device_command_state
    auth = _auth(token)
    created = device_command_client.post(
        "/api/v1/objects/existing-device/attached-devices",
        headers={**auth, "Idempotency-Key": "graph-chain-child-0001"},
        json={"device": _device("graph-chain-child").model_dump(mode="json")},
    )
    assert created.status_code == 201, created.text

    response = device_command_client.get(
        "/api/v1/objects/host-device-parent/device-graph",
        headers=auth,
    )
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["object_ref"] == "host:host-device-parent"
    assert payload["upstream_path"] == []
    assert payload["downstream_refs"] == [
        "device:existing-device",
        "device:graph-chain-child",
    ]
    edge_refs = {(edge["from_ref"], edge["to_ref"]) for edge in payload["edges"]}
    assert ("device:existing-device", "host:host-device-parent") in edge_refs
    assert ("device:graph-chain-child", "device:existing-device") in edge_refs
    node_by_ref = {node["ref"]: node for node in payload["nodes"]}
    assert node_by_ref["device:existing-device"]["kind"] == "device"
    assert node_by_ref["host:host-device-parent"]["kind"] == "host"
    assert node_by_ref["device:existing-device"]["visibility"] == "detail"
    assert node_by_ref["device:existing-device"]["category"] == "sensor"
    assert node_by_ref["device:existing-device"]["manufacturer"] == "acme"
    assert node_by_ref["device:existing-device"]["model"] == "x1"
    assert "manufacturer" not in node_by_ref["host:host-device-parent"]


def test_device_graph_conceals_unreadable_neighbors(
    alembic_session_factory,
) -> None:
    with alembic_session_factory() as session:
        with transaction(session):
            host = upsert_object(session, _host("visible-host"))
            upsert_object(session, _device("hidden-device"))
            create_relationship(
                session,
                from_ref="device:hidden-device",
                relation_type="attached_to",
                to_ref="host:visible-host",
            )
            reader = create_service_account(
                session,
                login="graph.reader",
                display_name="Graph Reader",
            )
            create_object_grant(
                session,
                principal_id=reader.id,
                object_id=host.id,
                role=Role.DISCOVERER,
                scope=GrantScope.SELF,
            )
            token = issue_service_token(session, principal_id=reader.id, name="graph")

    app = create_app()

    def override_get_session() -> Generator[Session, None, None]:
        with alembic_session_factory() as session:
            yield session

    app.dependency_overrides[get_session] = override_get_session

    with TestClient(app) as client:
        response = client.get(
            "/api/v1/objects/visible-host/device-graph",
            headers={"Authorization": f"Bearer {token.value}"},
        )
        assert response.status_code == 200, response.text
        payload = response.json()
        assert payload["downstream_refs"] == []
        assert payload["nodes"] == [
            {
                "ref": "host:visible-host",
                "id": "visible-host",
                "kind": "host",
                "label": "Visible Host",
                "visibility": "stub",
                "capabilities": ["discover"],
            }
        ]
        assert not any(node["ref"] == "device:hidden-device" for node in payload["nodes"])


def test_attached_device_command_layer_uses_canonical_metadata(
    alembic_session_factory,
) -> None:
    from blockwart.domain.auth import PrincipalContext
    from blockwart.services.commands import WriteContext
    from blockwart.services.policy import PolicySnapshot

    with alembic_session_factory() as session:
        with transaction(session):
            host = upsert_object(session, _host("cmd-parent"))
            principal = create_service_account(
                session,
                login="cmd.writer",
                display_name="Cmd Writer",
            )
            create_object_grant(
                session,
                principal_id=principal.id,
                object_id=host.id,
                role=Role.CREATOR,
                scope=GrantScope.SELF,
            )
            policy = PolicySnapshot(
                principal_id=principal.id,
                _permissions={host.id: frozenset(Permission)},
                _grants={},
            )
            context = WriteContext(
                principal=PrincipalContext(
                    id=principal.id,
                    principal_type="service_account",
                    login=principal.login,
                    display_name=principal.display_name,
                ),
                policy=policy,
                channel="test",
            )
            result = create_attached_device(
                session,
                context,
                parent_id=host.id,
                payload=_device("cmd-device"),
                metadata={"link_kind": "ethernet", "note": "  wired  ", "primary": True},
                idempotency_key="cmd-device-key-long",
                idempotency_ttl_seconds=3600,
            )
            assert result.catalog_object.id == "cmd-device"
            rel = session.scalar(
                select(Relationship).where(
                    Relationship.from_ref == "device:cmd-device",
                    Relationship.relation_type == "attached_to",
                    Relationship.to_ref == "host:cmd-parent",
                )
            )
            assert rel is not None
            assert rel.metadata_json == '{"link_kind":"ethernet","note":"wired","primary":true}'
