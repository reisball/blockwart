from collections.abc import Generator

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker

from blockwart.api.deps import get_session
from blockwart.db.base import Base
from blockwart.main import create_app
from blockwart.models import AuditEvent, Relationship


@pytest.fixture
def session_factory(tmp_path):
    engine = create_engine(
        f"sqlite:///{tmp_path / 'catalog.db'}",
        connect_args={"check_same_thread": False},
    )
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, autoflush=False, autocommit=False)


@pytest.fixture
def client(session_factory) -> Generator[TestClient, None, None]:
    app = create_app()

    def override_get_session() -> Generator[Session, None, None]:
        with session_factory() as session:
            yield session

    app.dependency_overrides[get_session] = override_get_session
    with TestClient(app) as test_client:
        yield test_client


def test_create_get_update_and_list_catalog_object(client: TestClient, session_factory) -> None:
    payload = {
        "id": "n8n",
        "kind": "system",
        "label": "n8n",
        "status": "active",
        "data": {
            "schema_version": 1,
            "network": {
                "hostnames": ["n8n.local"],
                "addresses": [{"ip": "192.168.50.83", "family": "ipv4"}],
            },
            "ports": [{"port": 5678, "protocol": "tcp", "exposure": "lan"}],
        },
    }

    create_response = client.put("/api/objects/n8n", json=payload)
    assert create_response.status_code == 200
    assert create_response.json()["label"] == "n8n"

    get_response = client.get("/api/objects/n8n")
    assert get_response.status_code == 200
    assert get_response.json()["data"]["network"]["addresses"][0]["ip"] == "192.168.50.83"

    payload["label"] = "n8n workflow"
    update_response = client.put("/api/objects/n8n", json=payload)
    assert update_response.status_code == 200
    assert update_response.json()["label"] == "n8n workflow"

    list_response = client.get("/api/objects")
    assert list_response.status_code == 200
    assert [item["id"] for item in list_response.json()] == ["n8n"]

    with session_factory() as session:
        actions = session.scalars(select(AuditEvent.action).order_by(AuditEvent.id)).all()
    assert actions == ["create", "update"]


def test_get_missing_catalog_object_returns_404(client: TestClient) -> None:
    response = client.get("/api/objects/missing")

    assert response.status_code == 404


def test_delete_catalog_object_writes_audit_event(client: TestClient, session_factory) -> None:
    payload = {
        "id": "rotate-vaultwarden",
        "kind": "runbook",
        "label": "Rotate Vaultwarden",
        "status": "active",
        "summary": "Credential rotation procedure.",
        "data": {
            "schema_version": 1,
            "risk_level": "safe-change",
            "approval_required": False,
            "steps": [{"order": 1, "title": "Open referenced vault item"}],
            "credential_references": ["credential_reference:vaultwarden-api"],
        },
    }
    assert client.put("/api/objects/rotate-vaultwarden", json=payload).status_code == 200

    delete_response = client.delete("/api/objects/rotate-vaultwarden")
    assert delete_response.status_code == 204
    assert client.get("/api/objects/rotate-vaultwarden").status_code == 404

    with session_factory() as session:
        events = session.scalars(select(AuditEvent).order_by(AuditEvent.id)).all()
    assert [event.action for event in events] == ["create", "delete"]
    assert events[-1].object_id == "rotate-vaultwarden"
    assert "runbook:rotate-vaultwarden" in events[-1].summary


def test_delete_catalog_object_removes_relationship_edges(
    client: TestClient,
    session_factory,
) -> None:
    system_payload = {
        "id": "n8n",
        "kind": "system",
        "label": "n8n",
        "status": "active",
        "data": {"schema_version": 1},
    }
    service_payload = {
        "id": "n8n-web-ui",
        "kind": "service",
        "label": "n8n Web UI",
        "status": "active",
        "data": {"schema_version": 1, "system_id": "system:n8n"},
    }
    assert client.put("/api/objects/n8n", json=system_payload).status_code == 200
    assert client.put("/api/objects/n8n-web-ui", json=service_payload).status_code == 200
    with session_factory() as session:
        session.add(
            Relationship(
                from_ref="system:n8n",
                relation_type="hosts",
                to_ref="service:n8n-web-ui",
            )
        )
        session.commit()

    assert client.delete("/api/objects/n8n-web-ui").status_code == 204

    with session_factory() as session:
        assert session.scalars(select(Relationship)).all() == []
        events = session.scalars(select(AuditEvent).order_by(AuditEvent.id)).all()
    assert [event.action for event in events] == ["create", "create", "delete"]
    assert events[1].object_id == "n8n-web-ui"
    assert events[-1].object_id == "n8n-web-ui"


def test_delete_missing_catalog_object_returns_404(client: TestClient) -> None:
    response = client.delete("/api/objects/missing")

    assert response.status_code == 404


def test_rejects_secret_shaped_catalog_payload(client: TestClient) -> None:
    response = client.put(
        "/api/objects/bad-service",
        json={
            "id": "bad-service",
            "kind": "service",
            "label": "Bad Service",
            "data": {"system_id": "system:n8n", "auth": {"token": "not-allowed"}},
        },
    )

    assert response.status_code == 422


def test_rejects_credential_reference_value_fields(client: TestClient) -> None:
    response = client.put(
        "/api/objects/vaultwarden-api",
        json={
            "id": "vaultwarden-api",
            "kind": "credential_reference",
            "label": "Vaultwarden API",
            "data": {
                "schema_version": 1,
                "provider": "vaultwarden",
                "reference": {"name": "Vaultwarden API"},
                "scope": {"access_type": "api"},
                "secret_value_stored": False,
                "value": "not-even-a-secret-but-still-not-a-reference",
            },
        },
    )

    assert response.status_code == 422
