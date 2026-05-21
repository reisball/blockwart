from collections.abc import Generator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker

from blockwart.api.deps import get_session
from blockwart.db.base import Base
from blockwart.main import create_app
from blockwart.models import AuditEvent
from blockwart.services.seeds import import_seed_file

SEED_PATH = Path(__file__).resolve().parents[1] / "seeds" / "pilot_objects.yaml"


@pytest.fixture
def session_factory(tmp_path):
    engine = create_engine(
        f"sqlite:///{tmp_path / 'api_v1.db'}",
        connect_args={"check_same_thread": False},
    )
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    with factory() as session:
        import_seed_file(session, SEED_PATH)
    return factory


@pytest.fixture
def client(session_factory) -> Generator[TestClient, None, None]:
    app = create_app()

    def override_get_session() -> Generator[Session, None, None]:
        with session_factory() as session:
            yield session

    app.dependency_overrides[get_session] = override_get_session
    with TestClient(app) as test_client:
        yield test_client


def test_api_v1_lists_objects_with_search_filters(client: TestClient) -> None:
    response = client.get("/api/v1/objects?q=n8n&kind=system&status=active")

    assert response.status_code == 200
    payload = response.json()
    assert [item["id"] for item in payload] == ["n8n"]
    assert payload[0]["kind"] == "system"


def test_api_v1_gets_canonical_object(client: TestClient) -> None:
    response = client.get("/api/v1/objects/n8n-web-ui")

    assert response.status_code == 200
    payload = response.json()
    assert payload["id"] == "n8n-web-ui"
    assert payload["kind"] == "service"
    assert payload["data"]["system_id"] == "system:n8n"
    assert "hostname" not in payload["data"]
    assert "interfaces" not in payload["data"]


def test_api_v1_agent_view_resolves_service_inheritance(client: TestClient) -> None:
    response = client.get("/api/v1/objects/n8n-web-ui/agent-view")

    assert response.status_code == 200
    payload = response.json()
    assert payload["identity"]["ref"] == "service:n8n-web-ui"
    assert payload["hierarchy"]["system"]["ref"] == "system:n8n"
    assert payload["hierarchy"]["host"]["ref"] == "system:fabrik"
    assert payload["resolved"]["hostname"] == "n8n"
    assert payload["resolved"]["network"]["hostnames"] == ["n8n"]
    assert payload["resolved"]["network"]["addresses"][0]["ip"] == "192.168.50.83"
    assert payload["endpoints"][0]["type"] == "Web"
    assert payload["endpoints"][0]["port"] == 5678
    assert "credential_reference:n8n-owner-account" in payload["credential_references"]
    assert payload["links"]["system"] == "/api/v1/objects/n8n/agent-view"


def test_api_v1_agent_view_accepts_typed_reference(client: TestClient) -> None:
    response = client.get("/api/v1/objects/system:n8n/agent-view")

    assert response.status_code == 200
    assert response.json()["identity"]["ref"] == "system:n8n"


def test_api_v1_agent_view_returns_404_for_kind_mismatch(client: TestClient) -> None:
    response = client.get("/api/v1/objects/service:n8n/agent-view")

    assert response.status_code == 404


def test_api_v1_post_creates_object(client: TestClient) -> None:
    response = client.post(
        "/api/v1/objects",
        json={
            "id": "demo-host",
            "kind": "host",
            "label": "Demo Host",
            "status": "active",
            "summary": "Temporary API test host.",
            "data": {
                "schema_version": 1,
                "hostname": "demo-host",
                "interfaces": [{"id": "eth0", "name": "eth0", "ip": "192.168.50.200"}],
            },
        },
    )

    assert response.status_code == 201
    payload = response.json()
    assert payload["id"] == "demo-host"
    assert payload["data"]["hostname"] == "demo-host"


def test_api_v1_post_rejects_duplicate_object(client: TestClient) -> None:
    response = client.post(
        "/api/v1/objects",
        json={
            "id": "n8n",
            "kind": "system",
            "label": "n8n duplicate",
            "status": "active",
            "data": {"schema_version": 1},
        },
    )

    assert response.status_code == 409


def test_api_v1_patch_updates_top_level_fields(client: TestClient) -> None:
    response = client.patch(
        "/api/v1/objects/n8n",
        json={"label": "n8n Workflow", "summary": "Updated over API v1."},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["label"] == "n8n Workflow"
    assert payload["summary"] == "Updated over API v1."
    assert payload["data"]["network"]["hostnames"] == ["n8n"]


def test_api_v1_patch_revalidates_data(client: TestClient) -> None:
    response = client.patch(
        "/api/v1/objects/n8n-web-ui",
        json={
            "data": {
                "schema_version": 1,
                "system_ref": "system:n8n",
                "hostname": "should-not-be-owned-by-service",
            }
        },
    )

    assert response.status_code == 422


def test_api_v1_patch_returns_404_for_missing_object(client: TestClient) -> None:
    response = client.patch("/api/v1/objects/missing", json={"label": "Missing"})

    assert response.status_code == 404


def test_api_v1_posts_and_lists_comments(
    client: TestClient,
    session_factory,
) -> None:
    first = client.post(
        "/api/v1/objects/n8n/comments",
        json={"comment": "First agent note", "actor": "agent:zoe"},
    )
    second = client.post(
        "/api/v1/objects/n8n/comments",
        json={"comment": "Second agent note", "actor": "agent:codex"},
    )

    assert first.status_code == 201
    assert second.status_code == 201
    payload = second.json()
    assert [item["text"] for item in payload["data"]["comments"]] == [
        "First agent note",
        "Second agent note",
    ]
    comments = client.get("/api/v1/objects/n8n/comments")
    assert comments.status_code == 200
    assert [item["text"] for item in comments.json()] == [
        "First agent note",
        "Second agent note",
    ]
    with session_factory() as session:
        event = session.scalars(select(AuditEvent).order_by(AuditEvent.id.desc())).first()
    assert event is not None
    assert "comments" in event.summary


def test_api_v1_post_comment_rejects_empty_comment(client: TestClient) -> None:
    response = client.post("/api/v1/objects/n8n/comments", json={"comment": "   "})

    assert response.status_code == 422


def test_api_v1_get_comments_returns_legacy_comment(client: TestClient) -> None:
    response = client.patch(
        "/api/v1/objects/n8n",
        json={
            "data": {
                "schema_version": 1,
                "host_ref": "host:fabrik",
                "hostname": "n8n",
                "platform": "LXC",
                "interfaces": [{"id": "eth0", "name": "eth0", "ip": "192.168.50.83"}],
                "endpoints": [{"type": "SSH", "url": "ssh://192.168.50.83:22", "port": 22}],
                "comment": "Legacy note",
            }
        },
    )
    assert response.status_code == 200

    comments = client.get("/api/v1/objects/n8n/comments")

    assert comments.status_code == 200
    assert comments.json()[0] == {"text": "Legacy note", "actor": "legacy", "created_at": None}


def test_api_v1_put_endpoints_replaces_only_endpoints(client: TestClient) -> None:
    response = client.put(
        "/api/v1/objects/n8n-web-ui/endpoints",
        json={
            "endpoints": [
                {
                    "type": "REST API",
                    "url": "http://192.168.50.83:9999/api",
                    "port": 9999,
                }
            ]
        },
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["data"]["endpoints"] == [
        {
            "type": "REST API",
            "url": "http://192.168.50.83:9999/api",
            "port": 9999,
        }
    ]
    assert payload["data"]["system_id"] == "system:n8n"


def test_api_v1_put_endpoints_revalidates_schema(client: TestClient) -> None:
    response = client.put(
        "/api/v1/objects/n8n/endpoints",
        json={
            "endpoints": [
                {
                    "type": "SMTP",
                    "url": "smtp://192.168.50.83:25",
                    "port": 25,
                }
            ]
        },
    )

    assert response.status_code == 422


def test_api_v1_put_endpoints_returns_404_for_missing_object(client: TestClient) -> None:
    response = client.put("/api/v1/objects/missing/endpoints", json={"endpoints": []})

    assert response.status_code == 404


def test_api_v1_put_ports_is_not_supported(client: TestClient) -> None:
    response = client.put("/api/v1/objects/n8n/ports", json={"ports": []})

    assert response.status_code == 422
    assert "use /api/v1/objects/{id}/endpoints" in response.json()["detail"]


def test_api_v1_put_access_methods_replaces_only_access_methods(client: TestClient) -> None:
    response = client.put(
        "/api/v1/objects/n8n-web-ui/access-methods",
        json={
            "access_methods": [
                {
                    "id": "demo-web",
                    "type": "web",
                    "port_ref": "tcp-5678",
                    "endpoint": "http://192.168.50.83:5678/demo",
                    "username": "kai",
                    "credential_reference": "credential_reference:n8n-owner-login",
                }
            ]
        },
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["data"]["access_methods"] == [
        {
            "id": "demo-web",
            "type": "web",
            "port_ref": "tcp-5678",
            "endpoint": "http://192.168.50.83:5678/demo",
            "username": "kai",
            "credential_reference": "credential_reference:n8n-owner-login",
        }
    ]
    assert payload["data"]["endpoints"][0]["port"] == 5678
    assert payload["data"]["system_id"] == "system:n8n"


def test_api_v1_put_access_methods_revalidates_schema(client: TestClient) -> None:
    response = client.put(
        "/api/v1/objects/n8n-web-ui/access-methods",
        json={
            "access_methods": [
                {
                    "id": "demo-web",
                    "type": "web",
                    "port_ref": "tcp-5678",
                    "endpoint": "http://192.168.50.83:5678/demo",
                    "auth_mode": "password",
                }
            ]
        },
    )

    assert response.status_code == 200


def test_api_v1_put_interfaces_replaces_only_interfaces(client: TestClient) -> None:
    response = client.put(
        "/api/v1/objects/n8n/interfaces",
        json={
            "interfaces": [
                {
                    "id": "eth1",
                    "name": "eth1",
                    "ip": "192.168.50.84",
                    "mac": "02:42:AC:11:00:80",
                }
            ]
        },
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["data"]["network"]["addresses"] == [
        {
            "id": "eth1",
            "name": "eth1",
            "ip": "192.168.50.84",
            "mac": "02:42:AC:11:00:80",
        }
    ]
    assert payload["data"]["network"]["addresses"][0]["ip"] == "192.168.50.84"


def test_api_v1_put_interfaces_rejects_service_interfaces(client: TestClient) -> None:
    response = client.put(
        "/api/v1/objects/n8n-web-ui/interfaces",
        json={"interfaces": [{"id": "eth0", "name": "eth0", "ip": "192.168.50.83"}]},
    )

    assert response.status_code == 422


def test_api_v1_put_interfaces_revalidates_schema(client: TestClient) -> None:
    response = client.put(
        "/api/v1/objects/n8n/interfaces",
        json={"interfaces": [{"id": "eth0", "name": "eth0", "ip": "not-an-ip"}]},
    )

    assert response.status_code == 422


def test_api_v1_put_relationships_sets_system_host_ref(client: TestClient) -> None:
    response = client.put(
        "/api/v1/objects/n8n/relationships",
        json={"host_ref": "host:denkstube"},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["data"]["host_ref"] == "host:denkstube"


def test_api_v1_put_relationships_sets_service_system_ref(client: TestClient) -> None:
    response = client.put(
        "/api/v1/objects/n8n-web-ui/relationships",
        json={"system_ref": "system:paperless-ngx"},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["data"]["system_id"] == "system:paperless-ngx"


def test_api_v1_put_relationships_rejects_wrong_ref_kind(client: TestClient) -> None:
    response = client.put(
        "/api/v1/objects/n8n-web-ui/relationships",
        json={"system_ref": "host:fabrik"},
    )

    assert response.status_code == 422


def test_api_v1_put_relationships_returns_404_for_missing_reference(client: TestClient) -> None:
    response = client.put(
        "/api/v1/objects/n8n-web-ui/relationships",
        json={"system_ref": "system:missing"},
    )

    assert response.status_code == 404


def test_api_v1_put_relationships_rejects_unsupported_kind(client: TestClient) -> None:
    response = client.put(
        "/api/v1/objects/runbook-check-ollama-api/relationships",
        json={"host_ref": "system:denkstube"},
    )

    assert response.status_code == 422
