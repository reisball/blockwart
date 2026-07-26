from collections.abc import Generator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from blockwart.api.deps import get_session
from blockwart.db.session import transaction
from blockwart.main import create_app
from blockwart.models import CatalogObject, Relationship
from blockwart.services.seeds import import_seed_file

SEED_PATH = Path(__file__).resolve().parents[1] / "seeds" / "pilot_objects.yaml"


@pytest.fixture
def session_factory(alembic_session_factory):
    with alembic_session_factory() as session:
        with transaction(session):
            import_seed_file(session, SEED_PATH)
    return alembic_session_factory


@pytest.fixture
def client(session_factory) -> Generator[TestClient, None, None]:
    app = create_app()

    def override_get_session() -> Generator[Session, None, None]:
        with session_factory() as session:
            yield session

    app.dependency_overrides[get_session] = override_get_session
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def resolved_asset_graph(session_factory) -> None:
    objects = [
        CatalogObject(
            id="baremetal-01",
            kind="host",
            label="Bare Metal 01",
            status="active",
            summary="Physical host.",
            data_json=(
                '{"schema_version": 1, "network": {'
                '"hostnames": ["baremetal-01"], '
                '"addresses": [{"ip": "10.20.0.10"}]}, '
                '"source_references": [{"label": "CMDB", "uri": "cmdb://baremetal-01"}]}'
            ),
        ),
        CatalogObject(
            id="runtime-01",
            kind="system",
            label="Runtime 01",
            status="active",
            summary="Runtime hosted on bare metal.",
            data_json=(
                '{"schema_version": 1, "lifecycle": "production", "health": "healthy", '
                '"network": {"hostnames": ["runtime-01"], '
                '"addresses": [{"ip": "10.20.0.20"}]}}'
            ),
        ),
        CatalogObject(
            id="runtime-api",
            kind="service",
            label="Runtime API",
            status="active",
            summary="Service on the runtime.",
            data_json=(
                '{"schema_version": 1, "lifecycle": "production", "health": "healthy", '
                '"endpoints": [{"type": "REST API", "url": "https://10.20.0.20:8443/api", '
                '"host": "10.20.0.20", "port": 8443, "protocol": "https"}]}'
            ),
        ),
        CatalogObject(
            id="auth",
            kind="service",
            label="Auth",
            status="active",
            summary="Authentication dependency.",
            data_json='{"schema_version": 1}',
        ),
        CatalogObject(
            id="hardware-console",
            kind="service",
            label="Hardware Console",
            status="active",
            summary="Service running directly on hardware.",
            data_json=(
                '{"schema_version": 1, '
                '"endpoints": [{"type": "Web", "url": "https://10.20.0.10:9443", '
                '"host": "10.20.0.10", "port": 9443}]}'
            ),
        ),
        CatalogObject(
            id="unassigned-service",
            kind="service",
            label="Unassigned Service",
            status="inactive",
            summary="Inventory item without placement.",
            data_json=(
                '{"schema_version": 1, "placement": {'
                '"state": "unassigned", "reason": "Pending decision"}}'
            ),
        ),
    ]
    relationships = [
        Relationship(
            from_ref="host:baremetal-01",
            relation_type="hosts",
            to_ref="system:runtime-01",
        ),
        Relationship(
            from_ref="system:runtime-01",
            relation_type="hosts",
            to_ref="service:runtime-api",
        ),
        Relationship(
            from_ref="host:baremetal-01",
            relation_type="hosts",
            to_ref="service:hardware-console",
        ),
        Relationship(
            from_ref="service:runtime-api",
            relation_type="depends_on",
            to_ref="service:auth",
        ),
    ]
    with session_factory() as session:
        session.add_all([*objects, *relationships])
        session.commit()


def test_agent_search_returns_summaries_only(client: TestClient) -> None:
    response = client.get("/api/agent/search?q=brieftraeger&kind=system")

    assert response.status_code == 200
    payload = response.json()
    assert payload["count"] >= 1
    first = payload["results"][0]
    assert first["ref"] == "system:brieftraeger"
    assert first["label"] == "Brieftraeger"
    assert "data" not in first
    assert "relationships" not in first


def test_agent_object_context_includes_relationships_and_credential_refs(
    client: TestClient,
) -> None:
    response = client.get("/api/agent/objects/brieftraeger")

    assert response.status_code == 200
    payload = response.json()
    assert payload["count"] == 1
    obj = payload["objects"][0]
    assert obj["ref"] == "system:brieftraeger"
    assert obj["relationships"]
    assert "credential_reference:brieftraeger-ssh-login" in obj["credential_references"]


def test_agent_context_limit_and_kind_filter(client: TestClient) -> None:
    response = client.get("/api/agent/context?q=brieftraeger&kind=service&limit=2")

    assert response.status_code == 200
    payload = response.json()
    assert payload["count"] == 2
    assert all(obj["kind"] == "service" for obj in payload["objects"])


def test_agent_namespace_is_read_only(client: TestClient) -> None:
    response = client.post(
        "/api/agent/objects/n8n",
        json={"label": "should not write"},
    )

    assert response.status_code == 405


def test_agent_output_redacts_secret_shaped_data(client: TestClient, session_factory) -> None:
    with session_factory() as session:
        session.add(
            CatalogObject(
                id="unsafe-import",
                kind="system",
                label="Unsafe Import",
                status="active",
                summary="Bypassed validation to prove agent output sanitization.",
                data_json='{"schema_version": 1, "password": "super-secret-value"}',
            )
        )
        session.commit()

    response = client.get("/api/agent/objects/unsafe-import")

    assert response.status_code == 200
    text = response.text
    assert "super-secret-value" not in text
    assert "[redacted-secret-field]" in text


def test_agent_context_resolves_host_system_service_path(
    client: TestClient,
    resolved_asset_graph: None,
) -> None:
    response = client.get("/api/agent/objects/runtime-api")

    assert response.status_code == 200
    obj = response.json()["objects"][0]
    assert obj["parent"]["ref"] == "system:runtime-01"
    assert obj["placement_state"] == "assigned"
    assert [node["ref"] for node in obj["parent_path"]] == [
        "host:baremetal-01",
        "system:runtime-01",
    ]
    assert obj["ips"] == ["10.20.0.20"]
    assert obj["primary_endpoint"]["port"] == 8443
    assert obj["primary_endpoint"] == {
        "id": "rest-api-8443-10-20-0-20",
        "type": "REST API",
        "label": None,
        "url": "https://10.20.0.20:8443/api",
        "host": "10.20.0.20",
        "port": 8443,
        "path": "/api",
        "protocol": "https",
        "transport": "tcp",
        "exposure": "unknown",
        "health_url": None,
    }
    assert obj["lifecycle"] == "production"
    assert obj["health"] == "healthy"
    assert obj["dependencies"] == {
        "upstream": ["service:auth"],
        "downstream": [],
    }
    assert obj["updated_at"]


def test_catalog_rest_and_agent_api_return_the_same_canonical_parent_path(
    client: TestClient,
    resolved_asset_graph: None,
) -> None:
    catalog_response = client.get("/api/objects/runtime-api")
    agent_response = client.get("/api/agent/objects/runtime-api")

    assert catalog_response.status_code == 200
    assert agent_response.status_code == 200
    catalog_path = [
        node["ref"] for node in catalog_response.json()["parent_path"]
    ]
    agent_path = [
        node["ref"]
        for node in agent_response.json()["objects"][0]["parent_path"]
    ]
    assert catalog_path == agent_path == [
        "host:baremetal-01",
        "system:runtime-01",
    ]


def test_agent_context_uses_canonical_seed_service_placement(client: TestClient) -> None:
    response = client.get("/api/agent/objects/n8n-web-ui")

    assert response.status_code == 200
    obj = response.json()["objects"][0]
    assert obj["parent"]["ref"] == "system:n8n"
    assert [node["ref"] for node in obj["parent_path"]] == ["system:n8n"]
    assert "system_id" not in obj["data"]
    assert any(
        relationship == {
            "from_ref": "system:n8n",
            "relation_type": "hosts",
            "to_ref": "service:n8n-web-ui",
        }
        for relationship in obj["relationships"]
    )


def test_agent_context_resolves_direct_hardware_service_and_children(
    client: TestClient,
    resolved_asset_graph: None,
) -> None:
    service_response = client.get("/api/agent/objects/hardware-console")
    host_response = client.get("/api/agent/objects/baremetal-01")

    assert service_response.status_code == 200
    service = service_response.json()["objects"][0]
    assert service["parent"]["ref"] == "host:baremetal-01"
    assert [node["ref"] for node in service["parent_path"]] == ["host:baremetal-01"]

    assert host_response.status_code == 200
    host = host_response.json()["objects"][0]
    assert host["placement_state"] == "root"
    child_refs = {child["ref"] for child in host["children"]}
    assert child_refs == {"system:runtime-01", "service:hardware-console"}
    assert host["source_references"] == [
        {"label": "CMDB", "uri": "cmdb://baremetal-01"}
    ]


def test_agent_context_keeps_unassigned_asset_explicit(
    client: TestClient,
    resolved_asset_graph: None,
) -> None:
    response = client.get("/api/agent/objects/unassigned-service")

    assert response.status_code == 200
    obj = response.json()["objects"][0]
    assert obj["placement_state"] == "unassigned"
    assert obj["parent"] is None
    assert obj["parent_path"] == []
    assert obj["children"] == []
    assert obj["ips"] == []
    assert obj["primary_endpoint"] is None


def test_agent_search_summaries_include_parent_ip_and_primary_endpoint(
    client: TestClient,
    resolved_asset_graph: None,
) -> None:
    response = client.get("/api/agent/search?q=runtime-api&kind=service")

    assert response.status_code == 200
    result = response.json()["results"][0]
    assert result["parent"]["ref"] == "system:runtime-01"
    assert result["ips"] == ["10.20.0.20"]
    assert result["primary_endpoint"]["url"] == "https://10.20.0.20:8443/api"


def test_agent_search_supports_structured_asset_filters(
    client: TestClient,
    resolved_asset_graph: None,
) -> None:
    response = client.get(
        "/api/agent/search",
        params={
            "kind": "service",
            "parent": "host:baremetal-01",
            "ip": "10.20.0.20",
            "port": 8443,
            "endpoint_type": "REST API",
            "protocol": "https",
            "exposure": "unknown",
            "status": "active",
            "lifecycle": "production",
            "health": "healthy",
        },
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["filters"] == {
        "parent": "host:baremetal-01",
        "ip": "10.20.0.20",
        "port": 8443,
        "endpoint_type": "REST API",
        "protocol": "https",
        "exposure": "unknown",
        "status": "active",
        "lifecycle": "production",
        "health": "healthy",
    }
    assert [result["ref"] for result in payload["results"]] == ["service:runtime-api"]


def test_agent_context_query_uses_the_same_structured_filters(
    client: TestClient,
    resolved_asset_graph: None,
) -> None:
    response = client.get(
        "/api/agent/context",
        params={"kind": "host", "ip": "10.20.0.10", "status": "active"},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["filters"]["ip"] == "10.20.0.10"
    assert [obj["ref"] for obj in payload["objects"]] == ["host:baremetal-01"]


def test_agent_routes_remain_get_only(
    client: TestClient,
    resolved_asset_graph: None,
) -> None:
    openapi = client.get("/openapi.json").json()
    agent_paths = {
        path: methods for path, methods in openapi["paths"].items() if path.startswith("/api/agent")
    }

    assert agent_paths
    assert all(set(methods) == {"get"} for methods in agent_paths.values())
    assert client.put("/api/agent/objects/runtime-api", json={}).status_code == 405
    assert client.delete("/api/agent/objects/runtime-api").status_code == 405
