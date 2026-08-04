from collections.abc import Generator

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from blockwart.api.deps import get_session
from blockwart.db.session import transaction
from blockwart.main import create_app
from blockwart.models import CatalogObject
from blockwart.schemas.catalog import CatalogObjectIn
from blockwart.services.catalog import create_relationship, upsert_object


@pytest.fixture
def session_factory(alembic_session_factory):
    with alembic_session_factory() as session:
        with transaction(session):
            for payload in (
                CatalogObjectIn(
                    id="v1-host",
                    kind="host",
                    label="V1 Host",
                    lifecycle="active",
                    health="healthy",
                    data={
                        "schema_version": 1,
                        "network": {
                            "hostnames": ["v1-host.local"],
                            "addresses": [{"ip": "10.43.0.10"}],
                        },
                    },
                ),
                CatalogObjectIn(
                    id="v1-runtime",
                    kind="system",
                    label="V1 Runtime",
                    lifecycle="active",
                    health="healthy",
                    data={"schema_version": 1},
                ),
                CatalogObjectIn(
                    id="v1-runtime-api",
                    kind="service",
                    label="V1 Runtime API",
                    lifecycle="active",
                    health="healthy",
                    data={
                        "schema_version": 1,
                        "endpoints": [
                            {
                                "type": "REST API",
                                "url": "https://10.43.0.20:8443/api",
                                "host": "10.43.0.20",
                                "port": 8443,
                                "protocol": "https",
                            }
                        ],
                    },
                ),
                CatalogObjectIn(
                    id="v1-auth",
                    kind="service",
                    label="V1 Auth",
                    lifecycle="active",
                    health="unknown",
                    data={"schema_version": 1},
                ),
                CatalogObjectIn(
                    id="v1-shared-a",
                    kind="service",
                    label="V1 Shared",
                    lifecycle="planned",
                    health="unknown",
                    data={"schema_version": 1},
                ),
                CatalogObjectIn(
                    id="v1-shared-b",
                    kind="service",
                    label="V1 Shared",
                    lifecycle="planned",
                    health="unknown",
                    data={"schema_version": 1},
                ),
                CatalogObjectIn(
                    id="v1-runbook",
                    kind="runbook",
                    label="V1 Runbook",
                    data={"schema_version": 1},
                    provenance={
                        "source_type": "import",
                        "source_ref": "runbook-export",
                        "stale_after": "2025-01-01T00:00:00Z",
                        "manual_override": False,
                    },
                ),
            ):
                upsert_object(session, payload)
            create_relationship(
                session,
                from_ref="host:v1-host",
                relation_type="hosts",
                to_ref="system:v1-runtime",
            )
            create_relationship(
                session,
                from_ref="system:v1-runtime",
                relation_type="hosts",
                to_ref="service:v1-runtime-api",
            )
            create_relationship(
                session,
                from_ref="service:v1-runtime-api",
                relation_type="depends_on",
                to_ref="service:v1-auth",
            )
            upsert_object(
                session,
                CatalogObjectIn(
                    id="v1-runtime-api",
                    kind="service",
                    label="V1 Runtime API",
                    lifecycle="active",
                    health="degraded",
                    data={
                        "schema_version": 1,
                        "endpoints": [
                            {
                                "type": "REST API",
                                "url": "https://10.43.0.20:8443/api",
                                "host": "10.43.0.20",
                                "port": 8443,
                                "protocol": "https",
                            }
                        ],
                    },
                ),
            )
    return alembic_session_factory


@pytest.fixture
def client(
    session_factory,
    install_unrestricted_read_access,
) -> Generator[TestClient, None, None]:
    app = create_app()
    install_unrestricted_read_access(app)

    def override_get_session() -> Generator[Session, None, None]:
        with session_factory() as session:
            yield session

    app.dependency_overrides[get_session] = override_get_session
    with TestClient(app) as test_client:
        yield test_client


def test_v1_object_list_enumerates_stable_keyset_pages(client: TestClient) -> None:
    cursor = None
    seen: list[tuple[str, str]] = []
    totals: list[int | None] = []
    while True:
        response = client.get(
            "/api/v1/objects",
            params={
                "limit": 2,
                "sort": "label",
                "cursor": cursor,
                "include_total": "true",
            },
        )
        assert response.status_code == 200, (cursor, response.text)
        payload = response.json()
        assert payload["sort"] == "label"
        assert payload["direction"] == "asc"
        totals.append(payload["total"])
        seen.extend(
            (item["label"].casefold(), item["id"])
            for item in payload["items"]
        )
        cursor = payload["next_cursor"]
        if cursor is None:
            break

    assert totals == [7, 7, 7, 7]
    assert seen == sorted(seen)
    assert len(seen) == len(set(seen)) == 7


def test_v1_filters_source_type_and_computed_staleness(client: TestClient) -> None:
    response = client.get(
        "/api/v1/objects",
        params={"source_type": "import", "stale": "true", "include_total": "true"},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["total"] == 1
    assert [item["id"] for item in payload["items"]] == ["v1-runbook"]
    assert payload["items"][0]["provenance"]["is_stale"] is True


def test_v1_cursor_is_bound_to_filters_sort_and_direction(
    client: TestClient,
) -> None:
    first = client.get(
        "/api/v1/objects",
        params={"kind": "service", "limit": 1},
    )
    cursor = first.json()["next_cursor"]
    assert cursor

    response = client.get(
        "/api/v1/objects",
        params={
            "kind": "host",
            "limit": 1,
            "cursor": cursor,
        },
        headers={"X-Correlation-ID": "v1-cursor-proof"},
    )

    assert response.status_code == 400
    assert response.json() == {
        "error": {
            "code": "invalid_request",
            "message": "Cursor is invalid or does not match the active query",
            "correlation_id": "v1-cursor-proof",
        }
    }
    assert client.get(
        "/api/v1/objects",
        params={
            "kind": "service",
            "limit": 1,
            "cursor": cursor,
            "sort": "label",
        },
    ).status_code == 400
    assert client.get(
        "/api/v1/objects",
        params={
            "kind": "service",
            "limit": 1,
            "cursor": cursor,
            "direction": "desc",
        },
    ).status_code == 400


def test_v1_descending_label_pages_keep_the_id_tie_breaker(
    client: TestClient,
) -> None:
    cursor = None
    seen: list[tuple[str, str]] = []
    while True:
        response = client.get(
            "/api/v1/objects",
            params={
                "kind": "service",
                "sort": "label",
                "direction": "desc",
                "limit": 1,
                "cursor": cursor,
            },
        )
        assert response.status_code == 200, (cursor, response.text)
        payload = response.json()
        seen.extend(
            (item["label"].casefold(), item["id"])
            for item in payload["items"]
        )
        cursor = payload["next_cursor"]
        if cursor is None:
            break

    assert seen == sorted(seen, reverse=True)
    assert len(seen) == len(set(seen)) == 4


def test_v1_structured_filters_use_canonical_resolved_model(
    client: TestClient,
) -> None:
    response = client.get(
        "/api/v1/objects",
        params={
            "q": "runtime",
            "kind": "service",
            "parent": "host:v1-host",
            "ip": "10.43.0.20",
            "port": 8443,
            "endpoint_type": "REST API",
            "protocol": "https",
            "status": "active",
            "lifecycle": "active",
            "health": "degraded",
        },
    )

    assert response.status_code == 200
    assert [item["ref"] for item in response.json()["items"]] == [
        "service:v1-runtime-api"
    ]


def test_v1_context_page_and_detail_share_the_agent_projection(
    client: TestClient,
) -> None:
    page = client.get(
        "/api/v1/context",
        params={"kind": "service", "limit": 1, "include_total": "true"},
    )
    detail = client.get("/api/v1/objects/v1-runtime-api")

    assert page.status_code == 200
    assert page.json()["total"] == 4
    assert page.json()["next_cursor"]
    assert page.json()["items"][0]["kind"] == "service"
    assert detail.status_code == 200
    assert detail.json()["ref"] == "service:v1-runtime-api"
    assert [node["ref"] for node in detail.json()["parent_path"]] == [
        "host:v1-host",
        "system:v1-runtime",
    ]


def test_v1_detail_keeps_corrupt_or_secret_shaped_data_safe(
    client: TestClient,
    session_factory,
) -> None:
    with session_factory() as session:
        session.add(
            CatalogObject(
                id="v1-unsafe",
                kind="service",
                label="V1 Unsafe",
                status="active",
                lifecycle="active",
                health="unknown",
                data_json='{"schema_version":1,"password":"must-not-leak"}',
            )
        )
        session.commit()

    response = client.get("/api/v1/objects/v1-unsafe")

    assert response.status_code == 200
    assert "must-not-leak" not in response.text
    assert response.json()["data"]["password"] == "[redacted-secret-field]"
    assert response.json()["record_state"] == "corrupt"


def test_v1_relationship_and_audit_lists_are_paginated(
    client: TestClient,
) -> None:
    relationships = client.get(
        "/api/v1/objects/v1-runtime-api/relationships",
        params={"limit": 1, "include_total": "true"},
    )
    audits = client.get(
        "/api/v1/objects/v1-runtime-api/audit-events",
        params={"limit": 1, "include_total": "true"},
    )

    assert relationships.status_code == 200
    assert relationships.json()["total"] == 2
    assert relationships.json()["next_cursor"]
    second_relationship = client.get(
        "/api/v1/objects/v1-runtime-api/relationships",
        params={
            "limit": 1,
            "cursor": relationships.json()["next_cursor"],
        },
    )
    relationship_items = [
        *relationships.json()["items"],
        *second_relationship.json()["items"],
    ]
    assert len(
        {
            (
                item["from_ref"],
                item["relation_type"],
                item["to_ref"],
            )
            for item in relationship_items
        }
    ) == 2

    assert audits.status_code == 200
    assert audits.json()["total"] >= 2
    assert audits.json()["next_cursor"]
    assert audits.json()["items"][0]["created_at"].endswith("Z")
    assert isinstance(audits.json()["items"][0]["id"], int)


def test_v1_topology_uses_the_canonical_host_system_service_chain(
    client: TestClient,
) -> None:
    response = client.get("/api/v1/objects/v1-runtime-api/topology")

    assert response.status_code == 200
    payload = response.json()
    assert payload["object_ref"] == "service:v1-runtime-api"
    chain = payload["chains"][0]
    assert [node["ref"] for node in chain["hosts"]] == ["host:v1-host"]
    assert [node["ref"] for node in chain["systems"]] == ["system:v1-runtime"]
    assert [node["ref"] for node in chain["services"]] == [
        "service:v1-runtime-api"
    ]


def test_v1_can_enumerate_more_than_the_legacy_agent_limit(
    client: TestClient,
    session_factory,
) -> None:
    with session_factory() as session:
        session.add_all(
            [
                CatalogObject(
                    id=f"bulk-{index:03d}",
                    kind="service",
                    label=f"Bulk {index:03d}",
                    status="active",
                    lifecycle="active",
                    health="unknown",
                    data_json='{"schema_version":1}',
                )
                for index in range(125)
            ]
        )
        session.commit()

    cursor = None
    seen: list[str] = []
    total = None
    while True:
        response = client.get(
            "/api/v1/objects",
            params={
                "q": "bulk-",
                "kind": "service",
                "limit": 37,
                "cursor": cursor,
                "include_total": "true",
            },
        )
        assert response.status_code == 200, (cursor, response.text)
        payload = response.json()
        total = payload["total"]
        seen.extend(item["id"] for item in payload["items"])
        cursor = payload["next_cursor"]
        if cursor is None:
            break

    assert total == 125
    assert seen == [f"bulk-{index:03d}" for index in range(125)]
    assert len(seen) == len(set(seen))


def test_v1_publishes_explicit_command_methods_and_compatibility_reads(
    client: TestClient,
) -> None:
    openapi = client.get("/openapi.json").json()
    v1_paths = {
        path: methods
        for path, methods in openapi["paths"].items()
        if path.startswith("/api/v1")
    }

    assert v1_paths
    assert set(v1_paths["/api/v1/objects/{object_id}"]) == {
        "get",
        "put",
        "delete",
    }
    assert set(v1_paths["/api/v1/objects/{object_id}/relationships"]) == {
        "get",
        "post",
        "delete",
    }
    assert set(v1_paths["/api/v1/objects/{parent_id}/children"]) == {"post"}
    assert client.post("/api/v1/objects", json={}).status_code == 405
    assert isinstance(client.get("/api/objects").json(), list)
    assert "results" in client.get("/api/agent/search").json()


@pytest.mark.parametrize(
    "path",
    [
        "/api/v1/objects/missing",
        "/api/v1/objects/missing/relationships",
        "/api/v1/objects/missing/audit-events",
        "/api/v1/objects/missing/network-topology",
        "/api/v1/objects/missing/topology",
    ],
)
def test_v1_missing_resources_return_404(
    client: TestClient,
    path: str,
) -> None:
    response = client.get(path)

    assert response.status_code == 404
    assert response.json()["error"]["code"] == "not_found"
