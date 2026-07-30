from collections.abc import Generator
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session

from blockwart.api.deps import get_session
from blockwart.domain.catalog_data import load_catalog_data
from blockwart.domain.timestamps import format_rfc3339_utc
from blockwart.main import create_app
from blockwart.models import AuditEvent, CatalogObject
from blockwart.services.catalog import list_audit_events_for_object


@pytest.fixture
def session_factory(alembic_session_factory):
    return alembic_session_factory


@contextmanager
def _client(
    session_factory,
    install_unrestricted_read_access,
) -> Generator[TestClient, None, None]:
    app = create_app()
    install_unrestricted_read_access(app)

    def override_get_session() -> Generator[Session, None, None]:
        with session_factory() as session:
            yield session

    app.dependency_overrides[get_session] = override_get_session
    with TestClient(app) as client:
        yield client


def test_external_timestamps_are_rfc3339_utc_and_legacy_naive_values_are_utc(
    session_factory,
    install_unrestricted_read_access,
) -> None:
    legacy_timestamp = datetime(2026, 7, 22, 21, 7, 38, 123456)
    with session_factory() as session:
        session.add(
            CatalogObject(
                id="legacy-time",
                kind="service",
                label="Legacy Time",
                status="active",
                lifecycle="active",
                health="unknown",
                data_json='{"schema_version": 1}',
                created_at=legacy_timestamp,
                updated_at=legacy_timestamp,
            )
        )
        session.add(
            AuditEvent(
                object_id="legacy-time",
                action="update",
                actor="test",
                summary="Timestamp proof",
                created_at=legacy_timestamp,
            )
        )
        session.commit()

    with _client(session_factory, install_unrestricted_read_access) as client:
        response = client.get("/api/objects/legacy-time")
        agent_response = client.get("/api/agent/objects/legacy-time")

    assert response.status_code == 200
    assert response.json()["created_at"] == "2026-07-22T21:07:38.123456Z"
    assert response.json()["updated_at"] == "2026-07-22T21:07:38.123456Z"
    assert (
        agent_response.json()["objects"][0]["updated_at"]
        == "2026-07-22T21:07:38.123456Z"
    )
    with session_factory() as session:
        audits = list_audit_events_for_object(session, "legacy-time")
    assert audits[0]["created_at"] == "2026-07-22T21:07:38.123456Z"

    offset_value = datetime(
        2026,
        7,
        22,
        23,
        7,
        38,
        123456,
        tzinfo=timezone(timedelta(hours=2)),
    )
    assert format_rfc3339_utc(offset_value) == "2026-07-22T21:07:38.123456Z"


def test_non_object_catalog_json_is_explicitly_corrupt() -> None:
    record = load_catalog_data("array-row", "[]")

    assert record.data == {}
    assert record.record_state == "corrupt"
    assert record.diagnostics[0].code == "corrupt_record"
    assert record.diagnostics[0].object_id == "array-row"
    assert record.diagnostics[0].message == (
        "Catalog object array-row data_json is not an object"
    )


def test_corrupt_catalog_row_is_marked_without_breaking_catalog_or_agent_reads(
    session_factory,
    install_unrestricted_read_access,
) -> None:
    with session_factory() as session:
        session.add_all(
            [
                CatalogObject(
                    id="healthy-row",
                    kind="service",
                    label="Healthy Row",
                    status="active",
                    lifecycle="active",
                    health="healthy",
                    data_json='{"schema_version": 1}',
                ),
                CatalogObject(
                    id="corrupt-row",
                    kind="service",
                    label="Corrupt Row",
                    status="active",
                    lifecycle="active",
                    health="unknown",
                    data_json='{"password":"must-not-leak"',
                ),
                CatalogObject(
                    id="schema-corrupt-row",
                    kind="service",
                    label="Schema Corrupt Row",
                    status="active",
                    lifecycle="active",
                    health="unknown",
                    data_json=(
                        '{"schema_version":1,"password":"schema-secret-must-not-leak"}'
                    ),
                ),
            ]
        )
        session.commit()

    with _client(session_factory, install_unrestricted_read_access) as client:
        catalog_response = client.get("/api/objects")
        catalog_detail = client.get("/api/objects/corrupt-row")
        schema_corrupt_detail = client.get("/api/objects/schema-corrupt-row")
        agent_search = client.get("/api/agent/search", params={"q": "Corrupt Row"})
        agent_detail = client.get("/api/agent/objects/corrupt-row")

    assert catalog_response.status_code == 200
    assert {item["id"] for item in catalog_response.json()} == {
        "corrupt-row",
        "healthy-row",
        "schema-corrupt-row",
    }
    corrupt = catalog_detail.json()
    assert corrupt["data"] == {}
    assert corrupt["record_state"] == "corrupt"
    assert corrupt["diagnostics"] == [
        {
            "code": "corrupt_record",
            "object_id": "corrupt-row",
            "message": "Catalog object corrupt-row has invalid data_json",
        }
    ]
    assert "must-not-leak" not in catalog_response.text
    assert "must-not-leak" not in catalog_detail.text
    assert schema_corrupt_detail.json()["record_state"] == "corrupt"
    assert schema_corrupt_detail.json()["data"] == {}
    assert schema_corrupt_detail.json()["diagnostics"][0]["message"] == (
        "Catalog object schema-corrupt-row violates the catalog schema"
    )
    assert "schema-secret-must-not-leak" not in schema_corrupt_detail.text

    assert agent_search.status_code == 200
    assert agent_search.json()["results"][0]["record_state"] == "corrupt"
    assert agent_detail.status_code == 200
    agent_object = agent_detail.json()["objects"][0]
    assert agent_object["data"] == {}
    assert agent_object["record_state"] == "corrupt"
    assert agent_object["diagnostics"][0]["object_id"] == "corrupt-row"
    assert "must-not-leak" not in agent_detail.text


def test_api_error_envelope_distinguishes_not_found_validation_and_conflict(
    session_factory,
    install_unrestricted_read_access,
) -> None:
    correlation_id = "boundary-proof-47"
    with _client(session_factory, install_unrestricted_read_access) as client:
        not_found = client.get(
            "/api/objects/missing",
            headers={"X-Correlation-ID": correlation_id},
        )
        invalid = client.get(
            "/api/objects",
            params={"health": "reachable"},
            headers={"X-Correlation-ID": correlation_id},
        )

    assert not_found.status_code == 404
    assert not_found.headers["X-Correlation-ID"] == correlation_id
    assert not_found.json() == {
        "error": {
            "code": "not_found",
            "message": "Catalog object not found",
            "correlation_id": correlation_id,
        }
    }
    assert invalid.status_code == 422
    assert invalid.json()["error"]["code"] == "validation_error"
    assert invalid.json()["error"]["correlation_id"] == correlation_id
    assert invalid.json()["error"]["details"][0]["location"] == "query.health"
    assert "input" not in invalid.json()["error"]["details"][0]

    app = create_app()

    @app.get("/api/test-conflict")
    def conflict() -> None:
        raise HTTPException(status_code=409, detail="Resource changed")

    with TestClient(app) as client:
        conflict_response = client.get(
            "/api/test-conflict",
            headers={"X-Correlation-ID": correlation_id},
        )
    assert conflict_response.status_code == 409
    assert conflict_response.json()["error"] == {
        "code": "conflict",
        "message": "Resource changed",
        "correlation_id": correlation_id,
    }


def test_api_database_failure_is_stable_and_redacted() -> None:
    app = create_app()

    def unavailable_session():
        raise OperationalError(
            "SELECT sensitive_column",
            {},
            RuntimeError("must-not-leak"),
        )
        yield

    app.dependency_overrides[get_session] = unavailable_session
    with TestClient(app) as client:
        response = client.get(
            "/api/objects",
            headers={"X-Correlation-ID": "db-proof-47"},
        )

    assert response.status_code == 503
    assert response.json() == {
        "error": {
            "code": "db_unavailable",
            "message": "Database is unavailable.",
            "correlation_id": "db-proof-47",
        }
    }
    assert response.headers["X-Correlation-ID"] == "db-proof-47"
    assert "sensitive" not in response.text
    assert "must-not-leak" not in response.text


def test_unexpected_api_failure_is_stable_and_redacted() -> None:
    app = create_app()

    @app.get("/api/test-internal-error")
    def internal_error() -> None:
        raise RuntimeError("must-not-leak")

    with TestClient(app) as client:
        response = client.get(
            "/api/test-internal-error",
            headers={"X-Correlation-ID": "internal-proof-47"},
        )

    assert response.status_code == 500
    assert response.json() == {
        "error": {
            "code": "internal_error",
            "message": "Request processing failed.",
            "correlation_id": "internal-proof-47",
        }
    }
    assert response.headers["X-Correlation-ID"] == "internal-proof-47"
    assert "must-not-leak" not in response.text


def test_invalid_correlation_id_is_replaced(
    install_unrestricted_read_access,
) -> None:
    app = create_app()
    install_unrestricted_read_access(app)
    with TestClient(app) as client:
        response = client.get(
            "/api/objects/missing",
            headers={"X-Correlation-ID": "contains spaces and is invalid"},
        )

    correlation_id = response.headers["X-Correlation-ID"]
    assert correlation_id != "contains spaces and is invalid"
    assert response.json()["error"]["correlation_id"] == correlation_id
