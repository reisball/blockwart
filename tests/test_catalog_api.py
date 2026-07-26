from collections.abc import Generator

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.orm import Session

from blockwart.api.deps import get_session
from blockwart.db.session import transaction
from blockwart.main import create_app
from blockwart.models import AuditEvent, CatalogObject, Relationship
from blockwart.schemas.catalog import CatalogObjectIn
from blockwart.services.catalog import delete_object, upsert_object


@pytest.fixture
def session_factory(alembic_session_factory):
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


def test_get_and_list_catalog_objects_are_read_only(client: TestClient, session_factory) -> None:
    with session_factory() as session:
        with transaction(session):
            created = upsert_object(
                session,
                CatalogObjectIn(
                    id="n8n",
                    kind="system",
                    label="n8n",
                    status="active",
                    data={
                        "schema_version": 1,
                        "network": {
                            "hostnames": ["n8n.local"],
                            "addresses": [{"ip": "192.168.50.83", "family": "ipv4"}],
                        },
                        "ports": [{"port": 5678, "protocol": "tcp", "exposure": "lan"}],
                    },
                ),
            )
    get_response = client.get("/api/objects/n8n")
    assert get_response.status_code == 200
    assert get_response.json()["created_at"] == created.created_at
    assert get_response.json()["data"]["network"]["addresses"][0]["ip"] == "192.168.50.83"
    assert get_response.json()["placement_state"] == "unknown"
    assert get_response.json()["provenance"] == {
        "source_type": "manual",
        "source_ref": None,
        "managed_by": None,
        "observed_at": None,
        "verified_at": None,
        "stale_after": None,
        "manual_override": True,
        "is_stale": False,
    }

    list_response = client.get("/api/objects")
    assert list_response.status_code == 200
    assert [item["id"] for item in list_response.json()] == ["n8n"]


def test_get_missing_catalog_object_returns_404(client: TestClient) -> None:
    response = client.get("/api/objects/missing")

    assert response.status_code == 404


def test_catalog_input_rejects_unsupported_status() -> None:
    with pytest.raises(ValidationError):
        CatalogObjectIn.model_validate(
            {
                "id": "bad-status",
                "kind": "system",
                "label": "Bad Status",
                "status": "partial",
                "data": {"schema_version": 1},
            }
        )


def test_catalog_input_rejects_invalid_or_non_asset_state_fields() -> None:
    with pytest.raises(ValidationError):
        CatalogObjectIn.model_validate(
            {
                "id": "invalid-health",
                "kind": "service",
                "label": "Invalid Health",
                "lifecycle": "active",
                "health": "reachable",
            }
        )
    with pytest.raises(ValidationError, match="only valid for asset kinds"):
        CatalogObjectIn.model_validate(
            {
                "id": "invalid-runbook-state",
                "kind": "runbook",
                "label": "Invalid Runbook State",
                "lifecycle": "active",
                "health": "unknown",
            }
        )
    with pytest.raises(ValidationError, match="top-level fields"):
        CatalogObjectIn.model_validate(
            {
                "id": "legacy-data-state",
                "kind": "service",
                "label": "Legacy Data State",
                "data": {"lifecycle": "active", "health": "healthy"},
            }
        )


def test_catalog_rest_filters_canonical_lifecycle_and_health(
    client: TestClient,
    session_factory,
) -> None:
    with session_factory() as session:
        with transaction(session):
            active = upsert_object(
                session,
                CatalogObjectIn(
                    id="active-api",
                    kind="service",
                    label="Active API",
                    lifecycle="active",
                    health="healthy",
                    data={"schema_version": 1},
                ),
            )
            down = upsert_object(
                session,
                CatalogObjectIn(
                    id="down-api",
                    kind="service",
                    label="Down API",
                    lifecycle="active",
                    health="down",
                    data={"schema_version": 1},
                ),
            )
            planned = upsert_object(
                session,
                CatalogObjectIn(
                    id="planned-api",
                    kind="service",
                    label="Planned API",
                    status="inactive",
                    data={"schema_version": 1},
                ),
            )

    assert (active.status, active.lifecycle, active.health) == (
        "active",
        "active",
        "healthy",
    )
    assert (down.status, down.lifecycle, down.health) == (
        "inactive",
        "active",
        "down",
    )
    assert (planned.status, planned.lifecycle, planned.health) == (
        "inactive",
        "planned",
        "unknown",
    )
    active_results = client.get(
        "/api/objects",
        params={"lifecycle": "active", "health": "healthy"},
    )
    planned_results = client.get(
        "/api/objects",
        params={"lifecycle": "planned", "health": "unknown"},
    )

    assert active_results.status_code == 200
    assert [item["id"] for item in active_results.json()] == ["active-api"]
    assert planned_results.status_code == 200
    assert [item["id"] for item in planned_results.json()] == ["planned-api"]
    assert client.get("/api/objects", params={"health": "reachable"}).status_code == 422


def test_asset_state_changes_have_distinct_audit_fields(session_factory) -> None:
    with session_factory() as session:
        with transaction(session):
            upsert_object(
                session,
                CatalogObjectIn(
                    id="state-audit",
                    kind="service",
                    label="State Audit",
                    data={"schema_version": 1},
                ),
            )
            upsert_object(
                session,
                CatalogObjectIn(
                    id="state-audit",
                    kind="service",
                    label="State Audit",
                    lifecycle="active",
                    health="degraded",
                    data={"schema_version": 1},
                ),
            )

    with session_factory() as session:
        audits = session.scalars(
            select(AuditEvent)
            .where(AuditEvent.object_id == "state-audit")
            .order_by(AuditEvent.id)
        ).all()

    assert len(audits) == 2
    assert "Feld Health wurde von unknown auf degraded geändert" in audits[-1].summary
    assert "Lifecycle" not in audits[-1].summary


def test_catalog_input_accepts_only_explicit_unassigned_placement_metadata() -> None:
    accepted = CatalogObjectIn.model_validate(
        {
            "id": "pending",
            "kind": "service",
            "label": "Pending",
            "data": {
                "schema_version": 1,
                "placement": {
                    "state": "unassigned",
                    "reason": "No parent decision yet",
                },
            },
        }
    )
    assert accepted.data["placement"]["state"] == "unassigned"

    with pytest.raises(ValidationError, match="must be unassigned"):
        CatalogObjectIn.model_validate(
            {
                "id": "invalid-placement",
                "kind": "service",
                "label": "Invalid Placement",
                "data": {
                    "schema_version": 1,
                    "placement": {"state": "assigned"},
                },
            }
        )


def test_delete_catalog_object_writes_audit_event(session_factory) -> None:
    with session_factory() as session:
        with transaction(session):
            upsert_object(
                session,
                CatalogObjectIn(
                    id="vaultwarden-api",
                    kind="credential_reference",
                    label="Vaultwarden API",
                    status="active",
                    data={"schema_version": 1},
                ),
            )
            upsert_object(
                session,
                CatalogObjectIn(
                    id="rotate-vaultwarden",
                    kind="runbook",
                    label="Rotate Vaultwarden",
                    status="active",
                    summary="Credential rotation procedure.",
                    data={
                        "schema_version": 1,
                        "risk_level": "safe-change",
                        "approval_required": False,
                        "steps": [{"order": 1, "title": "Open referenced vault item"}],
                        "credential_references": ["credential_reference:vaultwarden-api"],
                    },
                ),
            )
            assert delete_object(session, "rotate-vaultwarden")
        events = session.scalars(select(AuditEvent).order_by(AuditEvent.id)).all()
    assert [event.action for event in events] == ["create", "create", "delete"]
    assert events[-1].object_id == "rotate-vaultwarden"
    assert "runbook:rotate-vaultwarden" in events[-1].summary


def test_delete_catalog_object_blocks_existing_relationship_edges(
    session_factory,
) -> None:
    with session_factory() as session:
        with transaction(session):
            upsert_object(
                session,
                CatalogObjectIn(
                    id="n8n",
                    kind="system",
                    label="n8n",
                    status="active",
                    data={"schema_version": 1},
                ),
            )
            upsert_object(
                session,
                CatalogObjectIn(
                    id="n8n-web-ui",
                    kind="service",
                    label="n8n Web UI",
                    status="active",
                    data={"schema_version": 1},
                ),
            )
            session.add(
                Relationship(
                    from_ref="system:n8n",
                    relation_type="hosts",
                    to_ref="service:n8n-web-ui",
                )
            )
        with pytest.raises(ValueError, match="cannot delete service:n8n-web-ui"):
            with transaction(session):
                delete_object(session, "n8n-web-ui")
        assert len(session.scalars(select(Relationship)).all()) == 1
        assert session.get(CatalogObject, "n8n-web-ui") is not None
        events = session.scalars(select(AuditEvent).order_by(AuditEvent.id)).all()
    assert [event.action for event in events] == ["create", "create"]
    assert events[1].object_id == "n8n-web-ui"


def test_delete_missing_catalog_object_returns_false(session_factory) -> None:
    with session_factory() as session:
        assert not delete_object(session, "missing")


def test_catalog_input_rejects_secret_shaped_payload() -> None:
    with pytest.raises(ValidationError):
        CatalogObjectIn.model_validate(
            {
                "id": "bad-service",
                "kind": "service",
                "label": "Bad Service",
                "data": {"auth": {"token": "not-allowed"}},
            }
        )


def test_catalog_input_rejects_credential_reference_value_fields() -> None:
    with pytest.raises(ValidationError):
        CatalogObjectIn.model_validate(
            {
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
            }
        )
