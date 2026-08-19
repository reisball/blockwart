"""Regression tests for the Gatus webhook receiver (#177).

These tests exercise the push-based observation path: Gatus alert payload →
MonitoringObservation(provider="gatus") → record_service_observation().

Covered scenarios:
- Basic TRIGGERED and RESOLVED alerts create observations.
- Duplicate payloads (same checked_at) do not overwrite.
- Replays after a newer observation are rejected by the seam's guard.
- Out-of-order deliveries (older timestamp after newer) do not overwrite.
- Unknown endpoint identity → 404 fail-closed.
- Ambiguous mapping (two services match) → 409 fail-closed.
- Missing data.gatus mapping → 404.
- Maintenance precedence: a maintenance catalog_health is not overwritten
  because the webhook writes observations, not catalog health.
- Auth failure (no token) → 401.
- Policy denial (token not authorized for the service) → 403.
- No alert descriptions or error text are persisted.
- checked_at from the Gatus event, not server now(), is used for idempotency.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient
from sqlalchemy import select

from blockwart.api.deps import get_session
from blockwart.config import Settings
from blockwart.domain.auth import Permission, PrincipalContext, PrincipalType
from blockwart.main import create_app
from blockwart.models import CatalogObject, ServiceObservation
from blockwart.schemas.catalog import CatalogObjectIn
from blockwart.services.catalog import upsert_object
from blockwart.services.policy import PolicySnapshot
from blockwart.services.read_access import ReadAccess

NOW = datetime(2026, 8, 19, 12, 0, tzinfo=UTC)


def _service(
    object_id: str,
    *,
    gatus: dict | None = None,
    monitoring: dict | None = None,
    health: str = "unknown",
) -> CatalogObjectIn:
    data: dict = {"schema_version": 1}
    if gatus is not None:
        data["gatus"] = gatus
    if monitoring is not None:
        data["monitoring"] = monitoring
    return CatalogObjectIn(
        id=object_id,
        kind="service",
        label=object_id,
        lifecycle="active",
        health=health,
        data=data,
    )


def _gatus_payload(
    *,
    endpoint: str = "api-gateway",
    group: str | None = "core",
    source: str | None = None,
    alert: str = "TRIGGERED",
    timestamp: str | None = None,
    http_status: int | None = 503,
    latency_ms: int | None = 120,
) -> dict:
    if timestamp is None:
        timestamp = NOW.isoformat()
    payload: dict = {
        "endpoint": endpoint,
        "alert": alert,
        "timestamp": timestamp,
    }
    if group is not None:
        payload["group"] = group
    if source is not None:
        payload["source"] = source
    if http_status is not None:
        payload["http_status"] = http_status
    if latency_ms is not None:
        payload["latency_ms"] = latency_ms
    return payload


def _install_app_with_unrestricted_access(
    alembic_session_factory,
    install_unrestricted_read_access,
):
    app = create_app(settings=Settings())
    install_unrestricted_read_access(app)

    def override_get_session():
        with alembic_session_factory() as session:
            yield session

    app.dependency_overrides[get_session] = override_get_session
    return app


def _install_app_with_restricted_access(
    alembic_session_factory,
    allowed_object_ids: set[str],
):
    """Install a ReadAccess override that only allows DISCOVER on specific objects."""

    app = create_app(settings=Settings())

    def override_get_session():
        with alembic_session_factory() as session:
            yield session

    app.dependency_overrides[get_session] = override_get_session

    def restricted_access(
        session,
    ) -> ReadAccess:
        return ReadAccess(
            principal=PrincipalContext(
                id="test-restricted-principal",
                principal_type=PrincipalType.SERVICE_ACCOUNT,
                login="test-restricted",
                display_name="Test Restricted",
            ),
            policy=PolicySnapshot(
                principal_id="test-restricted-principal",
                _permissions={
                    object_id: frozenset({Permission.DISCOVER, Permission.READ})
                    for object_id in allowed_object_ids
                },
                _grants={},
            ),
        )

    from blockwart.api.security import require_api_read_access

    app.dependency_overrides[require_api_read_access] = restricted_access
    return app


# ---------------------------------------------------------------------------
# Basic ingestion: TRIGGERED and RESOLVED
# ---------------------------------------------------------------------------


def test_gatus_triggered_creates_down_observation(
    alembic_session_factory,
    install_unrestricted_read_access,
) -> None:
    with alembic_session_factory() as session:
        upsert_object(
            session,
            _service(
                "api-gateway",
                gatus={"endpoint": "api-gateway", "group": "core"},
                monitoring={"enabled": True, "provider": "gatus"},
            ),
        )
        session.commit()

    app = _install_app_with_unrestricted_access(
        alembic_session_factory, install_unrestricted_read_access
    )
    with TestClient(app) as client:
        response = client.post(
            "/api/v1/webhooks/gatus",
            json=_gatus_payload(
                endpoint="api-gateway",
                alert="TRIGGERED",
                http_status=503,
            ),
        )

    assert response.status_code == 200
    body = response.json()
    assert body["object_id"] == "api-gateway"
    assert body["state"] == "down"
    assert body["ingested"] is True

    with alembic_session_factory() as session:
        obs = session.scalar(
            select(ServiceObservation).where(
                ServiceObservation.object_id == "api-gateway",
                ServiceObservation.provider == "gatus",
            )
        )
        assert obs is not None
        assert obs.state == "down"
        assert obs.http_status == 503
        assert obs.latency_ms == 120


def test_gatus_resolved_creates_healthy_observation(
    alembic_session_factory,
    install_unrestricted_read_access,
) -> None:
    with alembic_session_factory() as session:
        upsert_object(
            session,
            _service(
                "api-gateway",
                gatus={"endpoint": "api-gateway", "group": "core"},
                monitoring={"enabled": True, "provider": "gatus"},
            ),
        )
        session.commit()

    app = _install_app_with_unrestricted_access(
        alembic_session_factory, install_unrestricted_read_access
    )
    with TestClient(app) as client:
        response = client.post(
            "/api/v1/webhooks/gatus",
            json=_gatus_payload(
                endpoint="api-gateway",
                alert="RESOLVED",
                http_status=200,
            ),
        )

    assert response.status_code == 200
    body = response.json()
    assert body["state"] == "healthy"

    with alembic_session_factory() as session:
        obs = session.scalar(
            select(ServiceObservation).where(
                ServiceObservation.object_id == "api-gateway",
                ServiceObservation.provider == "gatus",
            )
        )
        assert obs is not None
        assert obs.state == "healthy"
        assert obs.http_status == 200
        assert obs.last_success_at is not None


# ---------------------------------------------------------------------------
# Idempotency: duplicates, replays, out-of-order
# ---------------------------------------------------------------------------


def test_duplicate_payload_does_not_overwrite(
    alembic_session_factory,
    install_unrestricted_read_access,
) -> None:
    with alembic_session_factory() as session:
        upsert_object(
            session,
            _service(
                "dup-service",
                gatus={"endpoint": "dup-service"},
                monitoring={"enabled": True, "provider": "gatus"},
            ),
        )
        session.commit()

    app = _install_app_with_unrestricted_access(
        alembic_session_factory, install_unrestricted_read_access
    )
    ts = NOW.isoformat()
    with TestClient(app) as client:
        first = client.post(
            "/api/v1/webhooks/gatus",
            json=_gatus_payload(endpoint="dup-service", timestamp=ts, http_status=503),
        )
        second = client.post(
            "/api/v1/webhooks/gatus",
            json=_gatus_payload(endpoint="dup-service", timestamp=ts, http_status=503),
        )

    assert first.status_code == 200
    assert second.status_code == 200
    assert first.json() == second.json()


def test_out_of_order_older_timestamp_does_not_overwrite(
    alembic_session_factory,
    install_unrestricted_read_access,
) -> None:
    with alembic_session_factory() as session:
        upsert_object(
            session,
            _service(
                "ooo-service",
                gatus={"endpoint": "ooo-service"},
                monitoring={"enabled": True, "provider": "gatus"},
            ),
        )
        session.commit()

    app = _install_app_with_unrestricted_access(
        alembic_session_factory, install_unrestricted_read_access
    )
    later_ts = (NOW + timedelta(minutes=5)).isoformat()
    earlier_ts = NOW.isoformat()
    with TestClient(app) as client:
        first = client.post(
            "/api/v1/webhooks/gatus",
            json=_gatus_payload(
                endpoint="ooo-service",
                timestamp=later_ts,
                alert="TRIGGERED",
                http_status=503,
            ),
        )
        client.post(
            "/api/v1/webhooks/gatus",
            json=_gatus_payload(
                endpoint="ooo-service",
                timestamp=earlier_ts,
                alert="RESOLVED",
                http_status=200,
            ),
        )

    assert first.status_code == 200
    assert first.json()["state"] == "down"

    # The older RESOLVED must not overwrite the newer TRIGGERED.
    with alembic_session_factory() as session:
        obs = session.scalar(
            select(ServiceObservation).where(
                ServiceObservation.object_id == "ooo-service",
                ServiceObservation.provider == "gatus",
            )
        )
        assert obs is not None
        assert obs.state == "down"
        assert obs.http_status == 503


def test_replay_after_newer_observation_is_rejected(
    alembic_session_factory,
    install_unrestricted_read_access,
) -> None:
    with alembic_session_factory() as session:
        upsert_object(
            session,
            _service(
                "replay-service",
                gatus={"endpoint": "replay-service"},
                monitoring={"enabled": True, "provider": "gatus"},
            ),
        )
        session.commit()

    app = _install_app_with_unrestricted_access(
        alembic_session_factory, install_unrestricted_read_access
    )
    ts1 = NOW.isoformat()
    ts2 = (NOW + timedelta(minutes=10)).isoformat()
    with TestClient(app) as client:
        # First: TRIGGERED at NOW
        client.post(
            "/api/v1/webhooks/gatus",
            json=_gatus_payload(
                endpoint="replay-service",
                timestamp=ts1,
                alert="TRIGGERED",
            ),
        )
        # Second: RESOLVED at NOW+10
        client.post(
            "/api/v1/webhooks/gatus",
            json=_gatus_payload(
                endpoint="replay-service",
                timestamp=ts2,
                alert="RESOLVED",
            ),
        )
        # Replay: TRIGGERED at NOW (stale)
        client.post(
            "/api/v1/webhooks/gatus",
            json=_gatus_payload(
                endpoint="replay-service",
                timestamp=ts1,
                alert="TRIGGERED",
            ),
        )

    with alembic_session_factory() as session:
        obs = session.scalar(
            select(ServiceObservation).where(
                ServiceObservation.object_id == "replay-service",
                ServiceObservation.provider == "gatus",
            )
        )
        assert obs is not None
        assert obs.state == "healthy"
        assert obs.http_status == 200


# ---------------------------------------------------------------------------
# Fail-closed: unknown, ambiguous, missing mapping
# ---------------------------------------------------------------------------


def test_unknown_endpoint_returns_404(
    alembic_session_factory,
    install_unrestricted_read_access,
) -> None:
    with alembic_session_factory() as session:
        upsert_object(
            session,
            _service(
                "known-service",
                gatus={"endpoint": "known-service"},
                monitoring={"enabled": True, "provider": "gatus"},
            ),
        )
        session.commit()

    app = _install_app_with_unrestricted_access(
        alembic_session_factory, install_unrestricted_read_access
    )
    with TestClient(app) as client:
        response = client.post(
            "/api/v1/webhooks/gatus",
            json=_gatus_payload(endpoint="unknown-endpoint"),
        )

    assert response.status_code == 404


def test_ambiguous_mapping_returns_409(
    alembic_session_factory,
    install_unrestricted_read_access,
) -> None:
    with alembic_session_factory() as session:
        upsert_object(
            session,
            _service(
                "dup-a",
                gatus={"endpoint": "shared-endpoint"},
                monitoring={"enabled": True, "provider": "gatus"},
            ),
        )
        upsert_object(
            session,
            _service(
                "dup-b",
                gatus={"endpoint": "shared-endpoint"},
                monitoring={"enabled": True, "provider": "gatus"},
            ),
        )
        session.commit()

    app = _install_app_with_unrestricted_access(
        alembic_session_factory, install_unrestricted_read_access
    )
    with TestClient(app) as client:
        response = client.post(
            "/api/v1/webhooks/gatus",
            json=_gatus_payload(endpoint="shared-endpoint"),
        )

    assert response.status_code == 409


def test_service_without_gatus_mapping_returns_404(
    alembic_session_factory,
    install_unrestricted_read_access,
) -> None:
    with alembic_session_factory() as session:
        upsert_object(
            session,
            _service(
                "no-mapping",
                monitoring={"enabled": True, "provider": "gatus"},
            ),
        )
        session.commit()

    app = _install_app_with_unrestricted_access(
        alembic_session_factory, install_unrestricted_read_access
    )
    with TestClient(app) as client:
        response = client.post(
            "/api/v1/webhooks/gatus",
            json=_gatus_payload(endpoint="no-mapping"),
        )

    assert response.status_code == 404


# ---------------------------------------------------------------------------
# Maintenance precedence: webhook does not overwrite catalog health
# ---------------------------------------------------------------------------


def test_maintenance_precedence_webhook_does_not_touch_catalog_health(
    alembic_session_factory,
    install_unrestricted_read_access,
) -> None:
    with alembic_session_factory() as session:
        upsert_object(
            session,
            _service(
                "maint-service",
                gatus={"endpoint": "maint-service"},
                monitoring={"enabled": True, "provider": "gatus"},
                health="maintenance",
            ),
        )
        session.commit()

    app = _install_app_with_unrestricted_access(
        alembic_session_factory, install_unrestricted_read_access
    )
    with TestClient(app) as client:
        response = client.post(
            "/api/v1/webhooks/gatus",
            json=_gatus_payload(endpoint="maint-service", alert="TRIGGERED"),
        )

    assert response.status_code == 200

    # The catalog health must still be "maintenance".
    with alembic_session_factory() as session:
        row = session.get(CatalogObject, "maint-service")
        assert row is not None
        assert row.health == "maintenance"

        # But an observation was recorded.
        obs = session.scalar(
            select(ServiceObservation).where(
                ServiceObservation.object_id == "maint-service",
                ServiceObservation.provider == "gatus",
            )
        )
        assert obs is not None
        assert obs.state == "down"


# ---------------------------------------------------------------------------
# Auth failures
# ---------------------------------------------------------------------------


def test_gatus_webhook_requires_authentication(
    alembic_session_factory,
) -> None:
    with alembic_session_factory() as session:
        upsert_object(
            session,
            _service(
                "auth-service",
                gatus={"endpoint": "auth-service"},
                monitoring={"enabled": True, "provider": "gatus"},
            ),
        )
        session.commit()

    app = create_app(settings=Settings())

    def override_get_session():
        with alembic_session_factory() as session:
            yield session

    app.dependency_overrides[get_session] = override_get_session
    # No install_unrestricted_read_access: auth is not overridden.

    with TestClient(app) as client:
        response = client.post(
            "/api/v1/webhooks/gatus",
            json=_gatus_payload(endpoint="auth-service"),
        )

    assert response.status_code == 401


def test_gatus_webhook_policy_denial_returns_403(
    alembic_session_factory,
) -> None:
    with alembic_session_factory() as session:
        upsert_object(
            session,
            _service(
                "denied-service",
                gatus={"endpoint": "denied-service"},
                monitoring={"enabled": True, "provider": "gatus"},
            ),
        )
        upsert_object(
            session,
            _service(
                "allowed-service",
                gatus={"endpoint": "allowed-service"},
                monitoring={"enabled": True, "provider": "gatus"},
            ),
        )
        session.commit()

    # Token only authorized for "allowed-service", not "denied-service".
    app = _install_app_with_restricted_access(
        alembic_session_factory,
        allowed_object_ids={"allowed-service"},
    )
    with TestClient(app) as client:
        denied = client.post(
            "/api/v1/webhooks/gatus",
            json=_gatus_payload(endpoint="denied-service"),
        )
        allowed = client.post(
            "/api/v1/webhooks/gatus",
            json=_gatus_payload(endpoint="allowed-service", alert="RESOLVED"),
        )

    assert denied.status_code == 403
    assert allowed.status_code == 200


# ---------------------------------------------------------------------------
# No alert descriptions or error text persisted
# ---------------------------------------------------------------------------


def test_no_alert_description_or_error_text_persisted(
    alembic_session_factory,
    install_unrestricted_read_access,
) -> None:
    with alembic_session_factory() as session:
        upsert_object(
            session,
            _service(
                "clean-service",
                gatus={"endpoint": "clean-service"},
                monitoring={"enabled": True, "provider": "gatus"},
            ),
        )
        session.commit()

    app = _install_app_with_unrestricted_access(
        alembic_session_factory, install_unrestricted_read_access
    )
    with TestClient(app) as client:
        response = client.post(
            "/api/v1/webhooks/gatus",
            json=_gatus_payload(
                endpoint="clean-service",
                alert="TRIGGERED",
                http_status=500,
            ),
        )

    assert response.status_code == 200

    with alembic_session_factory() as session:
        obs = session.scalar(
            select(ServiceObservation).where(
                ServiceObservation.object_id == "clean-service",
                ServiceObservation.provider == "gatus",
            )
        )
        assert obs is not None
        # Only canonical fields are stored.
        assert obs.state == "down"
        assert obs.http_status == 500
        assert obs.latency_ms == 120
        # No error text column exists on ServiceObservation, but verify
        # error_code is None (Gatus receiver doesn't set it for HTTP 5xx;
        # the down state is sufficient).
        assert obs.error_code is None


# ---------------------------------------------------------------------------
# checked_at from payload, not server now()
# ---------------------------------------------------------------------------


def test_checked_at_from_payload_not_server_now(
    alembic_session_factory,
    install_unrestricted_read_access,
) -> None:
    with alembic_session_factory() as session:
        upsert_object(
            session,
            _service(
                "ts-service",
                gatus={"endpoint": "ts-service"},
                monitoring={"enabled": True, "provider": "gatus"},
            ),
        )
        session.commit()

    app = _install_app_with_unrestricted_access(
        alembic_session_factory, install_unrestricted_read_access
    )
    payload_ts = "2026-08-19T10:30:45Z"
    with TestClient(app) as client:
        response = client.post(
            "/api/v1/webhooks/gatus",
            json=_gatus_payload(
                endpoint="ts-service",
                timestamp=payload_ts,
                alert="TRIGGERED",
            ),
        )

    assert response.status_code == 200

    with alembic_session_factory() as session:
        obs = session.scalar(
            select(ServiceObservation).where(
                ServiceObservation.object_id == "ts-service",
                ServiceObservation.provider == "gatus",
            )
        )
        assert obs is not None
        # The stored last_checked_at must match the payload timestamp,
        # not the current server time.
        expected = datetime(2026, 8, 19, 10, 30, 45)
        assert obs.last_checked_at == expected


# ---------------------------------------------------------------------------
# Invalid timestamp
# ---------------------------------------------------------------------------


def test_invalid_timestamp_returns_422(
    alembic_session_factory,
    install_unrestricted_read_access,
) -> None:
    with alembic_session_factory() as session:
        upsert_object(
            session,
            _service(
                "bad-ts-service",
                gatus={"endpoint": "bad-ts-service"},
                monitoring={"enabled": True, "provider": "gatus"},
            ),
        )
        session.commit()

    app = _install_app_with_unrestricted_access(
        alembic_session_factory, install_unrestricted_read_access
    )
    with TestClient(app) as client:
        response = client.post(
            "/api/v1/webhooks/gatus",
            json=_gatus_payload(
                endpoint="bad-ts-service",
                timestamp="not-a-timestamp",
            ),
        )

    assert response.status_code == 422


# ---------------------------------------------------------------------------
# Source and group matching
# ---------------------------------------------------------------------------


def test_source_and_group_must_match_when_declared(
    alembic_session_factory,
    install_unrestricted_read_access,
) -> None:
    with alembic_session_factory() as session:
        upsert_object(
            session,
            _service(
                "sg-service",
                gatus={
                    "endpoint": "sg-service",
                    "group": "core",
                    "source": "prod",
                },
                monitoring={"enabled": True, "provider": "gatus"},
            ),
        )
        session.commit()

    app = _install_app_with_unrestricted_access(
        alembic_session_factory, install_unrestricted_read_access
    )
    with TestClient(app) as client:
        # Matching source + group
        ok = client.post(
            "/api/v1/webhooks/gatus",
            json=_gatus_payload(
                endpoint="sg-service",
                group="core",
                source="prod",
            ),
        )
        # Wrong group
        wrong_group = client.post(
            "/api/v1/webhooks/gatus",
            json=_gatus_payload(
                endpoint="sg-service",
                group="edge",
                source="prod",
            ),
        )
        # Wrong source
        wrong_source = client.post(
            "/api/v1/webhooks/gatus",
            json=_gatus_payload(
                endpoint="sg-service",
                group="core",
                source="staging",
            ),
        )

    assert ok.status_code == 200
    assert wrong_group.status_code == 404
    assert wrong_source.status_code == 404


# ---------------------------------------------------------------------------
# Webhook writes observation, not catalog health
# ---------------------------------------------------------------------------


def test_webhook_writes_observation_not_catalog_health(
    alembic_session_factory,
    install_unrestricted_read_access,
) -> None:
    with alembic_session_factory() as session:
        upsert_object(
            session,
            _service(
                "obs-only",
                gatus={"endpoint": "obs-only"},
                monitoring={"enabled": True, "provider": "gatus"},
                health="healthy",
            ),
        )
        session.commit()

    app = _install_app_with_unrestricted_access(
        alembic_session_factory, install_unrestricted_read_access
    )
    with TestClient(app) as client:
        response = client.post(
            "/api/v1/webhooks/gatus",
            json=_gatus_payload(endpoint="obs-only", alert="TRIGGERED"),
        )

    assert response.status_code == 200

    with alembic_session_factory() as session:
        row = session.get(CatalogObject, "obs-only")
        assert row is not None
        # Catalog health unchanged — the webhook writes observations only.
        assert row.health == "healthy"

        # But observation state is down.
        obs = session.scalar(
            select(ServiceObservation).where(
                ServiceObservation.object_id == "obs-only",
                ServiceObservation.provider == "gatus",
            )
        )
        assert obs is not None
        assert obs.state == "down"
