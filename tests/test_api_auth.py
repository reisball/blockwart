from collections.abc import Generator
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from blockwart.api.deps import get_session
from blockwart.config import Settings
from blockwart.db.session import transaction
from blockwart.main import create_app
from blockwart.models import SecurityEvent, ServiceToken, ServiceTokenFailureBucket
from blockwart.services.identity import create_service_account, issue_service_token, utc_now


@pytest.fixture
def api_auth_state(alembic_session_factory):
    with alembic_session_factory() as session:
        with transaction(session):
            principal = create_service_account(
                session,
                login="api.reader",
                display_name="API Reader",
            )
            token = issue_service_token(
                session,
                principal_id=principal.id,
                name="api",
            )
    return alembic_session_factory, principal, token


@pytest.fixture
def api_auth_client(api_auth_state) -> Generator[TestClient, None, None]:
    session_factory, _, _ = api_auth_state
    app = create_app(settings=Settings())

    def override_get_session() -> Generator[Session, None, None]:
        with session_factory() as session:
            yield session

    app.dependency_overrides[get_session] = override_get_session
    with TestClient(app) as client:
        yield client


def test_bearer_auth_returns_same_stable_principal(
    api_auth_client: TestClient,
    api_auth_state,
) -> None:
    _, principal, token = api_auth_state

    response = api_auth_client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {token.value}"},
    )

    assert response.status_code == 200
    assert response.json() == {
        "id": principal.id,
        "principal_type": "service_account",
        "login": "api.reader",
        "display_name": "API Reader",
        "platform_role": None,
        "revision": 1,
    }
    assert response.headers["x-correlation-id"]
    session_factory, _, _ = api_auth_state
    with session_factory() as session:
        assert session.scalar(
            select(func.count()).select_from(ServiceTokenFailureBucket)
        ) == 0


@pytest.mark.parametrize(
    "authorization",
    [None, "Basic not-supported", "Bearer invalid-token"],
)
def test_missing_or_invalid_bearer_is_uniform_and_bucketed(
    api_auth_client: TestClient,
    api_auth_state,
    authorization: str | None,
) -> None:
    session_factory, _, _ = api_auth_state
    headers = {"Authorization": authorization} if authorization else {}

    response = api_auth_client.get("/api/v1/auth/me", headers=headers)

    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"
    assert response.json()["error"]["code"] == "unauthorized"
    with session_factory() as session:
        assert session.scalar(
            select(SecurityEvent).where(
                SecurityEvent.event_type == "service_token_authentication"
            )
        ) is None
        buckets = list(session.scalars(select(ServiceTokenFailureBucket)).all())
        assert {bucket.dimension for bucket in buckets} == {"global", "source", "token"}
        serialized = " ".join(
            f"{bucket.key_hash} {bucket.dimension}" for bucket in buckets
        )
        assert "invalid-token" not in serialized
        assert "testclient" not in serialized


def test_openapi_publishes_http_bearer_without_write_surface(
    api_auth_client: TestClient,
) -> None:
    openapi = api_auth_client.get("/openapi.json").json()

    assert openapi["components"]["securitySchemes"]["HTTPBearer"] == {
        "scheme": "bearer",
        "type": "http",
    }
    assert openapi["paths"]["/api/v1/auth/me"]["get"]["security"] == [
        {"HTTPBearer": []}
    ]
    assert set(openapi["paths"]["/api/objects"]) == {"get"}


@pytest.mark.parametrize("state", ["revoked", "expired"])
def test_revoked_and_expired_tokens_use_uniform_bucketed_failure(
    api_auth_client: TestClient,
    api_auth_state,
    state: str,
) -> None:
    session_factory, _, token = api_auth_state
    with session_factory() as session:
        with transaction(session):
            row = session.get(ServiceToken, token.token_id)
            assert row is not None
            if state == "revoked":
                row.revoked_at = utc_now()
            else:
                row.expires_at = utc_now() - timedelta(seconds=1)

    response = api_auth_client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {token.value}"},
    )

    assert response.status_code == 401
    assert response.json()["error"]["code"] == "unauthorized"
    with session_factory() as session:
        assert {row.dimension for row in session.scalars(select(ServiceTokenFailureBucket))} == {
            "global",
            "source",
            "token",
        }


def test_api_fingerprint_threshold_stops_lookup_and_aggregates_one_event(
    api_auth_state,
) -> None:
    session_factory, _, _ = api_auth_state
    app = create_app(
        settings=Settings(
            auth_service_token_global_failure_limit=10,
            auth_service_token_source_failure_limit=10,
            auth_service_token_fingerprint_failure_limit=1,
        )
    )

    def override_get_session() -> Generator[Session, None, None]:
        with session_factory() as session:
            yield session

    app.dependency_overrides[get_session] = override_get_session
    with TestClient(app) as client:
        responses = [
            client.get(
                "/api/v1/auth/me",
                headers={"Authorization": "Bearer repeated-invalid-token"},
            )
            for _ in range(3)
        ]

    assert {response.status_code for response in responses} == {401}
    assert {response.json()["error"]["code"] for response in responses} == {
        "unauthorized"
    }
    with session_factory() as session:
        events = list(
            session.scalars(
                select(SecurityEvent).where(
                    SecurityEvent.event_type
                    == "service_token_authentication_throttled"
                )
            ).all()
        )
        assert len(events) == 1
        assert '"dimension":"token"' in events[0].details_json


def test_api_rejects_duplicate_forwarded_source_fields(api_auth_state) -> None:
    session_factory, _, _ = api_auth_state
    app = create_app(
        settings=Settings(auth_trusted_proxy_cidrs="192.0.2.10/32")
    )

    def override_get_session() -> Generator[Session, None, None]:
        with session_factory() as session:
            yield session

    app.dependency_overrides[get_session] = override_get_session
    with TestClient(app, client=("192.0.2.10", 50000)) as client:
        first = client.get(
            "/api/v1/auth/me",
            headers={
                "Authorization": "Bearer first-invalid-token",
                "X-Forwarded-For": "198.51.100.8",
            },
        )
        duplicate = client.get(
            "/api/v1/auth/me",
            headers=[
                ("Authorization", "Bearer second-invalid-token"),
                ("X-Forwarded-For", "198.51.100.8"),
                ("X-Forwarded-For", "203.0.113.9"),
            ],
        )

    assert first.status_code == 401
    assert duplicate.status_code == 401
    with session_factory() as session:
        source_buckets = list(
            session.scalars(
                select(ServiceTokenFailureBucket).where(
                    ServiceTokenFailureBucket.dimension == "source"
                )
            ).all()
        )
        assert len(source_buckets) == 2
        assert {bucket.failure_count for bucket in source_buckets} == {1}
