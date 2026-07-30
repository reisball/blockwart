from collections.abc import Generator

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from blockwart.api.deps import get_session
from blockwart.config import Settings
from blockwart.db.session import transaction
from blockwart.main import create_app
from blockwart.models import SecurityEvent
from blockwart.services.identity import create_service_account, issue_service_token


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
    }
    assert response.headers["x-correlation-id"]


@pytest.mark.parametrize(
    "authorization",
    [None, "Basic not-supported", "Bearer invalid-token"],
)
def test_missing_or_invalid_bearer_is_401_and_audited(
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
        event = session.scalar(
            select(SecurityEvent)
            .where(SecurityEvent.event_type == "service_token_authentication")
            .order_by(SecurityEvent.id.desc())
        )
        assert event is not None
        assert event.outcome == "failure"
        assert "invalid-token" not in event.details_json


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
