from collections.abc import Generator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from blockwart.api.deps import get_session
from blockwart.db.base import Base
from blockwart.main import create_app
from blockwart.models import CatalogObject
from blockwart.services.seeds import import_seed_file

SEED_PATH = Path(__file__).resolve().parents[1] / "seeds" / "pilot_objects.yaml"


@pytest.fixture
def session_factory(tmp_path):
    engine = create_engine(
        f"sqlite:///{tmp_path / 'agent.db'}",
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
