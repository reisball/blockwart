from collections.abc import Generator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from blockwart.api.deps import get_session
from blockwart.db.base import Base
from blockwart.main import create_app
from blockwart.services.seeds import import_seed_file

SEED_PATH = Path(__file__).resolve().parents[1] / "seeds" / "pilot_objects.yaml"


@pytest.fixture
def session_factory(tmp_path):
    engine = create_engine(
        f"sqlite:///{tmp_path / 'ui.db'}",
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


def test_index_lists_seeded_objects_and_filters_search(client: TestClient) -> None:
    response = client.get("/?q=brieftraeger&kind=system")

    assert response.status_code == 200
    assert "Brieftraeger" in response.text
    assert "brieftraeger-ocr-worker" not in response.text


def test_object_detail_shows_data_and_relationships(client: TestClient) -> None:
    response = client.get("/objects/n8n")

    assert response.status_code == 200
    assert "n8n Web UI" in response.text
    assert "Relationships" in response.text
    assert "system:n8n" in response.text


def test_create_object_form_redirects_to_detail(client: TestClient) -> None:
    response = client.post(
        "/objects",
        data={
            "object_id": "test-system",
            "kind": "system",
            "label": "Test System",
            "status": "active",
            "summary": "Created from UI test.",
            "data_json": '{"schema_version": 1}',
        },
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert response.headers["location"] == "/objects/test-system"
    detail = client.get("/objects/test-system")
    assert "Test System" in detail.text


def test_create_object_form_rejects_secret_values(client: TestClient) -> None:
    response = client.post(
        "/objects",
        data={
            "object_id": "bad-system",
            "kind": "system",
            "label": "Bad System",
            "status": "active",
            "summary": "",
            "data_json": '{"schema_version": 1, "password": "not-allowed"}',
        },
    )

    assert response.status_code == 422
    assert "forbidden secret-shaped key" in response.text
    assert "not-allowed" not in response.text


def test_update_object_form_updates_detail(client: TestClient) -> None:
    response = client.post(
        "/objects/n8n",
        data={
            "label": "n8n Workflows",
            "status": "active",
            "summary": "Updated through UI.",
            "data_json": '{"schema_version": 1}',
        },
        follow_redirects=False,
    )

    assert response.status_code == 303
    detail = client.get("/objects/n8n")
    assert "n8n Workflows" in detail.text
    assert "Updated through UI." in detail.text


def test_update_object_form_does_not_echo_rejected_secret_values(client: TestClient) -> None:
    response = client.post(
        "/objects/n8n",
        data={
            "label": "n8n",
            "status": "active",
            "summary": "",
            "data_json": '{"schema_version": 1, "password": "not-allowed"}',
        },
    )

    assert response.status_code == 422
    assert "forbidden secret-shaped key" in response.text
    assert "not-allowed" not in response.text
