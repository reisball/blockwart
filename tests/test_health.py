from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from blockwart.api.deps import get_session
from blockwart.db.base import Base
from blockwart.main import create_app


def test_health_endpoint() -> None:
    client = TestClient(create_app())

    response = client.get("/api/health")

    assert response.status_code == 200
    assert response.json()["ok"] is True
    assert response.json()["service"] == "blockwart"


def test_index_page(tmp_path) -> None:
    engine = create_engine(
        f"sqlite:///{tmp_path / 'health.db'}",
        connect_args={"check_same_thread": False},
    )
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    app = create_app()

    def override_get_session():
        with factory() as session:
            yield session

    app.dependency_overrides[get_session] = override_get_session
    client = TestClient(app)

    response = client.get("/")

    assert response.status_code == 200
    assert "Blockwart" in response.text
