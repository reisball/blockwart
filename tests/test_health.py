from pathlib import Path

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from alembic import command
from blockwart.api.deps import get_session
from blockwart.config import Settings
from blockwart.db.base import Base
from blockwart.db.migrations import BASELINE_REVISION, build_alembic_config, upgrade_database
from blockwart.db.session import build_engine
from blockwart.main import create_app


def _database_url(path: Path) -> str:
    return f"sqlite:///{path}"


def test_liveness_endpoints_do_not_depend_on_database(tmp_path: Path) -> None:
    missing_database = tmp_path / "missing" / "blockwart.sqlite3"
    client = TestClient(
        create_app(
            settings=Settings(
                database_url=_database_url(missing_database),
                build_revision="test-commit",
            )
        )
    )

    for endpoint in ("/api/health", "/api/health/live"):
        response = client.get(endpoint)

        assert response.status_code == 200
        assert response.json() == {
            "ok": True,
            "status": "alive",
            "service": "blockwart",
            "version": "0.1.0",
            "build_revision": "test-commit",
        }
    assert not missing_database.exists()


def test_readiness_checks_database_revision_and_sqlite_runtime(tmp_path: Path) -> None:
    database_url = _database_url(tmp_path / "ready.sqlite3")
    upgrade_database(database_url)
    client = TestClient(
        create_app(
            settings=Settings(
                database_url=database_url,
                build_revision="test-commit",
                sqlite_busy_timeout_ms=750,
            )
        )
    )

    response = client.get("/api/health/ready")

    assert response.status_code == 200
    assert response.json() == {
        "ok": True,
        "status": "ready",
        "service": "blockwart",
        "version": "0.1.0",
        "build_revision": "test-commit",
        "checks": {
            "database": "ok",
            "schema": "ok",
            "writable": "ok",
            "sqlite": "ok",
        },
        "revision": "20260723_0002",
        "error_code": None,
    }


def test_readiness_rejects_missing_database_without_creating_it(tmp_path: Path) -> None:
    missing_database = tmp_path / "missing.sqlite3"
    client = TestClient(
        create_app(settings=Settings(database_url=_database_url(missing_database)))
    )

    response = client.get("/api/health/ready")

    assert response.status_code == 503
    assert response.json()["error_code"] == "database_missing"
    assert response.json()["checks"]["database"] == "error"
    assert str(tmp_path) not in response.text
    assert not missing_database.exists()


def test_readiness_rejects_wrong_alembic_revision(tmp_path: Path) -> None:
    database_url = _database_url(tmp_path / "old.sqlite3")
    command.upgrade(build_alembic_config(database_url), BASELINE_REVISION)
    client = TestClient(create_app(settings=Settings(database_url=database_url)))

    response = client.get("/api/health/ready")

    assert response.status_code == 503
    assert response.json()["error_code"] == "schema_revision_mismatch"
    assert response.json()["revision"] == BASELINE_REVISION
    assert response.json()["checks"]["database"] == "ok"
    assert response.json()["checks"]["schema"] == "error"
    assert str(tmp_path) not in response.text


def test_readiness_rejects_locked_database_with_safe_error(tmp_path: Path) -> None:
    database_url = _database_url(tmp_path / "locked.sqlite3")
    upgrade_database(database_url)
    engine = build_engine(
        database_url,
        sqlite_busy_timeout_ms=100,
        sqlite_wal_enabled=True,
    )
    blocker = engine.connect()
    blocker.exec_driver_sql("BEGIN IMMEDIATE")
    try:
        client = TestClient(
            create_app(
                settings=Settings(
                    database_url=database_url,
                    sqlite_busy_timeout_ms=100,
                )
            )
        )

        response = client.get("/api/health/ready")
    finally:
        blocker.exec_driver_sql("ROLLBACK")
        blocker.close()
        engine.dispose()

    assert response.status_code == 503
    assert response.json()["error_code"] == "database_not_writable"
    assert response.json()["checks"]["writable"] == "error"
    assert str(tmp_path) not in response.text


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
