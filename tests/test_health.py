import json
import os
import pwd
import re
import sqlite3
import subprocess
import sys
import tempfile
from pathlib import Path

from alembic import command
from fastapi.testclient import TestClient

from blockwart.api.deps import get_session
from blockwart.config import Settings
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
    database_path = tmp_path / "ready.sqlite3"
    database_url = _database_url(database_path)
    upgrade_database(database_url)
    with sqlite3.connect(database_path) as connection:
        before = {
            "revision": connection.execute("SELECT version_num FROM alembic_version").fetchall(),
            "catalog": connection.execute("SELECT count(*) FROM catalog_objects").fetchone()[0],
            "relationships": connection.execute("SELECT count(*) FROM relationships").fetchone()[0],
            "audits": connection.execute("SELECT count(*) FROM audit_events").fetchone()[0],
        }
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
    with sqlite3.connect(database_path) as connection:
        after = {
            "revision": connection.execute("SELECT version_num FROM alembic_version").fetchall(),
            "catalog": connection.execute("SELECT count(*) FROM catalog_objects").fetchone()[0],
            "relationships": connection.execute("SELECT count(*) FROM relationships").fetchone()[0],
            "audits": connection.execute("SELECT count(*) FROM audit_events").fetchone()[0],
        }
        integrity = connection.execute("PRAGMA integrity_check").fetchone()[0]

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
        "revision": "20260731_0010",
        "error_code": None,
    }
    assert after == before
    assert integrity == "ok"


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


def test_readiness_rejects_files_that_allow_lock_but_not_write() -> None:
    with tempfile.TemporaryDirectory(prefix="blockwart-read-only-") as directory:
        database_directory = Path(directory)
        database_directory.chmod(0o755)
        database_path = database_directory / "read-only.sqlite3"
        database_url = _database_url(database_path)
        upgrade_database(database_url)
        keeper = sqlite3.connect(database_path)
        keeper.execute("SELECT version_num FROM alembic_version").fetchall()
        sqlite_files = (
            database_path,
            Path(f"{database_path}-wal"),
            Path(f"{database_path}-shm"),
        )
        assert all(path.exists() for path in sqlite_files)
        for path in sqlite_files:
            path.chmod(0o444)
        database_directory.chmod(0o555)

        try:
            status_code, payload = _readiness_response_for_read_only_database(database_url)
        finally:
            database_directory.chmod(0o755)
            for path in sqlite_files:
                if path.exists():
                    path.chmod(0o644)
            keeper.close()

        assert status_code == 503
        assert payload["error_code"] == "database_not_writable"
        assert payload["checks"]["writable"] == "error"
        assert str(database_directory) not in json.dumps(payload)


def _readiness_response_for_read_only_database(database_url: str) -> tuple[int, dict]:
    if os.geteuid() != 0:
        response = TestClient(
            create_app(
                settings=Settings(
                    database_url=database_url,
                    sqlite_busy_timeout_ms=100,
                )
            )
        ).get("/api/health/ready")
        return response.status_code, response.json()

    script = """
import json
import sys
from fastapi.testclient import TestClient
from blockwart.config import Settings
from blockwart.main import create_app

response = TestClient(
    create_app(
        settings=Settings(
            database_url=sys.argv[1],
            sqlite_busy_timeout_ms=100,
        )
    )
).get("/api/health/ready")
print(json.dumps({"status_code": response.status_code, "payload": response.json()}))
"""
    nobody = pwd.getpwnam("nobody")
    environment = os.environ.copy()
    environment.pop("PYTHONPATH", None)
    completed = subprocess.run(
        [sys.executable, "-c", script, database_url],
        capture_output=True,
        check=True,
        cwd="/",
        env=environment,
        group=nobody.pw_gid,
        text=True,
        user=nobody.pw_uid,
    )
    result = json.loads(completed.stdout)
    return int(result["status_code"]), result["payload"]


def test_container_healthcheck_deadlines_exceed_default_sqlite_lock_wait() -> None:
    dockerfile = (Path(__file__).resolve().parents[1] / "Dockerfile").read_text()
    docker_timeout_match = re.search(r"HEALTHCHECK .*--timeout=(\d+)s", dockerfile)
    http_timeout_match = re.search(r"urlopen\(.*timeout=(\d+)\)", dockerfile)
    assert docker_timeout_match is not None
    assert http_timeout_match is not None

    sqlite_wait_seconds = Settings.model_fields["sqlite_busy_timeout_ms"].default / 1000
    http_timeout_seconds = int(http_timeout_match.group(1))
    docker_timeout_seconds = int(docker_timeout_match.group(1))

    assert sqlite_wait_seconds < http_timeout_seconds < docker_timeout_seconds


def test_index_page(
    alembic_session_factory,
    install_unrestricted_read_access,
) -> None:
    app = create_app()
    install_unrestricted_read_access(app)

    def override_get_session():
        with alembic_session_factory() as session:
            yield session

    app.dependency_overrides[get_session] = override_get_session
    client = TestClient(app)

    response = client.get("/")

    assert response.status_code == 200
    assert "Blockwart" in response.text
