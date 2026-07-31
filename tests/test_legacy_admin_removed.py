from pathlib import Path

from fastapi.testclient import TestClient

from blockwart.config import Settings
from blockwart.main import create_app


def test_legacy_admin_routes_cookie_and_environment_are_inert(monkeypatch) -> None:
    monkeypatch.setenv("BLOCKWART_ADMIN_TOKEN", "legacy-value-that-must-grant-nothing")
    app = create_app(settings=Settings())

    with TestClient(app, base_url="https://testserver") as client:
        client.cookies.set("blockwart_admin_session", "legacy-cookie")
        assert client.get("/admin").status_code == 404
        assert client.post("/admin/unlock", data={"admin_token": "legacy"}).status_code == 404
        assert client.post("/admin/lock").status_code == 404
        assert client.post("/settings/schema", data={"kind": "system"}).status_code == 405


def test_legacy_admin_surface_is_absent_from_openapi() -> None:
    paths = create_app(settings=Settings()).openapi()["paths"]
    assert not any(path.startswith("/admin") for path in paths)
    assert "/settings/schema" not in paths


def test_production_compose_binds_only_to_localhost() -> None:
    compose = (Path(__file__).resolve().parents[1] / "compose.yaml").read_text()
    assert '"127.0.0.1:8000:8000"' in compose
    assert '"8000:8000"' not in compose.replace('"127.0.0.1:8000:8000"', "")
