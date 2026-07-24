import json
from pathlib import Path

from blockwart.config import Settings
from blockwart.main import create_app

CONTRACT_PATH = Path(__file__).resolve().parent / "contracts" / "openapi.json"
HTTP_METHODS = {"get", "post", "put", "patch", "delete"}
EXPECTED_OPERATIONS = {
    "/api/agent/context": {"get"},
    "/api/agent/objects/{object_id}": {"get"},
    "/api/agent/search": {"get"},
    "/api/health": {"get"},
    "/api/health/live": {"get"},
    "/api/health/ready": {"get"},
    "/api/objects": {"get"},
    "/api/objects/{object_id}": {"get"},
}


def test_openapi_matches_reviewed_contract() -> None:
    expected = json.loads(CONTRACT_PATH.read_text())
    actual = create_app(settings=Settings()).openapi()

    assert actual == expected


def test_openapi_exposes_only_reviewed_machine_operations() -> None:
    contract = json.loads(CONTRACT_PATH.read_text())
    operations = {
        path: set(path_item) & HTTP_METHODS
        for path, path_item in contract["paths"].items()
    }

    assert operations == EXPECTED_OPERATIONS
    assert all(methods == {"get"} for methods in operations.values())
    assert not any(
        path.startswith(("/admin", "/objects", "/settings")) for path in operations
    )
