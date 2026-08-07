import json
from pathlib import Path

from blockwart.config import Settings
from blockwart.main import create_app

CONTRACT_PATH = Path(__file__).resolve().parent / "contracts" / "openapi.json"
HTTP_METHODS = {"get", "post", "put", "patch", "delete"}
EXPECTED_OPERATIONS = {
    "/api/agent/context": {"get"},
    "/api/agent/objects/{object_id}": {"get"},
    "/api/agent/objects/{object_id}/network-topology": {"get"},
    "/api/agent/search": {"get"},
    "/api/health": {"get"},
    "/api/health/live": {"get"},
    "/api/health/ready": {"get"},
    "/api/objects": {"get"},
    "/api/objects/{object_id}": {"get"},
    "/api/v1/auth/me": {"get"},
    "/api/v1/admin/principals": {"get", "post"},
    "/api/v1/admin/principals/{principal_id}": {"get", "put"},
    "/api/v1/admin/principals/{principal_id}/grants": {"post"},
    "/api/v1/admin/principals/{principal_id}/grants/{grant_id}": {"put", "delete"},
    "/api/v1/admin/principals/{principal_id}/catalog-role": {"post"},
    "/api/v1/admin/principals/{principal_id}/password": {"post"},
    "/api/v1/admin/principals/{principal_id}/tokens": {"post"},
    "/api/v1/admin/principals/{principal_id}/tokens/rotate": {"post"},
    "/api/v1/admin/principals/{principal_id}/tokens/{token_name}": {"delete"},
    "/api/v1/context": {"get"},
    "/api/v1/objects": {"get"},
    "/api/v1/objects/{parent_id}/children": {"post"},
    "/api/v1/objects/{object_id}": {"get", "put", "delete"},
    "/api/v1/objects/{object_id}/comments": {"get", "post"},
    "/api/v1/objects/{object_id}/access": {"get"},
    "/api/v1/objects/{object_id}/access/grants": {"post"},
    "/api/v1/objects/{object_id}/access/grants/{grant_id}": {"put", "delete"},
    "/api/v1/objects/{object_id}/access/preview": {"get"},
    "/api/v1/objects/{object_id}/access/principals": {"get"},
    "/api/v1/objects/{object_id}/audit-events": {"get"},
    "/api/v1/objects/{object_id}/device-graph": {"get"},
    "/api/v1/objects/{object_id}/network-topology": {"get"},
    "/api/v1/objects/{object_id}/relationships": {"get", "post", "delete"},
    "/api/v1/objects/{object_id}/topology": {"get"},
    "/api/v1/objects/{parent_id}/attached-devices": {"post"},
    "/api/v1/roots": {"post"},
}


def test_openapi_matches_reviewed_contract() -> None:
    expected = json.loads(CONTRACT_PATH.read_text())
    actual = create_app(settings=Settings()).openapi()

    assert actual == expected


def test_openapi_exposes_only_reviewed_machine_operations() -> None:
    contract = json.loads(CONTRACT_PATH.read_text())
    operations = {
        path: set(path_item) & HTTP_METHODS for path, path_item in contract["paths"].items()
    }

    assert operations == EXPECTED_OPERATIONS
    assert not any(path.startswith(("/admin", "/objects", "/settings")) for path in operations)
