"""Discoverable interface vocabulary and safe write-boundary errors (#321)."""

import asyncio
import json

import pytest
from pydantic import ValidationError
from test_catalog_root_creation import root_state  # noqa: F401
from test_field_validation_errors import owner_headers, write_client  # noqa: F401

from blockwart.domain.interfaces import (
    CANONICAL_ACCESS_TYPES,
    CANONICAL_ENDPOINT_TYPES,
    InterfaceContractError,
    normalize_interface_data,
)
from blockwart.domain.validation_errors import detail_from_validation_error
from blockwart.mcp import server as mcp_server
from blockwart.mcp.server import describe_schema_payload, handle_call_tool
from blockwart.schemas.catalog import CatalogObjectIn


def service_data(endpoint_type="REST API", access_type="admin_api"):
    return {
        "endpoints": [{"type": endpoint_type, "url": "https://example.invalid/api/"}],
        "access_methods": [{"type": access_type}],
    }


@pytest.mark.parametrize(
    "path,values,alias,target,rule",
    [
        (
            "endpoints[].type",
            CANONICAL_ENDPOINT_TYPES,
            "rest_api",
            "REST API",
            "interface_endpoint_type",
        ),
        (
            "access_methods[].type",
            CANONICAL_ACCESS_TYPES,
            "api",
            "admin_api",
            "interface_access_type",
        ),
    ],
)
@pytest.mark.parametrize("kind", ["service", "device"])
def test_schema_exposes_runtime_type_contract(kind, path, values, alias, target, rule):
    schema = next(k for k in describe_schema_payload()["kinds"] if k["kind"] == kind)
    field = next(f for f in schema["data"]["fields"] if f["path"] == path)
    contract = field["type_contract"]
    assert contract["canonical_values"] == list(values)
    assert contract["aliases"][alias] == target
    assert contract["rule"] == rule
    assert "value_not_allowed" in field["violations"]
    assert "enum" not in field  # Aliases and extensions are still accepted.
    if path.startswith("endpoints"):
        assert contract["custom_pattern"] == r"^x-[a-z0-9][a-z0-9-]*$"
        assert contract["aliases"]["mcp"] == "MCP"
        assert "MCP" in contract["canonical_values"]
        assert "sdb" not in contract["canonical_values"]
    else:
        assert "mcp" not in contract["canonical_values"]
        assert "mcp" not in contract["aliases"]


@pytest.mark.parametrize(
    "endpoint,access,path,rule",
    [
        ("REST API", "bearer_http", "data.access_methods[0].type", "interface_access_type"),
        ("REST API", "mcp", "data.access_methods[0].type", "interface_access_type"),
        ("sdb", "admin_api", "data.endpoints[0].type", "interface_endpoint_type"),
        ("REST API", "REST API", "data.access_methods[0].type", "interface_access_type"),
        ("REST API", " ", "data.access_methods[0].type", "interface_access_type"),
        (" ", "admin_api", "data.endpoints[0].type", "interface_endpoint_type"),
        (
            "REST API via Caddy HTTPS",
            "admin_api",
            "data.endpoints[0].type",
            "interface_endpoint_type",
        ),
    ],
)
def test_domain_and_pydantic_keep_safe_structured_type_errors(endpoint, access, path, rule):
    data = service_data(endpoint, access)
    with pytest.raises(InterfaceContractError) as raised:
        normalize_interface_data(data, kind="service", object_id="private-object-name")
    assert raised.value.path == path
    with pytest.raises(ValidationError) as raised_model:
        CatalogObjectIn(id="private-object-name", kind="service", label="test", data=data)
    detail = detail_from_validation_error({**raised_model.value.errors()[0], "loc": ("body",)})
    assert detail["path"] == path
    assert detail["location"] == "body." + path
    assert detail["code"] == "value_not_allowed"
    assert detail["rule"] == rule
    assert "private-object-name" not in json.dumps(detail)
    if endpoint.strip():
        assert endpoint not in json.dumps(detail)
    if access.strip():
        assert access not in json.dumps(detail)


@pytest.mark.parametrize(
    "endpoint,access", [(" REST_API ", " API "), ("x-local-bridge", "admin_api"), (None, None)]
)
def test_existing_alias_extensions_and_defaults_remain_supported(endpoint, access):
    assert normalize_interface_data(service_data(endpoint, access), kind="service").data[
        "endpoints"
    ]


@pytest.mark.parametrize("tool", ["blockwart.preview_object_update", "blockwart.update_object"])
@pytest.mark.parametrize(
    "endpoint,access,path",
    [
        ("REST API", "bearer_http", "data.access_methods[0].type"),
        ("REST API", "mcp", "data.access_methods[0].type"),
        ("sdb", "admin_api", "data.endpoints[0].type"),
        ("REST API via Caddy HTTPS", "admin_api", "data.endpoints[0].type"),
    ],
)
def test_mcp_preview_and_update_keep_type_error_details(
    tool,
    endpoint,
    access,
    path,
    write_client,  # noqa: F811
    owner_headers,  # noqa: F811
    monkeypatch,  # noqa: F811
):  # noqa: F811
    def request(method, url, body, headers, **kwargs):
        from io import BytesIO
        from urllib.error import HTTPError

        response = write_client.request(
            method, url, json=body, headers={**owner_headers, **headers}
        )
        assert response.status_code == 422, response.text
        raise mcp_server._translate_http_error(
            HTTPError(
                url, response.status_code, "Rejected", response.headers, BytesIO(response.content)
            )
        )

    monkeypatch.setattr(mcp_server, "request_json", request)
    args = {
        "object_id": "synthetic-service",
        "if_match": '"rev-1"',
        "object": {
            "id": "synthetic-service",
            "kind": "service",
            "label": "Test",
            "data": service_data(endpoint, access),
        },
    }
    result = asyncio.run(handle_call_tool(tool, args))
    error = json.loads(result.content[0].text)["error"]
    assert result.isError
    assert error["details"][0]["path"] == path
    assert error["details"][0]["code"] == "value_not_allowed"


def test_api_rejections_leave_revision_unchanged(write_client, owner_headers):  # noqa: F811
    body = {"id": "synthetic-service", "kind": "service", "label": "Test", "data": service_data()}
    created = write_client.post(
        "/api/v1/roots",
        headers={**owner_headers, "Idempotency-Key": "interface321-create"},
        json=body,
    )
    assert created.status_code == 201, created.text
    before = write_client.get("/api/v1/objects/synthetic-service", headers=owner_headers)
    valid = write_client.post(
        "/api/v1/objects/synthetic-service/update-preview",
        headers={**owner_headers, "If-Match": before.headers["etag"]},
        json=body,
    )
    assert valid.status_code == 200, valid.text
    for suffix in ("/update-preview", ""):
        rejected = write_client.request(
            "POST" if suffix else "PUT",
            "/api/v1/objects/synthetic-service" + suffix,
            headers={**owner_headers, "If-Match": before.headers["etag"]},
            json={**body, "data": service_data(access_type="bearer_http")},
        )
        assert rejected.status_code == 422, rejected.text
        assert rejected.json()["error"]["details"][0]["path"] == "data.access_methods[0].type"
        after = write_client.get("/api/v1/objects/synthetic-service", headers=owner_headers)
        assert after.headers["etag"] == before.headers["etag"]
        assert after.json() == before.json()


@pytest.mark.parametrize("field", ["endpoints", "access_methods"])
def test_public_type_defaults_require_omission_not_explicit_null(field):
    omitted = service_data()
    omitted[field][0].pop("type")
    CatalogObjectIn(id="omitted-type", kind="service", label="Test", data=omitted)
    explicit_null = service_data()
    explicit_null[field][0]["type"] = None
    with pytest.raises(ValidationError) as raised:
        CatalogObjectIn(id="null-type", kind="service", label="Test", data=explicit_null)
    detail = detail_from_validation_error(raised.value.errors()[0])
    assert detail["code"] == "type_mismatch"
    assert detail["path"] == f"data.{field}[0].type"


@pytest.mark.parametrize(
    "endpoint,expected", [("MCP", "MCP"), ("mcp", "MCP"), ("x-sdb", "x-sdb"), ("TCP", "TCP")]
)
def test_additional_endpoint_cases_preserve_supported_vocabulary(endpoint, expected):
    payload = CatalogObjectIn(
        id="supported-interface",
        kind="service",
        label="Test",
        data=service_data(endpoint, "admin_api"),
    )
    normalized = normalize_interface_data(payload.data, kind=payload.kind).data
    assert normalized["endpoints"][0]["type"] == expected
    assert normalized["access_methods"][0]["type"] == "admin_api"


@pytest.mark.parametrize(
    "tool,kind,endpoint,access,path,rule",
    [
        (
            "blockwart.create_root",
            "service",
            "MCP",
            "mcp",
            "data.access_methods[0].type",
            "interface_access_type",
        ),
        (
            "blockwart.preview_object_update",
            "device",
            "sdb",
            "admin_api",
            "data.endpoints[0].type",
            "interface_endpoint_type",
        ),
        (
            "blockwart.update_object",
            "device",
            "sdb",
            "admin_api",
            "data.endpoints[0].type",
            "interface_endpoint_type",
        ),
    ],
)
def test_additional_mcp_rejections_leave_catalog_unchanged(
    tool,
    kind,
    endpoint,
    access,
    path,
    rule,
    write_client,  # noqa: F811
    owner_headers,  # noqa: F811
    monkeypatch,  # noqa: F811
):
    object_id = "additional-interface-case"
    valid_data = service_data()
    if kind == "device":
        valid_data["device"] = {"category": "other"}
    body = {"id": object_id, "kind": kind, "label": "Test", "data": valid_data}
    before = None
    if tool != "blockwart.create_root":
        created = write_client.post(
            "/api/v1/roots",
            headers={**owner_headers, "Idempotency-Key": "additional321-device"},
            json=body,
        )
        assert created.status_code == 201, created.text
        before = write_client.get(f"/api/v1/objects/{object_id}", headers=owner_headers)
        assert before.status_code == 200, before.text
    else:
        assert (
            write_client.get(f"/api/v1/objects/{object_id}", headers=owner_headers).status_code
            == 404
        )

    def request(method, url, body, headers, **kwargs):
        from io import BytesIO
        from urllib.error import HTTPError

        response = write_client.request(
            method, url, json=body, headers={**owner_headers, **headers}
        )
        assert response.status_code == 422, response.text
        raise mcp_server._translate_http_error(
            HTTPError(
                url, response.status_code, "Rejected", response.headers, BytesIO(response.content)
            )
        )

    monkeypatch.setattr(mcp_server, "request_json", request)
    invalid_data = {**valid_data, **service_data(endpoint, access)}
    args = {"object": {**body, "data": invalid_data}}
    if before is None:
        args["idempotency_key"] = "additional321-invalid-create"
    else:
        args.update(object_id=object_id, if_match=before.headers["etag"])
    result = asyncio.run(handle_call_tool(tool, args))
    assert result.isError
    error = json.loads(result.content[0].text)["error"]
    detail = error["details"][0]
    assert detail["path"] == path
    assert detail["code"] == "value_not_allowed"
    assert detail["rule"] == rule
    assert object_id not in json.dumps(detail)
    assert (access if kind == "service" else endpoint) not in json.dumps(detail)
    after = write_client.get(f"/api/v1/objects/{object_id}", headers=owner_headers)
    if before is None:
        assert after.status_code == 404
    else:
        assert after.headers["etag"] == before.headers["etag"]
        assert after.json() == before.json()
