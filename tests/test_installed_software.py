from __future__ import annotations

import json
import socket
import urllib.request
from collections.abc import Generator
from io import BytesIO
from urllib.error import HTTPError

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session
from test_catalog_root_creation import root_state  # noqa: F401

from blockwart.api.deps import get_session
from blockwart.domain.object_schema import (
    INSTALLED_SOFTWARE_KINDS,
    ObjectSchemaError,
    validate_object_data,
)
from blockwart.domain.schema_projection import object_schema_projection
from blockwart.main import create_app
from blockwart.mcp.server import (
    _tool_error_result,
    _translate_http_error,
    call_tool,
    describe_schema_payload,
)
from blockwart.schemas.catalog import CatalogObjectIn, ObjectKind

OPAQUE_VERSIONS = (
    "2026.08",
    "1:27.5.1-1~ubuntu.24.04",
    "vendor build+rev_7 / exact",
)


@pytest.fixture
def write_client(root_state) -> Generator[TestClient, None, None]:  # noqa: F811
    app = create_app()

    def override_get_session() -> Generator[Session, None, None]:
        with root_state["session_factory"]() as session:
            yield session

    app.dependency_overrides[get_session] = override_get_session
    with TestClient(app) as client:
        yield client


def _owner_headers(root_state) -> dict[str, str]:  # noqa: F811
    return {"Authorization": f"Bearer {root_state['owner_token']}"}


def _software_data() -> dict[str, object]:
    return {
        "installed_software": [
            {"name": "First", "version": OPAQUE_VERSIONS[0]},
            {
                "name": "Docker Engine",
                "version": OPAQUE_VERSIONS[1],
                "url": "https://docs.docker.com/engine/release-notes/27/",
            },
            {"name": "First", "version": OPAQUE_VERSIONS[2]},
        ]
    }


@pytest.mark.parametrize("kind", sorted(INSTALLED_SOFTWARE_KINDS))
def test_host_and_system_keep_order_duplicates_and_opaque_versions(kind: str) -> None:
    payload = CatalogObjectIn(
        id=f"software-{kind}",
        kind=kind,
        label=kind,
        data=_software_data(),
    )

    assert payload.data == _software_data()
    assert [entry["version"] for entry in payload.data["installed_software"]] == list(
        OPAQUE_VERSIONS
    )
    assert [entry["name"] for entry in payload.data["installed_software"]] == [
        "First",
        "Docker Engine",
        "First",
    ]


@pytest.mark.parametrize(
    "kind",
    sorted(set(ObjectKind.__args__) - set(INSTALLED_SOFTWARE_KINDS)),
)
def test_installed_software_is_rejected_for_every_other_object_kind(kind: str) -> None:
    with pytest.raises(ObjectSchemaError) as exc_info:
        validate_object_data(kind, {"installed_software": []})

    assert exc_info.value.path == "data.installed_software"
    assert exc_info.value.violation == "field_not_allowed"
    assert exc_info.value.rule is None


@pytest.mark.parametrize(
    ("data", "path", "violation", "rule"),
    [
        ({"installed_software": {}}, "data.installed_software", "type_mismatch", None),
        (
            {"installed_software": ["Docker"]},
            "data.installed_software[0]",
            "type_mismatch",
            None,
        ),
        (
            {"installed_software": [{"version": "1"}]},
            "data.installed_software[0].name",
            "required_field_missing",
            "require_installed_software_fields",
        ),
        (
            {"installed_software": [{"name": "Docker"}]},
            "data.installed_software[0].version",
            "required_field_missing",
            "require_installed_software_fields",
        ),
        (
            {"installed_software": [{"name": "", "version": "1"}]},
            "data.installed_software[0].name",
            "value_too_short",
            None,
        ),
        (
            {"installed_software": [{"name": "Docker", "version": "   "}]},
            "data.installed_software[0].version",
            "value_too_short",
            "reject_empty_installed_software_fields",
        ),
        (
            {
                "installed_software": [
                    {"name": "Docker", "version": "1", "vendor": "Example"}
                ]
            },
            "data.installed_software[0].vendor",
            "field_not_allowed",
            "reject_installed_software_extra_fields",
        ),
        (
            {
                "installed_software": [
                    {"name": "Docker", "version": "1", "url": "/relative"}
                ]
            },
            "data.installed_software[0].url",
            "invalid_format",
            None,
        ),
        (
            {
                "installed_software": [
                    {"name": "Docker", "version": "1", "url": "ftp://example.test/x"}
                ]
            },
            "data.installed_software[0].url",
            "invalid_format",
            None,
        ),
    ],
)
def test_invalid_entry_shapes_have_field_accurate_domain_errors(
    data: dict[str, object],
    path: str,
    violation: str,
    rule: str | None,
) -> None:
    with pytest.raises(ObjectSchemaError) as exc_info:
        validate_object_data("host", data)

    assert exc_info.value.path == path
    assert exc_info.value.violation == violation
    assert exc_info.value.rule == rule


@pytest.mark.parametrize(
    "url",
    [
        "http://[",
        "https://[::1",
        "http://[not-an-ipv6-address]",
        "https://[::1]:not-a-port/releases",
        "http://[::1]:70000/releases",
        "https://:443/releases",
    ],
)
def test_malformed_url_authorities_fail_closed_with_domain_error(url: str) -> None:
    with pytest.raises(ObjectSchemaError) as exc_info:
        validate_object_data(
            "host",
            {
                "installed_software": [
                    {"name": "Docker", "version": "27.5.1", "url": url}
                ]
            },
        )

    assert exc_info.value.path == "data.installed_software[0].url"
    assert exc_info.value.violation == "invalid_format"
    assert exc_info.value.rule is None


def test_rest_openapi_and_mcp_publish_the_same_canonical_projection() -> None:
    projection = object_schema_projection()
    openapi = create_app().openapi()
    rest_projection = openapi["x-blockwart-object-schema"]
    mcp_projection = describe_schema_payload()

    assert rest_projection == projection
    assert {kind["kind"] for kind in projection["kinds"]} == set(ObjectKind.__args__)
    assert mcp_projection["kinds"] == projection["kinds"]
    for kind in projection["kinds"]:
        fields = {field["path"]: field for field in kind["data"]["fields"]}
        requirement = fields["installed_software"]["requirement"]
        assert requirement == (
            "optional" if kind["kind"] in INSTALLED_SOFTWARE_KINDS else "forbidden"
        )
        if kind["kind"] in INSTALLED_SOFTWARE_KINDS:
            for path in (
                "installed_software[].name",
                "installed_software[].version",
            ):
                assert fields[path]["requirement"] == "required"
                assert fields[path]["required_scope"] == "containing_array_item"
            url_field = fields["installed_software[].url"]
            assert url_field["format"] == "uri"
            assert url_field["pattern"] == r"^[Hh][Tt][Tt][Pp][Ss]?://"


def test_mcp_update_forwards_installed_software_losslessly() -> None:
    requested = CatalogObjectIn(
        id="mcp-software",
        kind="host",
        label="MCP software",
        data=_software_data(),
    ).model_dump(mode="json")
    observed: dict[str, object] = {}

    def requester(method, path, body, headers):
        observed.update(method=method, path=path, body=body, headers=headers)
        return {"catalog_object": body, "etag": '"rev-2"', "changed": True}

    result = call_tool(
        "blockwart.update_object",
        {"object_id": "mcp-software", "if_match": '"rev-1"', "object": requested},
        requester=requester,
    )

    assert result["isError"] is False
    assert observed["body"]["data"] == _software_data()
    assert observed["headers"]["If-Match"] == '"rev-1"'
    assert observed["headers"]["X-Blockwart-Channel"] == "mcp"
    assert observed["headers"]["X-Correlation-ID"]


def test_rest_field_details_and_write_invariants_cover_installed_software(
    write_client: TestClient,
    root_state,  # noqa: F811
) -> None:
    headers = _owner_headers(root_state)
    invalid = write_client.post(
        "/api/v1/roots",
        headers={**headers, "Idempotency-Key": "software-invalid-root-0001"},
        json={
            "id": "invalid-software-root",
            "kind": "host",
            "label": "Invalid",
            "data": {"installed_software": [{"name": "Docker"}]},
        },
    )
    assert invalid.status_code == 422
    assert invalid.json()["error"]["details"] == [
        {
            "code": "required_field_missing",
            "location": "body.data.installed_software[0].version",
            "message": (
                "A required field is missing at this path."
            ),
            "path": "data.installed_software[0].version",
            "rule": "require_installed_software_fields",
        }
    ]

    created = write_client.post(
        "/api/v1/roots",
        headers={**headers, "Idempotency-Key": "software-valid-root-0001"},
        json={
            "id": "software-root",
            "kind": "host",
            "label": "Software root",
            "data": _software_data(),
        },
    )
    assert created.status_code == 201
    assert created.json()["catalog_object"]["data"] == _software_data()
    assert created.headers["etag"] == '"rev-1"'

    updated_data = {"installed_software": list(reversed(_software_data()["installed_software"]))}
    updated = write_client.put(
        "/api/v1/objects/software-root",
        headers={**headers, "If-Match": '"rev-1"'},
        json={
            "id": "software-root",
            "kind": "host",
            "label": "Software root",
            "data": updated_data,
        },
    )
    assert updated.status_code == 200
    assert updated.headers["etag"] == '"rev-2"'
    assert updated.json()["catalog_object"]["revision"] == 2
    assert updated.json()["catalog_object"]["data"] == updated_data

    conflict = write_client.put(
        "/api/v1/objects/software-root",
        headers={**headers, "If-Match": '"rev-1"'},
        json={
            "id": "software-root",
            "kind": "host",
            "label": "Software root",
            "data": _software_data(),
        },
    )
    assert conflict.status_code == 412

    audit = write_client.get("/api/v1/objects/software-root/audit-events", headers=headers)
    assert audit.status_code == 200
    assert [event["action"] for event in audit.json()["items"]][:2] == [
        "update",
        "create_root",
    ]
    assert audit.json()["items"][0]["details"]["old_revision"] == 1
    assert audit.json()["items"][0]["details"]["new_revision"] == 2

    hidden = write_client.get(
        "/api/v1/objects/software-root",
        headers={"Authorization": f"Bearer {root_state['scoped_token']}"},
    )
    assert hidden.status_code == 404
    assert "Docker Engine" not in hidden.text


def test_malformed_url_has_identical_rest_and_mcp_error_projection(
    write_client: TestClient,
    root_state,  # noqa: F811
) -> None:
    response = write_client.post(
        "/api/v1/roots",
        headers={
            **_owner_headers(root_state),
            "Idempotency-Key": "software-malformed-url-root-0001",
        },
        json={
            "id": "malformed-software-url-root",
            "kind": "host",
            "label": "Malformed URL",
            "data": {
                "installed_software": [
                    {"name": "Docker", "version": "27.5.1", "url": "http://["}
                ]
            },
        },
    )

    assert response.status_code == 422
    expected_detail = {
        "code": "invalid_format",
        "location": "body.data.installed_software[0].url",
        "message": (
            "The value at this path does not use the format this field requires."
        ),
        "path": "data.installed_software[0].url",
        "rule": None,
    }
    assert response.json()["error"]["details"] == [expected_detail]

    upstream = HTTPError(
        "http://127.0.0.1/api/v1/roots",
        422,
        "Unprocessable Entity",
        {},
        BytesIO(json.dumps(response.json()).encode()),
    )
    translated = _translate_http_error(upstream)
    mcp_result = _tool_error_result(
        translated.code,
        translated.public_message,
        correlation_id=translated.correlation_id,
        details=translated.details,
    )
    mcp_payload = json.loads(mcp_result.content[0].text)

    assert mcp_result.isError is True
    assert mcp_payload["error"]["code"] == "validation_error"
    assert mcp_payload["error"]["details"] == [expected_detail]


def test_validation_never_opens_an_installed_software_url(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def forbidden(*_args, **_kwargs):
        raise AssertionError("URL validation attempted an outgoing request")

    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(urllib.request, "urlopen", forbidden)

    payload = CatalogObjectIn(
        id="offline-url-proof",
        kind="system",
        label="Offline URL proof",
        data=_software_data(),
    )

    assert json.loads(payload.model_dump_json())["data"] == _software_data()
