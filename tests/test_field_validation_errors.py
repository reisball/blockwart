"""Field-accurate projection of rejected object writes (Issue #138, Slice B).

The domain object schema is the single source of both the published field
rules and the violation catalog. These tests pin the parity contract that
every object-write boundary must publish: a rejected write carries one detail
per violation, each detail names the canonical public data path, a stable
machine-readable violation code, the published schema rule when a
postcondition rejected the write, and the published description. Nothing else
is ever projected, so a client can react to a rejected write without parsing
any message and without seeing a rejected value.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Generator
from io import BytesIO
from urllib.error import HTTPError

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session
from test_catalog_root_creation import root_state  # noqa: F401

from blockwart.api.deps import get_session
from blockwart.domain.object_schema import (
    GENERIC_SCHEMA_VIOLATION,
    PUBLIC_SCHEMA_RULE_CONTRACTS,
    SCHEMA_VIOLATION_CONTRACTS,
    ObjectSchemaError,
    public_rule_name,
    validate_object_data,
)
from blockwart.domain.schema_projection import (
    object_schema_projection,
)
from blockwart.domain.validation_errors import (
    PUBLIC_DETAIL_FIELDS,
    detail_from_object_schema_error,
    detail_from_validation_error,
    public_detail,
    public_violation,
    sanitize_public_details,
)
from blockwart.main import create_app
from blockwart.mcp import server as mcp_server
from blockwart.mcp.server import (
    WRITE_INTENT_TOOLS,
    ToolInputError,
    UpstreamError,
    _tool_error_result,
    _translate_http_error,
    call_tool,
    handle_call_tool,
)

SECRET_MARKER = "test-marker-test-marker"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def write_client(root_state) -> Generator[TestClient, None, None]:  # noqa: F811
    session_factory = root_state["session_factory"]
    app = create_app()

    def override_get_session() -> Generator[Session, None, None]:
        with session_factory() as session:
            yield session

    app.dependency_overrides[get_session] = override_get_session
    with TestClient(app) as client:
        yield client


@pytest.fixture
def owner_headers(root_state) -> dict[str, str]:  # noqa: F811
    return {"Authorization": f"Bearer {root_state['owner_token']}"}


def _post_root(
    client: TestClient,
    headers: dict[str, str],
    data: dict,
    *,
    kind: str = "network",
    object_id: str = "slice-b-obj",
) -> dict:
    body = {"id": object_id, "kind": kind, "label": "Slice B", "data": data}
    return client.post("/api/v1/roots", headers=headers, json=body).json()


def _domain_error(kind: str, data: dict) -> ObjectSchemaError:
    with pytest.raises(ObjectSchemaError) as exc_info:
        validate_object_data(kind, data)
    return exc_info.value


# ---------------------------------------------------------------------------
# Schema-projection parity
# ---------------------------------------------------------------------------


def test_published_detail_fields_match_the_canonical_projection() -> None:
    projection = object_schema_projection()["violation_policy"]

    assert projection["detail_fields"] == list(PUBLIC_DETAIL_FIELDS)
    assert projection["generic_violation"] == GENERIC_SCHEMA_VIOLATION
    assert projection["unknown_violations_fall_back_to_generic"] is True


def test_published_violations_are_exactly_the_domain_catalog() -> None:
    projection = object_schema_projection()["violation_policy"]
    published = {entry["code"]: entry["description"] for entry in projection["violations"]}

    assert published == dict(SCHEMA_VIOLATION_CONTRACTS)


def test_every_field_violation_is_a_published_code() -> None:
    projection = object_schema_projection()
    published_codes = set(SCHEMA_VIOLATION_CONTRACTS)

    for kind in projection["kinds"]:
        for field in kind["data"]["fields"]:
            assert set(field["violations"]).issubset(published_codes), (
                f"field {field['path']} publishes an unknown violation"
            )
        for rule in kind["data"]["rules"]:
            assert rule["rule"] in PUBLIC_SCHEMA_RULE_CONTRACTS
            assert rule["violation"] in published_codes


def test_public_detail_only_carries_canonical_json_safe_fields() -> None:
    detail = public_detail(
        location="body.data.network.category",
        code="required_field_missing",
        path="data.network.category",
        rule=None,
    )

    assert set(detail) == set(PUBLIC_DETAIL_FIELDS)
    assert tuple(detail) == PUBLIC_DETAIL_FIELDS
    assert detail["code"] == "required_field_missing"
    assert detail["message"] == SCHEMA_VIOLATION_CONTRACTS["required_field_missing"]


# ---------------------------------------------------------------------------
# Domain -> public detail projection
# ---------------------------------------------------------------------------


def test_domain_rejection_projects_to_its_public_path_code_and_rule() -> None:
    error = _domain_error(
        "credential_reference",
        {"schema_version": 1, "secret_value": SECRET_MARKER},
    )

    detail = detail_from_object_schema_error(error, location="body")

    assert error.violation == "forbidden_key"
    assert error.rule == public_rule_name("_reject_credential_value_keys")
    assert error.path == "data.secret_value"
    assert detail == {
        "code": "forbidden_key",
        "location": "body.data.secret_value",
        "message": SCHEMA_VIOLATION_CONTRACTS["forbidden_key"],
        "path": "data.secret_value",
        "rule": "reject_credential_value_keys",
    }
    # The rejected value never reaches the public projection.
    assert SECRET_MARKER not in json.dumps(detail)


def test_unknown_violation_falls_back_to_the_generic_public_view() -> None:
    assert public_violation("never_published") == GENERIC_SCHEMA_VIOLATION
    assert public_violation(None) == GENERIC_SCHEMA_VIOLATION

    error = ObjectSchemaError("data.x", "internal detail", violation="never_published")
    detail = detail_from_object_schema_error(error, location="body")

    assert detail["code"] == GENERIC_SCHEMA_VIOLATION
    assert detail["message"] == SCHEMA_VIOLATION_CONTRACTS[GENERIC_SCHEMA_VIOLATION]
    assert detail["rule"] is None
    assert "internal detail" not in json.dumps(detail)


def test_unparsable_path_is_dropped_instead_of_echoed() -> None:
    error = ObjectSchemaError("data.;;bad;;", "x", violation="type_mismatch")
    detail = detail_from_object_schema_error(error, location="body")

    # The odd segment is truncated; only the safe canonical root survives and
    # the attacker-controlled segment is never echoed back.
    assert detail["path"] == "data"
    assert detail["location"] == "body.data"
    assert ";;bad;;" not in json.dumps(detail)


# ---------------------------------------------------------------------------
# API object-write parity with the domain
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("kind", "data", "expected_code"),
    [
        (
            "network",
            {"schema_version": 1, "network": {"hostnames": [], "addresses": []}},
            "required_field_missing",
        ),
        (
            "network",
            {"schema_version": 1, "network": {"category": "not-a-category"}},
            "value_not_allowed",
        ),
        (
            "network",
            {
                "schema_version": 1,
                "network": {"category": "segment", "manufacturer": "x" * 200},
            },
            "value_too_long",
        ),
        (
            "network",
            {"schema_version": "bad", "network": {"category": "segment"}},
            "type_mismatch",
        ),
    ],
)
def test_api_object_write_projects_domain_path_and_code(
    write_client,
    owner_headers,
    kind,
    data,
    expected_code,
) -> None:
    domain_error = _domain_error(kind, data)

    response = _post_root(write_client, owner_headers, data, kind=kind)

    assert response["error"]["code"] == "validation_error"
    detail = response["error"]["details"][0]
    assert detail["code"] == expected_code
    assert detail["code"] == domain_error.violation
    assert detail["path"] == domain_error.path
    assert detail["rule"] == domain_error.rule
    assert detail["message"] == SCHEMA_VIOLATION_CONTRACTS[expected_code]
    assert set(detail) == set(PUBLIC_DETAIL_FIELDS)


def test_api_write_projects_a_forbidden_secret_key_without_the_value(
    write_client,
    owner_headers,
) -> None:
    data = {
        "schema_version": 1,
        "provider": "vaultwarden",
        "reference": {"name": "n"},
        "secret_value": SECRET_MARKER,
    }
    domain_error = _domain_error("credential_reference", data)

    response = _post_root(
        write_client,
        owner_headers,
        data,
        kind="credential_reference",
        object_id="slice-b-credref",
    )
    detail = response["error"]["details"][0]

    assert detail["code"] == "forbidden_key"
    assert detail["code"] == domain_error.violation
    assert detail["path"] == "data.secret_value"
    assert detail["rule"] == "reject_credential_value_keys"
    assert detail["rule"] == domain_error.rule
    rendered = json.dumps(response)
    assert SECRET_MARKER not in rendered


def test_api_write_projects_an_invalid_reference_child(
    write_client,
    owner_headers,
) -> None:
    data = {
        "schema_version": 1,
        "risk_level": "read-only",
        "approval_required": False,
        "related_decisions": ["credential_reference:secret"],
    }
    domain_error = _domain_error("runbook", data)

    response = _post_root(
        write_client,
        owner_headers,
        data,
        kind="runbook",
        object_id="slice-b-runbook",
    )
    detail = response["error"]["details"][0]

    assert detail["code"] == "reference_kind_not_allowed"
    assert detail["code"] == domain_error.violation
    assert detail["path"] == "data.related_decisions[0]"
    assert detail["rule"] == domain_error.rule


def test_api_write_rejects_a_secret_shaped_data_key_without_leaking_it(
    write_client,
    owner_headers,
) -> None:
    data = {"schema_version": 1, "password": SECRET_MARKER}
    response = _post_root(
        write_client,
        owner_headers,
        data,
        kind="system",
        object_id="slice-b-system",
    )

    assert response["error"]["code"] == "validation_error"
    detail = response["error"]["details"][0]
    # A secret-shape rejection is not a published ObjectSchemaError, so it
    # fails closed onto the generic violation without naming the rejected key.
    assert detail["code"] == GENERIC_SCHEMA_VIOLATION
    assert detail["path"] is None
    assert detail["rule"] is None
    assert SECRET_MARKER not in json.dumps(response)


def test_api_write_returns_multiple_details_in_a_stable_order(
    write_client,
    owner_headers,
) -> None:
    body = {"id": "Bad ID", "kind": "boguskind", "data": {"schema_version": 1}}
    headers = {**owner_headers, "Idempotency-Key": "mcp-create-root-0001"}

    first = write_client.post("/api/v1/roots", headers=headers, json=body).json()
    second = write_client.post("/api/v1/roots", headers=headers, json=body).json()

    details = first["error"]["details"]
    assert len(details) >= 3
    assert [d["location"] for d in details] == sorted(d["location"] for d in details)
    assert first["error"]["details"] == second["error"]["details"]
    for detail in details:
        assert set(detail) == set(PUBLIC_DETAIL_FIELDS)


def test_api_detail_fields_match_the_published_contract_envelope() -> None:
    # The OpenAPI contract model is the public promise of the detail shape; it
    # must not carry any field the schema projection does not publish.
    from blockwart.schemas.errors import ApiErrorDetail

    assert set(ApiErrorDetail.model_fields) == set(PUBLIC_DETAIL_FIELDS)


# ---------------------------------------------------------------------------
# Unknown errors fail closed
# ---------------------------------------------------------------------------


def test_unknown_pydantic_type_falls_back_to_the_generic_violation() -> None:
    detail = detail_from_validation_error(
        {
            "type": "some_new_pydantic_rule",
            "loc": ("data", "x"),
            "msg": "leak",
            "input": SECRET_MARKER,
        }
    )

    assert detail["code"] == GENERIC_SCHEMA_VIOLATION
    assert detail["message"] == SCHEMA_VIOLATION_CONTRACTS[GENERIC_SCHEMA_VIOLATION]
    assert detail["path"] is None
    assert SECRET_MARKER not in json.dumps(detail)


def test_sanitize_public_details_drops_anything_not_published() -> None:
    raw = [
        {"code": "required_field_missing", "location": "body.data.x", "path": "data.x"},
        {"code": "never_published", "location": "body", "path": "data.y"},
        {"internal": "must-not-leak", "secret_value": SECRET_MARKER},
        "not-a-dict",
    ]

    sanitized = sanitize_public_details(raw)

    assert len(sanitized) == 1
    assert sanitized[0]["code"] == "required_field_missing"
    assert sanitized[0]["message"] == SCHEMA_VIOLATION_CONTRACTS["required_field_missing"]
    assert SECRET_MARKER not in json.dumps(sanitized)


# ---------------------------------------------------------------------------
# MCP write-tool argument projection
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("name", "arguments", "expected"),
    [
        (
            "blockwart.create_root",
            {"idempotency_key": "mcp-create-root-0001"},
            {"code": "required_field_missing", "location": "object"},
        ),
        (
            "blockwart.create_root",
            {
                "idempotency_key": "mcp-create-root-0001",
                "object": {"id": "x", "kind": "bogus", "label": "L", "data": {"schema_version": 1}},
            },
            {"code": "value_not_allowed", "location": "object.kind"},
        ),
        (
            "blockwart.create_root",
            {"idempotency_key": "mcp-create-root-0001", "object": "not-a-dict"},
            {"code": "type_mismatch", "location": "object"},
        ),
    ],
)
def test_mcp_write_tool_projects_field_accurate_argument_errors(
    name, arguments, expected
) -> None:
    with pytest.raises(ToolInputError) as exc_info:
        call_tool(name, arguments)

    details = exc_info.value.details
    assert details
    detail = details[0]
    assert detail["code"] == expected["code"]
    assert detail["location"] == expected["location"]
    assert set(detail) == set(PUBLIC_DETAIL_FIELDS)


def test_mcp_write_tool_argument_errors_carry_no_input_value() -> None:
    with pytest.raises(ToolInputError) as exc_info:
        call_tool(
            "blockwart.create_root",
            {"idempotency_key": "mcp-create-root-0001", "object": SECRET_MARKER},
        )

    assert SECRET_MARKER not in json.dumps(exc_info.value.details)


@pytest.mark.parametrize(
    "name",
    [
        "blockwart.create_child",
        "blockwart.create_root",
        "blockwart.update_object",
        "blockwart.create_attached_device",
    ],
)
def test_every_object_write_tool_is_in_scope(name) -> None:
    assert name in WRITE_INTENT_TOOLS


def test_non_write_tools_keep_their_opaque_invalid_arguments_contract() -> None:
    # Read and non-object-write tools must not widen the public contract.
    result = asyncio.run(handle_call_tool("blockwart.search", {"kind": "bogus"}))
    payload = json.loads(result.content[0].text)

    assert payload == {
        "error": {
            "code": "invalid_arguments",
            "message": "Tool arguments are invalid.",
        }
    }


def test_handle_call_tool_surfaces_write_argument_details() -> None:
    result = asyncio.run(
        handle_call_tool("blockwart.create_root", {"idempotency_key": "mcp-create-root-0001"})
    )
    payload = json.loads(result.content[0].text)

    assert payload["error"]["code"] == "invalid_arguments"
    detail = payload["error"]["details"][0]
    assert detail["code"] == "required_field_missing"
    assert detail["location"] == "object"
    assert set(detail) == set(PUBLIC_DETAIL_FIELDS)


# ---------------------------------------------------------------------------
# MCP upstream projection (API 422 -> MCP tool error)
# ---------------------------------------------------------------------------


def _upstream_422(details: list) -> HTTPError:
    body = json.dumps(
        {
            "error": {
                "code": "validation_error",
                "message": "Request validation failed.",
                "correlation_id": "mcp-proof-1",
                "details": details,
            }
        }
    ).encode()
    return HTTPError(
        "http://127.0.0.1/api/v1/objects",
        422,
        "Unprocessable Entity",
        {},
        BytesIO(body),
    )


def test_mcp_translates_upstream_validation_details_onto_the_contract() -> None:
    upstream = _upstream_422(
        [
            {
                "code": "required_field_missing",
                "location": "body.data.network.category",
                "message": "upstream-only-text",
                "path": "data.network.category",
                "rule": None,
            },
            {
                "code": "forbidden_key",
                "location": "body.data.password",
                "message": "upstream-only-text",
                "path": "data.password",
                "rule": "reject_credential_value_keys",
                "input": SECRET_MARKER,
            },
            {"code": "never_published", "location": "body", "internal": SECRET_MARKER},
            {"not-a-detail": True},
        ]
    )

    translated = _translate_http_error(upstream)

    assert translated.code == "validation_error"
    assert translated.correlation_id == "mcp-proof-1"
    result = _tool_error_result(
        translated.code,
        translated.public_message,
        correlation_id=translated.correlation_id,
        details=translated.details,
    )
    payload = json.loads(result.content[0].text)

    details = payload["error"]["details"]
    assert [d["path"] for d in details] == ["data.network.category", "data.password"]
    for detail in details:
        assert set(detail) == set(PUBLIC_DETAIL_FIELDS)
        # The upstream message is regenerated locally, never forwarded.
        assert detail["message"] != "upstream-only-text"
    rendered = result.content[0].text
    assert SECRET_MARKER not in rendered
    assert "never_published" not in rendered


def test_mcp_translates_an_upstream_error_without_details_to_a_generic_view() -> None:
    upstream = HTTPError(
        "http://127.0.0.1/api/v1/objects",
        409,
        "Conflict",
        {},
        BytesIO(json.dumps({"detail": SECRET_MARKER}).encode()),
    )

    translated = _translate_http_error(upstream)
    result = _tool_error_result(
        translated.code,
        translated.public_message,
        correlation_id=translated.correlation_id,
        details=translated.details,
    )

    assert translated.code == "upstream_http_error"
    payload = json.loads(result.content[0].text)
    assert "details" not in payload["error"]
    assert SECRET_MARKER not in result.content[0].text


def test_handle_call_tool_surfaces_upstream_validation_details(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_request_json(*_args, **_kwargs):
        raise UpstreamError(
            "validation_error",
            "Request validation failed.",
            "mcp-proof-2",
            details=[
                {
                    "code": "required_field_missing",
                    "location": "body.data.network.category",
                    "message": SCHEMA_VIOLATION_CONTRACTS["required_field_missing"],
                    "path": "data.network.category",
                    "rule": None,
                }
            ],
        )

    monkeypatch.setattr(mcp_server, "request_json", fake_request_json)

    result = asyncio.run(
        handle_call_tool(
            "blockwart.create_root",
            {
                "idempotency_key": "mcp-create-root-0001",
                "object": {
                    "id": "slice-b",
                    "kind": "network",
                    "label": "L",
                    "data": {"schema_version": 1, "network": {"hostnames": []}},
                },
            },
        )
    )
    payload = json.loads(result.content[0].text)

    assert payload["error"]["code"] == "validation_error"
    detail = payload["error"]["details"][0]
    assert detail["code"] == "required_field_missing"
    assert detail["path"] == "data.network.category"
    assert set(detail) == set(PUBLIC_DETAIL_FIELDS)
