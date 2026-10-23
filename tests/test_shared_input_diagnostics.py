"""Issue #299: input-only source rules survive API and real MCP HTTP transport."""

from __future__ import annotations

import asyncio
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import BaseModel
from test_catalog_root_creation import root_state  # noqa: F401
from test_field_validation_errors import owner_headers, write_client  # noqa: F401

from blockwart.api.errors import install_api_error_contract, install_request_context
from blockwart.mcp import server as mcp_server
from blockwart.schemas.catalog import CatalogObjectIn
from blockwart.schemas.project_workspace import ProjectAccessIn, ProjectActionIn, ProjectItemIn

BASE = {"id": "diagnostic-service", "kind": "service", "label": "Diagnostic", "data": {}}
MARKER = "Bearer " + "A" * 24


class Nested(BaseModel):
    payload: CatalogObjectIn


@pytest.fixture
def probe():
    app = FastAPI()
    install_api_error_contract(app)
    install_request_context(app)

    @app.post("/api/object")
    def obj(payload: CatalogObjectIn):
        return {"ok": True}

    @app.post("/api/nested")
    def nested(payload: Nested):
        return {"ok": True}

    @app.post("/api/item")
    def item(payload: ProjectItemIn):
        return {"ok": True}

    @app.post("/api/action")
    def action(payload: ProjectActionIn):
        return {"ok": True}

    @app.post("/api/access")
    def access(payload: ProjectAccessIn):
        return {"ok": True}

    with TestClient(app) as client:
        yield client


@pytest.mark.parametrize(
    ("patch", "code", "path", "rule"),
    [
        ({"data": {"password": MARKER}}, "forbidden_key", "data.password", "secret_content"),
        (
            {"data": {"extensions": [{"token": MARKER}]}},
            "forbidden_key",
            "data.extensions[0].token",
            "secret_content",
        ),
        ({"summary": MARKER}, "forbidden_key", "summary", "secret_content"),
        ({"data": {"permissions": []}}, "field_not_allowed", "data.permissions", "acl_metadata"),
        (
            {"data": {"extensions": [{"acl": []}]}},
            "field_not_allowed",
            "data.extensions[0].acl",
            "acl_metadata",
        ),
        ({"data": {"placement": []}}, "type_mismatch", "data.placement", "placement_object"),
        (
            {"data": {"placement": {"state": "assigned"}}},
            "value_not_allowed",
            "data.placement.state",
            "placement_state",
        ),
        (
            {"data": {"placement": {"state": "unassigned", "reason": ""}}},
            "value_too_short",
            "data.placement.reason",
            "placement_reason",
        ),
        (
            {"kind": "host", "data": {"placement": {"state": "unassigned"}}},
            "field_not_allowed",
            "data.placement",
            "placement_kind",
        ),
        (
            {"kind": "credential_reference", "lifecycle": "active"},
            "field_not_allowed",
            "lifecycle",
            "asset_state_kind",
        ),
        (
            {"provenance": {"observed_at": "not-a-date"}},
            "invalid_format",
            "provenance.observed_at",
            "timestamp_rfc3339",
        ),
    ],
)
def test_catalog_rules(probe, patch, code, path, rule):
    response = probe.post("/api/object", json={**BASE, **patch})
    assert response.status_code == 422
    details = response.json()["error"]["details"]
    assert any(d["code"] == code and d["path"] == path and d["rule"] == rule for d in details)
    assert MARKER not in response.text
    assert mcp_server._upstream_details(response.json()["error"]) == details


@pytest.mark.parametrize(
    ("endpoint", "payload", "rule", "path"),
    [
        ("item", {"description": MARKER}, "secret_content", "description"),
        ("item", {"criteria": [{"id": "c1", "description": "c"}]}, "requirement_fields", None),
        (
            "item",
            {
                "item_type": "requirement",
                "criteria": [{"id": "c1", "description": "c"}, {"id": "c1", "description": "d"}],
            },
            "unique_criterion_ids",
            "criteria",
        ),
        ("item", {"item_type": "evidence"}, "evidence_fields", None),
        ("item", {"issue_url": "ftp://example.invalid"}, "safe_http_url", "issue_url"),
        ("item", {"due_at": "not-a-date"}, "timestamp_rfc3339", "due_at"),
        (
            "item",
            {"github_references": [{"repository_id": "r", "kind": "issue"}]},
            "github_reference_identity",
            "github_references[0]",
        ),
        ("item", {"status_authority": "github"}, "github_status_authority", None),
        (
            "item",
            {
                "relations": [
                    {"relation": "depends_on", "target_id": "a"},
                    {"relation": "depends_on", "target_id": "a"},
                ]
            },
            "unique_relations",
            "relations",
        ),
        (
            "item",
            {
                "github_references": [
                    {"repository_id": "r", "kind": "issue", "number": 1},
                    {"repository_id": "r", "kind": "issue", "number": 1},
                ]
            },
            "unique_github_references",
            "github_references",
        ),
        ("action", {"action": "comment"}, "comment_body", "body"),
        ("action", {"action": "assess", "result": "accepted"}, "assessment_fields", None),
        ("action", {"action": "reuse_evidence"}, "evidence_reuse_fields", None),
        (
            "action",
            {"action": "comment", "body": "c", "changes": {"title": "a"}},
            "patch_changes",
            "changes",
        ),
        ("action", {"action": "comment", "body": MARKER}, "secret_content", "body"),
        (
            "access",
            {
                "credential_reference": "a",
                "new_credential_reference": {
                    "id": "b",
                    "kind": "credential_reference",
                    "label": "B",
                    "data": {},
                },
            },
            "one_credential_reference",
            None,
        ),
        (
            "access",
            {"new_credential_reference": BASE},
            "credential_reference_kind",
            "new_credential_reference.kind",
        ),
    ],
)
def test_project_rules(probe, endpoint, payload, rule, path):
    base = {} if endpoint == "action" else {"kind": endpoint, "title": "Diagnostic"}
    response = probe.post("/api/" + endpoint, json={**base, **payload})
    assert response.status_code == 422
    details = response.json()["error"]["details"]
    assert any(d["rule"] == rule and d["path"] == path for d in details), details
    assert all(d["code"] != "invalid_value" for d in details)
    assert MARKER not in response.text
    assert mcp_server._upstream_details(response.json()["error"]) == details


def test_nested_model_location_and_unknown_dictionary_key_redaction(probe):
    for key in ("bad.key", "ghp_" + "B" * 24, "unpublished-dictionary-name"):
        response = probe.post(
            "/api/nested", json={"payload": {**BASE, "data": {key: {"password": MARKER}}}}
        )
        detail = response.json()["error"]["details"][0]
        assert detail["location"] == "body.payload.data"
        assert detail["path"] == "data"
        assert detail["rule"] == "secret_content"
        assert key not in response.text and MARKER not in response.text


def test_multiple_violations_are_bounded_deduplicated_and_deterministic(probe):
    data = {"extensions": [{"password": MARKER, "acl": []} for _ in range(30)]}
    responses = [probe.post("/api/object", json={**BASE, "data": data}).json() for _ in range(2)]
    details = responses[0]["error"]["details"]
    assert len(details) == 20
    assert details == responses[1]["error"]["details"]
    assert len({json.dumps(d, sort_keys=True) for d in details}) == 20
    assert {d["rule"] for d in details} == {"secret_content", "acl_metadata"}
    assert MARKER not in json.dumps(responses)


@pytest.mark.parametrize(
    ("endpoint", "payload"),
    [
        ("object", BASE),
        ("item", {"kind": "item", "title": "Valid"}),
        ("action", {"action": "comment", "body": "Valid comment"}),
        ("object", {**BASE, "data": {"placement": {"state": "unassigned", "reason": "planned"}}}),
    ],
)
def test_valid_controls(probe, endpoint, payload):
    assert probe.post("/api/" + endpoint, json=payload).status_code == 200


def test_real_object_api_and_mcp_http_transport(write_client, owner_headers, monkeypatch):  # noqa: F811
    monkeypatch.setenv("BLOCKWART_API_TOKEN", "synthetic-runtime-token")
    monkeypatch.delenv("BLOCKWART_API_TOKEN_FILE", raising=False)
    # The upstream is the actual authenticated object-write API, not a handcrafted error.
    response = write_client.post(
        "/api/v1/roots",
        headers=owner_headers,
        json={**BASE, "data": {"extensions": [{"token": MARKER}]}},
    )
    assert response.status_code == 422
    expected = response.json()["error"]["details"]

    class ApiHandler(BaseHTTPRequestHandler):
        def do_POST(self):
            payload = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            upstream = write_client.post("/api/v1/roots", headers=owner_headers, json=payload)
            body = upstream.content
            self.send_response(upstream.status_code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), ApiHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    monkeypatch.setenv("BLOCKWART_API_BASE_URL", f"http://127.0.0.1:{server.server_port}")
    try:
        result = asyncio.run(
            mcp_server.handle_call_tool(
                "blockwart.create_root",
                {
                    "idempotency_key": "diagnostic-299-root",
                    "object": {**BASE, "data": {"extensions": [{"token": MARKER}]}},
                },
            )
        )
        payload = json.loads(result.content[0].text)
        assert result.isError
        assert payload["error"]["details"] == expected
        assert expected[0]["path"] == "data.extensions[0].token"
        assert expected[0]["rule"] == "secret_content"
        assert MARKER not in result.content[0].text
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_actual_project_create_and_patch_api_keep_diagnostics(write_client, root_state):  # noqa: F811
    from test_project_records import _save
    from test_project_workspace import _create_project

    _create_project(write_client, root_state["owner_token"], "work")
    invalid = _save(
        write_client, root_state, {"kind": "item", "title": "Diagnostic", "due_at": "not-a-date"}
    )
    assert invalid.status_code == 422
    detail = invalid.json()["error"]["details"][0]
    assert detail["rule"] == "timestamp_rfc3339" and detail["path"] == "due_at"

    created = _save(write_client, root_state, {"kind": "item", "title": "Diagnostic"})
    assert created.status_code == 201
    record = created.json()["record"]
    response = write_client.post(
        f"/api/v1/projects/work/workspace/actions/{record['id']}",
        headers={
            "Authorization": "Bearer " + root_state["owner_token"],
            "If-Match": record["record_etag"],
            "Idempotency-Key": "diagnostic-patch-299-key",
        },
        json={"action": "patch", "changes": {"due_at": "not-a-date"}},
    )
    assert response.status_code == 422, response.text
    detail = response.json()["error"]["details"][0]
    assert detail["rule"] == "timestamp_rfc3339" and detail["path"] == "due_at"
    assert "not-a-date" not in response.text
    after = write_client.get(
        f"/api/v1/projects/work/workspace/record/{record['id']}",
        headers={"Authorization": "Bearer " + root_state["owner_token"]},
    ).json()
    assert after["record_etag"] == record["record_etag"]


def test_placement_reason_type_is_not_reported_as_string_length(probe):
    response = probe.post(
        "/api/object", json={**BASE, "data": {"placement": {"state": "unassigned", "reason": 42}}}
    )
    assert response.status_code == 422
    detail = response.json()["error"]["details"][0]
    assert detail["code"] == "type_mismatch"
    assert detail["rule"] == "placement_reason_type"
    assert detail["path"] == "data.placement.reason"


@pytest.mark.parametrize(
    "key", ["secret", "SECRET", "ſecret", "ſession", "password", "Permissions", "acl"]
)
@pytest.mark.parametrize("acl", [False, True])
def test_structured_scanner_preserves_legacy_acceptance(key, acl):
    from blockwart.domain.security import (
        find_acl_data_violations,
        find_secret_violations,
        input_security_violations,
    )

    data = {"extensions": [{key: "ordinary metadata"}]}
    legacy = find_acl_data_violations(data) if acl else find_secret_violations(data)
    assert bool(list(input_security_violations(data, acl=acl))) == bool(legacy)


def test_unicode_non_secret_key_remains_accepted(probe):
    response = probe.post(
        "/api/object", json={**BASE, "data": {"extensions": {"ſecret": "ordinary metadata"}}}
    )
    assert response.status_code == 200


@pytest.mark.parametrize("marker", ["ghp_" + "B" * 24, "unpublished-patch-field", "bad.key"])
def test_project_patch_extra_keys_never_reach_api_or_mcp(write_client, root_state, marker):  # noqa: F811
    from test_project_records import _save
    from test_project_workspace import _create_project

    _create_project(write_client, root_state["owner_token"], "work")
    record = _save(write_client, root_state, {"kind": "item", "title": "Diagnostic"}).json()[
        "record"
    ]
    response = write_client.post(
        f"/api/v1/projects/work/workspace/actions/{record['id']}",
        headers={
            "Authorization": "Bearer " + root_state["owner_token"],
            "If-Match": record["record_etag"],
            "Idempotency-Key": "diagnostic-patch-extra-299",
        },
        json={"action": "patch", "changes": {marker: "ordinary metadata"}},
    )
    assert response.status_code == 422
    assert marker not in response.text
    details = response.json()["error"]["details"]
    assert details == mcp_server._upstream_details(response.json()["error"])
    assert details[0]["location"] == "body.item"
    assert details[0]["code"] == "field_not_allowed"


def test_attached_device_timestamp_has_canonical_provenance_path(write_client, owner_headers):  # noqa: F811
    response = write_client.post(
        "/api/v1/objects/existing-object/attached-devices",
        headers=owner_headers,
        json={
            "device": {
                "id": "diagnostic-device",
                "kind": "device",
                "label": "Diagnostic",
                "provenance": {"observed_at": "not-a-date"},
            }
        },
    )
    assert response.status_code == 422
    detail = response.json()["error"]["details"][0]
    assert detail["location"] == "body.device.provenance.observed_at"
    assert detail["path"] == "provenance.observed_at"
    assert detail["rule"] == "timestamp_rfc3339"


def test_nested_credential_timestamp_keeps_domain_path(probe):
    response = probe.post(
        "/api/access",
        json={
            "kind": "access",
            "title": "Diagnostic",
            "new_credential_reference": {
                "id": "diagnostic-ref",
                "kind": "credential_reference",
                "label": "Diagnostic",
                "provenance": {"verified_at": "not-a-date"},
            },
        },
    )
    detail = response.json()["error"]["details"][0]
    assert detail["location"] == "body.new_credential_reference.provenance.verified_at"
    assert detail["path"] == "provenance.verified_at"


def test_unknown_create_key_is_also_sanitized(probe):
    marker = "ghp_" + "C" * 24
    response = probe.post(
        "/api/item", json={"kind": "item", "title": "Diagnostic", marker: "ordinary"}
    )
    assert response.status_code == 422
    assert marker not in response.text
    assert response.json()["error"]["details"][0]["location"] == "body"


def test_domain_paths_and_untrusted_upstream_details_use_closed_vocabulary():
    from blockwart.domain.object_schema import ObjectSchemaError
    from blockwart.domain.relationships import (
        RelationshipIntegrityError,
        validate_relationship_metadata,
    )
    from blockwart.domain.validation_errors import (
        detail_from_object_schema_error,
        detail_from_relationship_error,
        sanitize_public_details,
    )

    marker = "ghp_" + "D" * 24
    object_detail = detail_from_object_schema_error(
        ObjectSchemaError(f"data.reference.{marker}.value", "internal", violation="forbidden_key"),
        location="body",
    )
    assert object_detail["path"] == "data.reference"
    assert object_detail["location"] == "body.data.reference"
    with pytest.raises(RelationshipIntegrityError) as caught:
        validate_relationship_metadata("hosts", {marker: "ordinary metadata"})
    relationship_detail = detail_from_relationship_error(caught.value, location="body")
    assert relationship_detail["path"] == "metadata"
    assert relationship_detail["location"] == "body.metadata"
    upstream = sanitize_public_details(
        [
            {
                "code": "forbidden_key",
                "location": f"body.data.reference.{marker}.value",
                "path": f"data.reference.{marker}.value",
                "rule": "reject_credential_value_keys",
            }
        ]
    )
    assert upstream[0]["location"] == "body.data.reference"
    assert upstream[0]["path"] == "data.reference"
    assert marker not in json.dumps([object_detail, relationship_detail, upstream])


def test_project_patch_domain_paths_never_reflect_dictionary_keys(write_client, root_state):  # noqa: F811
    from test_project_records import _save
    from test_project_workspace import _create_project

    _create_project(write_client, root_state["owner_token"], "work")
    record = _save(write_client, root_state, {"kind": "access", "title": "Diagnostic"}).json()[
        "record"
    ]
    marker = "ghp_" + "Z" * 24
    response = write_client.post(
        f"/api/v1/projects/work/workspace/actions/{record['id']}",
        headers={
            "Authorization": "Bearer " + root_state["owner_token"],
            "If-Match": record["record_etag"],
            "Idempotency-Key": "diagnostic-domain-path-299",
        },
        json={
            "action": "patch",
            "changes": {
                "new_credential_reference": {
                    "id": "diagnostic-ref",
                    "kind": "credential_reference",
                    "label": "Diagnostic",
                    "data": {marker: {"value": "ordinary metadata"}},
                }
            },
        },
    )
    assert response.status_code == 422
    assert marker not in response.text
    detail = response.json()["error"]["details"][0]
    assert detail["path"] == "data"
    assert detail["location"] == "body.access.new_credential_reference.data"
    assert detail["rule"] == "reject_credential_value_keys"
    assert mcp_server._upstream_details(response.json()["error"]) == [detail]


def test_every_declared_rest_and_mcp_parameter_retains_its_location():
    from pathlib import Path

    from blockwart.domain.validation_errors import public_detail

    contract = json.loads((Path(__file__).parent / "contracts" / "openapi.json").read_text())
    for path in contract["paths"].values():
        for operation in path.values():
            if not isinstance(operation, dict):
                continue
            for parameter in operation.get("parameters", []):
                location = parameter["in"] + "." + parameter["name"]
                assert (
                    public_detail(location=location, code="invalid_format")["location"] == location
                )
    for definition in mcp_server.TOOL_DEFINITIONS.values():
        schema = (
            definition.get("inputSchema", {})
            if isinstance(definition, dict)
            else definition.inputSchema
        )
        for name in schema.get("properties", {}):
            for location in (name, "arguments." + name):
                assert (
                    public_detail(location=location, code="invalid_format")["location"] == location
                )


@pytest.mark.parametrize(
    ("path", "locations"),
    [
        (
            "/api/v1/projects/work/workspace/item?overdue=invalid&blocked=invalid",
            {"query.overdue", "query.blocked"},
        ),
        (
            "/api/v1/attention?severity=invalid&signal_state=invalid",
            {"query.severity", "query.signal_state"},
        ),
    ],
)
def test_simultaneous_invalid_filters_remain_distinct(write_client, root_state, path, locations):  # noqa: F811
    from test_project_workspace import _create_project

    _create_project(write_client, root_state["owner_token"], "work")
    response = write_client.get(
        path, headers={"Authorization": "Bearer " + root_state["owner_token"]}
    )
    assert response.status_code == 422
    details = response.json()["error"]["details"]
    assert len(details) == 2
    assert {detail["location"] for detail in details} == locations
    assert mcp_server._upstream_details(response.json()["error"]) == details
