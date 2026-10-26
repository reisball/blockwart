"""Issue #302: actual MCP validation and error response, without private input."""

import asyncio
import json

import pytest

from blockwart.mcp import server

TOOL = "blockwart.save_project_record"


def arguments(record, **patch):
    return {
        "object_id": "project-example",
        "if_match": '"rev-7"',
        "idempotency_key": "record-diagnostic-0001",
        "record": {"kind": "page", "title": "Example", **record},
        **patch,
    }


@pytest.mark.parametrize("patch", [{}, {"record_id": "example-page"}])
def test_page_boundaries_use_real_mcp_response(monkeypatch, patch):
    requests = []

    def request(method, path, body, headers, **kwargs):
        requests.append((method, path, body, headers))
        return {"saved": True}

    monkeypatch.setattr(server, "request_json", request)
    valid = arguments({"body": "x" * 4000}, **patch)
    accepted = asyncio.run(server.handle_call_tool(TOOL, valid))
    assert not accepted.isError
    assert len(requests) == 1
    assert requests[0][2]["body"] == "x" * 4000
    assert requests[0][3]["If-Match"] == '"rev-7"'
    assert requests[0][3]["Idempotency-Key"] == valid["idempotency_key"]

    invalid = arguments({"body": "PRIVATE-MARKER-" + "x" * 4000}, **patch)
    invalid["record"]["body"] = invalid["record"]["body"][:4001]
    rejected = asyncio.run(server.handle_call_tool(TOOL, invalid))
    assert rejected.isError
    payload = json.loads(rejected.content[0].text)
    assert payload["error"]["code"] == "invalid_arguments"
    assert payload["error"]["details"] == [
        {
            "code": "value_too_long",
            "location": "record.body",
            "path": "body",
            "rule": "maxLength",
            "maximum": 4000,
            "message": server.public_detail(location="record.body", code="value_too_long")[
                "message"
            ],
        }
    ]
    assert "PRIVATE-MARKER" not in rejected.content[0].text
    assert len(requests) == 1


@pytest.mark.parametrize(
    ("record", "location", "maximum"),
    [
        ({"kind": "item", "description": "x" * 4001}, "record.description", 4000),
        (
            {"kind": "item", "requirement": {"original": "x" * 4001}},
            "record.requirement.original",
            4000,
        ),
        (
            {"kind": "item", "criteria": [{"id": "c", "description": "x" * 1001}]},
            "record.criteria.0.description",
            1000,
        ),
        ({"kind": "access", "purpose": "x" * 2001}, "record.purpose", 2000),
        ({"kind": "repository", "owner": "o" * 101, "name": "example"}, "record.owner", 100),
    ],
)
def test_only_selected_nested_record_branch_is_described(monkeypatch, record, location, maximum):
    def no_request(*args, **kwargs):
        pytest.fail("invalid record reached upstream")

    monkeypatch.setattr(server, "request_json", no_request)
    response = asyncio.run(server.handle_call_tool(TOOL, arguments(record)))
    details = json.loads(response.content[0].text)["error"]["details"]
    assert len(details) == 1
    assert details[0]["location"] == location
    expected_path = location.removeprefix("record.").replace(".0", "[0]")
    assert details[0]["path"] == expected_path
    assert details[0]["maximum"] == maximum
    assert details[0]["rule"] == "maxLength"
    assert "xxx" not in response.content[0].text


@pytest.mark.parametrize("kind", ["unpublished-marker", ["page"], None])
def test_invalid_discriminator_stays_safe(kind):
    response = asyncio.run(server.handle_call_tool(TOOL, arguments({"kind": kind})))
    assert response.isError
    assert "unpublished-marker" not in response.content[0].text
    assert "record.kind" in response.content[0].text


def test_unrelated_read_contract_remains_opaque():
    response = asyncio.run(
        server.handle_call_tool(
            "blockwart.list_project_records",
            {
                "object_id": "example",
                "kind": "page",
                "limit": 101,
            },
        )
    )
    assert "details" not in json.loads(response.content[0].text)["error"]


def test_stdio_transport_preserves_diagnostic_and_valid_boundary():
    import os
    import sys
    from pathlib import Path

    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client
    from test_mcp_server import _agent_api_server

    with _agent_api_server() as (base_url, requests):
        env = {
            **os.environ,
            "PYTHONPATH": str(Path("src").resolve()),
            "BLOCKWART_API_BASE_URL": base_url,
        }
        params = StdioServerParameters(
            command=sys.executable, args=["-m", "blockwart.mcp.server"], env=env
        )

        async def probe():
            async with stdio_client(params) as (read, write):
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    rejected = await session.call_tool(TOOL, arguments({"body": "x" * 4001}))
                    assert rejected.isError
                    detail = json.loads(rejected.content[0].text)["error"]["details"][0]
                    assert detail["location"] == "record.body"
                    assert detail["rule"] == "maxLength" and detail["maximum"] == 4000
                    assert requests == []
                    accepted = await session.call_tool(TOOL, arguments({"body": "x" * 4000}))
                    assert not accepted.isError

        asyncio.run(probe())
        assert len(requests) == 1
        assert requests[0]["if_match"] == '"rev-7"'
        assert requests[0]["idempotency_key"] == "record-diagnostic-0001"
        assert requests[0]["body"]["body"] == "x" * 4000


@pytest.mark.parametrize("key", ["body.password", "0", "title", "private-marker"])
@pytest.mark.parametrize("nested", [False, True])
def test_unknown_keys_are_not_published_as_schema_paths(monkeypatch, key, nested):
    def no_request(*args, **kwargs):
        pytest.fail("invalid record reached upstream")

    monkeypatch.setattr(server, "request_json", no_request)
    if nested:
        # title is declared at the record root, but not on a criterion.
        record = {"kind": "item", "criteria": [{"id": "c", key: "PRIVATE-VALUE"}]}
        expected_location, expected_path = "record.criteria.0", "criteria[0]"
    else:
        if key == "title":
            key = "description.password"
        record = {key: "PRIVATE-VALUE"}
        expected_location, expected_path = "record", None
    response = asyncio.run(server.handle_call_tool(TOOL, arguments(record)))
    assert response.isError
    details = json.loads(response.content[0].text)["error"]["details"]
    rejected = [d for d in details if d["code"] == "field_not_allowed"]
    assert len(rejected) == 1
    assert rejected[0]["location"] == expected_location
    assert rejected[0]["path"] == expected_path
    assert "PRIVATE-VALUE" not in response.content[0].text
