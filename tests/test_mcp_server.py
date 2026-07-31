import asyncio
import json
import os
import selectors
import subprocess
import sysconfig
import tempfile
import threading
from contextlib import contextmanager
from datetime import timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from io import BytesIO
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import parse_qs, urlsplit

import mcp.types as mcp_types
import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from blockwart.mcp import server as mcp_server
from blockwart.mcp.server import TOOLS, ToolInputError, call_tool


def _installed_entrypoint() -> Path:
    scripts_dir = Path(sysconfig.get_path("scripts"))
    entrypoint = scripts_dir / ("blockwart-mcp.exe" if os.name == "nt" else "blockwart-mcp")
    assert entrypoint.is_file(), "install the package before running the MCP transport tests"
    return entrypoint


def _server_environment(*, base_url: str | None = None) -> dict[str, str]:
    env = os.environ.copy()
    env.pop("PYTHONPATH", None)
    if base_url:
        env["BLOCKWART_API_BASE_URL"] = base_url
    return env


def _read_process_line(
    process: subprocess.Popen[bytes],
    selector: selectors.BaseSelector,
) -> bytes:
    assert selector.select(timeout=5), "server did not answer newline-delimited JSON-RPC"
    assert process.stdout is not None
    line = process.stdout.readline()
    assert line, "server closed stdout without a JSON-RPC response"
    assert line.endswith(b"\n")
    assert not line.startswith(b"Content-Length:")
    return line


@contextmanager
def _agent_api_server():
    requests: list[dict[str, object]] = []

    class AgentApiHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            parsed = urlsplit(self.path)
            query = parse_qs(parsed.query)
            requests.append(
                {
                    "method": "GET",
                    "path": parsed.path,
                    "query": query,
                    "authorization": self.headers.get("Authorization"),
                }
            )

            if query.get("q") == ["cause-upstream-error"]:
                body = b'{"detail":"sensitive-upstream-detail"}'
                self.send_response(503)
            else:
                item = {"path": parsed.path, "query": query}
                payload = (
                    {
                        "items": [item],
                        "next_cursor": None,
                        "total": 1,
                        "sort": "id",
                        "direction": "asc",
                    }
                    if parsed.path in {"/api/v1/objects", "/api/v1/context"}
                    else item
                )
                body = json.dumps(payload).encode()
                self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self) -> None:
            self._write_response("POST")

        def do_PUT(self) -> None:
            self._write_response("PUT")

        def do_DELETE(self) -> None:
            self._write_response("DELETE")

        def _write_response(self, method: str) -> None:
            content_length = int(self.headers.get("Content-Length", "0"))
            raw_body = self.rfile.read(content_length)
            requests.append(
                {
                    "method": method,
                    "path": urlsplit(self.path).path,
                    "authorization": self.headers.get("Authorization"),
                    "channel": self.headers.get("X-Blockwart-Channel"),
                    "if_match": self.headers.get("If-Match"),
                    "idempotency_key": self.headers.get("Idempotency-Key"),
                    "body": json.loads(raw_body or b"{}"),
                }
            )
            body = b'{"changed":true}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format: str, *args: object) -> None:
            pass

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), AgentApiHandler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        host, port = httpd.server_address
        yield f"http://{host}:{port}", requests
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=5)


@contextmanager
def _redirect_server(location: str):
    requests: list[str | None] = []

    class RedirectHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            requests.append(self.headers.get("Authorization"))
            self.send_response(302)
            self.send_header("Location", location)
            self.end_headers()

        def log_message(self, format: str, *args: object) -> None:
            pass

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), RedirectHandler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        host, port = httpd.server_address
        yield f"http://{host}:{port}", requests
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=5)


def test_mcp_console_entrypoint_uses_newline_delimited_jsonrpc() -> None:
    process = subprocess.Popen(
        [str(_installed_entrypoint())],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=_server_environment(),
    )
    selector = selectors.DefaultSelector()
    try:
        request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "blockwart-transport-test", "version": "1.0"},
            },
        }
        assert process.stdin is not None
        process.stdin.write(json.dumps(request, separators=(",", ":")).encode() + b"\n")
        process.stdin.flush()

        assert process.stdout is not None
        selector.register(process.stdout, selectors.EVENT_READ)
        initialize_line = _read_process_line(process, selector)
        initialize = json.loads(initialize_line)
        assert initialize["id"] == 1
        assert initialize["result"]["protocolVersion"] == "2025-11-25"

        initialized = {
            "jsonrpc": "2.0",
            "method": "notifications/initialized",
        }
        ping = {"jsonrpc": "2.0", "id": 2, "method": "ping"}
        process.stdin.write(json.dumps(initialized, separators=(",", ":")).encode() + b"\n")
        process.stdin.write(json.dumps(ping, separators=(",", ":")).encode() + b"\n")
        process.stdin.flush()

        ping_line = _read_process_line(process, selector)
        assert json.loads(ping_line) == {"jsonrpc": "2.0", "id": 2, "result": {}}
    finally:
        selector.close()
        if process.poll() is None:
            process.terminate()
        process.wait(timeout=5)


def test_mcp_client_completes_handshake_and_calls_every_read_only_tool() -> None:
    async def exercise_client(base_url: str):
        with tempfile.TemporaryFile(mode="w+") as stderr:
            params = StdioServerParameters(
                command=str(_installed_entrypoint()),
                env=_server_environment(base_url=base_url),
            )
            async with stdio_client(params, errlog=stderr) as (read_stream, write_stream):
                async with ClientSession(
                    read_stream,
                    write_stream,
                    read_timeout_seconds=timedelta(seconds=5),
                ) as session:
                    initialize = await session.initialize()
                    await session.send_ping()
                    listed = await session.list_tools()
                    results = {
                        "blockwart.search": await session.call_tool(
                            "blockwart.search",
                            {"q": "brieftraeger", "kind": "system", "limit": 3},
                        ),
                        "blockwart.get_object_context": await session.call_tool(
                            "blockwart.get_object_context",
                            {"object_id": "host/fabrik"},
                        ),
                        "blockwart.get_context": await session.call_tool(
                            "blockwart.get_context",
                            {"kind": "host", "limit": 2},
                        ),
                    }
                    upstream_error = await session.call_tool(
                        "blockwart.search",
                        {"q": "cause-upstream-error"},
                    )
                    invalid_arguments = await session.call_tool(
                        "blockwart.get_object_context",
                        {},
                    )
                    schema_invalid_arguments = {
                        "invalid_kind": await session.call_tool(
                            "blockwart.search",
                            {"kind": "definitely-not-valid"},
                        ),
                        "limit_zero": await session.call_tool(
                            "blockwart.search",
                            {"limit": 0},
                        ),
                        "limit_above_maximum": await session.call_tool(
                            "blockwart.search",
                            {"limit": 51},
                        ),
                        "unknown_field": await session.call_tool(
                            "blockwart.search",
                            {"unexpected": "ignored"},
                        ),
                    }
                    unknown_tool = await session.call_tool("blockwart.delete", {})
            stderr.seek(0)
            error_output = stderr.read()
        return (
            initialize,
            listed,
            results,
            upstream_error,
            invalid_arguments,
            schema_invalid_arguments,
            unknown_tool,
            error_output,
        )

    with _agent_api_server() as (base_url, requests):
        (
            initialize,
            listed,
            results,
            upstream_error,
            invalid_arguments,
            schema_invalid_arguments,
            unknown_tool,
            stderr,
        ) = asyncio.run(exercise_client(base_url))

    assert initialize.protocolVersion == mcp_types.LATEST_PROTOCOL_VERSION
    assert initialize.serverInfo.name == "blockwart-mcp"
    tools = {tool.name: tool for tool in listed.tools}
    assert set(tools) == {
        "blockwart.search",
        "blockwart.get_object_context",
        "blockwart.get_context",
        "blockwart.create_child",
        "blockwart.update_object",
        "blockwart.delete_object",
        "blockwart.create_relationship",
        "blockwart.delete_relationship",
    }
    assert all(
        tools[name].annotations and tools[name].annotations.readOnlyHint
        for name in {
            "blockwart.search",
            "blockwart.get_object_context",
            "blockwart.get_context",
        }
    )
    assert all(
        tools[name].annotations and not tools[name].annotations.readOnlyHint
        for name in {
            "blockwart.create_child",
            "blockwart.update_object",
            "blockwart.delete_object",
            "blockwart.create_relationship",
            "blockwart.delete_relationship",
        }
    )
    assert all(not result.isError for result in results.values())

    result_payloads = {}
    for name, result in results.items():
        content = result.content[0]
        assert isinstance(content, mcp_types.TextContent)
        result_payloads[name] = json.loads(content.text)
    assert result_payloads["blockwart.search"]["results"][0]["path"] == (
        "/api/v1/objects"
    )
    assert result_payloads["blockwart.get_object_context"]["objects"][0]["path"] == (
        "/api/v1/objects/host%2Ffabrik"
    )
    assert result_payloads["blockwart.get_context"]["objects"][0]["path"] == (
        "/api/v1/context"
    )

    upstream_content = upstream_error.content[0]
    assert isinstance(upstream_content, mcp_types.TextContent)
    assert upstream_error.isError is True
    assert json.loads(upstream_content.text) == {
        "error": {
            "code": "upstream_http_error",
            "message": "Blockwart Agent API returned an error.",
        }
    }
    assert "sensitive-upstream-detail" not in upstream_content.text

    invalid_content = invalid_arguments.content[0]
    assert isinstance(invalid_content, mcp_types.TextContent)
    assert invalid_arguments.isError is True
    assert json.loads(invalid_content.text)["error"]["code"] == "invalid_arguments"

    for result in schema_invalid_arguments.values():
        content = result.content[0]
        assert isinstance(content, mcp_types.TextContent)
        assert result.isError is True
        assert json.loads(content.text) == {
            "error": {
                "code": "invalid_arguments",
                "message": "Tool arguments are invalid.",
            }
        }

    unknown_content = unknown_tool.content[0]
    assert isinstance(unknown_content, mcp_types.TextContent)
    assert unknown_tool.isError is True
    assert json.loads(unknown_content.text)["error"]["code"] == "tool_not_found"

    assert [request["method"] for request in requests] == ["GET"] * 4
    assert [request["path"] for request in requests] == [
        "/api/v1/objects",
        "/api/v1/objects/host%2Ffabrik",
        "/api/v1/context",
        "/api/v1/objects",
    ]
    assert "Content-Length:" not in stderr
    assert "sensitive-upstream-detail" not in stderr


def test_mcp_forwards_bearer_only_from_runtime_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime_token = "bwst_00000000-0000-0000-0000-000000000001.runtime-secret"
    monkeypatch.setenv("BLOCKWART_API_TOKEN", runtime_token)
    monkeypatch.delenv("BLOCKWART_API_TOKEN_FILE", raising=False)

    with _agent_api_server() as (base_url, requests):
        result = mcp_server.fetch_json(
            "/api/v1/objects",
            {"limit": 1},
            base_url=base_url,
        )

    assert result["items"]
    assert requests[0]["authorization"] == f"Bearer {runtime_token}"
    assert runtime_token not in json.dumps(result)
    assert all(
        "token" not in tool["inputSchema"].get("properties", {})
        for tool in TOOLS
    )


def test_mcp_write_tools_forward_preconditions_without_credentials_in_arguments() -> None:
    calls = []

    def requester(method, path, body, headers):
        calls.append((method, path, body, headers))
        return {"changed": True}

    object_payload = {
        "id": "demo",
        "kind": "service",
        "label": "Demo",
        "lifecycle": "active",
        "health": "healthy",
        "data": {"schema_version": 1},
    }
    call_tool(
        "blockwart.create_child",
        {
            "parent_id": "fabrik",
            "idempotency_key": "mcp-create-key-0001",
            "object": object_payload,
        },
        requester=requester,
    )
    call_tool(
        "blockwart.update_object",
        {
            "object_id": "demo",
            "if_match": '"rev-1"',
            "object": object_payload,
        },
        requester=requester,
    )
    call_tool(
        "blockwart.delete_object",
        {"object_id": "demo", "if_match": '"rev-2"'},
        requester=requester,
    )

    assert calls == [
        (
            "POST",
            "/api/v1/objects/fabrik/children",
            object_payload,
            {
                "Idempotency-Key": "mcp-create-key-0001",
                "X-Blockwart-Channel": "mcp",
            },
        ),
        (
            "PUT",
            "/api/v1/objects/demo",
            object_payload,
            {"If-Match": '"rev-1"', "X-Blockwart-Channel": "mcp"},
        ),
        (
            "DELETE",
            "/api/v1/objects/demo",
            {},
            {"If-Match": '"rev-2"', "X-Blockwart-Channel": "mcp"},
        ),
    ]
    assert all(
        not {"token", "authorization", "credential"} & set(
            tool["inputSchema"].get("properties", {})
        )
        for tool in TOOLS
    )


def test_mcp_write_transport_uses_runtime_bearer_and_mcp_channel(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime_token = "bwst_00000000-0000-0000-0000-000000000001.write-secret"
    monkeypatch.setenv("BLOCKWART_API_TOKEN", runtime_token)
    monkeypatch.delenv("BLOCKWART_API_TOKEN_FILE", raising=False)

    with _agent_api_server() as (base_url, requests):
        result = mcp_server.request_json(
            "PUT",
            "/api/v1/objects/demo",
            {"id": "demo"},
            {
                "If-Match": '"rev-7"',
                "X-Blockwart-Channel": "mcp",
            },
            base_url=base_url,
        )

    assert result == {"changed": True}
    assert requests == [
        {
            "method": "PUT",
            "path": "/api/v1/objects/demo",
            "authorization": f"Bearer {runtime_token}",
            "channel": "mcp",
            "if_match": '"rev-7"',
            "idempotency_key": None,
            "body": {"id": "demo"},
        }
    ]


def test_mcp_rejects_redirect_without_forwarding_bearer_to_second_origin(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime_token = "bwst_00000000-0000-0000-0000-000000000001.redirect-secret"
    monkeypatch.setenv("BLOCKWART_API_TOKEN", runtime_token)
    monkeypatch.delenv("BLOCKWART_API_TOKEN_FILE", raising=False)

    with _agent_api_server() as (target_url, target_requests):
        with _redirect_server(f"{target_url}/api/v1/objects") as (
            redirect_url,
            redirect_requests,
        ):
            with pytest.raises(mcp_server.UpstreamError) as exc_info:
                mcp_server.fetch_json(
                    "/api/v1/objects",
                    {},
                    base_url=redirect_url,
                )

    assert exc_info.value.code == "upstream_http_error"
    assert redirect_requests == [f"Bearer {runtime_token}"]
    assert target_requests == []


def test_mcp_requires_https_for_non_loopback_bearer_transport(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(
        "BLOCKWART_API_TOKEN",
        "bwst_00000000-0000-0000-0000-000000000001.transport-secret",
    )
    monkeypatch.delenv("BLOCKWART_API_TOKEN_FILE", raising=False)

    with pytest.raises(mcp_server.UpstreamError) as exc_info:
        mcp_server.fetch_json(
            "/api/v1/objects",
            {},
            base_url="http://blockwart.example.test",
        )

    assert exc_info.value.code == "credential_configuration_error"


def test_mcp_token_file_is_reloaded_and_ambiguous_configuration_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    token_path = tmp_path / "blockwart.token"
    first = "bwst_00000000-0000-0000-0000-000000000001.first-secret"
    second = "bwst_00000000-0000-0000-0000-000000000001.second-secret"
    token_path.write_text(first, encoding="utf-8")
    monkeypatch.delenv("BLOCKWART_API_TOKEN", raising=False)
    monkeypatch.setenv("BLOCKWART_API_TOKEN_FILE", str(token_path))

    with _agent_api_server() as (base_url, requests):
        mcp_server.fetch_json("/api/v1/objects", {}, base_url=base_url)
        token_path.write_text(second, encoding="utf-8")
        mcp_server.fetch_json("/api/v1/objects", {}, base_url=base_url)

    assert [request["authorization"] for request in requests] == [
        f"Bearer {first}",
        f"Bearer {second}",
    ]

    monkeypatch.setenv("BLOCKWART_API_TOKEN", "ambiguous")
    with pytest.raises(
        mcp_server.UpstreamError,
        match="ambiguous",
    ) as exc_info:
        mcp_server.fetch_json("/api/v1/objects", {}, base_url="http://127.0.0.1:1")
    assert exc_info.value.code == "credential_configuration_error"


def test_mcp_rejects_oversized_token_file_without_an_upstream_request(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    token_path = tmp_path / "oversized.token"
    token_path.write_text("x" * 514, encoding="utf-8")
    monkeypatch.delenv("BLOCKWART_API_TOKEN", raising=False)
    monkeypatch.setenv("BLOCKWART_API_TOKEN_FILE", str(token_path))

    with pytest.raises(
        mcp_server.UpstreamError,
        match="invalid",
    ) as exc_info:
        mcp_server.fetch_json(
            "/api/v1/objects",
            {},
            base_url="http://127.0.0.1:1",
        )

    assert exc_info.value.code == "credential_configuration_error"


@pytest.mark.parametrize(
    ("name", "arguments"),
    [
        ("blockwart.search", {"kind": "definitely-not-valid"}),
        ("blockwart.search", {"limit": 0}),
        ("blockwart.search", {"limit": 51}),
        ("blockwart.search", {"unexpected": "ignored"}),
        ("blockwart.get_context", {"port": 0}),
        ("blockwart.get_object_context", {"object_id": 123}),
    ],
)
def test_mcp_rejects_schema_invalid_arguments_without_fetching(name, arguments) -> None:
    calls = []

    def fake_fetch(path, params):
        calls.append((path, params))
        return {}

    with pytest.raises(ToolInputError):
        call_tool(name, arguments, fetcher=fake_fetch)

    assert calls == []


def test_mcp_tools_publish_explicit_read_write_and_delete_hints() -> None:
    names = {tool["name"] for tool in TOOLS}

    assert names == {
        "blockwart.search",
        "blockwart.get_object_context",
        "blockwart.get_context",
        "blockwart.create_child",
        "blockwart.update_object",
        "blockwart.delete_object",
        "blockwart.create_relationship",
        "blockwart.delete_relationship",
    }
    tools = {tool["name"]: tool for tool in TOOLS}
    assert all(
        tools[name]["annotations"]["readOnlyHint"]
        for name in {
            "blockwart.search",
            "blockwart.get_object_context",
            "blockwart.get_context",
        }
    )
    assert tools["blockwart.delete_object"]["annotations"]["destructiveHint"]
    assert tools["blockwart.delete_relationship"]["annotations"]["destructiveHint"]
    assert not tools["blockwart.update_object"]["annotations"]["destructiveHint"]


def test_mcp_search_and_context_support_host_and_structured_filters() -> None:
    tools_by_name = {tool["name"]: tool for tool in TOOLS}

    for name in ("blockwart.search", "blockwart.get_context"):
        properties = tools_by_name[name]["inputSchema"]["properties"]
        assert "host" in properties["kind"]["enum"]
        assert set(properties) >= {
            "q",
            "kind",
            "parent",
            "ip",
            "port",
            "endpoint_type",
            "protocol",
            "exposure",
            "status",
            "lifecycle",
            "health",
            "source_type",
            "stale",
            "cursor",
            "sort",
            "direction",
            "include_total",
            "limit",
        }


def test_mcp_search_calls_read_only_agent_search_endpoint() -> None:
    calls = []

    def fake_fetch(path, params):
        calls.append((path, params))
        return {
            "items": [{"ref": "system:brieftraeger"}],
            "next_cursor": None,
            "total": None,
            "sort": "id",
            "direction": "asc",
        }

    response = call_tool(
        "blockwart.search",
        {
            "q": "brieftraeger",
            "kind": "system",
            "source_type": "import",
            "stale": False,
            "limit": 3,
        },
        fetcher=fake_fetch,
    )

    assert calls == [
        (
            "/api/v1/objects",
            {
                "q": "brieftraeger",
                "kind": "system",
                "source_type": "import",
                "stale": False,
                "limit": 3,
            },
        )
    ]
    payload = json.loads(response["content"][0]["text"])
    assert payload["results"][0]["ref"] == "system:brieftraeger"
    assert response["isError"] is False


def test_mcp_get_object_context_calls_read_only_agent_object_endpoint() -> None:
    calls = []

    def fake_fetch(path, params):
        calls.append((path, params))
        return {
            "ref": "service:n8n-web-ui",
            "parent_path": [
                {"ref": "host:fabrik"},
                {"ref": "system:n8n"},
            ],
        }

    response = call_tool(
        "blockwart.get_object_context",
        {"object_id": "n8n"},
        fetcher=fake_fetch,
    )

    assert calls == [("/api/v1/objects/n8n", {})]
    payload = json.loads(response["content"][0]["text"])
    assert payload["objects"][0]["ref"] == "service:n8n-web-ui"
    assert [node["ref"] for node in payload["objects"][0]["parent_path"]] == [
        "host:fabrik",
        "system:n8n",
    ]


def test_mcp_context_calls_read_only_agent_context_endpoint() -> None:
    calls = []

    def fake_fetch(path, params):
        calls.append((path, params))
        return {
            "items": [{"ref": "service:one"}, {"ref": "service:two"}],
            "next_cursor": None,
            "total": 2,
            "sort": "id",
            "direction": "asc",
        }

    response = call_tool(
        "blockwart.get_context",
        {"q": "paperless", "kind": "service", "limit": 2},
        fetcher=fake_fetch,
    )

    assert calls == [
        (
            "/api/v1/context",
            {"q": "paperless", "kind": "service", "limit": 2},
        )
    ]
    assert json.loads(response["content"][0]["text"])["count"] == 2


def test_mcp_forwards_structured_filters_to_the_read_only_agent_api() -> None:
    calls = []

    def fake_fetch(path, params):
        calls.append((path, params))
        return {
            "items": [{"ref": "host:baremetal-01"}],
            "next_cursor": None,
            "total": 1,
            "sort": "id",
            "direction": "asc",
        }

    response = call_tool(
        "blockwart.get_context",
        {
            "kind": "host",
            "parent": "host:rack-01",
            "ip": "10.20.0.10",
            "port": 8443,
            "endpoint_type": "REST API",
            "protocol": "https",
            "exposure": "lan",
            "status": "active",
            "lifecycle": "active",
            "health": "healthy",
            "limit": 4,
        },
        fetcher=fake_fetch,
    )

    assert calls == [
        (
            "/api/v1/context",
            {
                "q": None,
                "kind": "host",
                "parent": "host:rack-01",
                "ip": "10.20.0.10",
                "port": 8443,
                "endpoint_type": "REST API",
                "protocol": "https",
                "exposure": "lan",
                "status": "active",
                "lifecycle": "active",
                "health": "healthy",
                "limit": 4,
            },
        )
    ]
    assert json.loads(response["content"][0]["text"])["objects"][0]["ref"] == (
        "host:baremetal-01"
    )


def test_mcp_rejects_unknown_tools_without_fetching() -> None:
    def fake_fetch(path, params):
        raise AssertionError("fetcher should not be called")

    try:
        call_tool("blockwart.delete", {}, fetcher=fake_fetch)
    except ValueError as exc:
        assert "Unknown tool" in str(exc)
    else:
        raise AssertionError("unknown tool should fail")


def test_mcp_translates_stable_api_error_without_leaking_details() -> None:
    upstream_error = HTTPError(
        "http://127.0.0.1/api/agent/objects/missing",
        404,
        "Not Found",
        {},
        BytesIO(
            json.dumps(
                {
                    "error": {
                        "code": "not_found",
                        "message": "Catalog object not found",
                        "correlation_id": "mcp-proof-47",
                        "details": [{"internal": "must-not-leak"}],
                    }
                }
            ).encode()
        ),
    )

    translated = mcp_server._translate_http_error(upstream_error)
    result = mcp_server._tool_error_result(
        translated.code,
        translated.public_message,
        correlation_id=translated.correlation_id,
    )
    payload = json.loads(result.content[0].text)

    assert result.isError is True
    assert payload == {
        "error": {
            "code": "not_found",
            "message": "Catalog object not found",
            "correlation_id": "mcp-proof-47",
        }
    }
    assert "must-not-leak" not in result.content[0].text
