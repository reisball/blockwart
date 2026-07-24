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
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import mcp.types as mcp_types
import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

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
            requests.append({"method": "GET", "path": parsed.path, "query": query})

            if query.get("q") == ["cause-upstream-error"]:
                body = b'{"detail":"sensitive-upstream-detail"}'
                self.send_response(503)
            else:
                body = json.dumps({"path": parsed.path, "query": query}).encode()
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
    }
    assert all(tool.annotations and tool.annotations.readOnlyHint for tool in tools.values())
    assert all(not result.isError for result in results.values())

    result_payloads = {}
    for name, result in results.items():
        content = result.content[0]
        assert isinstance(content, mcp_types.TextContent)
        result_payloads[name] = json.loads(content.text)
    assert result_payloads["blockwart.search"]["path"] == "/api/agent/search"
    assert result_payloads["blockwart.get_object_context"]["path"] == (
        "/api/agent/objects/host%2Ffabrik"
    )
    assert result_payloads["blockwart.get_context"]["path"] == "/api/agent/context"

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
        "/api/agent/search",
        "/api/agent/objects/host%2Ffabrik",
        "/api/agent/context",
        "/api/agent/search",
    ]
    assert "Content-Length:" not in stderr
    assert "sensitive-upstream-detail" not in stderr


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


def test_mcp_tools_are_read_only() -> None:
    names = {tool["name"] for tool in TOOLS}

    assert names == {
        "blockwart.search",
        "blockwart.get_object_context",
        "blockwart.get_context",
    }
    assert not any("write" in name or "delete" in name or "update" in name for name in names)
    assert all(tool["annotations"]["readOnlyHint"] for tool in TOOLS)


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
            "status",
            "lifecycle",
            "health",
            "limit",
        }


def test_mcp_search_calls_read_only_agent_search_endpoint() -> None:
    calls = []

    def fake_fetch(path, params):
        calls.append((path, params))
        return {"count": 1, "results": [{"ref": "system:brieftraeger"}]}

    response = call_tool(
        "blockwart.search",
        {"q": "brieftraeger", "kind": "system", "limit": 3},
        fetcher=fake_fetch,
    )

    assert calls == [("/api/agent/search", {"q": "brieftraeger", "kind": "system", "limit": 3})]
    payload = json.loads(response["content"][0]["text"])
    assert payload["results"][0]["ref"] == "system:brieftraeger"
    assert response["isError"] is False


def test_mcp_get_object_context_calls_read_only_agent_object_endpoint() -> None:
    calls = []

    def fake_fetch(path, params):
        calls.append((path, params))
        return {
            "count": 1,
            "objects": [
                {
                    "ref": "service:n8n-web-ui",
                    "parent_path": [
                        {"ref": "host:fabrik"},
                        {"ref": "system:n8n"},
                    ],
                }
            ],
        }

    response = call_tool(
        "blockwart.get_object_context",
        {"object_id": "n8n"},
        fetcher=fake_fetch,
    )

    assert calls == [("/api/agent/objects/n8n", {})]
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
        return {"count": 2, "objects": []}

    response = call_tool(
        "blockwart.get_context",
        {"q": "paperless", "kind": "service", "limit": 2},
        fetcher=fake_fetch,
    )

    assert calls == [("/api/agent/context", {"q": "paperless", "kind": "service", "limit": 2})]
    assert json.loads(response["content"][0]["text"])["count"] == 2


def test_mcp_forwards_structured_filters_to_the_read_only_agent_api() -> None:
    calls = []

    def fake_fetch(path, params):
        calls.append((path, params))
        return {"count": 1, "objects": [{"ref": "host:baremetal-01"}]}

    response = call_tool(
        "blockwart.get_context",
        {
            "kind": "host",
            "parent": "host:rack-01",
            "ip": "10.20.0.10",
            "port": 8443,
            "status": "active",
            "lifecycle": "production",
            "health": "healthy",
            "limit": 4,
        },
        fetcher=fake_fetch,
    )

    assert calls == [
        (
            "/api/agent/context",
            {
                "q": None,
                "kind": "host",
                "parent": "host:rack-01",
                "ip": "10.20.0.10",
                "port": 8443,
                "status": "active",
                "lifecycle": "production",
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
