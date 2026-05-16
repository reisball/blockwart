from __future__ import annotations

import json
import os
import sys
from collections.abc import Callable
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode
from urllib.request import Request, urlopen

DEFAULT_BASE_URL = "http://127.0.0.1:8000"
JSON = dict[str, Any]
Fetcher = Callable[[str, dict[str, Any]], JSON]


TOOLS: list[JSON] = [
    {
        "name": "blockwart.search",
        "description": "Search Blockwart catalog summaries through the read-only agent API.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "q": {"type": "string", "description": "Search term"},
                "kind": {
                    "type": "string",
                    "enum": [
                        "system",
                        "service",
                        "credential_reference",
                        "runbook",
                        "decision",
                        "project",
                    ],
                },
                "limit": {"type": "integer", "minimum": 1, "maximum": 50, "default": 10},
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "blockwart.get_object_context",
        "description": "Get sanitized context for one Blockwart object by id.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "object_id": {"type": "string", "description": "Catalog object id"},
            },
            "required": ["object_id"],
            "additionalProperties": False,
        },
    },
    {
        "name": "blockwart.get_context",
        "description": "Get a small sanitized context bundle from Blockwart.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "q": {"type": "string", "description": "Search term"},
                "kind": {
                    "type": "string",
                    "enum": [
                        "system",
                        "service",
                        "credential_reference",
                        "runbook",
                        "decision",
                        "project",
                    ],
                },
                "limit": {"type": "integer", "minimum": 1, "maximum": 20, "default": 5},
            },
            "additionalProperties": False,
        },
    },
]


def call_tool(
    name: str,
    arguments: JSON | None,
    *,
    base_url: str | None = None,
    fetcher: Fetcher | None = None,
) -> JSON:
    args = arguments or {}
    fetch = fetcher or (lambda path, params: fetch_json(path, params, base_url=base_url))

    if name == "blockwart.search":
        payload = fetch("/api/agent/search", _clean_params(args, default_limit=10))
    elif name == "blockwart.get_object_context":
        object_id = _required_string(args, "object_id")
        payload = fetch(f"/api/agent/objects/{quote(object_id, safe='')}", {})
    elif name == "blockwart.get_context":
        payload = fetch("/api/agent/context", _clean_params(args, default_limit=5))
    else:
        raise ValueError(f"Unknown tool: {name}")

    return {
        "content": [
            {
                "type": "text",
                "text": json.dumps(payload, indent=2, sort_keys=True),
            }
        ],
        "isError": False,
    }


def fetch_json(path: str, params: JSON, *, base_url: str | None = None) -> JSON:
    root = (base_url or os.environ.get("BLOCKWART_API_BASE_URL") or DEFAULT_BASE_URL).rstrip("/")
    query = urlencode({key: value for key, value in params.items() if value is not None})
    url = f"{root}{path}"
    if query:
        url = f"{url}?{query}"
    request = Request(url, method="GET")
    try:
        with urlopen(request, timeout=10) as response:
            return json.loads(response.read().decode("utf-8"))
    except HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"Blockwart API returned HTTP {exc.code}: {detail}") from exc
    except URLError as exc:
        raise RuntimeError(f"Blockwart API unavailable: {exc.reason}") from exc


def handle_request(request: JSON) -> JSON | None:
    request_id = request.get("id")
    method = request.get("method")
    params = request.get("params") or {}

    try:
        if method == "initialize":
            result = {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "blockwart-mcp", "version": "0.1.0"},
            }
        elif method == "notifications/initialized":
            return None
        elif method == "tools/list":
            result = {"tools": TOOLS}
        elif method == "tools/call":
            result = call_tool(params.get("name", ""), params.get("arguments") or {})
        else:
            return _error_response(request_id, -32601, f"Unknown method: {method}")
        return {"jsonrpc": "2.0", "id": request_id, "result": result}
    except Exception as exc:
        return _error_response(request_id, -32000, str(exc))


def main() -> None:
    while True:
        message = _read_message(sys.stdin.buffer)
        if message is None:
            return
        response = handle_request(message)
        if response is not None:
            _write_message(sys.stdout.buffer, response)


def _clean_params(args: JSON, *, default_limit: int) -> JSON:
    return {
        "q": args.get("q"),
        "kind": args.get("kind"),
        "limit": args.get("limit", default_limit),
    }


def _required_string(args: JSON, key: str) -> str:
    value = args.get(key)
    if not isinstance(value, str) or not value:
        raise ValueError(f"{key} is required")
    return value


def _read_message(stream) -> JSON | None:
    headers: dict[str, str] = {}
    while True:
        line = stream.readline()
        if not line:
            return None
        if line in {b"\r\n", b"\n"}:
            break
        key, _, value = line.decode("ascii").partition(":")
        headers[key.lower()] = value.strip()

    length = int(headers.get("content-length", "0"))
    if length <= 0:
        return None
    return json.loads(stream.read(length).decode("utf-8"))


def _write_message(stream, payload: JSON) -> None:
    body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    stream.write(f"Content-Length: {len(body)}\r\n\r\n".encode("ascii"))
    stream.write(body)
    stream.flush()


def _error_response(request_id: Any, code: int, message: str) -> JSON:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {"code": code, "message": message},
    }


if __name__ == "__main__":
    main()
