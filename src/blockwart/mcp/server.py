from __future__ import annotations

import asyncio
import json
import logging
import os
from collections.abc import Callable
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode
from urllib.request import Request, urlopen

import mcp.server.stdio
import mcp.types as types
from jsonschema.exceptions import ValidationError
from jsonschema.protocols import Validator
from jsonschema.validators import validator_for
from mcp.server.lowlevel import NotificationOptions, Server

DEFAULT_BASE_URL = "http://127.0.0.1:8000"
SERVER_NAME = "blockwart-mcp"
SERVER_VERSION = "0.1.0"
JSON = dict[str, Any]
Fetcher = Callable[[str, dict[str, Any]], JSON]
logger = logging.getLogger(__name__)


class ToolInputError(ValueError):
    pass


class UnknownToolError(ToolInputError):
    pass


class UpstreamError(RuntimeError):
    def __init__(self, code: str, public_message: str) -> None:
        super().__init__(public_message)
        self.code = code
        self.public_message = public_message


READ_ONLY_ANNOTATIONS: JSON = {
    "readOnlyHint": True,
    "destructiveHint": False,
    "idempotentHint": True,
    "openWorldHint": True,
}

QUERY_FILTER_PROPERTIES: JSON = {
    "q": {"type": "string", "description": "Search term"},
    "kind": {
        "type": "string",
        "enum": ["host", "system", "netzwerk", "service"],
    },
    "parent": {"type": "string", "description": "Typed parent reference"},
    "ip": {"type": "string", "description": "Resolved exact IP address"},
    "port": {"type": "integer", "minimum": 1, "maximum": 65535},
    "endpoint_type": {"type": "string", "description": "Exact endpoint capability"},
    "protocol": {"type": "string", "description": "Exact application protocol"},
    "exposure": {
        "type": "string",
        "enum": ["loopback", "lan", "vpn", "internal", "public", "unknown"],
    },
    "status": {"type": "string", "enum": ["active", "inactive", "deleted"]},
    "lifecycle": {"type": "string"},
    "health": {"type": "string"},
}

TOOLS: list[JSON] = [
    {
        "name": "blockwart.search",
        "description": "Search Blockwart catalog summaries through the read-only agent API.",
        "inputSchema": {
            "type": "object",
            "properties": {
                **QUERY_FILTER_PROPERTIES,
                "limit": {"type": "integer", "minimum": 1, "maximum": 50, "default": 10},
            },
            "additionalProperties": False,
        },
        "annotations": READ_ONLY_ANNOTATIONS,
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
        "annotations": READ_ONLY_ANNOTATIONS,
    },
    {
        "name": "blockwart.get_context",
        "description": "Get a small sanitized context bundle from Blockwart.",
        "inputSchema": {
            "type": "object",
            "properties": {
                **QUERY_FILTER_PROPERTIES,
                "limit": {"type": "integer", "minimum": 1, "maximum": 20, "default": 5},
            },
            "additionalProperties": False,
        },
        "annotations": READ_ONLY_ANNOTATIONS,
    },
]
TOOL_DEFINITIONS: dict[str, JSON] = {tool["name"]: tool for tool in TOOLS}


def _compile_input_validator(schema: JSON) -> Validator:
    validator_class = validator_for(schema)
    validator_class.check_schema(schema)
    return validator_class(schema)


TOOL_INPUT_VALIDATORS: dict[str, Validator] = {
    name: _compile_input_validator(tool["inputSchema"])
    for name, tool in TOOL_DEFINITIONS.items()
}


def call_tool(
    name: str,
    arguments: JSON | None,
    *,
    base_url: str | None = None,
    fetcher: Fetcher | None = None,
) -> JSON:
    if name not in TOOL_DEFINITIONS:
        raise UnknownToolError(f"Unknown tool: {name}")

    args = {} if arguments is None else arguments
    try:
        TOOL_INPUT_VALIDATORS[name].validate(args)
    except ValidationError as exc:
        raise ToolInputError("Tool arguments are invalid") from exc

    fetch = fetcher or (lambda path, params: fetch_json(path, params, base_url=base_url))

    if name == "blockwart.search":
        payload = fetch("/api/agent/search", _clean_params(args, default_limit=10))
    elif name == "blockwart.get_object_context":
        object_id = _required_string(args, "object_id")
        payload = fetch(f"/api/agent/objects/{quote(object_id, safe='')}", {})
    elif name == "blockwart.get_context":
        payload = fetch("/api/agent/context", _clean_params(args, default_limit=5))
    else:
        raise UnknownToolError(f"Unknown tool: {name}")

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
            try:
                return json.loads(response.read().decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise UpstreamError(
                    "upstream_invalid_response",
                    "Blockwart Agent API returned an invalid response.",
                ) from exc
    except HTTPError as exc:
        raise UpstreamError(
            "upstream_http_error",
            "Blockwart Agent API returned an error.",
        ) from exc
    except URLError as exc:
        raise UpstreamError(
            "upstream_unavailable",
            "Blockwart Agent API is unavailable.",
        ) from exc


server = Server(SERVER_NAME, version=SERVER_VERSION)


@server.list_tools()
async def list_tools() -> list[types.Tool]:
    return [types.Tool.model_validate(tool) for tool in TOOLS]


# The SDK's validation response bypasses Blockwart's stable error envelope, so
# call_tool validates the exact published schemas before any upstream request.
@server.call_tool(validate_input=False)
async def handle_call_tool(name: str, arguments: JSON) -> types.CallToolResult:
    try:
        result = await asyncio.to_thread(call_tool, name, arguments)
        return types.CallToolResult.model_validate(result)
    except UnknownToolError:
        return _tool_error_result("tool_not_found", "Unknown Blockwart tool.")
    except ToolInputError:
        return _tool_error_result("invalid_arguments", "Tool arguments are invalid.")
    except UpstreamError as exc:
        return _tool_error_result(exc.code, exc.public_message)
    except Exception:
        logger.exception("Unexpected MCP tool failure for %s", name)
        return _tool_error_result("internal_error", "Blockwart tool execution failed.")


async def run_server() -> None:
    async with mcp.server.stdio.stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            server.create_initialization_options(
                notification_options=NotificationOptions(),
                experimental_capabilities={},
            ),
        )


def main() -> None:
    asyncio.run(run_server())


def _clean_params(args: JSON, *, default_limit: int) -> JSON:
    params = {
        "q": args.get("q"),
        "kind": args.get("kind"),
        "limit": args.get("limit", default_limit),
    }
    for name in (
        "parent",
        "ip",
        "port",
        "endpoint_type",
        "protocol",
        "exposure",
        "status",
        "lifecycle",
        "health",
    ):
        if name in args:
            params[name] = args[name]
    return params


def _required_string(args: JSON, key: str) -> str:
    value = args.get(key)
    if not isinstance(value, str) or not value:
        raise ToolInputError(f"{key} is required")
    return value


def _tool_error_result(code: str, message: str) -> types.CallToolResult:
    payload = {"error": {"code": code, "message": message}}
    return types.CallToolResult(
        content=[
            types.TextContent(
                type="text",
                text=json.dumps(payload, separators=(",", ":"), sort_keys=True),
            )
        ],
        isError=True,
    )


if __name__ == "__main__":
    main()
