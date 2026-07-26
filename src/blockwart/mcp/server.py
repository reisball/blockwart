from __future__ import annotations

import asyncio
import json
import logging
import os
import re
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
_API_ERROR_CODE_PATTERN = re.compile(r"^[a-z][a-z0-9_]{1,63}$")
_CORRELATION_ID_PATTERN = re.compile(r"^[A-Za-z0-9._-]{1,64}$")


class ToolInputError(ValueError):
    pass


class UnknownToolError(ToolInputError):
    pass


class UpstreamError(RuntimeError):
    def __init__(
        self,
        code: str,
        public_message: str,
        correlation_id: str | None = None,
    ) -> None:
        super().__init__(public_message)
        self.code = code
        self.public_message = public_message
        self.correlation_id = correlation_id


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
    "lifecycle": {
        "type": "string",
        "enum": ["planned", "active", "retired"],
    },
    "health": {
        "type": "string",
        "enum": ["unknown", "healthy", "degraded", "down", "maintenance"],
    },
    "cursor": {"type": "string", "description": "Opaque v1 continuation cursor"},
    "sort": {
        "type": "string",
        "enum": ["id", "label", "kind", "updated_at"],
        "default": "id",
    },
    "direction": {
        "type": "string",
        "enum": ["asc", "desc"],
        "default": "asc",
    },
    "include_total": {"type": "boolean", "default": False},
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
        payload = _legacy_page_payload(
            fetch("/api/v1/objects", _clean_params(args, default_limit=10)),
            args=args,
            items_field="results",
        )
    elif name == "blockwart.get_object_context":
        object_id = _required_string(args, "object_id")
        context = fetch(f"/api/v1/objects/{quote(object_id, safe='')}", {})
        payload = {
            "query": object_id,
            "count": 1,
            "objects": [context],
        }
    elif name == "blockwart.get_context":
        payload = _legacy_page_payload(
            fetch("/api/v1/context", _clean_params(args, default_limit=5)),
            args=args,
            items_field="objects",
        )
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
        raise _translate_http_error(exc) from exc
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
        return _tool_error_result(
            exc.code,
            exc.public_message,
            correlation_id=exc.correlation_id,
        )
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
        "cursor",
        "sort",
        "direction",
        "include_total",
    ):
        if name in args:
            params[name] = args[name]
    return params


def _legacy_page_payload(
    payload: JSON,
    *,
    args: JSON,
    items_field: str,
) -> JSON:
    items = payload.get("items")
    if not isinstance(items, list):
        raise UpstreamError(
            "upstream_invalid_response",
            "Blockwart v1 API returned an invalid response.",
        )
    filters = {
        key: args[key]
        for key in (
            "parent",
            "ip",
            "port",
            "endpoint_type",
            "protocol",
            "exposure",
            "status",
            "lifecycle",
            "health",
        )
        if key in args
    }
    return {
        "query": args.get("q"),
        "kind": args.get("kind"),
        "filters": filters,
        "count": len(items),
        items_field: items,
        "next_cursor": payload.get("next_cursor"),
        "total": payload.get("total"),
        "sort": payload.get("sort"),
        "direction": payload.get("direction"),
    }


def _required_string(args: JSON, key: str) -> str:
    value = args.get(key)
    if not isinstance(value, str) or not value:
        raise ToolInputError(f"{key} is required")
    return value


def _translate_http_error(exc: HTTPError) -> UpstreamError:
    try:
        body = exc.read(65537)
        payload = None if len(body) > 65536 else json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        payload = None
    if isinstance(payload, dict) and isinstance(error := payload.get("error"), dict):
        code = error.get("code")
        message = error.get("message")
        correlation_id = error.get("correlation_id")
        if (
            isinstance(code, str)
            and _API_ERROR_CODE_PATTERN.fullmatch(code)
            and isinstance(message, str)
            and 0 < len(message) <= 200
        ):
            safe_correlation_id = (
                correlation_id
                if isinstance(correlation_id, str)
                and _CORRELATION_ID_PATTERN.fullmatch(correlation_id)
                else None
            )
            return UpstreamError(code, message, safe_correlation_id)
    return UpstreamError(
        "upstream_http_error",
        "Blockwart Agent API returned an error.",
    )


def _tool_error_result(
    code: str,
    message: str,
    *,
    correlation_id: str | None = None,
) -> types.CallToolResult:
    error = {"code": code, "message": message}
    if correlation_id is not None:
        error["correlation_id"] = correlation_id
    payload = {"error": error}
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
