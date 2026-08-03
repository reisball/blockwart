from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import os
import re
from collections.abc import Callable
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener
from uuid import uuid4

import mcp.server.stdio
import mcp.types as types
from jsonschema.exceptions import ValidationError
from jsonschema.protocols import Validator
from jsonschema.validators import validator_for
from mcp.server.lowlevel import NotificationOptions, Server

DEFAULT_BASE_URL = "http://127.0.0.1:8000"
API_TOKEN_ENV = "BLOCKWART_API_TOKEN"
API_TOKEN_FILE_ENV = "BLOCKWART_API_TOKEN_FILE"
SERVER_NAME = "blockwart-mcp"
SERVER_VERSION = "0.1.0"
JSON = dict[str, Any]
Fetcher = Callable[[str, dict[str, Any]], JSON]
Requester = Callable[[str, str, JSON, dict[str, str]], JSON]
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


class _RejectRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, request, file_pointer, code, message, headers, new_url):
        return None


READ_ONLY_ANNOTATIONS: JSON = {
    "readOnlyHint": True,
    "destructiveHint": False,
    "idempotentHint": True,
    "openWorldHint": True,
}
WRITE_ANNOTATIONS: JSON = {
    "readOnlyHint": False,
    "destructiveHint": False,
    "idempotentHint": False,
    "openWorldHint": True,
}
DELETE_ANNOTATIONS: JSON = {
    "readOnlyHint": False,
    "destructiveHint": True,
    "idempotentHint": False,
    "openWorldHint": True,
}
ETAG_SCHEMA: JSON = {
    "type": "string",
    "pattern": '^"rev-[1-9][0-9]*"$',
    "description": "Strong ETag returned by the latest full object read",
}
OBJECT_WRITE_SCHEMA: JSON = {
    "type": "object",
    "required": ["id", "kind", "label"],
    "properties": {
        "id": {
            "type": "string",
            "pattern": "^[a-z0-9](?:[a-z0-9_-]*[a-z0-9])?$",
        },
        "kind": {
            "type": "string",
            "enum": [
                "host",
                "system",
                "network",
                "device",
                "service",
                "credential_reference",
                "runbook",
                "decision",
                "project",
            ],
        },
        "label": {"type": "string", "minLength": 1},
        "status": {
            "type": "string",
            "enum": ["active", "inactive", "deleted"],
            "default": "active",
        },
        "lifecycle": {
            "type": ["string", "null"],
            "enum": ["planned", "active", "retired", None],
        },
        "health": {
            "type": ["string", "null"],
            "enum": ["unknown", "healthy", "degraded", "down", "maintenance", None],
        },
        "summary": {"type": ["string", "null"]},
        "data": {"type": "object", "default": {}},
        "provenance": {"type": "object"},
    },
    "additionalProperties": False,
}
DEVICE_WRITE_SCHEMA: JSON = {
    **OBJECT_WRITE_SCHEMA,
    "properties": {
        **OBJECT_WRITE_SCHEMA["properties"],
        "kind": {"type": "string", "const": "device"},
    },
}
RELATIONSHIP_PROPERTIES: JSON = {
    "object_id": {"type": "string", "minLength": 1, "maxLength": 128},
    "if_match": ETAG_SCHEMA,
    "from_ref": {"type": "string", "minLength": 3, "maxLength": 192},
    "relation_type": {"type": "string", "minLength": 1, "maxLength": 96},
    "to_ref": {"type": "string", "minLength": 3, "maxLength": 192},
    "metadata": {
        "type": "object",
        "default": {},
        "additionalProperties": False,
        "properties": {
            "source_interface": {"type": "string", "minLength": 1, "maxLength": 128},
            "target_interface_or_port": {"type": "string", "minLength": 1, "maxLength": 128},
            "link_kind": {
                "type": "string",
                "enum": [
                    "ethernet",
                    "wifi",
                    "mesh",
                    "zigbee",
                    "bluetooth",
                    "usb",
                    "serial",
                    "gpio",
                    "power",
                    "virtual",
                    "other",
                ],
            },
            "primary": {"type": "boolean"},
            "note": {"type": "string", "minLength": 1, "maxLength": 512},
            "mode": {
                "type": "string",
                "enum": [
                    "access",
                    "trunk",
                    "routed",
                    "bridged",
                    "mesh",
                    "other",
                ],
            },
        },
    },
}
DEVICE_GRAPH_PROPERTIES: JSON = {
    "object_id": {"type": "string", "minLength": 1, "maxLength": 128},
}
NETWORK_TOPOLOGY_PROPERTIES: JSON = {
    "object_id": {"type": "string", "minLength": 1, "maxLength": 128},
}
GRANT_ROLE_SCHEMA: JSON = {
    "type": "string",
    "enum": [
        "discoverer",
        "viewer",
        "editor",
        "creator",
        "access_manager",
        "owner",
    ],
}
GRANT_SCOPE_SCHEMA: JSON = {
    "type": "string",
    "enum": ["self", "subtree"],
}

QUERY_FILTER_PROPERTIES: JSON = {
    "q": {"type": "string", "description": "Search term"},
    "kind": {
        "type": "string",
        "enum": ["host", "system", "network", "device", "service"],
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
    "source_type": {
        "type": "string",
        "enum": ["unknown", "manual", "import", "discovery"],
    },
    "stale": {
        "type": "boolean",
        "description": "Exact computed freshness state",
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
    {
        "name": "blockwart.create_child",
        "description": "Create one authorized child object with durable idempotency.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "parent_id": {"type": "string", "minLength": 1, "maxLength": 128},
                "idempotency_key": {
                    "type": "string",
                    "minLength": 16,
                    "maxLength": 128,
                    "pattern": "^[!-~]+$",
                },
                "object": OBJECT_WRITE_SCHEMA,
            },
            "required": ["parent_id", "idempotency_key", "object"],
            "additionalProperties": False,
        },
        "annotations": WRITE_ANNOTATIONS,
    },
    {
        "name": "blockwart.update_object",
        "description": "Update one authorized object using its current strong ETag.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "object_id": {"type": "string", "minLength": 1, "maxLength": 128},
                "if_match": ETAG_SCHEMA,
                "object": OBJECT_WRITE_SCHEMA,
            },
            "required": ["object_id", "if_match", "object"],
            "additionalProperties": False,
        },
        "annotations": WRITE_ANNOTATIONS,
    },
    {
        "name": "blockwart.delete_object",
        "description": "Delete one object when separately authorized and unreferenced.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "object_id": {"type": "string", "minLength": 1, "maxLength": 128},
                "if_match": ETAG_SCHEMA,
            },
            "required": ["object_id", "if_match"],
            "additionalProperties": False,
        },
        "annotations": DELETE_ANNOTATIONS,
    },
    {
        "name": "blockwart.create_relationship",
        "description": "Create or idempotently replace metadata for an authorized relationship.",
        "inputSchema": {
            "type": "object",
            "properties": RELATIONSHIP_PROPERTIES,
            "required": [
                "object_id",
                "if_match",
                "from_ref",
                "relation_type",
                "to_ref",
            ],
            "additionalProperties": False,
        },
        "annotations": WRITE_ANNOTATIONS,
    },
    {
        "name": "blockwart.delete_relationship",
        "description": "Delete an authorized relationship from the current object revision.",
        "inputSchema": {
            "type": "object",
            "properties": RELATIONSHIP_PROPERTIES,
            "required": [
                "object_id",
                "if_match",
                "from_ref",
                "relation_type",
                "to_ref",
            ],
            "additionalProperties": False,
        },
        "annotations": DELETE_ANNOTATIONS,
    },
    {
        "name": "blockwart.create_attached_device",
        "description": "Atomically create a device and attach it to a parent endpoint.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "parent_id": {"type": "string", "minLength": 1, "maxLength": 128},
                "idempotency_key": {
                    "type": "string",
                    "minLength": 16,
                    "maxLength": 128,
                    "pattern": "^[!-~]+$",
                },
                "device": DEVICE_WRITE_SCHEMA,
                "metadata": RELATIONSHIP_PROPERTIES["metadata"],
            },
            "required": ["parent_id", "idempotency_key", "device"],
            "additionalProperties": False,
        },
        "annotations": WRITE_ANNOTATIONS,
    },
    {
        "name": "blockwart.get_device_graph",
        "description": "Return the authorized attached_to graph for an object.",
        "inputSchema": {
            "type": "object",
            "properties": DEVICE_GRAPH_PROPERTIES,
            "required": ["object_id"],
            "additionalProperties": False,
        },
        "annotations": READ_ONLY_ANNOTATIONS,
    },
    {
        "name": "blockwart.get_network_topology",
        "description": "Return the authorized direct or inherited network paths for an object.",
        "inputSchema": {
            "type": "object",
            "properties": NETWORK_TOPOLOGY_PROPERTIES,
            "required": ["object_id"],
            "additionalProperties": False,
        },
        "annotations": READ_ONLY_ANNOTATIONS,
    },
    {
        "name": "blockwart.get_object_access",
        "description": "List direct grants and effective object permissions.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "object_id": {"type": "string", "minLength": 1, "maxLength": 128},
            },
            "required": ["object_id"],
            "additionalProperties": False,
        },
        "annotations": READ_ONLY_ANNOTATIONS,
    },
    {
        "name": "blockwart.search_principals",
        "description": "Search active principals through the minimized access-management view.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "object_id": {"type": "string", "minLength": 1, "maxLength": 128},
                "query": {"type": "string", "minLength": 2, "maxLength": 100},
                "limit": {"type": "integer", "minimum": 1, "maximum": 20, "default": 20},
            },
            "required": ["object_id", "query"],
            "additionalProperties": False,
        },
        "annotations": READ_ONLY_ANNOTATIONS,
    },
    {
        "name": "blockwart.list_admin_principals",
        "description": (
            "List users and agents for an explicit platform-admin principal; "
            "never returns credential values."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "maxLength": 100},
                "principal_type": {
                    "type": "string",
                    "enum": ["human", "service_account"],
                },
                "active": {"type": "boolean"},
                "limit": {"type": "integer", "minimum": 1, "maximum": 200, "default": 100},
                "cursor": {"type": "string", "maxLength": 2048},
            },
            "additionalProperties": False,
        },
        "annotations": READ_ONLY_ANNOTATIONS,
    },
    {
        "name": "blockwart.get_admin_principal",
        "description": (
            "Get one admin-authorized principal and only its actor-manageable "
            "object assignments; never returns secrets."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "principal_id": {"type": "string", "minLength": 1, "maxLength": 36},
            },
            "required": ["principal_id"],
            "additionalProperties": False,
        },
        "annotations": READ_ONLY_ANNOTATIONS,
    },
    {
        "name": "blockwart.preview_grant_scope",
        "description": "Preview the current canonical placement coverage of a grant scope.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "object_id": {"type": "string", "minLength": 1, "maxLength": 128},
                "scope": GRANT_SCOPE_SCHEMA,
            },
            "required": ["object_id", "scope"],
            "additionalProperties": False,
        },
        "annotations": READ_ONLY_ANNOTATIONS,
    },
    {
        "name": "blockwart.create_grant",
        "description": "Create one authorized direct object grant using the current ETag.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "object_id": {"type": "string", "minLength": 1, "maxLength": 128},
                "principal_id": {"type": "string", "minLength": 1, "maxLength": 36},
                "role": GRANT_ROLE_SCHEMA,
                "scope": GRANT_SCOPE_SCHEMA,
                "if_match": ETAG_SCHEMA,
            },
            "required": ["object_id", "principal_id", "role", "scope", "if_match"],
            "additionalProperties": False,
        },
        "annotations": WRITE_ANNOTATIONS,
    },
    {
        "name": "blockwart.update_grant",
        "description": "Change one direct grant role and scope using the current ETag.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "object_id": {"type": "string", "minLength": 1, "maxLength": 128},
                "grant_id": {"type": "integer", "minimum": 1},
                "role": GRANT_ROLE_SCHEMA,
                "scope": GRANT_SCOPE_SCHEMA,
                "if_match": ETAG_SCHEMA,
            },
            "required": ["object_id", "grant_id", "role", "scope", "if_match"],
            "additionalProperties": False,
        },
        "annotations": WRITE_ANNOTATIONS,
    },
    {
        "name": "blockwart.revoke_grant",
        "description": "Revoke one direct grant using the current ETag and owner guards.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "object_id": {"type": "string", "minLength": 1, "maxLength": 128},
                "grant_id": {"type": "integer", "minimum": 1},
                "if_match": ETAG_SCHEMA,
            },
            "required": ["object_id", "grant_id", "if_match"],
            "additionalProperties": False,
        },
        "annotations": DELETE_ANNOTATIONS,
    },
]
TOOL_DEFINITIONS: dict[str, JSON] = {tool["name"]: tool for tool in TOOLS}


def _compile_input_validator(schema: JSON) -> Validator:
    validator_class = validator_for(schema)
    validator_class.check_schema(schema)
    return validator_class(schema)


TOOL_INPUT_VALIDATORS: dict[str, Validator] = {
    name: _compile_input_validator(tool["inputSchema"]) for name, tool in TOOL_DEFINITIONS.items()
}


def call_tool(
    name: str,
    arguments: JSON | None,
    *,
    base_url: str | None = None,
    fetcher: Fetcher | None = None,
    requester: Requester | None = None,
    correlation_id: str | None = None,
) -> JSON:
    if name not in TOOL_DEFINITIONS:
        raise UnknownToolError(f"Unknown tool: {name}")

    args = {} if arguments is None else arguments
    try:
        TOOL_INPUT_VALIDATORS[name].validate(args)
    except ValidationError as exc:
        raise ToolInputError("Tool arguments are invalid") from exc

    request_id = _safe_correlation_id(correlation_id)
    fetch = fetcher or (
        lambda path, params: fetch_json(
            path,
            params,
            base_url=base_url,
            correlation_id=request_id,
        )
    )
    upstream_request = requester or (
        lambda method, path, body, headers: request_json(
            method,
            path,
            body,
            headers,
            base_url=base_url,
            correlation_id=request_id,
        )
    )

    def request(method: str, path: str, body: JSON, headers: dict[str, str]) -> JSON:
        return upstream_request(
            method,
            path,
            body,
            {**headers, "X-Correlation-ID": request_id},
        )

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
    elif name == "blockwart.create_child":
        parent_id = _required_string(args, "parent_id")
        payload = request(
            "POST",
            f"/api/v1/objects/{quote(parent_id, safe='')}/children",
            _required_object(args, "object"),
            {
                "Idempotency-Key": _required_string(args, "idempotency_key"),
                "X-Blockwart-Channel": "mcp",
            },
        )
    elif name == "blockwart.update_object":
        object_id = _required_string(args, "object_id")
        payload = request(
            "PUT",
            f"/api/v1/objects/{quote(object_id, safe='')}",
            _required_object(args, "object"),
            {
                "If-Match": _required_string(args, "if_match"),
                "X-Blockwart-Channel": "mcp",
            },
        )
    elif name == "blockwart.delete_object":
        object_id = _required_string(args, "object_id")
        payload = request(
            "DELETE",
            f"/api/v1/objects/{quote(object_id, safe='')}",
            {},
            {
                "If-Match": _required_string(args, "if_match"),
                "X-Blockwart-Channel": "mcp",
            },
        )
    elif name in {
        "blockwart.create_relationship",
        "blockwart.delete_relationship",
    }:
        object_id = _required_string(args, "object_id")
        body: JSON = {
            "from_ref": _required_string(args, "from_ref"),
            "relation_type": _required_string(args, "relation_type"),
            "to_ref": _required_string(args, "to_ref"),
        }
        metadata = args.get("metadata")
        if metadata:
            body["metadata"] = metadata
        payload = request(
            "POST" if name == "blockwart.create_relationship" else "DELETE",
            f"/api/v1/objects/{quote(object_id, safe='')}/relationships",
            body,
            {
                "If-Match": _required_string(args, "if_match"),
                "X-Blockwart-Channel": "mcp",
            },
        )
    elif name == "blockwart.create_attached_device":
        parent_id = _required_string(args, "parent_id")
        body = {
            "device": _required_object(args, "device"),
        }
        metadata = args.get("metadata")
        if metadata:
            body["metadata"] = metadata
        payload = request(
            "POST",
            f"/api/v1/objects/{quote(parent_id, safe='')}/attached-devices",
            body,
            {
                "Idempotency-Key": _required_string(args, "idempotency_key"),
                "X-Blockwart-Channel": "mcp",
            },
        )
    elif name == "blockwart.get_device_graph":
        object_id = _required_string(args, "object_id")
        payload = fetch(
            f"/api/v1/objects/{quote(object_id, safe='')}/device-graph",
            {},
        )
    elif name == "blockwart.get_network_topology":
        object_id = _required_string(args, "object_id")
        payload = fetch(
            f"/api/v1/objects/{quote(object_id, safe='')}/network-topology",
            {},
        )
    elif name == "blockwart.get_object_access":
        object_id = _required_string(args, "object_id")
        payload = fetch(
            f"/api/v1/objects/{quote(object_id, safe='')}/access",
            {},
        )
    elif name == "blockwart.search_principals":
        object_id = _required_string(args, "object_id")
        payload = fetch(
            f"/api/v1/objects/{quote(object_id, safe='')}/access/principals",
            {
                "q": _required_string(args, "query"),
                "limit": args.get("limit", 20),
            },
        )
    elif name == "blockwart.list_admin_principals":
        payload = fetch(
            "/api/v1/admin/principals",
            {
                "q": args.get("query"),
                "principal_type": args.get("principal_type"),
                "active": args.get("active"),
                "limit": args.get("limit", 100),
                "cursor": args.get("cursor"),
            },
        )
    elif name == "blockwart.get_admin_principal":
        principal_id = _required_string(args, "principal_id")
        payload = fetch(
            f"/api/v1/admin/principals/{quote(principal_id, safe='')}",
            {},
        )
    elif name == "blockwart.preview_grant_scope":
        object_id = _required_string(args, "object_id")
        payload = fetch(
            f"/api/v1/objects/{quote(object_id, safe='')}/access/preview",
            {"scope": _required_string(args, "scope")},
        )
    elif name == "blockwart.create_grant":
        object_id = _required_string(args, "object_id")
        payload = request(
            "POST",
            f"/api/v1/objects/{quote(object_id, safe='')}/access/grants",
            {
                "principal_id": _required_string(args, "principal_id"),
                "role": _required_string(args, "role"),
                "scope": _required_string(args, "scope"),
            },
            {
                "If-Match": _required_string(args, "if_match"),
                "X-Blockwart-Channel": "mcp",
            },
        )
    elif name == "blockwart.update_grant":
        object_id = _required_string(args, "object_id")
        payload = request(
            "PUT",
            (
                f"/api/v1/objects/{quote(object_id, safe='')}/access/grants/"
                f"{_required_integer(args, 'grant_id')}"
            ),
            {
                "role": _required_string(args, "role"),
                "scope": _required_string(args, "scope"),
            },
            {
                "If-Match": _required_string(args, "if_match"),
                "X-Blockwart-Channel": "mcp",
            },
        )
    elif name == "blockwart.revoke_grant":
        object_id = _required_string(args, "object_id")
        payload = request(
            "DELETE",
            (
                f"/api/v1/objects/{quote(object_id, safe='')}/access/grants/"
                f"{_required_integer(args, 'grant_id')}"
            ),
            {},
            {
                "If-Match": _required_string(args, "if_match"),
                "X-Blockwart-Channel": "mcp",
            },
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


def fetch_json(
    path: str,
    params: JSON,
    *,
    base_url: str | None = None,
    correlation_id: str | None = None,
) -> JSON:
    root = (base_url or os.environ.get("BLOCKWART_API_BASE_URL") or DEFAULT_BASE_URL).rstrip("/")
    query = urlencode({key: value for key, value in params.items() if value is not None})
    url = f"{root}{path}"
    if query:
        url = f"{url}?{query}"
    return _http_json(
        "GET",
        url,
        body=None,
        headers={},
        base_url=base_url,
        correlation_id=correlation_id,
    )


def request_json(
    method: str,
    path: str,
    body: JSON,
    headers: dict[str, str],
    *,
    base_url: str | None = None,
    correlation_id: str | None = None,
) -> JSON:
    if method not in {"POST", "PUT", "DELETE"}:
        raise ValueError("unsupported MCP upstream method")
    root = (base_url or os.environ.get("BLOCKWART_API_BASE_URL") or DEFAULT_BASE_URL).rstrip("/")
    url = f"{root}{path}"
    return _http_json(
        method,
        url,
        body=body,
        headers=headers,
        base_url=base_url,
        correlation_id=correlation_id,
    )


def _http_json(
    method: str,
    url: str,
    *,
    body: JSON | None,
    headers: dict[str, str],
    base_url: str | None,
    correlation_id: str | None = None,
) -> JSON:
    del base_url
    request_headers = dict(headers)
    request_headers["X-Correlation-ID"] = _safe_correlation_id(
        request_headers.get("X-Correlation-ID") or correlation_id
    )
    request_headers["X-Blockwart-Channel"] = "mcp"
    api_token = _api_token()
    if api_token is not None:
        _require_safe_token_transport(url)
        request_headers["Authorization"] = f"Bearer {api_token}"
    encoded_body = None
    if body is not None:
        encoded_body = json.dumps(
            body,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        request_headers["Content-Type"] = "application/json"
    request = Request(
        url,
        data=encoded_body,
        headers=request_headers,
        method=method,
    )
    try:
        with build_opener(_RejectRedirectHandler()).open(request, timeout=10) as response:
            try:
                return json.loads(response.read().decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise UpstreamError(
                    "upstream_invalid_response",
                    "Blockwart Agent API returned an invalid response.",
                ) from exc
    except HTTPError as exc:
        translated = _translate_http_error(exc)
        raise UpstreamError(
            translated.code,
            translated.public_message,
            request_headers["X-Correlation-ID"],
        ) from exc
    except URLError as exc:
        raise UpstreamError(
            "upstream_unavailable",
            "Blockwart Agent API is unavailable.",
        ) from exc


def _require_safe_token_transport(url: str) -> None:
    parsed = urlsplit(url)
    hostname = parsed.hostname
    if parsed.scheme == "https":
        return
    if parsed.scheme == "http" and hostname is not None and _is_loopback_host(hostname):
        return
    raise UpstreamError(
        "credential_configuration_error",
        "Blockwart MCP bearer credentials require HTTPS outside loopback.",
    )


def _is_loopback_host(hostname: str) -> bool:
    normalized = hostname.rstrip(".").casefold()
    if normalized == "localhost" or normalized.endswith(".localhost"):
        return True
    try:
        return ipaddress.ip_address(normalized).is_loopback
    except ValueError:
        return False


def _api_token() -> str | None:
    inline_token = os.environ.get(API_TOKEN_ENV)
    token_file = os.environ.get(API_TOKEN_FILE_ENV)
    if inline_token and token_file:
        raise UpstreamError(
            "credential_configuration_error",
            "Blockwart MCP credential configuration is ambiguous.",
        )
    if token_file:
        try:
            with Path(token_file).open(encoding="utf-8") as credential_file:
                raw_value = credential_file.read(514)
        except (OSError, UnicodeError) as exc:
            raise UpstreamError(
                "credential_configuration_error",
                "Blockwart MCP credential file is unavailable.",
            ) from exc
        if len(raw_value) > 513:
            raise UpstreamError(
                "credential_configuration_error",
                "Blockwart MCP credential is invalid.",
            )
        value = raw_value.strip()
    else:
        value = (inline_token or "").strip()
    if not value:
        return None
    if len(value) > 512 or any(character in value for character in "\r\n"):
        raise UpstreamError(
            "credential_configuration_error",
            "Blockwart MCP credential is invalid.",
        )
    return value


server = Server(SERVER_NAME, version=SERVER_VERSION)


@server.list_tools()
async def list_tools() -> list[types.Tool]:
    return [types.Tool.model_validate(tool) for tool in TOOLS]


# The SDK's validation response bypasses Blockwart's stable error envelope, so
# call_tool validates the exact published schemas before any upstream request.
@server.call_tool(validate_input=False)
async def handle_call_tool(name: str, arguments: JSON) -> types.CallToolResult:
    correlation_id = _safe_correlation_id(None)
    try:
        result = await asyncio.to_thread(
            call_tool,
            name,
            arguments,
            correlation_id=correlation_id,
        )
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
        logger.error(
            "mcp_tool_failure operation=%s code=internal_error channel=mcp correlation_id=%s",
            name if name in TOOL_DEFINITIONS else "unknown",
            correlation_id,
        )
        return _tool_error_result(
            "internal_error",
            "Blockwart tool execution failed.",
            correlation_id=correlation_id,
        )


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
        "source_type",
        "stale",
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
            "source_type",
            "stale",
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


def _required_object(args: JSON, key: str) -> JSON:
    value = args.get(key)
    if not isinstance(value, dict):
        raise ToolInputError(f"{key} is required")
    return value


def _required_integer(args: JSON, key: str) -> int:
    value = args.get(key)
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
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


def _safe_correlation_id(value: str | None) -> str:
    if value is not None and _CORRELATION_ID_PATTERN.fullmatch(value):
        return value
    return str(uuid4())


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
