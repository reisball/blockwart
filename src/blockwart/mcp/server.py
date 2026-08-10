from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import os
import re
from collections.abc import Callable
from pathlib import Path
from typing import Any, get_args
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

from blockwart.domain.asset_state import ASSET_KINDS
from blockwart.domain.object_schema import (
    GENERIC_SCHEMA_VIOLATION,
    VIOLATION_FIELD_NOT_ALLOWED,
    VIOLATION_INVALID_FORMAT,
    VIOLATION_REQUIRED_FIELD_MISSING,
    VIOLATION_TYPE_MISMATCH,
    VIOLATION_VALUE_NOT_ALLOWED,
    VIOLATION_VALUE_NOT_CONSTANT,
    VIOLATION_VALUE_OUT_OF_RANGE,
    VIOLATION_VALUE_TOO_LONG,
    VIOLATION_VALUE_TOO_SHORT,
)
from blockwart.domain.relationship_projection import (
    metadata_json_schema,
    metadata_union_json_schema,
    relation_type_json_schema,
    relationship_metadata_conditions,
    relationship_projection,
)
from blockwart.domain.relationships import RELATIONSHIP_PATH_ROOTS, RELATIONSHIP_RULES
from blockwart.domain.schema_projection import (
    minimal_object_example,
    object_schema_projection,
)
from blockwart.domain.validation_errors import (
    DATA_PATH_ROOT,
    order_public_details,
    public_detail,
    sanitize_public_details,
)
from blockwart.schemas.catalog import ObjectKind

ALL_OBJECT_KINDS: tuple[str, ...] = get_args(ObjectKind)
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
    def __init__(
        self,
        message: str,
        details: list[dict[str, str | None]] | None = None,
    ) -> None:
        super().__init__(message)
        self.details = details or []


class UnknownToolError(ToolInputError):
    pass


class UpstreamError(RuntimeError):
    def __init__(
        self,
        code: str,
        public_message: str,
        correlation_id: str | None = None,
        details: list[dict[str, str | None]] | None = None,
    ) -> None:
        super().__init__(public_message)
        self.code = code
        self.public_message = public_message
        self.correlation_id = correlation_id
        self.details = details or []


class _RejectRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, request, file_pointer, code, message, headers, new_url):
        return None


SCHEMA_TOOL_NAME = "blockwart.describe_schema"
READ_ONLY_ANNOTATIONS: JSON = {
    "readOnlyHint": True,
    "destructiveHint": False,
    "idempotentHint": True,
    "openWorldHint": True,
}
# The published schema contract is generated locally from the domain registry and
# reaches no external system.
CONTRACT_ANNOTATIONS: JSON = {
    "readOnlyHint": True,
    "destructiveHint": False,
    "idempotentHint": True,
    "openWorldHint": False,
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
OBJECT_DATA_DESCRIPTION = (
    "Kind-specific nested catalog data enforced by the canonical domain schema. "
    f"Call {SCHEMA_TOOL_NAME} for the required paths, enums, reference kinds, "
    "value bounds, normalization, forbidden secret keys, and one minimal valid "
    "example for this kind; a shallow or empty object is rejected for kinds with "
    "required nested paths."
)
ASSET_STATE_DESCRIPTION = (
    "Asset kinds only (" + ", ".join(sorted(ASSET_KINDS)) + "). Omit or send null "
    f"for knowledge kinds; see {SCHEMA_TOOL_NAME}."
)
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
            "enum": list(ALL_OBJECT_KINDS),
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
            "description": ASSET_STATE_DESCRIPTION,
        },
        "health": {
            "type": ["string", "null"],
            "enum": ["unknown", "healthy", "degraded", "down", "maintenance", None],
            "description": ASSET_STATE_DESCRIPTION,
        },
        "summary": {"type": ["string", "null"]},
        "data": {
            "type": "object",
            "default": {},
            "description": OBJECT_DATA_DESCRIPTION,
        },
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
# Every object write intent points at one canonical projection instead of
# carrying its own copy of the kind-specific data rules. The accepted kinds and
# parent kinds are derived from the same domain relationship registry the
# commands enforce.
_PLACEMENT_RULE = RELATIONSHIP_RULES["hosts"]
_ATTACHMENT_RULE = RELATIONSHIP_RULES["attached_to"]
CHILD_WRITE_KINDS: tuple[str, ...] = tuple(
    kind for kind in ALL_OBJECT_KINDS if kind in _PLACEMENT_RULE.to_kinds
)
ATTACHED_DEVICE_KINDS: tuple[str, ...] = ("device",)
WRITE_INTENT_TOOLS: tuple[str, ...] = (
    "blockwart.create_child",
    "blockwart.create_root",
    "blockwart.update_object",
    "blockwart.create_attached_device",
)
RELATIONSHIP_TOOLS: tuple[str, ...] = (
    "blockwart.create_relationship",
    "blockwart.delete_relationship",
)
# Tools whose rejected arguments are published as field-accurate details on the
# canonical violation contract.
FIELD_ACCURATE_TOOLS: tuple[str, ...] = (*WRITE_INTENT_TOOLS, *RELATIONSHIP_TOOLS)
# Tools whose arguments carry canonical relationship paths.
RELATIONSHIP_ARGUMENT_TOOLS: tuple[str, ...] = (
    *RELATIONSHIP_TOOLS,
    "blockwart.create_attached_device",
)
RELATIONSHIP_METADATA_DESCRIPTION = (
    "Type-dependent relationship metadata. Which fields are accepted follows "
    f"from relation_type; call {SCHEMA_TOOL_NAME} for the exact fields, enums, "
    "and bounds of each relationship type. A type without metadata fields "
    "accepts an empty object only."
)
# Both the accepted relationship vocabulary and the type-dependent metadata
# contract are generated from the domain relationship registry, so the
# published tool schema cannot carry a second, drifting copy of either.
RELATIONSHIP_PROPERTIES: JSON = {
    "object_id": {"type": "string", "minLength": 1, "maxLength": 128},
    "if_match": ETAG_SCHEMA,
    "from_ref": {"type": "string", "minLength": 3, "maxLength": 192},
    "relation_type": relation_type_json_schema(),
    "to_ref": {"type": "string", "minLength": 3, "maxLength": 192},
    "metadata": {
        **metadata_union_json_schema(),
        "default": {},
        "description": RELATIONSHIP_METADATA_DESCRIPTION,
    },
}
RELATIONSHIP_METADATA_CONDITIONS: list[JSON] = relationship_metadata_conditions()
ATTACHED_DEVICE_METADATA_SCHEMA: JSON = {
    **metadata_json_schema("attached_to"),
    "default": {},
    "description": (
        "Metadata of the created attached_to edge. It publishes exactly the "
        f"attached_to fields; see {SCHEMA_TOOL_NAME}."
    ),
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
        "enum": list(ALL_OBJECT_KINDS),
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
        "description": (
            "Find candidate Blockwart objects as compact summaries. Use get_context when "
            "the same call should search and return full authorized details."
        ),
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
        "description": (
            "Get full sanitized details for exactly one Blockwart object when its id is known, "
            "including its current strong ETag for unchanged use as if_match on write tools."
        ),
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
        "name": "blockwart.get_object_contexts",
        "description": (
            "Retrieve full sanitized contexts for up to 20 already-known Blockwart object ids in "
            "one bounded read-only roundtrip, preserving input order. Each readable item is "
            "field-equivalent to get_object_context including its write-ready strong ETag; "
            "discover-only items are strict stubs; concealed and missing ids are indistinguishable "
            "concealed placeholders. Use get_object_context for one id and get_context to search "
            "by attribute instead of by known id."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "object_ids": {
                    "type": "array",
                    "minItems": 1,
                    "maxItems": 20,
                    "items": {
                        "type": "string",
                        "pattern": "^[a-z0-9](?:[a-z0-9_-]*[a-z0-9])?$",
                    },
                    "description": "Known object ids, deduplicated by first occurrence",
                }
            },
            "required": ["object_ids"],
            "additionalProperties": False,
        },
        "annotations": READ_ONLY_ANNOTATIONS,
    },
    {
        "name": "blockwart.list_comments",
        "description": (
            "List the authorized append-only comment timeline for one known object. "
            "Returns immutable Markdown or legacy plain-text source, never rendered HTML."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "object_id": {"type": "string", "minLength": 1, "maxLength": 128},
                "limit": {"type": "integer", "minimum": 1, "maximum": 100, "default": 20},
                "cursor": {"type": "string", "maxLength": 2048},
                "include_total": {"type": "boolean", "default": False},
            },
            "required": ["object_id"],
            "additionalProperties": False,
        },
        "annotations": READ_ONLY_ANNOTATIONS,
    },
    {
        "name": "blockwart.list_audit_events",
        "description": (
            "List the immutable system audit timeline for one readable object in "
            "deterministic newest-first order. Operational comment content stays separate."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "object_id": {"type": "string", "minLength": 1, "maxLength": 128},
                "limit": {"type": "integer", "minimum": 1, "maximum": 100, "default": 50},
                "cursor": {"type": "string", "maxLength": 2048},
                "include_total": {"type": "boolean", "default": False},
            },
            "required": ["object_id"],
            "additionalProperties": False,
        },
        "annotations": READ_ONLY_ANNOTATIONS,
    },
    {
        "name": "blockwart.add_comment",
        "description": (
            "Append one Markdown comment to an authorized object. Requires an MCP-audience "
            "service token and an idempotency key; existing comments are never replaced."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "object_id": {"type": "string", "minLength": 1, "maxLength": 128},
                "body": {"type": "string", "minLength": 1, "maxLength": 4000},
                "idempotency_key": {
                    "type": "string",
                    "minLength": 16,
                    "maxLength": 128,
                    "pattern": "^[!-~]+$",
                },
            },
            "required": ["object_id", "body", "idempotency_key"],
            "additionalProperties": False,
        },
        "annotations": WRITE_ANNOTATIONS,
    },
    {
        "name": "blockwart.get_context",
        "description": (
            "Find objects by name, kind, parent, endpoint, state, or provenance and return "
            "their full sanitized details in one call, including current strong ETags. Reuse "
            "an ETag unchanged as if_match on write tools; use search for compact candidate "
            "lists."
        ),
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
        "name": SCHEMA_TOOL_NAME,
        "description": (
            "Describe the canonical Blockwart write contract: for every writable kind "
            "the required, optional, and forbidden nested data paths, types, enums, "
            "reference kinds, bounds, normalization, forbidden secret keys, "
            "lifecycle/health semantics, and one minimal valid example per write "
            "intent; and for every registered relationship type its directed endpoint "
            "kinds, endpoint predicates, type-dependent metadata fields, graph rules, "
            "revision/no-op semantics, and rejection catalog. Call it before "
            "create_child, create_root, update_object, create_attached_device, "
            "create_relationship, or delete_relationship; it reads no catalog data."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "kind": {
                    "type": "string",
                    "enum": list(ALL_OBJECT_KINDS),
                    "description": (
                        "Restrict the contract to exactly one object kind and the "
                        "relationship types that accept it as an endpoint"
                    ),
                },
            },
            "additionalProperties": False,
        },
        "annotations": CONTRACT_ANNOTATIONS,
    },
    {
        "name": "blockwart.create_child",
        "description": (
            "Create one authorized placement child in a single agent call. Returns the object, "
            "typed parent, exact hosts relationship, Owner/self assignment, revision, ETag, "
            f"and idempotency status. Build object.data from {SCHEMA_TOOL_NAME}."
        ),
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
        "name": "blockwart.create_root",
        "description": (
            "Create one disconnected top-level catalog root without a placement parent "
            "in a single agent call. Requires an already active catalog-owner principal "
            "with an MCP-audience service token and an idempotency key; it never assigns "
            "or removes any catalog role. Returns the object, Owner/self assignment, "
            f"revision, ETag, and idempotency status. Build object.data from {SCHEMA_TOOL_NAME}."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "idempotency_key": {
                    "type": "string",
                    "minLength": 16,
                    "maxLength": 128,
                    "pattern": "^[!-~]+$",
                },
                "object": OBJECT_WRITE_SCHEMA,
            },
            "required": ["idempotency_key", "object"],
            "additionalProperties": False,
        },
        "annotations": WRITE_ANNOTATIONS,
    },
    {
        "name": "blockwart.update_object",
        "description": (
            "Update one authorized object using its current strong ETag. Build "
            f"object.data from {SCHEMA_TOOL_NAME}."
        ),
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
        "description": (
            "Create or idempotently replace an authorized relationship between existing "
            "objects and return the exact relationship plus its new revision. Replaying "
            "the same canonical metadata is a no-op that reports changed = false. Call "
            f"{SCHEMA_TOOL_NAME} for the accepted relationship types, their directed "
            "endpoint kinds, endpoint predicates, and type-dependent metadata."
        ),
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
            "allOf": RELATIONSHIP_METADATA_CONDITIONS,
        },
        "annotations": WRITE_ANNOTATIONS,
    },
    {
        "name": "blockwart.delete_relationship",
        "description": (
            "Delete an authorized relationship from the current object revision. It "
            "matches the exact from_ref, relation_type, and to_ref triplet and never "
            f"depends on stored metadata. Call {SCHEMA_TOOL_NAME} for the accepted "
            "relationship types."
        ),
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
            "allOf": RELATIONSHIP_METADATA_CONDITIONS,
        },
        "annotations": DELETE_ANNOTATIONS,
    },
    {
        "name": "blockwart.create_attached_device",
        "description": (
            "Create a device and attach it to a parent endpoint in a single agent call. Returns "
            "the device, typed parent, exact attached_to relationship and metadata, Owner/self "
            "assignment, revision, ETag, and idempotency status. Build device.data from "
            f"{SCHEMA_TOOL_NAME}."
        ),
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
                "metadata": ATTACHED_DEVICE_METADATA_SCHEMA,
            },
            "required": ["parent_id", "idempotency_key", "device"],
            "additionalProperties": False,
        },
        "annotations": WRITE_ANNOTATIONS,
    },
    {
        "name": "blockwart.get_device_graph",
        "description": (
            "Return the authorized attached_to graph and relationship metadata for an object."
        ),
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
        "description": (
            "Return authorized direct or inherited network paths and link metadata for an object."
        ),
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


def describe_schema_payload(kind: str | None = None) -> JSON:
    """Project the canonical domain object and relationship registries for MCP clients.

    The payload is generated from `blockwart.domain.object_schema` and
    `blockwart.domain.relationships` on every call and contains no catalog data,
    credentials, or internal paths.
    """
    projection = object_schema_projection()
    if kind is not None:
        projection["kinds"] = [
            projected for projected in projection["kinds"] if projected["kind"] == kind
        ]
    return {
        **projection,
        "requested_kind": kind,
        "write_intents": _write_intents(kind),
        "relationships": relationship_projection(kind),
    }


def _write_intents(kind: str | None) -> list[JSON]:
    intents: list[JSON] = []
    for name, argument, kinds, arguments, relationship, parent_kinds in (
        (
            "blockwart.create_child",
            "object",
            CHILD_WRITE_KINDS,
            ("parent_id", "idempotency_key", "object"),
            _PLACEMENT_RULE.relation_type,
            sorted(_PLACEMENT_RULE.from_kinds),
        ),
        (
            "blockwart.create_root",
            "object",
            ALL_OBJECT_KINDS,
            ("idempotency_key", "object"),
            None,
            [],
        ),
        (
            "blockwart.update_object",
            "object",
            ALL_OBJECT_KINDS,
            ("object_id", "if_match", "object"),
            None,
            [],
        ),
        (
            "blockwart.create_attached_device",
            "device",
            ATTACHED_DEVICE_KINDS,
            ("parent_id", "idempotency_key", "device"),
            _ATTACHMENT_RULE.relation_type,
            sorted(_ATTACHMENT_RULE.to_kinds),
        ),
    ):
        supported = [supported_kind for supported_kind in kinds if kind in (None, supported_kind)]
        if not supported:
            continue
        intents.append(
            {
                "tool": name,
                "object_argument": argument,
                "kinds": supported,
                "required_arguments": list(arguments),
                "relation_type": relationship,
                "parent_kinds": parent_kinds,
                "example": _write_intent_example(name, argument, supported[0]),
            }
        )
    return intents


def _write_intent_example(name: str, argument: str, kind: str) -> JSON:
    example: JSON = {argument: minimal_object_example(kind)}
    idempotency_key = f"example-{name.split('.')[-1].replace('_', '-')}-0001"
    if name == "blockwart.update_object":
        return {
            "object_id": example[argument]["id"],
            "if_match": '"rev-1"',
            **example,
        }
    if name == "blockwart.create_root":
        return {"idempotency_key": idempotency_key, **example}
    parent_kind = "host" if name == "blockwart.create_child" else "system"
    intent_example: JSON = {
        "parent_id": f"example-{parent_kind}",
        "idempotency_key": idempotency_key,
        **example,
    }
    if name == "blockwart.create_attached_device":
        intent_example["metadata"] = {"link_kind": "ethernet"}
    return intent_example


WRITE_INTENT_OBJECT_ARGUMENTS: dict[str, str] = {
    intent["tool"]: intent["object_argument"] for intent in _write_intents(None)
}
# Published tool-argument keywords mapped onto the same domain violation
# catalog the API projects. An unmapped keyword stays generic instead of
# publishing an unreviewed code.
_ARGUMENT_VIOLATIONS: dict[str, str] = {
    "additionalProperties": VIOLATION_FIELD_NOT_ALLOWED,
    "const": VIOLATION_VALUE_NOT_CONSTANT,
    "enum": VIOLATION_VALUE_NOT_ALLOWED,
    "exclusiveMaximum": VIOLATION_VALUE_OUT_OF_RANGE,
    "exclusiveMinimum": VIOLATION_VALUE_OUT_OF_RANGE,
    "format": VIOLATION_INVALID_FORMAT,
    "maxItems": VIOLATION_VALUE_TOO_LONG,
    "maxLength": VIOLATION_VALUE_TOO_LONG,
    "maximum": VIOLATION_VALUE_OUT_OF_RANGE,
    "minItems": VIOLATION_VALUE_TOO_SHORT,
    "minLength": VIOLATION_VALUE_TOO_SHORT,
    "minimum": VIOLATION_VALUE_OUT_OF_RANGE,
    "multipleOf": VIOLATION_VALUE_OUT_OF_RANGE,
    "pattern": VIOLATION_INVALID_FORMAT,
    "required": VIOLATION_REQUIRED_FIELD_MISSING,
    "type": VIOLATION_TYPE_MISMATCH,
}


def _argument_details(name: str, arguments: JSON) -> list[dict[str, str | None]]:
    """Project rejected tool arguments onto the published violation contract.

    Only the argument location, the missing argument names declared by the
    published tool schema, and one violation code are projected. Rejected
    values and jsonschema messages are never copied.
    """
    details: list[dict[str, str | None]] = []
    for error in TOOL_INPUT_VALIDATORS[name].iter_errors(arguments):
        location = ".".join(str(part) for part in error.absolute_path)
        code = _ARGUMENT_VIOLATIONS.get(str(error.validator), GENERIC_SCHEMA_VIOLATION)
        rejected = [
            f"{location}.{argument}" if location else argument
            for argument in (*_missing_arguments(error), *_unexpected_arguments(error))
        ]
        for argument_location in rejected or [location]:
            details.append(
                public_detail(
                    location=argument_location,
                    code=code,
                    path=_canonical_argument_path(name, argument_location),
                )
            )
    return order_public_details(details)


def _missing_arguments(error: ValidationError) -> list[str]:
    """Return the schema-declared argument names missing from one instance."""
    if error.validator != "required" or not isinstance(error.validator_value, list):
        return []
    instance = error.instance if isinstance(error.instance, dict) else {}
    return [
        argument
        for argument in error.validator_value
        if isinstance(argument, str) and argument not in instance
    ]


def _unexpected_arguments(error: ValidationError) -> list[str]:
    """Return the argument names one instance carries beyond its published schema."""
    if error.validator != "additionalProperties" or error.validator_value is not False:
        return []
    instance = error.instance if isinstance(error.instance, dict) else {}
    published = error.schema.get("properties", {}) if isinstance(error.schema, dict) else {}
    return sorted(
        argument
        for argument in instance
        if isinstance(argument, str) and argument not in published
    )


def _canonical_argument_path(name: str, location: str) -> str | None:
    """Return the canonical catalog or relationship path an argument points at."""
    parts = location.split(".")
    if not parts or not parts[0]:
        return None
    if name in RELATIONSHIP_ARGUMENT_TOOLS and parts[0] in RELATIONSHIP_PATH_ROOTS:
        return location
    argument = WRITE_INTENT_OBJECT_ARGUMENTS.get(name)
    if argument is None or len(parts) < 2 or parts[0] != argument:
        return None
    if parts[1] != DATA_PATH_ROOT:
        return None
    return ".".join(parts[1:])


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
        # Object-write and relationship tools publish field-accurate argument
        # violations on the same contract the API projects. Read tools keep
        # their existing opaque invalid_arguments shape so the public contract
        # does not widen for tools outside this slice.
        raise ToolInputError(
            "Tool arguments are invalid",
            _argument_details(name, args) if name in FIELD_ACCURATE_TOOLS else [],
        ) from exc

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

    if name == SCHEMA_TOOL_NAME:
        # The published contract is generated locally: it reaches no upstream
        # API and therefore requires no credential.
        payload = describe_schema_payload(args.get("kind"))
    elif name == "blockwart.search":
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
    elif name == "blockwart.get_object_contexts":
        object_ids = _required_object_ids(args, "object_ids")
        payload = request(
            "POST",
            "/api/v1/object-contexts",
            {"object_ids": object_ids},
            {},
        )
    elif name == "blockwart.list_comments":
        object_id = _required_string(args, "object_id")
        payload = fetch(
            f"/api/v1/objects/{quote(object_id, safe='')}/comments",
            {
                "limit": args.get("limit", 20),
                "cursor": args.get("cursor"),
                "include_total": args.get("include_total", False),
            },
        )
    elif name == "blockwart.list_audit_events":
        object_id = _required_string(args, "object_id")
        payload = fetch(
            f"/api/v1/objects/{quote(object_id, safe='')}/audit-events",
            {
                "limit": args.get("limit", 50),
                "cursor": args.get("cursor"),
                "include_total": args.get("include_total", False),
            },
        )
    elif name == "blockwart.add_comment":
        object_id = _required_string(args, "object_id")
        payload = request(
            "POST",
            f"/api/v1/objects/{quote(object_id, safe='')}/comments",
            {"body": _required_string(args, "body")},
            {
                "Idempotency-Key": _required_string(args, "idempotency_key"),
                "X-Blockwart-Channel": "mcp",
            },
        )
    elif name == "blockwart.get_context":
        payload = _legacy_page_payload(
            fetch("/api/v1/context", _clean_params(args, default_limit=5)),
            args=args,
            items_field="objects",
        )
    elif name == "blockwart.create_child":
        parent_id = _required_string(args, "parent_id")
        requested_object = _required_object(args, "object")
        command_payload = request(
            "POST",
            f"/api/v1/objects/{quote(parent_id, safe='')}/children",
            requested_object,
            {
                "Idempotency-Key": _required_string(args, "idempotency_key"),
                "X-Blockwart-Channel": "mcp",
            },
        )
        parent = fetch(f"/api/v1/objects/{quote(parent_id, safe='')}", {})
        payload = _self_contained_create_payload(
            command_payload,
            parent=parent,
            requested_parent_id=parent_id,
            requested_object=requested_object,
            relation_type="hosts",
            parent_is_source=True,
        )
    elif name == "blockwart.create_root":
        requested_object = _required_object(args, "object")
        command_payload = request(
            "POST",
            "/api/v1/roots",
            requested_object,
            {
                "Idempotency-Key": _required_string(args, "idempotency_key"),
                "X-Blockwart-Channel": "mcp",
            },
        )
        payload = _self_contained_root_payload(
            command_payload,
            requested_object=requested_object,
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
        requested_device = _required_object(args, "device")
        body = {
            "device": requested_device,
        }
        metadata = args.get("metadata")
        if metadata:
            body["metadata"] = metadata
        command_payload = request(
            "POST",
            f"/api/v1/objects/{quote(parent_id, safe='')}/attached-devices",
            body,
            {
                "Idempotency-Key": _required_string(args, "idempotency_key"),
                "X-Blockwart-Channel": "mcp",
            },
        )
        parent = fetch(f"/api/v1/objects/{quote(parent_id, safe='')}", {})
        payload = _self_contained_create_payload(
            command_payload,
            parent=parent,
            requested_parent_id=parent_id,
            requested_object=requested_device,
            relation_type="attached_to",
            relationship_metadata=metadata,
            parent_is_source=False,
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
    except ToolInputError as exc:
        return _tool_error_result(
            "invalid_arguments",
            "Tool arguments are invalid.",
            details=exc.details,
        )
    except UpstreamError as exc:
        return _tool_error_result(
            exc.code,
            exc.public_message,
            correlation_id=exc.correlation_id,
            details=exc.details,
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


def _required_object_ids(args: JSON, key: str) -> list[str]:
    value = args.get(key)
    if not isinstance(value, list) or not value:
        raise ToolInputError(f"{key} is required")
    if len(value) > 20:
        raise ToolInputError(f"{key} must contain at most 20 ids")
    object_ids: list[str] = []
    for item in value:
        if not isinstance(item, str) or not item:
            raise ToolInputError(f"{key} must contain non-empty strings")
        object_ids.append(item)
    return object_ids


def _self_contained_create_payload(
    command_payload: JSON,
    *,
    parent: JSON,
    requested_parent_id: str,
    requested_object: JSON,
    relation_type: str,
    parent_is_source: bool,
    relationship_metadata: object | None = None,
) -> JSON:
    catalog_object = command_payload.get("catalog_object")
    if not isinstance(catalog_object, dict):
        raise _invalid_upstream_response()

    requested_id = requested_object.get("id")
    requested_kind = requested_object.get("kind")
    object_id = catalog_object.get("id")
    object_kind = catalog_object.get("kind")
    revision = catalog_object.get("revision")
    etag = command_payload.get("etag")
    if (
        not isinstance(requested_id, str)
        or not isinstance(requested_kind, str)
        or object_id != requested_id
        or object_kind != requested_kind
        or isinstance(revision, bool)
        or not isinstance(revision, int)
        or revision < 1
        or etag != f'"rev-{revision}"'
        or not isinstance(command_payload.get("changed"), bool)
        or not isinstance(command_payload.get("replayed"), bool)
    ):
        raise _invalid_upstream_response()

    parent_id = parent.get("id")
    parent_kind = parent.get("kind")
    parent_ref = parent.get("ref")
    if (
        not isinstance(parent_id, str)
        or parent_id != requested_parent_id
        or not isinstance(parent_kind, str)
        or parent_ref != f"{parent_kind}:{parent_id}"
    ):
        raise _invalid_upstream_response()

    metadata = {} if relationship_metadata is None else relationship_metadata
    if not isinstance(metadata, dict):
        raise _invalid_upstream_response()
    object_ref = f"{object_kind}:{object_id}"
    from_ref, to_ref = (parent_ref, object_ref) if parent_is_source else (object_ref, parent_ref)
    return {
        **command_payload,
        "parent_ref": parent_ref,
        "relationship": {
            "from_ref": from_ref,
            "relation_type": relation_type,
            "to_ref": to_ref,
            "metadata": metadata,
        },
        "owner_assignment": {
            "principal": "authenticated_caller",
            "role": "owner",
            "scope": "self",
        },
        "revision": revision,
    }


def _self_contained_root_payload(
    command_payload: JSON,
    *,
    requested_object: JSON,
) -> JSON:
    catalog_object = command_payload.get("catalog_object")
    if not isinstance(catalog_object, dict):
        raise _invalid_upstream_response()

    requested_id = requested_object.get("id")
    requested_kind = requested_object.get("kind")
    object_id = catalog_object.get("id")
    object_kind = catalog_object.get("kind")
    revision = catalog_object.get("revision")
    etag = command_payload.get("etag")
    if (
        not isinstance(requested_id, str)
        or not isinstance(requested_kind, str)
        or object_id != requested_id
        or object_kind != requested_kind
        or isinstance(revision, bool)
        or not isinstance(revision, int)
        or revision < 1
        or etag != f'"rev-{revision}"'
        or not isinstance(command_payload.get("changed"), bool)
        or not isinstance(command_payload.get("replayed"), bool)
        or catalog_object.get("parent_path") != []
    ):
        raise _invalid_upstream_response()

    return {
        **command_payload,
        "parent_ref": None,
        "owner_assignment": {
            "principal": "authenticated_caller",
            "role": "owner",
            "scope": "self",
        },
        "revision": revision,
    }


def _invalid_upstream_response() -> UpstreamError:
    return UpstreamError(
        "upstream_invalid_response",
        "Blockwart Agent API returned an invalid response.",
    )


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
            return UpstreamError(
                code,
                message,
                safe_correlation_id,
                details=_upstream_details(error),
            )
    return UpstreamError(
        "upstream_http_error",
        "Blockwart Agent API returned an error.",
    )


def _upstream_details(error: JSON) -> list[dict[str, str | None]]:
    """Re-derive publishable details from an untrusted upstream error body.

    Only a published violation code, a canonical path, and a published rule
    survive; the description is regenerated locally, so an upstream message,
    a rejected value, or any extra field is never forwarded. Anything that is
    not a known published violation is dropped, so a new or unknown upstream
    detail can never reach a client.
    """
    raw_details = error.get("details")
    return sanitize_public_details(raw_details)


def _safe_correlation_id(value: str | None) -> str:
    if value is not None and _CORRELATION_ID_PATTERN.fullmatch(value):
        return value
    return str(uuid4())


def _tool_error_result(
    code: str,
    message: str,
    *,
    correlation_id: str | None = None,
    details: list[dict[str, str | None]] | None = None,
) -> types.CallToolResult:
    error: dict[str, object] = {"code": code, "message": message}
    if correlation_id is not None:
        error["correlation_id"] = correlation_id
    if details:
        error["details"] = details
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
