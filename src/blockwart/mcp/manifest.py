"""Deterministic, public MCP wrapper contract evidence.

This module deliberately contains no transport configuration.  In particular,
the manifest is a projection of registered tool definitions, not a record of a
running MCP client, an API endpoint, or a catalog.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Mapping
from typing import Any, Literal, cast

JSON = dict[str, Any]
Compatibility = Literal["compatible", "incompatible", "unknown"]

# Bump this deliberately when compatibility rules for this projection change.
MCP_CONTRACT_VERSION = "1"
_MANIFEST_FIELDS = ("name", "description", "inputSchema", "annotations")
_METADATA_FIELDS = ("build_revision", "contract_version", "manifest_digest", "tool_count")


def canonical_manifest(tools: Iterable[Mapping[str, Any]]) -> JSON:
    """Return the contract projection of the actual registered MCP tools.

    Tool registration order and dictionary insertion order do not affect the
    projection.  Runtime-only values such as timestamps are not part of the
    registered source and are never added here.
    """
    projected: list[JSON] = []
    names: set[str] = set()
    for tool in tools:
        name = tool.get("name")
        if not isinstance(name, str) or not name:
            raise ValueError("registered MCP tools require a non-empty name")
        if name in names:
            raise ValueError("registered MCP tool names must be unique")
        names.add(name)
        projected.append({field: tool[field] for field in _MANIFEST_FIELDS if field in tool})
    return {
        "contract_version": MCP_CONTRACT_VERSION,
        "tools": sorted(projected, key=lambda tool: cast(str, tool["name"])),
    }


def canonical_manifest_bytes(tools: Iterable[Mapping[str, Any]]) -> bytes:
    """Serialize the manifest once, with stable JSON bytes for hashing and review."""
    return json.dumps(
        canonical_manifest(tools),
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def manifest_digest(tools: Iterable[Mapping[str, Any]]) -> str:
    return hashlib.sha256(canonical_manifest_bytes(tools)).hexdigest()


def contract_metadata(
    tools: Iterable[Mapping[str, Any]],
    *,
    build_revision: str,
) -> JSON:
    materialized_tools = list(tools)
    return {
        "build_revision": build_revision,
        "contract_version": MCP_CONTRACT_VERSION,
        "manifest_digest": manifest_digest(materialized_tools),
        "tool_count": len(materialized_tools),
    }


def runtime_catalog_evidence(tools: Iterable[Mapping[str, Any]]) -> JSON:
    """Return only digest/count evidence for an externally materialized tool catalog."""
    materialized_tools = list(tools)
    return {
        "manifest_digest": manifest_digest(materialized_tools),
        "tool_count": len(materialized_tools),
    }


def diagnose_contract(
    local: Mapping[str, Any],
    *,
    api: Mapping[str, Any] | None = None,
    runtime_catalog: Mapping[str, Any] | None = None,
) -> JSON:
    """Diagnose wrapper/API/catalog agreement without emitting sensitive inputs.

    ``tool_count`` is evidence only.  Compatibility is decided exclusively by
    build revision, explicit contract version, and manifest digest.
    """
    local_metadata = _validated_metadata(local)
    if local_metadata is None:
        raise ValueError("local MCP contract metadata is invalid")
    api_metadata = _validated_metadata(api) if api is not None else None
    runtime_evidence = _validated_runtime_evidence(runtime_catalog)

    api_status: Compatibility = "unknown"
    if api is not None and api_metadata is not None:
        api_status = _metadata_status(local_metadata, api_metadata)

    runtime_status: Compatibility = "unknown"
    if runtime_catalog is not None and runtime_evidence is not None:
        runtime_status = (
            "compatible"
            if runtime_evidence["manifest_digest"] == local_metadata["manifest_digest"]
            else "incompatible"
        )

    if api_status == "incompatible":
        status: Compatibility = "incompatible"
        classification = "wrapper_drift"
    elif runtime_status == "incompatible":
        status = "incompatible"
        classification = "stale_runtime_catalog"
    elif api_status == "compatible" and runtime_status in {"compatible", "unknown"}:
        status = "compatible"
        classification = "compatible"
    else:
        status = "unknown"
        classification = "unknown"

    result: JSON = {
        "status": status,
        "classification": classification,
        "local": local_metadata,
        "api_status": api_status,
        "runtime_catalog_status": runtime_status,
    }
    if api_metadata is not None:
        result["api"] = api_metadata
    if runtime_evidence is not None:
        result["runtime_catalog"] = runtime_evidence
    return result


def _metadata_status(local: JSON, candidate: JSON) -> Compatibility:
    return (
        "compatible"
        if all(local[field] == candidate[field] for field in _METADATA_FIELDS[:-1])
        else "incompatible"
    )


def _validated_metadata(value: Mapping[str, Any] | None) -> JSON | None:
    if value is None:
        return None
    build_revision = value.get("build_revision")
    contract_version = value.get("contract_version")
    digest = value.get("manifest_digest")
    tool_count = value.get("tool_count")
    if (
        not isinstance(build_revision, str)
        or not build_revision
        or not isinstance(contract_version, str)
        or not contract_version
        or not isinstance(digest, str)
        or len(digest) != 64
        or any(character not in "0123456789abcdef" for character in digest)
        or isinstance(tool_count, bool)
        or not isinstance(tool_count, int)
        or tool_count < 0
    ):
        return None
    return {field: value[field] for field in _METADATA_FIELDS}


def _validated_runtime_evidence(value: Mapping[str, Any] | None) -> JSON | None:
    if value is None:
        return None
    digest = value.get("manifest_digest")
    tool_count = value.get("tool_count")
    if (
        not isinstance(digest, str)
        or len(digest) != 64
        or any(character not in "0123456789abcdef" for character in digest)
        or isinstance(tool_count, bool)
        or not isinstance(tool_count, int)
        or tool_count < 0
    ):
        return None
    return {"manifest_digest": digest, "tool_count": tool_count}
