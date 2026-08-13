from __future__ import annotations

import copy
import json
from pathlib import Path

from blockwart.mcp.manifest import (
    canonical_manifest_bytes,
    contract_metadata,
    diagnose_contract,
    runtime_catalog_evidence,
)
from blockwart.mcp.server import TOOLS, local_contract_metadata, validate_runtime_catalog


def test_manifest_bytes_and_digest_ignore_registered_tool_order() -> None:
    original = copy.deepcopy(TOOLS)
    reordered = [
        _reverse_mapping_order(tool) for tool in reversed(copy.deepcopy(TOOLS))
    ]

    assert canonical_manifest_bytes(original) == canonical_manifest_bytes(reordered)
    assert contract_metadata(original, build_revision="same-build") == contract_metadata(
        reordered,
        build_revision="same-build",
    )


def _reverse_mapping_order(value):
    if isinstance(value, dict):
        return {key: _reverse_mapping_order(value[key]) for key in reversed(value)}
    if isinstance(value, list):
        return [_reverse_mapping_order(item) for item in value]
    return value


def test_reduced_catalog_is_incompatible_before_normal_tool_use() -> None:
    local = contract_metadata(TOOLS, build_revision="same-build")
    reduced = contract_metadata(TOOLS[:21], build_revision="same-build")

    diagnosis = diagnose_contract(local, api=reduced)

    assert local["tool_count"] == 26
    assert reduced["tool_count"] == 21
    assert diagnosis["status"] == "incompatible"
    assert diagnosis["classification"] == "wrapper_drift"


def test_same_tool_count_with_a_different_schema_is_incompatible() -> None:
    changed = copy.deepcopy(TOOLS)
    changed[0]["inputSchema"]["properties"]["limit"]["maximum"] = 49
    local = contract_metadata(TOOLS, build_revision="same-build")
    other = contract_metadata(changed, build_revision="same-build")

    assert local["tool_count"] == other["tool_count"]
    assert local["manifest_digest"] != other["manifest_digest"]
    assert diagnose_contract(local, api=other)["status"] == "incompatible"


def test_contract_diagnostic_covers_compatible_incompatible_and_unknown() -> None:
    local = contract_metadata(TOOLS, build_revision="same-build")
    incompatible = {**local, "build_revision": "other-build"}

    assert diagnose_contract(local, api=local)["status"] == "compatible"
    assert diagnose_contract(local, api=incompatible)["status"] == "incompatible"
    assert diagnose_contract(local)["status"] == "unknown"


def test_api_and_wrapper_metadata_share_source_build_contract_and_digest() -> None:
    expected = contract_metadata(TOOLS, build_revision="source-build")

    assert local_contract_metadata(build_revision="source-build") == expected


def test_runtime_catalog_verifier_distinguishes_stale_catalog_without_leaking_it(
    tmp_path: Path,
) -> None:
    local = contract_metadata(TOOLS, build_revision="same-build")
    stale_tools = copy.deepcopy(TOOLS[:21])
    stale_tools[0]["private_runtime_value"] = "token-should-not-appear"
    runtime = runtime_catalog_evidence(stale_tools)
    catalog_path = tmp_path / "materialized-tools.json"
    catalog_path.write_text(json.dumps({"tools": stale_tools}))

    diagnosis = diagnose_contract(local, api=local, runtime_catalog=runtime)
    file_diagnosis = validate_runtime_catalog(str(catalog_path))

    assert diagnosis["status"] == "incompatible"
    assert diagnosis["classification"] == "stale_runtime_catalog"
    assert diagnosis["runtime_catalog_status"] == "incompatible"
    assert "token-should-not-appear" not in json.dumps(diagnosis)
    assert file_diagnosis["status"] == "incompatible"
    assert file_diagnosis["classification"] == "stale_runtime_catalog"
    assert "token-should-not-appear" not in json.dumps(file_diagnosis)
