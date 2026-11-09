from __future__ import annotations

import copy
import json
from pathlib import Path

from blockwart.mcp import server
from blockwart.mcp.manifest import (
    canonical_manifest_bytes,
    contract_metadata,
    diagnose_contract,
    runtime_catalog_evidence,
)
from blockwart.mcp.server import TOOLS, local_contract_metadata, validate_runtime_catalog


def test_integrated_mcp_contract_has_reviewed_manifest_evidence() -> None:
    metadata = contract_metadata(TOOLS, build_revision="issue-188-236-245-248-249-250-251")

    # Reviewed #333: only the three projection argument descriptions now explain
    # full Project Instructions. The delta test below restores the pre-#333 digest.
    # Tool count, input shapes, annotations and contract version remain unchanged.
    assert metadata == {
        "build_revision": "issue-188-236-245-248-249-250-251",
        "contract_version": "1",
        "manifest_digest": "3d30cc14192c9369d1d0ac12ef4c796ebc3d35d104d2c6a5ae24a4a0dcd8802a",
        "tool_count": 48,
    }


def test_project_instruction_manifest_delta_is_only_three_projection_descriptions() -> None:
    """Reversing the reviewed description change restores the pre-#333 digest."""
    # Each tool gets its own copy: registration reuses the projection dict.
    previous = [copy.deepcopy(tool) for tool in TOOLS]
    changed = set()
    old_description = (
        "Closed server-defined read profile. compact keeps identity, state, and the "
        "type-aware short fields; context adds network, integrity, monitoring, and "
        "the detail document; full is the unchanged complete contract."
    )
    new_description = old_description.replace(
        "type-aware short fields",
        "type-aware knowledge fields including full Project Instructions",
    )
    for tool in previous:
        projection = tool["inputSchema"].get("properties", {}).get("projection")
        if projection is not None:
            assert projection["description"] == new_description
            projection["description"] = old_description
            changed.add(tool["name"])
    assert changed == {
        "blockwart.search",
        "blockwart.get_context",
        "blockwart.get_object_contexts",
    }
    # Generated independently from base 1574db2: no schema, permission,
    # annotation, tool-count or unrelated description delta may hide here.
    assert contract_metadata(previous, build_revision="base")["manifest_digest"] == (
        "69cf6585eb7f3e2cf71ec38ef2ee6abf2d706df8f1b175687452fc8f2402d8a0"
    )


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
    reduced = contract_metadata(TOOLS[:22], build_revision="same-build")

    diagnosis = diagnose_contract(local, api=reduced)

    assert local["tool_count"] == 48
    assert reduced["tool_count"] == 22
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
    stale_tools = copy.deepcopy(TOOLS[:22])
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


def test_doctor_reports_wrapper_drift_against_divergent_api(monkeypatch) -> None:
    local = contract_metadata(TOOLS, build_revision="same-build")
    monkeypatch.setattr(
        server,
        "fetch_json",
        lambda path, params: {**local, "build_revision": "old-api-build"},
    )

    diagnosis = server.doctor_contract()

    assert diagnosis["status"] == "incompatible"
    assert diagnosis["classification"] == "wrapper_drift"
    assert diagnosis["api_status"] == "incompatible"


def test_doctor_reports_unknown_when_api_metadata_is_unreachable(monkeypatch) -> None:
    def unreachable(path, params):
        raise server.UpstreamError(
            "upstream_http_error",
            "Blockwart Agent API returned an error.",
        )

    monkeypatch.setattr(server, "fetch_json", unreachable)

    diagnosis = server.doctor_contract()

    assert diagnosis["status"] == "unknown"
    assert diagnosis["classification"] == "unknown"


def test_doctor_separates_stale_runtime_catalog_from_wrapper_drift(
    monkeypatch,
    tmp_path: Path,
) -> None:
    """A matching API with a reduced materialized list is not wrapper drift."""
    monkeypatch.setattr(
        server, "fetch_json", lambda path, params: dict(server.local_contract_metadata())
    )
    # Same drift shape as the 2026-08-13 production find: deliberately fewer
    # materialized tools than the API contract publishes.
    catalog_path = tmp_path / "materialized-tools.json"
    catalog_path.write_text(json.dumps({"tools": copy.deepcopy(TOOLS[:-9])}))

    diagnosis = server.doctor_contract(runtime_catalog_path=str(catalog_path))

    assert diagnosis["api_status"] == "compatible"
    assert diagnosis["runtime_catalog_status"] == "incompatible"
    assert diagnosis["status"] == "incompatible"
    assert diagnosis["classification"] == "stale_runtime_catalog"
