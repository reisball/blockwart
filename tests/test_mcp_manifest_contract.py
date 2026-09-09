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


def test_rename_tools_have_the_reviewed_manifest_evidence() -> None:
    metadata = contract_metadata(TOOLS, build_revision="issue-233")

    assert metadata == {
        "build_revision": "issue-233",
        "contract_version": "1",
        "manifest_digest": "008dbad4f1727134e72ffa8fc5ba12a671dc23a553ad9428d18fa4731132949b",
        "tool_count": 33,
    }


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

    assert local["tool_count"] == 33
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
