from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path
from shutil import copytree

import jsonschema
import pytest

from blockwart.cli import knowledge_plan as knowledge_cli
from blockwart.services.knowledge_planning import (
    DISPOSITIONS,
    KnowledgePlanError,
    build_knowledge_plan,
    canonical_json_bytes,
    load_manifest,
    load_target_snapshot,
    manifest_json_schema,
    result_json_schema,
    target_snapshot_digest,
    target_snapshot_json_schema,
)

EXAMPLE_ROOT = Path(__file__).resolve().parents[1] / "examples" / "knowledge-plan"
MANIFEST_PATH = EXAMPLE_ROOT / "manifest.json"
SOURCE_ROOT = EXAMPLE_ROOT / "sources"
TARGET_PATH = EXAMPLE_ROOT / "target-snapshot.json"
COMMIT = "1" * 40
TREE = "2" * 40


def _manifest():
    return load_manifest(MANIFEST_PATH)


def _target():
    return load_target_snapshot(TARGET_PATH)


def _plan(*, target=True):
    return build_knowledge_plan(
        _manifest(),
        source_root=SOURCE_ROOT,
        implementation_commit=COMMIT,
        implementation_tree=TREE,
        target_snapshot=_target() if target else None,
    )


def _write_json(path: Path, payload: object) -> None:
    path.write_bytes(canonical_json_bytes(payload) + b"\n")


def test_source_only_plan_is_complete_deterministic_and_not_apply_ready() -> None:
    first = _plan(target=False)
    second = _plan(target=False)

    assert canonical_json_bytes(first) == canonical_json_bytes(second)
    assert first["mode"] == "dry-run"
    assert first["mutation_capabilities"] == []
    assert first["apply_ready"] is False
    assert first["plan_digest"] is None
    assert len(first["classification_digest"]) == 64
    assert first["summary"]["source_count"] == 2
    assert first["summary"]["entry_count"] == 2
    assert first["summary"]["comment_delta"] == 0
    assert first["summary"]["audit_delta"] == 0
    assert first["blockers"] == [{"code": "missing_target_snapshot"}]
    assert first["summary"]["disposition_counts"] == {
        disposition: int(disposition in {"asset_fact", "runbook"}) for disposition in DISPOSITIONS
    }


def test_complete_target_snapshot_produces_bound_plan_digest() -> None:
    result = _plan()

    assert result["apply_ready"] is True
    assert len(result["plan_digest"]) == 64
    assert result["target_snapshot_digest"] == _target().snapshot_digest
    assert result["summary"]["new_count"] == 1
    assert result["summary"]["update_count"] == 1
    assert result["summary"]["unchanged_count"] == 0
    assert result["summary"]["relationship_deltas"] == {
        "new": 1,
        "removed": 0,
        "unchanged": 0,
    }
    assert result["blockers"] == []


def test_input_enumeration_order_does_not_change_output_or_digests(tmp_path: Path) -> None:
    manifest_payload = json.loads(MANIFEST_PATH.read_text())
    manifest_payload["entries"].reverse()
    manifest_payload["source_snapshot"]["documents"].reverse()
    for entry in manifest_payload["entries"]:
        entry["field_mappings"].reverse()
        entry["relations"].reverse()
    manifest_path = tmp_path / "manifest.json"
    _write_json(manifest_path, manifest_payload)

    target_payload = json.loads(TARGET_PATH.read_text())
    target_payload["objects"].reverse()
    target_payload["relationships"].reverse()
    target_payload["snapshot_digest"] = target_snapshot_digest(target_payload)
    target_path = tmp_path / "target.json"
    _write_json(target_path, target_payload)

    reordered = build_knowledge_plan(
        load_manifest(manifest_path),
        source_root=SOURCE_ROOT,
        implementation_commit=COMMIT,
        implementation_tree=TREE,
        target_snapshot=load_target_snapshot(target_path),
    )
    original = _plan()
    assert canonical_json_bytes(reordered) == canonical_json_bytes(original)
    assert reordered["classification_digest"] == original["classification_digest"]
    assert reordered["plan_digest"] == original["plan_digest"]


def test_schemas_validate_synthetic_inputs_and_output() -> None:
    manifest_payload = json.loads(MANIFEST_PATH.read_text())
    target_payload = json.loads(TARGET_PATH.read_text())
    jsonschema.Draft202012Validator.check_schema(manifest_json_schema())
    jsonschema.Draft202012Validator.check_schema(target_snapshot_json_schema())
    jsonschema.Draft202012Validator.check_schema(result_json_schema())
    jsonschema.validate(manifest_payload, manifest_json_schema())
    jsonschema.validate(target_payload, target_snapshot_json_schema())
    jsonschema.validate(_plan(), result_json_schema())


@pytest.mark.parametrize(
    ("mutation", "code"),
    [
        (lambda data: data.update({"unknown": True}), "invalid_manifest"),
        (
            lambda data: data["entries"][0].update({"disposition": "comment_candidate"}),
            "invalid_manifest",
        ),
        (
            lambda data: data["source_snapshot"].update({"expected_entry_count": 1}),
            "invalid_manifest",
        ),
        (
            lambda data: data["entries"][0]["field_mappings"][0].update(
                {"value": {"token": "never-store-this"}}
            ),
            "unsafe_manifest",
        ),
    ],
)
def test_malformed_unknown_partial_and_unsafe_manifests_fail_closed(
    tmp_path: Path,
    mutation,
    code: str,
) -> None:
    payload = json.loads(MANIFEST_PATH.read_text())
    mutation(payload)
    path = tmp_path / "invalid.json"
    _write_json(path, payload)
    with pytest.raises(KnowledgePlanError, match=code):
        load_manifest(path)


def test_duplicate_json_keys_are_rejected(tmp_path: Path) -> None:
    path = tmp_path / "duplicate.json"
    path.write_text('{"schema_version":1,"schema_version":1}', encoding="utf-8")
    with pytest.raises(KnowledgePlanError, match="invalid_manifest"):
        load_manifest(path)


def test_duplicate_yaml_keys_are_rejected(tmp_path: Path) -> None:
    path = tmp_path / "duplicate.yaml"
    path.write_text("schema_version: 1\nschema_version: 1\n", encoding="utf-8")
    with pytest.raises(KnowledgePlanError, match="invalid_manifest"):
        load_manifest(path)


def test_conflicting_target_field_mappings_are_rejected(tmp_path: Path) -> None:
    payload = json.loads(MANIFEST_PATH.read_text())
    duplicate = deepcopy(payload["entries"][0])
    duplicate["entry_id"] = "synthetic-tools-row-02"
    duplicate["field_mappings"][0]["value"][0]["version"] = "2.0"
    payload["entries"].append(duplicate)
    payload["source_snapshot"]["documents"][0]["entry_ids"].append("synthetic-tools-row-02")
    payload["source_snapshot"]["expected_entry_count"] = 3
    path = tmp_path / "conflict.json"
    _write_json(path, payload)
    with pytest.raises(KnowledgePlanError, match="invalid_manifest"):
        load_manifest(path)


def test_source_byte_and_source_set_drift_fail_before_planning(tmp_path: Path) -> None:
    source_root = tmp_path / "sources"
    copytree(SOURCE_ROOT, source_root)
    (source_root / "TOOLS.md").write_text("changed", encoding="utf-8")
    with pytest.raises(KnowledgePlanError, match="source_drift"):
        build_knowledge_plan(
            _manifest(),
            source_root=source_root,
            implementation_commit=COMMIT,
            implementation_tree=TREE,
        )

    copytree(SOURCE_ROOT, source_root, dirs_exist_ok=True)
    (source_root / "references" / "EXTRA.md").write_text("synthetic", encoding="utf-8")
    with pytest.raises(KnowledgePlanError, match="source_set_drift"):
        build_knowledge_plan(
            _manifest(),
            source_root=source_root,
            implementation_commit=COMMIT,
            implementation_tree=TREE,
        )


def test_implementation_and_target_snapshot_drift_fail_closed(tmp_path: Path) -> None:
    with pytest.raises(KnowledgePlanError, match="implementation_drift"):
        build_knowledge_plan(
            _manifest(),
            source_root=SOURCE_ROOT,
            implementation_commit="3" * 40,
            implementation_tree=TREE,
        )

    payload = json.loads(TARGET_PATH.read_text())
    payload["objects"][0]["revision"] += 1
    path = tmp_path / "drifted-target.json"
    _write_json(path, payload)
    with pytest.raises(KnowledgePlanError, match="target_snapshot_drift"):
        load_target_snapshot(path)


def test_incomplete_target_evidence_never_produces_plan_digest(tmp_path: Path) -> None:
    payload = json.loads(TARGET_PATH.read_text())
    payload["relationships"] = []
    payload["snapshot_digest"] = target_snapshot_digest(payload)
    path = tmp_path / "partial-target.json"
    _write_json(path, payload)
    result = build_knowledge_plan(
        _manifest(),
        source_root=SOURCE_ROOT,
        implementation_commit=COMMIT,
        implementation_tree=TREE,
        target_snapshot=load_target_snapshot(path),
    )
    assert result["apply_ready"] is False
    assert result["plan_digest"] is None
    assert {item["code"] for item in result["blockers"]} == {"missing_target_evidence"}


def test_missing_typed_reference_is_a_blocker_not_an_inference(tmp_path: Path) -> None:
    manifest_payload = json.loads(MANIFEST_PATH.read_text())
    runbook = next(
        entry for entry in manifest_payload["entries"] if entry["disposition"] == "runbook"
    )
    applies_to = next(
        item for item in runbook["field_mappings"] if item["target_path"] == "data.applies_to"
    )
    applies_to["value"] = ["system:missing-runtime"]
    manifest_path = tmp_path / "manifest.json"
    _write_json(manifest_path, manifest_payload)
    result = build_knowledge_plan(
        load_manifest(manifest_path),
        source_root=SOURCE_ROOT,
        implementation_commit=COMMIT,
        implementation_tree=TREE,
        target_snapshot=_target(),
    )
    assert result["apply_ready"] is False
    assert "invalid_canonical_target" in {item["code"] for item in result["blockers"]}


def test_cli_emits_machine_json_summary_and_no_apply_surface(capsys) -> None:
    common = [
        "--manifest",
        str(MANIFEST_PATH),
        "--source-root",
        str(SOURCE_ROOT),
        "--implementation-commit",
        COMMIT,
        "--implementation-tree",
        TREE,
    ]
    assert knowledge_cli.main([*common, "--format", "json"]) == 0
    machine = json.loads(capsys.readouterr().out)
    assert machine["apply_ready"] is False
    assert machine["plan_digest"] is None

    assert knowledge_cli.main(common) == 0
    summary = capsys.readouterr().out
    assert "mode=dry-run" in summary
    assert "apply_ready=false" in summary
    assert "plan_digest_reason=missing_target_snapshot" in summary

    with pytest.raises(SystemExit):
        knowledge_cli.main(["--apply", *common])


def test_planner_source_has_no_network_database_subprocess_or_write_path() -> None:
    source = (
        Path(__file__).resolve().parents[1]
        / "src"
        / "blockwart"
        / "services"
        / "knowledge_planning.py"
    ).read_text(encoding="utf-8")
    for forbidden in (
        "import socket",
        "import subprocess",
        "import sqlalchemy",
        "requests.",
        "httpx.",
        ".write_text(",
        ".write_bytes(",
        'Path.open("w',
    ):
        assert forbidden not in source
