from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator
from sqlalchemy import func, select

from blockwart.cli import source_coverage as source_coverage_cli
from blockwart.db.session import transaction
from blockwart.domain.auth import CatalogRole, PrincipalType
from blockwart.models import (
    AuditEvent,
    CatalogObject,
    ObjectComment,
    ObjectGrant,
    Principal,
    Relationship,
)
from blockwart.models.source_coverage import SourceEntry as SourceEntryRow
from blockwart.models.source_coverage import SourceEntryMapping
from blockwart.models.source_coverage import SourceSnapshot as SourceSnapshotRow
from blockwart.services.source_coverage import load_current_snapshot
from blockwart.services.source_coverage_manifest import (
    SourceCoverageManifestError,
    TargetEvidence,
    dry_run,
    load_manifest,
    record_manifest_snapshot,
    target_evidence_digest,
)

NOW = "2026-08-20T12:00:00Z"
LATER = "2026-08-20T13:00:00Z"


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _mapping(
    object_id: str,
    fingerprint: str,
    *,
    kind: str = "service",
    role: str = "primary",
) -> dict[str, object]:
    return {
        "object_id": object_id,
        "target_kind": kind,
        "role": role,
        "imported_entry_fingerprint": fingerprint,
        "imported_at": NOW,
        "verified_at": NOW,
    }


def _entry(
    entry_id: str,
    *,
    fingerprint: str | None = None,
    mappings: list[dict[str, object]] | None = None,
    classification: str = "operational",
    intent: str = "expect_object",
    reason: str = "operational_inventory",
    presence: str = "present",
) -> dict[str, object]:
    resolved_fingerprint = fingerprint or _sha(entry_id)
    return {
        "entry_id": entry_id,
        "classification": classification,
        "intent": intent,
        "decision_reason": reason,
        "presence": presence,
        "entry_fingerprint": resolved_fingerprint,
        "mappings": (
            mappings
            if mappings is not None
            else [_mapping(f"target-{entry_id}", resolved_fingerprint)]
        ),
    }


def _write_manifest(
    root: Path,
    entries: list[dict[str, object]],
    *,
    source_name: str = "alpha.md",
    body: str = "reviewed source\n",
    collected_at: str = NOW,
) -> tuple[Path, Path, dict[str, object]]:
    source_root = root / "sources"
    knowledge = source_root / "knowledge"
    knowledge.mkdir(parents=True, exist_ok=True)
    source_path = knowledge / source_name
    source_path.write_text(body, encoding="utf-8")
    payload: dict[str, object] = {
        "schema_version": 1,
        "collector_version": "1",
        "inventory_id": "reviewed-knowledge",
        "collected_at": collected_at,
        "expected_source_count": 1,
        "expected_entry_count": len(entries),
        "closed_directories": [{"relative_path": "knowledge", "suffix": ".md"}],
        "sources": [
            {
                "source_id": "knowledge-alpha",
                "source_uri": f"workspace://knowledge/{source_name}",
                "relative_path": f"knowledge/{source_name}",
                "sha256": hashlib.sha256(source_path.read_bytes()).hexdigest(),
                "expected_entry_count": len(entries),
                "entries": entries,
            }
        ],
    }
    manifest_path = root / "manifest.json"
    manifest_path.write_text(json.dumps(payload), encoding="utf-8")
    return manifest_path, source_root, payload


def _install_catalog(session, object_ids: set[str], *, owner: bool = True) -> str:
    principal_id = "coverage-owner" if owner else "coverage-concealed"
    session.add(
        Principal(
            id=principal_id,
            principal_type=PrincipalType.HUMAN,
            login=principal_id,
            display_name=principal_id,
            active=True,
            catalog_role=CatalogRole.CATALOG_OWNER if owner else None,
        )
    )
    for object_id in sorted(object_ids):
        session.add(
            CatalogObject(
                id=object_id,
                kind="service",
                label=object_id,
                status="active",
                lifecycle="active",
                health="healthy",
                data_json="{}",
            )
        )
    session.flush()
    return principal_id


def _record_from_result(
    root: Path,
    database_url: str,
    manifest_path: Path,
    source_root: Path,
    principal_id: str,
    result: dict[str, object],
) -> dict[str, object]:
    evidence_path = root / "target-evidence.json"
    evidence_path.write_text(json.dumps(result["target_evidence"]), encoding="utf-8")
    snapshot = result["source_snapshot"]
    assert isinstance(snapshot, dict)
    evidence = result["target_evidence"]
    assert isinstance(evidence, dict)
    return record_manifest_snapshot(
        database_url=database_url,
        manifest_path=manifest_path,
        source_root=source_root,
        target_evidence_path=evidence_path,
        principal_id=principal_id,
        expected_manifest_digest=str(result["manifest_digest"]),
        expected_input_digest=str(result["input_digest"]),
        expected_snapshot_digest=str(snapshot["digest"]),
        expected_target_digest=str(evidence["target_snapshot_digest"]),
    )


def test_manifest_digests_and_machine_output_are_order_deterministic(
    tmp_path: Path,
    alembic_database,
) -> None:
    first_fp = _sha("first")
    second_fp = _sha("second")
    entries = [
        _entry("first", fingerprint=first_fp, mappings=[_mapping("target-first", first_fp)]),
        _entry("second", fingerprint=second_fp, mappings=[_mapping("target-second", second_fp)]),
    ]
    manifest_path, source_root, payload = _write_manifest(tmp_path, entries)
    with alembic_database.sessions() as session, transaction(session):
        principal_id = _install_catalog(session, {"target-first", "target-second"})

    first = dry_run(
        database_url=alembic_database.database_url,
        manifest_path=manifest_path,
        source_root=source_root,
        principal_id=principal_id,
    )
    reordered = deepcopy(payload)
    reordered["sources"][0]["entries"].reverse()  # type: ignore[index]
    for entry in reordered["sources"][0]["entries"]:  # type: ignore[index]
        entry["mappings"].reverse()
    manifest_path.write_text(json.dumps(reordered), encoding="utf-8")
    second = dry_run(
        database_url=alembic_database.database_url,
        manifest_path=manifest_path,
        source_root=source_root,
        principal_id=principal_id,
    )

    assert first == second
    assert first["blockers"] == []
    assert first["record_ready"] is True


@pytest.mark.parametrize(
    ("mutate", "code"),
    [
        (lambda payload: payload.update({"unknown": True}), "invalid_manifest"),
        (
            lambda payload: payload.update({"inventory_id": "ghp_abcdefghijklmnopqrstuvwxyz"}),
            "unsafe_manifest_secret",
        ),
        (
            lambda payload: payload["sources"][0].update(  # type: ignore[index]
                {"relative_path": "/home/private/knowledge.md"}
            ),
            "invalid_manifest",
        ),
        (
            lambda payload: payload.update({"permissions": ["read"]}),
            "unsafe_manifest_acl",
        ),
        (
            lambda payload: payload["sources"][0].update(  # type: ignore[index]
                {"source_body": "must never be representable"}
            ),
            "invalid_manifest",
        ),
        (
            lambda payload: payload["sources"][0]["entries"][0].update(  # type: ignore[index]
                {"classification": "unclassified"}
            ),
            "invalid_manifest",
        ),
    ],
)
def test_manifest_rejects_unknown_secret_private_path_and_acl_fields(
    tmp_path: Path,
    mutate,
    code: str,
) -> None:
    manifest_path, _source_root, payload = _write_manifest(tmp_path, [_entry("one")])
    mutate(payload)
    manifest_path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(SourceCoverageManifestError, match=code) as raised:
        load_manifest(manifest_path)
    assert raised.value.code == code


def test_manifest_rejects_duplicate_keys_identities_and_partial_counts(tmp_path: Path) -> None:
    manifest_path, _source_root, payload = _write_manifest(tmp_path, [_entry("one")])
    manifest_path.write_text('{"schema_version":1,"schema_version":1}', encoding="utf-8")
    with pytest.raises(SourceCoverageManifestError, match="invalid_manifest"):
        load_manifest(manifest_path)

    payload = deepcopy(payload)
    payload["expected_entry_count"] = 1
    payload["sources"][0]["expected_entry_count"] = 1  # type: ignore[index]
    duplicate_mapping = deepcopy(payload["sources"][0]["entries"][0]["mappings"][0])  # type: ignore[index]
    payload["sources"][0]["entries"][0]["mappings"].append(duplicate_mapping)  # type: ignore[index]
    manifest_path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(SourceCoverageManifestError, match="invalid_manifest"):
        load_manifest(manifest_path)

    payload["sources"][0]["entries"].append(deepcopy(payload["sources"][0]["entries"][0]))  # type: ignore[index]
    payload["expected_entry_count"] = 2
    payload["sources"][0]["expected_entry_count"] = 2  # type: ignore[index]
    manifest_path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(SourceCoverageManifestError, match="invalid_manifest"):
        load_manifest(manifest_path)

    payload["sources"][0]["entries"].pop()  # type: ignore[index]
    manifest_path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(SourceCoverageManifestError, match="invalid_manifest"):
        load_manifest(manifest_path)


def test_closed_source_set_and_declared_file_hash_are_exact(
    tmp_path: Path,
    alembic_database,
) -> None:
    manifest_path, source_root, _payload = _write_manifest(tmp_path, [_entry("one")])
    with alembic_database.sessions() as session, transaction(session):
        principal_id = _install_catalog(session, {"target-one"})
    (source_root / "knowledge" / "undeclared.md").write_text("extra", encoding="utf-8")
    with pytest.raises(SourceCoverageManifestError, match="source_set_drift"):
        dry_run(
            database_url=alembic_database.database_url,
            manifest_path=manifest_path,
            source_root=source_root,
            principal_id=principal_id,
        )
    (source_root / "knowledge" / "undeclared.md").unlink()
    (source_root / "knowledge" / "alpha.md").write_text("changed", encoding="utf-8")
    with pytest.raises(SourceCoverageManifestError, match="source_file_drift"):
        dry_run(
            database_url=alembic_database.database_url,
            manifest_path=manifest_path,
            source_root=source_root,
            principal_id=principal_id,
        )


def test_cli_defaults_to_write_free_json_and_publishes_valid_schemas(
    tmp_path: Path,
    alembic_database,
    capsys: pytest.CaptureFixture[str],
) -> None:
    manifest_path, source_root, _payload = _write_manifest(
        tmp_path,
        [
            _entry(
                "excluded",
                classification="research",
                intent="no_catalog_object",
                reason="research_material",
                mappings=[],
            )
        ],
    )
    with alembic_database.sessions() as session, transaction(session):
        principal_id = _install_catalog(session, set())
    result = source_coverage_cli.main(
        [
            "--database-url",
            alembic_database.database_url,
            "--manifest",
            str(manifest_path),
            "--source-root",
            str(source_root),
            "--principal-id",
            principal_id,
        ]
    )
    payload = json.loads(capsys.readouterr().out)
    assert result == 0
    assert payload["mode"] == "dry-run"
    with alembic_database.sessions() as session:
        assert session.scalar(select(func.count()).select_from(SourceSnapshotRow)) == 0

    for name in ("manifest", "target-evidence", "result"):
        assert source_coverage_cli.main(["--print-schema", name]) == 0
        schema = json.loads(capsys.readouterr().out)
        Draft202012Validator.check_schema(schema)
        if name == "result":
            Draft202012Validator(schema).validate(payload)


def test_collector_rejects_symlinked_and_unbounded_source_inputs(
    tmp_path: Path,
    alembic_database,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest_path, source_root, payload = _write_manifest(tmp_path, [_entry("one")])
    with alembic_database.sessions() as session, transaction(session):
        principal_id = _install_catalog(session, {"target-one"})
    source_file = source_root / "knowledge" / "alpha.md"
    real_file = source_root / "knowledge" / "real.txt"
    real_file.write_text(source_file.read_text(encoding="utf-8"), encoding="utf-8")
    source_file.unlink()
    source_file.symlink_to(real_file)
    with pytest.raises(SourceCoverageManifestError, match="source_file_unsafe"):
        dry_run(
            database_url=alembic_database.database_url,
            manifest_path=manifest_path,
            source_root=source_root,
            principal_id=principal_id,
        )

    source_file.unlink()
    source_file.write_text("too large", encoding="utf-8")
    payload["sources"][0]["sha256"] = hashlib.sha256(source_file.read_bytes()).hexdigest()  # type: ignore[index]
    manifest_path.write_text(json.dumps(payload), encoding="utf-8")
    import blockwart.services.source_coverage_manifest as service

    monkeypatch.setattr(service, "MAX_SOURCE_BYTES", 4)
    with pytest.raises(SourceCoverageManifestError, match="source_input_too_large"):
        dry_run(
            database_url=alembic_database.database_url,
            manifest_path=manifest_path,
            source_root=source_root,
            principal_id=principal_id,
        )


def test_dry_run_reports_explicit_exclusions_and_mapping_blockers(
    tmp_path: Path,
    alembic_database,
) -> None:
    shared_fp = _sha("shared")
    ambiguous_fp = _sha("ambiguous")
    entries = [
        _entry(
            "excluded",
            classification="research",
            intent="no_catalog_object",
            reason="research_material",
            mappings=[],
        ),
        _entry("duplicate-a", mappings=[_mapping("shared", shared_fp)]),
        _entry("duplicate-b", mappings=[_mapping("shared", shared_fp)]),
        _entry(
            "ambiguous",
            fingerprint=ambiguous_fp,
            mappings=[
                _mapping("one", ambiguous_fp),
                _mapping("two", ambiguous_fp),
            ],
        ),
        _entry("missing", mappings=[_mapping("missing-target", _sha("missing"))]),
    ]
    manifest_path, source_root, _payload = _write_manifest(tmp_path, entries)
    with alembic_database.sessions() as session, transaction(session):
        principal_id = _install_catalog(session, {"shared", "one", "two"})

    result = dry_run(
        database_url=alembic_database.database_url,
        manifest_path=manifest_path,
        source_root=source_root,
        principal_id=principal_id,
    )

    assert result["missing_targets"] == ["missing-target"]
    assert result["duplicate_mappings"] == ["shared"]
    assert result["ambiguous_mappings"] == ["workspace://knowledge/alpha.md|ambiguous"]
    assert result["summary"]["state_counts"]["intentionally_unmapped"] == 1
    assert result["summary"]["state_counts"]["orphaned_catalog_reference"] == 1
    assert result["record_ready"] is False


def test_concealed_and_kind_mismatched_targets_block_recording(
    tmp_path: Path,
    alembic_database,
) -> None:
    fingerprint = _sha("one")
    manifest_path, source_root, _payload = _write_manifest(
        tmp_path,
        [_entry("one", fingerprint=fingerprint, mappings=[_mapping("target-one", fingerprint)])],
    )
    with alembic_database.sessions() as session, transaction(session):
        principal_id = _install_catalog(session, {"target-one"}, owner=False)
        session.get(CatalogObject, "target-one").kind = "runbook"
        session.get(CatalogObject, "target-one").lifecycle = None
        session.get(CatalogObject, "target-one").health = None

    result = dry_run(
        database_url=alembic_database.database_url,
        manifest_path=manifest_path,
        source_root=source_root,
        principal_id=principal_id,
    )
    codes = {item["code"] for item in result["blockers"]}
    assert codes == {"concealed_target"}
    concealed_evidence = result["target_evidence"]["targets"][0]
    assert concealed_evidence == {
        "object_id": "target-one",
        "expected_kind": "service",
        "state": "concealed",
        "actual_kind": None,
        "revision": None,
        "catalog_fingerprint": None,
    }
    with alembic_database.sessions() as session, transaction(session):
        session.get(Principal, principal_id).catalog_role = CatalogRole.CATALOG_OWNER
    result = dry_run(
        database_url=alembic_database.database_url,
        manifest_path=manifest_path,
        source_root=source_root,
        principal_id=principal_id,
    )
    assert {item["code"] for item in result["blockers"]} == {"kind_mismatch"}
    with pytest.raises(SourceCoverageManifestError, match="record_blocked"):
        _record_from_result(
            tmp_path,
            alembic_database.database_url,
            manifest_path,
            source_root,
            principal_id,
            result,
        )


def test_record_preserves_removed_entries_and_resolves_new_changed_and_missing(
    tmp_path: Path,
    alembic_database,
) -> None:
    old_fp = _sha("old")
    keep_fp = _sha("keep")
    first_entries = [
        _entry("removed", fingerprint=old_fp, mappings=[_mapping("removed-target", old_fp)]),
        _entry("keep", fingerprint=keep_fp, mappings=[_mapping("keep-target", keep_fp)]),
    ]
    manifest_path, source_root, _payload = _write_manifest(tmp_path, first_entries)
    with alembic_database.sessions() as session, transaction(session):
        principal_id = _install_catalog(session, {"removed-target", "keep-target", "new-target"})
    first = dry_run(
        database_url=alembic_database.database_url,
        manifest_path=manifest_path,
        source_root=source_root,
        principal_id=principal_id,
    )
    _record_from_result(
        tmp_path,
        alembic_database.database_url,
        manifest_path,
        source_root,
        principal_id,
        first,
    )

    changed_fp = _sha("keep-changed")
    new_fp = _sha("new")
    manifest_path, source_root, _payload = _write_manifest(
        tmp_path,
        [
            _entry(
                "keep",
                fingerprint=changed_fp,
                mappings=[_mapping("keep-target", keep_fp)],
            ),
            _entry("new", fingerprint=new_fp, mappings=[_mapping("new-target", new_fp)]),
        ],
        body="reviewed source version two\n",
        collected_at=LATER,
    )
    second = dry_run(
        database_url=alembic_database.database_url,
        manifest_path=manifest_path,
        source_root=source_root,
        principal_id=principal_id,
    )

    states = second["summary"]["state_counts"]
    assert states["missing_source"] == 1
    assert states["source_changed_since_import"] == 1
    assert states["mapped_current"] == 1
    _record_from_result(
        tmp_path,
        alembic_database.database_url,
        manifest_path,
        source_root,
        principal_id,
        second,
    )
    with alembic_database.sessions() as session:
        current = load_current_snapshot(session)
        assert current is not None
        assert {entry.entry_id: entry.presence for entry in current.entries} == {
            "keep": "present",
            "new": "present",
            "removed": "absent",
        }


def test_record_requires_current_complete_evidence_and_is_a_semantic_noop(
    tmp_path: Path,
    alembic_database,
) -> None:
    manifest_path, source_root, _payload = _write_manifest(tmp_path, [_entry("one")])
    with alembic_database.sessions() as session, transaction(session):
        principal_id = _install_catalog(session, {"target-one"})
    first = dry_run(
        database_url=alembic_database.database_url,
        manifest_path=manifest_path,
        source_root=source_root,
        principal_id=principal_id,
    )
    recorded = _record_from_result(
        tmp_path,
        alembic_database.database_url,
        manifest_path,
        source_root,
        principal_id,
        first,
    )
    assert recorded["semantic_noop"] is False

    replay = dry_run(
        database_url=alembic_database.database_url,
        manifest_path=manifest_path,
        source_root=source_root,
        principal_id=principal_id,
    )
    assert replay["semantic_noop"] is True
    replayed = _record_from_result(
        tmp_path,
        alembic_database.database_url,
        manifest_path,
        source_root,
        principal_id,
        replay,
    )
    assert replayed["semantic_noop"] is True
    with alembic_database.sessions() as session:
        assert session.scalar(select(func.count()).select_from(SourceSnapshotRow)) == 1

    stale = dry_run(
        database_url=alembic_database.database_url,
        manifest_path=manifest_path,
        source_root=source_root,
        principal_id=principal_id,
    )
    with alembic_database.sessions() as session, transaction(session):
        row = session.get(CatalogObject, "target-one")
        row.label = "changed after evidence"
        row.revision += 1
    with pytest.raises(SourceCoverageManifestError, match="stale_target_evidence"):
        _record_from_result(
            tmp_path,
            alembic_database.database_url,
            manifest_path,
            source_root,
            principal_id,
            stale,
        )

    incomplete = dry_run(
        database_url=alembic_database.database_url,
        manifest_path=manifest_path,
        source_root=source_root,
        principal_id=principal_id,
    )
    evidence_payload = deepcopy(incomplete["target_evidence"])
    evidence_payload["targets"] = []
    provisional = TargetEvidence.model_construct(**evidence_payload)
    evidence_payload["target_snapshot_digest"] = target_evidence_digest(provisional)
    evidence_path = tmp_path / "incomplete-target-evidence.json"
    evidence_path.write_text(json.dumps(evidence_payload), encoding="utf-8")
    snapshot = incomplete["source_snapshot"]
    with pytest.raises(SourceCoverageManifestError, match="incomplete_target_evidence"):
        record_manifest_snapshot(
            database_url=alembic_database.database_url,
            manifest_path=manifest_path,
            source_root=source_root,
            target_evidence_path=evidence_path,
            principal_id=principal_id,
            expected_manifest_digest=incomplete["manifest_digest"],
            expected_input_digest=incomplete["input_digest"],
            expected_snapshot_digest=snapshot["digest"],
            expected_target_digest=evidence_payload["target_snapshot_digest"],
        )


def test_record_changes_only_coverage_tables_and_rolls_back_on_failure(
    tmp_path: Path,
    alembic_database,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest_path, source_root, _payload = _write_manifest(tmp_path, [_entry("one")])
    with alembic_database.sessions() as session, transaction(session):
        principal_id = _install_catalog(session, {"target-one"})
    plan = dry_run(
        database_url=alembic_database.database_url,
        manifest_path=manifest_path,
        source_root=source_root,
        principal_id=principal_id,
    )
    protected_models = (
        CatalogObject,
        Relationship,
        ObjectGrant,
        ObjectComment,
        AuditEvent,
    )
    with alembic_database.sessions() as session:
        before = {
            model.__tablename__: session.scalar(select(func.count()).select_from(model))
            for model in protected_models
        }
    _record_from_result(
        tmp_path,
        alembic_database.database_url,
        manifest_path,
        source_root,
        principal_id,
        plan,
    )
    with alembic_database.sessions() as session:
        after = {
            model.__tablename__: session.scalar(select(func.count()).select_from(model))
            for model in protected_models
        }
    assert after == before

    second_manifest, second_root, _payload = _write_manifest(
        tmp_path,
        [_entry("two", mappings=[_mapping("target-one", _sha("two"))])],
        body="second source state\n",
        collected_at=LATER,
    )
    second = dry_run(
        database_url=alembic_database.database_url,
        manifest_path=second_manifest,
        source_root=second_root,
        principal_id=principal_id,
    )
    import blockwart.services.source_coverage_manifest as service

    original = service.record_source_snapshot

    def fail_after_flush(session, snapshot):
        original(session, snapshot)
        raise RuntimeError("synthetic failure")

    monkeypatch.setattr(service, "record_source_snapshot", fail_after_flush)
    with pytest.raises(SourceCoverageManifestError, match="database_transaction_failed"):
        _record_from_result(
            tmp_path,
            alembic_database.database_url,
            second_manifest,
            second_root,
            principal_id,
            second,
        )
    with alembic_database.sessions() as session:
        assert session.scalar(select(func.count()).select_from(SourceSnapshotRow)) == 1
        assert session.scalar(select(func.count()).select_from(SourceEntryRow)) == 1
        assert session.scalar(select(func.count()).select_from(SourceEntryMapping)) == 1
