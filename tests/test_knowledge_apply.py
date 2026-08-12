from __future__ import annotations

import json
import stat
from pathlib import Path

import jsonschema
import pytest
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from blockwart.cli import knowledge_apply as apply_cli
from blockwart.db.migrations import upgrade_database
from blockwart.db.session import build_engine
from blockwart.domain.auth import CatalogRole, PrincipalType
from blockwart.domain.relationships import validate_relationship_request
from blockwart.models import AuditEvent, CatalogObject, ObjectComment, Principal, Relationship
from blockwart.services import knowledge_apply as knowledge_apply_service
from blockwart.services.audit import add_audit_event, load_audit_details
from blockwart.services.knowledge_apply import (
    ApplyRelation,
    KnowledgeApplyError,
    apply_knowledge,
    apply_result_json_schema,
    backup_receipt_json_schema,
    rollback_knowledge,
    rollback_result_json_schema,
)
from blockwart.services.knowledge_planning import (
    build_knowledge_plan,
    canonical_json_bytes,
    load_manifest,
    load_target_snapshot,
    target_snapshot_digest,
)

EXAMPLE_ROOT = Path(__file__).resolve().parents[1] / "examples" / "knowledge-plan"
MANIFEST_PATH = EXAMPLE_ROOT / "manifest.json"
SOURCE_ROOT = EXAMPLE_ROOT / "sources"
TARGET_PATH = EXAMPLE_ROOT / "target-snapshot.json"
COMMIT = "1" * 40
TREE = "2" * 40
OWNER_ID = "00000000-0000-0000-0000-000000000146"


def _expected() -> dict[str, str]:
    plan = build_knowledge_plan(
        load_manifest(MANIFEST_PATH),
        source_root=SOURCE_ROOT,
        implementation_commit=COMMIT,
        implementation_tree=TREE,
        target_snapshot=load_target_snapshot(TARGET_PATH),
    )
    return {
        "classification": plan["classification_digest"],
        "target": plan["target_snapshot_digest"],
        "plan": plan["plan_digest"],
    }


def _database(tmp_path: Path, *, owner: bool = True) -> tuple[str, Path]:
    path = tmp_path / "catalog.sqlite3"
    url = f"sqlite:///{path}"
    upgrade_database(url)
    engine = build_engine(url)
    try:
        with Session(engine) as session:
            session.add(
                Principal(
                    id=OWNER_ID,
                    principal_type=PrincipalType.HUMAN,
                    login="knowledge-owner",
                    display_name="Knowledge Owner",
                    active=True,
                    catalog_role=CatalogRole.CATALOG_OWNER if owner else None,
                )
            )
            session.add(
                CatalogObject(
                    id="demo-runtime",
                    kind="system",
                    label="Demo runtime",
                    status="active",
                    lifecycle="active",
                    health="unknown",
                    summary=None,
                    data_json='{"schema_version":1}',
                    provenance_json=(
                        '{"manual_override":true,"source_ref":null,'
                        '"source_type":"manual","managed_by":null,'
                        '"observed_at":null,"verified_at":null,"stale_after":null}'
                    ),
                    revision=7,
                )
            )
            session.commit()
    finally:
        engine.dispose()
    return url, path


def _apply_args(tmp_path: Path, *, owner: bool = True) -> dict[str, object]:
    database_url, _ = _database(tmp_path, owner=owner)
    expected = _expected()
    return {
        "database_url": database_url,
        "manifest_path": MANIFEST_PATH,
        "source_root": SOURCE_ROOT,
        "target_snapshot_path": TARGET_PATH,
        "expected_classification_digest": expected["classification"],
        "expected_target_digest": expected["target"],
        "expected_plan_digest": expected["plan"],
        "implementation_commit": COMMIT,
        "implementation_tree": TREE,
        "principal_id": OWNER_ID,
        "backup_path": tmp_path / "protected" / "before.sqlite3",
    }


def _prepare_args(tmp_path: Path, *, owner: bool = True) -> dict[str, object]:
    protected = tmp_path / "protected"
    protected.mkdir(mode=0o700)
    return _apply_args(tmp_path, owner=owner)


def _rollback_args(
    apply_args: dict[str, object], applied: dict[str, object]
) -> dict[str, object]:
    backup = Path(apply_args["backup_path"])
    return {
        "database_url": str(apply_args["database_url"]),
        "receipt_path": backup.with_name(f"{backup.name}.receipt.json"),
        "expected_receipt_digest": applied["backup_receipt_digest"],
        "expected_plan_digest": applied["plan_digest"],
        "expected_post_state_digest": applied["post_state_digest"],
        "expected_database_state_digest": applied["database_state_digest"],
        "principal_id": OWNER_ID,
    }


def _write_json(path: Path, payload: object) -> None:
    path.write_bytes(canonical_json_bytes(payload) + b"\n")


def _custom_args(
    tmp_path: Path,
    *,
    manifest_path: Path,
    target_path: Path = TARGET_PATH,
) -> dict[str, object]:
    protected = tmp_path / "protected"
    protected.mkdir(mode=0o700)
    database_url, _ = _database(tmp_path)
    plan = build_knowledge_plan(
        load_manifest(manifest_path),
        source_root=SOURCE_ROOT,
        implementation_commit=COMMIT,
        implementation_tree=TREE,
        target_snapshot=load_target_snapshot(target_path),
    )
    return {
        "database_url": database_url,
        "manifest_path": manifest_path,
        "source_root": SOURCE_ROOT,
        "target_snapshot_path": target_path,
        "expected_classification_digest": plan["classification_digest"],
        "expected_target_digest": plan["target_snapshot_digest"],
        "expected_plan_digest": plan["plan_digest"] or "f" * 64,
        "implementation_commit": COMMIT,
        "implementation_tree": TREE,
        "principal_id": OWNER_ID,
        "backup_path": protected / "before.sqlite3",
    }


def test_success_is_atomic_bounded_and_second_identical_apply_is_noop(tmp_path: Path) -> None:
    args = _prepare_args(tmp_path)
    first = apply_knowledge(**args)
    assert first["mode"] == "apply"
    assert first["changed"] is True
    assert first["replayed"] is False
    assert first["summary"] == {
        "objects_changed": 2,
        "relationships_changed": 1,
        "comments_changed": 0,
        "audits_written": 1,
    }
    assert first["evidence"]["coverage"] == {
        "documents": 2,
        "entries": 2,
        "covered_documents": 2,
        "covered_entries": 2,
    }
    assert first["evidence"]["owner_coverage"]["uncovered_ids"] == []
    assert first["evidence"]["integrity"] == {
        "relationship_diagnostics": 0,
        "sqlite": "ok",
    }

    backup = Path(args["backup_path"])
    receipt = backup.with_name(f"{backup.name}.receipt.json")
    assert stat.S_IMODE(backup.stat().st_mode) == 0o400
    assert stat.S_IMODE(receipt.stat().st_mode) == 0o400
    assert not any(
        Path(f"{backup}{suffix}").exists()
        for suffix in ("-journal", "-shm", "-wal")
    )
    assert not list(backup.parent.glob(f".{backup.name}.*.tmp*"))
    jsonschema.validate(json.loads(receipt.read_text()), backup_receipt_json_schema())
    jsonschema.validate(first, apply_result_json_schema())

    second_args = {**args, "backup_path": tmp_path / "protected" / "unused.sqlite3"}
    second = apply_knowledge(**second_args)
    assert second["changed"] is False
    assert second["replayed"] is True
    assert second["summary"] == {
        "objects_changed": 0,
        "relationships_changed": 0,
        "comments_changed": 0,
        "audits_written": 0,
    }
    assert not Path(second_args["backup_path"]).exists()
    assert second["database_state_digest"] == first["database_state_digest"]

    engine = build_engine(str(args["database_url"]))
    try:
        with Session(engine) as session:
            runbook = session.get(CatalogObject, "demo-diagnosis")
            runtime = session.get(CatalogObject, "demo-runtime")
            assert runbook is not None
            assert runtime is not None and runtime.revision == 9
            assert session.scalar(select(func.count(Relationship.id))) == 1
            assert session.scalar(select(func.count(ObjectComment.id))) == 0
            audits = list(
                session.scalars(select(AuditEvent).where(AuditEvent.action == "knowledge_apply"))
            )
            assert len(audits) == 1
            details = load_audit_details(audits[0])
            serialized = json.dumps(details)
            assert "Inspect a fictitious runtime" not in serialized
            assert "Synthetic diagnosis" not in serialized
            assert "secret" not in serialized.casefold()
            assert set(details["object_ids"]) == {"demo-diagnosis", "demo-runtime"}
            assert details["database_state_digest"] == first["database_state_digest"]
    finally:
        engine.dispose()


def test_relationship_audit_identity_digests_allowed_sensitive_metadata(tmp_path: Path) -> None:
    sensitive_value = "restricted recovery-console cabinet label"
    metadata = validate_relationship_request(
        from_ref="device:synthetic-client",
        relation_type="attached_to",
        to_ref="host:synthetic-host",
        metadata={"note": sensitive_value},
    )
    relation = ApplyRelation(
        from_ref="device:synthetic-client",
        relation_type="attached_to",
        to_ref="host:synthetic-host",
        metadata=metadata,
        action="new",
    )
    assert sensitive_value not in relation.key
    assert json.dumps(metadata, sort_keys=True) not in relation.key
    assert relation.key == (
        "device:synthetic-client|attached_to|host:synthetic-host|"
        f"{knowledge_apply_service.domain_digest('relationship-metadata', metadata)}"
    )

    args = _prepare_args(tmp_path)
    applied = apply_knowledge(**args)
    engine = build_engine(str(args["database_url"]))
    try:
        with Session(engine) as session:
            row = session.scalar(select(AuditEvent).where(AuditEvent.action == "knowledge_apply"))
            assert row is not None
            details = load_audit_details(row)
            details["relationship_keys"] = [relation.key]
            validated = knowledge_apply_service._validated_apply_audit(details)
            serialized = json.dumps(validated, sort_keys=True)
            assert sensitive_value not in serialized
            assert relation.key in serialized
            assert applied["changed"] is True
    finally:
        engine.dispose()


@pytest.mark.parametrize(
    ("field", "code"),
    [
        ("expected_classification_digest", "classification_digest_mismatch"),
        ("expected_target_digest", "target_snapshot_drift"),
        ("expected_plan_digest", "plan_digest_mismatch"),
    ],
)
def test_caller_digest_mismatch_fails_before_backup_or_write(
    tmp_path: Path, field: str, code: str
) -> None:
    args = _prepare_args(tmp_path)
    args[field] = "f" * 64
    with pytest.raises(KnowledgeApplyError, match=code):
        apply_knowledge(**args)
    assert not Path(args["backup_path"]).exists()
    engine = build_engine(str(args["database_url"]))
    try:
        with Session(engine) as session:
            assert session.get(CatalogObject, "demo-diagnosis") is None
            assert session.scalar(select(func.count(AuditEvent.id))) == 0
    finally:
        engine.dispose()


def test_stale_revision_manual_override_and_relationship_evidence_fail_prewrite(
    tmp_path: Path,
) -> None:
    for index, mutation in enumerate(("revision", "manual", "relationship")):
        case = tmp_path / str(index)
        case.mkdir()
        args = _prepare_args(case)
        engine = build_engine(str(args["database_url"]))
        try:
            with Session(engine) as session:
                runtime = session.get(CatalogObject, "demo-runtime")
                assert runtime is not None
                if mutation == "revision":
                    runtime.revision = 8
                elif mutation == "manual":
                    runtime.provenance_json = runtime.provenance_json.replace("true", "false")
                else:
                    session.add(
                        Relationship(
                            from_ref="runbook:demo-diagnosis",
                            relation_type="documents",
                            to_ref="system:demo-runtime",
                            metadata_json="{}",
                        )
                    )
                session.commit()
        finally:
            engine.dispose()
        code = {
            "revision": "stale_target_revision",
            "manual": "target_state_drift",
            "relationship": "relationship_evidence_drift",
        }[mutation]
        with pytest.raises(KnowledgeApplyError, match=code):
            apply_knowledge(**args)
        assert not Path(args["backup_path"]).exists()


def test_authorization_denial_and_concealment_use_one_failure(tmp_path: Path) -> None:
    args = _prepare_args(tmp_path, owner=False)
    with pytest.raises(KnowledgeApplyError, match="authorization_failed"):
        apply_knowledge(**args)
    args["principal_id"] = "00000000-0000-0000-0000-000000000000"
    with pytest.raises(KnowledgeApplyError, match="authorization_failed"):
        apply_knowledge(**args)
    assert not Path(args["backup_path"]).exists()


def test_transaction_failure_rolls_back_objects_relationships_and_audit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    args = _prepare_args(tmp_path)

    def fail_relationship(*_args, **_kwargs):
        raise RuntimeError("synthetic transaction fault")

    monkeypatch.setattr(
        "blockwart.services.knowledge_apply.create_relationship", fail_relationship
    )
    with pytest.raises(RuntimeError, match="synthetic transaction fault"):
        apply_knowledge(**args)
    assert Path(args["backup_path"]).exists()
    engine = build_engine(str(args["database_url"]))
    try:
        with Session(engine) as session:
            assert session.get(CatalogObject, "demo-diagnosis") is None
            runtime = session.get(CatalogObject, "demo-runtime")
            assert runtime is not None and runtime.revision == 7
            assert session.scalar(select(func.count(Relationship.id))) == 0
            assert session.scalar(select(func.count(AuditEvent.id))) == 0
    finally:
        engine.dispose()


def test_incomplete_provenance_and_unpermitted_asset_fields_fail_before_backup(
    tmp_path: Path,
) -> None:
    mutations = ("provenance", "asset-field")
    for index, mutation in enumerate(mutations):
        case = tmp_path / str(index)
        case.mkdir()
        payload = json.loads(MANIFEST_PATH.read_text())
        if mutation == "provenance":
            runbook = next(
                entry for entry in payload["entries"] if entry["disposition"] == "runbook"
            )
            runbook["provenance_state"] = "unknown"
        else:
            asset = next(
                entry
                for entry in payload["entries"]
                if entry["disposition"] == "asset_fact"
            )
            asset["field_mappings"][0] = {
                "source_locator": "table-row-01-label",
                "target_path": "label",
                "evidence": "explicit",
                "value": "Unpermitted asset rename",
            }
        manifest_path = case / "manifest.json"
        _write_json(manifest_path, payload)
        args = _custom_args(case, manifest_path=manifest_path)
        code = "incomplete_provenance" if mutation == "provenance" else "asset_field_not_permitted"
        with pytest.raises(KnowledgeApplyError, match=code):
            apply_knowledge(**args)
        assert not Path(args["backup_path"]).exists()


def test_missing_relationship_evidence_requires_apply_ready_before_backup(tmp_path: Path) -> None:
    payload = json.loads(TARGET_PATH.read_text())
    payload["relationships"] = []
    payload["snapshot_digest"] = target_snapshot_digest(payload)
    target_path = tmp_path / "target.json"
    _write_json(target_path, payload)
    args = _custom_args(tmp_path, manifest_path=MANIFEST_PATH, target_path=target_path)
    with pytest.raises(KnowledgeApplyError, match="plan_not_apply_ready"):
        apply_knowledge(**args)
    assert not Path(args["backup_path"]).exists()


def test_source_bundle_and_unsafe_manifest_fail_without_database_mutation(tmp_path: Path) -> None:
    args = _prepare_args(tmp_path)
    source_copy = tmp_path / "sources"
    source_copy.mkdir()
    (source_copy / "references").mkdir()
    (source_copy / "TOOLS.md").write_text("drift", encoding="utf-8")
    (source_copy / "references" / "OPERATOR.md").write_bytes(
        (SOURCE_ROOT / "references" / "OPERATOR.md").read_bytes()
    )
    args["source_root"] = source_copy
    with pytest.raises(KnowledgeApplyError, match="source_drift"):
        apply_knowledge(**args)

    payload = json.loads(MANIFEST_PATH.read_text())
    payload["entries"][0]["field_mappings"][0]["value"] = {
        "token": "never-import-this-value"
    }
    unsafe = tmp_path / "unsafe.json"
    _write_json(unsafe, payload)
    args["manifest_path"] = unsafe
    args["source_root"] = SOURCE_ROOT
    with pytest.raises(KnowledgeApplyError, match="unsafe_manifest"):
        apply_knowledge(**args)
    assert not Path(args["backup_path"]).exists()


def test_replay_and_source_entry_idempotency_drift_fail_closed(tmp_path: Path) -> None:
    args = _prepare_args(tmp_path)
    applied = apply_knowledge(**args)
    engine = build_engine(str(args["database_url"]))
    try:
        with Session(engine) as session:
            runbook = session.get(CatalogObject, "demo-diagnosis")
            assert runbook is not None
            runbook.revision += 1
            session.commit()
    finally:
        engine.dispose()
    replay_args = {**args, "backup_path": tmp_path / "protected" / "replay.sqlite3"}
    with pytest.raises(KnowledgeApplyError, match="idempotent_replay_drift"):
        apply_knowledge(**replay_args)
    assert not Path(replay_args["backup_path"]).exists()

    # Restore the exact post-apply state, then add a conflicting durable claim.
    engine = build_engine(str(args["database_url"]))
    try:
        with Session(engine) as session:
            runbook = session.get(CatalogObject, "demo-diagnosis")
            assert runbook is not None
            runbook.revision -= 1
            original_audit = session.scalar(
                select(AuditEvent).where(AuditEvent.action == "knowledge_apply")
            )
            assert original_audit is not None
            conflicting_details = load_audit_details(original_audit)
            conflicting_details["plan_digest"] = "e" * 64
            conflicting_details["source_entry_keys"] = [
                "synthetic-tools/synthetic-tools-row-01"
            ]
            add_audit_event(
                session,
                object_id=None,
                action="knowledge_apply",
                actor="synthetic-conflict",
                details=conflicting_details,
            )
            session.commit()
    finally:
        engine.dispose()
    with pytest.raises(KnowledgeApplyError, match="source_entry_idempotency_conflict"):
        apply_knowledge(**replay_args)
    assert applied["changed"] is True


def test_backup_location_and_backend_fail_closed(tmp_path: Path) -> None:
    args = _prepare_args(tmp_path)
    protected = Path(args["backup_path"]).parent
    protected.chmod(0o777)
    with pytest.raises(KnowledgeApplyError, match="backup_parent_unprotected"):
        apply_knowledge(**args)
    assert not Path(args["backup_path"]).exists()

    args["database_url"] = "postgresql+psycopg2://invalid/never-opened"
    with pytest.raises(KnowledgeApplyError, match="protected_sqlite_backup_required"):
        apply_knowledge(**args)


def test_digest_bound_paired_rollback_restores_backup_and_audits(tmp_path: Path) -> None:
    args = _prepare_args(tmp_path)
    applied = apply_knowledge(**args)
    result = rollback_knowledge(**_rollback_args(args, applied))
    jsonschema.validate(result, rollback_result_json_schema())
    assert result["mode"] == "rollback"
    assert result["evidence"]["comments"]["delta"] == 0
    engine = build_engine(str(args["database_url"]))
    try:
        with Session(engine) as session:
            assert session.get(CatalogObject, "demo-diagnosis") is None
            runtime = session.get(CatalogObject, "demo-runtime")
            assert runtime is not None and runtime.revision == 7
            assert session.scalar(select(func.count(Relationship.id))) == 0
            rows = list(session.scalars(select(AuditEvent).order_by(AuditEvent.id)))
            assert [row.action for row in rows] == ["knowledge_rollback"]
            assert "Synthetic diagnosis" not in rows[0].details_json
    finally:
        engine.dispose()


@pytest.mark.parametrize(
    "boundary",
    (
        "_create_restore_candidate",
        "_copy_backup_to_candidate",
        "_insert_candidate_rollback_audit",
        "_update_candidate_rollback_audit",
        "_validate_restore_candidate_integrity",
        "_validate_restore_candidate_digest",
        "_fsync_restore_candidate",
        "_fsync_restore_directory",
        "_replace_active_database",
    ),
)
def test_staged_rollback_faults_before_swap_preserve_live_database_bytes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    boundary: str,
) -> None:
    args = _prepare_args(tmp_path)
    applied = apply_knowledge(**args)
    database_path = tmp_path / "catalog.sqlite3"
    live_bytes = database_path.read_bytes()

    def fail_boundary(*_args, **_kwargs):
        raise RuntimeError(f"synthetic {boundary} fault")

    monkeypatch.setattr(knowledge_apply_service, boundary, fail_boundary)
    with pytest.raises(KnowledgeApplyError) as caught:
        rollback_knowledge(**_rollback_args(args, applied))
    assert caught.value.database_replaced is False
    assert database_path.read_bytes() == live_bytes
    assert not list(tmp_path.glob(".catalog.sqlite3.rollback-*"))

    engine = build_engine(str(args["database_url"]))
    try:
        with Session(engine) as session:
            assert session.get(CatalogObject, "demo-diagnosis") is not None
            assert session.scalar(
                select(func.count(AuditEvent.id)).where(
                    AuditEvent.action == "knowledge_rollback"
                )
            ) == 0
    finally:
        engine.dispose()


@pytest.mark.parametrize(
    ("boundary", "error_code"),
    (
        ("replace_after_swap", "rollback_replace_result_uncertain"),
        ("directory_fsync", "rollback_replaced_readback_failed"),
        ("readback", "rollback_replaced_readback_failed"),
    ),
)
def test_staged_rollback_faults_after_swap_report_replaced_complete_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    boundary: str,
    error_code: str,
) -> None:
    args = _prepare_args(tmp_path)
    applied = apply_knowledge(**args)
    rollback_args = _rollback_args(args, applied)
    if boundary == "replace_after_swap":
        real_replace = knowledge_apply_service._replace_active_database

        def replace_then_fail(*call_args, **call_kwargs):
            real_replace(*call_args, **call_kwargs)
            raise RuntimeError("synthetic failure after atomic replacement")

        monkeypatch.setattr(
            knowledge_apply_service, "_replace_active_database", replace_then_fail
        )
    elif boundary == "readback":

        def fail_readback(*_args, **_kwargs):
            raise RuntimeError("synthetic final readback fault")

        monkeypatch.setattr(
            knowledge_apply_service, "_readback_restored_database", fail_readback
        )
    else:
        real_fsync = knowledge_apply_service._fsync_restore_directory
        calls = 0

        def fail_second_fsync(*call_args, **call_kwargs):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise RuntimeError("synthetic post-replace directory fsync fault")
            return real_fsync(*call_args, **call_kwargs)

        monkeypatch.setattr(
            knowledge_apply_service, "_fsync_restore_directory", fail_second_fsync
        )

    with pytest.raises(KnowledgeApplyError, match=error_code) as caught:
        rollback_knowledge(**rollback_args)
    assert caught.value.database_replaced is True
    assert not list(tmp_path.glob(".catalog.sqlite3.rollback-*"))

    engine = build_engine(str(args["database_url"]))
    try:
        with Session(engine) as session:
            assert session.get(CatalogObject, "demo-diagnosis") is None
            assert session.get(CatalogObject, "demo-runtime") is not None
            rows = list(session.scalars(select(AuditEvent).order_by(AuditEvent.id)))
            assert [row.action for row in rows] == ["knowledge_rollback"]
            serialized = json.dumps(load_audit_details(rows[0]), sort_keys=True)
            assert "Synthetic diagnosis" not in serialized
            assert "Inspect a fictitious runtime" not in serialized
    finally:
        engine.dispose()

    with pytest.raises(KnowledgeApplyError, match="rollback_apply_evidence_missing"):
        rollback_knowledge(**rollback_args)


def test_rollback_fails_closed_on_receipt_poststate_database_or_auth_drift(
    tmp_path: Path,
) -> None:
    cases = ("receipt", "post", "database", "auth")
    for index, drift in enumerate(cases):
        case = tmp_path / str(index)
        case.mkdir()
        args = _prepare_args(case)
        applied = apply_knowledge(**args)
        backup = Path(args["backup_path"])
        receipt = backup.with_name(f"{backup.name}.receipt.json")
        rollback_args = {
            "database_url": str(args["database_url"]),
            "receipt_path": receipt,
            "expected_receipt_digest": applied["backup_receipt_digest"],
            "expected_plan_digest": applied["plan_digest"],
            "expected_post_state_digest": applied["post_state_digest"],
            "expected_database_state_digest": applied["database_state_digest"],
            "principal_id": OWNER_ID,
        }
        if drift == "receipt":
            rollback_args["expected_receipt_digest"] = "f" * 64
        elif drift == "post":
            rollback_args["expected_post_state_digest"] = "f" * 64
        elif drift == "database":
            engine = build_engine(str(args["database_url"]))
            try:
                with Session(engine) as session:
                    add_audit_event(
                        session,
                        object_id=None,
                        action="unrelated_test_event",
                        actor="test",
                    )
                    session.commit()
            finally:
                engine.dispose()
        else:
            rollback_args["principal_id"] = "missing"
        with pytest.raises(KnowledgeApplyError):
            rollback_knowledge(**rollback_args)
        engine = build_engine(str(args["database_url"]))
        try:
            with Session(engine) as session:
                assert session.get(CatalogObject, "demo-diagnosis") is not None
        finally:
            engine.dispose()


def test_rollback_rejects_nonempty_wal_without_touching_live_database(tmp_path: Path) -> None:
    args = _prepare_args(tmp_path)
    applied = apply_knowledge(**args)
    database_path = tmp_path / "catalog.sqlite3"
    live_bytes = database_path.read_bytes()
    Path(f"{database_path}-wal").write_bytes(b"synthetic uncheckpointed WAL")

    with pytest.raises(KnowledgeApplyError, match="rollback_active_sidecars_present") as caught:
        rollback_knowledge(**_rollback_args(args, applied))
    assert caught.value.database_replaced is False
    assert database_path.read_bytes() == live_bytes


def test_rollback_rejects_unprotected_backup_and_second_restore(tmp_path: Path) -> None:
    args = _prepare_args(tmp_path)
    applied = apply_knowledge(**args)
    backup = Path(args["backup_path"])
    receipt = backup.with_name(f"{backup.name}.receipt.json")
    rollback_args = {
        "database_url": str(args["database_url"]),
        "receipt_path": receipt,
        "expected_receipt_digest": applied["backup_receipt_digest"],
        "expected_plan_digest": applied["plan_digest"],
        "expected_post_state_digest": applied["post_state_digest"],
        "expected_database_state_digest": applied["database_state_digest"],
        "principal_id": OWNER_ID,
    }
    backup.chmod(0o600)
    with pytest.raises(KnowledgeApplyError, match="protected_file_invalid"):
        rollback_knowledge(**rollback_args)
    backup.chmod(0o400)
    backup_wal = Path(f"{backup}-wal")
    backup_wal.write_bytes(b"synthetic sidecar")
    with pytest.raises(KnowledgeApplyError, match="backup_sidecars_present"):
        rollback_knowledge(**rollback_args)
    backup_wal.unlink()
    rollback_knowledge(**rollback_args)
    with pytest.raises(KnowledgeApplyError, match="rollback_apply_evidence_missing"):
        rollback_knowledge(**rollback_args)


def test_cli_contracts_are_machine_readable_and_apply_is_separate(capsys) -> None:
    for name, schema in (
        ("apply-result", apply_result_json_schema()),
        ("backup-receipt", backup_receipt_json_schema()),
        ("rollback-result", rollback_result_json_schema()),
    ):
        assert apply_cli.main(["--print-schema", name]) == 0
        assert json.loads(capsys.readouterr().out) == schema
        jsonschema.Draft202012Validator.check_schema(schema)
    assert apply_cli.main([]) == 2
    assert "missing_action" in capsys.readouterr().err


def test_cli_reports_whether_a_failed_rollback_replaced_the_database(
    capsys,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_after_replace(**_kwargs):
        raise KnowledgeApplyError("synthetic_post_swap", database_replaced=True)

    monkeypatch.setattr(apply_cli, "rollback_knowledge", fail_after_replace)
    result = apply_cli.main(
        [
            "rollback",
            "--database-url",
            "sqlite:////not-opened.sqlite3",
            "--receipt",
            "/not-opened.receipt.json",
            "--expected-receipt-digest",
            "0" * 64,
            "--expected-plan-digest",
            "0" * 64,
            "--expected-post-state-digest",
            "0" * 64,
            "--expected-database-state-digest",
            "0" * 64,
            "--principal-id",
            OWNER_ID,
        ]
    )
    assert result == 1
    assert capsys.readouterr().err == (
        "knowledge_apply_error=synthetic_post_swap database_replaced=true\n"
    )
