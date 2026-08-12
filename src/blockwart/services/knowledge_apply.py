from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import stat
import tempfile
from collections.abc import Mapping, Sequence
from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sqlalchemy import func, select, text
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session

from blockwart.db.migrations import check_database_revision
from blockwart.db.session import _sqlite_database_path, build_engine, build_read_only_engine
from blockwart.domain.auth import CatalogRole, Permission
from blockwart.domain.provenance import load_provenance
from blockwart.domain.relationships import canonical_relationship_metadata_json
from blockwart.domain.security import find_acl_data_violations, find_secret_violations
from blockwart.models import AuditEvent, CatalogObject, ObjectComment, Principal, Relationship
from blockwart.schemas.catalog import CatalogObjectIn
from blockwart.services.access import active_owner_covered_object_ids
from blockwart.services.audit import add_audit_event, load_audit_details
from blockwart.services.catalog import create_relationship, relationship_diagnostics, upsert_object
from blockwart.services.knowledge_planning import (
    ASSET_KINDS,
    KnowledgeManifest,
    KnowledgePlanError,
    TargetSnapshot,
    _candidate_for_group,
    _group_targets,
    build_knowledge_plan,
    canonical_json_bytes,
    domain_digest,
    load_manifest,
    load_target_snapshot,
)
from blockwart.services.policy import policy_for_principal

APPLY_SCHEMA_VERSION = 1
ROLLBACK_SCHEMA_VERSION = 1
_HEX64 = frozenset("0123456789abcdef")
_APPLY_ACTION = "knowledge_apply"
_ROLLBACK_ACTION = "knowledge_rollback"
_ALLOWED_KINDS = frozenset({"runbook", "decision", "project", *ASSET_KINDS})
_MAX_SOURCE_ENTRIES = 1000
_MAX_TARGETS = 500
_MAX_RELATIONSHIPS = 1000


class KnowledgeApplyError(RuntimeError):
    def __init__(self, code: str, *, database_replaced: bool = False) -> None:
        super().__init__(code)
        self.code = code
        self.database_replaced = database_replaced


@dataclass(frozen=True, slots=True)
class ApplyTarget:
    target_ref: str
    object_id: str
    kind: str
    action: str
    expected_revision: int | None
    candidate: CatalogObjectIn
    source_entry_ids: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ApplyRelation:
    from_ref: str
    relation_type: str
    to_ref: str
    metadata: dict[str, Any]
    action: str

    @property
    def key(self) -> str:
        return "|".join(
            (
                self.from_ref,
                self.relation_type,
                self.to_ref,
                domain_digest("relationship-metadata", self.metadata),
            )
        )


@dataclass(frozen=True, slots=True)
class ApplyContract:
    targets: tuple[ApplyTarget, ...]
    relations: tuple[ApplyRelation, ...]
    source_entry_keys: tuple[str, ...]


def apply_result_json_schema() -> dict[str, Any]:
    return _closed_result_schema("BlockwartKnowledgeApplyResultV1", ("apply",))


def rollback_result_json_schema() -> dict[str, Any]:
    return _closed_result_schema("BlockwartKnowledgeRollbackResultV1", ("rollback",))


def backup_receipt_json_schema() -> dict[str, Any]:
    properties: dict[str, Any] = {
        "schema_version": {"const": 1, "type": "integer"},
        "mode": {"const": "knowledge-apply-backup", "type": "string"},
        "plan_digest": _digest_schema(),
        "classification_digest": _digest_schema(),
        "target_snapshot_digest": _digest_schema(),
        "source_bundle_digest": _digest_schema(),
        "backup_file": {"minLength": 1, "type": "string"},
        "backup_sha256": _digest_schema(),
        "database_state_digest": _digest_schema(),
        "database_revision": {"minLength": 1, "type": "string"},
    }
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "additionalProperties": False,
        "properties": properties,
        "required": list(properties),
        "title": "BlockwartKnowledgeBackupReceiptV1",
        "type": "object",
    }


def apply_knowledge(
    *,
    database_url: str,
    manifest_path: str | Path,
    source_root: str | Path,
    target_snapshot_path: str | Path,
    expected_classification_digest: str,
    expected_target_digest: str,
    expected_plan_digest: str,
    implementation_commit: str,
    implementation_tree: str,
    principal_id: str,
    backup_path: str | Path,
) -> dict[str, Any]:
    """Rebuild an exact Phase-A plan, then apply it to persistent SQLite.

    All caller-held digest checks and the complete read-only preflight finish
    before the backup is created or a write-capable engine is opened.
    """
    expected_classification_digest = _required_digest(
        expected_classification_digest, "invalid_classification_digest"
    )
    expected_target_digest = _required_digest(
        expected_target_digest, "invalid_target_digest"
    )
    expected_plan_digest = _required_digest(expected_plan_digest, "invalid_plan_digest")
    try:
        manifest = load_manifest(manifest_path)
        target_snapshot = load_target_snapshot(target_snapshot_path)
        plan = build_knowledge_plan(
            manifest,
            source_root=source_root,
            implementation_commit=implementation_commit,
            implementation_tree=implementation_tree,
            target_snapshot=target_snapshot,
            expected_target_digest=expected_target_digest,
        )
    except KnowledgePlanError as exc:
        raise KnowledgeApplyError(exc.code) from exc
    if plan["classification_digest"] != expected_classification_digest:
        raise KnowledgeApplyError("classification_digest_mismatch")
    if plan["target_snapshot_digest"] != expected_target_digest:
        raise KnowledgeApplyError("target_snapshot_digest_mismatch")
    if not plan["apply_ready"]:
        raise KnowledgeApplyError("plan_not_apply_ready")
    if plan["plan_digest"] != expected_plan_digest:
        raise KnowledgeApplyError("plan_digest_mismatch")
    contract = _materialize_contract(manifest, target_snapshot, plan)
    database_path = _persistent_sqlite_path(database_url)
    revision = check_database_revision(database_url, read_only=True)

    replay = _read_only_preflight(
        database_url,
        principal_id=principal_id,
        target_snapshot=target_snapshot,
        contract=contract,
        plan=plan,
        allow_replay=True,
    )
    if replay is not None:
        database_digest = _sqlite_database_digest(database_path)
        return _replay_result(replay, database_digest=database_digest)

    receipt, receipt_digest = _create_protected_backup(
        database_path=database_path,
        backup_path=Path(backup_path),
        database_revision=revision,
        manifest=manifest,
        target_snapshot=target_snapshot,
        plan=plan,
    )

    engine = build_engine(database_url)
    try:
        with Session(engine, autoflush=False, expire_on_commit=False) as session:
            try:
                session.execute(text("BEGIN IMMEDIATE"))
                if _sqlite_connection_digest(session) != receipt["database_state_digest"]:
                    raise KnowledgeApplyError("database_drift_after_backup")
                replay = _transaction_preflight(
                    session,
                    principal_id=principal_id,
                    target_snapshot=target_snapshot,
                    contract=contract,
                    plan=plan,
                    allow_replay=True,
                )
                if replay is not None:
                    session.rollback()
                    return _replay_result(
                        replay,
                        database_digest=_sqlite_database_digest(database_path),
                    )
                before = _boundary_evidence(session, contract)
                changed_object_ids: list[str] = []
                changed_relation_keys: list[str] = []
                known_kinds = {target.object_id: target.kind for target in contract.targets}
                for target in contract.targets:
                    result = upsert_object(
                        session,
                        target.candidate,
                        known_object_kinds=known_kinds,
                        expected_revision=target.expected_revision,
                        write_audit=False,
                    )
                    if target.action != "unchanged":
                        changed_object_ids.append(result.id)
                for relation in contract.relations:
                    if relation.action == "new":
                        create_relationship(
                            session,
                            from_ref=relation.from_ref,
                            relation_type=relation.relation_type,
                            to_ref=relation.to_ref,
                            metadata=relation.metadata,
                            write_audit=False,
                        )
                        changed_relation_keys.append(relation.key)
                session.flush()
                after = _boundary_evidence(session, contract)
                _verify_expected_deltas(
                    plan,
                    before=before,
                    after=after,
                    changed_object_ids=changed_object_ids,
                    changed_relation_keys=changed_relation_keys,
                )
                post_state = _post_state(session, contract)
                post_state_digest = domain_digest("apply-post-state", post_state)
                evidence = _apply_evidence(
                    plan,
                    before=before,
                    after=after,
                    post_state=post_state,
                    changed_object_ids=changed_object_ids,
                    changed_relation_keys=changed_relation_keys,
                )
                evidence_digest = domain_digest("apply-evidence", evidence)
                audit_details = _audit_details(
                    plan,
                    contract,
                    backup_digest=receipt["backup_sha256"],
                    receipt_digest=receipt_digest,
                    post_state_digest=post_state_digest,
                    evidence_digest=evidence_digest,
                    database_state_digest="0" * 64,
                    evidence=evidence,
                )
                if find_secret_violations(audit_details) or find_acl_data_violations(audit_details):
                    raise KnowledgeApplyError("unsafe_audit_evidence")
                actor = _principal_login(session, principal_id)
                add_audit_event(
                    session,
                    object_id=None,
                    action=_APPLY_ACTION,
                    actor=actor,
                    details=audit_details,
                )
                session.flush()
                audit_id = int(
                    session.scalar(
                        select(func.max(AuditEvent.id)).where(AuditEvent.action == _APPLY_ACTION)
                    )
                )
                evidence = {**evidence, "audits": {"delta": 1, "ids": [audit_id]}}
                evidence_digest = domain_digest("apply-evidence", evidence)
                audit_details = _audit_details(
                    plan,
                    contract,
                    backup_digest=receipt["backup_sha256"],
                    receipt_digest=receipt_digest,
                    post_state_digest=post_state_digest,
                    evidence_digest=evidence_digest,
                    database_state_digest="0" * 64,
                    evidence=evidence,
                )
                audit_row = session.get(AuditEvent, audit_id)
                if audit_row is None:
                    raise KnowledgeApplyError("apply_audit_missing")
                _replace_audit_details(audit_row, audit_details)
                session.flush()
                database_digest = _sqlite_connection_digest(session)
                audit_details["database_state_digest"] = database_digest
                _replace_audit_details(audit_row, audit_details)
                session.flush()
                if _sqlite_connection_digest(session) != database_digest:
                    raise KnowledgeApplyError("apply_evidence_drift")
                session.commit()
            except Exception:
                session.rollback()
                raise
    finally:
        engine.dispose()

    if _sqlite_database_digest(database_path) != database_digest:
        raise KnowledgeApplyError("apply_evidence_drift")
    return {
        "schema_version": APPLY_SCHEMA_VERSION,
        "mode": "apply",
        "changed": True,
        "replayed": False,
        "classification_digest": plan["classification_digest"],
        "target_snapshot_digest": plan["target_snapshot_digest"],
        "plan_digest": plan["plan_digest"],
        "source_bundle_digest": manifest.source_snapshot.bundle_digest,
        "backup_digest": receipt["backup_sha256"],
        "backup_receipt_digest": receipt_digest,
        "post_state_digest": post_state_digest,
        "database_state_digest": database_digest,
        "summary": _result_summary(evidence, audit_delta=1),
        "evidence": evidence,
    }


def rollback_knowledge(
    *,
    database_url: str,
    receipt_path: str | Path,
    expected_receipt_digest: str,
    expected_plan_digest: str,
    expected_post_state_digest: str,
    expected_database_state_digest: str,
    principal_id: str,
) -> dict[str, Any]:
    expected_receipt_digest = _required_digest(
        expected_receipt_digest, "invalid_receipt_digest"
    )
    expected_plan_digest = _required_digest(expected_plan_digest, "invalid_plan_digest")
    expected_post_state_digest = _required_digest(
        expected_post_state_digest, "invalid_post_state_digest"
    )
    expected_database_state_digest = _required_digest(
        expected_database_state_digest, "invalid_database_state_digest"
    )
    database_path = _persistent_sqlite_path(database_url)
    receipt_file = Path(receipt_path)
    receipt = _load_receipt(receipt_file, expected_receipt_digest)
    if receipt["plan_digest"] != expected_plan_digest:
        raise KnowledgeApplyError("rollback_plan_digest_mismatch")
    backup_path = receipt_file.parent / receipt["backup_file"]
    _verify_protected_file(backup_path)
    if _file_digest(backup_path) != receipt["backup_sha256"]:
        raise KnowledgeApplyError("backup_digest_mismatch")
    _require_sqlite_file_without_sidecars(backup_path)
    if _sqlite_database_digest(backup_path) != receipt["database_state_digest"]:
        raise KnowledgeApplyError("backup_state_mismatch")
    _sqlite_integrity(backup_path)

    apply_details = _rollback_preflight(
        database_url,
        principal_id=principal_id,
        plan_digest=expected_plan_digest,
        post_state_digest=expected_post_state_digest,
    )
    if apply_details.get("database_state_digest") != expected_database_state_digest:
        raise KnowledgeApplyError("rollback_database_digest_mismatch")
    if _sqlite_database_digest(database_path) != expected_database_state_digest:
        raise KnowledgeApplyError("rollback_database_drift")
    _require_quiescent_sqlite(database_path)
    active_file_digest = _file_digest(database_path)
    active_mode = stat.S_IMODE(database_path.stat().st_mode)
    candidate: Path | None = None
    try:
        candidate = _create_restore_candidate(database_path)
        _copy_backup_to_candidate(backup_path, candidate)
        _validate_restore_candidate_integrity(candidate)
        _validate_restore_candidate_digest(
            candidate,
            receipt["database_state_digest"],
            code="rollback_restore_mismatch",
        )
        audit_id, restored_digest, rollback_details = _write_candidate_rollback_audit(
            candidate,
            principal_id=principal_id,
            receipt=receipt,
            receipt_digest=expected_receipt_digest,
            plan_digest=expected_plan_digest,
            post_state_digest=expected_post_state_digest,
        )
        _validate_restore_candidate_integrity(candidate)
        _validate_restore_candidate_digest(
            candidate,
            restored_digest,
            code="rollback_evidence_drift",
        )
        os.chmod(candidate, active_mode)
        _fsync_restore_candidate(candidate)
        _fsync_restore_directory(database_path.parent)
        _verify_active_restore_state(
            database_path,
            expected_database_state_digest=expected_database_state_digest,
            expected_file_digest=active_file_digest,
        )
    except KnowledgeApplyError:
        _remove_restore_candidate(candidate)
        raise
    except Exception as exc:
        _remove_restore_candidate(candidate)
        raise KnowledgeApplyError("rollback_staging_failed") from exc

    try:
        _replace_active_database(candidate, database_path)
    except Exception as exc:
        # A conventional os.replace failure leaves the candidate in place. If
        # it disappeared, conservatively report that the live path may already
        # name the restored database rather than claiming it was untouched.
        replaced = not candidate.exists()
        _remove_restore_candidate(candidate)
        if replaced:
            raise KnowledgeApplyError(
                "rollback_replace_result_uncertain", database_replaced=True
            ) from exc
        raise KnowledgeApplyError("rollback_replace_failed") from exc

    try:
        _remove_replaced_database_sidecars(database_path)
        _fsync_restore_directory(database_path.parent)
        _readback_restored_database(
            database_path,
            expected_database_state_digest=restored_digest,
            expected_audit_id=audit_id,
            expected_audit_details=rollback_details,
        )
    except Exception as exc:
        raise KnowledgeApplyError(
            "rollback_replaced_readback_failed", database_replaced=True
        ) from exc
    return {
        "schema_version": ROLLBACK_SCHEMA_VERSION,
        "mode": "rollback",
        "changed": True,
        "replayed": False,
        "classification_digest": receipt["classification_digest"],
        "target_snapshot_digest": receipt["target_snapshot_digest"],
        "plan_digest": expected_plan_digest,
        "source_bundle_digest": receipt["source_bundle_digest"],
        "backup_digest": receipt["backup_sha256"],
        "backup_receipt_digest": expected_receipt_digest,
        "post_state_digest": expected_post_state_digest,
        "database_state_digest": restored_digest,
        "summary": {
            "objects_changed": len(apply_details["object_ids"]),
            "relationships_changed": len(apply_details["relationship_keys"]),
            "comments_changed": 0,
            "audits_written": 1,
        },
        "evidence": {
            "objects": {"ids": apply_details["object_ids"]},
            "relationships": {"keys": apply_details["relationship_keys"]},
            "comments": {"delta": 0},
            "audits": {"delta": 1, "ids": [audit_id]},
            "coverage": {
                "source_count": apply_details["source_count"],
                "entry_count": len(apply_details["source_entry_keys"]),
            },
            "owner_coverage": {"uncovered_ids": []},
            "integrity": {"relationship_diagnostics": 0, "sqlite": "ok"},
        },
    }


def _materialize_contract(
    manifest: KnowledgeManifest,
    snapshot: TargetSnapshot,
    plan: Mapping[str, Any],
) -> ApplyContract:
    blockers: list[dict[str, str]] = []
    groups = _group_targets(manifest.entries, blockers)
    if blockers:
        raise KnowledgeApplyError("classification_blocked")
    states = {item.ref: item for item in snapshot.objects}
    targets: list[ApplyTarget] = []
    relations: dict[tuple[str, str, str, str], ApplyRelation] = {}
    plan_targets = {item["target_ref"]: item for item in plan["targets"]}
    for target_ref, group in sorted(groups.items()):
        state = states[target_ref]
        candidate, action = _candidate_for_group(group, state)
        if candidate.kind not in _ALLOWED_KINDS:
            raise KnowledgeApplyError("target_kind_not_permitted")
        if candidate.kind in ASSET_KINDS:
            if state.state != "present" or group["provenance_states"] != {"preserve_existing"}:
                raise KnowledgeApplyError("asset_update_not_permitted")
            if any(not path.startswith("data.") for path in group["field_mappings"]):
                raise KnowledgeApplyError("asset_field_not_permitted")
        elif state.state == "absent" and group["provenance_states"] != {"explicit"}:
            raise KnowledgeApplyError("incomplete_provenance")
        elif group["provenance_states"] - {"explicit", "preserve_existing"}:
            raise KnowledgeApplyError("incomplete_provenance")
        planned = plan_targets[target_ref]
        if planned["action"] != action:
            raise KnowledgeApplyError("expected_delta_mismatch")
        targets.append(
            ApplyTarget(
                target_ref=target_ref,
                object_id=group["object_id"],
                kind=group["kind"],
                action=action,
                expected_revision=state.revision,
                candidate=candidate,
                source_entry_ids=tuple(sorted(group["entry_ids"])),
            )
        )
        for relation_plan in planned["relations"]:
            key = (
                relation_plan["from_ref"],
                relation_plan["relation_type"],
                relation_plan["to_ref"],
                canonical_json_bytes(relation_plan["metadata"]).decode("utf-8"),
            )
            relations[key] = ApplyRelation(
                from_ref=relation_plan["from_ref"],
                relation_type=relation_plan["relation_type"],
                to_ref=relation_plan["to_ref"],
                metadata=deepcopy(relation_plan["metadata"]),
                action=relation_plan["action"],
            )
    source_entry_keys = tuple(
        sorted(f"{entry.source_id}/{entry.entry_id}" for entry in manifest.entries)
    )
    if (
        len(source_entry_keys) > _MAX_SOURCE_ENTRIES
        or len(targets) > _MAX_TARGETS
        or len(relations) > _MAX_RELATIONSHIPS
    ):
        raise KnowledgeApplyError("apply_batch_too_large")
    return ApplyContract(tuple(targets), tuple(relations.values()), source_entry_keys)


def _read_only_preflight(
    database_url: str,
    *,
    principal_id: str,
    target_snapshot: TargetSnapshot,
    contract: ApplyContract,
    plan: Mapping[str, Any],
    allow_replay: bool,
) -> dict[str, Any] | None:
    engine = build_read_only_engine(database_url)
    try:
        with Session(engine) as session:
            return _transaction_preflight(
                session,
                principal_id=principal_id,
                target_snapshot=target_snapshot,
                contract=contract,
                plan=plan,
                allow_replay=allow_replay,
            )
    finally:
        engine.dispose()


def _transaction_preflight(
    session: Session,
    *,
    principal_id: str,
    target_snapshot: TargetSnapshot,
    contract: ApplyContract,
    plan: Mapping[str, Any],
    allow_replay: bool,
) -> dict[str, Any] | None:
    _require_authorization(session, principal_id, contract)
    prior = _prior_apply_details(session, str(plan["plan_digest"]), contract)
    if prior is not None:
        if not allow_replay:
            raise KnowledgeApplyError("already_applied")
        actual = domain_digest("apply-post-state", _post_state(session, contract))
        if prior.get("post_state_digest") != actual:
            raise KnowledgeApplyError("idempotent_replay_drift")
        if session.bind.dialect.name == "sqlite":
            stored_database_digest = prior.get("database_state_digest")
            if (
                not isinstance(stored_database_digest, str)
                or _sqlite_connection_digest(session) != stored_database_digest
            ):
                raise KnowledgeApplyError("idempotent_replay_drift")
        if relationship_diagnostics(session):
            raise KnowledgeApplyError("relationship_integrity_failure")
        return prior
    _validate_target_state(session, target_snapshot)
    if relationship_diagnostics(session):
        raise KnowledgeApplyError("relationship_integrity_failure")
    return None


def _require_authorization(
    session: Session,
    principal_id: str,
    contract: ApplyContract,
) -> None:
    principal = session.get(Principal, principal_id)
    if principal is None or not principal.active:
        raise KnowledgeApplyError("authorization_failed")
    policy = policy_for_principal(session, principal_id)
    new_object = any(target.expected_revision is None for target in contract.targets)
    if new_object and principal.catalog_role != CatalogRole.CATALOG_OWNER:
        raise KnowledgeApplyError("authorization_failed")
    new_ids = {
        target.object_id for target in contract.targets if target.expected_revision is None
    }
    required_ids = {
        target.object_id for target in contract.targets if target.expected_revision is not None
    }
    for relation in contract.relations:
        required_ids.update(
            {
                relation.from_ref.split(":", 1)[1],
                relation.to_ref.split(":", 1)[1],
            }
            - new_ids
        )
    for object_id in required_ids:
        if not policy.can(Permission.DISCOVER, object_id) or not policy.can(
            Permission.WRITE, object_id
        ):
            raise KnowledgeApplyError("authorization_failed")


def _validate_target_state(session: Session, snapshot: TargetSnapshot) -> None:
    for state in snapshot.objects:
        row = session.get(CatalogObject, state.ref.split(":", 1)[1])
        if state.state == "absent":
            if row is not None:
                raise KnowledgeApplyError("stale_target_revision")
            continue
        if row is None or row.kind != state.ref.split(":", 1)[0]:
            raise KnowledgeApplyError("stale_target_revision")
        if row.revision != state.revision:
            raise KnowledgeApplyError("stale_target_revision")
        if _catalog_payload(row) != state.object:
            raise KnowledgeApplyError("target_state_drift")
    for evidence in snapshot.relationships:
        row = session.scalar(
            select(Relationship).where(
                Relationship.from_ref == evidence.from_ref,
                Relationship.relation_type == evidence.relation_type,
                Relationship.to_ref == evidence.to_ref,
            )
        )
        present = row is not None and row.metadata_json == canonical_relationship_metadata_json(
            evidence.relation_type, evidence.metadata
        )
        if present != evidence.present:
            raise KnowledgeApplyError("relationship_evidence_drift")
        if row is not None and not present:
            raise KnowledgeApplyError("relationship_evidence_drift")


def _catalog_payload(row: CatalogObject) -> dict[str, Any]:
    try:
        data = json.loads(row.data_json)
        provenance, valid = load_provenance(row.provenance_json)
    except (TypeError, json.JSONDecodeError) as exc:
        raise KnowledgeApplyError("target_state_invalid") from exc
    if not valid:
        raise KnowledgeApplyError("target_state_invalid")
    try:
        candidate = CatalogObjectIn.model_validate(
            {
                "id": row.id,
                "kind": row.kind,
                "label": row.label,
                "status": row.status,
                "lifecycle": row.lifecycle,
                "health": row.health,
                "summary": row.summary,
                "data": data,
                "provenance": provenance.model_dump(mode="json"),
            }
        )
    except ValueError as exc:
        raise KnowledgeApplyError("target_state_invalid") from exc
    return candidate.model_dump(mode="json")


def _prior_apply_details(
    session: Session,
    plan_digest: str,
    contract: ApplyContract,
) -> dict[str, Any] | None:
    requested_entries = set(contract.source_entry_keys)
    matching: dict[str, Any] | None = None
    for row in session.scalars(
        select(AuditEvent).where(AuditEvent.action == _APPLY_ACTION).order_by(AuditEvent.id)
    ):
        details = _validated_apply_audit(load_audit_details(row))
        prior_entries = set(details["source_entry_keys"])
        if prior_entries & requested_entries and details.get("plan_digest") != plan_digest:
            raise KnowledgeApplyError("source_entry_idempotency_conflict")
        if details.get("plan_digest") == plan_digest:
            if matching is not None:
                raise KnowledgeApplyError("duplicate_apply_audit")
            matching = details
    return matching


def _boundary_evidence(session: Session, contract: ApplyContract) -> dict[str, Any]:
    return {
        "comments": int(session.scalar(select(func.count(ObjectComment.id))) or 0),
        "audits": int(session.scalar(select(func.count(AuditEvent.id))) or 0),
        "objects": int(session.scalar(select(func.count(CatalogObject.id))) or 0),
        "relationships": int(session.scalar(select(func.count(Relationship.id))) or 0),
        "owner_covered": len(active_owner_covered_object_ids(session)),
        "affected": _post_state(session, contract),
        "relationship_diagnostics": len(relationship_diagnostics(session)),
    }


def _post_state(session: Session, contract: ApplyContract) -> dict[str, Any]:
    objects: list[dict[str, Any]] = []
    for target in contract.targets:
        row = session.get(CatalogObject, target.object_id)
        if row is None:
            objects.append({"ref": target.target_ref, "present": False})
        else:
            objects.append(
                {
                    "ref": target.target_ref,
                    "present": True,
                    "revision": row.revision,
                    "state_digest": domain_digest("catalog-object-state", _catalog_payload(row)),
                }
            )
    relations: list[dict[str, Any]] = []
    for relation in contract.relations:
        row = session.scalar(
            select(Relationship).where(
                Relationship.from_ref == relation.from_ref,
                Relationship.relation_type == relation.relation_type,
                Relationship.to_ref == relation.to_ref,
            )
        )
        relations.append(
            {
                "key": relation.key,
                "present": row is not None,
                "metadata_digest": (
                    None
                    if row is None
                    else domain_digest("relationship-metadata", json.loads(row.metadata_json))
                ),
            }
        )
    return {"objects": objects, "relationships": relations}


def _verify_expected_deltas(
    plan: Mapping[str, Any],
    *,
    before: Mapping[str, Any],
    after: Mapping[str, Any],
    changed_object_ids: Sequence[str],
    changed_relation_keys: Sequence[str],
) -> None:
    summary = plan["summary"]
    if len(changed_object_ids) != summary["new_count"] + summary["update_count"]:
        raise KnowledgeApplyError("expected_delta_mismatch")
    if len(changed_relation_keys) != summary["relationship_deltas"]["new"]:
        raise KnowledgeApplyError("expected_delta_mismatch")
    if after["objects"] - before["objects"] != summary["new_count"]:
        raise KnowledgeApplyError("expected_delta_mismatch")
    if after["relationships"] - before["relationships"] != len(changed_relation_keys):
        raise KnowledgeApplyError("expected_delta_mismatch")
    if after["comments"] != before["comments"] or after["audits"] != before["audits"]:
        raise KnowledgeApplyError("unexpected_side_effect")
    if after["owner_covered"] != after["objects"] or after["relationship_diagnostics"]:
        raise KnowledgeApplyError("integrity_failure")


def _apply_evidence(
    plan: Mapping[str, Any],
    *,
    before: Mapping[str, Any],
    after: Mapping[str, Any],
    post_state: Mapping[str, Any],
    changed_object_ids: Sequence[str],
    changed_relation_keys: Sequence[str],
) -> dict[str, Any]:
    return {
        "objects": {
            "changed_ids": sorted(changed_object_ids),
            "count_before": before["objects"],
            "count_after": after["objects"],
            "states": post_state["objects"],
        },
        "relationships": {
            "changed_keys": sorted(changed_relation_keys),
            "count_before": before["relationships"],
            "count_after": after["relationships"],
            "states": post_state["relationships"],
        },
        "comments": {
            "delta": 0,
            "count_before": before["comments"],
            "count_after": after["comments"],
        },
        "audits": {"delta": 1, "ids": []},
        "coverage": deepcopy(plan["summary"]["expected_coverage"]),
        "owner_coverage": {"covered_count": after["owner_covered"], "uncovered_ids": []},
        "integrity": {"relationship_diagnostics": 0, "sqlite": "ok"},
    }


def _audit_details(
    plan: Mapping[str, Any],
    contract: ApplyContract,
    *,
    backup_digest: str,
    receipt_digest: str,
    post_state_digest: str,
    evidence_digest: str,
    database_state_digest: str,
    evidence: Mapping[str, Any],
) -> dict[str, Any]:
    return {
        "backup_digest": backup_digest,
        "classification_digest": plan["classification_digest"],
        "database_state_digest": database_state_digest,
        "evidence_digest": evidence_digest,
        "object_ids": sorted(target.object_id for target in contract.targets),
        "plan_digest": plan["plan_digest"],
        "post_state_digest": post_state_digest,
        "receipt_digest": receipt_digest,
        "relationship_keys": sorted(relation.key for relation in contract.relations),
        "source_bundle_digest": plan["source_snapshot"]["bundle_digest"],
        "source_count": plan["summary"]["source_count"],
        "source_entry_keys": list(contract.source_entry_keys),
        "summary": _result_summary(evidence, audit_delta=1),
        "target_snapshot_digest": plan["target_snapshot_digest"],
    }


def _result_summary(evidence: Mapping[str, Any], *, audit_delta: int) -> dict[str, int]:
    return {
        "objects_changed": len(evidence["objects"]["changed_ids"]),
        "relationships_changed": len(evidence["relationships"]["changed_keys"]),
        "comments_changed": evidence["comments"]["delta"],
        "audits_written": audit_delta,
    }


def _replay_result(details: Mapping[str, Any], *, database_digest: str) -> dict[str, Any]:
    summary = dict(details["summary"])
    summary["objects_changed"] = 0
    summary["relationships_changed"] = 0
    summary["audits_written"] = 0
    return {
        "schema_version": APPLY_SCHEMA_VERSION,
        "mode": "apply",
        "changed": False,
        "replayed": True,
        "classification_digest": details["classification_digest"],
        "target_snapshot_digest": details["target_snapshot_digest"],
        "plan_digest": details["plan_digest"],
        "source_bundle_digest": details["source_bundle_digest"],
        "backup_digest": details["backup_digest"],
        "backup_receipt_digest": details["receipt_digest"],
        "post_state_digest": details["post_state_digest"],
        "database_state_digest": database_digest,
        "summary": summary,
        "evidence": {
            "objects": {"changed_ids": []},
            "relationships": {"changed_keys": []},
            "comments": {"delta": 0},
            "audits": {"delta": 0, "ids": []},
            "coverage": {
                "source_count": details["source_count"],
                "entry_count": len(details["source_entry_keys"]),
            },
            "owner_coverage": {"uncovered_ids": []},
            "integrity": {"relationship_diagnostics": 0, "sqlite": "ok"},
        },
    }


def _create_protected_backup(
    *,
    database_path: Path,
    backup_path: Path,
    database_revision: str,
    manifest: KnowledgeManifest,
    target_snapshot: TargetSnapshot,
    plan: Mapping[str, Any],
) -> tuple[dict[str, Any], str]:
    database_path = database_path.resolve(strict=True)
    backup_path = backup_path.resolve(strict=False)
    receipt_path = backup_path.with_name(f"{backup_path.name}.receipt.json")
    if backup_path == database_path or backup_path.exists() or receipt_path.exists():
        raise KnowledgeApplyError("backup_target_exists")
    if not backup_path.parent.is_dir():
        raise KnowledgeApplyError("backup_parent_invalid")
    parent_stat = backup_path.parent.stat()
    parent_mode = stat.S_IMODE(parent_stat.st_mode)
    if parent_stat.st_uid != os.geteuid() or parent_mode & 0o022:
        raise KnowledgeApplyError("backup_parent_unprotected")
    temporary = backup_path.with_name(f".{backup_path.name}.{os.getpid()}.tmp")
    if temporary.exists():
        raise KnowledgeApplyError("backup_target_exists")
    try:
        with temporary.open("xb"):
            pass
        os.chmod(temporary, 0o600)
        source = sqlite3.connect(f"file:{database_path}?mode=ro", uri=True)
        destination = sqlite3.connect(temporary)
        try:
            source.backup(destination)
            destination.execute("PRAGMA journal_mode=DELETE").fetchone()
        finally:
            source.close()
            destination.close()
        _require_sqlite_file_without_sidecars(temporary)
        _sqlite_integrity(temporary)
        database_state_digest = _sqlite_database_digest(temporary)
        if database_state_digest != _sqlite_database_digest(database_path):
            raise KnowledgeApplyError("backup_source_drift")
        os.chmod(temporary, 0o400)
        os.replace(temporary, backup_path)
    except Exception:
        _remove_restore_candidate(temporary)
        raise
    receipt = {
        "schema_version": 1,
        "mode": "knowledge-apply-backup",
        "plan_digest": plan["plan_digest"],
        "classification_digest": plan["classification_digest"],
        "target_snapshot_digest": target_snapshot.snapshot_digest,
        "source_bundle_digest": manifest.source_snapshot.bundle_digest,
        "backup_file": backup_path.name,
        "backup_sha256": _file_digest(backup_path),
        "database_state_digest": database_state_digest,
        "database_revision": database_revision,
    }
    receipt_bytes = canonical_json_bytes(receipt) + b"\n"
    try:
        with receipt_path.open("xb") as file_handle:
            file_handle.write(receipt_bytes)
            file_handle.flush()
            os.fsync(file_handle.fileno())
        os.chmod(receipt_path, 0o400)
    except Exception:
        receipt_path.unlink(missing_ok=True)
        backup_path.unlink(missing_ok=True)
        raise
    return receipt, hashlib.sha256(receipt_bytes.rstrip(b"\n")).hexdigest()


def _load_receipt(path: Path, expected_digest: str) -> dict[str, Any]:
    _verify_protected_file(path)
    try:
        raw = path.read_bytes()
        payload = json.loads(raw)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise KnowledgeApplyError("invalid_backup_receipt") from exc
    actual = hashlib.sha256(raw.rstrip(b"\n")).hexdigest()
    if actual != expected_digest:
        raise KnowledgeApplyError("receipt_digest_mismatch")
    required = set(backup_receipt_json_schema()["required"])
    if not isinstance(payload, dict) or set(payload) != required:
        raise KnowledgeApplyError("invalid_backup_receipt")
    for key in (
        "plan_digest",
        "classification_digest",
        "target_snapshot_digest",
        "source_bundle_digest",
        "backup_sha256",
        "database_state_digest",
    ):
        _required_digest(payload.get(key), "invalid_backup_receipt")
    if payload.get("schema_version") != 1 or payload.get("mode") != "knowledge-apply-backup":
        raise KnowledgeApplyError("invalid_backup_receipt")
    backup_file = payload.get("backup_file")
    if not isinstance(backup_file, str) or Path(backup_file).name != backup_file:
        raise KnowledgeApplyError("invalid_backup_receipt")
    return payload


def _rollback_preflight(
    database_url: str,
    *,
    principal_id: str,
    plan_digest: str,
    post_state_digest: str,
) -> dict[str, Any]:
    engine = build_read_only_engine(database_url)
    try:
        with Session(engine) as session:
            principal = session.get(Principal, principal_id)
            if (
                principal is None
                or not principal.active
                or principal.catalog_role != CatalogRole.CATALOG_OWNER
            ):
                raise KnowledgeApplyError("authorization_failed")
            rows = list(
                session.scalars(
                    select(AuditEvent)
                    .where(AuditEvent.action == _APPLY_ACTION)
                    .order_by(AuditEvent.id)
                )
            )
            matches = [
                row
                for row in rows
                if _validated_apply_audit(load_audit_details(row))["plan_digest"]
                == plan_digest
            ]
            if len(matches) != 1:
                raise KnowledgeApplyError("rollback_apply_evidence_missing")
            details = _validated_apply_audit(load_audit_details(matches[0]))
            if details.get("post_state_digest") != post_state_digest:
                raise KnowledgeApplyError("rollback_post_state_digest_mismatch")
            return details
    finally:
        engine.dispose()


def _create_restore_candidate(database_path: Path) -> Path:
    """Create a private candidate beside the active database.

    Keeping the candidate in the active database directory makes the final
    replacement a same-filesystem atomic rename.
    """
    file_descriptor, raw_path = tempfile.mkstemp(
        prefix=f".{database_path.name}.rollback-",
        suffix=".sqlite3",
        dir=database_path.parent,
    )
    try:
        os.fchmod(file_descriptor, 0o600)
    except Exception:
        Path(raw_path).unlink(missing_ok=True)
        raise
    finally:
        os.close(file_descriptor)
    return Path(raw_path)


def _copy_backup_to_candidate(backup_path: Path, candidate_path: Path) -> None:
    source = sqlite3.connect(f"file:{backup_path}?mode=ro", uri=True)
    destination = sqlite3.connect(candidate_path)
    try:
        source.backup(destination)
        destination.execute("PRAGMA journal_mode=DELETE").fetchone()
    finally:
        source.close()
        destination.close()


def _write_candidate_rollback_audit(
    candidate_path: Path,
    *,
    principal_id: str,
    receipt: Mapping[str, Any],
    receipt_digest: str,
    plan_digest: str,
    post_state_digest: str,
) -> tuple[int, str, dict[str, Any]]:
    details = {
        "backup_digest": receipt["backup_sha256"],
        "classification_digest": receipt["classification_digest"],
        "plan_digest": plan_digest,
        "post_state_digest": post_state_digest,
        "receipt_digest": receipt_digest,
        "restored_database_state_digest": receipt["database_state_digest"],
        "source_bundle_digest": receipt["source_bundle_digest"],
        "target_snapshot_digest": receipt["target_snapshot_digest"],
        "database_state_digest": "0" * 64,
    }
    _validated_rollback_audit(details)
    connection = sqlite3.connect(candidate_path)
    try:
        connection.execute("BEGIN IMMEDIATE")
        actor = _principal_login_sqlite(connection, principal_id)
        audit_id = _insert_candidate_rollback_audit(connection, actor, details)
        restored_digest = _sqlite_connection_database_digest(connection)
        details["database_state_digest"] = restored_digest
        _validated_rollback_audit(details)
        _update_candidate_rollback_audit(connection, audit_id, details)
        if _sqlite_connection_database_digest(connection) != restored_digest:
            raise KnowledgeApplyError("rollback_evidence_drift")
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()
    return audit_id, restored_digest, details


def _insert_candidate_rollback_audit(
    connection: sqlite3.Connection,
    actor: str,
    details: Mapping[str, Any],
) -> int:
    connection.execute(
        "INSERT INTO audit_events (object_id, action, actor, summary, details_json) "
        "VALUES (NULL, ?, ?, ?, ?)",
        (
            _ROLLBACK_ACTION,
            actor,
            _ROLLBACK_ACTION,
            _rollback_audit_json(details),
        ),
    )
    return int(connection.execute("SELECT last_insert_rowid()").fetchone()[0])


def _update_candidate_rollback_audit(
    connection: sqlite3.Connection,
    audit_id: int,
    details: Mapping[str, Any],
) -> None:
    connection.execute(
        "UPDATE audit_events SET details_json=? WHERE id=?",
        (_rollback_audit_json(details), audit_id),
    )


def _rollback_audit_json(details: Mapping[str, Any]) -> str:
    return json.dumps(
        {"event": _ROLLBACK_ACTION, "version": 1, **dict(details)},
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def _validate_restore_candidate_integrity(candidate_path: Path) -> None:
    try:
        _sqlite_integrity(candidate_path)
    except KnowledgeApplyError as exc:
        raise KnowledgeApplyError("rollback_candidate_integrity_failure") from exc


def _validate_restore_candidate_digest(
    candidate_path: Path,
    expected_digest: str,
    *,
    code: str,
) -> None:
    if _sqlite_database_digest(candidate_path) != expected_digest:
        raise KnowledgeApplyError(code)


def _fsync_restore_candidate(candidate_path: Path) -> None:
    with candidate_path.open("rb") as file_handle:
        os.fsync(file_handle.fileno())


def _fsync_restore_directory(directory: Path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    file_descriptor = os.open(directory, flags)
    try:
        os.fsync(file_descriptor)
    finally:
        os.close(file_descriptor)


def _verify_active_restore_state(
    database_path: Path,
    *,
    expected_database_state_digest: str,
    expected_file_digest: str,
) -> None:
    _require_quiescent_sqlite(database_path)
    if _file_digest(database_path) != expected_file_digest:
        raise KnowledgeApplyError("rollback_database_drift")
    if _sqlite_database_digest(database_path) != expected_database_state_digest:
        raise KnowledgeApplyError("rollback_database_drift")


def _replace_active_database(candidate_path: Path, database_path: Path) -> None:
    os.replace(candidate_path, database_path)


def _readback_restored_database(
    database_path: Path,
    *,
    expected_database_state_digest: str,
    expected_audit_id: int,
    expected_audit_details: Mapping[str, Any],
) -> None:
    _validate_restore_candidate_integrity(database_path)
    _validate_restore_candidate_digest(
        database_path,
        expected_database_state_digest,
        code="rollback_evidence_drift",
    )
    connection = sqlite3.connect(f"file:{database_path}?mode=ro", uri=True)
    try:
        row = connection.execute(
            "SELECT details_json FROM audit_events WHERE id=? AND action=?",
            (expected_audit_id, _ROLLBACK_ACTION),
        ).fetchone()
    finally:
        connection.close()
    if row is None:
        raise KnowledgeApplyError("rollback_audit_missing")
    try:
        details = json.loads(row[0])
    except (TypeError, json.JSONDecodeError) as exc:
        raise KnowledgeApplyError("invalid_rollback_audit") from exc
    expected = {
        "event": _ROLLBACK_ACTION,
        "version": 1,
        **dict(expected_audit_details),
    }
    if details != expected:
        raise KnowledgeApplyError("invalid_rollback_audit")
    _validated_rollback_audit(details)


def _require_quiescent_sqlite(database_path: Path) -> None:
    journal = Path(f"{database_path}-journal")
    wal = Path(f"{database_path}-wal")
    if journal.exists() or (wal.exists() and wal.stat().st_size != 0):
        raise KnowledgeApplyError("rollback_active_sidecars_present")


def _require_sqlite_file_without_sidecars(database_path: Path) -> None:
    if any(
        Path(f"{database_path}{suffix}").exists()
        for suffix in ("-journal", "-shm", "-wal")
    ):
        raise KnowledgeApplyError("backup_sidecars_present")


def _remove_replaced_database_sidecars(database_path: Path) -> None:
    _require_quiescent_sqlite(database_path)
    for suffix in ("-shm", "-wal"):
        Path(f"{database_path}{suffix}").unlink(missing_ok=True)


def _remove_restore_candidate(candidate_path: Path | None) -> None:
    if candidate_path is None:
        return
    candidate_path.unlink(missing_ok=True)
    for suffix in ("-journal", "-shm", "-wal"):
        Path(f"{candidate_path}{suffix}").unlink(missing_ok=True)


def _persistent_sqlite_path(database_url: str) -> Path:
    url = make_url(database_url)
    if url.get_backend_name() != "sqlite" or not url.database:
        raise KnowledgeApplyError("protected_sqlite_backup_required")
    path = _sqlite_database_path(str(url.database))
    if str(path) == ":memory:" or not path.exists() or not path.is_file():
        raise KnowledgeApplyError("persistent_sqlite_required")
    return path


def _verify_protected_file(path: Path) -> None:
    try:
        mode = stat.S_IMODE(path.stat().st_mode)
    except OSError as exc:
        raise KnowledgeApplyError("protected_file_missing") from exc
    if not path.is_file() or path.is_symlink() or mode & 0o222:
        raise KnowledgeApplyError("protected_file_invalid")


def _sqlite_integrity(path: Path) -> None:
    connection = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        row = connection.execute("PRAGMA integrity_check").fetchone()
        foreign_key = connection.execute("PRAGMA foreign_key_check").fetchone()
    finally:
        connection.close()
    if row != ("ok",) or foreign_key is not None:
        raise KnowledgeApplyError("backup_integrity_failure")


def _sqlite_database_digest(path: Path) -> str:
    connection = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        return _sqlite_connection_database_digest(connection)
    finally:
        connection.close()


def _sqlite_connection_digest(session: Session) -> str:
    raw = session.connection().connection.driver_connection
    return _sqlite_connection_database_digest(raw)


def _sqlite_connection_database_digest(connection: sqlite3.Connection) -> str:
    digest = hashlib.sha256(b"blockwart:knowledge:sqlite-database:v1\n")
    tables = [
        str(row[0])
        for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table' "
            "AND name NOT LIKE 'sqlite_%' ORDER BY name"
        )
    ]
    for table in tables:
        quoted = table.replace('"', '""')
        schema = connection.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name=?", (table,)
        ).fetchone()[0]
        digest.update(_cell_bytes(table))
        digest.update(_cell_bytes(schema))
        row_hashes: list[bytes] = []
        columns = [
            str(column[1])
            for column in connection.execute(f'PRAGMA table_info("{quoted}")')
        ]
        for row in connection.execute(f'SELECT * FROM "{quoted}"'):
            values = list(row)
            if table == "audit_events":
                values = _normalized_audit_digest_row(columns, values)
            row_digest = hashlib.sha256()
            for value in values:
                row_digest.update(_cell_bytes(value))
            row_hashes.append(row_digest.digest())
        for row_hash in sorted(row_hashes):
            digest.update(row_hash)
    return digest.hexdigest()


def _cell_bytes(value: Any) -> bytes:
    if value is None:
        payload = b""
        kind = b"n"
    elif isinstance(value, bytes):
        payload = value
        kind = b"b"
    else:
        payload = str(value).encode("utf-8")
        kind = type(value).__name__.encode("ascii")
    return kind + b":" + str(len(payload)).encode("ascii") + b":" + payload + b";"


def _normalized_audit_digest_row(columns: Sequence[str], values: list[Any]) -> list[Any]:
    try:
        action_index = columns.index("action")
        details_index = columns.index("details_json")
    except ValueError:
        return values
    if values[action_index] not in {_APPLY_ACTION, _ROLLBACK_ACTION}:
        return values
    try:
        details = json.loads(values[details_index])
    except (TypeError, json.JSONDecodeError):
        return values
    if not isinstance(details, dict) or "database_state_digest" not in details:
        return values
    details["database_state_digest"] = "0" * 64
    values[details_index] = json.dumps(
        details,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )
    return values


def _validated_apply_audit(details: Mapping[str, Any]) -> dict[str, Any]:
    digest_fields = (
        "backup_digest",
        "classification_digest",
        "database_state_digest",
        "evidence_digest",
        "plan_digest",
        "post_state_digest",
        "receipt_digest",
        "source_bundle_digest",
        "target_snapshot_digest",
    )
    try:
        for field in digest_fields:
            _required_digest(details.get(field), "invalid_apply_audit")
        source_entry_keys = details["source_entry_keys"]
        object_ids = details["object_ids"]
        relationship_keys = details["relationship_keys"]
        summary = details["summary"]
        source_count = details["source_count"]
    except (KeyError, TypeError) as exc:
        raise KnowledgeApplyError("invalid_apply_audit") from exc
    if (
        not isinstance(source_entry_keys, list)
        or len(source_entry_keys) > _MAX_SOURCE_ENTRIES
        or not all(isinstance(value, str) for value in source_entry_keys)
        or len(set(source_entry_keys)) != len(source_entry_keys)
        or not isinstance(object_ids, list)
        or len(object_ids) > _MAX_TARGETS
        or not all(isinstance(value, str) for value in object_ids)
        or not isinstance(relationship_keys, list)
        or len(relationship_keys) > _MAX_RELATIONSHIPS
        or not all(_valid_relationship_audit_key(value) for value in relationship_keys)
        or not isinstance(summary, Mapping)
        or not isinstance(source_count, int)
        or source_count < 1
    ):
        raise KnowledgeApplyError("invalid_apply_audit")
    return dict(details)


def _valid_relationship_audit_key(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    from_ref, separator, remainder = value.partition("|")
    relation_type, separator_two, remainder = remainder.partition("|")
    to_ref, separator_three, metadata_digest = remainder.partition("|")
    return bool(
        separator
        and separator_two
        and separator_three
        and from_ref
        and relation_type
        and to_ref
        and len(metadata_digest) == 64
        and not set(metadata_digest) - _HEX64
    )


def _validated_rollback_audit(details: Mapping[str, Any]) -> dict[str, Any]:
    digest_fields = {
        "backup_digest",
        "classification_digest",
        "database_state_digest",
        "plan_digest",
        "post_state_digest",
        "receipt_digest",
        "restored_database_state_digest",
        "source_bundle_digest",
        "target_snapshot_digest",
    }
    keys = set(details)
    if keys == digest_fields | {"event", "version"}:
        if details.get("event") != _ROLLBACK_ACTION or details.get("version") != 1:
            raise KnowledgeApplyError("invalid_rollback_audit")
    elif keys != digest_fields:
        raise KnowledgeApplyError("invalid_rollback_audit")
    for field in digest_fields:
        _required_digest(details.get(field), "invalid_rollback_audit")
    return dict(details)


def _replace_audit_details(row: AuditEvent, details: Mapping[str, Any]) -> None:
    row.details_json = json.dumps(
        {"event": row.action, "version": 1, **dict(details)},
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def _file_digest(path: Path) -> str:
    with path.open("rb") as file_handle:
        return hashlib.file_digest(file_handle, "sha256").hexdigest()


def _principal_login(session: Session, principal_id: str) -> str:
    row = session.get(Principal, principal_id)
    if row is None:
        raise KnowledgeApplyError("authorization_failed")
    return str(row.login)


def _principal_login_sqlite(connection: sqlite3.Connection, principal_id: str) -> str:
    row = connection.execute(
        "SELECT login, active, catalog_role FROM principals WHERE id=?", (principal_id,)
    ).fetchone()
    if row is None or not bool(row[1]) or row[2] != CatalogRole.CATALOG_OWNER:
        raise KnowledgeApplyError("authorization_failed")
    return str(row[0])


def _required_digest(value: Any, code: str) -> str:
    if not isinstance(value, str) or len(value) != 64 or set(value) - _HEX64:
        raise KnowledgeApplyError(code)
    return value


def _digest_schema() -> dict[str, Any]:
    return {"pattern": "^[0-9a-f]{64}$", "type": "string"}


def _closed_result_schema(title: str, modes: tuple[str, ...]) -> dict[str, Any]:
    properties: dict[str, Any] = {
        "schema_version": {"const": 1, "type": "integer"},
        "mode": {"enum": list(modes), "type": "string"},
        "changed": {"type": "boolean"},
        "replayed": {"type": "boolean"},
        "classification_digest": _digest_schema(),
        "target_snapshot_digest": _digest_schema(),
        "plan_digest": _digest_schema(),
        "source_bundle_digest": _digest_schema(),
        "backup_digest": _digest_schema(),
        "backup_receipt_digest": _digest_schema(),
        "post_state_digest": _digest_schema(),
        "database_state_digest": _digest_schema(),
        "summary": {"type": "object"},
        "evidence": {"type": "object"},
    }
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "additionalProperties": False,
        "properties": properties,
        "required": list(properties),
        "title": title,
        "type": "object",
    }
