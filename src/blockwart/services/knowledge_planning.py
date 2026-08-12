from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from collections.abc import Mapping, Sequence
from copy import deepcopy
from pathlib import Path, PurePosixPath
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator
from yaml.constructor import ConstructorError
from yaml.nodes import MappingNode

from blockwart.domain.references import TypedReference
from blockwart.domain.relationships import (
    RelationshipIntegrityError,
    validate_data_references,
    validate_relationship_request,
)
from blockwart.domain.security import find_acl_data_violations, find_secret_violations
from blockwart.schemas.catalog import CatalogObjectIn

MANIFEST_SCHEMA_VERSION = 1
TARGET_SCHEMA_VERSION = 1
OUTPUT_SCHEMA_VERSION = 1
PLANNER_VERSION = "1"

DISPOSITIONS = (
    "asset_fact",
    "runbook",
    "decision",
    "project_research",
    "external_document",
    "historical",
    "retired",
    "migration",
    "ignored",
)
TARGET_KINDS = ("host", "system", "network", "device", "service", "runbook", "decision", "project")
ASSET_KINDS = frozenset({"host", "system", "network", "device", "service"})
ACTIONABLE_DISPOSITIONS = frozenset({"asset_fact", "runbook", "decision", "project_research"})
NON_CURRENT_DISPOSITIONS = frozenset(
    {"external_document", "historical", "retired", "migration", "ignored"}
)
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_GIT_HASH = re.compile(r"^[0-9a-f]{40,64}$")
_STABLE_ID = re.compile(r"^[a-z0-9][a-z0-9._/-]{0,126}[a-z0-9]$|^[a-z0-9]$")
_OBJECT_ID = re.compile(r"^[a-z0-9][a-z0-9_-]*[a-z0-9]$|^[a-z0-9]$")
_TARGET_PATH = re.compile(
    r"^(label|status|summary|lifecycle|health|data\.[A-Za-z0-9_.-]+|provenance\.[A-Za-z0-9_.-]+)$"
)


class KnowledgePlanError(RuntimeError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class _ContractModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ImplementationBinding(_ContractModel):
    commit: str
    tree: str

    @field_validator("commit", "tree")
    @classmethod
    def validate_git_hash(cls, value: str) -> str:
        if _GIT_HASH.fullmatch(value) is None:
            raise ValueError("implementation identifiers must be lowercase Git hashes")
        return value


class ClosedDirectory(_ContractModel):
    relative_path: str
    suffix: str = ".md"

    @field_validator("relative_path")
    @classmethod
    def validate_path(cls, value: str) -> str:
        return _relative_path(value, allow_file=False)

    @field_validator("suffix")
    @classmethod
    def validate_suffix(cls, value: str) -> str:
        if not value.startswith(".") or "/" in value or len(value) > 16:
            raise ValueError("closed-directory suffix is invalid")
        return value


class SourceDocument(_ContractModel):
    source_id: str
    relative_path: str
    sha256: str
    entry_ids: list[str] = Field(min_length=1)

    @field_validator("source_id")
    @classmethod
    def validate_source_id(cls, value: str) -> str:
        return _stable_id(value)

    @field_validator("relative_path")
    @classmethod
    def validate_path(cls, value: str) -> str:
        return _relative_path(value, allow_file=True)

    @field_validator("sha256")
    @classmethod
    def validate_hash(cls, value: str) -> str:
        return _sha256(value)

    @field_validator("entry_ids")
    @classmethod
    def validate_entry_ids(cls, values: list[str]) -> list[str]:
        normalized = [_stable_id(value) for value in values]
        if len(set(normalized)) != len(normalized):
            raise ValueError("document entry IDs must be unique")
        return normalized


class SourceSnapshot(_ContractModel):
    schema_version: Literal[1]
    bundle_digest: str
    expected_document_count: int = Field(ge=1)
    expected_entry_count: int = Field(ge=1)
    closed_directories: list[ClosedDirectory] = Field(default_factory=list)
    documents: list[SourceDocument] = Field(min_length=1)

    @field_validator("bundle_digest")
    @classmethod
    def validate_hash(cls, value: str) -> str:
        return _sha256(value)

    @model_validator(mode="after")
    def validate_inventory(self) -> SourceSnapshot:
        source_ids = [item.source_id for item in self.documents]
        paths = [item.relative_path for item in self.documents]
        if len(set(source_ids)) != len(source_ids) or len(set(paths)) != len(paths):
            raise ValueError("source documents must have unique IDs and paths")
        if self.expected_document_count != len(self.documents):
            raise ValueError("source document coverage count is incomplete")
        if self.expected_entry_count != sum(len(item.entry_ids) for item in self.documents):
            raise ValueError("source entry coverage count is incomplete")
        closed = [item.relative_path for item in self.closed_directories]
        if len(set(closed)) != len(closed):
            raise ValueError("closed directories must be unique")
        return self


class UnsafeFinding(_ContractModel):
    code: str
    location: str

    @field_validator("code", "location")
    @classmethod
    def validate_identifier(cls, value: str) -> str:
        return _stable_id(value)


class FieldMapping(_ContractModel):
    source_locator: str
    target_path: str
    evidence: Literal["explicit"]
    value: Any

    @field_validator("source_locator")
    @classmethod
    def validate_locator(cls, value: str) -> str:
        return _stable_id(value)

    @field_validator("target_path")
    @classmethod
    def validate_target_path(cls, value: str) -> str:
        if _TARGET_PATH.fullmatch(value) is None:
            raise ValueError("field mapping target path is not allowed")
        return value


class PlannedTarget(_ContractModel):
    object_id: str
    kind: Literal[
        "host", "system", "network", "device", "service", "runbook", "decision", "project"
    ]

    @field_validator("object_id")
    @classmethod
    def validate_object_id(cls, value: str) -> str:
        if _OBJECT_ID.fullmatch(value) is None:
            raise ValueError("target object ID is unstable")
        return value

    @property
    def ref(self) -> str:
        return f"{self.kind}:{self.object_id}"


class PlannedRelation(_ContractModel):
    from_ref: str
    relation_type: str
    to_ref: str
    metadata: dict[str, Any] = Field(default_factory=dict)
    source_locator: str
    evidence: Literal["explicit"]

    @field_validator("source_locator")
    @classmethod
    def validate_locator(cls, value: str) -> str:
        return _stable_id(value)

    @model_validator(mode="after")
    def validate_contract(self) -> PlannedRelation:
        validate_relationship_request(
            from_ref=self.from_ref,
            relation_type=self.relation_type,
            to_ref=self.to_ref,
            metadata=self.metadata,
        )
        if self.relation_type not in {"documents", "uses", "related_to"}:
            raise ValueError("knowledge plans allow only non-operational typed relations")
        return self

    @property
    def key(self) -> tuple[str, str, str, str]:
        return (
            self.from_ref,
            self.relation_type,
            self.to_ref,
            canonical_json_text(self.metadata),
        )


class ClassificationEntry(_ContractModel):
    entry_id: str
    source_id: str
    disposition: Literal[
        "asset_fact",
        "runbook",
        "decision",
        "project_research",
        "external_document",
        "historical",
        "retired",
        "migration",
        "ignored",
    ]
    target: PlannedTarget | None = None
    field_mappings: list[FieldMapping] = Field(default_factory=list)
    relations: list[PlannedRelation] = Field(default_factory=list)
    provenance_state: Literal["explicit", "preserve_existing", "unknown", "not_applicable"]
    ambiguity_state: Literal["clear", "unresolved"]
    conflict_state: Literal["none", "unresolved"]
    missing_requirements: list[str] = Field(default_factory=list)
    unsafe_findings: list[UnsafeFinding] = Field(default_factory=list)
    review_rationale: str = Field(min_length=1, max_length=500)

    @field_validator("entry_id", "source_id")
    @classmethod
    def validate_id(cls, value: str) -> str:
        return _stable_id(value)

    @field_validator("missing_requirements")
    @classmethod
    def validate_requirements(cls, values: list[str]) -> list[str]:
        normalized = [_stable_id(value) for value in values]
        if len(set(normalized)) != len(normalized):
            raise ValueError("missing requirements must be unique")
        return normalized

    @model_validator(mode="after")
    def validate_disposition(self) -> ClassificationEntry:
        if self.disposition in NON_CURRENT_DISPOSITIONS:
            if self.target is not None or self.field_mappings or self.relations:
                raise ValueError("external and non-current entries cannot plan writes")
            if self.provenance_state not in {"not_applicable", "unknown"}:
                raise ValueError("external and non-current provenance must remain non-canonical")
        else:
            if self.target is None and not self.is_blocked:
                raise ValueError("actionable entries require a target or an exact blocker")
            if self.target is not None:
                expected_kind: str | frozenset[str] = {
                    "asset_fact": ASSET_KINDS,
                    "runbook": "runbook",
                    "decision": "decision",
                    "project_research": "project",
                }[self.disposition]
                if isinstance(expected_kind, str):
                    valid = self.target.kind == expected_kind
                else:
                    valid = self.target.kind in expected_kind
                if not valid:
                    raise ValueError("target kind does not match disposition")
                for relation in self.relations:
                    if self.target.ref not in {relation.from_ref, relation.to_ref}:
                        raise ValueError("planned relation must include its target")
        if self.provenance_state == "explicit" and not any(
            item.target_path.startswith("provenance.") for item in self.field_mappings
        ):
            raise ValueError("explicit provenance requires an explicit provenance field mapping")
        if find_secret_violations(self.model_dump()) or find_acl_data_violations(
            {item.target_path: item.value for item in self.field_mappings}
        ):
            raise ValueError("classification entry contains unsafe content")
        return self

    @property
    def is_blocked(self) -> bool:
        return bool(
            self.missing_requirements
            or self.unsafe_findings
            or self.ambiguity_state == "unresolved"
            or self.conflict_state == "unresolved"
        )


class KnowledgeManifest(_ContractModel):
    schema_version: Literal[1]
    planner_version: Literal["1"]
    implementation: ImplementationBinding
    source_snapshot: SourceSnapshot
    entries: list[ClassificationEntry] = Field(min_length=1)

    @model_validator(mode="after")
    def validate_coverage(self) -> KnowledgeManifest:
        entries_by_id = {item.entry_id: item for item in self.entries}
        if len(entries_by_id) != len(self.entries):
            raise ValueError("classification entry IDs must be unique")
        declared: dict[str, str] = {}
        for document in self.source_snapshot.documents:
            for entry_id in document.entry_ids:
                if entry_id in declared:
                    raise ValueError("source entry is declared more than once")
                declared[entry_id] = document.source_id
        if set(declared) != set(entries_by_id):
            raise ValueError("classification coverage must be exact")
        for entry_id, source_id in declared.items():
            if entries_by_id[entry_id].source_id != source_id:
                raise ValueError("classification source ID does not match its document")
        target_mappings: dict[tuple[str, str], str] = {}
        for entry in self.entries:
            if entry.target is None:
                continue
            for mapping in entry.field_mappings:
                key = (entry.target.ref, mapping.target_path)
                value = canonical_json_text(mapping.value)
                previous = target_mappings.setdefault(key, value)
                if previous != value:
                    raise ValueError("conflicting target field mappings are forbidden")
        return self


class TargetObjectState(_ContractModel):
    ref: str
    state: Literal["present", "absent"]
    revision: int | None = Field(default=None, ge=1)
    object: dict[str, Any] | None = None

    @model_validator(mode="after")
    def validate_state(self) -> TargetObjectState:
        typed = TypedReference.parse(self.ref)
        if self.state == "absent":
            if self.revision is not None or self.object is not None:
                raise ValueError("absent target evidence cannot carry object state")
            return self
        if self.revision is None or self.object is None:
            raise ValueError("present target evidence requires revision and object")
        allowed = {
            "id",
            "kind",
            "label",
            "status",
            "lifecycle",
            "health",
            "summary",
            "data",
            "provenance",
        }
        if set(self.object) - allowed:
            raise ValueError("target object contains unknown fields")
        candidate = CatalogObjectIn.model_validate(self.object)
        if candidate.id != typed.object_id or candidate.kind != typed.kind:
            raise ValueError("target object identity does not match its typed reference")
        self.object = candidate.model_dump(mode="json")
        return self


class TargetRelationshipState(_ContractModel):
    from_ref: str
    relation_type: str
    to_ref: str
    metadata: dict[str, Any] = Field(default_factory=dict)
    present: bool

    @model_validator(mode="after")
    def validate_contract(self) -> TargetRelationshipState:
        self.metadata = validate_relationship_request(
            from_ref=self.from_ref,
            relation_type=self.relation_type,
            to_ref=self.to_ref,
            metadata=self.metadata,
        )
        return self

    @property
    def key(self) -> tuple[str, str, str, str]:
        return (
            self.from_ref,
            self.relation_type,
            self.to_ref,
            canonical_json_text(self.metadata),
        )


class TargetSnapshot(_ContractModel):
    schema_version: Literal[1]
    planner_version: Literal["1"]
    implementation: ImplementationBinding
    snapshot_digest: str
    objects: list[TargetObjectState]
    relationships: list[TargetRelationshipState]

    @field_validator("snapshot_digest")
    @classmethod
    def validate_hash(cls, value: str) -> str:
        return _sha256(value)

    @model_validator(mode="after")
    def validate_uniqueness(self) -> TargetSnapshot:
        refs = [item.ref for item in self.objects]
        keys = [item.key for item in self.relationships]
        if len(set(refs)) != len(refs) or len(set(keys)) != len(keys):
            raise ValueError("target snapshot evidence must be unique")
        return self

    def digest_payload(self) -> dict[str, Any]:
        payload = self.model_dump(mode="json", exclude={"snapshot_digest"})
        payload["objects"] = sorted(payload["objects"], key=lambda item: item["ref"])
        payload["relationships"] = sorted(
            payload["relationships"],
            key=lambda item: (
                item["from_ref"],
                item["relation_type"],
                item["to_ref"],
                canonical_json_text(item["metadata"]),
            ),
        )
        return payload


class _UniqueKeySafeLoader(yaml.SafeLoader):
    def construct_mapping(self, node: MappingNode, deep: bool = False) -> dict[Any, Any]:
        self.flatten_mapping(node)
        result: dict[Any, Any] = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            try:
                duplicate = key in result
            except TypeError as exc:
                raise ConstructorError(
                    "while constructing a mapping",
                    node.start_mark,
                    "found an unhashable mapping key",
                    key_node.start_mark,
                ) from exc
            if duplicate:
                raise ConstructorError(
                    "while constructing a mapping",
                    node.start_mark,
                    "found a duplicate mapping key",
                    key_node.start_mark,
                )
            result[key] = self.construct_object(value_node, deep=deep)
        return result


def load_manifest(path: str | Path) -> KnowledgeManifest:
    payload = _load_document(path, "invalid_manifest")
    if find_secret_violations(payload):
        raise KnowledgePlanError("unsafe_manifest")
    try:
        return KnowledgeManifest.model_validate(payload)
    except (ValidationError, RelationshipIntegrityError, ValueError) as exc:
        raise KnowledgePlanError("invalid_manifest") from exc


def load_target_snapshot(path: str | Path) -> TargetSnapshot:
    payload = _load_document(path, "invalid_target_snapshot")
    if find_secret_violations(payload):
        raise KnowledgePlanError("unsafe_target_snapshot")
    try:
        snapshot = TargetSnapshot.model_validate(payload)
    except (ValidationError, RelationshipIntegrityError, ValueError) as exc:
        raise KnowledgePlanError("invalid_target_snapshot") from exc
    actual = domain_digest("target-snapshot", snapshot.digest_payload())
    if actual != snapshot.snapshot_digest:
        raise KnowledgePlanError("target_snapshot_drift")
    return snapshot


def verify_source_snapshot(source_root: str | Path, snapshot: SourceSnapshot) -> None:
    root = Path(source_root)
    try:
        resolved_root = root.resolve(strict=True)
    except OSError as exc:
        raise KnowledgePlanError("source_root_unreadable") from exc
    if not resolved_root.is_dir():
        raise KnowledgePlanError("source_root_unreadable")
    expected_paths = {item.relative_path for item in snapshot.documents}
    for closed in snapshot.closed_directories:
        directory = resolved_root / closed.relative_path
        try:
            if directory.is_symlink() or not directory.is_dir():
                raise KnowledgePlanError("source_set_drift")
            actual = {
                item.relative_to(resolved_root).as_posix()
                for item in directory.iterdir()
                if item.is_file() and item.name.endswith(closed.suffix)
            }
        except OSError as exc:
            raise KnowledgePlanError("source_set_drift") from exc
        scoped_expected = {
            path
            for path in expected_paths
            if PurePosixPath(path).parent.as_posix() == closed.relative_path
            and path.endswith(closed.suffix)
        }
        if actual != scoped_expected:
            raise KnowledgePlanError("source_set_drift")
    hash_lines: list[str] = []
    for document in sorted(snapshot.documents, key=lambda item: item.relative_path):
        path = resolved_root / document.relative_path
        try:
            if (
                path.is_symlink()
                or not path.is_file()
                or not path.resolve().is_relative_to(resolved_root)
            ):
                raise KnowledgePlanError("source_set_drift")
            actual_hash = hashlib.sha256(path.read_bytes()).hexdigest()
        except OSError as exc:
            raise KnowledgePlanError("source_drift") from exc
        if actual_hash != document.sha256:
            raise KnowledgePlanError("source_drift")
        hash_lines.append(f"{actual_hash}  {document.relative_path}\n")
    actual_bundle = hashlib.sha256("".join(hash_lines).encode()).hexdigest()
    if actual_bundle != snapshot.bundle_digest:
        raise KnowledgePlanError("source_drift")


def build_knowledge_plan(
    manifest: KnowledgeManifest,
    *,
    source_root: str | Path,
    implementation_commit: str,
    implementation_tree: str,
    target_snapshot: TargetSnapshot | None = None,
    expected_target_digest: str | None = None,
) -> dict[str, Any]:
    if (
        manifest.implementation.commit != implementation_commit
        or manifest.implementation.tree != implementation_tree
    ):
        raise KnowledgePlanError("implementation_drift")
    verify_source_snapshot(source_root, manifest.source_snapshot)
    classification_digest = domain_digest(
        "classification-manifest", _manifest_digest_payload(manifest)
    )
    if target_snapshot is not None:
        if target_snapshot.implementation != manifest.implementation:
            raise KnowledgePlanError("implementation_drift")
        if expected_target_digest is not None:
            if _HEX64.fullmatch(expected_target_digest) is None:
                raise KnowledgePlanError("invalid_target_digest")
            if target_snapshot.snapshot_digest != expected_target_digest:
                raise KnowledgePlanError("target_snapshot_drift")

    entries = sorted(manifest.entries, key=lambda item: item.entry_id)
    blockers: list[dict[str, str]] = []
    entry_results: list[dict[str, Any]] = []
    for entry in entries:
        entry_blockers: list[dict[str, str]] = []
        for requirement in sorted(entry.missing_requirements):
            entry_blockers.append(
                {
                    "code": "missing_requirement",
                    "entry_id": entry.entry_id,
                    "requirement": requirement,
                }
            )
        if entry.ambiguity_state == "unresolved":
            entry_blockers.append({"code": "unresolved_ambiguity", "entry_id": entry.entry_id})
        if entry.conflict_state == "unresolved":
            entry_blockers.append({"code": "unresolved_conflict", "entry_id": entry.entry_id})
        for finding in sorted(entry.unsafe_findings, key=lambda item: (item.location, item.code)):
            entry_blockers.append(
                {
                    "code": "unsafe_finding",
                    "entry_id": entry.entry_id,
                    "finding_code": finding.code,
                    "location": finding.location,
                }
            )
        blockers.extend(entry_blockers)
        entry_results.append(
            {
                "entry_id": entry.entry_id,
                "source_id": entry.source_id,
                "disposition": entry.disposition,
                "target_ref": None if entry.target is None else entry.target.ref,
                "provenance_state": entry.provenance_state,
                "ambiguity_state": entry.ambiguity_state,
                "conflict_state": entry.conflict_state,
                "missing_requirements": sorted(entry.missing_requirements),
                "unsafe_findings": [
                    item.model_dump(mode="json")
                    for item in sorted(
                        entry.unsafe_findings, key=lambda item: (item.location, item.code)
                    )
                ],
                "review_rationale": entry.review_rationale,
            }
        )

    grouped = _group_targets(entries, blockers)
    complete_target_snapshot = target_snapshot is not None
    target_digest: str | None = None
    relationship_counts = Counter({"new": 0, "unchanged": 0, "removed": 0})
    target_results: list[dict[str, Any]] = []
    missing_target_evidence = 0
    if target_snapshot is None:
        blockers.append({"code": "missing_target_snapshot"})
        complete_target_snapshot = False
        missing_target_evidence = 1
        for target_ref, group in sorted(grouped.items()):
            target_results.append(_target_result(group, target_ref, "blocked", []))
    else:
        target_digest = target_snapshot.snapshot_digest
        target_results, target_blockers, relationship_counts, complete_target_snapshot = (
            _resolve_targets(grouped, target_snapshot)
        )
        blockers.extend(target_blockers)
        missing_target_evidence = sum(
            item["code"] == "missing_target_evidence" for item in target_blockers
        )

    blockers = sorted(blockers, key=canonical_json_text)
    plan_digest = None
    if target_snapshot is not None and complete_target_snapshot:
        plan_digest = domain_digest(
            "apply-ready-plan",
            {
                "classification_digest": classification_digest,
                "implementation": manifest.implementation.model_dump(mode="json"),
                "manifest_schema_version": MANIFEST_SCHEMA_VERSION,
                "output_schema_version": OUTPUT_SCHEMA_VERSION,
                "planner_version": PLANNER_VERSION,
                "target_schema_version": TARGET_SCHEMA_VERSION,
                "target_snapshot_digest": target_snapshot.snapshot_digest,
            },
        )
    action_counts = Counter(item["action"] for item in target_results)
    disposition_counts = Counter(item.disposition for item in entries)
    target_kind_counts = Counter(group["kind"] for group in grouped.values())
    unsafe_count = sum(len(item.unsafe_findings) for item in entries)
    skipped_count = sum(item.disposition in NON_CURRENT_DISPOSITIONS for item in entries)
    apply_ready = bool(plan_digest is not None and not blockers)
    return {
        "schema_version": OUTPUT_SCHEMA_VERSION,
        "planner_version": PLANNER_VERSION,
        "mode": "dry-run",
        "mutation_capabilities": [],
        "implementation": manifest.implementation.model_dump(mode="json"),
        "source_snapshot": {
            "bundle_digest": manifest.source_snapshot.bundle_digest,
            "document_count": manifest.source_snapshot.expected_document_count,
            "entry_count": manifest.source_snapshot.expected_entry_count,
        },
        "summary": {
            "source_count": manifest.source_snapshot.expected_document_count,
            "entry_count": manifest.source_snapshot.expected_entry_count,
            "disposition_counts": {key: disposition_counts[key] for key in DISPOSITIONS},
            "planned_target_counts_by_kind": {key: target_kind_counts[key] for key in TARGET_KINDS},
            "new_count": action_counts["new"],
            "update_count": action_counts["update"],
            "unchanged_count": action_counts["unchanged"],
            "skipped_count": skipped_count,
            "conflict_count": sum(item["code"] == "unresolved_conflict" for item in blockers),
            "blocker_count": len(blockers),
            "relationship_deltas": {
                "new": relationship_counts["new"],
                "unchanged": relationship_counts["unchanged"],
                "removed": 0,
            },
            "comment_delta": 0,
            "audit_delta": 0,
            "expected_coverage": {
                "documents": manifest.source_snapshot.expected_document_count,
                "entries": manifest.source_snapshot.expected_entry_count,
                "covered_documents": len(manifest.source_snapshot.documents),
                "covered_entries": len(entries),
            },
            "unsafe_finding_count": unsafe_count,
            "missing_target_evidence_count": missing_target_evidence,
        },
        "entries": entry_results,
        "targets": sorted(target_results, key=lambda item: item["target_ref"]),
        "blockers": blockers,
        "classification_digest": classification_digest,
        "target_snapshot_digest": target_digest,
        "plan_digest": plan_digest,
        "apply_ready": apply_ready,
    }


def result_summary(result: Mapping[str, Any]) -> str:
    summary = result["summary"]
    plan_digest = result["plan_digest"] or "absent"
    reason = "none" if result["plan_digest"] else _missing_plan_reason(result)
    return (
        "knowledge_plan mode=dry-run "
        f"sources={summary['source_count']} entries={summary['entry_count']} "
        f"targets={sum(summary['planned_target_counts_by_kind'].values())} "
        f"new={summary['new_count']} update={summary['update_count']} "
        f"unchanged={summary['unchanged_count']} skipped={summary['skipped_count']} "
        f"conflicts={summary['conflict_count']} blockers={summary['blocker_count']} "
        f"relationships_new={summary['relationship_deltas']['new']} "
        f"comments=0 audits=0 apply_ready={str(result['apply_ready']).lower()} "
        f"classification_digest={result['classification_digest']} "
        f"plan_digest={plan_digest} plan_digest_reason={reason}"
    )


def manifest_json_schema() -> dict[str, Any]:
    return KnowledgeManifest.model_json_schema()


def target_snapshot_json_schema() -> dict[str, Any]:
    return TargetSnapshot.model_json_schema()


def result_json_schema() -> dict[str, Any]:
    """Return the closed top-level v1 result contract.

    Nested planning records are intentionally JSON values owned by this same
    implementation; the closed top level prevents a consumer from confusing a
    future envelope with version 1.
    """
    properties: dict[str, Any] = {
        "schema_version": {"const": OUTPUT_SCHEMA_VERSION, "type": "integer"},
        "planner_version": {"const": PLANNER_VERSION, "type": "string"},
        "mode": {"const": "dry-run", "type": "string"},
        "mutation_capabilities": {"maxItems": 0, "type": "array"},
        "implementation": {"type": "object"},
        "source_snapshot": {"type": "object"},
        "summary": {"type": "object"},
        "entries": {"items": {"type": "object"}, "type": "array"},
        "targets": {"items": {"type": "object"}, "type": "array"},
        "blockers": {"items": {"type": "object"}, "type": "array"},
        "classification_digest": {"pattern": "^[0-9a-f]{64}$", "type": "string"},
        "target_snapshot_digest": {
            "anyOf": [
                {"pattern": "^[0-9a-f]{64}$", "type": "string"},
                {"type": "null"},
            ]
        },
        "plan_digest": {
            "anyOf": [
                {"pattern": "^[0-9a-f]{64}$", "type": "string"},
                {"type": "null"},
            ]
        },
        "apply_ready": {"type": "boolean"},
    }
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "additionalProperties": False,
        "properties": properties,
        "required": list(properties),
        "title": "BlockwartKnowledgePlanResultV1",
        "type": "object",
    }


def canonical_json_bytes(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise KnowledgePlanError("non_canonical_json") from exc


def canonical_json_text(value: Any) -> str:
    return canonical_json_bytes(value).decode("utf-8")


def domain_digest(domain: str, value: Any) -> str:
    prefix = f"blockwart:knowledge:{domain}:v1\n".encode()
    return hashlib.sha256(prefix + canonical_json_bytes(value)).hexdigest()


def target_snapshot_digest(payload: Mapping[str, Any]) -> str:
    try:
        sanitized = dict(payload)
        sanitized["snapshot_digest"] = "0" * 64
        snapshot = TargetSnapshot.model_validate(sanitized)
    except (ValidationError, RelationshipIntegrityError, ValueError) as exc:
        raise KnowledgePlanError("invalid_target_snapshot") from exc
    return domain_digest("target-snapshot", snapshot.digest_payload())


def _load_document(path: str | Path, code: str) -> Any:
    try:
        text = Path(path).read_text(encoding="utf-8")
        if str(path).lower().endswith(".json"):
            return json.loads(text, object_pairs_hook=_unique_json_object)
        return yaml.load(text, Loader=_UniqueKeySafeLoader)
    except (OSError, UnicodeError, json.JSONDecodeError, yaml.YAMLError, ValueError) as exc:
        raise KnowledgePlanError(code) from exc


def _unique_json_object(pairs: Sequence[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _relative_path(value: str, *, allow_file: bool) -> str:
    path = PurePosixPath(value)
    if not value or path.is_absolute() or ".." in path.parts or "." in path.parts:
        raise ValueError("source path must be a stable relative POSIX path")
    if path.as_posix() != value or (not allow_file and value.endswith("/")):
        raise ValueError("source path is not canonical")
    return value


def _stable_id(value: str) -> str:
    if _STABLE_ID.fullmatch(value) is None or "//" in value:
        raise ValueError("identifier is not stable")
    return value


def _sha256(value: str) -> str:
    if _HEX64.fullmatch(value) is None:
        raise ValueError("SHA-256 must be lowercase hexadecimal")
    return value


def _group_targets(
    entries: Sequence[ClassificationEntry],
    blockers: list[dict[str, str]],
) -> dict[str, dict[str, Any]]:
    grouped: dict[str, dict[str, Any]] = {}
    for entry in entries:
        if entry.target is None:
            continue
        group = grouped.setdefault(
            entry.target.ref,
            {
                "kind": entry.target.kind,
                "object_id": entry.target.object_id,
                "entry_ids": [],
                "field_mappings": {},
                "relations": {},
                "provenance_states": set(),
                "blocked": False,
            },
        )
        group["entry_ids"].append(entry.entry_id)
        group["provenance_states"].add(entry.provenance_state)
        group["blocked"] = group["blocked"] or entry.is_blocked
        for mapping in entry.field_mappings:
            group["field_mappings"][mapping.target_path] = mapping
        for relation in entry.relations:
            group["relations"][relation.key] = relation
    for target_ref, group in grouped.items():
        states = group["provenance_states"]
        if len(states) > 1:
            group["blocked"] = True
            blockers.append({"code": "conflicting_provenance_state", "target_ref": target_ref})
    return grouped


def _manifest_digest_payload(manifest: KnowledgeManifest) -> dict[str, Any]:
    payload = manifest.model_dump(mode="json")
    source_snapshot = payload["source_snapshot"]
    source_snapshot["closed_directories"] = sorted(
        source_snapshot["closed_directories"],
        key=lambda item: (item["relative_path"], item["suffix"]),
    )
    for document in source_snapshot["documents"]:
        document["entry_ids"] = sorted(document["entry_ids"])
    source_snapshot["documents"] = sorted(
        source_snapshot["documents"], key=lambda item: item["source_id"]
    )
    for entry in payload["entries"]:
        entry["field_mappings"] = sorted(
            entry["field_mappings"],
            key=lambda item: (item["target_path"], item["source_locator"]),
        )
        entry["relations"] = sorted(
            entry["relations"],
            key=lambda item: (
                item["from_ref"],
                item["relation_type"],
                item["to_ref"],
                canonical_json_text(item["metadata"]),
            ),
        )
        entry["missing_requirements"] = sorted(entry["missing_requirements"])
        entry["unsafe_findings"] = sorted(
            entry["unsafe_findings"], key=lambda item: (item["location"], item["code"])
        )
    payload["entries"] = sorted(payload["entries"], key=lambda item: item["entry_id"])
    return payload


def _resolve_targets(
    grouped: Mapping[str, dict[str, Any]],
    snapshot: TargetSnapshot,
) -> tuple[list[dict[str, Any]], list[dict[str, str]], Counter[str], bool]:
    blockers: list[dict[str, str]] = []
    results: list[dict[str, Any]] = []
    relationship_counts: Counter[str] = Counter({"new": 0, "unchanged": 0})
    object_states = {item.ref: item for item in snapshot.objects}
    relationship_states = {item.key: item for item in snapshot.relationships}
    required_refs = set(grouped)
    for group in grouped.values():
        for relation in group["relations"].values():
            required_refs.update({relation.from_ref, relation.to_ref})
    complete = set(object_states) == required_refs
    if not complete:
        blockers.append({"code": "missing_target_evidence"})
    required_relation_keys = {key for group in grouped.values() for key in group["relations"]}
    if set(relationship_states) != required_relation_keys:
        complete = False
        blockers.append({"code": "missing_target_evidence"})

    object_kinds: dict[str, str] = {}
    for state in object_states.values():
        typed = TypedReference.parse(state.ref)
        if state.state == "present":
            object_kinds[typed.object_id] = typed.kind
    for target_ref, group in grouped.items():
        state = object_states.get(target_ref)
        target_blockers: list[str] = []
        action = "blocked"
        if state is None:
            target_blockers.append("missing_target_evidence")
        elif group["blocked"]:
            target_blockers.append("classification_blocked")
        else:
            try:
                candidate, action = _candidate_for_group(group, state)
                candidate_kinds = dict(object_kinds)
                candidate_kinds[candidate.id] = candidate.kind
                validate_data_references(candidate.data, candidate_kinds, object_id=candidate.id)
            except (ValidationError, ValueError, RelationshipIntegrityError, KeyError):
                action = "blocked"
                target_blockers.append("invalid_canonical_target")
        if group["kind"] in ASSET_KINDS and state is not None and state.state == "absent":
            action = "blocked"
            target_blockers.append("asset_fact_target_must_exist")
        for code in sorted(set(target_blockers)):
            blockers.append({"code": code, "target_ref": target_ref})
        relation_actions: list[dict[str, Any]] = []
        for key, relation in sorted(group["relations"].items()):
            evidence = relationship_states.get(key)
            if evidence is None:
                relation_action = "blocked"
            elif evidence.present:
                relation_action = "unchanged"
                relationship_counts["unchanged"] += 1
            else:
                relation_action = "new"
                relationship_counts["new"] += 1
            relation_actions.append(
                {
                    "from_ref": relation.from_ref,
                    "relation_type": relation.relation_type,
                    "to_ref": relation.to_ref,
                    "metadata": relation.metadata,
                    "action": relation_action,
                }
            )
        results.append(_target_result(group, target_ref, action, relation_actions))
    return results, blockers, relationship_counts, complete


def _candidate_for_group(
    group: Mapping[str, Any], state: TargetObjectState
) -> tuple[CatalogObjectIn, str]:
    if state.state == "present":
        payload = deepcopy(state.object)
        action = "unchanged"
    else:
        payload = {"id": group["object_id"], "kind": group["kind"]}
        action = "new"
    for path, mapping in sorted(group["field_mappings"].items()):
        if _get_path(payload, path) != (True, mapping.value):
            if state.state == "present":
                action = "update"
            _set_path(payload, path, deepcopy(mapping.value))
    if state.state == "absent":
        required = {"label", "status", "data", "provenance"}
        if not required <= set(payload):
            raise ValueError("new target is incomplete")
    return CatalogObjectIn.model_validate(payload), action


def _get_path(payload: Mapping[str, Any], path: str) -> tuple[bool, Any]:
    current: Any = payload
    for part in path.split("."):
        if not isinstance(current, Mapping) or part not in current:
            return False, None
        current = current[part]
    return True, current


def _set_path(payload: dict[str, Any], path: str, value: Any) -> None:
    parts = path.split(".")
    current = payload
    for part in parts[:-1]:
        child = current.setdefault(part, {})
        if not isinstance(child, dict):
            raise ValueError("field mapping paths collide")
        current = child
    current[parts[-1]] = value


def _target_result(
    group: Mapping[str, Any],
    target_ref: str,
    action: str,
    relation_actions: list[dict[str, Any]],
) -> dict[str, Any]:
    return {
        "target_ref": target_ref,
        "kind": group["kind"],
        "source_entry_ids": sorted(group["entry_ids"]),
        "action": action,
        "field_mappings": [
            item.model_dump(mode="json")
            for item in sorted(group["field_mappings"].values(), key=lambda item: item.target_path)
        ],
        "relations": relation_actions,
        "provenance_state": sorted(group["provenance_states"]),
    }


def _missing_plan_reason(result: Mapping[str, Any]) -> str:
    codes = {item["code"] for item in result["blockers"]}
    if "missing_target_snapshot" in codes:
        return "missing_target_snapshot"
    if "missing_target_evidence" in codes:
        return "missing_target_evidence"
    return "target_snapshot_not_complete"
