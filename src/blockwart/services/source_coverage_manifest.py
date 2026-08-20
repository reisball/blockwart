"""Reviewed-manifest source coverage collection and recording.

This is an offline-only adapter around the canonical source-coverage domain.
Only callers of this module's explicit collection functions may supply a
source root. Runtime REST/MCP/UI services do not import this module and never
open a workspace file.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from datetime import datetime
from pathlib import Path, PurePosixPath
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator
from sqlalchemy import select, text
from sqlalchemy.orm import Session
from yaml.constructor import ConstructorError
from yaml.nodes import MappingNode

from blockwart.db.session import build_engine, build_read_only_engine
from blockwart.domain.auth import Permission
from blockwart.domain.provenance import is_stale, load_provenance
from blockwart.domain.references import VALID_REFERENCE_KINDS
from blockwart.domain.security import find_acl_data_violations, find_secret_violations
from blockwart.domain.source_coverage import (
    CLASSIFICATION_DEFAULTS,
    COVERAGE_STATES,
    MAX_SNAPSHOT_ENTRIES,
    SOURCE_CLASSIFICATIONS,
    CatalogTarget,
    SourceEntry,
    SourceMapping,
    SourceSnapshot,
    content_fingerprint,
    normalize_entry_id,
    normalize_source_uri,
    resolve_coverage,
    source_fingerprint,
    summarize_coverage,
    validate_snapshot,
)
from blockwart.models import CatalogObject, Principal
from blockwart.services.policy import policy_for_principal
from blockwart.services.source_coverage import load_current_snapshot, record_source_snapshot

MANIFEST_SCHEMA_VERSION = 1
TARGET_EVIDENCE_SCHEMA_VERSION = 1
RESULT_SCHEMA_VERSION = 1
COLLECTOR_VERSION = "1"
COLLECTOR_NAME = "knowledge_manifest_v1"
MAX_MANIFEST_BYTES = 2 * 1024 * 1024
MAX_TARGET_EVIDENCE_BYTES = 8 * 1024 * 1024
MAX_SOURCE_BYTES = 50 * 1024 * 1024
MAX_TOTAL_SOURCE_BYTES = 100 * 1024 * 1024
MAX_SOURCES = 1000

_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_STABLE_ID = re.compile(r"^[a-z0-9](?:[a-z0-9._/-]{0,254}[a-z0-9])?$")
_OBJECT_ID = re.compile(r"^[a-z0-9](?:[a-z0-9_-]*[a-z0-9])?$")
_SAFE_SOURCE_URI = re.compile(
    r"^(?:knowledge|repository|workspace)://[a-z0-9](?:[a-z0-9._/-]*[a-z0-9])?$"
)


class SourceCoverageManifestError(RuntimeError):
    """Stable public failure raised before a coverage write is attempted."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class _ContractModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ClosedDirectory(_ContractModel):
    relative_path: str
    suffix: str = ".md"

    @field_validator("relative_path")
    @classmethod
    def validate_relative_path(cls, value: str) -> str:
        return _relative_path(value, allow_root=True)

    @field_validator("suffix")
    @classmethod
    def validate_suffix(cls, value: str) -> str:
        if not re.fullmatch(r"\.[A-Za-z0-9][A-Za-z0-9._-]{0,14}", value):
            raise ValueError("closed source suffix is invalid")
        return value


class ManifestMapping(_ContractModel):
    object_id: str
    target_kind: Literal[
        "host",
        "system",
        "network",
        "device",
        "service",
        "credential_reference",
        "runbook",
        "decision",
        "project",
    ]
    role: Literal["primary", "derived"]
    imported_entry_fingerprint: str
    imported_at: str | None = None
    verified_at: str | None = None

    @field_validator("object_id")
    @classmethod
    def validate_object_id(cls, value: str) -> str:
        if len(value) > 128 or _OBJECT_ID.fullmatch(value) is None:
            raise ValueError("mapping object ID is unstable")
        return value

    @field_validator("imported_entry_fingerprint")
    @classmethod
    def validate_fingerprint(cls, value: str) -> str:
        return _sha256(value)

    @field_validator("imported_at", "verified_at")
    @classmethod
    def validate_optional_timestamp(cls, value: str | None) -> str | None:
        if value is not None:
            _timestamp(value)
        return value


class ManifestEntry(_ContractModel):
    entry_id: str
    classification: Literal[
        "operational", "retired", "historical", "research", "migration", "generated", "ignored"
    ]
    intent: Literal["expect_object", "no_catalog_object"]
    decision_reason: Literal[
        "operational_inventory",
        "retired_asset",
        "historical_record",
        "research_material",
        "migration_artifact",
        "generated_artifact",
        "explicitly_ignored",
        "not_infrastructure",
    ]
    presence: Literal["present", "absent"]
    entry_fingerprint: str
    mappings: list[ManifestMapping] = Field(max_length=100)

    @field_validator("entry_id")
    @classmethod
    def validate_entry_id(cls, value: str) -> str:
        _stable_id(value)
        normalize_entry_id(value)
        return value

    @field_validator("entry_fingerprint")
    @classmethod
    def validate_fingerprint(cls, value: str) -> str:
        return _sha256(value)

    @model_validator(mode="after")
    def validate_decision(self) -> ManifestEntry:
        default_intent, default_reason = CLASSIFICATION_DEFAULTS[self.classification]
        allowed_reason = self.decision_reason == default_reason or (
            self.classification == "ignored" and self.decision_reason == "not_infrastructure"
        )
        if self.intent != default_intent or not allowed_reason:
            raise ValueError("classification decision is not controlled")
        if self.intent == "no_catalog_object" and self.mappings:
            raise ValueError("explicit exclusions cannot carry catalog mappings")
        if self.intent == "expect_object" and not self.mappings:
            raise ValueError("object-bound entries require an explicit mapping")
        identities = [(item.object_id, item.role) for item in self.mappings]
        object_ids = [item.object_id for item in self.mappings]
        if len(set(identities)) != len(identities) or len(set(object_ids)) != len(object_ids):
            raise ValueError("mapping identities must be unique")
        return self


class ManifestSource(_ContractModel):
    source_id: str
    source_uri: str
    relative_path: str
    sha256: str
    expected_entry_count: int = Field(ge=1, le=MAX_SNAPSHOT_ENTRIES)
    entries: list[ManifestEntry] = Field(min_length=1, max_length=MAX_SNAPSHOT_ENTRIES)

    @field_validator("source_id")
    @classmethod
    def validate_source_id(cls, value: str) -> str:
        return _stable_id(value)

    @field_validator("source_uri")
    @classmethod
    def validate_source_uri(cls, value: str) -> str:
        normalize_source_uri(value)
        if _SAFE_SOURCE_URI.fullmatch(value) is None:
            raise ValueError("source URI is not a stable sanitized Knowledge URI")
        uri_path = value.split("://", 1)[1]
        if any(segment in {"", ".", ".."} for segment in uri_path.split("/")):
            raise ValueError("source URI is not a stable sanitized Knowledge URI")
        return value

    @field_validator("relative_path")
    @classmethod
    def validate_relative_path(cls, value: str) -> str:
        return _relative_path(value)

    @field_validator("sha256")
    @classmethod
    def validate_sha256(cls, value: str) -> str:
        return _sha256(value)

    @model_validator(mode="after")
    def validate_entry_inventory(self) -> ManifestSource:
        if self.expected_entry_count != len(self.entries):
            raise ValueError("source entry coverage is incomplete")
        entry_ids = [entry.entry_id for entry in self.entries]
        if len(set(entry_ids)) != len(entry_ids):
            raise ValueError("source entry identities must be unique")
        return self


class KnowledgeCoverageManifest(_ContractModel):
    schema_version: Literal[1]
    collector_version: Literal["1"]
    inventory_id: str
    collected_at: str
    expected_source_count: int = Field(ge=1, le=MAX_SOURCES)
    expected_entry_count: int = Field(ge=1, le=MAX_SNAPSHOT_ENTRIES)
    closed_directories: list[ClosedDirectory] = Field(min_length=1, max_length=100)
    sources: list[ManifestSource] = Field(min_length=1, max_length=MAX_SOURCES)

    @field_validator("inventory_id")
    @classmethod
    def validate_inventory_id(cls, value: str) -> str:
        return _stable_id(value)

    @field_validator("collected_at")
    @classmethod
    def validate_collected_at(cls, value: str) -> str:
        _timestamp(value)
        return value

    @model_validator(mode="after")
    def validate_closed_inventory(self) -> KnowledgeCoverageManifest:
        if self.expected_source_count != len(self.sources):
            raise ValueError("source coverage count is incomplete")
        if self.expected_entry_count != sum(len(source.entries) for source in self.sources):
            raise ValueError("entry coverage count is incomplete")
        source_ids = [source.source_id for source in self.sources]
        uris = [source.source_uri for source in self.sources]
        paths = [source.relative_path for source in self.sources]
        directories = [(item.relative_path, item.suffix) for item in self.closed_directories]
        if any(len(set(values)) != len(values) for values in (source_ids, uris, paths)):
            raise ValueError("source identities, URIs, and paths must be unique")
        if len(set(directories)) != len(directories):
            raise ValueError("closed source directories must be unique")
        for source in self.sources:
            matches = [
                closed
                for closed in self.closed_directories
                if _direct_parent(source.relative_path) == closed.relative_path
                and source.relative_path.endswith(closed.suffix)
            ]
            if len(matches) != 1:
                raise ValueError("every source must belong to exactly one closed directory")
        identities = [
            (source.source_uri, entry.entry_id)
            for source in self.sources
            for entry in source.entries
        ]
        if len(set(identities)) != len(identities):
            raise ValueError("coverage entry identities must be unique")
        return self


class TargetEvidenceItem(_ContractModel):
    object_id: str
    expected_kind: str | None
    state: Literal["present", "missing", "concealed"]
    actual_kind: str | None = None
    revision: int | None = Field(default=None, ge=1)
    catalog_fingerprint: str | None = None

    @field_validator("object_id")
    @classmethod
    def validate_object_id(cls, value: str) -> str:
        if len(value) > 128 or _OBJECT_ID.fullmatch(value) is None:
            raise ValueError("target object ID is unstable")
        return value

    @field_validator("expected_kind", "actual_kind")
    @classmethod
    def validate_kind(cls, value: str | None) -> str | None:
        if value is not None and value not in VALID_REFERENCE_KINDS:
            raise ValueError("target kind is invalid")
        return value

    @field_validator("catalog_fingerprint")
    @classmethod
    def validate_optional_fingerprint(cls, value: str | None) -> str | None:
        return None if value is None else _sha256(value)

    @model_validator(mode="after")
    def validate_state(self) -> TargetEvidenceItem:
        has_state = (
            self.actual_kind is not None
            and self.revision is not None
            and self.catalog_fingerprint is not None
        )
        if self.state in {"missing", "concealed"} and any(
            value is not None
            for value in (self.actual_kind, self.revision, self.catalog_fingerprint)
        ):
            raise ValueError("non-visible target evidence cannot carry catalog state")
        if self.state == "present" and not has_state:
            raise ValueError("visible target evidence requires complete catalog state")
        return self


class TargetEvidence(_ContractModel):
    schema_version: Literal[1]
    collector_version: Literal["1"]
    principal_id: str
    policy_fingerprint: str
    target_snapshot_digest: str
    targets: list[TargetEvidenceItem] = Field(max_length=10_000)

    @field_validator("principal_id")
    @classmethod
    def validate_principal_id(cls, value: str) -> str:
        if not value or len(value) > 128 or any(char.isspace() for char in value):
            raise ValueError("principal ID is invalid")
        return value

    @field_validator("policy_fingerprint")
    @classmethod
    def validate_policy_fingerprint(cls, value: str) -> str:
        if re.fullmatch(r"[0-9a-f]{24}", value) is None:
            raise ValueError("policy fingerprint is invalid")
        return value

    @field_validator("target_snapshot_digest")
    @classmethod
    def validate_digest(cls, value: str) -> str:
        return _sha256(value)

    @model_validator(mode="after")
    def validate_evidence(self) -> TargetEvidence:
        object_ids = [item.object_id for item in self.targets]
        if len(set(object_ids)) != len(object_ids):
            raise ValueError("target evidence identities must be unique")
        if self.target_snapshot_digest != target_evidence_digest(self):
            raise ValueError("target evidence digest does not match its normalized state")
        return self


@dataclass(frozen=True, slots=True)
class CollectionPlan:
    manifest_digest: str
    input_digest: str
    snapshot: SourceSnapshot
    target_evidence: TargetEvidence
    result: dict[str, Any]


def canonical_json_bytes(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise SourceCoverageManifestError("non_canonical_json") from exc


def canonical_json_text(value: Any) -> str:
    return canonical_json_bytes(value).decode("utf-8")


def manifest_json_schema() -> dict[str, Any]:
    return KnowledgeCoverageManifest.model_json_schema()


def target_evidence_json_schema() -> dict[str, Any]:
    return TargetEvidence.model_json_schema()


def result_json_schema() -> dict[str, Any]:
    target_item = {
        "additionalProperties": False,
        "properties": {
            "object_id": {"maxLength": 128, "minLength": 1, "type": "string"},
            "expected_kind": {
                "anyOf": [
                    {"enum": sorted(VALID_REFERENCE_KINDS), "type": "string"},
                    {"type": "null"},
                ]
            },
            "state": {"enum": ["present", "missing", "concealed"], "type": "string"},
            "actual_kind": {
                "anyOf": [
                    {"enum": sorted(VALID_REFERENCE_KINDS), "type": "string"},
                    {"type": "null"},
                ]
            },
            "revision": {"anyOf": [{"minimum": 1, "type": "integer"}, {"type": "null"}]},
            "catalog_fingerprint": {"anyOf": [_digest_schema(), {"type": "null"}]},
        },
        "required": [
            "object_id",
            "expected_kind",
            "state",
            "actual_kind",
            "revision",
            "catalog_fingerprint",
        ],
        "type": "object",
    }
    target_evidence = {
        "additionalProperties": False,
        "properties": {
            "schema_version": {"const": 1, "type": "integer"},
            "collector_version": {"const": "1", "type": "string"},
            "principal_id": {"maxLength": 128, "minLength": 1, "type": "string"},
            "policy_fingerprint": {"pattern": "^[0-9a-f]{24}$", "type": "string"},
            "target_snapshot_digest": _digest_schema(),
            "targets": {"items": target_item, "maxItems": 10_000, "type": "array"},
        },
        "required": [
            "schema_version",
            "collector_version",
            "principal_id",
            "policy_fingerprint",
            "target_snapshot_digest",
            "targets",
        ],
        "type": "object",
    }
    source_snapshot = {
        "additionalProperties": False,
        "properties": {
            "digest": _digest_schema(),
            "declared_source_count": {"minimum": 1, "type": "integer"},
            "source_count": {"minimum": 1, "type": "integer"},
            "entry_count": {"minimum": 1, "type": "integer"},
            "mapping_count": {"minimum": 0, "type": "integer"},
        },
        "required": [
            "digest",
            "declared_source_count",
            "source_count",
            "entry_count",
            "mapping_count",
        ],
        "type": "object",
    }
    summary = {
        "additionalProperties": False,
        "properties": {
            "classification_counts": _fixed_count_schema(SOURCE_CLASSIFICATIONS),
            "state_counts": _fixed_count_schema(COVERAGE_STATES),
            "presence_counts": _fixed_count_schema(("present", "absent")),
        },
        "required": ["classification_counts", "state_counts", "presence_counts"],
        "type": "object",
    }
    blocker = {
        "additionalProperties": False,
        "properties": {
            "code": {"minLength": 1, "type": "string"},
            "identity": {"minLength": 1, "type": "string"},
        },
        "required": ["code", "identity"],
        "type": "object",
    }
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "additionalProperties": False,
        "properties": {
            "schema_version": {"const": 1, "type": "integer"},
            "collector_version": {"const": "1", "type": "string"},
            "mode": {"enum": ["dry-run", "record"], "type": "string"},
            "manifest_digest": _digest_schema(),
            "input_digest": _digest_schema(),
            "source_snapshot": source_snapshot,
            "target_evidence": target_evidence,
            "summary": summary,
            "missing_targets": {"items": {"type": "string"}, "type": "array"},
            "ambiguous_mappings": {"items": {"type": "string"}, "type": "array"},
            "duplicate_mappings": {"items": {"type": "string"}, "type": "array"},
            "unsafe_findings": {"items": {"type": "string"}, "type": "array"},
            "blockers": {"items": blocker, "type": "array"},
            "record_ready": {"type": "boolean"},
            "semantic_noop": {"type": "boolean"},
        },
        "required": [
            "schema_version",
            "collector_version",
            "mode",
            "manifest_digest",
            "input_digest",
            "source_snapshot",
            "target_evidence",
            "summary",
            "missing_targets",
            "ambiguous_mappings",
            "duplicate_mappings",
            "unsafe_findings",
            "blockers",
            "record_ready",
            "semantic_noop",
        ],
        "title": "BlockwartSourceCoverageResultV1",
        "type": "object",
    }


def load_manifest(path: str | Path) -> KnowledgeCoverageManifest:
    payload = _load_document(path, "invalid_manifest", max_bytes=MAX_MANIFEST_BYTES)
    if find_secret_violations(payload):
        raise SourceCoverageManifestError("unsafe_manifest_secret")
    if find_acl_data_violations(payload, "manifest"):
        raise SourceCoverageManifestError("unsafe_manifest_acl")
    try:
        return KnowledgeCoverageManifest.model_validate(payload)
    except (ValidationError, ValueError) as exc:
        raise SourceCoverageManifestError("invalid_manifest") from exc


def load_target_evidence(path: str | Path) -> TargetEvidence:
    payload = _load_document(
        path,
        "invalid_target_evidence",
        max_bytes=MAX_TARGET_EVIDENCE_BYTES,
    )
    if find_secret_violations(payload):
        raise SourceCoverageManifestError("unsafe_target_evidence_secret")
    if find_acl_data_violations(payload, "target_evidence"):
        raise SourceCoverageManifestError("unsafe_target_evidence_acl")
    try:
        return TargetEvidence.model_validate(payload)
    except (ValidationError, ValueError) as exc:
        raise SourceCoverageManifestError("invalid_target_evidence") from exc


def collect_source_files(
    manifest: KnowledgeCoverageManifest,
    source_root: str | Path,
) -> dict[str, str]:
    """Hash only exact declared files after enforcing each closed directory."""
    root = Path(source_root)
    try:
        resolved_root = root.resolve(strict=True)
    except OSError as exc:
        raise SourceCoverageManifestError("source_root_unreadable") from exc
    if not resolved_root.is_dir():
        raise SourceCoverageManifestError("source_root_unreadable")
    expected_paths = {source.relative_path for source in manifest.sources}
    for closed in manifest.closed_directories:
        directory = (
            resolved_root if closed.relative_path == "." else resolved_root / closed.relative_path
        )
        try:
            resolved_directory = directory.resolve(strict=True)
            if (
                not resolved_directory.is_relative_to(resolved_root)
                or _path_has_symlink(resolved_root, closed.relative_path)
            ):
                raise SourceCoverageManifestError("source_set_drift")
            actual = {
                item.relative_to(resolved_root).as_posix()
                for item in directory.iterdir()
                if item.is_file() and item.name.endswith(closed.suffix)
            }
        except OSError as exc:
            raise SourceCoverageManifestError("source_set_drift") from exc
        scoped_expected = {
            path
            for path in expected_paths
            if _direct_parent(path) == closed.relative_path and path.endswith(closed.suffix)
        }
        if actual != scoped_expected:
            raise SourceCoverageManifestError("source_set_drift")

    digests: dict[str, str] = {}
    total_size = 0
    for source in sorted(manifest.sources, key=lambda item: item.source_id):
        path = resolved_root / source.relative_path
        try:
            resolved = path.resolve(strict=True)
            if (
                _path_has_symlink(resolved_root, source.relative_path)
                or not resolved.is_relative_to(resolved_root)
                or not resolved.is_file()
            ):
                raise SourceCoverageManifestError("source_file_unsafe")
            digest, size = _file_sha256(resolved, max_bytes=MAX_SOURCE_BYTES)
            total_size += size
            if total_size > MAX_TOTAL_SOURCE_BYTES:
                raise SourceCoverageManifestError("source_input_too_large")
        except OSError as exc:
            raise SourceCoverageManifestError("source_file_unreadable") from exc
        if digest != source.sha256:
            raise SourceCoverageManifestError("source_file_drift")
        digests[source.source_id] = digest
    return digests


def build_collection_plan(
    manifest: KnowledgeCoverageManifest,
    *,
    source_root: str | Path,
    session: Session,
    principal_id: str,
) -> CollectionPlan:
    source_digests = collect_source_files(manifest, source_root)
    previous = load_current_snapshot(session)
    snapshot = _materialize_snapshot(manifest, previous)
    evidence, targets, kind_conflicts = _target_evidence(
        session,
        snapshot,
        manifest=manifest,
        principal_id=principal_id,
    )
    details = resolve_coverage(snapshot, targets)
    summary = summarize_coverage(details)
    mapping_owner_counts = Counter(
        mapping.object_id
        for entry in snapshot.entries
        if entry.presence == "present"
        for mapping in entry.mappings
        if mapping.role == "primary"
    )
    ambiguous = sorted(
        f"{entry.source_uri}|{entry.entry_id or ''}"
        for entry in snapshot.entries
        if entry.presence == "present"
        and sum(mapping.role == "primary" for mapping in entry.mappings) != 1
        and entry.intent == "expect_object"
    )
    duplicate = sorted(object_id for object_id, count in mapping_owner_counts.items() if count > 1)
    missing = sorted(item.object_id for item in evidence.targets if item.state == "missing")
    concealed = sorted(item.object_id for item in evidence.targets if item.state == "concealed")
    kind_mismatches = sorted(
        item.object_id
        for item in evidence.targets
        if item.expected_kind is not None
        and item.actual_kind is not None
        and item.actual_kind != item.expected_kind
    )
    collection_not_newer = (
        previous is not None
        and previous.digest != snapshot.digest
        and _parse_timestamp(manifest.collected_at) <= _parse_timestamp(previous.collected_at)
    )
    blockers = [
        *({"code": "missing_target", "identity": value} for value in missing),
        *({"code": "concealed_target", "identity": value} for value in concealed),
        *({"code": "kind_mismatch", "identity": value} for value in kind_mismatches),
        *({"code": "ambiguous_target_kind", "identity": value} for value in kind_conflicts),
        *({"code": "ambiguous_mapping", "identity": value} for value in ambiguous),
        *({"code": "duplicate_mapping", "identity": value} for value in duplicate),
        *(
            ({"code": "collection_not_newer", "identity": "manifest.collected_at"},)
            if collection_not_newer
            else ()
        ),
    ]
    manifest_digest = _domain_digest("manifest", _manifest_payload(manifest))
    previous_digest = previous.digest if previous is not None else None
    input_digest = _domain_digest(
        "inputs",
        {
            "manifest_digest": manifest_digest,
            "previous_snapshot_digest": previous_digest,
            "sources": source_digests,
        },
    )
    semantic_noop = previous is not None and previous.digest == snapshot.digest
    presence_counts = Counter(entry.presence for entry in snapshot.entries)
    result: dict[str, Any] = {
        "schema_version": RESULT_SCHEMA_VERSION,
        "collector_version": COLLECTOR_VERSION,
        "mode": "dry-run",
        "manifest_digest": manifest_digest,
        "input_digest": input_digest,
        "source_snapshot": {
            "digest": snapshot.digest,
            "declared_source_count": len(manifest.sources),
            "source_count": len(snapshot.source_uris),
            "entry_count": len(snapshot.entries),
            "mapping_count": sum(len(entry.mappings) for entry in snapshot.entries),
        },
        "target_evidence": evidence.model_dump(mode="json"),
        "summary": {
            "classification_counts": summary.by_classification,
            "state_counts": summary.by_state,
            "presence_counts": {
                presence: presence_counts[presence] for presence in ("present", "absent")
            },
        },
        "missing_targets": missing,
        "ambiguous_mappings": ambiguous,
        "duplicate_mappings": duplicate,
        "unsafe_findings": [],
        "blockers": sorted(blockers, key=lambda item: (item["code"], item["identity"])),
        "record_ready": not blockers,
        "semantic_noop": semantic_noop,
    }
    return CollectionPlan(
        manifest_digest=manifest_digest,
        input_digest=input_digest,
        snapshot=snapshot,
        target_evidence=evidence,
        result=result,
    )


def dry_run(
    *,
    database_url: str,
    manifest_path: str | Path,
    source_root: str | Path,
    principal_id: str,
) -> dict[str, Any]:
    manifest = load_manifest(manifest_path)
    engine = None
    try:
        engine = build_read_only_engine(database_url)
        with Session(engine, autoflush=False, expire_on_commit=False) as session:
            return build_collection_plan(
                manifest,
                source_root=source_root,
                session=session,
                principal_id=principal_id,
            ).result
    except SourceCoverageManifestError:
        raise
    except Exception as exc:
        raise SourceCoverageManifestError("database_read_failed") from exc
    finally:
        if engine is not None:
            engine.dispose()


def record_manifest_snapshot(
    *,
    database_url: str,
    manifest_path: str | Path,
    source_root: str | Path,
    target_evidence_path: str | Path,
    principal_id: str,
    expected_manifest_digest: str,
    expected_input_digest: str,
    expected_snapshot_digest: str,
    expected_target_digest: str,
) -> dict[str, Any]:
    """Recompute all caller-retained evidence, then record only coverage rows."""
    expected = {
        "manifest_digest": _required_digest(expected_manifest_digest),
        "input_digest": _required_digest(expected_input_digest),
        "snapshot_digest": _required_digest(expected_snapshot_digest),
        "target_digest": _required_digest(expected_target_digest),
    }
    manifest = load_manifest(manifest_path)
    retained_evidence = load_target_evidence(target_evidence_path)
    if retained_evidence.principal_id != principal_id:
        raise SourceCoverageManifestError("target_evidence_principal_mismatch")

    read_engine = None
    try:
        read_engine = build_read_only_engine(database_url)
        with Session(read_engine, autoflush=False, expire_on_commit=False) as session:
            preflight = build_collection_plan(
                manifest,
                source_root=source_root,
                session=session,
                principal_id=principal_id,
            )
            _verify_record_contract(preflight, retained_evidence, expected)
    except SourceCoverageManifestError:
        raise
    except Exception as exc:
        raise SourceCoverageManifestError("database_read_failed") from exc
    finally:
        if read_engine is not None:
            read_engine.dispose()

    engine = None
    try:
        engine = build_engine(database_url, sqlite_configure_journal_mode=False)
        with Session(engine, autoflush=False, expire_on_commit=False) as session:
            try:
                _begin_record_transaction(session)
                current = build_collection_plan(
                    manifest,
                    source_root=source_root,
                    session=session,
                    principal_id=principal_id,
                )
                _verify_record_contract(current, retained_evidence, expected)
                semantic_noop = current.result["semantic_noop"]
                info = record_source_snapshot(session, current.snapshot)
                session.commit()
            except Exception:
                session.rollback()
                raise
    except SourceCoverageManifestError:
        raise
    except Exception as exc:
        raise SourceCoverageManifestError("database_transaction_failed") from exc
    finally:
        if engine is not None:
            engine.dispose()
    result = dict(current.result)
    result["mode"] = "record"
    result["semantic_noop"] = semantic_noop
    result["source_snapshot"] = {
        **result["source_snapshot"],
        "digest": info.digest,
    }
    return result


def target_evidence_digest(evidence: TargetEvidence) -> str:
    payload = evidence.model_dump(mode="json", exclude={"target_snapshot_digest"})
    payload["targets"] = sorted(payload["targets"], key=lambda item: item["object_id"])
    return _domain_digest("target-evidence", payload)


def _materialize_snapshot(
    manifest: KnowledgeCoverageManifest,
    previous: SourceSnapshot | None,
) -> SourceSnapshot:
    entries: dict[tuple[str, str], SourceEntry] = {}
    for source in manifest.sources:
        for entry in source.entries:
            normalized_entry_fingerprint = _bound_fingerprint(
                source.sha256, entry.entry_fingerprint
            )
            entries[(source.source_uri, entry.entry_id)] = SourceEntry(
                source_uri=source.source_uri,
                entry_id=entry.entry_id,
                classification=entry.classification,
                intent=entry.intent,
                decision_reason=entry.decision_reason,
                entry_fingerprint=normalized_entry_fingerprint,
                source_fingerprint="0" * 64,
                observed_at=manifest.collected_at,
                presence=entry.presence,
                mappings=tuple(
                    SourceMapping(
                        object_id=mapping.object_id,
                        role=mapping.role,
                        imported_entry_fingerprint=_bound_fingerprint(
                            source.sha256,
                            mapping.imported_entry_fingerprint,
                        ),
                        imported_at=mapping.imported_at,
                        verified_at=mapping.verified_at,
                    )
                    for mapping in sorted(
                        entry.mappings, key=lambda item: (item.object_id, item.role)
                    )
                ),
            )
    if previous is not None:
        for old in previous.entries:
            if old.key in entries:
                continue
            entries[old.key] = replace(
                old,
                observed_at=manifest.collected_at,
                presence="absent",
            )
    if len(entries) > MAX_SNAPSHOT_ENTRIES:
        raise SourceCoverageManifestError("merged_snapshot_too_large")
    grouped: dict[str, list[SourceEntry]] = {}
    for entry in entries.values():
        grouped.setdefault(entry.source_uri, []).append(entry)
    for source_entries in grouped.values():
        aggregate = source_fingerprint(
            entry.entry_fingerprint for entry in source_entries if entry.presence == "present"
        )
        for entry in source_entries:
            entries[entry.key] = replace(entry, source_fingerprint=aggregate)
    snapshot = SourceSnapshot(
        collector=COLLECTOR_NAME,
        collected_at=manifest.collected_at,
        entries=tuple(sorted(entries.values(), key=lambda item: item.key)),
    ).with_digest()
    try:
        return validate_snapshot(snapshot)
    except ValueError as exc:
        raise SourceCoverageManifestError("invalid_normalized_snapshot") from exc


def _target_evidence(
    session: Session,
    snapshot: SourceSnapshot,
    *,
    manifest: KnowledgeCoverageManifest,
    principal_id: str,
) -> tuple[TargetEvidence, dict[str, CatalogTarget], list[str]]:
    principal = session.get(Principal, principal_id)
    if principal is None or not principal.active:
        raise SourceCoverageManifestError("effective_principal_unavailable")
    expected_kinds: dict[str, set[str]] = {}
    for entry in snapshot.entries:
        for mapping in entry.mappings:
            # Manifest entries carry reviewed kinds. Tombstones loaded from an
            # older collector do not; use the current kind when it exists.
            expected_kinds.setdefault(mapping.object_id, set())
    for source in manifest.sources:
        for entry in source.entries:
            for mapping in entry.mappings:
                expected_kinds.setdefault(mapping.object_id, set()).add(mapping.target_kind)
    kind_conflicts = sorted(
        object_id for object_id, kinds in expected_kinds.items() if len(kinds) > 1
    )
    object_ids = sorted(expected_kinds)
    rows = {
        row.id: row
        for row in session.scalars(select(CatalogObject).where(CatalogObject.id.in_(object_ids)))
    }
    policy = policy_for_principal(session, principal_id)
    visible = policy.authorized_ids(Permission.READ)
    items: list[TargetEvidenceItem] = []
    targets: dict[str, CatalogTarget] = {}
    for object_id in object_ids:
        row = rows.get(object_id)
        declared_kinds = expected_kinds[object_id]
        expected_kind = next(iter(declared_kinds)) if len(declared_kinds) == 1 else None
        if expected_kind is None and row is not None and not declared_kinds:
            expected_kind = row.kind
        if row is None:
            items.append(
                TargetEvidenceItem(
                    object_id=object_id,
                    expected_kind=expected_kind,
                    state="missing",
                )
            )
            targets[object_id] = CatalogTarget(object_id, "", False, False)
            continue
        if object_id not in visible:
            items.append(
                TargetEvidenceItem(
                    object_id=object_id,
                    expected_kind=expected_kind,
                    state="concealed",
                )
            )
            targets[object_id] = CatalogTarget(object_id, "", True, False)
            continue
        items.append(
            TargetEvidenceItem(
                object_id=object_id,
                expected_kind=expected_kind,
                state="present",
                actual_kind=row.kind,
                revision=row.revision,
                catalog_fingerprint=_catalog_fingerprint(row),
            )
        )
        provenance, _valid = load_provenance(row.provenance_json)
        targets[object_id] = CatalogTarget(
            object_id,
            row.kind,
            True,
            is_stale(provenance, now=_parse_timestamp(manifest.collected_at)),
        )
    provisional = TargetEvidence.model_construct(
        schema_version=TARGET_EVIDENCE_SCHEMA_VERSION,
        collector_version=COLLECTOR_VERSION,
        principal_id=principal_id,
        policy_fingerprint=policy.fingerprint(),
        target_snapshot_digest="0" * 64,
        targets=items,
    )
    evidence = TargetEvidence.model_validate(
        {
            **provisional.model_dump(mode="json"),
            "target_snapshot_digest": target_evidence_digest(provisional),
        }
    )
    return evidence, targets, kind_conflicts


def _verify_record_contract(
    plan: CollectionPlan,
    retained: TargetEvidence,
    expected: Mapping[str, str],
) -> None:
    checks = {
        "manifest_digest_mismatch": plan.manifest_digest == expected["manifest_digest"],
        "input_digest_mismatch": plan.input_digest == expected["input_digest"],
        "snapshot_digest_mismatch": plan.snapshot.digest == expected["snapshot_digest"],
        "target_digest_mismatch": (retained.target_snapshot_digest == expected["target_digest"]),
    }
    for code, passed in checks.items():
        if not passed:
            raise SourceCoverageManifestError(code)
    planned_ids = {item.object_id for item in plan.target_evidence.targets}
    retained_ids = {item.object_id for item in retained.targets}
    if planned_ids != retained_ids:
        raise SourceCoverageManifestError("incomplete_target_evidence")
    if plan.target_evidence != retained:
        raise SourceCoverageManifestError("stale_target_evidence")
    if not plan.result["record_ready"]:
        raise SourceCoverageManifestError("record_blocked")


def _begin_record_transaction(session: Session) -> None:
    if session.bind is None:
        raise SourceCoverageManifestError("database_transaction_failed")
    dialect = session.bind.dialect.name
    if dialect == "sqlite":
        session.execute(text("BEGIN IMMEDIATE"))
        return
    if dialect == "postgresql":
        session.connection(execution_options={"isolation_level": "SERIALIZABLE"})
        # Keep the exact target, authorization, and prior-snapshot evidence
        # stable until the immutable coverage insert commits. The offline
        # recorder never locks or writes source files.
        session.execute(
            text(
                "LOCK TABLE catalog_objects, principals, object_grants, relationships "
                "IN SHARE MODE"
            )
        )
        session.execute(
            text(
                "LOCK TABLE source_snapshots, source_entries, source_entry_mappings "
                "IN SHARE ROW EXCLUSIVE MODE"
            )
        )


def _manifest_payload(manifest: KnowledgeCoverageManifest) -> dict[str, Any]:
    payload = manifest.model_dump(mode="json")
    payload["closed_directories"] = sorted(
        payload["closed_directories"], key=lambda item: (item["relative_path"], item["suffix"])
    )
    payload["sources"] = sorted(payload["sources"], key=lambda item: item["source_id"])
    for source in payload["sources"]:
        source["entries"] = sorted(source["entries"], key=lambda item: item["entry_id"])
        for entry in source["entries"]:
            entry["mappings"] = sorted(
                entry["mappings"], key=lambda item: (item["object_id"], item["role"])
            )
    return payload


def _catalog_fingerprint(row: CatalogObject) -> str:
    return _domain_digest(
        "catalog-object",
        {
            "id": row.id,
            "instance_id": row.instance_id,
            "kind": row.kind,
            "label": row.label,
            "status": row.status,
            "lifecycle": row.lifecycle,
            "health": row.health,
            "summary": row.summary,
            "data_json": row.data_json,
            "provenance_json": row.provenance_json,
            "revision": row.revision,
            "created_at": str(row.created_at),
            "updated_at": str(row.updated_at),
        },
    )


def _domain_digest(domain: str, value: Any) -> str:
    prefix = f"blockwart:source-coverage:{domain}:v1\n".encode()
    return hashlib.sha256(prefix + canonical_json_bytes(value)).hexdigest()


def _bound_fingerprint(source_sha256: str, entry_fingerprint: str) -> str:
    """Bind an opaque reviewed entry fact to the exact declared source bytes."""
    return content_fingerprint(
        [
            {
                "entry_fingerprint": entry_fingerprint,
                "source_sha256": source_sha256,
            }
        ]
    )


def _load_document(path: str | Path, code: str, *, max_bytes: int) -> Any:
    candidate = Path(path)
    try:
        if candidate.stat().st_size > max_bytes:
            raise SourceCoverageManifestError("input_document_too_large")
        body = candidate.read_text(encoding="utf-8")
        if candidate.suffix.lower() == ".json":
            return json.loads(body, object_pairs_hook=_unique_json_object)
        return yaml.load(body, Loader=_UniqueKeySafeLoader)
    except SourceCoverageManifestError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError, yaml.YAMLError, ValueError) as exc:
        raise SourceCoverageManifestError(code) from exc


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


def _unique_json_object(pairs: Sequence[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _relative_path(value: str, *, allow_root: bool = False) -> str:
    if allow_root and value == ".":
        return value
    path = PurePosixPath(value)
    if (
        not value
        or path.is_absolute()
        or "." in path.parts
        or ".." in path.parts
        or path.as_posix() != value
        or "\\" in value
    ):
        raise ValueError("source path must be a canonical relative POSIX path")
    return value


def _direct_parent(value: str) -> str:
    parent = PurePosixPath(value).parent.as_posix()
    return "." if parent == "." else parent


def _stable_id(value: str) -> str:
    if (
        len(value) > 256
        or _STABLE_ID.fullmatch(value) is None
        or "//" in value
        or any(part in {".", ".."} for part in PurePosixPath(value).parts)
    ):
        raise ValueError("identifier is not stable")
    return value


def _sha256(value: str) -> str:
    if _HEX64.fullmatch(value) is None:
        raise ValueError("SHA-256 must be lowercase hexadecimal")
    return value


def _required_digest(value: str) -> str:
    try:
        return _sha256(value)
    except ValueError as exc:
        raise SourceCoverageManifestError("invalid_expected_digest") from exc


def _timestamp(value: str) -> None:
    _parse_timestamp(value)


def _parse_timestamp(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("timestamp must be RFC3339") from exc
    if parsed.tzinfo is None:
        raise ValueError("timestamp must include an UTC offset")
    return parsed


def _file_sha256(path: Path, *, max_bytes: int) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            size += len(chunk)
            if size > max_bytes:
                raise SourceCoverageManifestError("source_input_too_large")
            digest.update(chunk)
    return digest.hexdigest(), size


def _path_has_symlink(root: Path, relative_path: str) -> bool:
    if relative_path == ".":
        return False
    candidate = root
    for part in PurePosixPath(relative_path).parts:
        candidate /= part
        if candidate.is_symlink():
            return True
    return False


def _digest_schema() -> dict[str, Any]:
    return {"pattern": "^[0-9a-f]{64}$", "type": "string"}


def _fixed_count_schema(keys: Sequence[str]) -> dict[str, Any]:
    return {
        "additionalProperties": False,
        "properties": {key: {"minimum": 0, "type": "integer"} for key in keys},
        "required": list(keys),
        "type": "object",
    }
