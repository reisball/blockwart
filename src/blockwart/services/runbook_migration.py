from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.orm import Session
from yaml.constructor import ConstructorError
from yaml.nodes import MappingNode

from blockwart.domain.object_schema import (
    FORBIDDEN_DATA_VALUE_KEYS,
    RUNBOOK_STATUSES,
    ObjectSchemaError,
)
from blockwart.domain.provenance import load_provenance
from blockwart.domain.relationships import RelationshipIntegrityError, validate_data_references
from blockwart.domain.runbooks import RunbookIntegrityError, validate_runbook_integrity
from blockwart.domain.security import find_secret_violations
from blockwart.models import CatalogObject
from blockwart.schemas.catalog import CatalogObjectIn
from blockwart.services.audit import add_audit_event


class RunbookMigrationError(RuntimeError):
    pass


class _UniqueKeySafeLoader(yaml.SafeLoader):
    def construct_mapping(self, node: MappingNode, deep: bool = False) -> dict[Any, Any]:
        self.flatten_mapping(node)
        mapping: dict[Any, Any] = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            try:
                duplicate = key in mapping
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
                    f"found duplicate key {key!r}",
                    key_node.start_mark,
                )
            mapping[key] = self.construct_object(value_node, deep=deep)
        return mapping


@dataclass(frozen=True, slots=True)
class RunbookMigrationDiagnostic:
    code: str
    object_id: str


@dataclass(frozen=True, slots=True)
class RunbookObjectChange:
    object_id: str
    before: dict[str, Any]
    after: dict[str, Any]
    expected_data_sha256: str


@dataclass(frozen=True, slots=True)
class RunbookMigrationPlan:
    scanned_runbooks: int
    canonical_runbooks: int
    changes: tuple[RunbookObjectChange, ...]
    diagnostics: tuple[RunbookMigrationDiagnostic, ...]
    state_hashes: tuple[tuple[str, str], ...]

    @property
    def blocked_runbooks(self) -> int:
        return len({item.object_id for item in self.diagnostics})

    @property
    def diagnostic_counts(self) -> dict[str, int]:
        return dict(sorted(Counter(item.code for item in self.diagnostics).items()))

    @property
    def plan_digest(self) -> str:
        payload = {
            "version": 1,
            "state": list(self.state_hashes),
            "changes": [
                {
                    "object_id": change.object_id,
                    "before_sha256": change.expected_data_sha256,
                    "after_sha256": runbook_data_sha256(change.after),
                }
                for change in self.changes
            ],
            "diagnostics": [
                {"object_id": item.object_id, "code": item.code}
                for item in self.diagnostics
            ],
        }
        return _sha256_json(payload)


def load_runbook_migration_mapping(path: str | Path) -> dict[str, dict[str, Any]]:
    try:
        payload = yaml.load(
            Path(path).read_text(encoding="utf-8"),
            Loader=_UniqueKeySafeLoader,
        )
    except (OSError, UnicodeError, yaml.YAMLError) as exc:
        raise RunbookMigrationError("runbook migration mapping is unreadable") from exc
    if (
        not isinstance(payload, Mapping)
        or set(payload) != {"version", "runbooks"}
        or type(payload.get("version")) is not int
        or payload.get("version") != 1
    ):
        raise RunbookMigrationError("runbook migration mapping must use version 1")
    entries = payload.get("runbooks")
    if not isinstance(entries, list):
        raise RunbookMigrationError("runbook migration mapping requires runbooks list")
    result: dict[str, dict[str, Any]] = {}
    for entry in entries:
        if not isinstance(entry, Mapping) or set(entry) != {
            "object_id",
            "expected_data_sha256",
            "data_patch",
        }:
            raise RunbookMigrationError("runbook migration entry must be an object")
        object_id = entry.get("object_id")
        fingerprint = entry.get("expected_data_sha256")
        patch = entry.get("data_patch")
        if (
            not isinstance(object_id, str)
            or not object_id
            or object_id in result
            or not isinstance(fingerprint, str)
            or re.fullmatch(r"[0-9A-Fa-f]{64}", fingerprint) is None
            or not isinstance(patch, Mapping)
            or _has_unsafe_content(patch)
        ):
            raise RunbookMigrationError("runbook migration entry is invalid")
        result[object_id] = {
            "expected_data_sha256": fingerprint.casefold(),
            "data_patch": dict(patch),
        }
    return result


def build_runbook_migration_plan(
    session: Session,
    mapping: Mapping[str, Mapping[str, Any]] | None = None,
) -> RunbookMigrationPlan:
    rows = list(
        session.scalars(
            select(CatalogObject)
            .where(CatalogObject.kind == "runbook")
            .order_by(CatalogObject.id)
        ).all()
    )
    row_by_id = {row.id: row for row in rows}
    supplied = dict(mapping or {})
    diagnostics = [
        RunbookMigrationDiagnostic("unknown_mapping_object", object_id)
        for object_id in sorted(set(supplied) - set(row_by_id))
    ]
    changes: list[RunbookObjectChange] = []
    canonical = 0
    state_hashes: list[tuple[str, str]] = []
    object_kinds = {
        str(object_id): str(kind)
        for object_id, kind in session.execute(
            select(CatalogObject.id, CatalogObject.kind)
        ).all()
    }
    for row in rows:
        try:
            before = json.loads(row.data_json)
        except (TypeError, json.JSONDecodeError):
            diagnostics.append(RunbookMigrationDiagnostic("invalid_stored_json", row.id))
            state_hashes.append((row.id, hashlib.sha256(str(row.data_json).encode()).hexdigest()))
            continue
        if not isinstance(before, dict):
            diagnostics.append(RunbookMigrationDiagnostic("invalid_stored_json", row.id))
            state_hashes.append((row.id, _sha256_json(before)))
            continue
        fingerprint = runbook_data_sha256(before)
        state_hashes.append((row.id, fingerprint))
        canonical_candidate = _canonical_candidate(
            row, before, rows=rows, object_kinds=object_kinds
        )
        entry = supplied.get(row.id)
        if canonical_candidate is not None:
            canonical += 1
            if entry is not None and not _mapping_is_already_applied(before, entry):
                diagnostics.append(
                    RunbookMigrationDiagnostic("mapping_for_canonical_runbook", row.id)
                )
            continue
        if entry is None:
            diagnostics.extend(
                RunbookMigrationDiagnostic(code, row.id)
                for code in classify_legacy_runbook(before)
            )
            continue
        if entry.get("expected_data_sha256") != fingerprint:
            diagnostics.append(RunbookMigrationDiagnostic("fingerprint_mismatch", row.id))
            continue
        patch = entry.get("data_patch")
        if not isinstance(patch, Mapping):
            diagnostics.append(RunbookMigrationDiagnostic("invalid_mapping", row.id))
            continue
        after = {**before, **dict(patch)}
        candidate = _canonical_candidate(
            row, after, rows=rows, object_kinds=object_kinds
        )
        if candidate is None:
            diagnostics.append(RunbookMigrationDiagnostic("invalid_mapping", row.id))
            continue
        changes.append(
            RunbookObjectChange(
                object_id=row.id,
                before=before,
                after=candidate.data,
                expected_data_sha256=fingerprint,
            )
        )

    if changes:
        changed = {change.object_id: change.after for change in changes}
        projected_rows = [
            {
                "id": row.id,
                "kind": row.kind,
                "data_json": (
                    json.dumps(changed[row.id])
                    if row.id in changed
                    else row.data_json
                ),
            }
            for row in rows
        ]
        for change in changes:
            try:
                validate_runbook_integrity(
                    projected_rows, object_id=change.object_id, data=change.after
                )
            except RunbookIntegrityError:
                diagnostics.append(
                    RunbookMigrationDiagnostic(
                        "invalid_supersession_graph", change.object_id
                    )
                )
    return RunbookMigrationPlan(
        scanned_runbooks=len(rows),
        canonical_runbooks=canonical,
        changes=tuple(changes),
        diagnostics=tuple(sorted(diagnostics, key=lambda item: (item.object_id, item.code))),
        state_hashes=tuple(state_hashes),
    )


def classify_legacy_runbook(data: Mapping[str, Any]) -> tuple[str, ...]:
    """Return deterministic blockers without inferring operational meaning."""
    blockers: list[str] = []
    if _has_unsafe_content(data):
        blockers.append("unsafe_content")
    status = data.get("runbook_status")
    if status is None:
        blockers.append("missing_runbook_status")
    elif not isinstance(status, str) or status not in RUNBOOK_STATUSES:
        blockers.append("invalid_runbook_status")
    if "approval_required" not in data:
        blockers.append("missing_approval_required")
    if "risk_level" in data and data.get("risk_level") not in {
        "read-only",
        "safe-change",
        "disruptive",
        "destructive",
    }:
        blockers.append("invalid_risk_level")
    for section in ("prerequisites", "steps", "verification", "rollback", "recovery"):
        if section in data and not isinstance(data.get(section), list):
            blockers.append(f"invalid_{section}")
    if not blockers:
        blockers.append("invalid_canonical_runbook")
    return tuple(blockers)


def apply_runbook_migration_plan(session: Session, plan: RunbookMigrationPlan) -> int:
    if plan.diagnostics:
        raise RunbookMigrationError("runbook migration plan has blockers")
    current_rows = list(
        session.scalars(
            select(CatalogObject)
            .where(CatalogObject.kind == "runbook")
            .order_by(CatalogObject.id)
        ).all()
    )
    current_state: list[tuple[str, str]] = []
    for row in current_rows:
        try:
            data = json.loads(row.data_json)
        except (TypeError, json.JSONDecodeError) as exc:
            raise RunbookMigrationError("runbook set changed after planning") from exc
        current_state.append((row.id, _sha256_json(data)))
    if tuple(current_state) != plan.state_hashes:
        raise RunbookMigrationError("runbook set changed after planning")

    changed_at = datetime.now(UTC).replace(tzinfo=None)
    for change in plan.changes:
        row = session.get(CatalogObject, change.object_id)
        if row is None or row.kind != "runbook":
            raise RunbookMigrationError("runbook changed after planning")
        current = json.loads(row.data_json)
        if current != change.before or _sha256_json(current) != change.expected_data_sha256:
            raise RunbookMigrationError("runbook changed after planning")
        row.data_json = json.dumps(change.after, ensure_ascii=False, sort_keys=True)
        row.revision += 1
        row.updated_at = changed_at
        add_audit_event(
            session,
            object_id=row.id,
            action="runbook_normalize",
            actor="runbook-migration",
            details={
                "object_ref": f"runbook:{row.id}",
                "plan_digest": plan.plan_digest,
            },
        )
    session.flush()
    return len(plan.changes)


def runbook_data_sha256(data: Mapping[str, Any]) -> str:
    return _sha256_json(data)


def _canonical_candidate(
    row: CatalogObject,
    data: Mapping[str, Any],
    *,
    rows: list[CatalogObject],
    object_kinds: Mapping[str, str],
) -> CatalogObjectIn | None:
    provenance, _ = load_provenance(row.provenance_json)
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
                "data": dict(data),
                "provenance": provenance.model_dump(),
            }
        )
        validate_data_references(candidate.data, object_kinds, object_id=row.id)
        validate_runbook_integrity(rows, object_id=row.id, data=candidate.data)
    except (
        ValidationError,
        ObjectSchemaError,
        RelationshipIntegrityError,
        RunbookIntegrityError,
    ):
        return None
    return candidate


def _mapping_is_already_applied(
    data: Mapping[str, Any], entry: Mapping[str, Any]
) -> bool:
    patch = entry.get("data_patch")
    return isinstance(patch, Mapping) and all(
        data.get(key) == value for key, value in patch.items()
    )


def _sha256_json(value: Any) -> str:
    encoded = json.dumps(
        value, ensure_ascii=True, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _has_unsafe_content(value: Any) -> bool:
    if find_secret_violations(value, path="data"):
        return True
    if isinstance(value, Mapping):
        return any(
            str(key).casefold() in FORBIDDEN_DATA_VALUE_KEYS
            or _has_unsafe_content(child)
            for key, child in value.items()
        )
    if isinstance(value, list):
        return any(_has_unsafe_content(child) for child in value)
    return False
