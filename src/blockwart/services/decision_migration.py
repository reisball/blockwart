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

from blockwart.domain.decisions import DecisionIntegrityError, validate_decision_integrity
from blockwart.domain.provenance import load_provenance
from blockwart.domain.relationships import RelationshipIntegrityError, validate_data_references
from blockwart.models import CatalogObject
from blockwart.schemas.catalog import CatalogObjectIn
from blockwart.services.audit import add_audit_event


class DecisionMigrationError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class DecisionMigrationDiagnostic:
    code: str
    object_id: str


@dataclass(frozen=True, slots=True)
class DecisionObjectChange:
    object_id: str
    before: dict[str, Any]
    after: dict[str, Any]
    expected_data_sha256: str


@dataclass(frozen=True, slots=True)
class DecisionMigrationPlan:
    scanned_decisions: int
    canonical_decisions: int
    changes: tuple[DecisionObjectChange, ...]
    diagnostics: tuple[DecisionMigrationDiagnostic, ...]

    @property
    def blocked_decisions(self) -> int:
        return len({item.object_id for item in self.diagnostics})

    @property
    def diagnostic_counts(self) -> dict[str, int]:
        return dict(sorted(Counter(item.code for item in self.diagnostics).items()))


def load_decision_migration_mapping(path: str | Path) -> dict[str, dict[str, Any]]:
    try:
        payload = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise DecisionMigrationError("decision migration mapping is unreadable") from exc
    if not isinstance(payload, Mapping) or payload.get("version") != 1:
        raise DecisionMigrationError("decision migration mapping must use version 1")
    entries = payload.get("decisions")
    if not isinstance(entries, list):
        raise DecisionMigrationError("decision migration mapping requires decisions list")
    result: dict[str, dict[str, Any]] = {}
    for entry in entries:
        if not isinstance(entry, Mapping):
            raise DecisionMigrationError("decision migration entry must be an object")
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
        ):
            raise DecisionMigrationError("decision migration entry is invalid")
        result[object_id] = {
            "expected_data_sha256": fingerprint.casefold(),
            "data_patch": dict(patch),
        }
    return result


def build_decision_migration_plan(
    session: Session,
    mapping: Mapping[str, Mapping[str, Any]] | None = None,
) -> DecisionMigrationPlan:
    rows = list(
        session.scalars(
            select(CatalogObject)
            .where(CatalogObject.kind == "decision")
            .order_by(CatalogObject.id)
        ).all()
    )
    row_by_id = {row.id: row for row in rows}
    supplied = dict(mapping or {})
    diagnostics = [
        DecisionMigrationDiagnostic("unknown_mapping_object", object_id)
        for object_id in sorted(set(supplied) - set(row_by_id))
    ]
    changes: list[DecisionObjectChange] = []
    canonical = 0
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
            diagnostics.append(DecisionMigrationDiagnostic("invalid_stored_json", row.id))
            continue
        if not isinstance(before, dict):
            diagnostics.append(DecisionMigrationDiagnostic("invalid_stored_json", row.id))
            continue
        missing_mapping_code = "missing_mapping"
        if "decision_status" in before:
            try:
                _validate_candidate(row, before, rows, object_kinds)
            except (ValidationError, RelationshipIntegrityError, DecisionIntegrityError):
                missing_mapping_code = "invalid_canonical_decision"
            else:
                canonical += 1
                if row.id in supplied:
                    diagnostics.append(
                        DecisionMigrationDiagnostic("mapping_for_canonical_decision", row.id)
                    )
                continue
        entry = supplied.get(row.id)
        if entry is None:
            diagnostics.append(DecisionMigrationDiagnostic(missing_mapping_code, row.id))
            continue
        fingerprint = decision_data_sha256(before)
        if entry.get("expected_data_sha256") != fingerprint:
            diagnostics.append(DecisionMigrationDiagnostic("fingerprint_mismatch", row.id))
            continue
        patch = entry.get("data_patch")
        if not isinstance(patch, Mapping):
            diagnostics.append(DecisionMigrationDiagnostic("invalid_mapping", row.id))
            continue
        after = {**before, **dict(patch)}
        try:
            candidate = _validate_candidate(row, after, rows, object_kinds)
        except (ValidationError, RelationshipIntegrityError, DecisionIntegrityError):
            diagnostics.append(DecisionMigrationDiagnostic("invalid_mapping", row.id))
            continue
        changes.append(
            DecisionObjectChange(
                object_id=row.id,
                before=before,
                after=candidate.data,
                expected_data_sha256=fingerprint,
            )
        )
    if changes:
        changed_data = {change.object_id: change.after for change in changes}
        projected_rows = [
            {
                "id": row.id,
                "kind": row.kind,
                "data_json": (
                    json.dumps(changed_data[row.id])
                    if row.id in changed_data
                    else row.data_json
                ),
            }
            for row in rows
        ]
        for change in changes:
            try:
                validate_decision_integrity(
                    projected_rows,
                    object_id=change.object_id,
                    data=change.after,
                )
            except DecisionIntegrityError:
                diagnostics.append(
                    DecisionMigrationDiagnostic("invalid_supersession_graph", change.object_id)
                )
    return DecisionMigrationPlan(
        scanned_decisions=len(rows),
        canonical_decisions=canonical,
        changes=tuple(changes),
        diagnostics=tuple(sorted(diagnostics, key=lambda item: (item.object_id, item.code))),
    )


def apply_decision_migration_plan(
    session: Session,
    plan: DecisionMigrationPlan,
) -> int:
    if plan.diagnostics:
        raise DecisionMigrationError("decision migration plan has blockers")
    changed_at = datetime.now(UTC).replace(tzinfo=None)
    for change in plan.changes:
        row = session.get(CatalogObject, change.object_id)
        if row is None or row.kind != "decision":
            raise DecisionMigrationError("decision changed after planning")
        try:
            current = json.loads(row.data_json)
        except (TypeError, json.JSONDecodeError) as exc:
            raise DecisionMigrationError("decision changed after planning") from exc
        if current != change.before or decision_data_sha256(current) != change.expected_data_sha256:
            raise DecisionMigrationError("decision changed after planning")
        row.data_json = json.dumps(change.after, ensure_ascii=False, sort_keys=True)
        row.revision += 1
        row.updated_at = changed_at
        add_audit_event(
            session,
            object_id=row.id,
            action="decision_normalize",
            actor="decision-migration",
            details={"object_ref": f"decision:{row.id}"},
        )
    session.flush()
    return len(plan.changes)


def decision_data_sha256(data: Mapping[str, Any]) -> str:
    encoded = json.dumps(
        data,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _validate_candidate(
    row: CatalogObject,
    data: Mapping[str, Any],
    decision_rows: list[CatalogObject],
    object_kinds: Mapping[str, str],
) -> CatalogObjectIn:
    provenance, _ = load_provenance(row.provenance_json)
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
    validate_decision_integrity(decision_rows, object_id=row.id, data=candidate.data)
    return candidate
