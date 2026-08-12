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

from blockwart.domain.object_schema import (
    ALL_PROJECT_CATEGORY_FIELD_NAMES,
    PROJECT_CATEGORIES,
    PROJECT_CATEGORY_FIELD_NAMES,
    PROJECT_STATUSES,
    ObjectSchemaError,
    validate_object_data,
)
from blockwart.domain.provenance import load_provenance
from blockwart.domain.relationships import RelationshipIntegrityError, validate_data_references
from blockwart.models import CatalogObject
from blockwart.schemas.catalog import CatalogObjectIn
from blockwart.services.audit import add_audit_event


class ProjectMigrationError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class ProjectMigrationDiagnostic:
    code: str
    object_id: str


@dataclass(frozen=True, slots=True)
class ProjectObjectChange:
    object_id: str
    before: dict[str, Any]
    after: dict[str, Any]
    expected_data_sha256: str


@dataclass(frozen=True, slots=True)
class ProjectMigrationPlan:
    scanned_projects: int
    canonical_projects: int
    changes: tuple[ProjectObjectChange, ...]
    diagnostics: tuple[ProjectMigrationDiagnostic, ...]

    @property
    def blocked_projects(self) -> int:
        return len({item.object_id for item in self.diagnostics})

    @property
    def diagnostic_counts(self) -> dict[str, int]:
        return dict(sorted(Counter(item.code for item in self.diagnostics).items()))


def load_project_migration_mapping(path: str | Path) -> dict[str, dict[str, Any]]:
    try:
        payload = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise ProjectMigrationError("project migration mapping is unreadable") from exc
    if not isinstance(payload, Mapping) or payload.get("version") != 1:
        raise ProjectMigrationError("project migration mapping must use version 1")
    entries = payload.get("projects")
    if not isinstance(entries, list):
        raise ProjectMigrationError("project migration mapping requires projects list")
    result: dict[str, dict[str, Any]] = {}
    for entry in entries:
        if not isinstance(entry, Mapping):
            raise ProjectMigrationError("project migration entry must be an object")
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
            raise ProjectMigrationError("project migration entry is invalid")
        result[object_id] = {
            "expected_data_sha256": fingerprint.casefold(),
            "data_patch": dict(patch),
        }
    return result


def build_project_migration_plan(
    session: Session,
    mapping: Mapping[str, Mapping[str, Any]] | None = None,
) -> ProjectMigrationPlan:
    rows = list(
        session.scalars(
            select(CatalogObject)
            .where(CatalogObject.kind == "project")
            .order_by(CatalogObject.id)
        ).all()
    )
    row_by_id = {row.id: row for row in rows}
    supplied = dict(mapping or {})
    diagnostics = [
        ProjectMigrationDiagnostic("unknown_mapping_object", object_id)
        for object_id in sorted(set(supplied) - set(row_by_id))
    ]
    changes: list[ProjectObjectChange] = []
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
            diagnostics.append(ProjectMigrationDiagnostic("invalid_stored_json", row.id))
            continue
        if not isinstance(before, dict):
            diagnostics.append(ProjectMigrationDiagnostic("invalid_stored_json", row.id))
            continue
        if "category" in before:
            try:
                _validate_candidate(row, before, object_kinds)
            except (ValidationError, RelationshipIntegrityError):
                if row.id not in supplied:
                    diagnostics.extend(
                        ProjectMigrationDiagnostic(code, row.id)
                        for code in classify_legacy_project(before)
                    )
                    continue
            else:
                canonical += 1
                if row.id in supplied:
                    diagnostics.append(
                        ProjectMigrationDiagnostic("mapping_for_canonical_project", row.id)
                    )
                continue
        entry = supplied.get(row.id)
        if entry is None:
            diagnostics.extend(
                ProjectMigrationDiagnostic(code, row.id)
                for code in classify_legacy_project(before)
            )
            continue
        fingerprint = project_data_sha256(before)
        if entry.get("expected_data_sha256") != fingerprint:
            diagnostics.append(ProjectMigrationDiagnostic("fingerprint_mismatch", row.id))
            continue
        patch = entry.get("data_patch")
        if not isinstance(patch, Mapping):
            diagnostics.append(ProjectMigrationDiagnostic("invalid_mapping", row.id))
            continue
        after = {**before, **dict(patch)}
        try:
            candidate = _validate_candidate(row, after, object_kinds)
        except (ValidationError, RelationshipIntegrityError):
            diagnostics.append(ProjectMigrationDiagnostic("invalid_mapping", row.id))
            continue
        changes.append(
            ProjectObjectChange(
                object_id=row.id,
                before=before,
                after=candidate.data,
                expected_data_sha256=fingerprint,
            )
        )
    return ProjectMigrationPlan(
        scanned_projects=len(rows),
        canonical_projects=canonical,
        changes=tuple(changes),
        diagnostics=tuple(sorted(diagnostics, key=lambda item: (item.object_id, item.code))),
    )


def classify_legacy_project(data: Mapping[str, Any]) -> tuple[str, ...]:
    """Explain, without guessing, why one row needs a reviewed mapping.

    The returned codes are blockers: a category or status is never inferred
    from historical content, and every reported defect names one reviewable
    reason a human must resolve before the row can become canonical.
    """
    blockers: list[str] = []
    category = data.get("category")
    if category is None:
        blockers.append("missing_category")
    elif not isinstance(category, str) or category not in PROJECT_CATEGORIES:
        blockers.append("invalid_category")
    status = data.get("project_status")
    if status is None:
        blockers.append("missing_project_status")
    elif not isinstance(status, str) or status not in PROJECT_STATUSES:
        blockers.append("invalid_project_status")

    present = ALL_PROJECT_CATEGORY_FIELD_NAMES & set(data)
    if present:
        matching = {
            candidate
            for candidate, allowed in PROJECT_CATEGORY_FIELD_NAMES.items()
            if present <= allowed
        }
        if not matching:
            blockers.append("ambiguous_category")
        elif isinstance(category, str) and category in PROJECT_CATEGORIES:
            allowed = PROJECT_CATEGORY_FIELD_NAMES.get(category, frozenset())
            if not present <= allowed:
                blockers.append("contradictory_category_fields")

    for code, section in (
        ("invalid_sources", "sources"),
        ("invalid_evidence", "findings"),
        ("invalid_evidence", "measurements"),
    ):
        if section in data and _section_is_invalid(data, section) and code not in blockers:
            blockers.append(code)

    if not blockers:
        blockers.append(_canonical_blocker(data))
    return tuple(blockers)


# Maps the schema rule that rejected an otherwise well-shaped row onto the
# reviewable reason a human has to resolve before the row can become canonical.
_RULE_BLOCKERS: Mapping[str, str] = {
    "reject_project_contradictory_fields": "contradictory_category_fields",
    "require_project_conditional_fields": "invalid_lifecycle",
    "validate_project_timestamp_order": "invalid_lifecycle",
    "reject_ambiguous_project_evidence": "invalid_evidence",
}


def _canonical_blocker(data: Mapping[str, Any]) -> str:
    try:
        validate_object_data("project", data)
    except ObjectSchemaError as exc:
        if exc.rule is not None:
            return _RULE_BLOCKERS.get(exc.rule, "invalid_canonical_project")
        return "invalid_canonical_project"
    except ValueError:
        return "invalid_canonical_project"
    return "missing_mapping"


def apply_project_migration_plan(
    session: Session,
    plan: ProjectMigrationPlan,
) -> int:
    if plan.diagnostics:
        raise ProjectMigrationError("project migration plan has blockers")
    changed_at = datetime.now(UTC).replace(tzinfo=None)
    for change in plan.changes:
        row = session.get(CatalogObject, change.object_id)
        if row is None or row.kind != "project":
            raise ProjectMigrationError("project changed after planning")
        try:
            current = json.loads(row.data_json)
        except (TypeError, json.JSONDecodeError) as exc:
            raise ProjectMigrationError("project changed after planning") from exc
        if current != change.before or project_data_sha256(current) != (
            change.expected_data_sha256
        ):
            raise ProjectMigrationError("project changed after planning")
        row.data_json = json.dumps(change.after, ensure_ascii=False, sort_keys=True)
        row.revision += 1
        row.updated_at = changed_at
        add_audit_event(
            session,
            object_id=row.id,
            action="project_normalize",
            actor="project-migration",
            details={"object_ref": f"project:{row.id}"},
        )
    session.flush()
    return len(plan.changes)


def project_data_sha256(data: Mapping[str, Any]) -> str:
    encoded = json.dumps(
        data,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _section_is_invalid(data: Mapping[str, Any], section: str) -> bool:
    """Whether one nested canonical section alone fails the canonical schema."""
    category = "experiment" if section == "measurements" else "research"
    probe = {
        "schema_version": 1,
        "category": category,
        "project_status": "planned",
        section: data[section],
    }
    try:
        validate_object_data("project", probe)
    except ObjectSchemaError:
        return True
    return False


def _validate_candidate(
    row: CatalogObject,
    data: Mapping[str, Any],
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
    return candidate
