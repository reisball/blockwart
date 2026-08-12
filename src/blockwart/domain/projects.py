from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from copy import deepcopy
from dataclasses import dataclass
from typing import Any, Literal, cast

from blockwart.domain.object_schema import (
    BUILTIN_SCHEMAS,
    PROJECT_CATEGORY_FIELD_NAMES,
    PROJECT_CATEGORY_VALUES,
    PROJECT_COMMON_ONLY_CATEGORY_FIELD_NAMES,
    PROJECT_EVIDENCE_GRADE_VALUES,
    PROJECT_MANAGED_BY_KIND_VALUES,
    PROJECT_TIMELINE_REFERENCE_TYPE_VALUES,
)
from blockwart.domain.object_schema import (
    PROJECT_STATUS_VALUES as OBJECT_SCHEMA_PROJECT_STATUS_VALUES,
)
from blockwart.domain.references import TypedReference

ProjectCategory = Literal[
    "implementation",
    "migration",
    "research",
    "experiment",
    "incident_review",
    "other",
]
ProjectStatus = Literal[
    "planned",
    "active",
    "paused",
    "completed",
    "cancelled",
    "archived",
]
PROJECT_CATEGORIES: tuple[ProjectCategory, ...] = tuple(
    cast(ProjectCategory, value) for value in PROJECT_CATEGORY_VALUES
)
PROJECT_STATUSES: tuple[ProjectStatus, ...] = tuple(
    cast(ProjectStatus, value) for value in OBJECT_SCHEMA_PROJECT_STATUS_VALUES
)
PROJECT_SOURCE_TYPE_VALUES = tuple(
    sorted(
        next(
            field.enum_values
            for field in BUILTIN_SCHEMAS["project"].fields
            if field.path == "sources[].source_type"
        )
    )
)
# One exact `kind:id` reference naming any object a Project may point at.
RELATED_OBJECT_PATTERN = (
    r"^(host|system|network|device|service|runbook|decision|project):[^:]+$"
)
RELATED_OBJECT_MAX_LENGTH = 192


@dataclass(frozen=True, slots=True)
class ProjectReference:
    path: str
    value: str
    parsed: TypedReference


def project_reference_paths() -> tuple[str, ...]:
    """Derive every Project reference path from the canonical object schema."""
    return tuple(
        field.path
        for field in BUILTIN_SCHEMAS["project"].fields
        if field.field_type == "reference"
    )


def iter_project_references(data: Mapping[str, Any]) -> Iterable[ProjectReference]:
    for declared_path in project_reference_paths():
        key = declared_path.removesuffix("[]")
        raw = data.get(key)
        values = raw if declared_path.endswith("[]") and isinstance(raw, list) else [raw]
        for index, value in enumerate(values):
            if not isinstance(value, str):
                continue
            try:
                parsed = TypedReference.parse(value)
            except ValueError:
                continue
            path = f"data.{key}[{index}]" if declared_path.endswith("[]") else f"data.{key}"
            yield ProjectReference(path=path, value=value, parsed=parsed)


def project_authorized_data(
    data: Mapping[str, Any],
    *,
    can_discover: Callable[[str], bool],
) -> dict[str, Any]:
    """Remove typed links whose targets are concealed from the reader."""
    projected = deepcopy(dict(data))
    for declared_path in project_reference_paths():
        key = declared_path.removesuffix("[]")
        raw = projected.get(key)
        if declared_path.endswith("[]"):
            if isinstance(raw, list):
                projected[key] = [
                    value
                    for value in raw
                    if not isinstance(value, str)
                    or _reference_is_discoverable(value, can_discover)
                ]
            continue
        if isinstance(raw, str) and not _reference_is_discoverable(raw, can_discover):
            projected.pop(key, None)
    return projected


def project_matches_filters(
    data: Mapping[str, Any],
    *,
    project_category: ProjectCategory | None,
    project_status: ProjectStatus | None,
    related_object: str | None,
) -> bool:
    if project_category is not None and data.get("category") != project_category:
        return False
    if project_status is not None and data.get("project_status") != project_status:
        return False
    if related_object is not None:
        related = {
            reference.value for reference in iter_project_references(data)
        }
        if related_object not in related:
            return False
    return True


def project_category_fields(category: str | None) -> tuple[str, ...]:
    """Return the category-specific field names one category admits."""
    if not isinstance(category, str):
        return ()
    return tuple(
        sorted(
            PROJECT_CATEGORY_FIELD_NAMES.get(
                category,
                PROJECT_COMMON_ONLY_CATEGORY_FIELD_NAMES,
            )
        )
    )


def project_contract_projection() -> dict[str, Any]:
    return {
        "category": {
            "values": list(PROJECT_CATEGORY_VALUES),
            "guessed_during_compatibility": False,
            "fields_by_category": {
                category: list(project_category_fields(category))
                for category in PROJECT_CATEGORY_VALUES
            },
        },
        "project_status": {"values": list(OBJECT_SCHEMA_PROJECT_STATUS_VALUES)},
        "evidence": {
            "findings_path": "data.findings[]",
            "grades": list(PROJECT_EVIDENCE_GRADE_VALUES),
            "source_backed_requires_source_ids": True,
            "citation_target": "data.sources[].id",
            "evidence_timestamps": ["observed_at", "verified_at"],
            "contradictory_findings_allowed": True,
        },
        "external_sources": {
            "path": "data.sources[]",
            "source_type_values": list(PROJECT_SOURCE_TYPE_VALUES),
            "http_only": True,
            "embedded_credentials_allowed": False,
            "secret_query_parameters_allowed": False,
            "live_fetch": False,
            "full_text_import": False,
        },
        "ownership": {
            "path": "data.managed_by",
            "kinds": list(PROJECT_MANAGED_BY_KIND_VALUES),
            "grants_access": False,
            "resolved": False,
        },
        "timeline_reference": {
            "path": "data.timeline_reference",
            "types": list(PROJECT_TIMELINE_REFERENCE_TYPE_VALUES),
        },
        "reference_paths": list(project_reference_paths()),
        "knowledge_layers": {
            "fields": "current reviewed knowledge and results",
            "comments": "append-only work chronology, never promoted automatically",
            "audit": "material canonical-field changes without comment or secret bodies",
            "decisions": "binding choices created from the work",
            "runbooks": "resulting operational or recovery procedures",
            "external_docs": "large originals, referenced but never imported",
        },
        "legacy_reads": {
            "missing_category": "readable",
            "writes": "must satisfy the canonical schema",
        },
    }


def validate_related_object_filter(value: str) -> TypedReference:
    try:
        parsed = TypedReference.parse(value)
    except ValueError as exc:
        raise ValueError("related_object must be a kind:id reference") from exc
    allowed = {
        kind
        for field in BUILTIN_SCHEMAS["project"].fields
        if field.field_type == "reference"
        for kind in field.reference_kinds
    }
    if parsed.kind not in allowed:
        raise ValueError("related_object must be a kind:id reference")
    return parsed


def _reference_is_discoverable(
    value: str,
    can_discover: Callable[[str], bool],
) -> bool:
    try:
        return can_discover(TypedReference.parse(value).object_id)
    except ValueError:
        return False
