"""Structured browser form handling for canonical Project knowledge objects.

Every control here is derived from the canonical schema in
`blockwart.domain.object_schema`; nothing in this module defines a second
contract. Normal users never edit raw JSON: scalars, line lists, typed
reference lists, the closed nested groups, and the closed nested tables all
have their own controls, and the canonical validator remains the only authority
on what is accepted.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Annotated, Any

from fastapi import Form
from pydantic import ValidationError

from blockwart.domain.object_schema import (
    PROJECT_CATEGORY_VALUES,
    PROJECT_EVIDENCE_GRADE_VALUES,
    PROJECT_EXTERNAL_REFERENCE_KIND_VALUES,
    PROJECT_MANAGED_BY_KIND_VALUES,
    PROJECT_STATUS_VALUES,
    PROJECT_TIMELINE_REFERENCE_TYPE_VALUES,
    SOURCE_TYPE_VALUES,
    is_safe_external_http_url,
)
from blockwart.domain.projects import project_category_fields
from blockwart.domain.security import redact_secret_values
from blockwart.schemas.catalog import CatalogObjectIn

PROJECT_KIND = "project"

PROJECT_TEXT_FIELDS = (
    "objective",
    "current_summary",
    "methodology",
    "hypothesis",
    "setup",
    "expected_result",
    "observed_result",
    "conclusion",
    "reproducibility_notes",
    "impact",
    "detection",
    "root_cause",
    "source_state",
    "target_state",
    "rollback",
    "outcome",
)
PROJECT_TIMESTAMP_FIELDS = ("started_at", "completed_at", "review_after")
PROJECT_TEXT_LIST_FIELDS = (
    "in_scope",
    "out_of_scope",
    "open_questions",
    "blockers",
    "recommendations",
    "next_actions",
    "lessons_learned",
    "research_questions",
    "hypotheses",
    "limitations",
    "conclusions",
    "contributing_factors",
    "remediation",
    "prevention",
    "migration_plan",
    "verification",
)
PROJECT_REFERENCE_LIST_FIELDS = (
    "related_assets",
    "related_runbooks",
    "related_decisions",
    "related_projects",
)
PROJECT_ENUM_FIELDS = ("category", "project_status")
PROJECT_SCALAR_FIELDS = (
    *PROJECT_ENUM_FIELDS,
    *PROJECT_TEXT_FIELDS,
    *PROJECT_TIMESTAMP_FIELDS,
)
PROJECT_LINE_FIELDS = (*PROJECT_TEXT_LIST_FIELDS, *PROJECT_REFERENCE_LIST_FIELDS)
PROJECT_GROUP_FIELDS: Mapping[str, tuple[str, ...]] = {
    "managed_by": ("kind", "label", "principal_id"),
    "incident_window": ("started_at", "ended_at"),
    "timeline_reference": ("type", "source_id", "note"),
}
PROJECT_SOURCE_COLUMNS = (
    "id",
    "source_type",
    "reference_kind",
    "title",
    "url",
    "author",
    "publisher",
    "published_at",
    "retrieved_at",
)
PROJECT_FINDING_COLUMNS = (
    "id",
    "statement",
    "evidence_grade",
    "source_ids",
    "observed_at",
    "verified_at",
)
PROJECT_MEASUREMENT_COLUMNS = ("name", "quantity", "unit", "observed_at")
PROJECT_TABLES: Mapping[str, tuple[str, ...]] = {
    "sources": PROJECT_SOURCE_COLUMNS,
    "findings": PROJECT_FINDING_COLUMNS,
    "measurements": PROJECT_MEASUREMENT_COLUMNS,
}
# The single finding column that carries several ids in one control.
FINDING_LIST_COLUMNS = frozenset({"source_ids"})

PROJECT_CATEGORY_OPTIONS = PROJECT_CATEGORY_VALUES
PROJECT_STATUS_OPTIONS = PROJECT_STATUS_VALUES
PROJECT_SOURCE_TYPE_OPTIONS = tuple(sorted(SOURCE_TYPE_VALUES))
PROJECT_REFERENCE_KIND_OPTIONS = PROJECT_EXTERNAL_REFERENCE_KIND_VALUES
PROJECT_EVIDENCE_GRADE_OPTIONS = PROJECT_EVIDENCE_GRADE_VALUES
PROJECT_MANAGED_BY_KIND_OPTIONS = PROJECT_MANAGED_BY_KIND_VALUES
PROJECT_TIMELINE_TYPE_OPTIONS = PROJECT_TIMELINE_REFERENCE_TYPE_VALUES

_OPTIONAL_TEXT = Annotated[str | None, Form()]
_OPTIONAL_ROWS = Annotated[list[str] | None, Form()]


class ProjectForm:
    """The submitted Project section of a browser create or edit request."""

    def __init__(  # noqa: PLR0913 - one browser control per canonical field
        self,
        category: _OPTIONAL_TEXT = None,
        project_status: _OPTIONAL_TEXT = None,
        objective: _OPTIONAL_TEXT = None,
        current_summary: _OPTIONAL_TEXT = None,
        methodology: _OPTIONAL_TEXT = None,
        hypothesis: _OPTIONAL_TEXT = None,
        setup: _OPTIONAL_TEXT = None,
        expected_result: _OPTIONAL_TEXT = None,
        observed_result: _OPTIONAL_TEXT = None,
        conclusion: _OPTIONAL_TEXT = None,
        reproducibility_notes: _OPTIONAL_TEXT = None,
        impact: _OPTIONAL_TEXT = None,
        detection: _OPTIONAL_TEXT = None,
        root_cause: _OPTIONAL_TEXT = None,
        source_state: _OPTIONAL_TEXT = None,
        target_state: _OPTIONAL_TEXT = None,
        rollback: _OPTIONAL_TEXT = None,
        outcome: _OPTIONAL_TEXT = None,
        started_at: _OPTIONAL_TEXT = None,
        completed_at: _OPTIONAL_TEXT = None,
        review_after: _OPTIONAL_TEXT = None,
        in_scope: _OPTIONAL_TEXT = None,
        out_of_scope: _OPTIONAL_TEXT = None,
        open_questions: _OPTIONAL_TEXT = None,
        blockers: _OPTIONAL_TEXT = None,
        recommendations: _OPTIONAL_TEXT = None,
        next_actions: _OPTIONAL_TEXT = None,
        lessons_learned: _OPTIONAL_TEXT = None,
        research_questions: _OPTIONAL_TEXT = None,
        hypotheses: _OPTIONAL_TEXT = None,
        limitations: _OPTIONAL_TEXT = None,
        conclusions: _OPTIONAL_TEXT = None,
        contributing_factors: _OPTIONAL_TEXT = None,
        remediation: _OPTIONAL_TEXT = None,
        prevention: _OPTIONAL_TEXT = None,
        migration_plan: _OPTIONAL_TEXT = None,
        verification: _OPTIONAL_TEXT = None,
        related_assets: _OPTIONAL_TEXT = None,
        related_runbooks: _OPTIONAL_TEXT = None,
        related_decisions: _OPTIONAL_TEXT = None,
        related_projects: _OPTIONAL_TEXT = None,
        managed_by_kind: _OPTIONAL_TEXT = None,
        managed_by_label: _OPTIONAL_TEXT = None,
        managed_by_principal_id: _OPTIONAL_TEXT = None,
        incident_window_started_at: _OPTIONAL_TEXT = None,
        incident_window_ended_at: _OPTIONAL_TEXT = None,
        timeline_reference_type: _OPTIONAL_TEXT = None,
        timeline_reference_source_id: _OPTIONAL_TEXT = None,
        timeline_reference_note: _OPTIONAL_TEXT = None,
        source_id: _OPTIONAL_ROWS = None,
        source_source_type: _OPTIONAL_ROWS = None,
        source_reference_kind: _OPTIONAL_ROWS = None,
        source_title: _OPTIONAL_ROWS = None,
        source_url: _OPTIONAL_ROWS = None,
        source_author: _OPTIONAL_ROWS = None,
        source_publisher: _OPTIONAL_ROWS = None,
        source_published_at: _OPTIONAL_ROWS = None,
        source_retrieved_at: _OPTIONAL_ROWS = None,
        finding_id: _OPTIONAL_ROWS = None,
        finding_statement: _OPTIONAL_ROWS = None,
        finding_evidence_grade: _OPTIONAL_ROWS = None,
        finding_source_ids: _OPTIONAL_ROWS = None,
        finding_observed_at: _OPTIONAL_ROWS = None,
        finding_verified_at: _OPTIONAL_ROWS = None,
        measurement_name: _OPTIONAL_ROWS = None,
        measurement_quantity: _OPTIONAL_ROWS = None,
        measurement_unit: _OPTIONAL_ROWS = None,
        measurement_observed_at: _OPTIONAL_ROWS = None,
    ) -> None:
        local = locals()
        self.values: dict[str, str | None] = {
            name: local[name]
            for name in (*PROJECT_SCALAR_FIELDS, *PROJECT_LINE_FIELDS)
        }
        self.groups: dict[str, dict[str, str | None]] = {
            group: {key: local[f"{group}_{key}"] for key in keys}
            for group, keys in PROJECT_GROUP_FIELDS.items()
        }
        self.tables: dict[str, list[dict[str, str]]] = {
            "sources": _submitted_rows(
                PROJECT_SOURCE_COLUMNS,
                {key: local[f"source_{key}"] for key in PROJECT_SOURCE_COLUMNS},
            ),
            "findings": _submitted_rows(
                PROJECT_FINDING_COLUMNS,
                {key: local[f"finding_{key}"] for key in PROJECT_FINDING_COLUMNS},
            ),
            "measurements": _submitted_rows(
                PROJECT_MEASUREMENT_COLUMNS,
                {
                    key: local[f"measurement_{key}"]
                    for key in PROJECT_MEASUREMENT_COLUMNS
                },
            ),
        }

    @property
    def submitted(self) -> bool:
        return (
            any(value is not None for value in self.values.values())
            or any(
                value is not None
                for group in self.groups.values()
                for value in group.values()
            )
            or any(rows for rows in self.tables.values())
        )

    @property
    def category(self) -> str:
        return str(self.values.get("category") or "").strip()


def _submitted_rows(
    columns: tuple[str, ...],
    submitted: Mapping[str, list[str] | None],
) -> list[dict[str, str]]:
    """Zip the parallel per-column form arrays back into positional rows."""
    values = {key: submitted[key] or [] for key in columns}
    count = max((len(column) for column in values.values()), default=0)
    return [
        {
            key: (column[index] if index < len(column) else "")
            for key, column in values.items()
        }
        for index in range(count)
    ]


def apply_project_form_data(
    data: dict[str, Any],
    form: ProjectForm,
    *,
    concealed_references: Mapping[str, list[str]] | None = None,
    preserve_legacy_sources: bool = False,
) -> None:
    """Write one submitted Project form onto the canonical data document.

    Every canonical field the contract knows is rewritten from the submission,
    including the category-specific fields of *other* categories, which are
    removed. A category switch therefore cannot leave contradictory leftovers
    behind. Unknown legacy extension fields are never touched.
    """
    data["schema_version"] = 1
    for field_name in PROJECT_SCALAR_FIELDS:
        _assign(data, field_name, str(form.values.get(field_name) or "").strip())
    for field_name in PROJECT_LINE_FIELDS:
        items = split_form_lines(form.values.get(field_name))
        for reference in (concealed_references or {}).get(field_name, []):
            if reference not in items:
                items.append(reference)
        _assign(data, field_name, items)
    for group, keys in PROJECT_GROUP_FIELDS.items():
        submitted = form.groups[group]
        entry = {
            key: value
            for key in keys
            if (value := str(submitted.get(key) or "").strip())
        }
        _assign(data, group, entry)
    for table, columns in PROJECT_TABLES.items():
        entries: list[dict[str, Any]] = []
        for row in form.tables[table]:
            entry: dict[str, Any] = {}
            for column in columns:
                raw = str(row.get(column) or "").strip()
                if column in FINDING_LIST_COLUMNS:
                    items = split_form_lines(raw)
                    if items:
                        entry[column] = items
                elif raw:
                    entry[column] = raw
            if entry:
                entries.append(entry)
        if entries:
            data[table] = entries
        elif table != "sources" or not preserve_legacy_sources:
            data.pop(table, None)
    _drop_foreign_category_fields(data, form.category)


def apply_project_workspace_form_data(
    data: dict[str, Any],
    form: ProjectForm,
    *,
    concealed_references: Mapping[str, list[str]] | None = None,
    preserve_legacy_sources: bool = False,
) -> None:
    """Patch only the focused work-state fields shown by the Project workspace.

    Category-specific reviewed results and every unknown compatible extension
    remain untouched. Concealed typed references are retained because a reader
    cannot safely confirm or remove a target they cannot discover.
    """
    data["schema_version"] = 1
    for field_name in ("objective", "current_summary"):
        _assign(data, field_name, str(form.values.get(field_name) or "").strip())
    for field_name in (
        "in_scope",
        "out_of_scope",
        "open_questions",
        "blockers",
        "next_actions",
        *PROJECT_REFERENCE_LIST_FIELDS,
    ):
        items = _deduplicated_lines(form.values.get(field_name))
        for reference in (concealed_references or {}).get(field_name, []):
            if reference not in items:
                items.append(reference)
        _assign(data, field_name, items)

    sources: list[dict[str, Any]] = []
    for row in form.tables["sources"]:
        entry = {
            column: raw
            for column in PROJECT_SOURCE_COLUMNS
            if (raw := str(row.get(column) or "").strip())
        }
        if entry:
            sources.append(entry)
    if sources:
        data["sources"] = sources
    elif not preserve_legacy_sources:
        data.pop("sources", None)


def _deduplicated_lines(value: str | None) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for line in split_form_lines(value):
        if line in seen:
            continue
        seen.add(line)
        result.append(line)
    return result


def _drop_foreign_category_fields(data: dict[str, Any], category: str) -> None:
    allowed = set(project_category_fields(category))
    for other in PROJECT_CATEGORY_VALUES:
        for field_name in project_category_fields(other):
            if field_name not in allowed:
                data.pop(field_name, None)


def _assign(data: dict[str, Any], field_name: str, value: Any) -> None:
    if value:
        data[field_name] = value
    else:
        data.pop(field_name, None)


def split_form_lines(value: str | None) -> list[str]:
    if value is None:
        return []
    return [line for raw in value.splitlines() if (line := raw.strip())]


def project_form_values(data: Mapping[str, Any]) -> dict[str, str]:
    """Render one stored Project document back into flat form values."""
    values = {
        field_name: str(data.get(field_name) or "")
        for field_name in PROJECT_SCALAR_FIELDS
    }
    for field_name in PROJECT_LINE_FIELDS:
        raw = data.get(field_name)
        values[field_name] = (
            "\n".join(str(item) for item in raw if isinstance(item, str))
            if isinstance(raw, list)
            else ""
        )
    for group, keys in PROJECT_GROUP_FIELDS.items():
        entry = data.get(group)
        entry = entry if isinstance(entry, Mapping) else {}
        for key in keys:
            values[f"{group}_{key}"] = str(entry.get(key) or "")
    return values


def safe_project_form_values(form: ProjectForm) -> dict[str, str]:
    """Redact a rejected submission before echoing it back into the form."""
    values = {
        key: str(redact_secret_values(value or ""))
        for key, value in form.values.items()
    }
    for group, keys in PROJECT_GROUP_FIELDS.items():
        for key in keys:
            values[f"{group}_{key}"] = str(
                redact_secret_values(form.groups[group].get(key) or "")
            )
    return values


def safe_project_form_rows(form: ProjectForm, table: str) -> list[dict[str, str]]:
    """Redact rejected table rows, dropping any URL that is not safe to echo."""
    safe_rows: list[dict[str, str]] = []
    for row in form.tables[table]:
        safe_row: dict[str, str] = {}
        for column, value in row.items():
            text = str(value or "")
            if column == "url":
                safe_row[column] = text if is_safe_external_http_url(text) else ""
            else:
                safe_row[column] = str(redact_secret_values(text))
        safe_rows.append(safe_row)
    return safe_rows


def canonical_project_rows(
    data: Mapping[str, Any],
    table: str,
) -> list[dict[str, Any]]:
    """Return only the entries of one nested table that are canonically valid.

    Historical entries that do not satisfy the closed shape stay in storage but
    are never rendered as if they were reviewed content, and an unsafe URL is
    never emitted as a link.
    """
    rows: list[dict[str, Any]] = []
    raw_entries = data.get(table)
    if not isinstance(raw_entries, list):
        return rows
    declared_sources = _declared_sources(data) if table == "findings" else []
    for raw in raw_entries:
        normalized = _canonical_project_row(table, raw, declared_sources)
        if normalized is not None:
            rows.append(normalized)
    return rows


def _declared_sources(data: Mapping[str, Any]) -> list[Any]:
    """The stored source entries a finding is allowed to cite."""
    raw_sources = data.get("sources")
    if not isinstance(raw_sources, list):
        return []
    return [
        entry
        for entry in raw_sources
        if _canonical_project_row("sources", entry, []) is not None
    ]


def project_has_legacy_rows(data: Mapping[str, Any], table: str) -> bool:
    raw_entries = data.get(table)
    if not isinstance(raw_entries, list):
        return False
    return len(canonical_project_rows(data, table)) != len(raw_entries)


def _canonical_project_row(
    table: str,
    raw: Any,
    declared_sources: list[Any],
) -> dict[str, Any] | None:
    probe: dict[str, Any] = {
        "schema_version": 1,
        "category": "experiment" if table == "measurements" else "research",
        "project_status": "planned",
        table: [raw],
    }
    if table == "findings" and declared_sources:
        probe["sources"] = declared_sources
    try:
        candidate = CatalogObjectIn(
            id="project-section-validation",
            kind=PROJECT_KIND,
            label="Project section validation",
            data=probe,
        )
    except ValidationError:
        return None
    normalized = dict(candidate.data[table][0])
    if table == "sources":
        url = str(normalized.get("url") or "")
        normalized["safe_url"] = url if is_safe_external_http_url(url) else ""
    if table == "findings":
        cited = normalized.get("source_ids")
        normalized["source_ids_text"] = "\n".join(
            str(item) for item in cited if isinstance(item, str)
        ) if isinstance(cited, list) else ""
    return normalized


def blank_project_rows(table: str) -> list[dict[str, str]]:
    """One empty starter row so an empty table still renders an editor."""
    return [{column: "" for column in PROJECT_TABLES[table]}]
