"""Structured browser form handling for canonical Runbook knowledge objects."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Annotated, Any

from fastapi import Form
from pydantic import ValidationError

from blockwart.domain.object_schema import (
    RUNBOOK_CHANGE_FALLBACK_VALUES,
    SOURCE_TYPE_VALUES,
    is_safe_external_http_url,
)
from blockwart.domain.runbooks import RUNBOOK_RISKS, RUNBOOK_STATUSES
from blockwart.domain.security import redact_secret_values
from blockwart.schemas.catalog import CatalogObjectIn

RUNBOOK_KIND = "runbook"
RUNBOOK_TEXT_FIELDS = (
    "purpose",
    "approval_requirement",
    "change_fallback_rationale",
    "deprecation_rationale",
    "successor_recommendation",
)
RUNBOOK_TIMESTAMP_FIELDS = ("last_verified_at", "review_after")
RUNBOOK_ENUM_FIELDS = ("runbook_status", "risk_level", "change_fallback")
RUNBOOK_REFERENCE_FIELDS = ("superseded_by",)
RUNBOOK_SCALAR_FIELDS = (
    *RUNBOOK_ENUM_FIELDS,
    *RUNBOOK_TEXT_FIELDS,
    *RUNBOOK_TIMESTAMP_FIELDS,
    *RUNBOOK_REFERENCE_FIELDS,
)
RUNBOOK_TEXT_LIST_FIELDS = ("in_scope", "out_of_scope")
RUNBOOK_REFERENCE_LIST_FIELDS = (
    "applies_to",
    "credential_references",
    "related_decisions",
    "related_projects",
    "related_runbooks",
    "supersedes",
)
RUNBOOK_LINE_FIELDS = (*RUNBOOK_TEXT_LIST_FIELDS, *RUNBOOK_REFERENCE_LIST_FIELDS)
RUNBOOK_PREREQUISITE_COLUMNS = ("id", "description")
RUNBOOK_PROCEDURE_COLUMNS = (
    "id",
    "title",
    "description",
    "command",
    "expected_effect",
)
RUNBOOK_VERIFICATION_COLUMNS = ("id", "description", "success_expectation")
RUNBOOK_SOURCE_COLUMNS = (
    "id",
    "source_type",
    "title",
    "url",
    "author",
    "publisher",
    "published_at",
    "retrieved_at",
)
RUNBOOK_TABLES: Mapping[str, tuple[str, ...]] = {
    "prerequisites": RUNBOOK_PREREQUISITE_COLUMNS,
    "steps": RUNBOOK_PROCEDURE_COLUMNS,
    "verification": RUNBOOK_VERIFICATION_COLUMNS,
    "rollback": RUNBOOK_PROCEDURE_COLUMNS,
    "recovery": RUNBOOK_PROCEDURE_COLUMNS,
    "sources": RUNBOOK_SOURCE_COLUMNS,
}

RUNBOOK_STATUS_OPTIONS = RUNBOOK_STATUSES
RUNBOOK_RISK_OPTIONS = RUNBOOK_RISKS
RUNBOOK_CHANGE_FALLBACK_OPTIONS = RUNBOOK_CHANGE_FALLBACK_VALUES
RUNBOOK_SOURCE_TYPE_OPTIONS = tuple(SOURCE_TYPE_VALUES)

_OPTIONAL_TEXT = Annotated[str | None, Form()]
_OPTIONAL_ROWS = Annotated[list[str] | None, Form()]


class RunbookForm:
    def __init__(  # noqa: PLR0913 - one browser control per canonical field
        self,
        runbook_status: _OPTIONAL_TEXT = None,
        purpose: _OPTIONAL_TEXT = None,
        in_scope: _OPTIONAL_TEXT = None,
        out_of_scope: _OPTIONAL_TEXT = None,
        risk_level: _OPTIONAL_TEXT = None,
        approval_required: _OPTIONAL_TEXT = None,
        approval_requirement: _OPTIONAL_TEXT = None,
        change_fallback: _OPTIONAL_TEXT = None,
        change_fallback_rationale: _OPTIONAL_TEXT = None,
        deprecation_rationale: _OPTIONAL_TEXT = None,
        successor_recommendation: _OPTIONAL_TEXT = None,
        applies_to: _OPTIONAL_TEXT = None,
        credential_references: _OPTIONAL_TEXT = None,
        related_decisions: _OPTIONAL_TEXT = None,
        related_projects: _OPTIONAL_TEXT = None,
        related_runbooks: _OPTIONAL_TEXT = None,
        supersedes: _OPTIONAL_TEXT = None,
        superseded_by: _OPTIONAL_TEXT = None,
        last_verified_at: _OPTIONAL_TEXT = None,
        review_after: _OPTIONAL_TEXT = None,
        prerequisite_id: _OPTIONAL_ROWS = None,
        prerequisite_description: _OPTIONAL_ROWS = None,
        step_id: _OPTIONAL_ROWS = None,
        step_title: _OPTIONAL_ROWS = None,
        step_description: _OPTIONAL_ROWS = None,
        step_command: _OPTIONAL_ROWS = None,
        step_expected_effect: _OPTIONAL_ROWS = None,
        verification_id: _OPTIONAL_ROWS = None,
        verification_description: _OPTIONAL_ROWS = None,
        verification_success_expectation: _OPTIONAL_ROWS = None,
        rollback_id: _OPTIONAL_ROWS = None,
        rollback_title: _OPTIONAL_ROWS = None,
        rollback_description: _OPTIONAL_ROWS = None,
        rollback_command: _OPTIONAL_ROWS = None,
        rollback_expected_effect: _OPTIONAL_ROWS = None,
        recovery_id: _OPTIONAL_ROWS = None,
        recovery_title: _OPTIONAL_ROWS = None,
        recovery_description: _OPTIONAL_ROWS = None,
        recovery_command: _OPTIONAL_ROWS = None,
        recovery_expected_effect: _OPTIONAL_ROWS = None,
        runbook_source_id: _OPTIONAL_ROWS = None,
        runbook_source_source_type: _OPTIONAL_ROWS = None,
        runbook_source_title: _OPTIONAL_ROWS = None,
        runbook_source_url: _OPTIONAL_ROWS = None,
        runbook_source_author: _OPTIONAL_ROWS = None,
        runbook_source_publisher: _OPTIONAL_ROWS = None,
        runbook_source_published_at: _OPTIONAL_ROWS = None,
        runbook_source_retrieved_at: _OPTIONAL_ROWS = None,
    ) -> None:
        local = locals()
        self.values: dict[str, str | None] = {
            name: local[name] for name in (*RUNBOOK_SCALAR_FIELDS, *RUNBOOK_LINE_FIELDS)
        }
        self.approval_required = approval_required
        self.tables: dict[str, list[dict[str, str]]] = {
            "prerequisites": _submitted_rows(
                RUNBOOK_PREREQUISITE_COLUMNS,
                {
                    "id": prerequisite_id,
                    "description": prerequisite_description,
                },
            ),
            "steps": _procedure_rows("step", local),
            "verification": _submitted_rows(
                RUNBOOK_VERIFICATION_COLUMNS,
                {
                    "id": verification_id,
                    "description": verification_description,
                    "success_expectation": verification_success_expectation,
                },
            ),
            "rollback": _procedure_rows("rollback", local),
            "recovery": _procedure_rows("recovery", local),
            "sources": _submitted_rows(
                RUNBOOK_SOURCE_COLUMNS,
                {
                    key: local[f"runbook_source_{key}"]
                    for key in RUNBOOK_SOURCE_COLUMNS
                },
            ),
        }

    @property
    def submitted(self) -> bool:
        return (
            any(value is not None for value in self.values.values())
            or self.approval_required is not None
            or any(self.tables.values())
        )


def _procedure_rows(prefix: str, local: Mapping[str, Any]) -> list[dict[str, str]]:
    return _submitted_rows(
        RUNBOOK_PROCEDURE_COLUMNS,
        {key: local[f"{prefix}_{key}"] for key in RUNBOOK_PROCEDURE_COLUMNS},
    )


def _submitted_rows(
    columns: tuple[str, ...], submitted: Mapping[str, list[str] | None]
) -> list[dict[str, str]]:
    values = {key: submitted[key] or [] for key in columns}
    count = max((len(column) for column in values.values()), default=0)
    return [
        {
            key: (column[index] if index < len(column) else "")
            for key, column in values.items()
        }
        for index in range(count)
    ]


def apply_runbook_form_data(
    data: dict[str, Any],
    form: RunbookForm,
    *,
    concealed_references: Mapping[str, list[str]] | None = None,
    preserve_legacy_sources: bool = False,
) -> None:
    data["schema_version"] = 1
    for field_name in RUNBOOK_SCALAR_FIELDS:
        _assign(data, field_name, str(form.values.get(field_name) or "").strip())
    for field_name in RUNBOOK_LINE_FIELDS:
        items = split_form_lines(form.values.get(field_name))
        for reference in (concealed_references or {}).get(field_name, []):
            if reference not in items:
                items.append(reference)
        _assign(data, field_name, items)
    successor = (concealed_references or {}).get("superseded_by", [])
    if successor:
        data["superseded_by"] = successor[0]
    data["approval_required"] = form.approval_required == "true"

    for table, columns in RUNBOOK_TABLES.items():
        entries: list[dict[str, str]] = []
        for row in form.tables[table]:
            entry: dict[str, str] = {}
            for column in columns:
                raw = str(row.get(column) or "")
                value = raw if column == "command" else raw.strip()
                if value:
                    entry[column] = value
            if entry:
                entries.append(entry)
        if entries:
            data[table] = entries
        elif table != "sources" or not preserve_legacy_sources:
            data.pop(table, None)


def runbook_form_values(data: Mapping[str, Any]) -> dict[str, str]:
    values = {
        field_name: str(data.get(field_name) or "")
        for field_name in RUNBOOK_SCALAR_FIELDS
    }
    for field_name in RUNBOOK_LINE_FIELDS:
        raw = data.get(field_name)
        values[field_name] = (
            "\n".join(str(item) for item in raw if isinstance(item, str))
            if isinstance(raw, list)
            else ""
        )
    values["approval_required"] = (
        "true" if data.get("approval_required") is True else "false"
    )
    return values


def split_form_lines(value: str | None) -> list[str]:
    if value is None:
        return []
    return [line for raw in value.splitlines() if (line := raw.strip())]


def safe_runbook_form_values(form: RunbookForm) -> dict[str, str]:
    values = {
        key: str(redact_secret_values(value or "")) for key, value in form.values.items()
    }
    values["approval_required"] = (
        "true" if form.approval_required == "true" else "false"
    )
    return values


def safe_runbook_form_rows(form: RunbookForm, table: str) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for row in form.tables[table]:
        safe: dict[str, str] = {}
        for column, raw in row.items():
            value = str(raw or "")
            safe[column] = (
                value
                if column == "url" and is_safe_external_http_url(value)
                else ""
                if column == "url"
                else str(redact_secret_values(value))
            )
        rows.append(safe)
    return rows


def canonical_runbook_rows(data: Mapping[str, Any], table: str) -> list[dict[str, Any]]:
    raw_entries = data.get(table)
    if not isinstance(raw_entries, list):
        return []
    rows: list[dict[str, Any]] = []
    for raw in raw_entries:
        try:
            candidate = CatalogObjectIn(
                id="runbook-section-validation",
                kind=RUNBOOK_KIND,
                label="Runbook section validation",
                data={
                    "schema_version": 1,
                    "runbook_status": "draft",
                    "approval_required": False,
                    table: [raw],
                },
            )
        except ValidationError:
            continue
        normalized = dict(candidate.data[table][0])
        if table == "sources":
            url = str(normalized.get("url") or "")
            normalized["safe_url"] = url if is_safe_external_http_url(url) else ""
        rows.append(normalized)
    return rows


def runbook_has_legacy_rows(data: Mapping[str, Any], table: str) -> bool:
    raw = data.get(table)
    return isinstance(raw, list) and len(canonical_runbook_rows(data, table)) != len(raw)


def blank_runbook_rows(table: str) -> list[dict[str, str]]:
    return [{column: "" for column in RUNBOOK_TABLES[table]}]


def _assign(data: dict[str, Any], key: str, value: Any) -> None:
    if value:
        data[key] = value
    else:
        data.pop(key, None)
