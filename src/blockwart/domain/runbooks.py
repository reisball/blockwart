from __future__ import annotations

import json
from collections.abc import Callable, Iterable, Mapping
from copy import deepcopy
from dataclasses import dataclass
from typing import Any, Literal, cast

from blockwart.domain.object_schema import (
    BUILTIN_SCHEMAS,
    RUNBOOK_CHANGE_FALLBACK_VALUES,
    RUNBOOK_RISK_LEVELS,
    RUNBOOK_STATUS_VALUES,
    SOURCE_TYPE_VALUES,
)
from blockwart.domain.references import TypedReference

RunbookStatus = Literal[
    "draft",
    "approved",
    "active",
    "deprecated",
    "superseded",
    "retired",
]
RunbookRisk = Literal["read-only", "safe-change", "disruptive", "destructive"]

RUNBOOK_STATUSES: tuple[RunbookStatus, ...] = tuple(
    cast(RunbookStatus, value) for value in RUNBOOK_STATUS_VALUES
)
RUNBOOK_RISKS: tuple[RunbookRisk, ...] = tuple(
    cast(RunbookRisk, value) for value in sorted(RUNBOOK_RISK_LEVELS)
)
RUNBOOK_RELATED_OBJECT_MAX_LENGTH = 192
RUNBOOK_RELATED_OBJECT_PATTERN = (
    r"^(host|system|network|device|service|credential_reference|runbook|decision|project):[^:]+$"
)


class RunbookIntegrityError(ValueError):
    """A canonical Runbook supersession link violates graph integrity."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(message)


@dataclass(frozen=True, slots=True)
class RunbookReference:
    path: str
    value: str
    parsed: TypedReference


def runbook_reference_paths() -> tuple[str, ...]:
    """Derive every Runbook reference path from the canonical object schema."""
    return tuple(
        field.path
        for field in BUILTIN_SCHEMAS["runbook"].fields
        if field.field_type == "reference"
    )


def iter_runbook_references(data: Mapping[str, Any]) -> Iterable[RunbookReference]:
    for declared_path in runbook_reference_paths():
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
            yield RunbookReference(path=path, value=value, parsed=parsed)


def authorized_runbook_data(
    data: Mapping[str, Any],
    *,
    can_discover: Callable[[str], bool],
) -> dict[str, Any]:
    """Remove typed links whose targets are concealed from the reader."""
    projected = deepcopy(dict(data))
    for declared_path in runbook_reference_paths():
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


def runbook_matches_filters(
    data: Mapping[str, Any],
    *,
    runbook_status: RunbookStatus | None,
    runbook_risk: RunbookRisk | None,
    related_object: str | None,
) -> bool:
    if runbook_status is not None and data.get("runbook_status") != runbook_status:
        return False
    if runbook_risk is not None and data.get("risk_level") != runbook_risk:
        return False
    if related_object is not None and related_object not in {
        reference.value for reference in iter_runbook_references(data)
    }:
        return False
    return True


def validate_runbook_integrity(
    rows: Iterable[Any],
    *,
    object_id: str,
    data: Mapping[str, Any],
) -> None:
    """Reject Runbook supersession self-links and cycles before persistence."""
    documents: dict[str, Mapping[str, Any]] = {}
    for row in rows:
        row_id = str(_record_value(row, "id"))
        if str(_record_value(row, "kind")) != "runbook" or row_id == object_id:
            continue
        raw = _record_value(row, "data_json")
        try:
            parsed = json.loads(str(raw))
        except (TypeError, json.JSONDecodeError):
            continue
        if isinstance(parsed, Mapping):
            documents[row_id] = parsed
    documents[object_id] = data

    edges: dict[str, set[str]] = {}
    for owner_id, document in documents.items():
        successor = _runbook_id(document.get("superseded_by"))
        if successor is not None:
            _add_edge(edges, owner_id, successor, projected_id=object_id)
        supersedes = document.get("supersedes")
        if isinstance(supersedes, list):
            for predecessor_ref in supersedes:
                predecessor = _runbook_id(predecessor_ref)
                if predecessor is not None:
                    _add_edge(edges, predecessor, owner_id, projected_id=object_id)
    cycle = _first_cycle(edges)
    if cycle is not None and object_id in cycle:
        raise RunbookIntegrityError(
            "runbook_supersession_cycle",
            "runbook supersession links would create a cycle",
        )


def validate_runbook_related_object_filter(value: str) -> TypedReference:
    try:
        parsed = TypedReference.parse(value)
    except ValueError as exc:
        raise ValueError("runbook_related_object must be a kind:id reference") from exc
    allowed = {
        kind
        for field in BUILTIN_SCHEMAS["runbook"].fields
        if field.field_type == "reference"
        for kind in field.reference_kinds
    }
    if parsed.kind not in allowed:
        raise ValueError("runbook_related_object must be a kind:id reference")
    return parsed


def runbook_contract_projection() -> dict[str, Any]:
    return {
        "runbook_status": {"values": list(RUNBOOK_STATUS_VALUES)},
        "risk_level": {"values": sorted(RUNBOOK_RISK_LEVELS)},
        "change_fallback": {"values": list(RUNBOOK_CHANGE_FALLBACK_VALUES)},
        "reference_paths": list(runbook_reference_paths()),
        "commands": {
            "paths": [
                "data.steps[].command",
                "data.rollback[].command",
                "data.recovery[].command",
            ],
            "normalization": "none",
            "round_trip": "exact",
            "inert": True,
            "shell_execution": False,
            "placeholder_expansion": False,
            "credential_resolution": False,
            "network_retrieval": False,
            "deployment": False,
            "expected_effect_path": "sibling expected_effect",
            "verification_path": "data.verification[]",
        },
        "procedures": {
            "rollback": "reverses a change",
            "recovery": "restores a safe or healthy state when reversal is insufficient",
            "distinct": True,
        },
        "external_sources": {
            "path": "data.sources[]",
            "source_type_values": list(SOURCE_TYPE_VALUES),
            "http_only": True,
            "embedded_credentials_allowed": False,
            "secret_query_parameters_allowed": False,
            "live_fetch": False,
            "full_text_import": False,
        },
        "supersession": {
            "direction": "superseded runbook to successor",
            "self_reference_allowed": False,
            "cycles_allowed": False,
            "superseded_requires": "data.superseded_by",
        },
        "knowledge_layers": {
            "fields": "current reviewed operating and recovery truth",
            "comments": "review and observation chronology",
            "audit": "material canonical-field changes without comment bodies",
            "external_docs": "sources only; never fetched or executed",
            "executor": False,
        },
        "legacy_reads": {
            "missing_runbook_status": "readable",
            "writes": "must satisfy the canonical schema",
        },
    }


def _reference_is_discoverable(value: str, can_discover: Callable[[str], bool]) -> bool:
    try:
        return can_discover(TypedReference.parse(value).object_id)
    except ValueError:
        return False


def _runbook_id(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = TypedReference.parse(value)
    except ValueError:
        return None
    return parsed.object_id if parsed.kind == "runbook" else None


def _add_edge(
    edges: dict[str, set[str]], source: str, target: str, *, projected_id: str
) -> None:
    if source == target and source == projected_id:
        raise RunbookIntegrityError(
            "runbook_self_reference", "a runbook cannot supersede itself"
        )
    edges.setdefault(source, set()).add(target)


def _first_cycle(edges: Mapping[str, set[str]]) -> tuple[str, ...] | None:
    visited: set[str] = set()
    active: set[str] = set()
    path: list[str] = []

    def visit(node: str) -> tuple[str, ...] | None:
        if node in active:
            start = path.index(node)
            return (*path[start:], node)
        if node in visited:
            return None
        visited.add(node)
        active.add(node)
        path.append(node)
        for target in sorted(edges.get(node, set())):
            cycle = visit(target)
            if cycle is not None:
                return cycle
        path.pop()
        active.remove(node)
        return None

    for node in sorted(set(edges) | {target for values in edges.values() for target in values}):
        cycle = visit(node)
        if cycle is not None:
            return cycle
    return None


def _record_value(record: Any, field: str) -> Any:
    if isinstance(record, Mapping):
        return record[field]
    return getattr(record, field)
