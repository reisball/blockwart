from __future__ import annotations

import json
from collections.abc import Callable, Iterable, Mapping
from copy import deepcopy
from dataclasses import dataclass
from typing import Any, Literal, cast

from blockwart.domain.asset_state import ASSET_KINDS
from blockwart.domain.object_schema import (
    BUILTIN_SCHEMAS,
)
from blockwart.domain.object_schema import (
    DECISION_STATUS_VALUES as OBJECT_SCHEMA_DECISION_STATUS_VALUES,
)
from blockwart.domain.references import TypedReference

DecisionStatus = Literal[
    "proposed",
    "accepted",
    "superseded",
    "deprecated",
    "rejected",
]
DECISION_STATUS_VALUES: tuple[DecisionStatus, ...] = tuple(
    cast(DecisionStatus, value) for value in OBJECT_SCHEMA_DECISION_STATUS_VALUES
)
DECISION_SOURCE_TYPE_VALUES = tuple(
    sorted(
        next(
            field.enum_values
            for field in BUILTIN_SCHEMAS["decision"].fields
            if field.path == "docs[].source_type"
        )
    )
)
APPLIES_TO_PATTERN = r"^(host|system|network|device|service):[^:]+$"
APPLIES_TO_MAX_LENGTH = 192


class DecisionIntegrityError(ValueError):
    """A canonical Decision link violates catalog or graph integrity."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(message)


@dataclass(frozen=True, slots=True)
class DecisionReference:
    path: str
    value: str
    parsed: TypedReference


def decision_reference_paths() -> tuple[str, ...]:
    """Derive every Decision reference path from the canonical object schema."""
    return tuple(
        field.path
        for field in BUILTIN_SCHEMAS["decision"].fields
        if field.field_type == "reference"
    )


def iter_decision_references(data: Mapping[str, Any]) -> Iterable[DecisionReference]:
    for declared_path in decision_reference_paths():
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
            yield DecisionReference(path=path, value=value, parsed=parsed)


def project_authorized_decision_data(
    data: Mapping[str, Any],
    *,
    can_discover: Callable[[str], bool],
) -> dict[str, Any]:
    """Remove typed links whose targets are concealed from the reader."""
    projected = deepcopy(dict(data))
    for declared_path in decision_reference_paths():
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


def decision_matches_filters(
    data: Mapping[str, Any],
    *,
    decision_status: DecisionStatus | None,
    applies_to: str | None,
) -> bool:
    if decision_status is not None and data.get("decision_status") != decision_status:
        return False
    if applies_to is not None:
        references = data.get("applies_to")
        if not isinstance(references, list) or applies_to not in references:
            return False
    return True


def validate_decision_integrity(
    rows: Iterable[Any],
    *,
    object_id: str,
    data: Mapping[str, Any],
) -> None:
    """Validate supersession self-references and cycles for one projected write.

    Existing legacy rows are read tolerantly. Only well-formed canonical link
    values participate in the graph, and unrelated historical defects do not
    block a write. The projected object itself is always checked fail closed.
    """
    documents: dict[str, Mapping[str, Any]] = {}
    for row in rows:
        row_id = str(_record_value(row, "id"))
        if str(_record_value(row, "kind")) != "decision" or row_id == object_id:
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
        successor = _decision_id(document.get("superseded_by"))
        if successor is not None:
            _add_edge(edges, owner_id, successor, projected_id=object_id)
        supersedes = document.get("supersedes")
        if isinstance(supersedes, list):
            for predecessor_ref in supersedes:
                predecessor = _decision_id(predecessor_ref)
                if predecessor is not None:
                    _add_edge(edges, predecessor, owner_id, projected_id=object_id)

    cycle = _first_cycle(edges)
    if cycle is not None and object_id in cycle:
        raise DecisionIntegrityError(
            "decision_supersession_cycle",
            "decision supersession links would create a cycle",
        )


def decision_contract_projection() -> dict[str, Any]:
    return {
        "decision_status": {"values": list(DECISION_STATUS_VALUES)},
        "reference_paths": list(decision_reference_paths()),
        "external_sources": {
            "path": "data.docs[]",
            "source_type_values": list(DECISION_SOURCE_TYPE_VALUES),
            "http_only": True,
            "embedded_credentials_allowed": False,
            "secret_query_parameters_allowed": False,
            "live_fetch": False,
        },
        "supersession": {
            "direction": "superseded decision to successor",
            "self_reference_allowed": False,
            "cycles_allowed": False,
            "superseded_requires": "data.superseded_by",
        },
        "legacy_reads": {
            "missing_decision_status": "readable",
            "writes": "must satisfy the canonical schema",
        },
    }


def _reference_is_discoverable(
    value: str,
    can_discover: Callable[[str], bool],
) -> bool:
    try:
        return can_discover(TypedReference.parse(value).object_id)
    except ValueError:
        return False


def _decision_id(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = TypedReference.parse(value)
    except ValueError:
        return None
    return parsed.object_id if parsed.kind == "decision" else None


def _add_edge(
    edges: dict[str, set[str]],
    source: str,
    target: str,
    *,
    projected_id: str,
) -> None:
    if source == target and source == projected_id:
        raise DecisionIntegrityError(
            "decision_self_reference",
            "a decision cannot supersede itself",
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

    for node in sorted(set(edges) | {target for targets in edges.values() for target in targets}):
        cycle = visit(node)
        if cycle is not None:
            return cycle
    return None


def _record_value(record: Any, field: str) -> Any:
    if isinstance(record, Mapping):
        return record[field]
    return getattr(record, field)


def validate_applies_to_filter(value: str) -> TypedReference:
    try:
        parsed = TypedReference.parse(value)
    except ValueError as exc:
        raise ValueError("applies_to must be an asset kind:id reference") from exc
    if parsed.kind not in ASSET_KINDS:
        raise ValueError("applies_to must be an asset kind:id reference")
    return parsed
