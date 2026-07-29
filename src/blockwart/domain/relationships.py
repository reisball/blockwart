from __future__ import annotations

import json
from collections import Counter
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from blockwart.domain.placement import (
    CANONICAL_PLACEMENT_RELATION_TYPE,
    SUPPORTED_PLACEMENT_PAIRS,
)
from blockwart.domain.references import VALID_REFERENCE_KINDS, TypedReference

ASSET_KINDS = frozenset({"host", "system", "network", "service"})
ALL_KINDS = frozenset(VALID_REFERENCE_KINDS)


@dataclass(frozen=True)
class RelationshipRule:
    relation_type: str
    from_kinds: frozenset[str]
    to_kinds: frozenset[str]
    description: str


RELATIONSHIP_RULES: dict[str, RelationshipRule] = {
    CANONICAL_PLACEMENT_RELATION_TYPE: RelationshipRule(
        relation_type=CANONICAL_PLACEMENT_RELATION_TYPE,
        from_kinds=frozenset({"host", "system"}),
        to_kinds=frozenset({"system", "service"}),
        description="Canonical parent-to-child asset placement.",
    ),
    "depends_on": RelationshipRule(
        relation_type="depends_on",
        from_kinds=ASSET_KINDS,
        to_kinds=ASSET_KINDS,
        description="The source asset operationally depends on the target asset.",
    ),
    "supports": RelationshipRule(
        relation_type="supports",
        from_kinds=frozenset({"service"}),
        to_kinds=frozenset({"service"}),
        description="The source service supports the target service.",
    ),
    "feeds": RelationshipRule(
        relation_type="feeds",
        from_kinds=frozenset({"service"}),
        to_kinds=frozenset({"service"}),
        description="The source service feeds data or work to the target service.",
    ),
    "exposes": RelationshipRule(
        relation_type="exposes",
        from_kinds=frozenset({"service"}),
        to_kinds=frozenset({"service"}),
        description="The source service exposes the target service interface.",
    ),
    "documents": RelationshipRule(
        relation_type="documents",
        from_kinds=frozenset({"runbook", "decision", "project"}),
        to_kinds=ALL_KINDS,
        description="The source knowledge object documents the target object.",
    ),
    "uses": RelationshipRule(
        relation_type="uses",
        from_kinds=ALL_KINDS,
        to_kinds=ALL_KINDS,
        description="The source object explicitly uses the target object.",
    ),
    "related_to": RelationshipRule(
        relation_type="related_to",
        from_kinds=ALL_KINDS,
        to_kinds=ALL_KINDS,
        description="A deliberately loose directed association.",
    ),
}
RELATIONSHIP_TYPES = tuple(RELATIONSHIP_RULES)


class RelationshipIntegrityError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True, order=True)
class RelationshipDiagnostic:
    code: str
    location: str
    message: str


def object_kind_map(objects: Iterable[Any]) -> dict[str, str]:
    return {
        str(_record_value(obj, "id")): str(_record_value(obj, "kind"))
        for obj in objects
    }


def validate_relationship(
    *,
    from_ref: str,
    relation_type: str,
    to_ref: str,
    object_kinds: Mapping[str, str],
) -> tuple[TypedReference, TypedReference]:
    rule = RELATIONSHIP_RULES.get(relation_type)
    if rule is None:
        raise RelationshipIntegrityError(
            "unsupported_relation_type",
            f"unsupported relationship type: {relation_type}",
        )

    source = resolve_reference(from_ref, object_kinds, location="from_ref")
    target = resolve_reference(to_ref, object_kinds, location="to_ref")
    if source.object_id == target.object_id:
        raise RelationshipIntegrityError(
            "self_reference",
            f"relationship must not reference the same object twice: {from_ref}",
        )
    if (source.kind, target.kind) not in _allowed_pairs(rule):
        raise RelationshipIntegrityError(
            "invalid_relationship_direction",
            f"unsupported relationship direction: {from_ref} {relation_type} {to_ref}",
        )
    return source, target


def validate_relationship_collection(
    relationships: Iterable[Any],
    object_kinds: Mapping[str, str],
) -> None:
    triplets: list[tuple[str, str, str]] = []
    placement_parents: dict[str, set[str]] = {}
    for relationship in relationships:
        from_ref = str(_record_value(relationship, "from_ref"))
        relation_type = str(_record_value(relationship, "relation_type"))
        to_ref = str(_record_value(relationship, "to_ref"))
        validate_relationship(
            from_ref=from_ref,
            relation_type=relation_type,
            to_ref=to_ref,
            object_kinds=object_kinds,
        )
        triplets.append((from_ref, relation_type, to_ref))
        if relation_type == CANONICAL_PLACEMENT_RELATION_TYPE:
            placement_parents.setdefault(to_ref, set()).add(from_ref)

    duplicate = next(
        (triplet for triplet, count in Counter(triplets).items() if count > 1),
        None,
    )
    if duplicate is not None:
        raise RelationshipIntegrityError(
            "duplicate_relationship",
            f"duplicate relationship: {' '.join(duplicate)}",
        )
    conflicting_parent = next(
        (
            (child_ref, sorted(parent_refs))
            for child_ref, parent_refs in placement_parents.items()
            if len(parent_refs) > 1
        ),
        None,
    )
    if conflicting_parent is not None:
        child_ref, parent_refs = conflicting_parent
        raise RelationshipIntegrityError(
            "multiple_placement_parents",
            f"{child_ref} has multiple placement parents: {', '.join(parent_refs)}",
        )


def resolve_reference(
    value: str,
    object_kinds: Mapping[str, str],
    *,
    location: str,
) -> TypedReference:
    try:
        parsed = TypedReference.parse(value)
    except ValueError as exc:
        raise RelationshipIntegrityError(
            "invalid_typed_reference",
            f"{location} is not a valid typed reference: {value}",
        ) from exc
    actual_kind = object_kinds.get(parsed.object_id)
    if actual_kind is None:
        raise RelationshipIntegrityError(
            "dangling_typed_reference",
            f"{location} references a missing object: {value}",
        )
    if actual_kind != parsed.kind:
        raise RelationshipIntegrityError(
            "typed_reference_kind_mismatch",
            f"{location} asserts {parsed.kind} but {parsed.object_id} is {actual_kind}",
        )
    return parsed


def iter_typed_reference_strings(value: Any) -> Iterable[str]:
    if isinstance(value, Mapping):
        for child in value.values():
            yield from iter_typed_reference_strings(child)
        return
    if isinstance(value, list | tuple):
        for child in value:
            yield from iter_typed_reference_strings(child)
        return
    if not isinstance(value, str) or ":" not in value:
        return
    prefix = value.split(":", 1)[0]
    if prefix in VALID_REFERENCE_KINDS:
        yield value


def validate_data_references(
    data: Mapping[str, Any],
    object_kinds: Mapping[str, str],
    *,
    object_id: str,
) -> None:
    for index, reference in enumerate(iter_typed_reference_strings(data)):
        resolve_reference(
            reference,
            object_kinds,
            location=f"catalog_objects[{object_id}].data_ref[{index}]",
        )


def dependency_relationships_from_data(
    *,
    owner_ref: str,
    data: Mapping[str, Any],
) -> list[dict[str, str]]:
    dependencies = data.get("dependencies")
    if dependencies is None:
        return []
    if not isinstance(dependencies, Mapping):
        raise RelationshipIntegrityError(
            "invalid_legacy_dependencies",
            "data.dependencies must be an object",
        )

    relationships: list[dict[str, str]] = []
    for side in ("upstream", "downstream"):
        references = dependencies.get(side, [])
        if not isinstance(references, list):
            raise RelationshipIntegrityError(
                "invalid_legacy_dependencies",
                f"data.dependencies.{side} must be a list",
            )
        for reference in references:
            if not isinstance(reference, str):
                raise RelationshipIntegrityError(
                    "invalid_legacy_dependencies",
                    f"data.dependencies.{side} entries must be typed references",
                )
            if side == "upstream":
                from_ref, to_ref = owner_ref, reference
            else:
                from_ref, to_ref = reference, owner_ref
            relationships.append(
                {
                    "from_ref": from_ref,
                    "relation_type": "depends_on",
                    "to_ref": to_ref,
                }
            )
    return relationships


def diagnose_relationship_integrity(
    objects: Iterable[Any],
    relationships: Iterable[Any],
) -> list[RelationshipDiagnostic]:
    object_rows = list(objects)
    relationship_rows = list(relationships)
    object_kinds = object_kind_map(object_rows)
    diagnostics: list[RelationshipDiagnostic] = []
    triplets: list[tuple[str, str, str]] = []
    placement_parents: dict[str, set[str]] = {}

    for index, relationship in enumerate(relationship_rows):
        relationship_id = _optional_record_value(relationship, "id")
        location = (
            f"relationships[{relationship_id}]"
            if relationship_id is not None
            else f"relationships[{index}]"
        )
        from_ref = str(_record_value(relationship, "from_ref"))
        relation_type = str(_record_value(relationship, "relation_type"))
        to_ref = str(_record_value(relationship, "to_ref"))
        try:
            validate_relationship(
                from_ref=from_ref,
                relation_type=relation_type,
                to_ref=to_ref,
                object_kinds=object_kinds,
            )
        except RelationshipIntegrityError as exc:
            diagnostics.append(
                RelationshipDiagnostic(exc.code, location, str(exc))
            )
            continue
        triplets.append((from_ref, relation_type, to_ref))
        if relation_type == CANONICAL_PLACEMENT_RELATION_TYPE:
            placement_parents.setdefault(to_ref, set()).add(from_ref)

    for triplet, count in sorted(Counter(triplets).items()):
        if count > 1:
            diagnostics.append(
                RelationshipDiagnostic(
                    "duplicate_relationship",
                    "relationships",
                    f"{count} copies of {' '.join(triplet)}",
                )
            )
    for child_ref, parent_refs in sorted(placement_parents.items()):
        if len(parent_refs) > 1:
            diagnostics.append(
                RelationshipDiagnostic(
                    "multiple_placement_parents",
                    child_ref,
                    f"multiple placement parents: {', '.join(sorted(parent_refs))}",
                )
            )

    for row in object_rows:
        object_id = str(_record_value(row, "id"))
        raw_data = _record_value(row, "data_json")
        try:
            data = json.loads(str(raw_data))
        except (TypeError, json.JSONDecodeError):
            diagnostics.append(
                RelationshipDiagnostic(
                    "invalid_object_json",
                    f"catalog_objects[{object_id}]",
                    "data_json is not valid JSON",
                )
            )
            continue
        if not isinstance(data, dict):
            diagnostics.append(
                RelationshipDiagnostic(
                    "invalid_object_json",
                    f"catalog_objects[{object_id}]",
                    "data_json must contain an object",
                )
            )
            continue
        if "dependencies" in data:
            diagnostics.append(
                RelationshipDiagnostic(
                    "obsolete_data_dependencies",
                    f"catalog_objects[{object_id}]",
                    "data.dependencies must be stored as depends_on relationships",
                )
            )
        for index, reference in enumerate(iter_typed_reference_strings(data)):
            try:
                resolve_reference(
                    reference,
                    object_kinds,
                    location=f"catalog_objects[{object_id}].data_ref[{index}]",
                )
            except RelationshipIntegrityError as exc:
                diagnostics.append(
                    RelationshipDiagnostic(
                        exc.code,
                        f"catalog_objects[{object_id}]",
                        str(exc),
                    )
                )

    return sorted(set(diagnostics))


def _allowed_pairs(rule: RelationshipRule) -> frozenset[tuple[str, str]]:
    if rule.relation_type == CANONICAL_PLACEMENT_RELATION_TYPE:
        return frozenset(SUPPORTED_PLACEMENT_PAIRS)
    return frozenset(
        (from_kind, to_kind)
        for from_kind in rule.from_kinds
        for to_kind in rule.to_kinds
    )


def _record_value(record: Any, field: str) -> Any:
    if isinstance(record, Mapping):
        return record[field]
    return getattr(record, field)


def _optional_record_value(record: Any, field: str) -> Any | None:
    if isinstance(record, Mapping):
        return record.get(field)
    return getattr(record, field, None)
