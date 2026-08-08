"""JSON-safe projection of the canonical relationship registry.

Machine contracts (MCP tools, OpenAPI, documentation, clients) publish this
projection instead of restating the relationship vocabulary. It is generated
from the same in-code registry that validates every relationship write, so a
published contract cannot drift from server-side validation, and
`blockwart.domain.relationships` stays the single source of truth.

The projection describes the contract only. It never contains stored objects,
edges, or metadata values: it publishes registered relationship types, their
accepted directed endpoint kinds, the safe general endpoint predicates, the
type-dependent metadata fields, the graph rules, the revision semantics of the
commands, and the published rejection catalog.
"""

from __future__ import annotations

from typing import Any

from blockwart.domain.object_schema import (
    VIOLATION_FORBIDDEN_KEY,
    VIOLATION_REQUIRED_FIELD_MISSING,
    VIOLATION_TYPE_MISMATCH,
    VIOLATION_VALUE_NOT_ALLOWED,
    VIOLATION_VALUE_TOO_LONG,
    VIOLATION_VALUE_TOO_SHORT,
)
from blockwart.domain.relationships import (
    CATEGORY_SENSITIVE_PREDICATES,
    ENDPOINT_PREDICATE_CONTRACTS,
    GRAPH_RULE_CONTRACTS,
    NETWORK_DEVICE_CATEGORIES,
    RELATIONSHIP_PATH_ROOTS,
    RELATIONSHIP_REJECTIONS,
    RELATIONSHIP_RULES,
    RELATIONSHIP_TYPES,
    RelationshipMetadataFieldSpec,
    allowed_endpoint_pairs,
)
from blockwart.domain.schema_projection import FORBIDDEN, OPTIONAL, REQUIRED
from blockwart.domain.validation_errors import PUBLIC_DETAIL_FIELDS

RELATIONSHIP_PROJECTION_VERSION = 1


def relationship_projection(kind: str | None = None) -> dict[str, Any]:
    """Return the complete machine-readable projection of the relationship registry.

    `kind` restricts the detailed entries to the relationship types that accept
    that object kind on either endpoint. The published `relation_types`
    vocabulary always stays the complete closed registry, so a filtered
    contract can never look like a different one.
    """
    return {
        "version": RELATIONSHIP_PROJECTION_VERSION,
        "source": "blockwart.domain.relationships",
        "relation_types": list(RELATIONSHIP_TYPES),
        "relation_type_is_closed": True,
        "endpoint_predicates": endpoint_predicate_projections(),
        "graph_rules": [
            {"rule": rule, "description": description}
            for rule, description in sorted(GRAPH_RULE_CONTRACTS.items())
        ],
        "metadata_policy": metadata_policy_projection(),
        "command_semantics": command_semantics_projection(),
        "rejection_policy": rejection_policy_projection(),
        "types": [
            relationship_type_projection(relation_type)
            for relation_type in RELATIONSHIP_TYPES
            if kind is None or _accepts_kind(relation_type, kind)
        ],
    }


def relationship_type_projection(relation_type: str) -> dict[str, Any]:
    """Return the published contract for exactly one registered relationship type."""
    rule = RELATIONSHIP_RULES[relation_type]
    pairs = sorted(allowed_endpoint_pairs(relation_type))
    return {
        "relation_type": relation_type,
        "description": rule.description,
        "direction": {
            "from_kinds": sorted({from_kind for from_kind, _ in pairs}),
            "to_kinds": sorted({to_kind for _, to_kind in pairs}),
            "directed_pairs": [
                {"from_kind": from_kind, "to_kind": to_kind} for from_kind, to_kind in pairs
            ],
        },
        "endpoint_predicate": endpoint_predicate_projection(rule.endpoint_predicate_name),
        "metadata": metadata_projection(relation_type),
        "graph_rules": [
            {"rule": rule_name, "description": GRAPH_RULE_CONTRACTS[rule_name]}
            for rule_name in sorted(rule.graph_rules)
        ],
    }


def endpoint_predicate_projections() -> list[dict[str, Any]]:
    """Publish every endpoint predicate the registry can apply."""
    return [endpoint_predicate_projection(name) for name in sorted(ENDPOINT_PREDICATE_CONTRACTS)]


def endpoint_predicate_projection(name: str) -> dict[str, Any]:
    """Publish one endpoint predicate as a safe general rule.

    Category-sensitive predicates additionally read stored endpoint data, so a
    client cannot decide them from the typed references alone. The projection
    names that dependency and publishes the category vocabulary it uses; it
    never publishes a concrete object, edge, or stored category value.
    """
    category_sensitive = name in CATEGORY_SENSITIVE_PREDICATES
    projected: dict[str, Any] = {
        "name": name,
        "description": ENDPOINT_PREDICATE_CONTRACTS[name],
        "decidable_from_request": not category_sensitive,
    }
    if category_sensitive:
        projected["network_device_categories"] = sorted(NETWORK_DEVICE_CATEGORIES)
    return projected


def metadata_policy_projection() -> dict[str, Any]:
    """Publish the rules every relationship metadata document shares."""
    return {
        "type_dependent": True,
        "unknown_fields": FORBIDDEN,
        "canonical_empty_value": {},
        "secret_values_rejected": True,
        "description": (
            "Relationship metadata is validated against the fields of its exact "
            "relationship type. A type without published metadata fields accepts "
            "an empty document only. Unset fields stay absent from the canonical "
            "document instead of being stored as null."
        ),
    }


def metadata_projection(relation_type: str) -> dict[str, Any]:
    """Return the type-dependent metadata contract of one relationship type."""
    rule = RELATIONSHIP_RULES[relation_type]
    return {
        "supported": bool(rule.metadata_fields),
        "requirement": OPTIONAL if rule.metadata_fields else FORBIDDEN,
        "unknown_fields": FORBIDDEN,
        "fields": [metadata_field_projection(spec) for spec in rule.metadata_fields],
        "json_schema": metadata_json_schema(relation_type),
    }


def metadata_field_projection(spec: RelationshipMetadataFieldSpec) -> dict[str, Any]:
    """Project one immutable metadata field spec into its published contract."""
    projected: dict[str, Any] = {
        "name": spec.name,
        "json_type": spec.json_type,
        "requirement": REQUIRED if spec.required else OPTIONAL,
        "normalization": ["strip_whitespace"] if spec.json_type == "string" else [],
    }
    if spec.json_type == "string":
        projected["min_length"] = 1
    if spec.max_length is not None:
        projected["max_length"] = spec.max_length
    if spec.enum_values:
        projected["enum"] = sorted(spec.enum_values)
    projected["violations"] = sorted(metadata_field_violations(spec))
    return projected


def metadata_field_violations(spec: RelationshipMetadataFieldSpec) -> set[str]:
    """Return every violation type one metadata field can raise, from its own rules."""
    violations = {VIOLATION_TYPE_MISMATCH}
    if spec.required:
        violations.add(VIOLATION_REQUIRED_FIELD_MISSING)
    if spec.json_type == "string":
        violations.add(VIOLATION_VALUE_TOO_SHORT)
    if spec.max_length is not None:
        violations.add(VIOLATION_VALUE_TOO_LONG)
    if spec.enum_values:
        violations.add(VIOLATION_VALUE_NOT_ALLOWED)
    if spec.reject_secrets:
        violations.add(VIOLATION_FORBIDDEN_KEY)
    return violations


def command_semantics_projection() -> dict[str, Any]:
    """Publish the revision, idempotency, and no-op semantics of the commands."""
    return {
        "precondition": "if_match",
        "create_replaces_metadata": True,
        "no_op_when_metadata_is_unchanged": True,
        "advances_revision_when_changed": True,
        "delete_ignores_metadata": True,
        "description": (
            "Creating an existing triplet replaces its canonical metadata. An "
            "identical canonical document is a no-op: the response reports "
            "changed = false and neither endpoint revision advances. Any actual "
            "create, metadata replacement, or delete advances both endpoint "
            "revisions and writes exactly one audit event. Delete matches the "
            "triplet only; it never depends on stored metadata."
        ),
    }


def rejection_policy_projection() -> dict[str, Any]:
    """Publish the stable rejection catalog of relationship commands."""
    return {
        "detail_fields": list(PUBLIC_DETAIL_FIELDS),
        "path_roots": list(RELATIONSHIP_PATH_ROOTS),
        "stages": ["request", "catalog", "graph"],
        "rejections": [
            {
                "code": rejection.code,
                "stage": rejection.stage,
                "description": rejection.description,
                "violation": rejection.violation,
                "field_accurate": rejection.violation is not None,
            }
            for rejection in sorted(RELATIONSHIP_REJECTIONS.values(), key=lambda entry: entry.code)
        ],
        "description": (
            "A request-stage rejection follows from the command payload alone: "
            "it is published as a field validation error naming one canonical "
            "relationship path and one violation code. Catalog- and graph-stage "
            "rejections depend on stored state and are published as conflicts "
            "without a field, so no rejected caller can probe the catalog "
            "through them."
        ),
    }


def relation_type_json_schema() -> dict[str, Any]:
    """Return the closed JSON Schema of the `relation_type` argument."""
    return {
        "type": "string",
        "enum": list(RELATIONSHIP_TYPES),
        "description": (
            "Registered relationship type. Accepted endpoint kinds and metadata "
            "fields depend on this exact value."
        ),
    }


def metadata_json_schema(relation_type: str) -> dict[str, Any]:
    """Return the JSON Schema of exactly one relationship type's metadata."""
    rule = RELATIONSHIP_RULES[relation_type]
    return _metadata_object_schema(rule.metadata_fields)


def metadata_union_json_schema() -> dict[str, Any]:
    """Return the JSON Schema of every published metadata field of any type.

    The union is the shared shape of the `metadata` argument; the published
    conditions narrow it to the exact fields of the requested relationship
    type.
    """
    specs: dict[str, RelationshipMetadataFieldSpec] = {}
    for rule in RELATIONSHIP_RULES.values():
        for spec in rule.metadata_fields:
            specs.setdefault(spec.name, spec)
    return _metadata_object_schema(tuple(specs.values()))


def relationship_metadata_conditions() -> list[dict[str, Any]]:
    """Return one JSON Schema condition per relationship type.

    Each condition binds the accepted metadata document to the exact
    relationship type, so a published contract states the type-dependent
    metadata rules instead of the union of every type's fields.
    """
    return [
        {
            "if": {
                "properties": {"relation_type": {"const": relation_type}},
                "required": ["relation_type"],
            },
            "then": {"properties": {"metadata": metadata_json_schema(relation_type)}},
        }
        for relation_type in RELATIONSHIP_TYPES
    ]


def _metadata_object_schema(
    specs: tuple[RelationshipMetadataFieldSpec, ...],
) -> dict[str, Any]:
    schema: dict[str, Any] = {
        "type": "object",
        "additionalProperties": False,
        "properties": {spec.name: _metadata_field_json_schema(spec) for spec in specs},
    }
    required = [spec.name for spec in specs if spec.required]
    if required:
        schema["required"] = required
    return schema


def _metadata_field_json_schema(spec: RelationshipMetadataFieldSpec) -> dict[str, Any]:
    if spec.json_type == "boolean":
        return {"type": "boolean"}
    if spec.enum_values:
        return {"type": "string", "enum": sorted(spec.enum_values)}
    schema: dict[str, Any] = {"type": "string", "minLength": 1}
    if spec.max_length is not None:
        schema["maxLength"] = spec.max_length
    return schema


def _accepts_kind(relation_type: str, kind: str) -> bool:
    return any(kind in pair for pair in allowed_endpoint_pairs(relation_type))
