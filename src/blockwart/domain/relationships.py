from __future__ import annotations

import json
import re
from collections import Counter
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Literal

from blockwart.domain.object_schema import (
    DEVICE_CATEGORIES,
    NETWORK_CATEGORIES,
    VIOLATION_FIELD_NOT_ALLOWED,
    VIOLATION_FORBIDDEN_KEY,
    VIOLATION_INVALID_FORMAT,
    VIOLATION_REQUIRED_FIELD_MISSING,
    VIOLATION_TYPE_MISMATCH,
    VIOLATION_VALUE_NOT_ALLOWED,
    VIOLATION_VALUE_TOO_LONG,
    VIOLATION_VALUE_TOO_SHORT,
    ObjectSchemaError,
    normalize_object_data,
    validate_object_data,
)
from blockwart.domain.placement import (
    CANONICAL_PLACEMENT_RELATION_TYPE,
    SUPPORTED_PLACEMENT_PAIRS,
)
from blockwart.domain.references import VALID_REFERENCE_KINDS, TypedReference
from blockwart.domain.security import find_secret_violations

ASSET_KINDS = frozenset({"host", "system", "network", "device", "service"})
ALL_KINDS = frozenset(VALID_REFERENCE_KINDS)
NETWORK_DEVICE_CATEGORIES = frozenset(
    {"switch", "router", "access_point", "mesh", "firewall", "gateway", "other_device"}
)
LINK_KINDS = frozenset(
    {
        "ethernet",
        "wifi",
        "mesh",
        "zigbee",
        "bluetooth",
        "usb",
        "serial",
        "gpio",
        "power",
        "virtual",
        "other",
    }
)
UPLINK_MODES = frozenset({"access", "trunk", "routed", "bridged", "mesh", "other"})
RelationshipMetadataJsonType = Literal["string", "boolean"]

# Request paths a rejected relationship command can name. They are the closed
# set of canonical relationship locations a boundary may publish; anything else
# stays internal.
RELATIONSHIP_PATH_ROOTS: tuple[str, ...] = ("from_ref", "metadata", "relation_type", "to_ref")
REFERENCE_PATHS = frozenset({"from_ref", "to_ref"})
_METADATA_FIELD_PATTERN = re.compile(r"^[A-Za-z0-9_-]{1,64}$")

# Endpoint predicates are published by name and description only. They describe
# the safe general rule a client can check before a write; the concrete objects,
# edges, and stored categories a rejection saw stay internal.
ENDPOINT_PREDICATE_CONTRACTS: Mapping[str, str] = MappingProxyType(
    {
        "kind_pair_allowed": (
            "Every endpoint pair listed under directed_pairs is accepted; the "
            "relationship type adds no further endpoint condition."
        ),
        "attached_endpoint_allowed": (
            "A device may attach to a host, a system, another device, or a "
            "network device; a host or system may attach only to a network "
            "device. A network endpoint qualifies as a network device only "
            "through its published network device categories."
        ),
        "network_devices_only": (
            "Both endpoints must be network objects whose category is one of "
            "the published network device categories."
        ),
    }
)
# Predicates that additionally depend on the stored endpoint category, so a
# client cannot decide them from the typed references alone.
CATEGORY_SENSITIVE_PREDICATES = frozenset({"attached_endpoint_allowed", "network_devices_only"})

# Graph rules hold across a set of edges instead of one command payload. They
# are declared per relationship type and enforced by the central collection
# validator.
GRAPH_RULE_CONTRACTS: Mapping[str, str] = MappingProxyType(
    {
        "single_placement_parent": (
            "A child object may have at most one canonical placement parent."
        ),
        "single_primary_per_source": (
            "At most one edge per source object and relationship type may carry "
            "metadata.primary = true."
        ),
        "acyclic_edges": (
            "The directed edges of this relationship type must not contain a cycle."
        ),
    }
)
_COLLECTION_GRAPH_RULES = frozenset({"single_primary_per_source", "acyclic_edges"})


@dataclass(frozen=True)
class EndpointDescriptor:
    kind: str
    data: Mapping[str, Any]


EndpointPredicate = Callable[[EndpointDescriptor, EndpointDescriptor], bool]


@dataclass(frozen=True)
class RelationshipMetadataFieldSpec:
    name: str
    json_type: RelationshipMetadataJsonType
    required: bool = False
    max_length: int | None = None
    enum_values: frozenset[str] = frozenset()
    reject_secrets: bool = True


_COMMON_LINK_METADATA_FIELDS = (
    RelationshipMetadataFieldSpec("source_interface", "string", max_length=128),
    RelationshipMetadataFieldSpec("target_interface_or_port", "string", max_length=128),
    RelationshipMetadataFieldSpec("link_kind", "string", enum_values=LINK_KINDS),
    RelationshipMetadataFieldSpec("primary", "boolean"),
    RelationshipMetadataFieldSpec("note", "string", max_length=512),
)


def _kind_pair_allowed(source: EndpointDescriptor, target: EndpointDescriptor) -> bool:
    del source, target
    return True


def _network_category(endpoint: EndpointDescriptor) -> str | None:
    network = endpoint.data.get("network")
    if not isinstance(network, Mapping):
        return None
    category = network.get("category")
    return category if isinstance(category, str) else None


def is_network_device(endpoint: EndpointDescriptor) -> bool:
    return endpoint.kind == "network" and _network_category(endpoint) in NETWORK_DEVICE_CATEGORIES


def _attached_endpoint_allowed(
    source: EndpointDescriptor,
    target: EndpointDescriptor,
) -> bool:
    if source.kind == "device":
        return target.kind in {"host", "system", "device"} or is_network_device(target)
    if source.kind in {"host", "system"}:
        return is_network_device(target)
    return False


def _uplink_endpoint_allowed(
    source: EndpointDescriptor,
    target: EndpointDescriptor,
) -> bool:
    return is_network_device(source) and is_network_device(target)


@dataclass(frozen=True)
class RelationshipRule:
    relation_type: str
    from_kinds: frozenset[str]
    to_kinds: frozenset[str]
    description: str
    endpoint_predicate_name: str = "kind_pair_allowed"
    endpoint_predicate: EndpointPredicate = _kind_pair_allowed
    metadata_fields: tuple[RelationshipMetadataFieldSpec, ...] = ()
    graph_rules: frozenset[str] = frozenset()


RELATIONSHIP_RULES: dict[str, RelationshipRule] = {
    CANONICAL_PLACEMENT_RELATION_TYPE: RelationshipRule(
        relation_type=CANONICAL_PLACEMENT_RELATION_TYPE,
        from_kinds=frozenset({"host", "system"}),
        to_kinds=frozenset({"system", "service"}),
        description="Canonical parent-to-child asset placement.",
        graph_rules=frozenset({"single_placement_parent"}),
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
    "attached_to": RelationshipRule(
        relation_type="attached_to",
        from_kinds=frozenset({"host", "system", "device"}),
        to_kinds=frozenset({"host", "system", "network", "device"}),
        description="The source endpoint is directly attached to its immediate upstream endpoint.",
        endpoint_predicate_name="attached_endpoint_allowed",
        endpoint_predicate=_attached_endpoint_allowed,
        metadata_fields=_COMMON_LINK_METADATA_FIELDS,
        graph_rules=frozenset({"single_primary_per_source", "acyclic_edges"}),
    ),
    "uplinks_to": RelationshipRule(
        relation_type="uplinks_to",
        from_kinds=frozenset({"network"}),
        to_kinds=frozenset({"network"}),
        description="The source network device uplinks to the target network device.",
        endpoint_predicate_name="network_devices_only",
        endpoint_predicate=_uplink_endpoint_allowed,
        metadata_fields=(
            *_COMMON_LINK_METADATA_FIELDS,
            RelationshipMetadataFieldSpec("mode", "string", enum_values=UPLINK_MODES),
        ),
        graph_rules=frozenset({"single_primary_per_source", "acyclic_edges"}),
    ),
}
RELATIONSHIP_TYPES = tuple(RELATIONSHIP_RULES)
# Relationship types whose stored edge set is additionally validated as a graph.
GRAPH_TRACKED_TYPES = frozenset(
    relation_type
    for relation_type, rule in RELATIONSHIP_RULES.items()
    if rule.graph_rules & _COLLECTION_GRAPH_RULES
)

@dataclass(frozen=True)
class RelationshipRejection:
    """The published contract of one stable relationship rejection code.

    `stage` says what a rejection needed to decide: `request` rejections follow
    from the command payload alone and are attributable to one request field,
    `catalog` rejections additionally read the stored endpoints, and `graph`
    rejections hold across the surrounding edge set. `violation` is the
    published violation type of a `request` rejection.
    """

    code: str
    stage: Literal["request", "catalog", "graph"]
    description: str
    violation: str | None = None


# Every field-attributable relationship rejection maps onto the same published
# violation catalog the object write contract uses, so one client error handler
# covers both. Catalog and graph rejections deliberately publish no field: they
# are decided by stored state a rejected caller must not be able to probe.
RELATIONSHIP_REJECTIONS: Mapping[str, RelationshipRejection] = MappingProxyType(
    {
        rejection.code: rejection
        for rejection in (
            RelationshipRejection(
                "unsupported_relation_type",
                "request",
                "The relationship type is not part of the registered vocabulary.",
                VIOLATION_VALUE_NOT_ALLOWED,
            ),
            RelationshipRejection(
                "invalid_typed_reference",
                "request",
                "An endpoint is not a valid kind:id typed reference.",
                VIOLATION_INVALID_FORMAT,
            ),
            RelationshipRejection(
                "self_reference",
                "request",
                "Both endpoints name the same object.",
                VIOLATION_VALUE_NOT_ALLOWED,
            ),
            RelationshipRejection(
                "invalid_relationship_direction",
                "request",
                (
                    "The asserted endpoint kinds are not a directed pair of this "
                    "relationship type."
                ),
                VIOLATION_VALUE_NOT_ALLOWED,
            ),
            RelationshipRejection(
                "invalid_relationship_metadata",
                "request",
                (
                    "The metadata document violates the type-dependent metadata "
                    "contract of this relationship type."
                ),
                VIOLATION_FIELD_NOT_ALLOWED,
            ),
            RelationshipRejection(
                "secret_relationship_metadata",
                "request",
                "The metadata document carries secret-shaped keys or values.",
                VIOLATION_FORBIDDEN_KEY,
            ),
            RelationshipRejection(
                "dangling_typed_reference",
                "catalog",
                "An endpoint reference names no existing catalog object.",
            ),
            RelationshipRejection(
                "typed_reference_kind_mismatch",
                "catalog",
                "An endpoint reference asserts a different kind than the stored object.",
            ),
            RelationshipRejection(
                "invalid_relationship_endpoint",
                "catalog",
                "The stored endpoints violate the endpoint predicate of this type.",
            ),
            RelationshipRejection(
                "duplicate_relationship",
                "graph",
                "The same from_ref, relation_type, and to_ref triplet already exists.",
            ),
            RelationshipRejection(
                "multiple_placement_parents",
                "graph",
                "The child object would have more than one canonical placement parent.",
            ),
            RelationshipRejection(
                "multiple_primary_relationships",
                "graph",
                "The source object would carry more than one primary edge of this type.",
            ),
            RelationshipRejection(
                "relationship_cycle",
                "graph",
                "The edge would close a cycle in an acyclic relationship graph.",
            ),
        )
    }
)
RELATIONSHIP_VIOLATIONS: Mapping[str, str] = MappingProxyType(
    {
        code: rejection.violation
        for code, rejection in RELATIONSHIP_REJECTIONS.items()
        if rejection.violation is not None
    }
)


class RelationshipIntegrityError(ValueError):
    """A relationship violates the canonical registry contract.

    `code` stays the established stable domain code. `path` names the canonical
    relationship request path when the rejection is attributable to one field,
    and `violation` the published violation type for it. A rejection that only
    a stored catalog state can decide carries neither, so a boundary publishes
    it as a conflict instead of inventing a field.
    """

    def __init__(
        self,
        code: str,
        message: str,
        *,
        path: str | None = None,
        violation: str | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.path = path
        self.violation = (
            violation if violation is not None else RELATIONSHIP_VIOLATIONS.get(code)
        )


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


def endpoint_descriptor_map(
    objects: Iterable[Any],
    *,
    validate_catalog_schema: bool = True,
) -> dict[str, EndpointDescriptor]:
    descriptors: dict[str, EndpointDescriptor] = {}
    for obj in objects:
        object_id = str(_record_value(obj, "id"))
        kind = str(_record_value(obj, "kind"))
        raw_data = _optional_record_value(obj, "data")
        if raw_data is None:
            raw_data = _record_value(obj, "data_json")
            try:
                raw_data = json.loads(str(raw_data))
            except (TypeError, json.JSONDecodeError) as exc:
                raise RelationshipIntegrityError(
                    "invalid_endpoint_data",
                    f"catalog object {object_id} has invalid data_json",
                ) from exc
        if not isinstance(raw_data, Mapping):
            raise RelationshipIntegrityError(
                "invalid_endpoint_data",
                f"catalog object {object_id} data must be an object",
            )
        try:
            canonical_data = normalize_object_data(kind, raw_data)
            if validate_catalog_schema:
                validate_object_data(
                    kind,
                    canonical_data,
                    allow_legacy_network_without_category=True,
                )
        except (KeyError, ObjectSchemaError) as exc:
            raise RelationshipIntegrityError(
                "invalid_endpoint_data",
                f"catalog object {object_id} violates the catalog schema",
            ) from exc
        if kind == "network":
            network = canonical_data.get("network")
            category = network.get("category") if isinstance(network, Mapping) else None
            if category is not None and category not in NETWORK_CATEGORIES:
                raise RelationshipIntegrityError(
                    "invalid_endpoint_data",
                    f"catalog object {object_id} has an unknown network category",
                )
        if kind == "device":
            device = canonical_data.get("device")
            category = device.get("category") if isinstance(device, Mapping) else None
            if category not in DEVICE_CATEGORIES:
                raise RelationshipIntegrityError(
                    "invalid_endpoint_data",
                    f"catalog object {object_id} has an invalid device category",
                )
        descriptors[object_id] = EndpointDescriptor(
            kind=kind,
            data=MappingProxyType(canonical_data),
        )
    return descriptors


def validate_relationship(
    *,
    from_ref: str,
    relation_type: str,
    to_ref: str,
    endpoints: Mapping[str, EndpointDescriptor],
) -> tuple[TypedReference, TypedReference]:
    rule = _require_rule(relation_type)

    source = resolve_reference(from_ref, endpoints, location="from_ref")
    target = resolve_reference(to_ref, endpoints, location="to_ref")
    _validate_endpoint_kinds(
        rule,
        from_ref=from_ref,
        source=source,
        to_ref=to_ref,
        target=target,
    )
    source_endpoint = endpoints[source.object_id]
    target_endpoint = endpoints[target.object_id]
    if not rule.endpoint_predicate(source_endpoint, target_endpoint):
        raise RelationshipIntegrityError(
            "invalid_relationship_endpoint",
            f"relationship endpoints violate {rule.endpoint_predicate_name}: "
            f"{from_ref} {relation_type} {to_ref}",
        )
    return source, target


def validate_relationship_request(
    *,
    from_ref: str,
    relation_type: str,
    to_ref: str,
    metadata: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Validate one relationship command payload against the canonical registry.

    This is the catalog-free part of the contract: the registered relationship
    type, the typed-reference grammar, the asserted endpoint kinds, and the
    type-dependent metadata. It reads no catalog data, so a boundary can reject
    an impossible request without disclosing whether any object exists.

    Rules that depend on stored endpoint data (endpoint predicates, reference
    existence) and on the surrounding edge set (graph rules) stay with
    `validate_relationship` and `validate_relationship_collection`.
    """
    rule = _require_rule(relation_type)
    source = parse_reference(from_ref, location="from_ref")
    target = parse_reference(to_ref, location="to_ref")
    _validate_endpoint_kinds(
        rule,
        from_ref=from_ref,
        source=source,
        to_ref=to_ref,
        target=target,
    )
    return validate_relationship_metadata(relation_type, metadata)


def allowed_endpoint_pairs(relation_type: str) -> frozenset[tuple[str, str]]:
    """Return every accepted `(from_kind, to_kind)` pair of one relationship type."""
    return _allowed_pairs(_require_rule(relation_type))


def _require_rule(relation_type: str) -> RelationshipRule:
    rule = RELATIONSHIP_RULES.get(relation_type)
    if rule is None:
        raise RelationshipIntegrityError(
            "unsupported_relation_type",
            f"unsupported relationship type: {relation_type}",
            path="relation_type",
        )
    return rule


def _validate_endpoint_kinds(
    rule: RelationshipRule,
    *,
    from_ref: str,
    source: TypedReference,
    to_ref: str,
    target: TypedReference,
) -> None:
    if source.object_id == target.object_id:
        raise RelationshipIntegrityError(
            "self_reference",
            f"relationship must not reference the same object twice: {from_ref}",
            path="to_ref",
        )
    pairs = _allowed_pairs(rule)
    if (source.kind, target.kind) in pairs:
        return
    raise RelationshipIntegrityError(
        "invalid_relationship_direction",
        f"unsupported relationship direction: {from_ref} {rule.relation_type} {to_ref}",
        path="from_ref" if source.kind not in {pair[0] for pair in pairs} else "to_ref",
    )


def validate_relationship_collection(
    relationships: Iterable[Any],
    endpoints: Mapping[str, EndpointDescriptor],
) -> None:
    relationship_rows = list(relationships)
    triplets: list[tuple[str, str, str]] = []
    placement_parents: dict[str, set[str]] = {}
    for relationship in relationship_rows:
        from_ref = str(_record_value(relationship, "from_ref"))
        relation_type = str(_record_value(relationship, "relation_type"))
        to_ref = str(_record_value(relationship, "to_ref"))
        validate_relationship(
            from_ref=from_ref,
            relation_type=relation_type,
            to_ref=to_ref,
            endpoints=endpoints,
        )
        relationship_metadata(relationship, relation_type=relation_type)
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
    graph_diagnostics = relationship_graph_diagnostics(relationship_rows, endpoints)
    if graph_diagnostics:
        first = graph_diagnostics[0]
        raise RelationshipIntegrityError(first.code, first.message)


def validate_relationship_metadata(
    relation_type: str,
    metadata: Mapping[str, Any] | None,
) -> dict[str, Any]:
    rule = _require_rule(relation_type)
    raw_metadata: Any = {} if metadata is None else metadata
    if not isinstance(raw_metadata, Mapping):
        raise RelationshipIntegrityError(
            "invalid_relationship_metadata",
            "relationship metadata must be an object",
            path="metadata",
            violation=VIOLATION_TYPE_MISMATCH,
        )
    secret_violations = find_secret_violations(raw_metadata, path="metadata")
    if secret_violations:
        raise RelationshipIntegrityError(
            "secret_relationship_metadata",
            "; ".join(secret_violations),
            path="metadata",
        )

    specs = {spec.name: spec for spec in rule.metadata_fields}
    unknown_fields = sorted(
        str(field_name)
        for field_name in raw_metadata
        if not isinstance(field_name, str) or field_name not in specs
    )
    if unknown_fields:
        raise RelationshipIntegrityError(
            "invalid_relationship_metadata",
            f"unsupported metadata fields for {relation_type}: {', '.join(unknown_fields)}",
            path=_metadata_path(unknown_fields[0]),
        )

    canonical: dict[str, Any] = {}
    for spec in rule.metadata_fields:
        path = f"metadata.{spec.name}"
        if spec.name not in raw_metadata:
            if spec.required:
                raise RelationshipIntegrityError(
                    "invalid_relationship_metadata",
                    f"metadata.{spec.name} is required",
                    path=path,
                    violation=VIOLATION_REQUIRED_FIELD_MISSING,
                )
            continue
        value = raw_metadata[spec.name]
        if spec.json_type == "boolean":
            if not isinstance(value, bool):
                raise RelationshipIntegrityError(
                    "invalid_relationship_metadata",
                    f"metadata.{spec.name} must be a boolean",
                    path=path,
                    violation=VIOLATION_TYPE_MISMATCH,
                )
            canonical[spec.name] = value
            continue
        if not isinstance(value, str):
            raise RelationshipIntegrityError(
                "invalid_relationship_metadata",
                f"metadata.{spec.name} must be a string",
                path=path,
                violation=VIOLATION_TYPE_MISMATCH,
            )
        normalized = value.strip()
        if not normalized:
            raise RelationshipIntegrityError(
                "invalid_relationship_metadata",
                f"metadata.{spec.name} must not be empty",
                path=path,
                violation=VIOLATION_VALUE_TOO_SHORT,
            )
        if spec.max_length is not None and len(normalized) > spec.max_length:
            raise RelationshipIntegrityError(
                "invalid_relationship_metadata",
                f"metadata.{spec.name} must contain at most {spec.max_length} characters",
                path=path,
                violation=VIOLATION_VALUE_TOO_LONG,
            )
        if spec.enum_values and normalized not in spec.enum_values:
            allowed = ", ".join(sorted(spec.enum_values))
            raise RelationshipIntegrityError(
                "invalid_relationship_metadata",
                f"metadata.{spec.name} must be one of: {allowed}",
                path=path,
                violation=VIOLATION_VALUE_NOT_ALLOWED,
            )
        if spec.reject_secrets:
            violations = find_secret_violations(normalized, path=f"metadata.{spec.name}")
            if violations:
                raise RelationshipIntegrityError(
                    "secret_relationship_metadata",
                    "; ".join(violations),
                    path=path,
                )
        canonical[spec.name] = normalized
    return canonical


def _metadata_path(field_name: str) -> str:
    """Return the canonical path of one rejected metadata field.

    A rejected field name is republished only when it uses the canonical
    segment grammar, so an unknown caller-supplied key can never be echoed back
    inside a published path.
    """
    if _METADATA_FIELD_PATTERN.fullmatch(field_name):
        return f"metadata.{field_name}"
    return "metadata"


def canonical_relationship_metadata_json(
    relation_type: str,
    metadata: Mapping[str, Any] | None,
) -> str:
    return json.dumps(
        validate_relationship_metadata(relation_type, metadata),
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    )


def relationship_metadata(
    relationship: Any,
    *,
    relation_type: str | None = None,
) -> dict[str, Any]:
    effective_type = relation_type or str(_record_value(relationship, "relation_type"))
    raw_metadata = relationship.get("metadata") if isinstance(relationship, Mapping) else None
    if raw_metadata is None:
        raw_json = _optional_record_value(relationship, "metadata_json")
        if raw_json is None:
            raw_metadata = {}
        else:
            try:
                raw_metadata = json.loads(str(raw_json))
            except (TypeError, json.JSONDecodeError) as exc:
                raise RelationshipIntegrityError(
                    "invalid_relationship_metadata",
                    "relationship metadata_json is not valid JSON",
                ) from exc
    if not isinstance(raw_metadata, Mapping):
        raise RelationshipIntegrityError(
            "invalid_relationship_metadata",
            "relationship metadata must be an object",
        )
    return validate_relationship_metadata(effective_type, raw_metadata)


def relationship_graph_diagnostics(
    relationships: Iterable[Any],
    endpoints: Mapping[str, EndpointDescriptor],
) -> list[RelationshipDiagnostic]:
    rows = list(relationships)
    diagnostics: list[RelationshipDiagnostic] = []
    primary_by_source: dict[tuple[str, str], list[str]] = {}
    attachment_edges: dict[str, set[str]] = {}
    uplink_edges: dict[str, set[str]] = {}

    for relationship in rows:
        relation_type = str(_record_value(relationship, "relation_type"))
        if relation_type not in GRAPH_TRACKED_TYPES:
            continue
        from_ref = str(_record_value(relationship, "from_ref"))
        to_ref = str(_record_value(relationship, "to_ref"))
        metadata = relationship_metadata(relationship, relation_type=relation_type)
        if metadata.get("primary") is True:
            primary_by_source.setdefault((from_ref, relation_type), []).append(to_ref)

        source = TypedReference.parse(from_ref)
        target = TypedReference.parse(to_ref)
        if (
            relation_type == "attached_to"
            and endpoints[source.object_id].kind == "device"
            and endpoints[target.object_id].kind == "device"
        ):
            attachment_edges.setdefault(from_ref, set()).add(to_ref)
        elif relation_type == "uplinks_to":
            uplink_edges.setdefault(from_ref, set()).add(to_ref)

    for (from_ref, relation_type), target_refs in sorted(primary_by_source.items()):
        if len(target_refs) > 1:
            diagnostics.append(
                RelationshipDiagnostic(
                    "multiple_primary_relationships",
                    from_ref,
                    f"{from_ref} has multiple primary {relation_type} targets: "
                    f"{', '.join(sorted(target_refs))}",
                )
            )

    for relation_type, edges in (
        ("attached_to", attachment_edges),
        ("uplinks_to", uplink_edges),
    ):
        cycle = _first_cycle(edges)
        if cycle is not None:
            diagnostics.append(
                RelationshipDiagnostic(
                    "relationship_cycle",
                    relation_type,
                    f"{relation_type} graph contains a cycle: {' -> '.join(cycle)}",
                )
            )
    return sorted(set(diagnostics))


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


def parse_reference(value: str, *, location: str) -> TypedReference:
    """Parse one typed reference without resolving it against the catalog."""
    try:
        return TypedReference.parse(value)
    except ValueError as exc:
        raise RelationshipIntegrityError(
            "invalid_typed_reference",
            f"{location} is not a valid typed reference: {value}",
            path=location if location in REFERENCE_PATHS else None,
        ) from exc


def resolve_reference(
    value: str,
    endpoints: Mapping[str, EndpointDescriptor],
    *,
    location: str,
) -> TypedReference:
    parsed = parse_reference(value, location=location)
    endpoint = endpoints.get(parsed.object_id)
    if endpoint is None:
        raise RelationshipIntegrityError(
            "dangling_typed_reference",
            f"{location} references a missing object: {value}",
        )
    if endpoint.kind != parsed.kind:
        raise RelationshipIntegrityError(
            "typed_reference_kind_mismatch",
            f"{location} asserts {parsed.kind} but {parsed.object_id} is {endpoint.kind}",
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
    endpoints = {
        object_id: EndpointDescriptor(kind=kind, data=MappingProxyType({}))
        for object_id, kind in object_kinds.items()
    }
    for index, reference in enumerate(iter_typed_reference_strings(data)):
        resolve_reference(
            reference,
            endpoints,
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
    try:
        endpoints = endpoint_descriptor_map(
            object_rows,
            validate_catalog_schema=False,
        )
    except RelationshipIntegrityError as exc:
        return [RelationshipDiagnostic(exc.code, "catalog_objects", str(exc))]
    diagnostics: list[RelationshipDiagnostic] = []
    triplets: list[tuple[str, str, str]] = []
    placement_parents: dict[str, set[str]] = {}
    valid_relationships: list[Any] = []

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
                endpoints=endpoints,
            )
            relationship_metadata(relationship, relation_type=relation_type)
        except RelationshipIntegrityError as exc:
            diagnostics.append(
                RelationshipDiagnostic(exc.code, location, str(exc))
            )
            continue
        triplets.append((from_ref, relation_type, to_ref))
        valid_relationships.append(relationship)
        if relation_type == CANONICAL_PLACEMENT_RELATION_TYPE:
            placement_parents.setdefault(to_ref, set()).add(from_ref)

    try:
        diagnostics.extend(relationship_graph_diagnostics(valid_relationships, endpoints))
    except (RelationshipIntegrityError, ValueError) as exc:
        code = (
            exc.code
            if isinstance(exc, RelationshipIntegrityError)
            else "invalid_typed_reference"
        )
        diagnostics.append(RelationshipDiagnostic(code, "relationships", str(exc)))

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
                    endpoints,
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
