"""JSON-safe projection of the canonical catalog object schema registry.

Machine contracts (MCP tools, documentation, clients) publish this projection
instead of restating field rules. It is generated from the same in-code registry
that validates every write, so a published contract cannot drift from
server-side validation, and the registry stays the single source of truth.

The projection describes catalog data only. It never contains stored records,
credential values, tokens, or internal paths: the secret section publishes the
globally forbidden *key names* and nothing else.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, get_args

from blockwart.domain.asset_state import (
    ASSET_HEALTH_VALUES,
    ASSET_KINDS,
    ASSET_LIFECYCLES,
    LegacyObjectStatus,
    is_asset_kind,
)
from blockwart.domain.decisions import decision_contract_projection
from blockwart.domain.monitoring import service_monitoring_contract_projection
from blockwart.domain.object_schema import (
    BUILTIN_SCHEMAS,
    FORBIDDEN_DATA_VALUE_KEYS,
    GENERIC_SCHEMA_VIOLATION,
    PUBLIC_SCHEMA_RULE_CONTRACTS,
    PUBLIC_SCHEMA_RULE_VIOLATIONS,
    SCHEMA_VIOLATION_CONTRACTS,
    VIOLATION_FIELD_NOT_ALLOWED,
    VIOLATION_INVALID_FORMAT,
    VIOLATION_REFERENCE_KIND_NOT_ALLOWED,
    VIOLATION_REQUIRED_FIELD_MISSING,
    VIOLATION_TYPE_MISMATCH,
    VIOLATION_VALUE_NOT_ALLOWED,
    VIOLATION_VALUE_NOT_CONSTANT,
    VIOLATION_VALUE_OUT_OF_RANGE,
    VIOLATION_VALUE_TOO_LONG,
    VIOLATION_VALUE_TOO_SHORT,
    FieldSpec,
    public_rule_name,
)
from blockwart.domain.projects import project_contract_projection
from blockwart.domain.runbooks import runbook_contract_projection
from blockwart.domain.security import FORBIDDEN_ACL_DATA_KEYS, FORBIDDEN_SECRET_KEYS
from blockwart.domain.service_components import service_component_contract_projection

# Version 7 additively publishes opt-in service monitoring: the closed
# configuration document, the provider-neutral observation vocabulary, and
# integer value bounds. Version 6 additively published bounded service-local
# components and their directed dependency graph.
SCHEMA_PROJECTION_VERSION = 7
SCHEMA_DATA_VERSION = 1
OBJECT_STATUS_VALUES: tuple[str, ...] = get_args(LegacyObjectStatus)
DEFAULT_OBJECT_STATUS = "active"
WRITABLE_KINDS: tuple[str, ...] = tuple(BUILTIN_SCHEMAS)

REQUIRED = "required"
OPTIONAL = "optional"
FORBIDDEN = "forbidden"

# JSON types accepted for each declarative domain field type.
_JSON_TYPES: Mapping[str, tuple[str, ...]] = {
    "array": ("array",),
    "boolean": ("boolean",),
    "datetime": ("string",),
    "integer": ("integer",),
    "ip": ("string",),
    "object": ("object",),
    "port": ("integer",),
    "reference": ("string",),
    "string": ("string",),
    "string_or_object": ("object", "string"),
    "text": ("string",),
    "url": ("string",),
}
# Violation types a field of each declarative type can raise for its own value,
# before required/enum/bounds/reference rules add their own.
_TYPE_VIOLATIONS: Mapping[str, frozenset[str]] = {
    "array": frozenset({VIOLATION_TYPE_MISMATCH}),
    "boolean": frozenset({VIOLATION_TYPE_MISMATCH}),
    "datetime": frozenset({VIOLATION_INVALID_FORMAT}),
    "enum": frozenset({VIOLATION_VALUE_NOT_ALLOWED}),
    "integer": frozenset({VIOLATION_TYPE_MISMATCH}),
    "ip": frozenset({VIOLATION_INVALID_FORMAT}),
    "object": frozenset({VIOLATION_TYPE_MISMATCH}),
    "port": frozenset({VIOLATION_TYPE_MISMATCH, VIOLATION_VALUE_OUT_OF_RANGE}),
    "reference": frozenset({VIOLATION_TYPE_MISMATCH, VIOLATION_INVALID_FORMAT}),
    "string": frozenset({VIOLATION_TYPE_MISMATCH}),
    "string_or_object": frozenset({VIOLATION_TYPE_MISMATCH}),
    "text": frozenset({VIOLATION_TYPE_MISMATCH}),
    "url": frozenset({VIOLATION_INVALID_FORMAT}),
}
_PYTHON_JSON_TYPES: tuple[tuple[type, str], ...] = (
    (bool, "boolean"),
    (int, "integer"),
    (float, "number"),
    (str, "string"),
)
_FORMATS: Mapping[str, str] = {
    "datetime": "date-time",
    "ip": "ip-address",
    "port": "tcp-udp-port",
    "reference": "kind:id",
    "text": "multiline-text",
    "url": "uri",
}
# Documentation-reserved placeholder values (RFC 5737 / RFC 2606) keep generated
# examples valid without pointing at any real host or address.
_EXAMPLE_IP = "192.0.2.1"
_EXAMPLE_URL = "https://service.example.invalid/"
_EXAMPLE_PORT = 8443
_EXAMPLE_TEXT = "example"
_EXAMPLE_DATETIME = "2026-08-11T12:00:00Z"
_HTTP_URL_PATTERN = r"^[Hh][Tt][Tt][Pp][Ss]?://"
_PINNED_ENUM_EXAMPLES: Mapping[str, str] = {
    "runbook_status": "draft",
    "decision_status": "proposed",
    "category": "implementation",
    "project_status": "planned",
}


def object_schema_projection() -> dict[str, Any]:
    """Return the complete machine-readable projection of the schema registry."""
    return {
        "version": SCHEMA_PROJECTION_VERSION,
        "source": "blockwart.domain.object_schema",
        "requirement_values": [REQUIRED, OPTIONAL, FORBIDDEN],
        "object_status": {
            "values": list(OBJECT_STATUS_VALUES),
            "default": DEFAULT_OBJECT_STATUS,
        },
        "asset_kinds": sorted(ASSET_KINDS),
        "knowledge_kinds": sorted(set(WRITABLE_KINDS) - set(ASSET_KINDS)),
        "secret_policy": secret_policy_projection(),
        "violation_policy": violation_policy_projection(),
        "kinds": [kind_schema_projection(kind) for kind in WRITABLE_KINDS],
    }


def violation_policy_projection() -> dict[str, Any]:
    """Publish the machine-readable violation contract of rejected writes.

    Every rejected object write reports one of these violation types for one
    canonical public path. The published description is the only failure text a
    boundary returns: rejected values, inputs, and exception text stay internal.
    """
    return {
        "detail_fields": ["code", "location", "message", "path", "rule"],
        "generic_violation": GENERIC_SCHEMA_VIOLATION,
        "unknown_violations_fall_back_to_generic": True,
        "violations": [
            {"code": code, "description": SCHEMA_VIOLATION_CONTRACTS[code]}
            for code in sorted(SCHEMA_VIOLATION_CONTRACTS)
        ],
        "description": (
            "A rejected write names the canonical public data path, one violation "
            "code, and the published rule when a schema postcondition rejected it. "
            "Rejected values are never returned."
        ),
    }


def secret_policy_projection() -> dict[str, Any]:
    """Publish the global fail-closed secret rules without any value."""
    return {
        "mode": "global_enforced",
        "enforced_before_kind_schema": True,
        "can_be_disabled_by_a_kind_schema": False,
        "forbidden_key_names": sorted(FORBIDDEN_SECRET_KEYS),
        "forbidden_value_key_names": sorted(FORBIDDEN_DATA_VALUE_KEYS),
        "forbidden_access_control_key_names": sorted(FORBIDDEN_ACL_DATA_KEYS),
        "applies_to": "every key below data, at any nesting depth, for every kind",
        "raw_secret_values_rejected": True,
        "description": (
            "Writes are rejected when any nested key uses a secret-like or raw "
            "credential-value name, when a string looks like a raw secret, or when "
            "a key describes access control. Credential-reference metadata such as "
            "a provider, a protected storage path, or a credential-reference id "
            "stays allowed. Blockwart never stores or returns credential values."
        ),
    }


def kind_schema_projection(kind: str) -> dict[str, Any]:
    """Return the published contract for exactly one writable object kind."""
    schema = BUILTIN_SCHEMAS[kind]
    asset = is_asset_kind(kind)
    projection = {
        "kind": kind,
        "kind_class": "asset" if asset else "knowledge",
        "status": {
            "values": list(OBJECT_STATUS_VALUES),
            "default": DEFAULT_OBJECT_STATUS,
        },
        "lifecycle": _state_projection(asset, ASSET_LIFECYCLES),
        "health": _state_projection(asset, ASSET_HEALTH_VALUES),
        "data": {
            "unknown_properties": schema.extra,
            "secret_policy": schema.secret_policy,
            "fields": [field_projection(field) for field in schema.fields],
            "rules": [
                {
                    "rule": public_rule_name(rule),
                    "description": PUBLIC_SCHEMA_RULE_CONTRACTS[public_rule_name(rule)],
                    "violation": PUBLIC_SCHEMA_RULE_VIOLATIONS[public_rule_name(rule)],
                }
                for rule in schema.rules
            ],
        },
        "minimal_example": minimal_object_example(kind),
    }
    if kind == "decision":
        projection["decision"] = decision_contract_projection()
    if kind == "project":
        projection["project"] = project_contract_projection()
    if kind == "runbook":
        projection["runbook"] = runbook_contract_projection()
    if kind == "service":
        projection["service_components"] = service_component_contract_projection()
        projection["service_monitoring"] = service_monitoring_contract_projection()
    return projection


def field_projection(field: FieldSpec) -> dict[str, Any]:
    """Project one immutable FieldSpec into its published contract."""
    projected: dict[str, Any] = {
        "path": field.path,
        "type": field.field_type,
        "json_types": list(_json_types(field)),
        "requirement": _requirement(field),
        "normalization": ["strip_whitespace"] if field.strip_whitespace else [],
    }
    if field.field_type in _FORMATS:
        projected["format"] = _FORMATS[field.field_type]
    if field.field_type == "url":
        projected["pattern"] = _HTTP_URL_PATTERN
    if field.required_in_item:
        projected["required_scope"] = "containing_array_item"
    if field.required_in_item_rule is not None:
        projected["required_rule"] = field.required_in_item_rule
    if field.enum_values:
        projected["enum"] = sorted(field.enum_values, key=_enum_sort_key)
    if field.reference_kinds:
        projected["reference_kinds"] = sorted(field.reference_kinds)
    if field.has_literal:
        projected["const"] = field.literal
    if field.min_length is not None:
        projected["min_length"] = field.min_length
    if field.max_length is not None:
        projected["max_length"] = field.max_length
    if field.min_items is not None:
        projected["min_items"] = field.min_items
    if field.max_items is not None:
        projected["max_items"] = field.max_items
    if field.minimum is not None:
        projected["minimum"] = field.minimum
    if field.maximum is not None:
        projected["maximum"] = field.maximum
    if field.allowed_keys:
        projected["allowed_keys"] = sorted(field.allowed_keys)
        projected["additional_properties"] = False
    if field.forbid_url_credentials:
        projected["embedded_credentials_allowed"] = False
        projected["secret_query_parameters_allowed"] = False
    if field.forbidden_message is not None:
        projected["reason"] = field.forbidden_message
    elif field.message is not None:
        projected["constraint"] = field.message
    projected["violations"] = sorted(field_violations(field))
    return projected


def field_violations(field: FieldSpec) -> set[str]:
    """Return every violation type this field can raise, from its own rules."""
    if field.forbidden_message is not None:
        return {VIOLATION_FIELD_NOT_ALLOWED}
    violations: set[str] = set(_TYPE_VIOLATIONS[field.field_type])
    if field.required or field.required_in_item:
        violations.add(VIOLATION_REQUIRED_FIELD_MISSING)
    if field.enum_values:
        violations.add(VIOLATION_VALUE_NOT_ALLOWED)
    if field.reference_kinds:
        violations.add(VIOLATION_REFERENCE_KIND_NOT_ALLOWED)
    if field.has_literal:
        violations.add(VIOLATION_VALUE_NOT_CONSTANT)
    if field.min_length is not None:
        violations.add(VIOLATION_VALUE_TOO_SHORT)
    if field.max_length is not None:
        violations.add(VIOLATION_VALUE_TOO_LONG)
    if field.min_items is not None or field.max_items is not None:
        violations.add(VIOLATION_VALUE_OUT_OF_RANGE)
    if field.minimum is not None or field.maximum is not None:
        violations.add(VIOLATION_VALUE_OUT_OF_RANGE)
    if field.allowed_keys:
        violations.add(VIOLATION_FIELD_NOT_ALLOWED)
    return violations


def minimal_object_data(kind: str) -> dict[str, Any]:
    """Build the smallest `data` document the domain accepts for one kind."""
    data: dict[str, Any] = {"schema_version": SCHEMA_DATA_VERSION}
    for field in BUILTIN_SCHEMAS[kind].fields:
        if field.required:
            _assign_example_path(data, field.path.split("."), field)
    return data


def minimal_object_example(kind: str) -> dict[str, Any]:
    """Build one complete minimal write body for a writable object kind."""
    return {
        "id": f"example-{kind.replace('_', '-')}",
        "kind": kind,
        "label": f"Example {kind.replace('_', ' ')}",
        "status": DEFAULT_OBJECT_STATUS,
        "data": minimal_object_data(kind),
    }


def _state_projection(asset: bool, values: tuple[str, ...]) -> dict[str, Any]:
    return {
        "supported": asset,
        "values": list(values) if asset else [],
        "requirement": OPTIONAL if asset else FORBIDDEN,
        "nullable": True,
        "default": None,
        "reason": (
            None
            if asset
            else "lifecycle and health are only valid for asset kinds"
        ),
    }


def _requirement(field: FieldSpec) -> str:
    if field.forbidden_message is not None:
        return FORBIDDEN
    return REQUIRED if field.required or field.required_in_item else OPTIONAL


def _json_types(field: FieldSpec) -> tuple[str, ...]:
    if field.field_type != "enum":
        return _JSON_TYPES[field.field_type]
    types = {_python_json_type(value) for value in field.enum_values}
    return tuple(sorted(types))


def _python_json_type(value: Any) -> str:
    for python_type, json_type in _PYTHON_JSON_TYPES:
        if isinstance(value, python_type):
            return json_type
    return "string"


def _enum_sort_key(value: Any) -> tuple[str, str]:
    return (_python_json_type(value), str(value))


def _assign_example_path(
    parent: dict[str, Any],
    parts: list[str],
    field: FieldSpec,
) -> None:
    key = parts[0].removesuffix("[]")
    is_array = parts[0].endswith("[]")
    if len(parts) == 1:
        parent.setdefault(key, _example_value(field, is_array=is_array))
        return
    child = parent.setdefault(key, [{}] if is_array else {})
    if is_array:
        if not child:
            child.append({})
        _assign_example_path(child[0], parts[1:], field)
        return
    _assign_example_path(child, parts[1:], field)


def _example_value(field: FieldSpec, *, is_array: bool) -> Any:
    value = _scalar_example_value(field)
    return [value] if is_array else value


def _scalar_example_value(field: FieldSpec) -> Any:
    if field.has_literal:
        return field.literal
    field_type = field.field_type
    if field_type == "enum":
        # A minimal example must itself satisfy the schema rules, so the
        # discriminators pin the values that require no further fields.
        pinned = _PINNED_ENUM_EXAMPLES.get(field.path)
        if pinned is not None:
            return pinned
        return sorted(field.enum_values, key=_enum_sort_key)[0]
    if field_type == "reference":
        return f"{sorted(field.reference_kinds)[0]}:example"
    if field_type == "object":
        return {}
    if field_type == "array":
        return []
    if field_type == "boolean":
        return False
    if field_type == "integer":
        return 1
    if field_type == "port":
        return _EXAMPLE_PORT
    if field_type == "ip":
        return _EXAMPLE_IP
    if field_type == "url":
        return _EXAMPLE_URL
    if field_type == "datetime":
        return _EXAMPLE_DATETIME
    return _bounded_text(field)


def _bounded_text(field: FieldSpec) -> str:
    text = _EXAMPLE_TEXT
    if field.min_length is not None and len(text) < field.min_length:
        text = text.ljust(field.min_length, "x")
    if field.max_length is not None:
        text = text[: field.max_length]
    return text
