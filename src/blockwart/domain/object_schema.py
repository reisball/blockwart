from __future__ import annotations

from collections.abc import Callable, Mapping
from copy import deepcopy
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from ipaddress import ip_address
from types import MappingProxyType
from typing import Any, Literal
from urllib.parse import parse_qsl, urlsplit

from blockwart.domain.interfaces import CANONICAL_EXPOSURES, CANONICAL_TRANSPORTS
from blockwart.domain.references import TypedReference
from blockwart.domain.security import FORBIDDEN_SECRET_KEYS
from blockwart.domain.service_components import (
    COMPONENT_DEPENDENCY_KEYS,
    COMPONENT_DOCUMENT_KEYS,
    COMPONENT_ITEM_KEYS,
    MAX_SERVICE_COMPONENT_DEPENDENCIES,
    MAX_SERVICE_COMPONENTS,
    SERVICE_COMPONENT_ROLES,
    normalize_service_components,
    service_component_violations,
)

FieldType = Literal[
    "array",
    "boolean",
    "datetime",
    "enum",
    "integer",
    "ip",
    "object",
    "port",
    "reference",
    "string",
    "string_or_object",
    "text",
    "url",
]
ExtraPolicy = Literal["allow"]
SecretPolicy = Literal["global_enforced"]
SchemaRule = Callable[[Mapping[str, Any]], None]

SECRET_POLICY: SecretPolicy = "global_enforced"
_UNSET = object()
# Published as part of the machine-readable schema contract: these key names may
# never appear anywhere below `data`, at any depth, for any object kind.
FORBIDDEN_DATA_VALUE_KEYS = frozenset(
    FORBIDDEN_SECRET_KEYS
    | {
        "credential",
        "credentials",
        "plaintext",
        "raw",
        "raw_value",
        "secret_value",
        "value",
    }
)

# Stable machine-readable violation types. Every ObjectSchemaError names exactly
# one of them, and the schema projection publishes this catalog next to the field
# rules, so a client contract cannot drift from what validation actually raises.
# The public description is the only text a boundary is allowed to return: it
# describes the broken rule, never the rejected value.
VIOLATION_REQUIRED_FIELD_MISSING = "required_field_missing"
VIOLATION_FIELD_NOT_ALLOWED = "field_not_allowed"
VIOLATION_TYPE_MISMATCH = "type_mismatch"
VIOLATION_VALUE_NOT_ALLOWED = "value_not_allowed"
VIOLATION_VALUE_NOT_CONSTANT = "value_not_constant"
VIOLATION_VALUE_TOO_SHORT = "value_too_short"
VIOLATION_VALUE_TOO_LONG = "value_too_long"
VIOLATION_VALUE_OUT_OF_RANGE = "value_out_of_range"
VIOLATION_INVALID_FORMAT = "invalid_format"
VIOLATION_REFERENCE_KIND_NOT_ALLOWED = "reference_kind_not_allowed"
VIOLATION_FORBIDDEN_KEY = "forbidden_key"
VIOLATION_RULE_VIOLATION = "rule_violation"
GENERIC_SCHEMA_VIOLATION = "invalid_value"

SCHEMA_VIOLATION_CONTRACTS: Mapping[str, str] = MappingProxyType(
    {
        VIOLATION_REQUIRED_FIELD_MISSING: "A required field is missing at this path.",
        VIOLATION_FIELD_NOT_ALLOWED: (
            "This path is not part of the published contract that applies here."
        ),
        VIOLATION_TYPE_MISMATCH: (
            "The value at this path does not use the JSON type this field requires."
        ),
        VIOLATION_VALUE_NOT_ALLOWED: (
            "The value at this path is not one of the values this field allows."
        ),
        VIOLATION_VALUE_NOT_CONSTANT: (
            "The value at this path must equal the single constant this field pins."
        ),
        VIOLATION_VALUE_TOO_SHORT: (
            "The value at this path is shorter than this field allows."
        ),
        VIOLATION_VALUE_TOO_LONG: (
            "The value at this path is longer than this field allows."
        ),
        VIOLATION_VALUE_OUT_OF_RANGE: (
            "The value at this path is outside the range this field allows."
        ),
        VIOLATION_INVALID_FORMAT: (
            "The value at this path does not use the format this field requires."
        ),
        VIOLATION_REFERENCE_KIND_NOT_ALLOWED: (
            "The reference at this path names an object kind this field does not accept."
        ),
        VIOLATION_FORBIDDEN_KEY: (
            "A key or value at this path is globally forbidden as secret-shaped."
        ),
        VIOLATION_RULE_VIOLATION: (
            "A published schema rule for this object kind rejects this combination "
            "of fields."
        ),
        GENERIC_SCHEMA_VIOLATION: (
            "The value at this path is rejected by the canonical object schema."
        ),
    }
)

CREDENTIAL_PROVIDERS = frozenset(
    {"vaultwarden", "secrets_json", "env_file", "local_file", "external"}
)
CREDENTIAL_ACCESS_TYPES = frozenset(
    {"ssh", "web", "api", "database", "smb", "sudo", "token", "other"}
)
RUNBOOK_RISK_LEVELS = frozenset(
    {"read-only", "safe-change", "disruptive", "destructive"}
)
RUNBOOK_STATUS_VALUES = (
    "draft",
    "approved",
    "active",
    "deprecated",
    "superseded",
    "retired",
)
RUNBOOK_STATUSES = frozenset(RUNBOOK_STATUS_VALUES)
RUNBOOK_CHANGE_FALLBACK_VALUES = ("rollback", "recovery", "no_rollback")
RUNBOOK_CHANGE_FALLBACKS = frozenset(RUNBOOK_CHANGE_FALLBACK_VALUES)
DEVICE_CATEGORIES = frozenset(
    {"antenna", "sensor", "adapter", "controller", "ups", "other"}
)
NETWORK_CATEGORIES = frozenset(
    {
        "segment",
        "switch",
        "router",
        "access_point",
        "mesh",
        "firewall",
        "gateway",
        "other_device",
    }
)
DECISION_STATUS_VALUES = (
    "proposed",
    "accepted",
    "superseded",
    "deprecated",
    "rejected",
)
DECISION_STATUSES = frozenset(DECISION_STATUS_VALUES)
# One shared closed vocabulary for every safe structured source reference. The
# Decision `docs` contract accepted in #144 and the Project `sources` contract
# use the same values so a client cannot learn two source taxonomies.
SOURCE_TYPE_VALUES = ("original", "documentation", "reference")
SOURCE_TYPES = frozenset(SOURCE_TYPE_VALUES)
PROJECT_CATEGORY_VALUES = (
    "implementation",
    "migration",
    "research",
    "experiment",
    "incident_review",
    "other",
)
PROJECT_CATEGORIES = frozenset(PROJECT_CATEGORY_VALUES)
PROJECT_STATUS_VALUES = (
    "planned",
    "active",
    "paused",
    "completed",
    "cancelled",
    "archived",
)
PROJECT_STATUSES = frozenset(PROJECT_STATUS_VALUES)
PROJECT_EVIDENCE_GRADE_VALUES = ("source_backed", "observed", "inferred")
PROJECT_EVIDENCE_GRADES = frozenset(PROJECT_EVIDENCE_GRADE_VALUES)
# `principal` names a Blockwart principal id as provenance only. Resolving it is
# deliberately not attempted, so it can neither confer nor prove access.
PROJECT_MANAGED_BY_KIND_VALUES = ("principal", "person", "team")
PROJECT_MANAGED_BY_KINDS = frozenset(PROJECT_MANAGED_BY_KIND_VALUES)
PROJECT_TIMELINE_REFERENCE_TYPE_VALUES = ("object_comments", "source")
PROJECT_TIMELINE_REFERENCE_TYPES = frozenset(PROJECT_TIMELINE_REFERENCE_TYPE_VALUES)
INSTALLED_SOFTWARE_KINDS = frozenset({"host", "system"})
INSTALLED_SOFTWARE_ENTRY_FIELDS = frozenset({"name", "version", "url"})

REFERENCE_TARGETS: Mapping[str, frozenset[str]] = MappingProxyType(
    {
        "credential_references": frozenset({"credential_reference"}),
        "related_services": frozenset({"service"}),
        "runbooks": frozenset({"runbook"}),
        "related_projects": frozenset({"project"}),
        "related_decisions": frozenset({"decision"}),
        "related_systems": frozenset({"system"}),
        "related_runbooks": frozenset({"runbook"}),
    }
)


class ObjectSchemaError(ValueError):
    """A catalog data field violates the fixed schema for its object kind.

    `path` is the resolved canonical data path, `violation` one published
    machine-readable violation type, and `rule` the published schema rule that
    rejected the write when a postcondition raised. Unknown violation types and
    unknown rule names fall back to the generic public view instead of
    publishing an unreviewed contract.
    """

    def __init__(
        self,
        path: str,
        message: str,
        *,
        violation: str = GENERIC_SCHEMA_VIOLATION,
        rule: str | None = None,
    ) -> None:
        self.path = path
        self.message = message
        self.violation = (
            violation
            if violation in SCHEMA_VIOLATION_CONTRACTS
            else GENERIC_SCHEMA_VIOLATION
        )
        self.rule = rule if rule in PUBLIC_SCHEMA_RULE_CONTRACTS else None
        super().__init__(f"{path} {message}")


@dataclass(frozen=True)
class FieldSpec:
    path: str
    field_type: FieldType
    required: bool = False
    required_in_item: bool = False
    required_in_item_rule: str | None = None
    enum_values: frozenset[Any] = frozenset()
    reference_kinds: frozenset[str] = frozenset()
    literal: Any = _UNSET
    strip_whitespace: bool = False
    min_length: int | None = None
    max_length: int | None = None
    min_items: int | None = None
    max_items: int | None = None
    allowed_keys: frozenset[str] = frozenset()
    forbid_url_credentials: bool = False
    message: str | None = None
    forbidden_message: str | None = None

    @property
    def has_literal(self) -> bool:
        """Whether this field pins one exact value, without exposing the sentinel."""
        return self.literal is not _UNSET

    def __post_init__(self) -> None:
        if not self.path or any(not part for part in self.path.split(".")):
            raise ValueError("schema field paths must use non-empty dot-separated keys")
        if self.required_in_item_rule is not None and not self.required_in_item:
            raise ValueError(
                f"only item-required fields may declare a required-item rule: {self.path}"
            )
        path_keys = {part.removesuffix("[]").lower() for part in self.path.split(".")}
        forbidden_keys = path_keys & FORBIDDEN_DATA_VALUE_KEYS
        if forbidden_keys:
            joined = ", ".join(sorted(forbidden_keys))
            raise ValueError(f"schema fields may not declare secret value keys: {joined}")
        if self.field_type == "enum" and not self.enum_values:
            raise ValueError(f"enum field {self.path} requires enum_values")
        if self.field_type == "reference" and not self.reference_kinds:
            raise ValueError(f"reference field {self.path} requires reference_kinds")
        if self.strip_whitespace and self.field_type not in {"string", "text"}:
            raise ValueError(f"only string fields may strip whitespace: {self.path}")
        if (self.min_length is not None or self.max_length is not None) and self.field_type not in {
            "string",
            "text",
            "url",
        }:
            raise ValueError(f"only string fields may declare length limits: {self.path}")
        if self.min_length is not None and self.min_length < 0:
            raise ValueError(f"minimum length must be non-negative: {self.path}")
        if self.max_length is not None and self.max_length < 0:
            raise ValueError(f"maximum length must be non-negative: {self.path}")
        if (
            self.min_length is not None
            and self.max_length is not None
            and self.min_length > self.max_length
        ):
            raise ValueError(f"minimum length exceeds maximum length: {self.path}")
        if (
            self.min_items is not None or self.max_items is not None
        ) and self.field_type != "array":
            raise ValueError(f"only array fields may declare item bounds: {self.path}")
        if self.min_items is not None and self.min_items < 0:
            raise ValueError(f"minimum items must be non-negative: {self.path}")
        if self.max_items is not None and self.max_items < 0:
            raise ValueError(f"maximum items must be non-negative: {self.path}")
        if (
            self.min_items is not None
            and self.max_items is not None
            and self.min_items > self.max_items
        ):
            raise ValueError(f"minimum items exceeds maximum items: {self.path}")
        if self.allowed_keys and self.field_type != "object":
            raise ValueError(f"only object fields may declare allowed keys: {self.path}")
        if self.forbid_url_credentials and self.field_type != "url":
            raise ValueError(f"only URL fields may forbid credentials: {self.path}")
        if self.forbidden_message is not None and (
            self.required
            or self.required_in_item
            or self.enum_values
            or self.reference_kinds
            or self.has_literal
        ):
            raise ValueError(f"forbidden field {self.path} cannot define validation options")
        if self.required_in_item and "[]" not in self.path:
            raise ValueError(
                f"item-required field must be nested below an array: {self.path}"
            )


@dataclass(frozen=True)
class TypeSchema:
    kind: str
    fields: tuple[FieldSpec, ...]
    rules: tuple[SchemaRule, ...] = ()
    extra: ExtraPolicy = "allow"
    secret_policy: SecretPolicy = SECRET_POLICY

    def __post_init__(self) -> None:
        if self.extra != "allow":
            raise ValueError("fixed catalog schemas must preserve unknown fields")
        if self.secret_policy != SECRET_POLICY:
            raise ValueError("catalog schema secret enforcement cannot be disabled")
        paths = [field.path for field in self.fields]
        if len(paths) != len(set(paths)):
            raise ValueError(f"schema {self.kind} contains duplicate field paths")


def normalize_object_data(kind: str, data: Mapping[str, Any]) -> dict[str, Any]:
    normalized = deepcopy(dict(data))
    for field in BUILTIN_SCHEMAS[kind].fields:
        if field.strip_whitespace:
            _normalize_string_field(normalized, field.path.split("."))
        if field.field_type == "datetime":
            _normalize_datetime_field(normalized, field.path.split("."))
    if kind == "service":
        normalized = normalize_service_components(normalized)
    return normalized


# The fields a legacy knowledge row is still held to. They are the obsolete
# markers and the globally forbidden shapes, never the canonical contract, so a
# historical free-form document stays readable without being reinterpreted.
LEGACY_KNOWLEDGE_READ_FIELD_PATHS = frozenset(
    {"schema_version", "lifecycle", "health", "dependencies", "installed_software"}
)


def validate_object_data(
    kind: str,
    data: Mapping[str, Any],
    *,
    allow_legacy_network_without_category: bool = False,
    allow_legacy_decision_without_status: bool = False,
    allow_legacy_decision_data: bool = False,
    allow_legacy_project_without_category: bool = False,
    allow_legacy_project_data: bool = False,
    allow_legacy_runbook_without_status: bool = False,
    allow_legacy_runbook_data: bool = False,
) -> None:
    schema = BUILTIN_SCHEMAS[kind]
    fields = schema.fields
    if allow_legacy_network_without_category and kind == "network":
        fields = tuple(
            replace(field, required=False)
            if field.path == "network.category"
            else field
            for field in fields
        )
    if _reads_as_legacy_knowledge_row(
        kind,
        data,
        allow_legacy_decision_without_status=allow_legacy_decision_without_status,
        allow_legacy_decision_data=allow_legacy_decision_data,
        allow_legacy_project_without_category=allow_legacy_project_without_category,
        allow_legacy_project_data=allow_legacy_project_data,
        allow_legacy_runbook_without_status=allow_legacy_runbook_without_status,
        allow_legacy_runbook_data=allow_legacy_runbook_data,
    ):
        validate_fields(
            data,
            tuple(
                field
                for field in fields
                if field.path in LEGACY_KNOWLEDGE_READ_FIELD_PATHS
            ),
        )
        return
    if kind == "runbook" and "runbook_status" not in data:
        # Keep precise public errors for malformed references and forbidden
        # asset fields without changing validation order for any other kind.
        validate_fields(
            data,
            tuple(
                field
                for field in fields
                if field.field_type == "reference"
                or field.forbidden_message is not None
            ),
        )
        # Preserve the historical loose-shape diagnostic before the canonical
        # pass below requires runbook_status on every rewrite.
        validate_fields(data, LEGACY_RUNBOOK_SUBMISSION_FIELDS)
    validate_fields(data, fields)
    for rule in schema.rules:
        rule(data)


def _reads_as_legacy_knowledge_row(
    kind: str,
    data: Mapping[str, Any],
    *,
    allow_legacy_decision_without_status: bool,
    allow_legacy_decision_data: bool,
    allow_legacy_project_without_category: bool,
    allow_legacy_project_data: bool,
    allow_legacy_runbook_without_status: bool,
    allow_legacy_runbook_data: bool,
) -> bool:
    """Whether this read may fall back to the tolerant legacy field set.

    A Project without a canonical `category` is historical free-form content.
    Blockwart never guesses which category it was, so the canonical contract is
    not applied to it on read; any rewrite must still satisfy that contract.
    """
    if kind == "decision":
        return allow_legacy_decision_data or (
            allow_legacy_decision_without_status and "decision_status" not in data
        )
    if kind == "project":
        return allow_legacy_project_data or (
            allow_legacy_project_without_category and "category" not in data
        )
    if kind == "runbook":
        return allow_legacy_runbook_data or (
            allow_legacy_runbook_without_status and "runbook_status" not in data
        )
    return False


def _normalize_string_field(value: Any, path: list[str]) -> None:
    if not path or not isinstance(value, dict):
        return
    raw_part = path[0]
    is_array = raw_part.endswith("[]")
    key = raw_part.removesuffix("[]")
    if key not in value:
        return
    child = value[key]
    if len(path) == 1:
        if is_array and isinstance(child, list):
            value[key] = [item.strip() if isinstance(item, str) else item for item in child]
        elif not is_array and isinstance(child, str):
            value[key] = child.strip()
        return
    if is_array and isinstance(child, list):
        for item in child:
            _normalize_string_field(item, path[1:])
    else:
        _normalize_string_field(child, path[1:])


def _normalize_datetime_field(value: Any, path: list[str]) -> None:
    if not path or not isinstance(value, dict):
        return
    raw_part = path[0]
    is_array = raw_part.endswith("[]")
    key = raw_part.removesuffix("[]")
    if key not in value:
        return
    child = value[key]
    if len(path) > 1:
        if is_array and isinstance(child, list):
            for item in child:
                _normalize_datetime_field(item, path[1:])
        else:
            _normalize_datetime_field(child, path[1:])
        return
    if is_array and isinstance(child, list):
        value[key] = [
            parsed.astimezone(UTC).isoformat().replace("+00:00", "Z")
            if (parsed := _parse_rfc3339(item)) is not None
            else item
            for item in child
        ]
    else:
        parsed = _parse_rfc3339(child)
        if parsed is not None:
            value[key] = parsed.astimezone(UTC).isoformat().replace("+00:00", "Z")


def validate_fields(
    data: Mapping[str, Any],
    fields: tuple[FieldSpec, ...],
) -> None:
    for field in fields:
        values = _resolve_values(data, field.path)
        if field.required and not values:
            raise ObjectSchemaError(
                f"data.{field.path}",
                "is required",
                violation=VIOLATION_REQUIRED_FIELD_MISSING,
            )
        if field.required_in_item:
            missing_path = _first_missing_item_field(data, field.path)
            if missing_path is not None:
                raise ObjectSchemaError(
                    missing_path,
                    "is required",
                    violation=VIOLATION_REQUIRED_FIELD_MISSING,
                    rule=field.required_in_item_rule,
                )
        for path, value in values:
            if field.forbidden_message is not None:
                raise ObjectSchemaError(
                    path,
                    field.forbidden_message,
                    violation=VIOLATION_FIELD_NOT_ALLOWED,
                )
            _validate_value(field, path, value)


def _resolve_values(
    data: Mapping[str, Any],
    declared_path: str,
) -> list[tuple[str, Any]]:
    resolved: list[tuple[str, Any]] = [("data", data)]
    for raw_part in declared_path.split("."):
        is_array = raw_part.endswith("[]")
        key = raw_part.removesuffix("[]")
        next_values: list[tuple[str, Any]] = []
        for parent_path, parent in resolved:
            if not isinstance(parent, Mapping):
                raise ObjectSchemaError(
                    parent_path,
                    "must be an object",
                    violation=VIOLATION_TYPE_MISMATCH,
                )
            if key not in parent:
                continue
            value = parent[key]
            value_path = f"{parent_path}.{key}"
            if not is_array:
                next_values.append((value_path, value))
                continue
            if not isinstance(value, list):
                raise ObjectSchemaError(
                    value_path,
                    "must be a list",
                    violation=VIOLATION_TYPE_MISMATCH,
                )
            next_values.extend(
                (f"{value_path}[{index}]", item)
                for index, item in enumerate(value)
            )
        resolved = next_values
    return resolved


def _validate_value(field: FieldSpec, path: str, value: Any) -> None:
    field_type = field.field_type
    violation = VIOLATION_TYPE_MISMATCH
    if field_type in {"string", "text"}:
        valid = isinstance(value, str)
        default_message = "must be a string"
    elif field_type == "datetime":
        valid = _parse_rfc3339(value) is not None
        default_message = "must be an RFC 3339 timestamp with a timezone"
        violation = VIOLATION_INVALID_FORMAT
    elif field_type == "integer":
        valid = isinstance(value, int) and not isinstance(value, bool)
        default_message = "must be an integer"
    elif field_type == "boolean":
        valid = isinstance(value, bool)
        default_message = "must be a boolean"
    elif field_type == "object":
        valid = isinstance(value, Mapping)
        default_message = "must be an object"
    elif field_type == "array":
        valid = isinstance(value, list)
        default_message = "must be a list"
    elif field_type == "string_or_object":
        valid = isinstance(value, (str, Mapping))
        default_message = "must be a string or object"
    elif field_type == "enum":
        try:
            valid = value in field.enum_values
        except TypeError:
            valid = False
        allowed = ", ".join(sorted(str(item) for item in field.enum_values))
        default_message = f"must be one of: {allowed}"
        violation = VIOLATION_VALUE_NOT_ALLOWED
    elif field_type == "ip":
        valid = _is_ip(value)
        default_message = "must be a valid IP address"
        violation = VIOLATION_INVALID_FORMAT
    elif field_type == "url":
        valid = (
            is_safe_external_http_url(value)
            if field.forbid_url_credentials
            else is_absolute_http_url(value)
        )
        default_message = "must be a valid URL"
        violation = VIOLATION_INVALID_FORMAT
    elif field_type == "port":
        numeric = isinstance(value, int) and not isinstance(value, bool)
        valid = numeric and 1 <= value <= 65535
        default_message = "must be an integer from 1 to 65535"
        violation = VIOLATION_VALUE_OUT_OF_RANGE if numeric else VIOLATION_TYPE_MISMATCH
    elif field_type == "reference":
        _validate_reference(value, field.reference_kinds, path)
        valid = True
        default_message = ""
    else:  # pragma: no cover - Literal and construction tests make this unreachable
        raise AssertionError(f"unsupported schema field type: {field_type}")

    if not valid:
        raise ObjectSchemaError(path, field.message or default_message, violation=violation)
    if isinstance(value, str):
        if field.min_length is not None and len(value) < field.min_length:
            raise ObjectSchemaError(
                path,
                field.message or "must not be empty",
                violation=VIOLATION_VALUE_TOO_SHORT,
            )
        if field.max_length is not None and len(value) > field.max_length:
            raise ObjectSchemaError(
                path,
                field.message or f"must contain at most {field.max_length} characters",
                violation=VIOLATION_VALUE_TOO_LONG,
            )
    if isinstance(value, list):
        if field.min_items is not None and len(value) < field.min_items:
            raise ObjectSchemaError(
                path,
                f"must contain at least {field.min_items} items",
                violation=VIOLATION_VALUE_OUT_OF_RANGE,
            )
        if field.max_items is not None and len(value) > field.max_items:
            raise ObjectSchemaError(
                path,
                f"must contain at most {field.max_items} items",
                violation=VIOLATION_VALUE_OUT_OF_RANGE,
            )
    if isinstance(value, Mapping) and field.allowed_keys:
        unexpected = sorted(set(value) - field.allowed_keys)
        if unexpected:
            raise ObjectSchemaError(
                f"{path}.{unexpected[0]}",
                "is not allowed",
                violation=VIOLATION_FIELD_NOT_ALLOWED,
            )
    if field.has_literal and value != field.literal:
        raise ObjectSchemaError(
            path,
            field.message or f"must be {field.literal!r}",
            violation=VIOLATION_VALUE_NOT_CONSTANT,
        )


def _validate_reference(
    value: Any,
    allowed_kinds: frozenset[str],
    path: str,
) -> None:
    if not isinstance(value, str):
        raise ObjectSchemaError(path, "must be a string", violation=VIOLATION_TYPE_MISMATCH)
    try:
        parsed = TypedReference.parse(value)
    except ValueError as exc:
        raise ObjectSchemaError(
            path,
            "must use a supported kind:id reference",
            violation=VIOLATION_INVALID_FORMAT,
        ) from exc
    if parsed.kind not in allowed_kinds:
        allowed = ", ".join(sorted(allowed_kinds))
        raise ObjectSchemaError(
            path,
            f"must reference one of: {allowed}",
            violation=VIOLATION_REFERENCE_KIND_NOT_ALLOWED,
        )


def _is_ip(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    try:
        ip_address(value)
    except ValueError:
        return False
    return True


def _parse_rfc3339(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    normalized = f"{value[:-1]}+00:00" if value.endswith(("Z", "z")) else value
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else None


def is_absolute_http_url(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    try:
        parsed = urlsplit(value)
        port = parsed.port
        port_is_valid = port is None or isinstance(port, int)
        return (
            parsed.scheme.casefold() in {"http", "https"}
            and bool(parsed.hostname)
            and port_is_valid
        )
    except ValueError:
        return False


def is_safe_external_http_url(value: Any) -> bool:
    if not is_absolute_http_url(value):
        return False
    try:
        parsed = urlsplit(value)
    except ValueError:
        return False
    if parsed.username is not None or parsed.password is not None:
        return False
    forbidden_query_keys = FORBIDDEN_DATA_VALUE_KEYS | FORBIDDEN_SECRET_KEYS
    return all(
        key.casefold() not in forbidden_query_keys
        for key, _ in parse_qsl(parsed.query, keep_blank_values=True)
    )


def _first_missing_item_field(
    data: Mapping[str, Any],
    declared_path: str,
) -> str | None:
    array_path, separator, item_path = declared_path.partition("[].")
    if not separator:
        return None
    parent: Any = data
    rendered_parent = "data"
    for part in array_path.split("."):
        if not isinstance(parent, Mapping) or part not in parent:
            return None
        parent = parent[part]
        rendered_parent = f"{rendered_parent}.{part}"
    if not isinstance(parent, list):
        return None
    item_parts = item_path.split(".")
    for index, item in enumerate(parent):
        current: Any = item
        rendered = f"{rendered_parent}[{index}]"
        for part in item_parts:
            if not isinstance(current, Mapping) or part not in current:
                return f"{rendered}.{part}"
            current = current[part]
            rendered = f"{rendered}.{part}"
    return None


def _field(
    path: str,
    field_type: FieldType,
    **kwargs: Any,
) -> FieldSpec:
    return FieldSpec(path, field_type, **kwargs)


def _reference_list(
    path: str,
    *kinds: str,
) -> tuple[FieldSpec, FieldSpec]:
    return (
        _field(path, "array"),
        _field(f"{path}[]", "reference", reference_kinds=frozenset(kinds)),
    )


def _text_list(
    path: str,
    *,
    max_items: int = 50,
    max_length: int = 2000,
) -> tuple[FieldSpec, FieldSpec]:
    """Declare one bounded array of trimmed, nonblank free-text entries."""
    return (
        _field(path, "array", max_items=max_items),
        _field(
            f"{path}[]",
            "text",
            strip_whitespace=True,
            min_length=1,
            max_length=max_length,
        ),
    )


def _entry_id(path: str) -> FieldSpec:
    """Declare the stable, document-local identifier of one closed list entry."""
    return _field(
        path,
        "string",
        required_in_item=True,
        strip_whitespace=True,
        min_length=1,
        max_length=64,
    )


def _source_entries(
    path: str,
    *,
    max_items: int,
    identified: bool = False,
    retrieval_metadata: bool = False,
) -> tuple[FieldSpec, ...]:
    """Declare one safe structured external-source array.

    This is the single definition of Blockwart's source-entry contract. The
    base shape is exactly the Decision `docs` contract accepted in #144:
    a closed entry with a required source type, a required nonblank title, a
    required credential-free absolute HTTP(S) URL, and an optional publication
    timestamp. Blockwart stores the reference and never fetches the original.

    `identified` adds the document-local `id` that evidence entries cite, and
    `retrieval_metadata` adds the explicit provenance a research record needs.
    Both are opt-in so the accepted #144 entry shape stays byte-identical.
    """
    keys = {"source_type", "title", "url", "published_at"}
    fields = [
        _field(path, "array", max_items=max_items),
        _field(
            f"{path}[].source_type",
            "enum",
            required_in_item=True,
            enum_values=SOURCE_TYPES,
        ),
        _field(
            f"{path}[].title",
            "text",
            required_in_item=True,
            strip_whitespace=True,
            min_length=1,
            max_length=200,
        ),
        _field(
            f"{path}[].url",
            "url",
            required_in_item=True,
            max_length=2048,
            forbid_url_credentials=True,
            message="must be an HTTP(S) URL without embedded credentials",
        ),
        _field(f"{path}[].published_at", "datetime"),
    ]
    if identified:
        keys.add("id")
        fields.append(_entry_id(f"{path}[].id"))
    if retrieval_metadata:
        keys.update({"author", "publisher", "retrieved_at"})
        fields.extend(
            (
                _field(
                    f"{path}[].author",
                    "text",
                    strip_whitespace=True,
                    min_length=1,
                    max_length=200,
                ),
                _field(
                    f"{path}[].publisher",
                    "text",
                    strip_whitespace=True,
                    min_length=1,
                    max_length=200,
                ),
                _field(f"{path}[].retrieved_at", "datetime"),
            )
        )
    return (
        fields[0],
        _field(f"{path}[]", "object", allowed_keys=frozenset(keys)),
        *fields[1:],
    )


COMMON_FIELDS = (
    _field("schema_version", "integer", literal=1, message="must be 1"),
    _field(
        "lifecycle",
        "string",
        forbidden_message="is obsolete; use top-level fields",
    ),
    _field(
        "health",
        "string",
        forbidden_message="is obsolete; use top-level fields",
    ),
    _field(
        "dependencies",
        "object",
        forbidden_message="is obsolete; use depends_on relationships",
    ),
)

INTERFACE_FIELDS = (
    _field("endpoints", "array"),
    _field("endpoints[]", "object"),
    _field("endpoints[].type", "string"),
    _field("endpoints[].url", "string"),
    _field("endpoints[].host", "string"),
    _field("endpoints[].port", "port"),
    _field(
        "endpoints[].transport",
        "enum",
        enum_values=CANONICAL_TRANSPORTS,
    ),
    _field(
        "endpoints[].exposure",
        "enum",
        enum_values=CANONICAL_EXPOSURES,
    ),
    _field("ports", "array"),
    _field("ports[]", "object"),
    _field("ports[].port", "port"),
    _field(
        "ports[].protocol",
        "enum",
        enum_values=CANONICAL_TRANSPORTS,
        message="must be tcp or udp",
    ),
    _field(
        "ports[].transport",
        "enum",
        enum_values=CANONICAL_TRANSPORTS,
        message="must be tcp or udp",
    ),
    _field("access_methods", "array"),
    _field("access_methods[]", "object"),
    _field("access_methods[].type", "string"),
    _field("access_methods[].endpoint", "string"),
    _field("access_methods[].endpoint_id", "string"),
    *_reference_list(
        "access_methods[].credential_references",
        "credential_reference",
    ),
)

NETWORK_FIELDS = (
    _field("network", "object"),
    _field("network.hostnames", "array"),
    _field("network.hostnames[]", "string"),
    _field("network.addresses", "array"),
    _field("network.addresses[]", "object"),
    _field("network.addresses[].ip", "ip"),
)

INSTALLED_SOFTWARE_FIELDS = (
    _field("installed_software", "array"),
    _field("installed_software[]", "object"),
    _field(
        "installed_software[].name",
        "string",
        required_in_item=True,
        required_in_item_rule="require_installed_software_fields",
        min_length=1,
    ),
    _field(
        "installed_software[].version",
        "string",
        required_in_item=True,
        required_in_item_rule="require_installed_software_fields",
        min_length=1,
    ),
    _field("installed_software[].url", "url"),
)

INSTALLED_SOFTWARE_FORBIDDEN_FIELDS = (
    _field(
        "installed_software",
        "array",
        forbidden_message="is supported only for host and system objects",
    ),
)

NETWORK_OBJECT_FIELDS = (
    _field(
        "network.category",
        "enum",
        required=True,
        enum_values=NETWORK_CATEGORIES,
    ),
    _field(
        "network.manufacturer",
        "string",
        strip_whitespace=True,
        min_length=1,
        max_length=128,
    ),
    _field(
        "network.model",
        "string",
        strip_whitespace=True,
        min_length=1,
        max_length=128,
    ),
    _field(
        "network.location",
        "string",
        max_length=255,
    ),
)

DEVICE_FIELDS = (
    _field("device", "object", required=True),
    _field(
        "device.category",
        "enum",
        required=True,
        enum_values=DEVICE_CATEGORIES,
    ),
    _field(
        "device.manufacturer",
        "string",
        strip_whitespace=True,
        min_length=1,
        max_length=128,
    ),
    _field(
        "device.model",
        "string",
        strip_whitespace=True,
        min_length=1,
        max_length=128,
    ),
)

REFERENCE_FIELDS = tuple(
    field
    for path, kinds in REFERENCE_TARGETS.items()
    for field in _reference_list(path, *sorted(kinds))
)

SERVICE_FIELDS = (
    _field(
        "system_id",
        "string",
        forbidden_message="is obsolete; use a hosts relationship",
    ),
    _field("owner", "string"),
    _field("auth", "object"),
    *_reference_list("auth.credential_references", "credential_reference"),
    _field("components", "object", allowed_keys=COMPONENT_DOCUMENT_KEYS),
    _field(
        "components.items",
        "array",
        max_items=MAX_SERVICE_COMPONENTS,
    ),
    _field(
        "components.items[]",
        "object",
        allowed_keys=COMPONENT_ITEM_KEYS,
    ),
    _entry_id("components.items[].id"),
    _field(
        "components.items[].name",
        "string",
        required_in_item=True,
        strip_whitespace=True,
        min_length=1,
        max_length=128,
    ),
    _field(
        "components.items[].role",
        "enum",
        required_in_item=True,
        enum_values=SERVICE_COMPONENT_ROLES,
    ),
    _field(
        "components.items[].description",
        "text",
        required_in_item=True,
        strip_whitespace=True,
        min_length=1,
        max_length=512,
    ),
    _field(
        "components.dependencies",
        "array",
        max_items=MAX_SERVICE_COMPONENT_DEPENDENCIES,
    ),
    _field(
        "components.dependencies[]",
        "object",
        allowed_keys=COMPONENT_DEPENDENCY_KEYS,
    ),
    _entry_id("components.dependencies[].component_id"),
    _entry_id("components.dependencies[].depends_on"),
    _field(
        "components.dependencies[].description",
        "text",
        strip_whitespace=True,
        min_length=1,
        max_length=512,
    ),
)

SERVICE_COMPONENTS_FORBIDDEN_FIELDS = (
    _field(
        "components",
        "object",
        forbidden_message="is supported only for service objects",
    ),
)

CREDENTIAL_REFERENCE_FIELDS = (
    _field(
        "provider",
        "enum",
        enum_values=CREDENTIAL_PROVIDERS,
        message="must be a supported credential reference provider",
    ),
    _field("reference", "object"),
    _field("reference.name", "string"),
    _field("reference.path", "string"),
    _field("reference.key", "string"),
    _field("reference.item_hint", "string"),
    _field("scope", "object"),
    _field(
        "scope.access_type",
        "enum",
        enum_values=CREDENTIAL_ACCESS_TYPES,
        message="must be a supported access type",
    ),
    *_reference_list("scope.systems", "system"),
    *_reference_list("scope.services", "service"),
    _field("used_by", "object"),
    *_reference_list("used_by.systems", "system"),
    *_reference_list("used_by.services", "service"),
    *_reference_list("used_by.runbooks", "runbook"),
    _field("handling_rules", "object"),
    _field(
        "handling_rules.telegram_allowed",
        "boolean",
        literal=False,
        message="must be false",
    ),
    _field(
        "handling_rules.markdown_secret_allowed",
        "boolean",
        literal=False,
        message="must be false",
    ),
    _field(
        "handling_rules.agents_may_read_value",
        "boolean",
        literal=False,
        message="must be false",
    ),
    _field(
        "secret_value_stored",
        "boolean",
        literal=False,
        message="must be false",
    ),
)

RUNBOOK_PROCEDURE_KEYS = frozenset(
    {"id", "title", "description", "command", "expected_effect"}
)
LEGACY_RUNBOOK_SUBMISSION_FIELDS = (
    _field("steps", "array"),
    _field("steps[]", "string_or_object"),
    _field("verification", "array"),
    _field("verification[]", "string_or_object"),
    _field("prerequisites", "array"),
    _field("prerequisites[]", "string_or_object"),
    _field("docs", "array"),
    _field("docs[]", "string_or_object"),
)


def _runbook_procedure(path: str, *, max_items: int) -> tuple[FieldSpec, ...]:
    """Declare ordered inert instruction entries from the Runbook contract."""
    return (
        _field(path, "array", max_items=max_items),
        _field(f"{path}[]", "object", allowed_keys=RUNBOOK_PROCEDURE_KEYS),
        _entry_id(f"{path}[].id"),
        _field(
            f"{path}[].title",
            "text",
            strip_whitespace=True,
            min_length=1,
            max_length=200,
        ),
        _field(
            f"{path}[].description",
            "text",
            strip_whitespace=True,
            min_length=1,
            max_length=4000,
        ),
        # Deliberately no whitespace normalization: command text is an inert,
        # byte-for-byte stored instruction, never an executable field.
        _field(f"{path}[].command", "text", min_length=1, max_length=16000),
        _field(
            f"{path}[].expected_effect",
            "text",
            required_in_item=True,
            strip_whitespace=True,
            min_length=1,
            max_length=4000,
        ),
    )


RUNBOOK_FIELDS = (
    _field(
        "runbook_status",
        "enum",
        required=True,
        enum_values=RUNBOOK_STATUSES,
        message="must be a supported runbook status",
    ),
    _field("purpose", "text", strip_whitespace=True, max_length=4000),
    *_text_list("in_scope"),
    *_text_list("out_of_scope"),
    _field(
        "risk_level",
        "enum",
        enum_values=RUNBOOK_RISK_LEVELS,
        message="must be a supported runbook risk level",
    ),
    _field("approval_required", "boolean", required=True),
    _field(
        "approval_requirement",
        "text",
        strip_whitespace=True,
        min_length=1,
        max_length=2000,
    ),
    _field("prerequisites", "array", max_items=100),
    _field(
        "prerequisites[]",
        "object",
        allowed_keys=frozenset({"id", "description"}),
    ),
    _entry_id("prerequisites[].id"),
    _field(
        "prerequisites[].description",
        "text",
        required_in_item=True,
        strip_whitespace=True,
        min_length=1,
        max_length=4000,
    ),
    *_runbook_procedure("steps", max_items=200),
    _field("verification", "array", max_items=100),
    _field(
        "verification[]",
        "object",
        allowed_keys=frozenset({"id", "description", "success_expectation"}),
    ),
    _entry_id("verification[].id"),
    _field(
        "verification[].description",
        "text",
        required_in_item=True,
        strip_whitespace=True,
        min_length=1,
        max_length=4000,
    ),
    _field(
        "verification[].success_expectation",
        "text",
        required_in_item=True,
        strip_whitespace=True,
        min_length=1,
        max_length=4000,
    ),
    *_runbook_procedure("rollback", max_items=100),
    *_runbook_procedure("recovery", max_items=100),
    _field(
        "change_fallback",
        "enum",
        enum_values=RUNBOOK_CHANGE_FALLBACKS,
        message="must be rollback, recovery, or no_rollback",
    ),
    _field(
        "change_fallback_rationale",
        "text",
        strip_whitespace=True,
        min_length=1,
        max_length=4000,
    ),
    _field(
        "deprecation_rationale",
        "text",
        strip_whitespace=True,
        min_length=1,
        max_length=4000,
    ),
    _field(
        "successor_recommendation",
        "text",
        strip_whitespace=True,
        min_length=1,
        max_length=4000,
    ),
    *_reference_list("applies_to", "host", "system", "network", "device", "service"),
    *_reference_list("credential_references", "credential_reference"),
    *_reference_list("related_decisions", "decision"),
    *_reference_list("related_projects", "project"),
    *_reference_list("related_runbooks", "runbook"),
    *_reference_list("supersedes", "runbook"),
    _field("superseded_by", "reference", reference_kinds=frozenset({"runbook"})),
    *_source_entries(
        "sources",
        max_items=50,
        identified=True,
        retrieval_metadata=True,
    ),
    _field("last_verified_at", "datetime"),
    _field("review_after", "datetime"),
)

DECISION_FIELDS = (
    _field(
        "decision_status",
        "enum",
        required=True,
        enum_values=DECISION_STATUSES,
        message="must be a supported decision status",
    ),
    _field("context", "text", strip_whitespace=True),
    _field("decision", "text", strip_whitespace=True),
    _field("rationale", "text", strip_whitespace=True),
    _field("alternatives", "array", max_items=50),
    _field(
        "alternatives[]",
        "text",
        strip_whitespace=True,
        min_length=1,
        max_length=2000,
    ),
    _field("consequences", "array", max_items=50),
    _field(
        "consequences[]",
        "text",
        strip_whitespace=True,
        min_length=1,
        max_length=2000,
    ),
    _field("decided_at", "datetime"),
    _field("effective_at", "datetime"),
    _field("review_after", "datetime"),
    *_reference_list("applies_to", "host", "system", "network", "device", "service"),
    *_reference_list("related_projects", "project"),
    *_reference_list("related_runbooks", "runbook"),
    *_reference_list("related_decisions", "decision"),
    *_reference_list("supersedes", "decision"),
    _field("superseded_by", "reference", reference_kinds=frozenset({"decision"})),
    *_source_entries("docs", max_items=25),
)

# Fields every canonical Project carries, whatever its category. `category` and
# `project_status` are the two closed discriminators; everything below them is
# the reviewed current knowledge state, never work chronology.
PROJECT_COMMON_FIELDS = (
    _field(
        "category",
        "enum",
        required=True,
        enum_values=PROJECT_CATEGORIES,
        message="must be a supported project category",
    ),
    _field(
        "project_status",
        "enum",
        required=True,
        enum_values=PROJECT_STATUSES,
        message="must be a supported project status",
    ),
    _field("objective", "text", strip_whitespace=True, max_length=4000),
    *_text_list("in_scope"),
    *_text_list("out_of_scope"),
    _field(
        "managed_by",
        "object",
        allowed_keys=frozenset({"kind", "label", "principal_id"}),
    ),
    _field(
        "managed_by.kind",
        "enum",
        enum_values=PROJECT_MANAGED_BY_KINDS,
        message="must be principal, person, or team",
    ),
    _field(
        "managed_by.label",
        "text",
        strip_whitespace=True,
        min_length=1,
        max_length=128,
    ),
    _field(
        "managed_by.principal_id",
        "string",
        strip_whitespace=True,
        min_length=1,
        max_length=128,
    ),
    _field("started_at", "datetime"),
    _field("completed_at", "datetime"),
    _field("review_after", "datetime"),
    *_reference_list(
        "related_assets",
        "host",
        "system",
        "network",
        "device",
        "service",
    ),
    *_reference_list("related_runbooks", "runbook"),
    *_reference_list("related_decisions", "decision"),
    *_reference_list("related_projects", "project"),
    *_source_entries(
        "sources",
        max_items=50,
        identified=True,
        retrieval_metadata=True,
    ),
    _field("current_summary", "text", strip_whitespace=True, max_length=4000),
    *_text_list("open_questions"),
    *_text_list("recommendations"),
    *_text_list("next_actions"),
)

PROJECT_RESEARCH_FIELDS = (
    *_text_list("research_questions"),
    *_text_list("hypotheses"),
    _field("methodology", "text", strip_whitespace=True, max_length=4000),
    _field("findings", "array", max_items=100),
    _field(
        "findings[]",
        "object",
        allowed_keys=frozenset(
            {
                "id",
                "statement",
                "evidence_grade",
                "source_ids",
                "observed_at",
                "verified_at",
            }
        ),
    ),
    _entry_id("findings[].id"),
    _field(
        "findings[].statement",
        "text",
        required_in_item=True,
        strip_whitespace=True,
        min_length=1,
        max_length=2000,
    ),
    _field(
        "findings[].evidence_grade",
        "enum",
        required_in_item=True,
        enum_values=PROJECT_EVIDENCE_GRADES,
        message="must be source_backed, observed, or inferred",
    ),
    _field("findings[].source_ids", "array", max_items=25),
    _field(
        "findings[].source_ids[]",
        "string",
        strip_whitespace=True,
        min_length=1,
        max_length=64,
    ),
    _field("findings[].observed_at", "datetime"),
    _field("findings[].verified_at", "datetime"),
    *_text_list("limitations"),
    *_text_list("conclusions"),
)

PROJECT_EXPERIMENT_FIELDS = (
    _field("hypothesis", "text", strip_whitespace=True, max_length=4000),
    _field("setup", "text", strip_whitespace=True, max_length=4000),
    _field("expected_result", "text", strip_whitespace=True, max_length=4000),
    _field("observed_result", "text", strip_whitespace=True, max_length=4000),
    _field("measurements", "array", max_items=100),
    _field(
        "measurements[]",
        "object",
        allowed_keys=frozenset({"name", "quantity", "unit", "observed_at"}),
    ),
    _field(
        "measurements[].name",
        "text",
        required_in_item=True,
        strip_whitespace=True,
        min_length=1,
        max_length=128,
    ),
    _field(
        "measurements[].quantity",
        "string",
        required_in_item=True,
        strip_whitespace=True,
        min_length=1,
        max_length=128,
    ),
    _field(
        "measurements[].unit",
        "string",
        strip_whitespace=True,
        min_length=1,
        max_length=64,
    ),
    _field("measurements[].observed_at", "datetime"),
    _field("conclusion", "text", strip_whitespace=True, max_length=4000),
    _field(
        "reproducibility_notes",
        "text",
        strip_whitespace=True,
        max_length=4000,
    ),
)

PROJECT_INCIDENT_REVIEW_FIELDS = (
    _field(
        "incident_window",
        "object",
        allowed_keys=frozenset({"started_at", "ended_at"}),
    ),
    _field("incident_window.started_at", "datetime"),
    _field("incident_window.ended_at", "datetime"),
    _field("impact", "text", strip_whitespace=True, max_length=4000),
    _field("detection", "text", strip_whitespace=True, max_length=4000),
    _field(
        "timeline_reference",
        "object",
        allowed_keys=frozenset({"type", "source_id", "note"}),
    ),
    _field(
        "timeline_reference.type",
        "enum",
        enum_values=PROJECT_TIMELINE_REFERENCE_TYPES,
        message="must be object_comments or source",
    ),
    _field(
        "timeline_reference.source_id",
        "string",
        strip_whitespace=True,
        min_length=1,
        max_length=64,
    ),
    _field(
        "timeline_reference.note",
        "text",
        strip_whitespace=True,
        min_length=1,
        max_length=2000,
    ),
    _field("root_cause", "text", strip_whitespace=True, max_length=4000),
    *_text_list("contributing_factors"),
    *_text_list("remediation"),
    *_text_list("prevention"),
)

PROJECT_MIGRATION_FIELDS = (
    _field("source_state", "text", strip_whitespace=True, max_length=4000),
    _field("target_state", "text", strip_whitespace=True, max_length=4000),
    *_text_list("migration_plan"),
    *_text_list("verification"),
    _field("rollback", "text", strip_whitespace=True, max_length=4000),
    _field("outcome", "text", strip_whitespace=True, max_length=4000),
)

# `lessons_learned` is deliberately shared: research, experiment retrospectives,
# incident reviews, and migrations all record it with the same meaning.
PROJECT_SHARED_CATEGORY_FIELDS = (*_text_list("lessons_learned"),)

# Which category admits which category-specific top-level fields. Every field
# below is rejected with a field-accurate error under any other category, so a
# Project can never silently carry contradictory category content.
PROJECT_CATEGORY_FIELD_GROUPS: Mapping[str, tuple[FieldSpec, ...]] = MappingProxyType(
    {
        "research": PROJECT_RESEARCH_FIELDS,
        "experiment": PROJECT_EXPERIMENT_FIELDS,
        "incident_review": PROJECT_INCIDENT_REVIEW_FIELDS,
        "migration": PROJECT_MIGRATION_FIELDS,
    }
)


def _top_level_paths(fields: tuple[FieldSpec, ...]) -> frozenset[str]:
    return frozenset(
        field.path.split(".")[0].removesuffix("[]") for field in fields
    )


PROJECT_CATEGORY_FIELD_NAMES: Mapping[str, frozenset[str]] = MappingProxyType(
    {
        category: _top_level_paths(fields)
        | _top_level_paths(PROJECT_SHARED_CATEGORY_FIELDS)
        for category, fields in PROJECT_CATEGORY_FIELD_GROUPS.items()
    }
)
# `implementation` and `other` carry the common contract only. They still admit
# `lessons_learned`, which is common retrospective content rather than a
# category-specific result shape.
PROJECT_COMMON_ONLY_CATEGORY_FIELD_NAMES = _top_level_paths(
    PROJECT_SHARED_CATEGORY_FIELDS
)
ALL_PROJECT_CATEGORY_FIELD_NAMES = frozenset(
    name
    for fields in PROJECT_CATEGORY_FIELD_GROUPS.values()
    for name in _top_level_paths(fields)
)

PROJECT_FIELDS = (
    *PROJECT_COMMON_FIELDS,
    *PROJECT_SHARED_CATEGORY_FIELDS,
    *PROJECT_RESEARCH_FIELDS,
    *PROJECT_EXPERIMENT_FIELDS,
    *PROJECT_INCIDENT_REVIEW_FIELDS,
    *PROJECT_MIGRATION_FIELDS,
)


def _reject_credential_value_keys(
    value: Any,
    path: str = "data",
) -> None:
    if isinstance(value, Mapping):
        for key, child_value in value.items():
            key_text = str(key).lower()
            child_path = f"{path}.{key}"
            if key_text in FORBIDDEN_DATA_VALUE_KEYS:
                raise ObjectSchemaError(
                    child_path,
                    "credential references may not contain raw value fields",
                    violation=VIOLATION_FORBIDDEN_KEY,
                    rule=public_rule_name(_reject_credential_value_keys),
                )
            _reject_credential_value_keys(child_value, child_path)
    elif isinstance(value, list):
        for index, child_value in enumerate(value):
            _reject_credential_value_keys(child_value, f"{path}[{index}]")


def _require_runbook_conditional_fields(data: Mapping[str, Any]) -> None:
    """Require lifecycle, approval, and change-control fields as one contract."""
    rule = public_rule_name(_require_runbook_conditional_fields)
    status = data.get("runbook_status")
    if status in {"approved", "active"}:
        for field_name in (
            "purpose",
            "risk_level",
            "prerequisites",
            "steps",
            "verification",
            "last_verified_at",
        ):
            value = data.get(field_name)
            if value is None or value == "" or value == []:
                raise ObjectSchemaError(
                    f"data.{field_name}",
                    f"is required for {status} runbooks",
                    violation=VIOLATION_REQUIRED_FIELD_MISSING,
                    rule=rule,
                )

    approval_required = data.get("approval_required")
    if approval_required is True and not _nonblank_text(
        data.get("approval_requirement")
    ):
        raise ObjectSchemaError(
            "data.approval_requirement",
            "is required when approval is required",
            violation=VIOLATION_REQUIRED_FIELD_MISSING,
            rule=rule,
        )

    risk = data.get("risk_level")
    if risk in {"disruptive", "destructive"}:
        if approval_required is not True:
            raise ObjectSchemaError(
                "data.approval_required",
                "must be true for disruptive or destructive runbooks",
                violation=VIOLATION_REQUIRED_FIELD_MISSING,
                rule=rule,
            )
        if not data.get("rollback") and not data.get("recovery"):
            raise ObjectSchemaError(
                "data.rollback",
                "or data.recovery must be nonempty for disruptive or destructive runbooks",
                violation=VIOLATION_REQUIRED_FIELD_MISSING,
                rule=rule,
            )

    if risk in {"safe-change", "disruptive", "destructive"}:
        fallback = data.get("change_fallback")
        if fallback is None:
            raise ObjectSchemaError(
                "data.change_fallback",
                "is required for change runbooks",
                violation=VIOLATION_REQUIRED_FIELD_MISSING,
                rule=rule,
            )
        if fallback == "rollback" and not data.get("rollback"):
            raise ObjectSchemaError(
                "data.rollback",
                "must be nonempty when change_fallback is rollback",
                violation=VIOLATION_REQUIRED_FIELD_MISSING,
                rule=rule,
            )
        if fallback == "recovery" and not data.get("recovery"):
            raise ObjectSchemaError(
                "data.recovery",
                "must be nonempty when change_fallback is recovery",
                violation=VIOLATION_REQUIRED_FIELD_MISSING,
                rule=rule,
            )
        if fallback in {"recovery", "no_rollback"} and not _nonblank_text(
            data.get("change_fallback_rationale")
        ):
            raise ObjectSchemaError(
                "data.change_fallback_rationale",
                f"is required when change_fallback is {fallback}",
                violation=VIOLATION_REQUIRED_FIELD_MISSING,
                rule=rule,
            )

    if status == "deprecated" and not (
        _nonblank_text(data.get("deprecation_rationale"))
        or _nonblank_text(data.get("successor_recommendation"))
    ):
        raise ObjectSchemaError(
            "data.deprecation_rationale",
            "or data.successor_recommendation is required for deprecated runbooks",
            violation=VIOLATION_REQUIRED_FIELD_MISSING,
            rule=rule,
        )
    if status == "superseded" and "superseded_by" not in data:
        raise ObjectSchemaError(
            "data.superseded_by",
            "is required for superseded runbooks",
            violation=VIOLATION_REQUIRED_FIELD_MISSING,
            rule=rule,
        )


def _reject_runbook_contradictions(data: Mapping[str, Any]) -> None:
    """Reject combinations whose stored meaning would be ambiguous."""
    rule = public_rule_name(_reject_runbook_contradictions)
    if data.get("approval_required") is False and "approval_requirement" in data:
        raise ObjectSchemaError(
            "data.approval_requirement",
            "is allowed only when approval_required is true",
            violation=VIOLATION_FIELD_NOT_ALLOWED,
            rule=rule,
        )
    if (
        data.get("change_fallback") == "no_rollback"
        and data.get("risk_level") in {"disruptive", "destructive"}
    ):
        raise ObjectSchemaError(
            "data.change_fallback",
            "no_rollback is not allowed for disruptive or destructive runbooks",
            violation=VIOLATION_FIELD_NOT_ALLOWED,
            rule=rule,
        )


def _validate_runbook_entries(data: Mapping[str, Any]) -> None:
    """Keep local ids unique and instruction/command content unambiguous."""
    rule = public_rule_name(_validate_runbook_entries)
    for path in ("prerequisites", "steps", "verification", "rollback", "recovery", "sources"):
        _unique_entry_ids(data.get(path), f"data.{path}", rule=rule)
    for path in ("steps", "rollback", "recovery"):
        entries = data.get(path)
        if not isinstance(entries, list):
            continue
        for index, entry in enumerate(entries):
            if not isinstance(entry, Mapping):
                continue
            if not (
                _nonblank_text(entry.get("title"))
                or _nonblank_text(entry.get("description"))
            ):
                raise ObjectSchemaError(
                    f"data.{path}[{index}].description",
                    "or title must be nonblank",
                    violation=VIOLATION_VALUE_NOT_ALLOWED,
                    rule=rule,
                )
            command = entry.get("command")
            if isinstance(command, str) and not command.strip():
                raise ObjectSchemaError(
                    f"data.{path}[{index}].command",
                    "must not be blank",
                    violation=VIOLATION_VALUE_NOT_ALLOWED,
                    rule=rule,
                )


def _validate_runbook_timestamp_order(data: Mapping[str, Any]) -> None:
    rule = public_rule_name(_validate_runbook_timestamp_order)
    verified = _parse_rfc3339(data.get("last_verified_at"))
    review = _parse_rfc3339(data.get("review_after"))
    _require_order("data.review_after", verified, review, rule=rule)


def _nonblank_text(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _validate_decision_lifecycle(data: Mapping[str, Any]) -> None:
    status = data.get("decision_status")
    if status == "accepted":
        for field_name in ("context", "decision", "rationale", "decided_at"):
            value = data.get(field_name)
            if not isinstance(value, str) or not value.strip():
                raise ObjectSchemaError(
                    f"data.{field_name}",
                    "is required and must not be blank for accepted decisions",
                    violation=VIOLATION_REQUIRED_FIELD_MISSING,
                    rule=public_rule_name(_validate_decision_lifecycle),
                )
    if status == "superseded" and "superseded_by" not in data:
        raise ObjectSchemaError(
            "data.superseded_by",
            "is required for superseded decisions",
            violation=VIOLATION_REQUIRED_FIELD_MISSING,
            rule=public_rule_name(_validate_decision_lifecycle),
        )


def _require_project_conditional_fields(data: Mapping[str, Any]) -> None:
    """Require the fields other canonical Project fields make mandatory."""
    rule = public_rule_name(_require_project_conditional_fields)
    status = data.get("project_status")
    if status in {"active", "paused", "completed"} and "started_at" not in data:
        raise ObjectSchemaError(
            "data.started_at",
            f"is required for {status} projects",
            violation=VIOLATION_REQUIRED_FIELD_MISSING,
            rule=rule,
        )
    if status == "completed" and "completed_at" not in data:
        raise ObjectSchemaError(
            "data.completed_at",
            "is required for completed projects",
            violation=VIOLATION_REQUIRED_FIELD_MISSING,
            rule=rule,
        )
    if "completed_at" in data and "started_at" not in data:
        raise ObjectSchemaError(
            "data.started_at",
            "is required when data.completed_at is present",
            violation=VIOLATION_REQUIRED_FIELD_MISSING,
            rule=rule,
        )

    managed_by = data.get("managed_by")
    if isinstance(managed_by, Mapping):
        owner_kind = managed_by.get("kind")
        if owner_kind is None:
            raise ObjectSchemaError(
                "data.managed_by.kind",
                "is required",
                violation=VIOLATION_REQUIRED_FIELD_MISSING,
                rule=rule,
            )
        required_key = "principal_id" if owner_kind == "principal" else "label"
        if owner_kind in PROJECT_MANAGED_BY_KINDS and required_key not in managed_by:
            raise ObjectSchemaError(
                f"data.managed_by.{required_key}",
                f"is required for {owner_kind} ownership",
                violation=VIOLATION_REQUIRED_FIELD_MISSING,
                rule=rule,
            )

    timeline = data.get("timeline_reference")
    if isinstance(timeline, Mapping):
        if "type" not in timeline:
            raise ObjectSchemaError(
                "data.timeline_reference.type",
                "is required",
                violation=VIOLATION_REQUIRED_FIELD_MISSING,
                rule=rule,
            )
        if timeline.get("type") == "source" and "source_id" not in timeline:
            raise ObjectSchemaError(
                "data.timeline_reference.source_id",
                "is required for source timeline references",
                violation=VIOLATION_REQUIRED_FIELD_MISSING,
                rule=rule,
            )

    incident_window = data.get("incident_window")
    if isinstance(incident_window, Mapping):
        for field_name in ("started_at", "ended_at"):
            if field_name not in incident_window:
                raise ObjectSchemaError(
                    f"data.incident_window.{field_name}",
                    "is required when data.incident_window is present",
                    violation=VIOLATION_REQUIRED_FIELD_MISSING,
                    rule=rule,
                )
    findings = data.get("findings")
    if isinstance(findings, list):
        for index, finding in enumerate(findings):
            if not isinstance(finding, Mapping):
                continue
            if finding.get("evidence_grade") == "source_backed" and not finding.get(
                "source_ids"
            ):
                raise ObjectSchemaError(
                    f"data.findings[{index}].source_ids",
                    "is required for source_backed findings",
                    violation=VIOLATION_REQUIRED_FIELD_MISSING,
                    rule=rule,
                )


def _reject_project_contradictory_fields(data: Mapping[str, Any]) -> None:
    """Reject fields the declared category, status, or shape does not admit."""
    rule = public_rule_name(_reject_project_contradictory_fields)
    category = data.get("category")
    if isinstance(category, str) and category in PROJECT_CATEGORIES:
        allowed = PROJECT_CATEGORY_FIELD_NAMES.get(
            category,
            PROJECT_COMMON_ONLY_CATEGORY_FIELD_NAMES,
        )
        present = sorted((ALL_PROJECT_CATEGORY_FIELD_NAMES & set(data)) - allowed)
        if present:
            raise ObjectSchemaError(
                f"data.{present[0]}",
                f"is not part of the {category} project contract",
                violation=VIOLATION_FIELD_NOT_ALLOWED,
                rule=rule,
            )

    status = data.get("project_status")
    if status == "planned" and "started_at" in data:
        raise ObjectSchemaError(
            "data.started_at",
            "is not allowed for planned projects",
            violation=VIOLATION_FIELD_NOT_ALLOWED,
            rule=rule,
        )
    if status in {"planned", "active", "paused"} and "completed_at" in data:
        raise ObjectSchemaError(
            "data.completed_at",
            f"is not allowed for {status} projects",
            violation=VIOLATION_FIELD_NOT_ALLOWED,
            rule=rule,
        )

    managed_by = data.get("managed_by")
    if isinstance(managed_by, Mapping):
        forbidden_key = (
            "label" if managed_by.get("kind") == "principal" else "principal_id"
        )
        if managed_by.get("kind") in PROJECT_MANAGED_BY_KINDS and forbidden_key in (
            managed_by
        ):
            raise ObjectSchemaError(
                f"data.managed_by.{forbidden_key}",
                f"is not allowed for {managed_by['kind']} ownership",
                violation=VIOLATION_FIELD_NOT_ALLOWED,
                rule=rule,
            )

    timeline = data.get("timeline_reference")
    if (
        isinstance(timeline, Mapping)
        and timeline.get("type") == "object_comments"
        and "source_id" in timeline
    ):
        raise ObjectSchemaError(
            "data.timeline_reference.source_id",
            "is allowed only for source timeline references",
            violation=VIOLATION_FIELD_NOT_ALLOWED,
            rule=rule,
        )


def _reject_ambiguous_project_evidence(data: Mapping[str, Any]) -> None:
    """Keep sources, findings, citations, and measurements unambiguous.

    Contradictory findings stay representable: two findings may make opposite
    statements about the same subject as long as each carries its own id. Only
    entries the canonical contract cannot tell apart are rejected.
    """
    rule = public_rule_name(_reject_ambiguous_project_evidence)
    source_ids = _unique_entry_ids(data.get("sources"), "data.sources", rule=rule)
    _unique_entry_ids(data.get("findings"), "data.findings", rule=rule)

    findings = data.get("findings")
    if isinstance(findings, list):
        for index, finding in enumerate(findings):
            if not isinstance(finding, Mapping):
                continue
            cited = finding.get("source_ids")
            if not isinstance(cited, list):
                continue
            seen_citations: set[str] = set()
            for cited_index, cited_id in enumerate(cited):
                if not isinstance(cited_id, str):
                    continue
                path = f"data.findings[{index}].source_ids[{cited_index}]"
                if cited_id not in source_ids:
                    raise ObjectSchemaError(
                        path,
                        "must name an id declared in data.sources",
                        violation=VIOLATION_VALUE_NOT_ALLOWED,
                        rule=rule,
                    )
                if cited_id in seen_citations:
                    raise ObjectSchemaError(
                        path,
                        "cites the same source twice",
                        violation=VIOLATION_VALUE_NOT_ALLOWED,
                        rule=rule,
                    )
                seen_citations.add(cited_id)

    timeline = data.get("timeline_reference")
    if (
        isinstance(timeline, Mapping)
        and timeline.get("type") == "source"
        and isinstance(source_id := timeline.get("source_id"), str)
        and source_id not in source_ids
    ):
        raise ObjectSchemaError(
            "data.timeline_reference.source_id",
            "must name an id declared in data.sources",
            violation=VIOLATION_VALUE_NOT_ALLOWED,
            rule=rule,
        )

    measurements = data.get("measurements")
    if isinstance(measurements, list):
        seen_measurements: set[tuple[str, str]] = set()
        for index, measurement in enumerate(measurements):
            if not isinstance(measurement, Mapping):
                continue
            key = (str(measurement.get("name")), str(measurement.get("observed_at")))
            if key in seen_measurements:
                raise ObjectSchemaError(
                    f"data.measurements[{index}].name",
                    "repeats an earlier measurement of the same name and time",
                    violation=VIOLATION_VALUE_NOT_ALLOWED,
                    rule=rule,
                )
            seen_measurements.add(key)


def _validate_project_timestamp_order(data: Mapping[str, Any]) -> None:
    """Reject Project timestamps that run backwards."""
    rule = public_rule_name(_validate_project_timestamp_order)
    started_at = _parse_rfc3339(data.get("started_at"))
    completed_at = _parse_rfc3339(data.get("completed_at"))
    _require_order(
        "data.completed_at",
        started_at,
        completed_at,
        rule=rule,
    )
    _require_order(
        "data.review_after",
        completed_at or started_at,
        _parse_rfc3339(data.get("review_after")),
        rule=rule,
    )
    window = data.get("incident_window")
    if isinstance(window, Mapping):
        _require_order(
            "data.incident_window.ended_at",
            _parse_rfc3339(window.get("started_at")),
            _parse_rfc3339(window.get("ended_at")),
            rule=rule,
        )
        if completed_at is not None:
            _require_order(
                "data.completed_at",
                _parse_rfc3339(window.get("ended_at")),
                completed_at,
                rule=rule,
            )
    sources = data.get("sources")
    if isinstance(sources, list):
        for index, source in enumerate(sources):
            if not isinstance(source, Mapping):
                continue
            _require_order(
                f"data.sources[{index}].retrieved_at",
                _parse_rfc3339(source.get("published_at")),
                _parse_rfc3339(source.get("retrieved_at")),
                rule=rule,
            )
    findings = data.get("findings")
    if isinstance(findings, list):
        for index, finding in enumerate(findings):
            if not isinstance(finding, Mapping):
                continue
            _require_order(
                f"data.findings[{index}].verified_at",
                _parse_rfc3339(finding.get("observed_at")),
                _parse_rfc3339(finding.get("verified_at")),
                rule=rule,
            )


def _unique_entry_ids(
    entries: Any,
    path: str,
    *,
    rule: str,
) -> set[str]:
    if not isinstance(entries, list):
        return set()
    seen: set[str] = set()
    for index, entry in enumerate(entries):
        if not isinstance(entry, Mapping):
            continue
        entry_id = entry.get("id")
        if not isinstance(entry_id, str):
            continue
        if entry_id in seen:
            raise ObjectSchemaError(
                f"{path}[{index}].id",
                "repeats an earlier entry id",
                violation=VIOLATION_VALUE_NOT_ALLOWED,
                rule=rule,
            )
        seen.add(entry_id)
    return seen


def _require_order(
    path: str,
    earlier: datetime | None,
    later: datetime | None,
    *,
    rule: str,
) -> None:
    if earlier is not None and later is not None and later < earlier:
        raise ObjectSchemaError(
            path,
            "must not be earlier than the timestamp it follows",
            violation=VIOLATION_VALUE_OUT_OF_RANGE,
            rule=rule,
        )


def _require_installed_software_fields(data: Mapping[str, Any]) -> None:
    entries = data.get("installed_software")
    if not isinstance(entries, list):
        return
    for index, entry in enumerate(entries):
        if not isinstance(entry, Mapping):
            continue
        for field_name in ("name", "version"):
            if field_name not in entry:
                raise ObjectSchemaError(
                    f"data.installed_software[{index}].{field_name}",
                    "is required",
                    violation=VIOLATION_REQUIRED_FIELD_MISSING,
                    rule=public_rule_name(_require_installed_software_fields),
                )


def _reject_empty_installed_software_fields(data: Mapping[str, Any]) -> None:
    entries = data.get("installed_software")
    if not isinstance(entries, list):
        return
    for index, entry in enumerate(entries):
        if not isinstance(entry, Mapping):
            continue
        for field_name in ("name", "version"):
            value = entry.get(field_name)
            if isinstance(value, str) and not value.strip():
                raise ObjectSchemaError(
                    f"data.installed_software[{index}].{field_name}",
                    "must not be empty",
                    violation=VIOLATION_VALUE_TOO_SHORT,
                    rule=public_rule_name(_reject_empty_installed_software_fields),
                )


def _reject_installed_software_extra_fields(data: Mapping[str, Any]) -> None:
    entries = data.get("installed_software")
    if not isinstance(entries, list):
        return
    for index, entry in enumerate(entries):
        if not isinstance(entry, Mapping):
            continue
        additional_fields = sorted(set(entry) - INSTALLED_SOFTWARE_ENTRY_FIELDS)
        if additional_fields:
            raise ObjectSchemaError(
                f"data.installed_software[{index}].{additional_fields[0]}",
                "is not allowed",
                violation=VIOLATION_FIELD_NOT_ALLOWED,
                rule=public_rule_name(_reject_installed_software_extra_fields),
            )


def _validate_service_components(data: Mapping[str, Any]) -> None:
    """Enforce local identity and graph integrity after field-shape checks."""

    violations = service_component_violations(data)
    if not violations:
        return
    violation = violations[0]
    raise ObjectSchemaError(
        violation.path,
        violation.message,
        violation=violation.violation,
        rule=public_rule_name(_validate_service_components),
    )


# Published description for every schema-bound postcondition, keyed by the rule
# callable's name. Rules stay executable in one place; the projection publishes
# them instead of restating conditional validation in a second contract.
SCHEMA_RULE_CONTRACTS: Mapping[str, str] = MappingProxyType(
    {
        "_reject_credential_value_keys": (
            "No key anywhere below data may name a raw credential or secret value."
        ),
        "_require_runbook_conditional_fields": (
            "Approved and active runbooks require purpose, risk_level, nonempty "
            "prerequisites, steps, verification, and last_verified_at. Approval "
            "requirements, disruptive/destructive fallback procedures, change "
            "fallback selection and rationale, deprecated rationale or successor "
            "recommendation, and superseded successor links are conditionally required."
        ),
        "_reject_runbook_contradictions": (
            "approval_requirement is allowed only when approval_required is true, "
            "and disruptive or destructive runbooks cannot declare no_rollback."
        ),
        "_validate_runbook_entries": (
            "Prerequisite, instruction, verification, rollback, recovery, and source "
            "ids are unique within their ordered collection; each procedure entry "
            "has a nonblank title or description; inert command text cannot be blank."
        ),
        "_validate_runbook_timestamp_order": (
            "review_after must not precede last_verified_at."
        ),
        "_validate_decision_lifecycle": (
            "Accepted decisions require nonblank context, decision, rationale, and "
            "decided_at; superseded decisions require superseded_by."
        ),
        "_require_project_conditional_fields": (
            "Active, paused, and completed projects require data.started_at; "
            "completed projects require data.completed_at; data.completed_at "
            "requires data.started_at; data.managed_by requires kind plus the "
            "principal_id or label that kind uses; a source timeline reference "
            "requires source_id; an incident window requires both timestamps; "
            "and source_backed findings require source_ids."
        ),
        "_reject_project_contradictory_fields": (
            "A project may carry only the category-specific fields its declared "
            "data.category admits; planned projects reject data.started_at; "
            "planned, active, and paused projects reject data.completed_at; "
            "principal ownership rejects label and human or team ownership "
            "rejects principal_id; and an object-comment timeline reference "
            "rejects source_id."
        ),
        "_reject_ambiguous_project_evidence": (
            "Source and finding ids are unique, findings and source timeline "
            "references cite declared source ids at most once each, and no two "
            "measurements repeat the same name at the same time."
        ),
        "_validate_project_timestamp_order": (
            "data.completed_at must not precede data.started_at; data.review_after "
            "must not precede completion when present (otherwise start); an "
            "incident window must not end before it starts or after review "
            "completion; source retrieval must not precede publication; and a "
            "finding must not be verified before it was observed."
        ),
        "_require_installed_software_fields": (
            "Every installed-software entry must contain name and version fields."
        ),
        "_reject_empty_installed_software_fields": (
            "Installed-software names and versions must not be empty or whitespace-only."
        ),
        "_reject_installed_software_extra_fields": (
            "Installed-software entries may contain only name, version, and url."
        ),
        "_validate_service_components": (
            "data.components is a closed service-only document with required items "
            "and dependencies arrays. Component ids are unique lowercase local ids; "
            "dependency endpoints must name components in the same service; self "
            "references and duplicate directed pairs are rejected. Directed cycles "
            "are allowed and consumers must honor the published traversal bounds."
        ),
    }
)


# The violation type every schema-bound postcondition reports. Field rules stay
# field-typed; a rule failure names the published rule instead.
SCHEMA_RULE_VIOLATIONS: Mapping[str, str] = MappingProxyType(
    {
        "_reject_credential_value_keys": VIOLATION_FORBIDDEN_KEY,
        "_require_runbook_conditional_fields": VIOLATION_REQUIRED_FIELD_MISSING,
        "_reject_runbook_contradictions": VIOLATION_FIELD_NOT_ALLOWED,
        "_validate_runbook_entries": VIOLATION_VALUE_NOT_ALLOWED,
        "_validate_runbook_timestamp_order": VIOLATION_VALUE_OUT_OF_RANGE,
        "_validate_decision_lifecycle": VIOLATION_REQUIRED_FIELD_MISSING,
        "_require_project_conditional_fields": VIOLATION_REQUIRED_FIELD_MISSING,
        "_reject_project_contradictory_fields": VIOLATION_FIELD_NOT_ALLOWED,
        "_reject_ambiguous_project_evidence": VIOLATION_VALUE_NOT_ALLOWED,
        "_validate_project_timestamp_order": VIOLATION_VALUE_OUT_OF_RANGE,
        "_require_installed_software_fields": VIOLATION_REQUIRED_FIELD_MISSING,
        "_reject_empty_installed_software_fields": VIOLATION_VALUE_TOO_SHORT,
        "_reject_installed_software_extra_fields": VIOLATION_FIELD_NOT_ALLOWED,
        "_validate_service_components": VIOLATION_VALUE_NOT_ALLOWED,
    }
)


def rule_name(rule: SchemaRule) -> str:
    return getattr(rule, "__name__", repr(rule))


def public_rule_name(rule: SchemaRule | str) -> str:
    """Return the published name of one schema rule, without its private prefix."""
    name = rule if isinstance(rule, str) else rule_name(rule)
    return name.lstrip("_")


PUBLIC_SCHEMA_RULE_CONTRACTS: Mapping[str, str] = MappingProxyType(
    {
        public_rule_name(name): description
        for name, description in SCHEMA_RULE_CONTRACTS.items()
    }
)
PUBLIC_SCHEMA_RULE_VIOLATIONS: Mapping[str, str] = MappingProxyType(
    {
        public_rule_name(name): violation
        for name, violation in SCHEMA_RULE_VIOLATIONS.items()
    }
)


def _schema(
    kind: str,
    *fields: FieldSpec,
    rules: tuple[SchemaRule, ...] = (),
) -> TypeSchema:
    return TypeSchema(
        kind=kind,
        fields=(*COMMON_FIELDS, *fields),
        rules=rules,
    )


BUILTIN_SCHEMAS: Mapping[str, TypeSchema] = MappingProxyType(
    {
        "host": _schema(
            "host",
            *INTERFACE_FIELDS,
            *NETWORK_FIELDS,
            *INSTALLED_SOFTWARE_FIELDS,
            *SERVICE_COMPONENTS_FORBIDDEN_FIELDS,
            *REFERENCE_FIELDS,
            rules=(
                _require_installed_software_fields,
                _reject_empty_installed_software_fields,
                _reject_installed_software_extra_fields,
            ),
        ),
        "system": _schema(
            "system",
            *INTERFACE_FIELDS,
            *NETWORK_FIELDS,
            *INSTALLED_SOFTWARE_FIELDS,
            *SERVICE_COMPONENTS_FORBIDDEN_FIELDS,
            *REFERENCE_FIELDS,
            rules=(
                _require_installed_software_fields,
                _reject_empty_installed_software_fields,
                _reject_installed_software_extra_fields,
            ),
        ),
        "network": _schema(
            "network",
            *INSTALLED_SOFTWARE_FORBIDDEN_FIELDS,
            *INTERFACE_FIELDS,
            *NETWORK_FIELDS,
            *NETWORK_OBJECT_FIELDS,
            *SERVICE_COMPONENTS_FORBIDDEN_FIELDS,
        ),
        "device": _schema(
            "device",
            *INSTALLED_SOFTWARE_FORBIDDEN_FIELDS,
            *INTERFACE_FIELDS,
            *DEVICE_FIELDS,
            *REFERENCE_FIELDS,
            *SERVICE_COMPONENTS_FORBIDDEN_FIELDS,
        ),
        "service": _schema(
            "service",
            *INTERFACE_FIELDS,
            *SERVICE_FIELDS,
            *REFERENCE_FIELDS,
            *INSTALLED_SOFTWARE_FORBIDDEN_FIELDS,
            rules=(_validate_service_components,),
        ),
        "credential_reference": _schema(
            "credential_reference",
            *CREDENTIAL_REFERENCE_FIELDS,
            *INSTALLED_SOFTWARE_FORBIDDEN_FIELDS,
            *SERVICE_COMPONENTS_FORBIDDEN_FIELDS,
            rules=(_reject_credential_value_keys,),
        ),
        "runbook": _schema(
            "runbook",
            *RUNBOOK_FIELDS,
            *INSTALLED_SOFTWARE_FORBIDDEN_FIELDS,
            *SERVICE_COMPONENTS_FORBIDDEN_FIELDS,
            rules=(
                _reject_credential_value_keys,
                _require_runbook_conditional_fields,
                _reject_runbook_contradictions,
                _validate_runbook_entries,
                _validate_runbook_timestamp_order,
            ),
        ),
        "decision": _schema(
            "decision",
            *INSTALLED_SOFTWARE_FORBIDDEN_FIELDS,
            *DECISION_FIELDS,
            *SERVICE_COMPONENTS_FORBIDDEN_FIELDS,
            rules=(_validate_decision_lifecycle,),
        ),
        "project": _schema(
            "project",
            *INSTALLED_SOFTWARE_FORBIDDEN_FIELDS,
            *PROJECT_FIELDS,
            *SERVICE_COMPONENTS_FORBIDDEN_FIELDS,
            rules=(
                _require_project_conditional_fields,
                _reject_project_contradictory_fields,
                _reject_ambiguous_project_evidence,
                _validate_project_timestamp_order,
            ),
        ),
    }
)
