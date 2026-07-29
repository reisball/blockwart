from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from ipaddress import ip_address
from types import MappingProxyType
from typing import Any, Literal
from urllib.parse import urlsplit

from blockwart.domain.interfaces import CANONICAL_EXPOSURES, CANONICAL_TRANSPORTS
from blockwart.domain.references import TypedReference
from blockwart.domain.security import FORBIDDEN_SECRET_KEYS

FieldType = Literal[
    "array",
    "boolean",
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
_FORBIDDEN_SCHEMA_KEYS = FORBIDDEN_SECRET_KEYS | {
    "credential",
    "credentials",
    "plaintext",
    "raw",
    "raw_value",
    "secret_value",
    "value",
}

CREDENTIAL_PROVIDERS = frozenset(
    {"vaultwarden", "secrets_json", "env_file", "local_file", "external"}
)
CREDENTIAL_ACCESS_TYPES = frozenset(
    {"ssh", "web", "api", "database", "smb", "sudo", "token", "other"}
)
RUNBOOK_RISK_LEVELS = frozenset(
    {"read-only", "safe-change", "disruptive", "destructive"}
)

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
    """A catalog data field violates the fixed schema for its object kind."""

    def __init__(self, path: str, message: str) -> None:
        self.path = path
        self.message = message
        super().__init__(f"{path} {message}")


@dataclass(frozen=True)
class FieldSpec:
    path: str
    field_type: FieldType
    required: bool = False
    enum_values: frozenset[Any] = frozenset()
    reference_kinds: frozenset[str] = frozenset()
    literal: Any = _UNSET
    message: str | None = None
    forbidden_message: str | None = None

    def __post_init__(self) -> None:
        if not self.path or any(not part for part in self.path.split(".")):
            raise ValueError("schema field paths must use non-empty dot-separated keys")
        path_keys = {part.removesuffix("[]").lower() for part in self.path.split(".")}
        forbidden_keys = path_keys & _FORBIDDEN_SCHEMA_KEYS
        if forbidden_keys:
            joined = ", ".join(sorted(forbidden_keys))
            raise ValueError(f"schema fields may not declare secret value keys: {joined}")
        if self.field_type == "enum" and not self.enum_values:
            raise ValueError(f"enum field {self.path} requires enum_values")
        if self.field_type == "reference" and not self.reference_kinds:
            raise ValueError(f"reference field {self.path} requires reference_kinds")
        if self.forbidden_message is not None and (
            self.required
            or self.enum_values
            or self.reference_kinds
            or self.literal is not _UNSET
        ):
            raise ValueError(f"forbidden field {self.path} cannot define validation options")


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


def validate_object_data(kind: str, data: Mapping[str, Any]) -> None:
    schema = BUILTIN_SCHEMAS[kind]
    validate_fields(data, schema.fields)
    for rule in schema.rules:
        rule(data)


def validate_fields(
    data: Mapping[str, Any],
    fields: tuple[FieldSpec, ...],
) -> None:
    for field in fields:
        values = _resolve_values(data, field.path)
        if field.required and not values:
            raise ObjectSchemaError(f"data.{field.path}", "is required")
        for path, value in values:
            if field.forbidden_message is not None:
                raise ObjectSchemaError(path, field.forbidden_message)
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
                raise ObjectSchemaError(parent_path, "must be an object")
            if key not in parent:
                continue
            value = parent[key]
            value_path = f"{parent_path}.{key}"
            if not is_array:
                next_values.append((value_path, value))
                continue
            if not isinstance(value, list):
                raise ObjectSchemaError(value_path, "must be a list")
            next_values.extend(
                (f"{value_path}[{index}]", item)
                for index, item in enumerate(value)
            )
        resolved = next_values
    return resolved


def _validate_value(field: FieldSpec, path: str, value: Any) -> None:
    field_type = field.field_type
    if field_type in {"string", "text"}:
        valid = isinstance(value, str)
        default_message = "must be a string"
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
        valid = value in field.enum_values
        allowed = ", ".join(sorted(str(item) for item in field.enum_values))
        default_message = f"must be one of: {allowed}"
    elif field_type == "ip":
        valid = _is_ip(value)
        default_message = "must be a valid IP address"
    elif field_type == "url":
        valid = _is_url(value)
        default_message = "must be a valid URL"
    elif field_type == "port":
        valid = (
            isinstance(value, int)
            and not isinstance(value, bool)
            and 1 <= value <= 65535
        )
        default_message = "must be an integer from 1 to 65535"
    elif field_type == "reference":
        _validate_reference(value, field.reference_kinds, path)
        valid = True
        default_message = ""
    else:  # pragma: no cover - Literal and construction tests make this unreachable
        raise AssertionError(f"unsupported schema field type: {field_type}")

    if not valid:
        raise ObjectSchemaError(path, field.message or default_message)
    if field.literal is not _UNSET and value != field.literal:
        raise ObjectSchemaError(path, field.message or f"must be {field.literal!r}")


def _validate_reference(
    value: Any,
    allowed_kinds: frozenset[str],
    path: str,
) -> None:
    if not isinstance(value, str):
        raise ObjectSchemaError(path, "must be a string")
    try:
        parsed = TypedReference.parse(value)
    except ValueError as exc:
        raise ObjectSchemaError(path, "must use a supported kind:id reference") from exc
    if parsed.kind not in allowed_kinds:
        allowed = ", ".join(sorted(allowed_kinds))
        raise ObjectSchemaError(path, f"must reference one of: {allowed}")


def _is_ip(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    try:
        ip_address(value)
    except ValueError:
        return False
    return True


def _is_url(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    parsed = urlsplit(value)
    return bool(parsed.scheme and (parsed.netloc or parsed.path))


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

RUNBOOK_FIELDS = (
    _field(
        "risk_level",
        "enum",
        enum_values=RUNBOOK_RISK_LEVELS,
        message="must be a supported runbook risk level",
    ),
    _field("approval_required", "boolean"),
    _field("steps", "array"),
    _field("steps[]", "string_or_object"),
    _field("verification", "array"),
    _field("verification[]", "string_or_object"),
    _field("prerequisites", "array"),
    _field("prerequisites[]", "string_or_object"),
    _field("docs", "array"),
    _field("docs[]", "string_or_object"),
    _field("applies_to", "object"),
    *_reference_list("applies_to.systems", "system"),
    *_reference_list("applies_to.services", "service"),
    *_reference_list("credential_references", "credential_reference"),
    *_reference_list("related_decisions", "decision"),
)


def _reject_credential_value_keys(
    value: Any,
    path: str = "data",
) -> None:
    if isinstance(value, Mapping):
        for key, child_value in value.items():
            key_text = str(key).lower()
            child_path = f"{path}.{key}"
            if key_text in _FORBIDDEN_SCHEMA_KEYS:
                raise ObjectSchemaError(
                    child_path,
                    "credential references may not contain raw value fields",
                )
            _reject_credential_value_keys(child_value, child_path)
    elif isinstance(value, list):
        for index, child_value in enumerate(value):
            _reject_credential_value_keys(child_value, f"{path}[{index}]")


def _validate_runbook_approval(data: Mapping[str, Any]) -> None:
    if (
        data.get("risk_level") in {"disruptive", "destructive"}
        and data.get("approval_required") is False
    ):
        raise ObjectSchemaError(
            "data.approval_required",
            "must be true for disruptive or destructive runbooks",
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
            *REFERENCE_FIELDS,
        ),
        "system": _schema(
            "system",
            *INTERFACE_FIELDS,
            *NETWORK_FIELDS,
            *REFERENCE_FIELDS,
        ),
        "network": _schema(
            "network",
            *INTERFACE_FIELDS,
            *NETWORK_FIELDS,
        ),
        "service": _schema(
            "service",
            *INTERFACE_FIELDS,
            *SERVICE_FIELDS,
            *REFERENCE_FIELDS,
        ),
        "credential_reference": _schema(
            "credential_reference",
            *CREDENTIAL_REFERENCE_FIELDS,
            rules=(_reject_credential_value_keys,),
        ),
        "runbook": _schema(
            "runbook",
            *RUNBOOK_FIELDS,
            rules=(_validate_runbook_approval,),
        ),
        "decision": _schema("decision"),
        "project": _schema("project"),
    }
)
