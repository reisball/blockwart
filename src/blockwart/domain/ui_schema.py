import json
import os
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from blockwart.config import get_settings

PrimaryNameStorage = Literal["label", "network_hostname"]


class SchemaOverridesError(ValueError):
    """The configured schema override document is unreadable or invalid."""


@dataclass(frozen=True)
class SchemaOverridesMigrationPlan:
    configured: bool
    exists: bool
    source_version: int | None
    target_version: int
    changed: bool
    kinds: tuple[str, ...]


@dataclass(frozen=True)
class UiField:
    key: str
    label_key: str
    input_type: str
    storage_path: str
    required: bool = False
    placeholder_key: str = ""
    visible_in_create: bool = False
    visible_in_detail: bool = True
    localized_labels: dict[str, str] = field(default_factory=dict)
    localized_placeholders: dict[str, str] = field(default_factory=dict)

    def as_dict(self) -> dict[str, object]:
        return {
            "key": self.key,
            "label_key": self.label_key,
            "input_type": self.input_type,
            "storage_path": self.storage_path,
            "required": self.required,
            "placeholder_key": self.placeholder_key,
            "visible_in_create": self.visible_in_create,
            "visible_in_detail": self.visible_in_detail,
            "localized_labels": self.localized_labels,
            "localized_placeholders": self.localized_placeholders,
        }


@dataclass(frozen=True)
class UiPanel:
    key: str
    label_key: str
    route_section: str
    always_visible: bool = True

    def as_dict(self) -> dict[str, str | bool]:
        return {
            "key": self.key,
            "label_key": self.label_key,
            "route_section": self.route_section,
            "always_visible": self.always_visible,
        }


@dataclass(frozen=True)
class UiTypeSchema:
    kind: str
    primary_name_label_key: str
    primary_name_storage: PrimaryNameStorage
    supports_platform: bool
    fields: tuple[str, ...]
    create_fields: tuple[str, ...]
    panels: tuple[UiPanel, ...]
    field_overrides: dict[str, UiField] = field(default_factory=dict)

    def as_dict(self) -> dict[str, object]:
        return {
            "kind": self.kind,
            "primary_name_label_key": self.primary_name_label_key,
            "primary_name_storage": self.primary_name_storage,
            "primary_name_storage_path": primary_name_storage_path(self),
            "supports_platform": self.supports_platform,
            "storage_conventions": STORAGE_CONVENTIONS,
            "fields": list(self.fields),
            "create_fields": list(self.create_fields),
            "panels": [panel.as_dict() for panel in self.panels],
        }


STORAGE_CONVENTIONS: dict[str, str] = {
    "catalog_objects.*": "Core identity, state, and summary fields.",
    "data_json.network.*": "Network hostnames, addresses, and interface data.",
    "data_json.hardware.*": "Hardware and resource data for hosts and systems.",
    "data_json.*": "Flexible kind-specific data.",
    "relationships.*": "Relationships stored independently from catalog objects.",
}

BASE_UI_PANELS = (
    UiPanel("overview", "panel.overview", "overview"),
    UiPanel("network", "panel.network", "network"),
    UiPanel("access", "panel.access", "access"),
    UiPanel("relationships", "panel.relationships", "relationship-add"),
    UiPanel("comment", "panel.comment", "comment"),
    UiPanel("audit", "panel.audit", "audit"),
)

SERVICE_UI_PANELS = (
    UiPanel("overview", "panel.overview", "overview"),
    UiPanel("service_information", "panel.service_information", "service-information"),
    UiPanel("network", "panel.network", "network"),
    UiPanel("access", "panel.access", "access"),
    UiPanel("relationships", "panel.relationships", "relationship-add"),
    UiPanel("comment", "panel.comment", "comment"),
    UiPanel("audit", "panel.audit", "audit"),
)

FIELD_DEFINITIONS: dict[str, UiField] = {
    "kind": UiField(
        "kind",
        "field.kind.label",
        "select",
        "catalog_objects.kind",
        required=True,
        visible_in_create=True,
    ),
    "object_id": UiField(
        "object_id",
        "field.object_id.label",
        "text",
        "catalog_objects.object_id",
        required=True,
        placeholder_key="field.object_id.placeholder",
        visible_in_create=True,
    ),
    "primary_name": UiField(
        "primary_name",
        "field.primary_name.label",
        "text",
        "kind-dependent",
        required=True,
        placeholder_key="field.primary_name.placeholder",
        visible_in_create=True,
    ),
    "labels": UiField(
        "labels",
        "field.labels.label",
        "text",
        "data_json.labels[]",
        placeholder_key="field.labels.placeholder",
        visible_in_create=True,
    ),
    "platform": UiField(
        "platform",
        "field.platform.label",
        "select",
        "data_json.platform",
        visible_in_create=True,
    ),
    "status": UiField(
        "status",
        "field.status.label",
        "select",
        "catalog_objects.status",
        required=True,
        visible_in_create=True,
    ),
    "relationship": UiField(
        "relationship",
        "field.relationship.label",
        "select",
        "relationships.from_ref/to_ref",
        visible_in_create=True,
        visible_in_detail=False,
    ),
    "relation_type": UiField(
        "relation_type",
        "field.relation_type.label",
        "select",
        "relationships.relation_type",
        visible_in_create=True,
        visible_in_detail=False,
    ),
    "summary": UiField(
        "summary",
        "field.summary.label",
        "textarea",
        "catalog_objects.summary",
        placeholder_key="field.summary.placeholder",
        visible_in_create=True,
    ),
    "hardware_model": UiField(
        "hardware_model",
        "field.hardware_model.label",
        "text",
        "data_json.hardware.model",
        placeholder_key="field.hardware_model.placeholder",
    ),
    "hardware_cpu_vendor": UiField(
        "hardware_cpu_vendor",
        "field.hardware_cpu_vendor.label",
        "text",
        "data_json.hardware.cpu.vendor",
        placeholder_key="field.hardware_cpu_vendor.placeholder",
    ),
    "hardware_cpu_name": UiField(
        "hardware_cpu_name",
        "field.hardware_cpu_name.label",
        "text",
        "data_json.hardware.cpu.name",
        placeholder_key="field.hardware_cpu_name.placeholder",
    ),
    "hardware_cpu_cores": UiField(
        "hardware_cpu_cores",
        "field.hardware_cpu_cores.label",
        "number",
        "data_json.hardware.cpu.cores",
        placeholder_key="field.hardware_cpu_cores.placeholder",
    ),
    "hardware_memory": UiField(
        "hardware_memory",
        "field.hardware_memory.label",
        "text",
        "data_json.hardware.memory",
        placeholder_key="field.hardware_memory.placeholder",
    ),
    "hardware_gpu": UiField(
        "hardware_gpu",
        "field.hardware_gpu.label",
        "text",
        "data_json.hardware.gpu",
        placeholder_key="field.hardware_gpu.placeholder",
    ),
    "hardware_storage": UiField(
        "hardware_storage",
        "field.hardware_storage.label",
        "text",
        "data_json.hardware.storage",
        placeholder_key="field.hardware_storage.placeholder",
    ),
    "device_category": UiField(
        "device_category",
        "field.device_category.label",
        "select",
        "data_json.device.category",
        required=True,
        visible_in_create=True,
    ),
    "device_manufacturer": UiField(
        "device_manufacturer",
        "field.device_manufacturer.label",
        "text",
        "data_json.device.manufacturer",
        placeholder_key="field.device_manufacturer.placeholder",
        visible_in_create=True,
    ),
    "device_model": UiField(
        "device_model",
        "field.device_model.label",
        "text",
        "data_json.device.model",
        placeholder_key="field.device_model.placeholder",
        visible_in_create=True,
    ),
    "endpoint_type": UiField(
        "endpoint_type",
        "field.endpoint_type.label",
        "select",
        "data_json.endpoints[].type",
        placeholder_key="field.endpoint_type.placeholder",
    ),
    "endpoint_url": UiField(
        "endpoint_url",
        "field.endpoint_url.label",
        "url",
        "data_json.endpoints[].url",
        placeholder_key="field.endpoint_url.placeholder",
    ),
    "endpoint_port": UiField(
        "endpoint_port",
        "field.endpoint_port.label",
        "number",
        "data_json.endpoints[].port",
        placeholder_key="field.endpoint_port.placeholder",
    ),
    "service_sources": UiField(
        "service_sources",
        "field.service_sources.label",
        "textarea",
        "data_json.service_information.sources[]",
        placeholder_key="field.service_sources.placeholder",
    ),
    "service_running_version": UiField(
        "service_running_version",
        "field.service_running_version.label",
        "text",
        "data_json.service_information.running_version",
        placeholder_key="field.service_running_version.placeholder",
    ),
}

COMMON_CREATE_FIELDS = (
    "kind",
    "object_id",
    "primary_name",
    "labels",
    "status",
    "relationship",
    "relation_type",
    "summary",
)

PLATFORM_CREATE_FIELDS = (
    "kind",
    "object_id",
    "primary_name",
    "labels",
    "platform",
    "status",
    "relationship",
    "relation_type",
    "summary",
)

COMMON_SCHEMA_FIELDS = COMMON_CREATE_FIELDS
PLATFORM_SCHEMA_FIELDS = PLATFORM_CREATE_FIELDS
HARDWARE_SCHEMA_FIELDS = (
    "hardware_model",
    "hardware_cpu_vendor",
    "hardware_cpu_name",
    "hardware_cpu_cores",
    "hardware_memory",
    "hardware_gpu",
    "hardware_storage",
)
SYSTEM_HARDWARE_SCHEMA_FIELDS = (
    "hardware_cpu_cores",
    "hardware_memory",
    "hardware_gpu",
    "hardware_storage",
)
ENDPOINT_SCHEMA_FIELDS = (
    "endpoint_type",
    "endpoint_url",
    "endpoint_port",
)

SERVICE_INFORMATION_SCHEMA_FIELDS = (
    "service_sources",
    "service_running_version",
)

DEVICE_SCHEMA_FIELDS = (
    "device_category",
    "device_manufacturer",
    "device_model",
)
DEVICE_CREATE_FIELDS = COMMON_CREATE_FIELDS + DEVICE_SCHEMA_FIELDS


UI_SCHEMAS: dict[str, UiTypeSchema] = {
    "host": UiTypeSchema(
        kind="host",
        primary_name_label_key="field.primary_name.host.label",
        primary_name_storage="network_hostname",
        supports_platform=False,
        fields=COMMON_SCHEMA_FIELDS + HARDWARE_SCHEMA_FIELDS + ENDPOINT_SCHEMA_FIELDS,
        create_fields=COMMON_CREATE_FIELDS,
        panels=BASE_UI_PANELS,
    ),
    "system": UiTypeSchema(
        kind="system",
        primary_name_label_key="field.primary_name.system.label",
        primary_name_storage="network_hostname",
        supports_platform=True,
        fields=PLATFORM_SCHEMA_FIELDS + SYSTEM_HARDWARE_SCHEMA_FIELDS + ENDPOINT_SCHEMA_FIELDS,
        create_fields=PLATFORM_CREATE_FIELDS,
        panels=BASE_UI_PANELS,
    ),
    "network": UiTypeSchema(
        kind="network",
        primary_name_label_key="field.primary_name.network.label",
        primary_name_storage="label",
        supports_platform=False,
        fields=COMMON_SCHEMA_FIELDS + ENDPOINT_SCHEMA_FIELDS,
        create_fields=COMMON_CREATE_FIELDS,
        panels=BASE_UI_PANELS,
    ),
    "device": UiTypeSchema(
        kind="device",
        primary_name_label_key="field.primary_name.device.label",
        primary_name_storage="label",
        supports_platform=False,
        fields=COMMON_SCHEMA_FIELDS + DEVICE_SCHEMA_FIELDS + ENDPOINT_SCHEMA_FIELDS,
        create_fields=DEVICE_CREATE_FIELDS,
        panels=BASE_UI_PANELS,
    ),
    "service": UiTypeSchema(
        kind="service",
        primary_name_label_key="field.primary_name.service.label",
        primary_name_storage="label",
        supports_platform=False,
        fields=COMMON_SCHEMA_FIELDS + SERVICE_INFORMATION_SCHEMA_FIELDS + ENDPOINT_SCHEMA_FIELDS,
        create_fields=COMMON_CREATE_FIELDS,
        panels=SERVICE_UI_PANELS,
    ),
}


def get_ui_schema(kind: str) -> UiTypeSchema:
    schema = UI_SCHEMAS.get(kind, UI_SCHEMAS["system"])
    return _apply_schema_overrides(schema, _load_schema_overrides().get(schema.kind, {}))


def ui_schema_payload() -> dict[str, dict[str, object]]:
    payload: dict[str, dict[str, object]] = {}
    for kind in UI_SCHEMAS:
        schema = get_ui_schema(kind)
        schema_payload = schema.as_dict()
        schema_payload["schema_fields"] = schema_field_payload(schema)
        schema_payload["create_field_definitions"] = create_field_payload(schema)
        payload[kind] = schema_payload
    return payload


def primary_name_storage_path(schema: UiTypeSchema) -> str:
    if schema.primary_name_storage == "network_hostname":
        return "data_json.network.hostnames[0]"
    return "catalog_objects.label"


def create_field_payload(schema: UiTypeSchema) -> list[dict[str, object]]:
    return _field_payload(schema, schema.create_fields, visible_in_create=True)


def schema_field_payload(schema: UiTypeSchema) -> list[dict[str, object]]:
    return _field_payload(schema, schema.fields)


def _field_payload(
    schema: UiTypeSchema,
    field_keys: tuple[str, ...],
    *,
    visible_in_create: bool | None = None,
) -> list[dict[str, object]]:
    fields: list[dict[str, object]] = []
    for key in field_keys:
        field = schema.field_overrides.get(key, FIELD_DEFINITIONS[key])
        payload = field.as_dict()
        if key == "primary_name":
            payload["label_key"] = schema.primary_name_label_key
            payload["storage_path"] = primary_name_storage_path(schema)
        if visible_in_create is not None:
            payload["visible_in_create"] = visible_in_create
        fields.append(payload)
    return fields


def load_editable_schema_settings(kind: str) -> dict[str, Any]:
    schema = get_ui_schema(kind)
    return {
        "kind": schema.kind,
        "field_order": list(schema.fields),
        "fields": schema_field_payload(schema),
    }


def save_editable_schema_settings(
    kind: str,
    *,
    field_order: list[str],
    fields: dict[str, dict[str, object]],
) -> None:
    base_schema = UI_SCHEMAS.get(kind)
    if base_schema is None:
        raise ValueError(f"unknown schema kind: {kind}")
    _validate_field_order(base_schema, field_order)
    _validate_field_settings(base_schema, fields)
    overrides = _load_schema_overrides()
    overrides[kind] = {
        "field_order": field_order,
        "fields": fields,
    }
    _write_schema_overrides(overrides)


def build_schema_overrides_migration_plan() -> SchemaOverridesMigrationPlan:
    path = _schema_overrides_path()
    if path is None:
        return SchemaOverridesMigrationPlan(
            configured=False,
            exists=False,
            source_version=None,
            target_version=2,
            changed=False,
            kinds=(),
        )
    if not path.exists():
        return SchemaOverridesMigrationPlan(
            configured=True,
            exists=False,
            source_version=None,
            target_version=2,
            changed=False,
            kinds=(),
        )
    document = _read_schema_overrides_document(path)
    overrides = _parse_schema_overrides_document(document)
    payload = json.loads(document)
    source_version = int(payload["version"])
    return SchemaOverridesMigrationPlan(
        configured=True,
        exists=True,
        source_version=source_version,
        target_version=2,
        changed=source_version == 1,
        kinds=tuple(sorted(overrides)),
    )


def apply_schema_overrides_migration() -> Path | None:
    path = _schema_overrides_path()
    if path is None or not path.exists():
        return None
    document = _read_schema_overrides_document(path)
    overrides = _parse_schema_overrides_document(document)
    payload = json.loads(document)
    if payload["version"] == 2:
        return None
    backup_path = Path(f"{path}.v1.bak")
    try:
        file_descriptor = os.open(
            backup_path,
            os.O_CREAT | os.O_EXCL | os.O_WRONLY,
            0o600,
        )
    except FileExistsError as exc:
        raise SchemaOverridesError(
            "schema override migration backup already exists"
        ) from exc
    try:
        with os.fdopen(file_descriptor, "wb") as backup:
            backup.write(document.encode("utf-8"))
            backup.flush()
            os.fsync(backup.fileno())
        _write_schema_overrides(overrides)
    except Exception:
        # The backup intentionally remains available if replacing the active
        # document fails after it has been created.
        raise
    return backup_path


def _apply_schema_overrides(schema: UiTypeSchema, raw_override: object) -> UiTypeSchema:
    if not isinstance(raw_override, dict):
        return schema
    field_order = raw_override.get("field_order")
    fields_override = raw_override.get("fields")
    fields = schema.fields
    create_fields = schema.create_fields
    if isinstance(field_order, list):
        candidate_order = [str(key) for key in field_order]
        if (
            set(candidate_order) == set(schema.fields)
            and len(candidate_order) == len(schema.fields)
        ):
            fields = tuple(candidate_order)
            create_fields = tuple(key for key in fields if key in schema.create_fields)
    field_overrides: dict[str, UiField] = {}
    if isinstance(fields_override, dict):
        for key in schema.fields:
            base_field = FIELD_DEFINITIONS[key]
            raw_field = fields_override.get(key)
            if not isinstance(raw_field, dict):
                continue
            field_overrides[key] = UiField(
                key=base_field.key,
                label_key=base_field.label_key,
                input_type=base_field.input_type,
                storage_path=base_field.storage_path,
                required=_clean_bool(raw_field.get("required"), base_field.required),
                placeholder_key=base_field.placeholder_key,
                visible_in_create=base_field.visible_in_create,
                visible_in_detail=_clean_bool(
                    raw_field.get("visible_in_detail"),
                    base_field.visible_in_detail,
                ),
                localized_labels=_clean_localized_texts(raw_field.get("labels")),
                localized_placeholders=_clean_localized_texts(
                    raw_field.get("placeholders"),
                    allow_empty=True,
                ),
            )
    return UiTypeSchema(
        kind=schema.kind,
        primary_name_label_key=schema.primary_name_label_key,
        primary_name_storage=schema.primary_name_storage,
        supports_platform=schema.supports_platform,
        fields=fields,
        create_fields=create_fields,
        panels=schema.panels,
        field_overrides=field_overrides,
    )


def _schema_overrides_path() -> Path | None:
    configured = get_settings().schema_overrides_path.strip()
    if not configured:
        return None
    return Path(configured)


def _load_schema_overrides() -> dict[str, Any]:
    path = _schema_overrides_path()
    if path is None or not path.exists():
        return {}
    return _parse_schema_overrides_document(_read_schema_overrides_document(path))


def _read_schema_overrides_document(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except OSError as exc:
        raise SchemaOverridesError("schema override file could not be read") from exc


def _write_schema_overrides(overrides: dict[str, Any]) -> None:
    path = _schema_overrides_path()
    if path is None:
        raise ValueError("schema overrides path is not configured")
    path.parent.mkdir(parents=True, exist_ok=True)
    document = json.dumps(
        {"version": 2, "kinds": overrides},
        indent=2,
        sort_keys=True,
    ) + "\n"
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as temporary_file:
            temporary_path = Path(temporary_file.name)
            temporary_file.write(document)
            temporary_file.flush()
            os.fsync(temporary_file.fileno())
        persisted = _parse_schema_overrides_document(
            temporary_path.read_text(encoding="utf-8")
        )
        if persisted != overrides:
            raise SchemaOverridesError("schema override serialization changed its meaning")
        os.replace(temporary_path, path)
        temporary_path = None
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


def _parse_schema_overrides_document(document: str) -> dict[str, Any]:
    try:
        payload = json.loads(document)
    except json.JSONDecodeError as exc:
        raise SchemaOverridesError("schema override file contains invalid JSON") from exc
    if not isinstance(payload, dict):
        raise SchemaOverridesError("schema override document must be an object")
    if set(payload) != {"version", "kinds"}:
        raise SchemaOverridesError(
            "schema override document must contain exactly version and kinds"
        )
    if payload["version"] == 1:
        return _upgrade_v1_schema_overrides(payload["kinds"])
    if payload["version"] != 2:
        raise SchemaOverridesError("schema override file uses an unsupported version")
    kinds = payload["kinds"]
    if not isinstance(kinds, dict):
        raise SchemaOverridesError("schema override kinds must be an object")
    for kind, raw_override in kinds.items():
        schema = UI_SCHEMAS.get(kind)
        if schema is None:
            raise SchemaOverridesError(f"unknown schema kind: {kind}")
        if not isinstance(raw_override, dict) or set(raw_override) != {
            "field_order",
            "fields",
        }:
            raise SchemaOverridesError(
                f"schema override for {kind} must contain field_order and fields"
            )
        field_order = raw_override["field_order"]
        fields = raw_override["fields"]
        if not isinstance(field_order, list) or not all(
            isinstance(key, str) for key in field_order
        ):
            raise SchemaOverridesError(f"schema override for {kind} has invalid field_order")
        if not isinstance(fields, dict) or not all(
            isinstance(key, str) and isinstance(settings, dict)
            for key, settings in fields.items()
        ):
            raise SchemaOverridesError(f"schema override for {kind} has invalid fields")
        try:
            _validate_field_order(schema, field_order)
            _validate_field_settings(schema, fields)
        except ValueError as exc:
            raise SchemaOverridesError(f"schema override for {kind} is invalid: {exc}") from exc
    return kinds


def _upgrade_v1_schema_overrides(raw_kinds: object) -> dict[str, Any]:
    if not isinstance(raw_kinds, dict):
        raise SchemaOverridesError("schema override kinds must be an object")
    upgraded: dict[str, Any] = {}
    for legacy_kind, raw_override in raw_kinds.items():
        kind = "network" if legacy_kind == "netzwerk" else legacy_kind
        if kind in upgraded:
            raise SchemaOverridesError(
                f"schema override migration has a kind collision for {kind}"
            )
        schema = UI_SCHEMAS.get(kind)
        if schema is None:
            raise SchemaOverridesError(f"unknown schema kind: {legacy_kind}")
        if not isinstance(raw_override, dict) or set(raw_override) != {
            "field_order",
            "fields",
        }:
            raise SchemaOverridesError(
                f"schema override for {legacy_kind} must contain field_order and fields"
            )
        field_order = raw_override["field_order"]
        raw_fields = raw_override["fields"]
        if not isinstance(field_order, list) or not all(
            isinstance(key, str) for key in field_order
        ):
            raise SchemaOverridesError(
                f"schema override for {legacy_kind} has invalid field_order"
            )
        if not isinstance(raw_fields, dict):
            raise SchemaOverridesError(
                f"schema override for {legacy_kind} has invalid fields"
            )
        fields: dict[str, dict[str, object]] = {}
        for key, raw_settings in raw_fields.items():
            if not isinstance(key, str) or not isinstance(raw_settings, dict):
                raise SchemaOverridesError(
                    f"schema override for {legacy_kind} has invalid fields"
                )
            label = raw_settings.get("label")
            placeholder = raw_settings.get("placeholder")
            required = raw_settings.get("required")
            visible = raw_settings.get("visible_in_detail")
            if (
                not isinstance(label, str)
                or not isinstance(placeholder, str)
                or not isinstance(required, bool)
                or not isinstance(visible, bool)
            ):
                raise SchemaOverridesError(
                    f"schema override for {legacy_kind}.{key} is invalid"
                )
            # Version 1 did not record the language of configured display
            # strings. Preserve the exact value for both locales instead of
            # guessing and silently changing the administrator's text.
            fields[key] = {
                "labels": {"en": label, "de": label},
                "placeholders": {"en": placeholder, "de": placeholder},
                "required": required,
                "visible_in_detail": visible,
            }
        try:
            _validate_field_order(schema, field_order)
            _validate_field_settings(schema, fields)
        except ValueError as exc:
            raise SchemaOverridesError(
                f"schema override for {legacy_kind} is invalid: {exc}"
            ) from exc
        upgraded[kind] = {
            "field_order": field_order,
            "fields": fields,
        }
    return upgraded


def _validate_field_order(schema: UiTypeSchema, field_order: list[str]) -> None:
    if set(field_order) != set(schema.fields) or len(field_order) != len(schema.fields):
        raise ValueError("field order must contain exactly the schema fields")


def _validate_field_settings(
    schema: UiTypeSchema,
    fields: dict[str, dict[str, object]],
) -> None:
    if set(fields) != set(schema.fields):
        raise ValueError("field settings must contain exactly the schema fields")
    for key, field_settings in fields.items():
        if set(field_settings) != {
            "labels",
            "placeholders",
            "required",
            "visible_in_detail",
        }:
            raise ValueError(
                f"{key} settings must contain labels, placeholders, "
                "required, and visible_in_detail"
            )
        _validate_localized_texts(field_settings.get("labels"), f"{key}.labels")
        _validate_localized_texts(
            field_settings.get("placeholders"),
            f"{key}.placeholders",
            allow_empty=True,
        )
        for bool_key in ("required", "visible_in_detail"):
            if not isinstance(field_settings.get(bool_key), bool):
                raise ValueError(f"{key}.{bool_key} must be boolean")


def _validate_localized_texts(
    value: object,
    location: str,
    *,
    allow_empty: bool = False,
) -> None:
    if not isinstance(value, dict):
        raise ValueError(f"{location} must be an object")
    for locale, text in value.items():
        if locale not in {"en", "de"} or not isinstance(text, str):
            raise ValueError(f"{location} contains an invalid locale value")
        if not allow_empty and not text.strip():
            raise ValueError(f"{location}.{locale} must not be empty")


def _clean_localized_texts(
    value: object,
    *,
    allow_empty: bool = False,
) -> dict[str, str]:
    if not isinstance(value, dict):
        return {}
    cleaned: dict[str, str] = {}
    for locale, text in value.items():
        if locale not in {"en", "de"} or not isinstance(text, str):
            continue
        normalized = text.strip()
        if normalized or allow_empty:
            cleaned[locale] = normalized
    return cleaned


def _clean_bool(value: object, fallback: bool) -> bool:
    return value if isinstance(value, bool) else fallback
