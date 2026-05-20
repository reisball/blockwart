import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from blockwart.config import get_settings

PrimaryNameStorage = Literal["label", "network_hostname"]


@dataclass(frozen=True)
class UiField:
    key: str
    label: str
    input_type: str
    storage_path: str
    required: bool = False
    placeholder: str = ""
    visible_in_create: bool = False
    visible_in_detail: bool = True

    def as_dict(self) -> dict[str, str | bool]:
        return {
            "key": self.key,
            "label": self.label,
            "input_type": self.input_type,
            "storage_path": self.storage_path,
            "required": self.required,
            "placeholder": self.placeholder,
            "visible_in_create": self.visible_in_create,
            "visible_in_detail": self.visible_in_detail,
        }


@dataclass(frozen=True)
class UiPanel:
    key: str
    label: str
    route_section: str
    always_visible: bool = True

    def as_dict(self) -> dict[str, str | bool]:
        return {
            "key": self.key,
            "label": self.label,
            "route_section": self.route_section,
            "always_visible": self.always_visible,
        }


@dataclass(frozen=True)
class UiTypeSchema:
    kind: str
    primary_name_label: str
    primary_name_storage: PrimaryNameStorage
    supports_platform: bool
    fields: tuple[str, ...]
    create_fields: tuple[str, ...]
    panels: tuple[UiPanel, ...]
    field_overrides: dict[str, UiField] = field(default_factory=dict)

    def as_dict(self) -> dict[str, object]:
        return {
            "kind": self.kind,
            "primary_name_label": self.primary_name_label,
            "primary_name_storage": self.primary_name_storage,
            "primary_name_storage_path": primary_name_storage_path(self),
            "supports_platform": self.supports_platform,
            "storage_conventions": STORAGE_CONVENTIONS,
            "fields": list(self.fields),
            "create_fields": list(self.create_fields),
            "panels": [panel.as_dict() for panel in self.panels],
        }


STORAGE_CONVENTIONS: dict[str, str] = {
    "catalog_objects.*": "Kernfelder fuer Identitaet, Status und Zusammenfassung.",
    "data_json.network.*": "Netzwerkdaten wie Hostnames, IP-Adressen und MAC-Adressen.",
    "data_json.hardware.*": "Hardware-/Ressourcen-Daten fuer Hosts und Systeme.",
    "data_json.*": "Flexible typbezogene Nutzdaten.",
    "relationships.*": "Beziehungen zwischen Objekten, nicht im Objekt selbst gespeichert.",
}

CURRENT_UI_PANELS = (
    UiPanel("overview", "Überblick", "overview"),
    UiPanel("network", "Netzwerk", "network"),
    UiPanel("access", "Zugriff", "access"),
    UiPanel("relationships", "Relationships", "relationship-add"),
    UiPanel("comment", "Kommentar", "comment"),
    UiPanel("audit", "Audit", "audit"),
)

FIELD_DEFINITIONS: dict[str, UiField] = {
    "kind": UiField(
        "kind",
        "Typ",
        "select",
        "catalog_objects.kind",
        required=True,
        visible_in_create=True,
    ),
    "object_id": UiField(
        "object_id",
        "ID",
        "text",
        "catalog_objects.object_id",
        required=True,
        placeholder="n8n",
        visible_in_create=True,
    ),
    "primary_name": UiField(
        "primary_name",
        "Primärname",
        "text",
        "kindabhängig",
        required=True,
        placeholder="n8n",
        visible_in_create=True,
    ),
    "labels": UiField(
        "labels",
        "Label",
        "text",
        "data_json.labels[]",
        placeholder="infra, docker, intern",
        visible_in_create=True,
    ),
    "platform": UiField(
        "platform",
        "Plattform",
        "select",
        "data_json.platform",
        visible_in_create=True,
    ),
    "status": UiField(
        "status",
        "Status",
        "select",
        "catalog_objects.status",
        required=True,
        visible_in_create=True,
    ),
    "relationship": UiField(
        "relationship",
        "Relationship",
        "select",
        "relationships.from_ref/to_ref",
        visible_in_create=True,
        visible_in_detail=False,
    ),
    "relation_type": UiField(
        "relation_type",
        "Relationstyp",
        "select",
        "relationships.relation_type",
        visible_in_create=True,
        visible_in_detail=False,
    ),
    "summary": UiField(
        "summary",
        "Kurzbeschreibung",
        "textarea",
        "catalog_objects.summary",
        placeholder="Wofür ist das Objekt da?",
        visible_in_create=True,
    ),
    "hardware_model": UiField(
        "hardware_model",
        "Modell",
        "text",
        "data_json.hardware.model",
        placeholder="z.B. Beelink SER5",
    ),
    "hardware_cpu_vendor": UiField(
        "hardware_cpu_vendor",
        "CPU Hersteller",
        "text",
        "data_json.hardware.cpu.vendor",
        placeholder="z.B. AMD",
    ),
    "hardware_cpu_name": UiField(
        "hardware_cpu_name",
        "CPU Name",
        "text",
        "data_json.hardware.cpu.name",
        placeholder="z.B. Ryzen 7 7840U",
    ),
    "hardware_cpu_cores": UiField(
        "hardware_cpu_cores",
        "CPU Cores",
        "number",
        "data_json.hardware.cpu.cores",
        placeholder="z.B. 8",
    ),
    "hardware_memory": UiField(
        "hardware_memory",
        "Memory",
        "text",
        "data_json.hardware.memory",
        placeholder="z.B. 32 GB",
    ),
    "hardware_gpu": UiField(
        "hardware_gpu",
        "GPU",
        "text",
        "data_json.hardware.gpu",
        placeholder="z.B. RTX 4070",
    ),
    "hardware_storage": UiField(
        "hardware_storage",
        "Storage / HDD",
        "text",
        "data_json.hardware.storage",
        placeholder="z.B. 2 TB NVMe",
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


UI_SCHEMAS: dict[str, UiTypeSchema] = {
    "host": UiTypeSchema(
        kind="host",
        primary_name_label="Hostname",
        primary_name_storage="network_hostname",
        supports_platform=False,
        fields=COMMON_SCHEMA_FIELDS + HARDWARE_SCHEMA_FIELDS,
        create_fields=COMMON_CREATE_FIELDS,
        panels=CURRENT_UI_PANELS,
    ),
    "system": UiTypeSchema(
        kind="system",
        primary_name_label="Hostname",
        primary_name_storage="network_hostname",
        supports_platform=True,
        fields=PLATFORM_SCHEMA_FIELDS + SYSTEM_HARDWARE_SCHEMA_FIELDS,
        create_fields=PLATFORM_CREATE_FIELDS,
        panels=CURRENT_UI_PANELS,
    ),
    "netzwerk": UiTypeSchema(
        kind="netzwerk",
        primary_name_label="Name",
        primary_name_storage="label",
        supports_platform=False,
        fields=COMMON_SCHEMA_FIELDS,
        create_fields=COMMON_CREATE_FIELDS,
        panels=CURRENT_UI_PANELS,
    ),
    "service": UiTypeSchema(
        kind="service",
        primary_name_label="Service-Name",
        primary_name_storage="label",
        supports_platform=True,
        fields=PLATFORM_SCHEMA_FIELDS,
        create_fields=PLATFORM_CREATE_FIELDS,
        panels=CURRENT_UI_PANELS,
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


def create_field_payload(schema: UiTypeSchema) -> list[dict[str, str | bool]]:
    return _field_payload(schema, schema.create_fields, visible_in_create=True)


def schema_field_payload(schema: UiTypeSchema) -> list[dict[str, str | bool]]:
    return _field_payload(schema, schema.fields)


def _field_payload(
    schema: UiTypeSchema,
    field_keys: tuple[str, ...],
    *,
    visible_in_create: bool | None = None,
) -> list[dict[str, str | bool]]:
    fields: list[dict[str, str | bool]] = []
    for key in field_keys:
        field = schema.field_overrides.get(key, FIELD_DEFINITIONS[key])
        payload = field.as_dict()
        if key == "primary_name":
            payload["label"] = schema.primary_name_label
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
    fields: dict[str, dict[str, str | bool]],
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
                label=_clean_text(raw_field.get("label"), base_field.label),
                input_type=base_field.input_type,
                storage_path=base_field.storage_path,
                required=_clean_bool(raw_field.get("required"), base_field.required),
                placeholder=_clean_placeholder(
                    raw_field.get("placeholder"),
                    base_field.placeholder,
                ),
                visible_in_create=base_field.visible_in_create,
                visible_in_detail=_clean_bool(
                    raw_field.get("visible_in_detail"),
                    base_field.visible_in_detail,
                ),
            )
    primary_name_label = schema.primary_name_label
    if "primary_name" in field_overrides:
        primary_name_label = field_overrides["primary_name"].label
    return UiTypeSchema(
        kind=schema.kind,
        primary_name_label=primary_name_label,
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
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    kinds = payload.get("kinds") if isinstance(payload, dict) else None
    return kinds if isinstance(kinds, dict) else {}


def _write_schema_overrides(overrides: dict[str, Any]) -> None:
    path = _schema_overrides_path()
    if path is None:
        raise ValueError("schema overrides path is not configured")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps({"version": 1, "kinds": overrides}, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _validate_field_order(schema: UiTypeSchema, field_order: list[str]) -> None:
    if set(field_order) != set(schema.fields) or len(field_order) != len(schema.fields):
        raise ValueError("field order must contain exactly the schema fields")


def _validate_field_settings(
    schema: UiTypeSchema,
    fields: dict[str, dict[str, str | bool]],
) -> None:
    if set(fields) != set(schema.fields):
        raise ValueError("field settings must contain exactly the schema fields")
    for key, field_settings in fields.items():
        if not isinstance(field_settings.get("label"), str):
            raise ValueError(f"{key}.label must be text")
        if not isinstance(field_settings.get("placeholder"), str):
            raise ValueError(f"{key}.placeholder must be text")
        for bool_key in ("required", "visible_in_detail"):
            if not isinstance(field_settings.get(bool_key), bool):
                raise ValueError(f"{key}.{bool_key} must be boolean")


def _clean_text(value: object, fallback: str) -> str:
    if not isinstance(value, str):
        return fallback
    clean = value.strip()
    return clean or fallback


def _clean_placeholder(value: object, fallback: str) -> str:
    if not isinstance(value, str):
        return fallback
    return value.strip()


def _clean_bool(value: object, fallback: bool) -> bool:
    return value if isinstance(value, bool) else fallback
