from dataclasses import dataclass
from typing import Literal

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
    "hardware_cpu": UiField(
        "hardware_cpu",
        "CPU",
        "text",
        "data_json.hardware.cpu",
        placeholder="z.B. 8C/16T Ryzen 7",
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
    "hardware_cpu",
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
        fields=PLATFORM_SCHEMA_FIELDS + HARDWARE_SCHEMA_FIELDS,
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
    return UI_SCHEMAS.get(kind, UI_SCHEMAS["system"])


def ui_schema_payload() -> dict[str, dict[str, object]]:
    return {kind: schema.as_dict() for kind, schema in UI_SCHEMAS.items()}


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
        field = FIELD_DEFINITIONS[key]
        payload = field.as_dict()
        if key == "primary_name":
            payload["label"] = schema.primary_name_label
            payload["storage_path"] = primary_name_storage_path(schema)
        if visible_in_create is not None:
            payload["visible_in_create"] = visible_in_create
        fields.append(payload)
    return fields
