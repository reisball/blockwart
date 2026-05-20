from dataclasses import dataclass
from typing import Literal

PrimaryNameStorage = Literal["label", "network_hostname"]


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
    panels: tuple[UiPanel, ...]

    def as_dict(self) -> dict[str, object]:
        return {
            "kind": self.kind,
            "primary_name_label": self.primary_name_label,
            "primary_name_storage": self.primary_name_storage,
            "supports_platform": self.supports_platform,
            "panels": [panel.as_dict() for panel in self.panels],
        }


CURRENT_UI_PANELS = (
    UiPanel("overview", "Überblick", "overview"),
    UiPanel("network", "Netzwerk", "network"),
    UiPanel("access", "Zugriff", "access"),
    UiPanel("relationships", "Relationships", "relationship-add"),
    UiPanel("comment", "Kommentar", "comment"),
    UiPanel("audit", "Audit", "audit"),
)


UI_SCHEMAS: dict[str, UiTypeSchema] = {
    "host": UiTypeSchema(
        kind="host",
        primary_name_label="Hostname",
        primary_name_storage="network_hostname",
        supports_platform=False,
        panels=CURRENT_UI_PANELS,
    ),
    "system": UiTypeSchema(
        kind="system",
        primary_name_label="Hostname",
        primary_name_storage="network_hostname",
        supports_platform=True,
        panels=CURRENT_UI_PANELS,
    ),
    "netzwerk": UiTypeSchema(
        kind="netzwerk",
        primary_name_label="Name",
        primary_name_storage="label",
        supports_platform=False,
        panels=CURRENT_UI_PANELS,
    ),
    "service": UiTypeSchema(
        kind="service",
        primary_name_label="Service-Name",
        primary_name_storage="label",
        supports_platform=True,
        panels=CURRENT_UI_PANELS,
    ),
}


def get_ui_schema(kind: str) -> UiTypeSchema:
    return UI_SCHEMAS.get(kind, UI_SCHEMAS["system"])


def ui_schema_payload() -> dict[str, dict[str, object]]:
    return {kind: schema.as_dict() for kind, schema in UI_SCHEMAS.items()}
