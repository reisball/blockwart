import json
from pathlib import Path
from typing import get_args

import pytest

from blockwart.domain import asset_state
from blockwart.domain.object_schema import (
    BUILTIN_SCHEMAS,
    DEVICE_CATEGORIES,
    NETWORK_CATEGORIES,
)
from blockwart.domain.references import VALID_REFERENCE_KINDS
from blockwart.domain.relationships import ASSET_KINDS as RELATIONSHIP_ASSET_KINDS
from blockwart.domain.ui_schema import UI_SCHEMAS
from blockwart.mcp.server import OBJECT_WRITE_SCHEMA, QUERY_FILTER_PROPERTIES
from blockwart.schemas.catalog import (
    OBJECT_STATUSES,
    PUBLIC_OBJECT_KINDS,
    ObjectKind,
    PublicObjectKind,
)

PUBLIC_ASSET_KINDS = {"host", "system", "network", "device", "service"}
NON_PUBLIC_KINDS = {"credential_reference", "runbook", "decision", "project"}
LOCALES = Path(__file__).resolve().parents[1] / "src" / "blockwart" / "ui" / "locales"


def _assert_exact_registry(name: str, actual: set[str]) -> None:
    missing = PUBLIC_ASSET_KINDS - actual
    additional = actual - PUBLIC_ASSET_KINDS
    assert not missing and not additional, (
        f"{name} kind drift: missing={sorted(missing)} additional={sorted(additional)}"
    )


def test_public_asset_kind_registries_are_exactly_equal() -> None:
    object_kinds = set(get_args(ObjectKind))
    registries = {
        "typed references": set(VALID_REFERENCE_KINDS) - NON_PUBLIC_KINDS,
        "asset state": set(asset_state.ASSET_KINDS),
        "relationships": set(RELATIONSHIP_ASSET_KINDS),
        "ObjectKind": object_kinds - NON_PUBLIC_KINDS,
        "PublicObjectKind": set(get_args(PublicObjectKind)),
        "PUBLIC_OBJECT_KINDS": set(PUBLIC_OBJECT_KINDS),
        "built-in schemas": set(BUILTIN_SCHEMAS) - NON_PUBLIC_KINDS,
        "MCP object writes": set(OBJECT_WRITE_SCHEMA["properties"]["kind"]["enum"])
        - NON_PUBLIC_KINDS,
    }
    for name, registry in registries.items():
        _assert_exact_registry(name, registry)
    assert set(UI_SCHEMAS) == PUBLIC_ASSET_KINDS | {"decision", "project", "runbook"}

    assert set(VALID_REFERENCE_KINDS) == object_kinds == set(BUILTIN_SCHEMAS)
    assert OBJECT_STATUSES == ("active", "inactive", "deleted")

    # MCP read filters (`blockwart.search` / `blockwart.get_context`) cover every
    # canonical ObjectKind, not just the public asset subset: knowledge kinds are
    # readable through MCP subject to the same authorization as REST v1.
    assert set(OBJECT_WRITE_SCHEMA["properties"]["kind"]["enum"]) == object_kinds
    assert set(QUERY_FILTER_PROPERTIES["kind"]["enum"]) == object_kinds


def test_parity_guard_reports_missing_and_additional_kinds() -> None:
    with pytest.raises(AssertionError, match=r"missing=\['device'\].*additional=\['appliance'\]"):
        _assert_exact_registry(
            "synthetic drift",
            (PUBLIC_ASSET_KINDS - {"device"}) | {"appliance"},
        )


def test_device_schema_ui_mcp_and_locales_are_registered() -> None:
    device_fields = {field.path: field for field in BUILTIN_SCHEMAS["device"].fields}
    assert device_fields["device.category"].required is True
    assert device_fields["device.category"].enum_values == DEVICE_CATEGORIES
    for path in ("device.manufacturer", "device.model"):
        assert device_fields[path].strip_whitespace is True
        assert device_fields[path].min_length == 1
        assert device_fields[path].max_length == 128

    ui_schema = UI_SCHEMAS["device"]
    assert ui_schema.kind == "device"
    assert {"device_category", "device_manufacturer", "device_model"} <= set(ui_schema.fields)
    assert "device_category" in ui_schema.create_fields
    assert "device" in OBJECT_WRITE_SCHEMA["properties"]["kind"]["enum"]
    assert "device" in QUERY_FILTER_PROPERTIES["kind"]["enum"]

    assert json.loads((LOCALES / "en.json").read_text(encoding="utf-8"))["kind.device"] == (
        "Device"
    )
    assert json.loads((LOCALES / "de.json").read_text(encoding="utf-8"))["kind.device"] == (
        "Gerät"
    )


def test_network_equipment_schema_is_closed_and_bounded() -> None:
    network_fields = {field.path: field for field in BUILTIN_SCHEMAS["network"].fields}
    assert network_fields["network.category"].required is True
    assert network_fields["network.category"].enum_values == NETWORK_CATEGORIES
    for path in ("network.manufacturer", "network.model"):
        assert network_fields[path].strip_whitespace is True
        assert network_fields[path].min_length == 1
        assert network_fields[path].max_length == 128
    assert network_fields["network.location"].max_length == 255
