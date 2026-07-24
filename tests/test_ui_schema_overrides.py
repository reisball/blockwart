from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from blockwart.domain import ui_schema
from blockwart.domain.ui_schema import (
    UI_SCHEMAS,
    load_editable_schema_settings,
    save_editable_schema_settings,
)


def _editable_settings(kind: str) -> tuple[list[str], dict[str, dict[str, str | bool]]]:
    settings = load_editable_schema_settings(kind)
    fields = {
        str(field["key"]): {
            "label": str(field["label"]),
            "placeholder": str(field["placeholder"]),
            "required": bool(field["required"]),
            "visible_in_detail": bool(field["visible_in_detail"]),
        }
        for field in settings["fields"]
    }
    return list(settings["field_order"]), fields


def _temporary_files(path: Path) -> list[Path]:
    return list(path.parent.glob(f".{path.name}.*.tmp"))


def test_schema_override_write_round_trips_semantically(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    override_path = tmp_path / "ui_schema_overrides.json"
    monkeypatch.setenv("BLOCKWART_SCHEMA_OVERRIDES_PATH", str(override_path))
    field_order, fields = _editable_settings("system")
    fields["hardware_storage"]["label"] = "Persisted Disk"

    save_editable_schema_settings("system", field_order=field_order, fields=fields)

    payload = json.loads(override_path.read_text(encoding="utf-8"))
    reloaded = load_editable_schema_settings("system")
    labels = {str(field["key"]): str(field["label"]) for field in reloaded["fields"]}
    assert payload == {
        "version": 1,
        "kinds": {
            "system": {
                "field_order": field_order,
                "fields": fields,
            }
        },
    }
    assert labels["hardware_storage"] == "Persisted Disk"
    assert _temporary_files(override_path) == []


def test_schema_override_replace_failure_preserves_previous_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    override_path = tmp_path / "ui_schema_overrides.json"
    monkeypatch.setenv("BLOCKWART_SCHEMA_OVERRIDES_PATH", str(override_path))
    field_order, fields = _editable_settings("system")
    fields["hardware_storage"]["label"] = "Old Disk"
    save_editable_schema_settings("system", field_order=field_order, fields=fields)
    previous = override_path.read_bytes()
    fields["hardware_storage"]["label"] = "New Disk"

    def fail_replace(source: str | Path, target: str | Path) -> None:
        raise OSError("injected replace failure")

    monkeypatch.setattr(os, "replace", fail_replace)

    with pytest.raises(OSError, match="injected replace failure"):
        save_editable_schema_settings("system", field_order=field_order, fields=fields)

    assert override_path.read_bytes() == previous
    assert _temporary_files(override_path) == []


def test_schema_override_serialization_is_validated_before_replace(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    override_path = tmp_path / "ui_schema_overrides.json"
    monkeypatch.setenv("BLOCKWART_SCHEMA_OVERRIDES_PATH", str(override_path))
    field_order, fields = _editable_settings("system")
    save_editable_schema_settings("system", field_order=field_order, fields=fields)
    previous = override_path.read_bytes()
    monkeypatch.setattr(ui_schema.json, "dumps", lambda *args, **kwargs: '{"version":1')

    with pytest.raises(ValueError, match="invalid JSON"):
        save_editable_schema_settings("system", field_order=field_order, fields=fields)

    assert override_path.read_bytes() == previous
    assert _temporary_files(override_path) == []


@pytest.mark.parametrize(
    ("payload", "message"),
    [
        ('{"version": 1, "kinds":', "invalid JSON"),
        ('{"version": 2, "kinds": {}}', "unsupported version"),
        ('{"version": 1, "kinds": []}', "kinds must be an object"),
        (
            '{"version": 1, "kinds": {"unknown": {}}}',
            "unknown schema kind",
        ),
    ],
)
def test_corrupt_schema_override_file_fails_diagnostically(
    payload: str,
    message: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    override_path = tmp_path / "ui_schema_overrides.json"
    override_path.write_text(payload, encoding="utf-8")
    monkeypatch.setenv("BLOCKWART_SCHEMA_OVERRIDES_PATH", str(override_path))

    with pytest.raises(ValueError, match=message):
        load_editable_schema_settings("system")

    assert UI_SCHEMAS["system"].field_overrides == {}
