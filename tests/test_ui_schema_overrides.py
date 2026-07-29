from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from blockwart.domain import ui_schema
from blockwart.domain.ui_schema import (
    UI_SCHEMAS,
    apply_schema_overrides_migration,
    build_schema_overrides_migration_plan,
    load_editable_schema_settings,
    save_editable_schema_settings,
)


def _editable_settings(kind: str) -> tuple[list[str], dict[str, dict[str, object]]]:
    settings = load_editable_schema_settings(kind)
    fields = {
        str(field["key"]): {
            "labels": dict(field["localized_labels"]),
            "placeholders": dict(field["localized_placeholders"]),
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
    fields["hardware_storage"]["labels"] = {
        "en": "Persisted disk",
        "de": "Persistierter Speicher",
    }

    save_editable_schema_settings("system", field_order=field_order, fields=fields)

    payload = json.loads(override_path.read_text(encoding="utf-8"))
    reloaded = load_editable_schema_settings("system")
    labels = {
        str(field["key"]): dict(field["localized_labels"])
        for field in reloaded["fields"]
    }
    assert payload == {
        "version": 2,
        "kinds": {
            "system": {
                "field_order": field_order,
                "fields": fields,
            }
        },
    }
    assert labels["hardware_storage"] == {
        "en": "Persisted disk",
        "de": "Persistierter Speicher",
    }
    assert _temporary_files(override_path) == []


def test_schema_override_replace_failure_preserves_previous_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    override_path = tmp_path / "ui_schema_overrides.json"
    monkeypatch.setenv("BLOCKWART_SCHEMA_OVERRIDES_PATH", str(override_path))
    field_order, fields = _editable_settings("system")
    fields["hardware_storage"]["labels"] = {"en": "Old disk"}
    save_editable_schema_settings("system", field_order=field_order, fields=fields)
    previous = override_path.read_bytes()
    fields["hardware_storage"]["labels"] = {"en": "New disk"}

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
        ('{"version": 3, "kinds": {}}', "unsupported version"),
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


def test_v1_schema_override_migration_is_lossless_and_recoverable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    override_path = tmp_path / "ui_schema_overrides.json"
    monkeypatch.setenv("BLOCKWART_SCHEMA_OVERRIDES_PATH", str(override_path))
    field_order = list(UI_SCHEMAS["network"].fields)
    legacy_fields = {
        key: {
            "label": f"Legacy {key}",
            "placeholder": f"Legacy placeholder {key}",
            "required": False,
            "visible_in_detail": True,
        }
        for key in field_order
    }
    original = {
        "version": 1,
        "kinds": {
            "netzwerk": {
                "field_order": field_order,
                "fields": legacy_fields,
            }
        },
    }
    original_bytes = (json.dumps(original, indent=2) + "\n").encode()
    override_path.write_bytes(original_bytes)

    dry_run = build_schema_overrides_migration_plan()

    assert dry_run.source_version == 1
    assert dry_run.target_version == 2
    assert dry_run.changed is True
    assert dry_run.kinds == ("network",)
    assert override_path.read_bytes() == original_bytes

    backup_path = apply_schema_overrides_migration()

    assert backup_path is not None
    assert backup_path.read_bytes() == original_bytes
    assert backup_path.stat().st_mode & 0o777 == 0o600
    migrated = json.loads(override_path.read_text(encoding="utf-8"))
    assert migrated["version"] == 2
    assert set(migrated["kinds"]) == {"network"}
    migrated_label = migrated["kinds"]["network"]["fields"]["primary_name"]["labels"]
    assert migrated_label == {
        "de": "Legacy primary_name",
        "en": "Legacy primary_name",
    }
    assert build_schema_overrides_migration_plan().changed is False
    assert apply_schema_overrides_migration() is None


def test_schema_override_migration_refuses_to_overwrite_existing_backup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    override_path = tmp_path / "ui_schema_overrides.json"
    monkeypatch.setenv("BLOCKWART_SCHEMA_OVERRIDES_PATH", str(override_path))
    field_order = list(UI_SCHEMAS["system"].fields)
    fields = {
        key: {
            "label": key,
            "placeholder": "",
            "required": False,
            "visible_in_detail": True,
        }
        for key in field_order
    }
    override_path.write_text(
        json.dumps(
            {
                "version": 1,
                "kinds": {
                    "system": {
                        "field_order": field_order,
                        "fields": fields,
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    backup_path = Path(f"{override_path}.v1.bak")
    backup_path.write_text("existing", encoding="utf-8")

    with pytest.raises(ValueError, match="backup already exists"):
        apply_schema_overrides_migration()

    assert backup_path.read_text(encoding="utf-8") == "existing"
    assert json.loads(override_path.read_text(encoding="utf-8"))["version"] == 1
