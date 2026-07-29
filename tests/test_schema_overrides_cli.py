from __future__ import annotations

import json
from pathlib import Path

from blockwart.cli import schema_overrides as schema_overrides_cli
from blockwart.domain.ui_schema import UI_SCHEMAS


def _legacy_document(kind: str) -> dict[str, object]:
    field_order = list(UI_SCHEMAS[kind].fields)
    return {
        "version": 1,
        "kinds": {
            kind: {
                "field_order": field_order,
                "fields": {
                    key: {
                        "label": key,
                        "placeholder": "",
                        "required": False,
                        "visible_in_detail": True,
                    }
                    for key in field_order
                },
            }
        },
    }


def test_schema_overrides_cli_defaults_to_read_only_dry_run(
    tmp_path: Path,
    monkeypatch,
    capsys,
) -> None:
    path = tmp_path / "ui_schema_overrides.json"
    original = json.dumps(_legacy_document("system"))
    path.write_text(original, encoding="utf-8")
    monkeypatch.setenv("BLOCKWART_SCHEMA_OVERRIDES_PATH", str(path))

    assert schema_overrides_cli.main([]) == 0

    output = capsys.readouterr().out
    assert "mode=dry-run" in output
    assert "source_version=1 target_version=2 changed=1" in output
    assert "backup_created=0" in output
    assert path.read_text(encoding="utf-8") == original
    assert not Path(f"{path}.v1.bak").exists()


def test_schema_overrides_cli_apply_creates_backup_and_v2_document(
    tmp_path: Path,
    monkeypatch,
    capsys,
) -> None:
    path = tmp_path / "ui_schema_overrides.json"
    original = json.dumps(_legacy_document("network"))
    path.write_text(original, encoding="utf-8")
    monkeypatch.setenv("BLOCKWART_SCHEMA_OVERRIDES_PATH", str(path))

    assert schema_overrides_cli.main(["--apply"]) == 0

    output = capsys.readouterr().out
    assert "mode=apply" in output
    assert "source_version=1 target_version=2 changed=1" in output
    assert "backup_created=1" in output
    assert Path(f"{path}.v1.bak").read_text(encoding="utf-8") == original
    assert json.loads(path.read_text(encoding="utf-8"))["version"] == 2


def test_schema_overrides_cli_redacts_validation_failure(
    tmp_path: Path,
    monkeypatch,
    capsys,
) -> None:
    path = tmp_path / "ui_schema_overrides.json"
    path.write_text('{"sensitive": "must-not-leak"}', encoding="utf-8")
    monkeypatch.setenv("BLOCKWART_SCHEMA_OVERRIDES_PATH", str(path))

    assert schema_overrides_cli.main(["--apply"]) == 1

    captured = capsys.readouterr()
    assert captured.err.strip() == "schema_overrides_migration_error=failed"
    assert "sensitive" not in captured.err
