from __future__ import annotations

import json
from pathlib import Path

from sqlalchemy import create_engine, text

from blockwart.cli import database as database_cli


def _network_database(tmp_path: Path) -> tuple[str, object]:
    database_url = f"sqlite:///{tmp_path / 'network-classification.sqlite3'}"
    assert database_cli.main(["--database-url", database_url, "upgrade"]) == 0
    engine = create_engine(database_url)
    with engine.begin() as connection:
        connection.execute(
            text(
                "INSERT INTO catalog_objects "
                "(id, kind, label, status, lifecycle, health, data_json) VALUES "
                "('lan', 'network', 'LAN', 'active', 'active', 'unknown', :lan),"
                "('edge', 'network', 'Edge', 'active', 'active', 'unknown', :edge)"
            ),
            {
                "lan": '{"schema_version":1,"network":{"category":"segment"}}',
                "edge": '{"schema_version":1,"network":{"manufacturer":"Example"}}',
            },
        )
    return database_url, engine


def _classification_rows(output: str) -> list[dict]:
    return [
        json.loads(line.removeprefix("network_classification "))
        for line in output.splitlines()
        if line.startswith("network_classification {")
    ]


def test_network_classification_dry_run_fails_closed_without_evidence(
    tmp_path: Path,
    capsys,
) -> None:
    database_url, engine = _network_database(tmp_path)
    capsys.readouterr()
    try:
        assert database_cli.main(["--database-url", database_url, "networks"]) == 1
        captured = capsys.readouterr()
        rows = _classification_rows(captured.out)
        assert rows == [
            {
                "action": "blocked",
                "blockers": ["missing_category_evidence"],
                "current_category": None,
                "evidence_source": None,
                "label": "Edge",
                "object_ref": "network:edge",
                "target_category": None,
            },
            {
                "action": "none",
                "blockers": [],
                "current_category": "segment",
                "evidence_source": "catalog:data.network.category",
                "label": "LAN",
                "object_ref": "network:lan",
                "target_category": "segment",
            },
        ]
        assert (
            "database_networks_error revision=20260801_0013 mode=dry-run "
            "scanned=2 changed=0 blocked=1 diagnostics=0"
        ) in captured.out
        with engine.connect() as connection:
            stored = connection.execute(
                text("SELECT data_json FROM catalog_objects WHERE id='edge'")
            ).scalar_one()
        assert json.loads(stored) == {
            "schema_version": 1,
            "network": {"manufacturer": "Example"},
        }
    finally:
        engine.dispose()


def test_network_classification_mapping_is_evidenced_and_still_write_free(
    tmp_path: Path,
    capsys,
) -> None:
    database_url, engine = _network_database(tmp_path)
    capsys.readouterr()
    mapping = tmp_path / "network-mapping.yaml"
    mapping.write_text(
        "\n".join(
            [
                "schema_version: 1",
                "networks:",
                "  - object_id: edge",
                "    target_category: switch",
                "    evidence_source: references/network.md#edge-switch",
            ]
        ),
        encoding="utf-8",
    )
    try:
        assert (
            database_cli.main(
                [
                    "--database-url",
                    database_url,
                    "--mapping",
                    str(mapping),
                    "networks",
                ]
            )
            == 0
        )
        captured = capsys.readouterr()
        rows = _classification_rows(captured.out)
        assert rows[0] == {
            "action": "set_category",
            "blockers": [],
            "current_category": None,
            "evidence_source": "references/network.md#edge-switch",
            "label": "Edge",
            "object_ref": "network:edge",
            "target_category": "switch",
        }
        assert (
            "database_networks_ok revision=20260801_0013 mode=dry-run "
            "scanned=2 changed=1 blocked=0 diagnostics=0"
        ) in captured.out

        assert (
            database_cli.main(
                [
                    "--database-url",
                    database_url,
                    "--mapping",
                    str(mapping),
                    "--apply",
                    "networks",
                ]
            )
            == 1
        )
        assert (
            capsys.readouterr().err.strip()
            == "network_classification_error=apply_not_available"
        )
        with engine.connect() as connection:
            stored = connection.execute(
                text("SELECT data_json FROM catalog_objects WHERE id='edge'")
            ).scalar_one()
        assert "category" not in json.loads(stored)["network"]
    finally:
        engine.dispose()


def test_network_classification_rejects_unknown_mapping_refs(
    tmp_path: Path,
    capsys,
) -> None:
    database_url, engine = _network_database(tmp_path)
    capsys.readouterr()
    mapping = tmp_path / "unknown-network.yaml"
    mapping.write_text(
        "\n".join(
            [
                "schema_version: 1",
                "networks:",
                "  - object_id: not-in-catalog",
                "    target_category: router",
                "    evidence_source: references/network.md#router",
            ]
        ),
        encoding="utf-8",
    )
    try:
        assert (
            database_cli.main(
                [
                    "--database-url",
                    database_url,
                    "--mapping",
                    str(mapping),
                    "networks",
                ]
            )
            == 1
        )
        captured = capsys.readouterr()
        assert "unknown_mapping_ref:network:not-in-catalog" in captured.err
        assert "diagnostics=1" in captured.out
    finally:
        engine.dispose()
