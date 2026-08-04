from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path
from urllib.parse import quote

import pytest
from sqlalchemy import create_engine, text

from blockwart.cli import database as database_cli
from blockwart.db import session as db_session
from blockwart.services.network_classification import (
    NetworkClassificationError,
    load_network_classification_evidence,
)


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
            "database_networks_error revision=20260804_0014 mode=dry-run "
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


@pytest.mark.parametrize(
    "database_url",
    [
        "sqlite:////definitely-missing/blockwart.sqlite3",
        "not-a-database-url",
        "sqlite:///file://remote.invalid/share/blockwart.sqlite3?mode=ro&uri=true",
    ],
)
def test_network_classification_apply_rejection_precedes_database_inspection(
    database_url: str,
    capsys,
) -> None:
    assert (
        database_cli.main(
            ["--database-url", database_url, "--apply", "networks"]
        )
        == 1
    )
    captured = capsys.readouterr()
    assert captured.out == ""
    assert (
        captured.err.strip()
        == "network_classification_error=apply_not_available"
    )


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
            "database_networks_ok revision=20260804_0014 mode=dry-run "
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


def test_network_classification_blocks_malformed_stored_network_data(
    tmp_path: Path,
    capsys,
) -> None:
    database_url, engine = _network_database(tmp_path)
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
    with engine.begin() as connection:
        connection.execute(
            text("UPDATE catalog_objects SET data_json=:data WHERE id='edge'"),
            {"data": '{"schema_version":1,"network":"not-an-object"}'},
        )
    capsys.readouterr()
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
        edge = _classification_rows(captured.out)[0]
        assert edge["action"] == "blocked"
        assert edge["blockers"] == ["invalid_network_data"]
        assert "database_networks_error" in captured.out
    finally:
        engine.dispose()


def test_network_classification_mapping_rejects_boolean_schema_version(
    tmp_path: Path,
) -> None:
    mapping = tmp_path / "boolean-schema-version.yaml"
    mapping.write_text("schema_version: true\nnetworks: []\n", encoding="utf-8")

    with pytest.raises(NetworkClassificationError, match="schema is invalid"):
        load_network_classification_evidence(mapping)


def test_network_classification_blocks_json_null_stored_data(
    tmp_path: Path,
    capsys,
) -> None:
    database_url, engine = _network_database(tmp_path)
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
    with engine.begin() as connection:
        connection.execute(
            text("UPDATE catalog_objects SET data_json='null' WHERE id='edge'")
        )
    capsys.readouterr()
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
        edge = _classification_rows(captured.out)[0]
        assert edge["action"] == "blocked"
        assert edge["blockers"] == ["invalid_network_data"]
        assert "database_networks_error" in captured.out
    finally:
        engine.dispose()


@pytest.mark.parametrize("invalid_category", [[], {}])
def test_network_classification_blocks_unhashable_stored_category(
    tmp_path: Path,
    capsys,
    invalid_category,
) -> None:
    database_url, engine = _network_database(tmp_path)
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
    with engine.begin() as connection:
        connection.execute(
            text("UPDATE catalog_objects SET data_json=:data WHERE id='edge'"),
            {
                "data": json.dumps(
                    {"schema_version": 1, "network": {"category": invalid_category}}
                )
            },
        )
    capsys.readouterr()
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
        edge = _classification_rows(captured.out)[0]
        assert edge["action"] == "blocked"
        assert edge["blockers"] == [
            "invalid_current_category_type",
            "invalid_network_data",
        ]
        assert "database_networks_error" in captured.out
    finally:
        engine.dispose()


@pytest.mark.parametrize(
    "target_category_yaml",
    ["[]", "{}"],
)
def test_network_classification_mapping_rejects_container_target_category(
    tmp_path: Path,
    target_category_yaml: str,
) -> None:
    mapping = tmp_path / "container-category.yaml"
    mapping.write_text(
        "\n".join(
            [
                "schema_version: 1",
                "networks:",
                "  - object_id: edge",
                f"    target_category: {target_category_yaml}",
                "    evidence_source: references/network.md#edge-switch",
            ]
        ),
        encoding="utf-8",
    )

    with pytest.raises(NetworkClassificationError, match="invalid target_category"):
        load_network_classification_evidence(mapping)


def test_network_classification_mapping_rejects_duplicate_yaml_keys(
    tmp_path: Path,
) -> None:
    mapping = tmp_path / "duplicate-key.yaml"
    mapping.write_text(
        "\n".join(
            [
                "schema_version: 1",
                "networks:",
                "  - object_id: edge",
                "    object_id: overwritten",
                "    target_category: switch",
                "    evidence_source: references/network.md#edge-switch",
            ]
        ),
        encoding="utf-8",
    )

    with pytest.raises(NetworkClassificationError, match="file is invalid"):
        load_network_classification_evidence(mapping)


def test_network_classification_dry_run_preserves_sqlite_file_and_journal_mode(
    tmp_path: Path,
    capsys,
) -> None:
    database_url, engine = _network_database(tmp_path)
    engine.dispose()
    database_path = tmp_path / "network-classification.sqlite3"
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
    with sqlite3.connect(database_path) as connection:
        connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        assert connection.execute("PRAGMA journal_mode=DELETE").fetchone() == (
            "delete",
        )
    before_hash = hashlib.sha256(database_path.read_bytes()).hexdigest()
    capsys.readouterr()

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
    assert "database_networks_ok" in capsys.readouterr().out
    after_hash = hashlib.sha256(database_path.read_bytes()).hexdigest()
    with sqlite3.connect(database_path) as connection:
        assert connection.execute("PRAGMA journal_mode").fetchone() == ("delete",)
    assert after_hash == before_hash
    assert not database_path.with_name(f"{database_path.name}-wal").exists()
    assert not database_path.with_name(f"{database_path.name}-shm").exists()


def test_network_classification_dry_run_does_not_create_closed_wal_sidecars(
    tmp_path: Path,
    capsys,
) -> None:
    database_url, engine = _network_database(tmp_path)
    engine.dispose()
    database_path = tmp_path / "network-classification.sqlite3"
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
    with sqlite3.connect(database_path) as connection:
        assert connection.execute("PRAGMA journal_mode=WAL").fetchone() == ("wal",)
        connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    wal_path = database_path.with_name(f"{database_path.name}-wal")
    shm_path = database_path.with_name(f"{database_path.name}-shm")
    if wal_path.exists():
        assert wal_path.stat().st_size == 0
        wal_path.unlink()
    shm_path.unlink(missing_ok=True)
    assert not wal_path.exists()
    assert not shm_path.exists()
    before_hash = hashlib.sha256(database_path.read_bytes()).hexdigest()
    capsys.readouterr()

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

    assert "database_networks_ok" in capsys.readouterr().out
    assert hashlib.sha256(database_path.read_bytes()).hexdigest() == before_hash
    assert not wal_path.exists()
    assert not shm_path.exists()


def test_network_classification_dry_run_preserves_live_wal_sidecars(
    tmp_path: Path,
    capsys,
) -> None:
    database_url, engine = _network_database(tmp_path)
    engine.dispose()
    database_path = tmp_path / "network-classification.sqlite3"
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
    wal_path = database_path.with_name(f"{database_path.name}-wal")
    shm_path = database_path.with_name(f"{database_path.name}-shm")

    with sqlite3.connect(database_path) as writer:
        assert writer.execute("PRAGMA journal_mode=WAL").fetchone() == ("wal",)
        writer.execute("UPDATE catalog_objects SET label = 'Edge Live WAL' WHERE id = 'edge'")
        writer.commit()
        assert wal_path.stat().st_size > 0
        assert shm_path.stat().st_size > 0
        paths = (database_path, wal_path, shm_path)
        before_hashes = {
            path: hashlib.sha256(path.read_bytes()).hexdigest() for path in paths
        }
        capsys.readouterr()

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

        output = capsys.readouterr().out
        assert "database_networks_ok" in output
        assert '\"label\":\"Edge Live WAL\"' in output
        assert {
            path: hashlib.sha256(path.read_bytes()).hexdigest() for path in paths
        } == before_hashes


def test_network_classification_rejects_active_delete_journal_without_source_changes(
    tmp_path: Path,
    capsys,
) -> None:
    database_url, engine = _network_database(tmp_path)
    engine.dispose()
    database_path = tmp_path / "network-classification.sqlite3"
    journal_path = database_path.with_name(f"{database_path.name}-journal")

    with sqlite3.connect(database_path) as writer:
        assert writer.execute("PRAGMA journal_mode=DELETE").fetchone() == ("delete",)
        writer.execute("CREATE TABLE journal_probe (payload BLOB)")
        writer.commit()
        writer.execute("PRAGMA cache_size=1")
        writer.execute("BEGIN IMMEDIATE")
        writer.executemany(
            "INSERT INTO journal_probe (payload) VALUES (?)",
            [(b"x" * 4096,) for _ in range(128)],
        )
        writer.execute(
            "UPDATE catalog_objects SET data_json = ? WHERE id = 'lan'",
            ('{"schema_version":1,"network":{"category":"router"}}',),
        )
        assert journal_path.stat().st_size > 0
        assert any(journal_path.read_bytes()[:8])
        paths = (database_path, journal_path)
        before_hashes = {
            path: hashlib.sha256(path.read_bytes()).hexdigest() for path in paths
        }
        capsys.readouterr()

        assert database_cli.main(["--database-url", database_url, "networks"]) == 1

        assert "database_networks_error=failed" in capsys.readouterr().err
        assert {
            path: hashlib.sha256(path.read_bytes()).hexdigest() for path in paths
        } == before_hashes
        writer.rollback()
        stored = writer.execute(
            "SELECT data_json FROM catalog_objects WHERE id = 'lan'"
        ).fetchone()[0]
        assert json.loads(stored)["network"]["category"] == "segment"


@pytest.mark.parametrize("journal_body", [b"", bytes(4096)])
def test_network_classification_accepts_non_hot_stale_rollback_journal(
    tmp_path: Path,
    capsys,
    journal_body: bytes,
) -> None:
    database_url, engine = _network_database(tmp_path)
    engine.dispose()
    database_path = tmp_path / "network-classification.sqlite3"
    journal_path = database_path.with_name(f"{database_path.name}-journal")
    journal_path.write_bytes(journal_body)
    before_hashes = {
        path: hashlib.sha256(path.read_bytes()).hexdigest()
        for path in (database_path, journal_path)
    }
    capsys.readouterr()

    assert database_cli.main(["--database-url", database_url, "networks"]) == 1

    captured = capsys.readouterr()
    assert "database_networks_error revision=" in captured.out
    assert "database_networks_error=failed" not in captured.err
    assert {
        path: hashlib.sha256(path.read_bytes()).hexdigest()
        for path in (database_path, journal_path)
    } == before_hashes


def test_network_classification_accepts_persist_commit_journal(
    tmp_path: Path,
    capsys,
) -> None:
    database_url, engine = _network_database(tmp_path)
    engine.dispose()
    database_path = tmp_path / "network-classification.sqlite3"
    journal_path = database_path.with_name(f"{database_path.name}-journal")
    with sqlite3.connect(database_path) as writer:
        assert writer.execute("PRAGMA journal_mode=PERSIST").fetchone() == ("persist",)
        writer.execute("UPDATE catalog_objects SET label = 'LAN Persist' WHERE id = 'lan'")
        writer.commit()
    assert journal_path.stat().st_size > 512
    assert journal_path.read_bytes()[:8] == bytes(8)
    before_hashes = {
        path: hashlib.sha256(path.read_bytes()).hexdigest()
        for path in (database_path, journal_path)
    }
    capsys.readouterr()

    assert database_cli.main(["--database-url", database_url, "networks"]) == 1

    captured = capsys.readouterr()
    assert "database_networks_error revision=" in captured.out
    assert "database_networks_error=failed" not in captured.err
    assert {
        path: hashlib.sha256(path.read_bytes()).hexdigest()
        for path in (database_path, journal_path)
    } == before_hashes


def test_sqlite_snapshot_rejects_unstable_rollback_journal(
    tmp_path: Path,
    monkeypatch,
) -> None:
    source_path = tmp_path / "source.sqlite3"
    snapshot_path = tmp_path / "snapshot.sqlite3"
    journal_path = source_path.with_name(f"{source_path.name}-journal")
    source_path.write_bytes(b"database")
    journal_path.write_bytes(bytes(1024))
    real_copyfile = db_session.shutil.copyfile

    def copy_and_mutate(source, destination):
        result = real_copyfile(source, destination)
        if Path(source) == journal_path:
            with journal_path.open("ab") as journal_file:
                journal_file.write(b"x")
        return result

    monkeypatch.setattr(db_session.shutil, "copyfile", copy_and_mutate)

    with pytest.raises(
        RuntimeError,
        match="SQLite source changed while creating read-only snapshot",
    ):
        db_session._copy_stable_sqlite_snapshot(source_path, snapshot_path)


@pytest.mark.parametrize("mode", ["ro", "rw"])
def test_network_classification_accepts_existing_sqlite_uri_url(
    tmp_path: Path,
    capsys,
    mode: str,
) -> None:
    database_directory = tmp_path / "database with space"
    database_directory.mkdir()
    _, engine = _network_database(database_directory)
    engine.dispose()
    database_path = database_directory / "network-classification.sqlite3"
    database_url = f"sqlite:///file:{database_path}?mode={mode}&uri=true"
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
    capsys.readouterr()

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
    assert "database_networks_ok" in capsys.readouterr().out


def test_network_classification_accepts_localhost_sqlite_uri(
    tmp_path: Path,
    capsys,
) -> None:
    _, engine = _network_database(tmp_path)
    engine.dispose()
    database_path = tmp_path / "network-classification.sqlite3"
    encoded_path = quote(str(database_path), safe="/")
    database_url = f"sqlite:///file://localhost{encoded_path}?mode=ro&uri=true"
    capsys.readouterr()

    assert database_cli.main(["--database-url", database_url, "networks"]) == 1

    captured = capsys.readouterr()
    assert "database_networks_error" in captured.out
    assert "database_networks_error=failed" not in captured.err


@pytest.mark.parametrize("mode", ["ro", "rw"])
def test_network_classification_accepts_encoded_sqlite_uri_filename(
    tmp_path: Path,
    capsys,
    mode: str,
) -> None:
    original_url, engine = _network_database(tmp_path)
    engine.dispose()
    original_path = Path(original_url.removeprefix("sqlite:///"))
    database_path = tmp_path / "network ?#%.sqlite3"
    original_path.rename(database_path)
    encoded_path = quote(str(database_path), safe="/")
    database_url = f"sqlite:///file:{encoded_path}?mode={mode}&uri=true"
    capsys.readouterr()

    assert database_cli.main(["--database-url", database_url, "networks"]) == 1

    captured = capsys.readouterr()
    assert "database_networks_error" in captured.out
    assert "database_networks_error=failed" not in captured.err


def test_network_classification_reads_from_non_writable_sqlite_directory(
    tmp_path: Path,
    capsys,
) -> None:
    database_directory = tmp_path / "read-only-database"
    database_directory.mkdir()
    database_url, engine = _network_database(database_directory)
    engine.dispose()
    database_path = database_directory / "network-classification.sqlite3"
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
    before_hash = hashlib.sha256(database_path.read_bytes()).hexdigest()
    before_names = {path.name for path in database_directory.iterdir()}
    database_path.chmod(0o444)
    database_directory.chmod(0o555)
    capsys.readouterr()

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
        assert "database_networks_ok" in capsys.readouterr().out
        assert hashlib.sha256(database_path.read_bytes()).hexdigest() == before_hash
        assert {path.name for path in database_directory.iterdir()} == before_names
    finally:
        database_directory.chmod(0o755)
        database_path.chmod(0o644)
