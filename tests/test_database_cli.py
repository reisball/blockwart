from __future__ import annotations

import os
from pathlib import Path

import pytest
from sqlalchemy import create_engine, text

from blockwart.cli import database as database_cli
from blockwart.cli import import_markdown as import_markdown_cli
from blockwart.cli import seed as seed_cli
from blockwart.cli import start as start_cli
from blockwart.db.migrations import DatabaseMigrationError


def test_database_cli_upgrades_then_checks_database(tmp_path: Path, capsys) -> None:
    database_url = f"sqlite:///{tmp_path / 'cli.sqlite3'}"

    assert database_cli.main(["--database-url", database_url, "upgrade"]) == 0
    assert "database_upgrade_ok revision=20260724_0003" in capsys.readouterr().out

    assert database_cli.main(["--database-url", database_url, "check"]) == 0
    assert "database_check_ok revision=20260724_0003" in capsys.readouterr().out


def test_database_cli_redacts_migration_failure(
    monkeypatch: pytest.MonkeyPatch,
    capsys,
) -> None:
    def fail_upgrade(_database_url: str | None = None) -> str:
        raise DatabaseMigrationError("sensitive detail")

    monkeypatch.setattr(database_cli, "upgrade_database", fail_upgrade)

    assert database_cli.main(["upgrade"]) == 1
    captured = capsys.readouterr()
    assert captured.err.strip() == "database_upgrade_error=failed"
    assert "sensitive" not in captured.err


def test_markdown_create_schema_uses_alembic(
    tmp_path: Path,
    capsys,
) -> None:
    tools_path = tmp_path / "TOOLS.md"
    tools_path.write_text(
        "\n".join(
            [
                "| System | Typ | IP:Port | Status | Access | Auth | Nutzung | Ref | Skill |",
                "|--------|-----|---------|--------|--------|------|---------|-----|-------|",
                "| Migration Demo | Service | 192.0.2.42:443 | ✅ | Web | none | Demo | - | - |",
            ]
        ),
        encoding="utf-8",
    )
    database_url = f"sqlite:///{tmp_path / 'markdown.sqlite3'}"

    assert (
        import_markdown_cli.main(
            [
                "--database-url",
                database_url,
                "--tools",
                str(tools_path),
                "--references-root",
                str(tmp_path),
                "--create-schema",
                "--apply",
            ]
        )
        == 0
    )
    assert "markdown_import_applied objects=1" in capsys.readouterr().out

    engine = create_engine(database_url)
    with engine.connect() as connection:
        assert connection.execute(text("SELECT version_num FROM alembic_version")).scalar_one() == (
            "20260724_0003"
        )
    engine.dispose()


@pytest.mark.parametrize(
    ("cli_module", "argv", "expected_error"),
    [
        (
            seed_cli,
            ["--seed", "seeds/pilot_objects.yaml", "--create-schema"],
            "seed_error=database_migration_failed",
        ),
        (
            import_markdown_cli,
            [
                "--tools",
                "TOOLS.md",
                "--references-root",
                ".",
                "--create-schema",
                "--apply",
            ],
            "markdown_import_error=database_migration_failed",
        ),
    ],
)
def test_import_clis_redact_migration_failure(
    cli_module,
    argv: list[str],
    expected_error: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys,
) -> None:
    if cli_module is import_markdown_cli:
        tools_path = tmp_path / "TOOLS.md"
        tools_path.write_text(
            "\n".join(
                [
                    "| System | Typ | IP:Port | Status | Access | Auth | Nutzung | Ref | Skill |",
                    "|--------|-----|---------|--------|--------|------|---------|-----|-------|",
                ]
            ),
            encoding="utf-8",
        )
        argv = [
            "--tools",
            str(tools_path),
            "--references-root",
            str(tmp_path),
            "--create-schema",
            "--apply",
        ]

    def fail_upgrade(_database_url: str | None = None) -> str:
        raise DatabaseMigrationError("sensitive migration detail")

    monkeypatch.setattr(cli_module, "upgrade_database", fail_upgrade)

    assert cli_module.main(argv) == 1
    captured = capsys.readouterr()
    assert captured.err.strip() == expected_error
    assert "sensitive" not in captured.err


def test_startup_upgrades_before_exec(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[str, object]] = []

    def record_upgrade() -> str:
        calls.append(("upgrade", None))
        return "20260724_0003"

    def record_exec(file: str, args: list[str]) -> None:
        calls.append(("exec", (file, args)))
        raise RuntimeError("stop after proof")

    monkeypatch.setattr(start_cli, "upgrade_database", record_upgrade)
    monkeypatch.setattr(os, "execv", record_exec)

    with pytest.raises(RuntimeError, match="stop after proof"):
        start_cli.main()

    assert calls == [
        ("upgrade", None),
        ("exec", (start_cli.UVICORN_COMMAND[0], start_cli.UVICORN_COMMAND)),
    ]


def test_startup_aborts_before_exec_on_migration_failure(
    monkeypatch: pytest.MonkeyPatch,
    capsys,
) -> None:
    def fail_upgrade() -> str:
        raise DatabaseMigrationError("sensitive database detail")

    def forbidden_exec(_file: str, _args: list[str]) -> None:
        raise AssertionError("uvicorn must not start")

    monkeypatch.setattr(start_cli, "upgrade_database", fail_upgrade)
    monkeypatch.setattr(os, "execv", forbidden_exec)

    assert start_cli.main() == 1
    captured = capsys.readouterr()
    assert captured.err.strip() == "startup_error=database_migration_failed"
    assert "sensitive" not in captured.err
