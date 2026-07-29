from pathlib import Path

from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from blockwart.cli.seed import main
from blockwart.models import AuditEvent, CatalogObject, Relationship

SEED_PATH = Path("seeds/pilot_objects.yaml")


def test_seed_cli_creates_schema_and_imports_seed(tmp_path, capsys):
    db_path = tmp_path / "blockwart.sqlite3"
    exit_code = main(
        [
            "--database-url",
            f"sqlite:///{db_path}",
            "--seed",
            str(SEED_PATH),
            "--create-schema",
        ]
    )

    assert exit_code == 0
    output = capsys.readouterr().out
    assert "seed_imported objects=52 relationships=63" in output
    assert "catalog_summary objects=52 relationships=63 audit_events=115" in output

    engine = create_engine(f"sqlite:///{db_path}", connect_args={"check_same_thread": False})
    session_factory = sessionmaker(bind=engine)
    with session_factory() as session:
        assert session.query(CatalogObject).count() == 52
        assert session.query(Relationship).count() == 63
        assert session.query(AuditEvent).count() == 115
        assert session.execute(text("SELECT version_num FROM alembic_version")).scalar_one() == (
            "20260729_0007"
        )


def test_seed_cli_summary_only_reads_existing_database(tmp_path, capsys):
    db_path = tmp_path / "blockwart.sqlite3"
    database_url = f"sqlite:///{db_path}"
    assert main(["--database-url", database_url, "--seed", str(SEED_PATH), "--create-schema"]) == 0
    capsys.readouterr()

    assert main(["--database-url", database_url, "--summary-only"]) == 0

    output = capsys.readouterr().out
    assert "catalog_summary objects=52 relationships=63 audit_events=115" in output


def test_seed_cli_rejects_missing_seed_file(tmp_path, capsys):
    db_path = tmp_path / "blockwart.sqlite3"
    exit_code = main(
        [
            "--database-url",
            f"sqlite:///{db_path}",
            "--seed",
            str(tmp_path / "missing.yaml"),
            "--create-schema",
        ]
    )

    assert exit_code == 2
    error = capsys.readouterr().err
    assert "seed_error=missing_file" in error
