import io
import json
import stat
from pathlib import Path

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from blockwart.cli import auth as auth_cli
from blockwart.config import Settings
from blockwart.db.migrations import upgrade_database
from blockwart.db.readiness import DatabaseReadinessError, check_database_readiness
from blockwart.db.session import build_engine
from blockwart.models import (
    CatalogObject,
    ObjectGrant,
    PasswordCredential,
    Principal,
    SecurityEvent,
    ServiceToken,
)
from blockwart.services.identity import authenticate_service_token

PASSWORD = "correct horse battery staple"


def _database(tmp_path: Path) -> tuple[str, object]:
    database_url = f"sqlite:///{tmp_path / 'auth-cli.sqlite3'}"
    upgrade_database(database_url)
    engine = build_engine(database_url)
    with Session(engine) as session:
        session.add(
            CatalogObject(
                id="fabrik",
                kind="host",
                label="Fabrik",
                status="active",
                lifecycle="active",
                health="healthy",
                summary=None,
                data_json="{}",
                provenance_json='{"manual_override":false,"source_type":"unknown"}',
            )
        )
        session.commit()
    return database_url, engine


def test_bootstrap_owner_is_atomic_idempotent_and_secret_free(
    tmp_path: Path,
    monkeypatch,
    capsys,
) -> None:
    database_url, engine = _database(tmp_path)
    monkeypatch.setattr("sys.stdin", io.StringIO(f"{PASSWORD}\n"))

    result = auth_cli.main(
        [
            "--database-url",
            database_url,
            "bootstrap-owner",
            "--login",
            "kai.owner",
            "--display-name",
            "Kai Owner",
            "--object-id",
            "fabrik",
            "--scope",
            "subtree",
            "--password-stdin",
        ]
    )

    output = capsys.readouterr()
    assert result == 0
    assert "mode=created" in output.out
    assert PASSWORD not in output.out
    assert output.err == ""
    with Session(engine) as session:
        principal = session.scalar(select(Principal))
        grant = session.scalar(select(ObjectGrant))
        credential = session.scalar(select(PasswordCredential))
        assert principal is not None
        assert grant is not None
        assert credential is not None
        assert grant.principal_id == principal.id
        assert grant.object_id == "fabrik"
        assert grant.role == "owner"
        assert grant.scope == "subtree"
        assert principal.platform_role == "admin"
        assert principal.revision == 1
        assert PASSWORD not in credential.password_hash

    monkeypatch.setattr("sys.stdin", io.StringIO(""))
    repeated = auth_cli.main(
        [
            "--database-url",
            database_url,
            "bootstrap-owner",
            "--login",
            "kai.owner",
            "--display-name",
            "Kai Owner",
            "--object-id",
            "fabrik",
            "--scope",
            "subtree",
            "--password-stdin",
        ]
    )
    repeated_output = capsys.readouterr()
    assert repeated == 0
    assert "mode=unchanged" in repeated_output.out
    with Session(engine) as session:
        assert len(session.scalars(select(Principal)).all()) == 1
        assert len(session.scalars(select(ObjectGrant)).all()) == 1
    engine.dispose()


def test_existing_human_can_be_explicitly_promoted_to_platform_admin(
    tmp_path: Path,
    monkeypatch,
    capsys,
) -> None:
    database_url, engine = _database(tmp_path)
    monkeypatch.setattr("sys.stdin", io.StringIO(f"{PASSWORD}\n"))
    assert auth_cli.main(
        [
            "--database-url",
            database_url,
            "create-human",
            "--login",
            "kai",
            "--display-name",
            "Kai",
            "--password-stdin",
        ]
    ) == 0
    capsys.readouterr()

    assert auth_cli.main(
        ["--database-url", database_url, "promote-admin", "--login", "kai"]
    ) == 0
    output = capsys.readouterr()
    assert "changed=1" in output.out
    with Session(engine) as session:
        principal = session.scalar(select(Principal).where(Principal.login == "kai"))
        assert principal is not None
        assert principal.platform_role == "admin"
        assert principal.revision == 2

    assert auth_cli.main(
        ["--database-url", database_url, "promote-admin", "--login", "kai"]
    ) == 0
    assert "changed=0" in capsys.readouterr().out
    engine.dispose()


def test_bootstrap_refuses_conflicting_existing_identity(
    tmp_path: Path,
    monkeypatch,
    capsys,
) -> None:
    database_url, engine = _database(tmp_path)
    with Session(engine) as session:
        session.add(
            Principal(
                id="00000000-0000-0000-0000-000000000001",
                principal_type="service_account",
                login="already.exists",
                display_name="Existing",
                active=True,
            )
        )
        session.commit()
    monkeypatch.setattr("sys.stdin", io.StringIO(f"{PASSWORD}\n"))

    result = auth_cli.main(
        [
            "--database-url",
            database_url,
            "bootstrap-owner",
            "--login",
            "kai.owner",
            "--display-name",
            "Kai Owner",
            "--object-id",
            "fabrik",
            "--password-stdin",
        ]
    )

    output = capsys.readouterr()
    assert result == 1
    assert output.out == ""
    assert output.err == "auth_bootstrap_owner_error=failed\n"
    assert PASSWORD not in output.err
    with Session(engine) as session:
        assert len(session.scalars(select(Principal)).all()) == 1
        assert session.scalar(select(ObjectGrant)) is None
    engine.dispose()


def test_multi_anchor_bootstrap_rolls_back_incomplete_coverage_and_is_idempotent(
    tmp_path: Path,
    monkeypatch,
    capsys,
) -> None:
    database_url, engine = _database(tmp_path)
    with Session(engine) as session:
        session.add(
            CatalogObject(
                id="other-root",
                kind="host",
                label="Other Root",
                status="active",
                lifecycle="active",
                health="healthy",
                summary=None,
                data_json="{}",
                provenance_json='{"manual_override":false,"source_type":"unknown"}',
            )
        )
        session.commit()

    base_args = [
        "--database-url",
        database_url,
        "bootstrap-owner",
        "--login",
        "multi.owner",
        "--display-name",
        "Multi Owner",
        "--scope",
        "subtree",
        "--password-stdin",
    ]
    monkeypatch.setattr("sys.stdin", io.StringIO(f"{PASSWORD}\n"))
    assert auth_cli.main([*base_args, "--object-id", "fabrik"]) == 1
    assert capsys.readouterr().err == "auth_bootstrap_owner_error=failed\n"
    with Session(engine) as session:
        assert session.scalar(select(Principal)) is None
        assert session.scalar(select(PasswordCredential)) is None
        assert session.scalar(select(ObjectGrant)) is None

    complete_args = [
        *base_args,
        "--object-id",
        "fabrik",
        "--object-id",
        "other-root",
    ]
    monkeypatch.setattr("sys.stdin", io.StringIO(f"{PASSWORD}\n"))
    assert auth_cli.main(complete_args) == 0
    output = capsys.readouterr()
    assert "mode=created" in output.out
    assert "object_ids=fabrik,other-root" in output.out

    monkeypatch.setattr("sys.stdin", io.StringIO(""))
    assert auth_cli.main(complete_args) == 0
    assert "mode=unchanged" in capsys.readouterr().out
    with Session(engine) as session:
        assert len(session.scalars(select(Principal)).all()) == 1
        assert {grant.object_id for grant in session.scalars(select(ObjectGrant)).all()} == {
            "fabrik",
            "other-root",
        }
    engine.dispose()


def test_service_token_is_written_once_to_new_mode_0600_file(
    tmp_path: Path,
    capsys,
) -> None:
    database_url, engine = _database(tmp_path)
    create = auth_cli.main(
        [
            "--database-url",
            database_url,
            "create-service-account",
            "--login",
            "mcp.reader",
            "--display-name",
            "MCP Reader",
        ]
    )
    assert create == 0
    capsys.readouterr()
    token_path = tmp_path / "mcp-reader.token"

    issue = auth_cli.main(
        [
            "--database-url",
            database_url,
            "issue-token",
            "--login",
            "mcp.reader",
            "--name",
            "runtime",
            "--output-file",
            str(token_path),
        ]
    )

    output = capsys.readouterr()
    assert issue == 0
    token = token_path.read_text(encoding="utf-8").strip()
    assert token.startswith("bwst_")
    assert token not in output.out
    assert stat.S_IMODE(token_path.stat().st_mode) == 0o600
    with Session(engine) as session:
        stored = session.scalar(select(ServiceToken))
        principal = session.scalar(select(Principal).where(Principal.login == "mcp.reader"))
        assert stored is not None
        assert principal is not None
        assert principal.revision == 2
        assert token not in stored.token_hash
        assert authenticate_service_token(session, token=token) is not None

    duplicate = auth_cli.main(
        [
            "--database-url",
            database_url,
            "rotate-token",
            "--login",
            "mcp.reader",
            "--name",
            "runtime",
            "--output-file",
            str(token_path),
        ]
    )
    duplicate_output = capsys.readouterr()
    assert duplicate == 1
    assert duplicate_output.err == "auth_rotate_token_error=failed\n"
    assert token_path.read_text(encoding="utf-8").strip() == token

    rotated_path = tmp_path / "mcp-reader-rotated.token"
    assert auth_cli.main(
        [
            "--database-url",
            database_url,
            "rotate-token",
            "--login",
            "mcp.reader",
            "--name",
            "runtime",
            "--output-file",
            str(rotated_path),
        ]
    ) == 0
    capsys.readouterr()
    with Session(engine) as session:
        principal = session.scalar(select(Principal).where(Principal.login == "mcp.reader"))
        assert principal is not None
        assert principal.revision == 3

    assert auth_cli.main(
        [
            "--database-url",
            database_url,
            "revoke-token",
            "--login",
            "mcp.reader",
            "--name",
            "runtime",
        ]
    ) == 0
    assert "changed=1" in capsys.readouterr().out
    with Session(engine) as session:
        principal = session.scalar(select(Principal).where(Principal.login == "mcp.reader"))
        assert principal is not None
        assert principal.revision == 4

    assert auth_cli.main(
        [
            "--database-url",
            database_url,
            "revoke-token",
            "--login",
            "mcp.reader",
            "--name",
            "runtime",
        ]
    ) == 0
    assert "changed=0" in capsys.readouterr().out
    with Session(engine) as session:
        principal = session.scalar(select(Principal).where(Principal.login == "mcp.reader"))
        assert principal is not None
        assert principal.revision == 4
    engine.dispose()


def test_bootstrap_owner_assigns_the_catalog_role_in_the_same_transaction(
    tmp_path: Path,
    monkeypatch,
    capsys,
) -> None:
    database_url, engine = _database(tmp_path)
    monkeypatch.setattr("sys.stdin", io.StringIO(f"{PASSWORD}\n"))

    arguments = [
        "--database-url",
        database_url,
        "bootstrap-owner",
        "--login",
        "kai.owner",
        "--display-name",
        "Kai Owner",
        "--object-id",
        "fabrik",
        "--scope",
        "subtree",
        "--password-stdin",
        "--catalog-owner",
    ]
    assert auth_cli.main(arguments) == 0
    output = capsys.readouterr()
    assert "mode=created" in output.out
    assert "catalog_owner=1" in output.out
    assert PASSWORD not in output.out
    with Session(engine) as session:
        principal = session.scalar(select(Principal))
        assert principal is not None
        assert principal.catalog_role == "catalog_owner"
        assert principal.platform_role == "admin"
        assert principal.revision == 1
        assert len(session.scalars(select(ObjectGrant)).all()) == 1

    monkeypatch.setattr("sys.stdin", io.StringIO(""))
    assert auth_cli.main(arguments) == 0
    assert "mode=unchanged" in capsys.readouterr().out
    with Session(engine) as session:
        assert len(session.scalars(select(Principal)).all()) == 1
        assert len(session.scalars(select(ObjectGrant)).all()) == 1
    engine.dispose()


def test_bootstrap_owner_without_the_flag_leaves_the_catalog_role_unset(
    tmp_path: Path,
    monkeypatch,
    capsys,
) -> None:
    database_url, engine = _database(tmp_path)
    monkeypatch.setattr("sys.stdin", io.StringIO(f"{PASSWORD}\n"))

    assert auth_cli.main(
        [
            "--database-url",
            database_url,
            "bootstrap-owner",
            "--login",
            "kai.owner",
            "--display-name",
            "Kai Owner",
            "--object-id",
            "fabrik",
            "--password-stdin",
        ]
    ) == 0
    assert "catalog_owner=0" in capsys.readouterr().out
    with Session(engine) as session:
        principal = session.scalar(select(Principal))
        assert principal is not None
        assert principal.catalog_role is None

    with pytest.raises(DatabaseReadinessError) as gated:
        check_database_readiness(Settings(database_url=database_url))
    assert gated.value.code == "catalog_owner_missing"
    engine.dispose()


def test_catalog_owner_recovery_is_protected_idempotent_and_grant_free(
    tmp_path: Path,
    monkeypatch,
    capsys,
) -> None:
    database_url, engine = _database(tmp_path)
    monkeypatch.setattr("sys.stdin", io.StringIO(f"{PASSWORD}\n"))
    assert auth_cli.main(
        [
            "--database-url",
            database_url,
            "bootstrap-owner",
            "--login",
            "kai.owner",
            "--display-name",
            "Kai Owner",
            "--object-id",
            "fabrik",
            "--password-stdin",
        ]
    ) == 0
    assert auth_cli.main(
        [
            "--database-url",
            database_url,
            "create-service-account",
            "--login",
            "spare.agent",
            "--display-name",
            "Spare Agent",
        ]
    ) == 0
    capsys.readouterr()

    assert auth_cli.main(
        [
            "--database-url",
            database_url,
            "bootstrap-catalog-owner",
            "--login",
            "kai.owner",
        ]
    ) == 0
    output = capsys.readouterr()
    assert "auth_bootstrap_catalog_owner_ok" in output.out
    assert "changed=1" in output.out
    assert PASSWORD not in output.out
    assert output.err == ""
    with Session(engine) as session:
        principal = session.scalar(select(Principal).where(Principal.login == "kai.owner"))
        assert principal is not None
        assert principal.catalog_role == "catalog_owner"
        assert principal.revision == 2
        assert len(session.scalars(select(ObjectGrant)).all()) == 1
        event = session.scalars(
            select(SecurityEvent).where(SecurityEvent.event_type == "catalog_owner_selected")
        ).one()
        assert event.channel == "cli"
        assert event.outcome == "success"
        assert event.principal_id == principal.id
        assert json.loads(event.details_json) == {"actor": "protected_cli"}
        assert PASSWORD not in event.details_json

    # Repeating the selection for the same owner stays a no-op.
    assert auth_cli.main(
        [
            "--database-url",
            database_url,
            "bootstrap-catalog-owner",
            "--login",
            "kai.owner",
        ]
    ) == 0
    assert "changed=0" in capsys.readouterr().out
    with Session(engine) as session:
        principal = session.scalar(select(Principal).where(Principal.login == "kai.owner"))
        assert principal is not None
        assert principal.revision == 2
        assert len(session.scalars(
            select(SecurityEvent).where(
                SecurityEvent.event_type == "catalog_owner_selected"
            )
        ).all()) == 1

    # It is never a routine way to add another owner.
    assert auth_cli.main(
        [
            "--database-url",
            database_url,
            "bootstrap-catalog-owner",
            "--login",
            "spare.agent",
        ]
    ) == 1
    assert "auth_bootstrap_catalog_owner_error=failed" in capsys.readouterr().err
    with Session(engine) as session:
        spare = session.scalar(select(Principal).where(Principal.login == "spare.agent"))
        assert spare is not None
        assert spare.catalog_role is None
        assert spare.revision == 1

    check_database_readiness(Settings(database_url=database_url))
    engine.dispose()


def test_catalog_owner_recovery_rejects_unknown_and_inactive_principals(
    tmp_path: Path,
    monkeypatch,
    capsys,
) -> None:
    database_url, engine = _database(tmp_path)
    monkeypatch.setattr("sys.stdin", io.StringIO(f"{PASSWORD}\n"))
    assert auth_cli.main(
        [
            "--database-url",
            database_url,
            "bootstrap-owner",
            "--login",
            "kai.owner",
            "--display-name",
            "Kai Owner",
            "--object-id",
            "fabrik",
            "--password-stdin",
        ]
    ) == 0
    with Session(engine) as session:
        session.add(
            Principal(
                id="00000000-0000-0000-0000-0000000000aa",
                principal_type="service_account",
                login="retired.agent",
                display_name="Retired Agent",
                active=False,
            )
        )
        session.commit()
    capsys.readouterr()

    for login in ("missing.principal", "retired.agent"):
        assert auth_cli.main(
            [
                "--database-url",
                database_url,
                "bootstrap-catalog-owner",
                "--login",
                login,
            ]
        ) == 1
        assert "auth_bootstrap_catalog_owner_error=failed" in capsys.readouterr().err

    with Session(engine) as session:
        assert session.scalars(
            select(Principal).where(Principal.catalog_role.is_not(None))
        ).all() == []
    engine.dispose()
