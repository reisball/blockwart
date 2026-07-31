from collections.abc import Generator
from contextlib import contextmanager
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session

from blockwart.api.deps import get_session
from blockwart.cli import import_markdown as import_markdown_cli
from blockwart.cli import seed as seed_cli
from blockwart.config import Settings
from blockwart.db.session import transaction
from blockwart.domain.asset_state import is_asset_kind
from blockwart.main import create_app
from blockwart.models import AuditEvent, CatalogObject, Relationship
from blockwart.schemas.catalog import CatalogObjectIn
from blockwart.services.catalog import (
    create_relationship,
    delete_object,
    get_object,
    upsert_object,
)
from blockwart.services.markdown_import import import_tools_markdown
from blockwart.services.seeds import import_seed_file

SEED_PATH = Path(__file__).resolve().parents[1] / "seeds" / "pilot_objects.yaml"
TEST_ADMIN_TOKEN = "test-admin-token-with-at-least-32-characters"


class CommitCountingSession(Session):
    commit_calls: int

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.commit_calls = 0

    def commit(self) -> None:
        self.commit_calls += 1
        super().commit()


@pytest.fixture
def session_factory(alembic_session_factory):
    return alembic_session_factory


def _add_object(
    session: Session,
    *,
    object_id: str,
    kind: str = "system",
    data_json: str = '{"schema_version": 1}',
) -> None:
    session.add(
        CatalogObject(
            id=object_id,
            kind=kind,
            label=object_id,
            status="active",
            lifecycle="active" if is_asset_kind(kind) else None,
            health="unknown" if is_asset_kind(kind) else None,
            summary=None,
            data_json=data_json,
        )
    )


@contextmanager
def _unlocked_client(
    session_factory,
    install_unrestricted_read_access,
) -> Generator[TestClient, None, None]:
    app = create_app(settings=Settings(admin_token=TEST_ADMIN_TOKEN))
    install_unrestricted_read_access(app)

    def override_get_session() -> Generator[Session, None, None]:
        with session_factory() as session:
            yield session

    app.dependency_overrides[get_session] = override_get_session
    with TestClient(app) as client:
        response = client.post(
            "/admin/unlock",
            data={"admin_token": TEST_ADMIN_TOKEN},
            follow_redirects=False,
        )
        assert response.status_code == 303
        yield client


def test_catalog_helpers_flush_without_committing(alembic_database_factory) -> None:
    factory = alembic_database_factory(
        "helper-commits.db",
        session_class=CommitCountingSession,
    ).sessions

    with factory() as session:
        upsert_object(
            session,
            CatalogObjectIn(
                id="host",
                kind="host",
                label="Host",
                status="active",
                data={"schema_version": 1},
            ),
        )
        upsert_object(
            session,
            CatalogObjectIn(
                id="service",
                kind="service",
                label="Service",
                status="active",
                data={"schema_version": 1},
            ),
        )
        create_relationship(
            session,
            from_ref="host:host",
            relation_type="hosts",
            to_ref="service:service",
        )

        assert session.commit_calls == 0
        assert session.scalar(select(Relationship)) is not None


def test_fault_after_object_upsert_rolls_back_object_and_audit(session_factory) -> None:
    with pytest.raises(RuntimeError, match="forced relationship failure"):
        with session_factory() as session:
            try:
                upsert_object(
                    session,
                    CatalogObjectIn(
                        id="partial-object",
                        kind="system",
                        label="Partial Object",
                        status="active",
                        data={"schema_version": 1},
                    ),
                )
                raise RuntimeError("forced relationship failure")
            except Exception:
                session.rollback()
                raise

    with session_factory() as session:
        assert session.get(CatalogObject, "partial-object") is None
        assert session.scalars(
            select(AuditEvent).where(AuditEvent.object_id == "partial-object")
        ).all() == []


def test_fault_after_relationship_rolls_back_object_edge_and_audits(session_factory) -> None:
    with session_factory() as session:
        _add_object(session, object_id="relationship-parent", kind="host")
        session.commit()

    with pytest.raises(RuntimeError, match="forced post-relationship failure"):
        with session_factory() as session:
            with transaction(session):
                upsert_object(
                    session,
                    CatalogObjectIn(
                        id="relationship-child",
                        kind="service",
                        label="Relationship Child",
                        status="active",
                        data={"schema_version": 1},
                    ),
                )
                create_relationship(
                    session,
                    from_ref="host:relationship-parent",
                    relation_type="hosts",
                    to_ref="service:relationship-child",
                )
                raise RuntimeError("forced post-relationship failure")

    with session_factory() as session:
        assert session.get(CatalogObject, "relationship-child") is None
        assert session.scalars(
            select(Relationship).where(Relationship.to_ref == "service:relationship-child")
        ).all() == []
        assert session.scalars(
            select(AuditEvent).where(
                (AuditEvent.object_id == "relationship-child")
                | (AuditEvent.action == "relationship_create")
            )
        ).all() == []


def test_ui_object_and_relationship_are_one_transaction(
    session_factory,
    install_unrestricted_read_access,
    monkeypatch,
) -> None:
    with session_factory() as session:
        _add_object(session, object_id="target", kind="host")
        session.commit()

    def fail_relationship(*args, **kwargs):
        raise RuntimeError("forced relationship failure")

    monkeypatch.setattr("blockwart.ui.routes.create_relationship", fail_relationship)

    with _unlocked_client(
        session_factory,
        install_unrestricted_read_access,
    ) as client:
        with pytest.raises(RuntimeError, match="forced relationship failure"):
            client.post(
                "/objects",
                data={
                    "object_id": "ui-partial",
                    "kind": "service",
                    "primary_name": "UI Partial",
                    "status": "active",
                    "data_json": '{"schema_version": 1}',
                    "relation_target_ref": "host:target",
                    "relation_type": "related_to",
                },
                follow_redirects=False,
            )

    with session_factory() as session:
        assert session.get(CatalogObject, "ui-partial") is None
        assert session.scalars(
            select(AuditEvent).where(AuditEvent.object_id == "ui-partial")
        ).all() == []


def test_multi_object_access_update_rolls_back_first_object(
    session_factory,
    install_unrestricted_read_access,
    monkeypatch,
) -> None:
    old_data = (
        '{"access_methods": [{"auth_mode": "key", "endpoint": "ssh://old", "type": "ssh"}], '
        '"schema_version": 1}'
    )
    with session_factory() as session:
        _add_object(session, object_id="access-a", data_json=old_data)
        _add_object(
            session,
            object_id="access-b",
            kind="service",
            data_json=old_data,
        )
        session.add(
            Relationship(
                from_ref="system:access-a",
                relation_type="hosts",
                to_ref="service:access-b",
            )
        )
        session.commit()

    calls = 0

    def fail_before_second_upsert(session: Session, payload: CatalogObjectIn):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise RuntimeError("forced second access update failure")
        return upsert_object(session, payload)

    monkeypatch.setattr("blockwart.ui.routes.upsert_object", fail_before_second_upsert)

    with _unlocked_client(
        session_factory,
        install_unrestricted_read_access,
    ) as client:
        with pytest.raises(RuntimeError, match="forced second access update failure"):
            client.post(
                "/objects/access-a/access",
                data={
                    "method_ref": ["system:access-a", "service:access-b"],
                    "method_index": ["0", "0"],
                    "method_type": ["ssh", "ssh"],
                    "method_endpoint": ["ssh://new-a", "ssh://new-b"],
                    "method_auth_mode": ["key-only", "key-only"],
                },
                follow_redirects=False,
            )

    with session_factory() as session:
        first = get_object(session, "access-a")
        second = get_object(session, "access-b")
        assert first is not None
        assert second is not None
        assert first.data["access_methods"][0]["endpoint"] == "ssh://old"
        assert second.data["access_methods"][0]["endpoint"] == "ssh://old"
        assert session.scalars(
            select(AuditEvent).where(AuditEvent.object_id.in_(["access-a", "access-b"]))
        ).all() == []


def test_import_services_flush_without_committing(
    tmp_path,
    alembic_database_factory,
) -> None:
    factory = alembic_database_factory(
        "import-commits.db",
        session_class=CommitCountingSession,
    ).sessions
    tools_path = tmp_path / "TOOLS.md"
    tools_path.write_text(
        "\n".join(
            [
                "| System | Typ | IP:Port | Status | Access | Auth | Nutzung | Ref | Skill |",
                "|--------|-----|---------|--------|--------|------|---------|-----|-------|",
                "| Atomic Demo | Service | 192.0.2.10:443 | ✅ | Web | none | Demo | - | - |",
            ]
        ),
        encoding="utf-8",
    )

    with factory() as session:
        import_seed_file(session, SEED_PATH)
        assert session.commit_calls == 0
        session.rollback()

    with factory() as session:
        import_tools_markdown(session, tools_path, references_root=tmp_path)
        assert session.commit_calls == 0
        session.rollback()

    with factory() as session:
        with transaction(session):
            import_seed_file(session, SEED_PATH)
        assert session.commit_calls == 1

    with factory() as session:
        session.query(AuditEvent).delete()
        session.query(Relationship).delete()
        session.query(CatalogObject).delete()
        session.commit()
        session.commit_calls = 0
        with transaction(session):
            import_tools_markdown(session, tools_path, references_root=tmp_path)
        assert session.commit_calls == 1


def test_markdown_replace_rolls_back_on_database_error(
    tmp_path,
    monkeypatch,
    capsys,
    alembic_database_factory,
) -> None:
    database = alembic_database_factory("replace.db")
    database_url = database.database_url
    factory = database.sessions
    with factory() as session:
        _add_object(session, object_id="must-survive")
        session.commit()

    tools_path = tmp_path / "TOOLS.md"
    tools_path.write_text(
        "\n".join(
            [
                "| System | Typ | IP:Port | Status | Access | Auth | Nutzung | Ref | Skill |",
                "|--------|-----|---------|--------|--------|------|---------|-----|-------|",
                "| Replacement | Service | 192.0.2.11:443 | ✅ | Web | none | Demo | - | - |",
            ]
        ),
        encoding="utf-8",
    )

    def fail_import(session: Session, *args, **kwargs):
        _add_object(session, object_id="partial-replacement")
        session.flush()
        raise OperationalError("INSERT", {}, RuntimeError("forced database error"))

    monkeypatch.setattr(import_markdown_cli, "import_tools_markdown", fail_import)

    exit_code = import_markdown_cli.main(
        [
            "--database-url",
            database_url,
            "--tools",
            str(tools_path),
            "--references-root",
            str(tmp_path),
            "--apply",
            "--replace",
        ]
    )

    assert exit_code == 1
    assert "markdown_import_error=database_transaction_failed" in capsys.readouterr().err
    with factory() as session:
        assert session.get(CatalogObject, "must-survive") is not None
        assert session.get(CatalogObject, "partial-replacement") is None


def test_markdown_replace_preserves_same_id_revision_monotonicity(
    tmp_path,
    alembic_database_factory,
) -> None:
    database = alembic_database_factory("replace-revision.db")
    with database.sessions() as session:
        _add_object(
            session,
            object_id="revision-demo",
            kind="service",
        )
        session.flush()
        session.get(CatalogObject, "revision-demo").revision = 7
        session.commit()

    tools_path = tmp_path / "TOOLS.md"
    tools_path.write_text(
        "\n".join(
            [
                "| System | Typ | IP:Port | Status | Access | Auth | Nutzung | Ref | Skill |",
                "|--------|-----|---------|--------|--------|------|---------|-----|-------|",
                "| Revision Demo | Service | 192.0.2.12:443 | ✅ | Web | none | Demo | - | - |",
            ]
        ),
        encoding="utf-8",
    )

    assert (
        import_markdown_cli.main(
            [
                "--database-url",
                database.database_url,
                "--tools",
                str(tools_path),
                "--references-root",
                str(tmp_path),
                "--apply",
                "--replace",
            ]
        )
        == 0
    )

    with database.sessions() as session:
        row = session.get(CatalogObject, "revision-demo")
        assert row is not None
        assert row.revision >= 8


def test_seed_cli_rolls_back_and_redacts_database_error(
    tmp_path,
    monkeypatch,
    capsys,
    alembic_database_factory,
) -> None:
    database = alembic_database_factory("seed-error.db")
    database_url = database.database_url
    factory = database.sessions
    with factory() as session:
        _add_object(session, object_id="seed-survivor")
        session.commit()

    def fail_seed(session: Session, *args, **kwargs):
        _add_object(session, object_id="partial-seed")
        session.flush()
        raise OperationalError("INSERT", {}, RuntimeError("sensitive forced database error"))

    monkeypatch.setattr(seed_cli, "import_seed_file", fail_seed)

    exit_code = seed_cli.main(
        [
            "--database-url",
            database_url,
            "--seed",
            str(SEED_PATH),
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == 1
    assert captured.err.strip() == "seed_error=database_transaction_failed"
    assert "sensitive" not in captured.err
    with factory() as session:
        assert session.get(CatalogObject, "seed-survivor") is not None
        assert session.get(CatalogObject, "partial-seed") is None


def test_ui_database_error_is_redacted_and_rolled_back(
    session_factory,
    install_unrestricted_read_access,
    monkeypatch,
) -> None:
    with session_factory() as session:
        _add_object(session, object_id="db-error-object")
        session.commit()

    def fail_upsert(session: Session, payload: CatalogObjectIn):
        session.get(CatalogObject, payload.id).label = "must roll back"
        session.add(
            AuditEvent(
                object_id=payload.id,
                action="partial",
                actor="test",
                summary="must roll back",
            )
        )
        session.flush()
        raise OperationalError("UPDATE", {}, RuntimeError("sensitive database detail"))

    monkeypatch.setattr("blockwart.ui.routes.upsert_object", fail_upsert)

    with _unlocked_client(
        session_factory,
        install_unrestricted_read_access,
    ) as client:
        response = client.post(
            "/objects/db-error-object/comment",
            data={"comment": "trigger"},
            follow_redirects=False,
        )

    assert response.status_code == 503
    assert response.json() == {"detail": "Database transaction failed"}
    assert "sensitive" not in response.text
    with session_factory() as session:
        row = session.get(CatalogObject, "db-error-object")
        assert row is not None
        assert row.label == "db-error-object"
        assert session.scalars(
            select(AuditEvent).where(AuditEvent.object_id == "db-error-object")
        ).all() == []


def test_delete_blocks_referenced_object_without_changing_data(session_factory) -> None:
    with session_factory() as session:
        _add_object(session, object_id="delete-parent", kind="host")
        _add_object(session, object_id="delete-child", kind="service")
        session.add(
            Relationship(
                from_ref="host:delete-parent",
                relation_type="hosts",
                to_ref="service:delete-child",
            )
        )
        session.commit()

    with pytest.raises(ValueError, match="cannot delete service:delete-child"):
        with session_factory() as session:
            with transaction(session):
                delete_object(session, "delete-child")

    with session_factory() as session:
        assert session.get(CatalogObject, "delete-child") is not None
        assert session.scalar(
            select(Relationship).where(Relationship.to_ref == "service:delete-child")
        ) is not None
        assert session.scalars(
            select(AuditEvent).where(AuditEvent.object_id == "delete-child")
        ).all() == []


def test_unreferenced_delete_rolls_back_with_audit_on_later_failure(
    session_factory,
) -> None:
    with session_factory() as session:
        _add_object(session, object_id="delete-unreferenced", kind="service")
        session.commit()

    with pytest.raises(RuntimeError, match="forced post-delete failure"):
        with session_factory() as session:
            with transaction(session):
                assert delete_object(session, "delete-unreferenced")
                raise RuntimeError("forced post-delete failure")

    with session_factory() as session:
        assert session.get(CatalogObject, "delete-unreferenced") is not None
        assert session.scalars(
            select(AuditEvent).where(AuditEvent.object_id == "delete-unreferenced")
        ).all() == []
