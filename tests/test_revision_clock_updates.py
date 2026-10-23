"""Review-only reproducer. No repository files are modified."""

import os
import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from blockwart.api.deps import get_session
from blockwart.config import Settings
from blockwart.db.migrations import upgrade_database
from blockwart.db.session import build_engine, transaction
from blockwart.domain.auth import CatalogRole
from blockwart.main import create_app
from blockwart.services import seeds
from blockwart.services.identity import create_service_account, issue_service_token


@pytest.fixture(params=["sqlite", "postgresql"])
def db(request, tmp_path):
    admin = None
    name = "bw_review_" + uuid.uuid4().hex[:12]
    if request.param == "postgresql":
        base = os.environ["BLOCKWART_TEST_PG_URL"].rsplit("/", 1)[0]
        admin = create_engine(base + "/postgres", isolation_level="AUTOCOMMIT")
        with admin.connect() as c:
            c.execute(text(f'CREATE DATABASE "{name}"'))
        url = base + "/" + name
    else:
        url = "sqlite:///" + str(tmp_path / "review.db")
    engine = None
    try:
        upgrade_database(url)
        engine = build_engine(url)
        yield url, engine, sessionmaker(bind=engine, autoflush=False)
    finally:
        if engine is not None:
            engine.dispose()
        if admin is not None:
            with admin.connect() as c:
                c.execute(text(f'DROP DATABASE "{name}" WITH (FORCE)'))
            admin.dispose()


def test_seed_interleaving_must_not_reuse_a_published_etag(db, monkeypatch):
    url, engine, sessions = db
    payload = {"id": "reused", "kind": "host", "label": "Original", "data": {"schema_version": 1}}
    seed = {"schema_version": 1, "objects": [payload], "relationships": []}
    with sessions() as s, transaction(s):
        owner = create_service_account(
            s,
            login="review.owner",
            display_name="Review owner",
            catalog_role=CatalogRole.CATALOG_OWNER,
        )
        owner_id = owner.id
        token = issue_service_token(s, principal_id=owner_id, name="review").value
        seeds.import_seed_payload(s, seed, owner_principal_id=owner_id)
    app = create_app(
        Settings(
            _env_file=None,
            database_url=url,
            monitoring_poller_enabled=False,
            release_monitoring_poller_enabled=False,
        )
    )

    def dep():
        with sessions() as s:
            yield s

    app.dependency_overrides[get_session] = dep
    auth = {"Authorization": "Bearer " + token}
    saved = {}
    with TestClient(app) as client:
        original_check = seeds.ensure_kind_change_allowed

        def interleave(session, row, kind):
            assert row.revision == 1
            etag = '"rev-1"'
            for revision in (2, 3, 4):
                # Seed already holds Owner locks. Do not synchronously call an
                # authorized API writer that is correctly serialized behind it.
                with engine.begin() as writer:
                    writer.execute(text(
                        "UPDATE catalog_objects SET label=:label, revision=:revision "
                        "WHERE id='reused'"
                    ), {"label": f"Published {revision}", "revision": revision})
                etag = f'"rev-{revision}"'
            saved["old_etag"] = etag
            original_check(session, row, kind)

        monkeypatch.setattr(seeds, "ensure_kind_change_allowed", interleave)
        with sessions() as s, transaction(s):
            seeds.import_seed_payload(
                s,
                {**seed, "objects": [{**payload, "label": "Delayed seed"}]},
                owner_principal_id=owner_id,
            )
        with engine.connect() as c:
            revision = c.execute(
                text("SELECT revision FROM catalog_objects WHERE id='reused'")
            ).scalar_one()
            floor = c.execute(
                text("SELECT revision FROM object_revision_clocks WHERE object_id='reused'")
            ).scalar_one()
        response = client.delete(
            "/api/v1/objects/reused", headers={**auth, "If-Match": f'"rev-{revision}"'}
        )
        assert response.status_code == 200, response.text
        response = client.post(
            "/api/v1/roots",
            headers={**auth, "Idempotency-Key": "review-replacement-01"},
            json={**payload, "label": "Replacement"},
        )
        assert response.status_code == 201, response.text
        replacement_etag = response.headers["etag"]
        response = client.put(
            "/api/v1/objects/reused",
            headers={**auth, "If-Match": saved["old_etag"]},
            json={**payload, "label": "STALE TOKEN WRITE"},
        )
        print(
            engine.dialect.name,
            {
                "old_etag": saved["old_etag"],
                "revision_after_seed": revision,
                "clock_after_seed": floor,
                "replacement_etag": replacement_etag,
                "stale_put_status": response.status_code,
            },
        )
        assert response.status_code == 412, response.text


def test_every_update_keeps_the_clock_and_representation_revision_monotone(db):
    """Cover lower/equal explicit revisions, omitted increments and true SQL no-op."""
    _, engine, sessions = db
    from blockwart.schemas.catalog import CatalogObjectIn
    from blockwart.services.catalog import upsert_object

    with sessions() as session, transaction(session):
        upsert_object(
            session,
            CatalogObjectIn(
                id="clock-update", kind="host", label="First", data={"schema_version": 1}
            ),
        )
    with engine.begin() as connection:

        def state():
            return connection.execute(
                text(
                    "SELECT c.revision, k.revision FROM catalog_objects c "
                    "JOIN object_revision_clocks k ON k.object_id=c.id WHERE c.id=:id"
                ),
                {"id": "clock-update"},
            ).one()

        assert state() == (1, 1)
        connection.execute(
            text("UPDATE catalog_objects SET revision=4, label=:label WHERE id=:id"),
            {"id": "clock-update", "label": "Higher revision"},
        )
        assert state() == (4, 4)
        connection.execute(
            text("UPDATE catalog_objects SET revision=2, label=:label WHERE id=:id"),
            {"id": "clock-update", "label": "Stale cached increment"},
        )
        assert state() == (5, 5)
        connection.execute(
            text("UPDATE catalog_objects SET summary=:summary WHERE id=:id"),
            {"id": "clock-update", "summary": "Omitted increment"},
        )
        assert state() == (6, 6)
        connection.execute(
            text("UPDATE catalog_objects SET summary=summary WHERE id=:id"), {"id": "clock-update"}
        )
        assert state() == (6, 6)
        # Advancing a raw revision is retained even when deletion follows a lower write.
        connection.execute(
            text("UPDATE catalog_objects SET revision=3 WHERE id=:id"), {"id": "clock-update"}
        )
        assert state() == (7, 7)
        connection.execute(text("DELETE FROM catalog_objects WHERE id=:id"), {"id": "clock-update"})
    with sessions() as session, transaction(session):
        replacement = upsert_object(
            session,
            CatalogObjectIn(
                id="clock-update", kind="host", label="Replacement", data={"schema_version": 1}
            ),
        )
        assert replacement.revision == 8


def test_sqlite_recursive_update_guard_terminates_and_preserves_noop(alembic_database):
    from blockwart.schemas.catalog import CatalogObjectIn
    from blockwart.services.catalog import upsert_object

    engine = alembic_database.engine
    with engine.begin() as connection:
        connection.execute(text("PRAGMA recursive_triggers=ON"))
    with alembic_database.sessions() as session, transaction(session):
        upsert_object(
            session,
            CatalogObjectIn(id="recursive", kind="host", label="First", data={"schema_version": 1}),
        )
    with engine.begin() as connection:
        connection.execute(text("PRAGMA recursive_triggers=ON"))
        connection.execute(text("UPDATE catalog_objects SET label='Changed' WHERE id='recursive'"))
        assert (
            connection.scalar(text("SELECT revision FROM catalog_objects WHERE id='recursive'"))
            == 2
        )
        connection.execute(text("UPDATE catalog_objects SET label=label WHERE id='recursive'"))
        assert (
            connection.scalar(text("SELECT revision FROM catalog_objects WHERE id='recursive'"))
            == 2
        )


def test_ignored_insert_and_noop_upsert_do_not_reserve_revisions(db):
    """PostgreSQL conflict resolution must not publish an invisible clock advance."""
    url, engine, sessions = db
    with sessions() as session, transaction(session):
        owner = create_service_account(
            session,
            login="conflict.owner",
            display_name="Owner",
            catalog_role=CatalogRole.CATALOG_OWNER,
        )
        token = issue_service_token(session, principal_id=owner.id, name="conflict").value
    app = create_app(
        Settings(
            _env_file=None,
            database_url=url,
            monitoring_poller_enabled=False,
            release_monitoring_poller_enabled=False,
        )
    )

    def dep():
        with sessions() as session:
            yield session

    app.dependency_overrides[get_session] = dep
    auth = {"Authorization": "Bearer " + token}
    with TestClient(app) as client:
        for name in ("target", "peer"):
            made = client.post(
                "/api/v1/roots",
                headers={**auth, "Idempotency-Key": "root-" + name + "-conflict-01"},
                json={"id": name, "kind": "host", "label": name, "data": {"schema_version": 1}},
            )
            assert made.status_code == 201, made.text
        target = client.get("/api/v1/objects/target", headers=auth)
        with engine.begin() as connection:
            for _ in range(2):
                connection.execute(
                    text(
                        "INSERT INTO catalog_objects SELECT * FROM catalog_objects "
                        "WHERE id='target' ON CONFLICT(id) DO NOTHING"
                    )
                )
            connection.execute(
                text(
                    "INSERT INTO catalog_objects SELECT * FROM catalog_objects "
                    "WHERE id='target' ON CONFLICT(id) DO UPDATE SET label=excluded.label"
                )
            )
            connection.execute(text("UPDATE catalog_objects SET label=label WHERE id='target'"))
            assert (
                connection.scalar(text("SELECT revision FROM catalog_objects WHERE id='target'"))
                == 1
            )
            assert (
                connection.scalar(
                    text("SELECT revision FROM object_revision_clocks WHERE object_id='target'")
                )
                == 1
            )
        relationship = {
            "from_ref": "host:target",
            "relation_type": "related_to",
            "to_ref": "host:peer",
        }
        created = client.post(
            "/api/v1/objects/target/relationships",
            headers={**auth, "If-Match": target.headers["etag"]},
            json=relationship,
        )
        assert created.status_code == 200, created.text
        current = client.get("/api/v1/objects/target", headers=auth)
        assert created.headers["etag"] == current.headers["etag"]
        deleted = client.request(
            "DELETE",
            "/api/v1/objects/target/relationships",
            headers={**auth, "If-Match": created.headers["etag"]},
            json=relationship,
        )
        assert deleted.status_code == 200, deleted.text
