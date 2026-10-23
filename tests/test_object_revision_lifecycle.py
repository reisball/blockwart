"""An ETag cannot outlive the catalog object it originally identified. Refs #272."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from blockwart.api.deps import get_session
from blockwart.config import Settings
from blockwart.db.session import transaction
from blockwart.domain.auth import CatalogRole
from blockwart.main import create_app
from blockwart.schemas.catalog import CatalogObjectIn
from blockwart.services.catalog import (
    RevisionConflict,
    apply_object_upsert,
    delete_object,
    plan_object_upsert,
    upsert_object,
)
from blockwart.services.identity import create_service_account, issue_service_token


def test_recreated_object_rejects_old_put_and_delete(alembic_database):
    db = alembic_database
    with db.sessions() as session, transaction(session):
        actor = create_service_account(
            session,
            login="lifecycle.owner",
            display_name="Owner",
            catalog_role=CatalogRole.CATALOG_OWNER,
        )
        token = issue_service_token(session, principal_id=actor.id, name="lifecycle")
    app = create_app(
        Settings(
            _env_file=None,
            database_url=db.database_url,
            monitoring_poller_enabled=False,
            release_monitoring_poller_enabled=False,
        )
    )

    def dep():
        with db.sessions() as session:
            yield session

    app.dependency_overrides[get_session] = dep
    with TestClient(app) as client:
        headers = {"Authorization": "Bearer " + token.value}
        payload = {
            "id": "reused",
            "kind": "host",
            "label": "Original",
            "data": {"schema_version": 1},
        }
        old = client.post(
            "/api/v1/roots",
            headers={**headers, "Idempotency-Key": "lifecycle-old-01"},
            json=payload,
        )
        assert old.status_code == 201, old.text
        old_etag = old.headers["etag"]
        assert (
            client.delete(
                "/api/v1/objects/reused", headers={**headers, "If-Match": old_etag}
            ).status_code
            == 200
        )
        new = client.post(
            "/api/v1/roots",
            headers={**headers, "Idempotency-Key": "lifecycle-new-01"},
            json={**payload, "label": "Replacement"},
        )
        assert new.status_code == 201, new.text
        for method in ("put", "delete"):
            kwargs = {"json": payload} if method == "put" else {}
            response = getattr(client, method)(
                "/api/v1/objects/reused", headers={**headers, "If-Match": old_etag}, **kwargs
            )
            assert response.status_code == 412, response.text
        assert new.headers["etag"] != old_etag
        fresh = client.put(
            "/api/v1/objects/reused",
            headers={**headers, "If-Match": new.headers["etag"]},
            json={**payload, "label": "Fresh write"},
        )
        assert fresh.status_code == 200, fresh.text


@pytest.mark.parametrize("unchanged", [False, True])
def test_plan_cannot_claim_replacement_instance(alembic_database, unchanged):
    """The atomic SQL claim, not only the request-level read, must reject ABA."""
    engine = alembic_database.engine
    original = CatalogObjectIn(
        id="reused", kind="host", label="Original", data={"schema_version": 1}
    )
    with Session(engine) as session, transaction(session):
        old = upsert_object(session, original)
    with Session(engine) as reader:
        candidate = original if unchanged else original.model_copy(update={"label": "Delayed"})
        plan = plan_object_upsert(reader, candidate, expected_revision=old.revision)
        # Release the SQLite read transaction while retaining the stale plan.
        reader.commit()
        with Session(engine) as writer, transaction(writer):
            assert delete_object(writer, "reused")
            upsert_object(writer, original.model_copy(update={"label": "Replacement"}))
        with pytest.raises(RevisionConflict), transaction(reader):
            apply_object_upsert(reader, plan)


def test_revision_history_survives_multiple_lifecycles_and_rollback(alembic_database):
    from sqlalchemy import delete

    from blockwart.models import CatalogObject, ObjectRevisionClock

    db = alembic_database
    payload = CatalogObjectIn(id="clocked", kind="host", label="First", data={"schema_version": 1})
    with db.sessions() as session, transaction(session):
        old = upsert_object(session, payload)
        for i in range(4):
            old = upsert_object(session, payload.model_copy(update={"label": f"Update {i}"}))
        old_revision = old.revision
        # Raw SQL deletion must retain the floor, too (not only REST/domain deletes).
        session.execute(delete(CatalogObject).where(CatalogObject.id == payload.id))
    with db.sessions() as session:
        row = upsert_object(session, payload)
        assert row.revision > old_revision
        session.rollback()
    with db.sessions() as session, transaction(session):
        replacement = upsert_object(session, payload)
        assert replacement.revision == old_revision + 1
        assert session.get(ObjectRevisionClock, payload.id).revision == replacement.revision


def test_downgrade_refuses_to_discard_revision_history(alembic_database):
    from alembic import command

    from blockwart.db.migrations import build_alembic_config

    with alembic_database.sessions() as session, transaction(session):
        upsert_object(
            session,
            CatalogObjectIn(
                id="retained", kind="host", label="Retained", data={"schema_version": 1}
            ),
        )
        assert delete_object(session, "retained")
    with pytest.raises(RuntimeError, match="Refusing to discard object revision history"):
        command.downgrade(build_alembic_config(alembic_database.database_url), "20261022_0027")
