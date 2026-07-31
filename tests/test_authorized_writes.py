from __future__ import annotations

import json
from collections.abc import Generator
from concurrent.futures import ThreadPoolExecutor

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from blockwart.api.deps import get_session
from blockwart.db.session import transaction
from blockwart.domain.auth import GrantScope, Permission, Role
from blockwart.main import create_app
from blockwart.models import (
    AuditEvent,
    CatalogObject,
    IdempotencyRecord,
    ObjectGrant,
    Relationship,
    SecurityEvent,
)
from blockwart.schemas.catalog import CatalogObjectIn
from blockwart.services.access import create_object_grant
from blockwart.services.catalog import create_relationship, upsert_object
from blockwart.services.identity import (
    create_human_principal,
    create_service_account,
    issue_browser_session,
    issue_service_token,
)
from blockwart.ui.security import (
    AUTH_CSRF_COOKIE_NAME,
    AUTH_SESSION_COOKIE_NAME,
)


def _asset(
    object_id: str,
    *,
    kind: str = "service",
    label: str | None = None,
    summary: str | None = None,
) -> CatalogObjectIn:
    return CatalogObjectIn(
        id=object_id,
        kind=kind,
        label=label or object_id,
        lifecycle="active",
        health="healthy",
        summary=summary,
        data={"schema_version": 1},
    )


@pytest.fixture
def authorized_write_state(alembic_session_factory):
    with alembic_session_factory() as session:
        with transaction(session):
            parent = upsert_object(
                session,
                _asset("write-parent", kind="host", label="Write Parent"),
            )
            editable = upsert_object(session, _asset("editable", summary="before"))
            peer = upsert_object(session, _asset("peer"))
            deletable = upsert_object(session, _asset("deletable"))
            principal = create_service_account(
                session,
                login="authorized.writer",
                display_name="Authorized Writer",
            )
            create_object_grant(
                session,
                principal_id=principal.id,
                object_id=parent.id,
                role=Role.CREATOR,
                scope=GrantScope.SELF,
            )
            create_object_grant(
                session,
                principal_id=principal.id,
                object_id=editable.id,
                role=Role.EDITOR,
                scope=GrantScope.SELF,
            )
            create_object_grant(
                session,
                principal_id=principal.id,
                object_id=peer.id,
                role=Role.DISCOVERER,
                scope=GrantScope.SELF,
            )
            create_object_grant(
                session,
                principal_id=principal.id,
                object_id=deletable.id,
                role=Role.OWNER,
                scope=GrantScope.SELF,
            )
            token = issue_service_token(
                session,
                principal_id=principal.id,
                name="writes",
            )
    return alembic_session_factory, principal.id, token.value


@pytest.fixture
def authorized_write_client(
    authorized_write_state,
) -> Generator[TestClient, None, None]:
    session_factory, _, _ = authorized_write_state
    app = create_app()

    def override_get_session() -> Generator[Session, None, None]:
        with session_factory() as session:
            yield session

    app.dependency_overrides[get_session] = override_get_session
    with TestClient(app) as client:
        yield client


def _authorization(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def test_create_child_is_atomic_audited_and_idempotent(
    authorized_write_client: TestClient,
    authorized_write_state,
) -> None:
    session_factory, principal_id, token = authorized_write_state
    headers = {
        **_authorization(token),
        "Idempotency-Key": "create-child-key-0001",
    }
    payload = _asset("created-child", summary="created once").model_dump(mode="json")

    first = authorized_write_client.post(
        "/api/v1/objects/write-parent/children",
        headers=headers,
        json=payload,
    )
    replay = authorized_write_client.post(
        "/api/v1/objects/write-parent/children",
        headers=headers,
        json=payload,
    )

    assert first.status_code == 201, first.text
    assert replay.status_code == 201, replay.text
    assert first.headers["etag"] == '"rev-1"'
    assert set(first.json()["catalog_object"]["capabilities"]) == {
        permission.value for permission in Permission
    }
    assert replay.json() == {**first.json(), "replayed": True}
    with session_factory() as session:
        assert session.scalar(
            select(func.count())
            .select_from(CatalogObject)
            .where(CatalogObject.id == "created-child")
        ) == 1
        assert session.scalar(
            select(func.count())
            .select_from(Relationship)
            .where(
                Relationship.from_ref == "host:write-parent",
                Relationship.relation_type == "hosts",
                Relationship.to_ref == "service:created-child",
            )
        ) == 1
        owner = session.scalar(
            select(ObjectGrant).where(ObjectGrant.object_id == "created-child")
        )
        assert owner is not None
        assert owner.principal_id == principal_id
        assert (owner.role, owner.scope) == ("owner", "self")
        events = session.scalars(
            select(AuditEvent).where(AuditEvent.object_id == "created-child")
        ).all()
        assert len(events) == 1
        assert events[0].action == "create"
        assert events[0].actor == principal_id
        record = session.scalar(select(IdempotencyRecord))
        assert record is not None
        assert "create-child-key-0001" not in record.key_hash
        assert "create-child-key-0001" not in record.response_json


def test_idempotency_key_conflict_has_no_partial_write(
    authorized_write_client: TestClient,
    authorized_write_state,
) -> None:
    session_factory, _, token = authorized_write_state
    headers = {
        **_authorization(token),
        "Idempotency-Key": "create-child-key-0002",
    }
    first = authorized_write_client.post(
        "/api/v1/objects/write-parent/children",
        headers=headers,
        json=_asset("first-child").model_dump(mode="json"),
    )
    conflict = authorized_write_client.post(
        "/api/v1/objects/write-parent/children",
        headers=headers,
        json=_asset("second-child").model_dump(mode="json"),
    )

    assert first.status_code == 201
    assert conflict.status_code == 409
    assert conflict.json()["error"]["code"] == "conflict"
    with session_factory() as session:
        assert session.get(CatalogObject, "second-child") is None
        assert session.scalar(
            select(func.count())
            .select_from(AuditEvent)
            .where(AuditEvent.object_id == "second-child")
        ) == 0


def test_update_requires_current_etag_and_denied_delete_is_security_only(
    authorized_write_client: TestClient,
    authorized_write_state,
) -> None:
    session_factory, principal_id, token = authorized_write_state
    auth = _authorization(token)
    current = authorized_write_client.get("/api/v1/objects/editable", headers=auth)
    assert current.status_code == 200
    etag = current.headers["etag"]
    payload = _asset("editable", summary="after").model_dump(mode="json")

    missing = authorized_write_client.put(
        "/api/v1/objects/editable",
        headers=auth,
        json=payload,
    )
    updated = authorized_write_client.put(
        "/api/v1/objects/editable",
        headers={**auth, "If-Match": etag},
        json=payload,
    )
    stale = authorized_write_client.put(
        "/api/v1/objects/editable",
        headers={**auth, "If-Match": etag},
        json=_asset("editable", summary="lost update").model_dump(mode="json"),
    )
    denied_delete = authorized_write_client.delete(
        "/api/v1/objects/editable",
        headers={**auth, "If-Match": updated.headers["etag"]},
    )

    assert missing.status_code == 428
    assert updated.status_code == 200
    assert updated.json()["catalog_object"]["summary"] == "after"
    assert stale.status_code == 412
    assert denied_delete.status_code == 403
    with session_factory() as session:
        row = session.get(CatalogObject, "editable")
        assert row is not None
        assert row.summary == "after"
        events = session.scalars(
            select(AuditEvent)
            .where(AuditEvent.object_id == "editable")
            .order_by(AuditEvent.id)
        ).all()
        assert [event.action for event in events].count("update") == 1
        denial = session.scalar(
            select(SecurityEvent)
            .where(
                SecurityEvent.principal_id == principal_id,
                SecurityEvent.event_type == "object_command_authorization",
            )
            .order_by(SecurityEvent.id.desc())
        )
        assert denial is not None
        assert denial.outcome == "denied"
        assert '"permission":"delete"' in denial.details_json


def test_relationship_mutations_use_target_etag_and_one_audit_each(
    authorized_write_client: TestClient,
    authorized_write_state,
) -> None:
    session_factory, _, token = authorized_write_state
    auth = _authorization(token)
    detail = authorized_write_client.get("/api/v1/objects/editable", headers=auth)
    relationship = {
        "from_ref": "service:editable",
        "relation_type": "depends_on",
        "to_ref": "service:peer",
    }

    created = authorized_write_client.post(
        "/api/v1/objects/editable/relationships",
        headers={**auth, "If-Match": detail.headers["etag"]},
        json=relationship,
    )
    deleted = authorized_write_client.request(
        "DELETE",
        "/api/v1/objects/editable/relationships",
        headers={**auth, "If-Match": created.headers["etag"]},
        json=relationship,
    )

    assert created.status_code == 200, created.text
    assert deleted.status_code == 200, deleted.text
    assert created.json()["changed"] is True
    assert deleted.json()["changed"] is True
    with session_factory() as session:
        assert session.scalar(
            select(func.count())
            .select_from(Relationship)
            .where(Relationship.from_ref == "service:editable")
        ) == 0
        actions = session.scalars(
            select(AuditEvent.action)
            .where(AuditEvent.object_id == "editable")
            .order_by(AuditEvent.id)
        ).all()
        assert actions.count("relationship_create") == 1
        assert actions.count("relationship_delete") == 1


def test_delete_permission_is_separate_and_audit_survives_object(
    authorized_write_client: TestClient,
    authorized_write_state,
) -> None:
    session_factory, principal_id, token = authorized_write_state
    auth = _authorization(token)
    detail = authorized_write_client.get("/api/v1/objects/deletable", headers=auth)

    deleted = authorized_write_client.delete(
        "/api/v1/objects/deletable",
        headers={**auth, "If-Match": detail.headers["etag"]},
    )

    assert deleted.status_code == 200, deleted.text
    with session_factory() as session:
        assert session.get(CatalogObject, "deletable") is None
        assert session.scalar(
            select(func.count())
            .select_from(ObjectGrant)
            .where(ObjectGrant.object_id == "deletable")
        ) == 0
        event = session.scalar(
            select(AuditEvent)
            .where(
                AuditEvent.object_id == "deletable",
                AuditEvent.action == "delete",
            )
            .order_by(AuditEvent.id.desc())
        )
        assert event is not None
        assert event.actor == principal_id


def test_parallel_updates_allow_exactly_one_current_etag_winner(
    authorized_write_state,
) -> None:
    session_factory, _, token = authorized_write_state
    app = create_app()

    def override_get_session() -> Generator[Session, None, None]:
        with session_factory() as session:
            yield session

    app.dependency_overrides[get_session] = override_get_session
    auth = _authorization(token)
    with TestClient(app) as client:
        etag = client.get("/api/v1/objects/editable", headers=auth).headers["etag"]

        def update(summary: str) -> int:
            return client.put(
                "/api/v1/objects/editable",
                headers={**auth, "If-Match": etag},
                json=_asset("editable", summary=summary).model_dump(mode="json"),
            ).status_code

        with ThreadPoolExecutor(max_workers=2) as pool:
            statuses = list(pool.map(update, ("parallel-a", "parallel-b")))

    assert sorted(statuses) == [200, 412]
    with session_factory() as session:
        assert session.get(CatalogObject, "editable").summary in {
            "parallel-a",
            "parallel-b",
        }


def test_parallel_same_key_create_returns_one_object_and_one_audit(
    authorized_write_state,
) -> None:
    session_factory, _, token = authorized_write_state
    app = create_app()

    def override_get_session() -> Generator[Session, None, None]:
        with session_factory() as session:
            yield session

    app.dependency_overrides[get_session] = override_get_session
    headers = {
        **_authorization(token),
        "Idempotency-Key": "parallel-create-key-001",
    }
    payload = _asset("parallel-child").model_dump(mode="json")
    with TestClient(app) as client:
        with ThreadPoolExecutor(max_workers=2) as pool:
            responses = list(
                pool.map(
                    lambda _: client.post(
                        "/api/v1/objects/write-parent/children",
                        headers=headers,
                        json=payload,
                    ),
                    range(2),
                )
            )

    assert [response.status_code for response in responses] == [201, 201]
    assert sorted(response.json()["replayed"] for response in responses) == [
        False,
        True,
    ]
    with session_factory() as session:
        assert session.scalar(
            select(func.count())
            .select_from(CatalogObject)
            .where(CatalogObject.id == "parallel-child")
        ) == 1
        assert session.scalar(
            select(func.count())
            .select_from(AuditEvent)
            .where(
                AuditEvent.object_id == "parallel-child",
                AuditEvent.action == "create",
            )
        ) == 1


def test_blocked_delete_rolls_back_claim_grants_and_audit(
    authorized_write_client: TestClient,
    authorized_write_state,
) -> None:
    session_factory, _, token = authorized_write_state
    with session_factory() as session:
        with transaction(session):
            create_relationship(
                session,
                from_ref="service:deletable",
                relation_type="depends_on",
                to_ref="service:peer",
            )
        before_revision = session.get(CatalogObject, "deletable").revision
        before_grants = session.scalar(
            select(func.count())
            .select_from(ObjectGrant)
            .where(ObjectGrant.object_id == "deletable")
        )
    blocked = authorized_write_client.delete(
        "/api/v1/objects/deletable",
        headers={
            **_authorization(token),
            "If-Match": f'"rev-{before_revision}"',
        },
    )

    assert blocked.status_code == 409
    with session_factory() as session:
        row = session.get(CatalogObject, "deletable")
        assert row is not None
        assert row.revision == before_revision
        assert session.scalar(
            select(func.count())
            .select_from(ObjectGrant)
            .where(ObjectGrant.object_id == "deletable")
        ) == before_grants
        assert session.scalar(
            select(func.count())
            .select_from(AuditEvent)
            .where(
                AuditEvent.object_id == "deletable",
                AuditEvent.action == "delete",
            )
        ) == 0


def test_full_object_read_namespaces_publish_same_revision_etag(
    authorized_write_client: TestClient,
    authorized_write_state,
) -> None:
    _, _, token = authorized_write_state
    auth = _authorization(token)
    catalog = authorized_write_client.get("/api/objects/editable", headers=auth)
    agent = authorized_write_client.get("/api/agent/objects/editable", headers=auth)
    v1 = authorized_write_client.get("/api/v1/objects/editable", headers=auth)

    assert catalog.status_code == agent.status_code == v1.status_code == 200
    assert catalog.headers["etag"] == agent.headers["etag"] == v1.headers["etag"]
    revision = catalog.json()["revision"]
    assert agent.json()["objects"][0]["revision"] == revision
    assert v1.json()["revision"] == revision


def test_mcp_reported_channel_is_preserved_in_command_audit(
    authorized_write_client: TestClient,
    authorized_write_state,
) -> None:
    session_factory, _, token = authorized_write_state
    auth = _authorization(token)
    detail = authorized_write_client.get("/api/v1/objects/editable", headers=auth)
    response = authorized_write_client.put(
        "/api/v1/objects/editable",
        headers={
            **auth,
            "If-Match": detail.headers["etag"],
            "X-Blockwart-Channel": "mcp",
        },
        json=_asset("editable", summary="through MCP").model_dump(mode="json"),
    )

    assert response.status_code == 200
    with session_factory() as session:
        event = session.scalar(
            select(AuditEvent)
            .where(
                AuditEvent.object_id == "editable",
                AuditEvent.action == "update",
            )
            .order_by(AuditEvent.id.desc())
        )
        assert event is not None
        assert '"channel":"mcp"' in event.details_json


def test_command_audit_redacts_secret_shaped_legacy_before_state(
    authorized_write_client: TestClient,
    authorized_write_state,
) -> None:
    session_factory, _, token = authorized_write_state
    leaked_value = "Bearer abcdefghijklmnopqrstuvwxyz0123456789"
    with session_factory() as session:
        with transaction(session):
            row = session.get(CatalogObject, "editable")
            assert row is not None
            row.data_json = json.dumps(
                {
                    "schema_version": 1,
                    "password": leaked_value,
                    "note": leaked_value,
                }
            )
    auth = _authorization(token)
    detail = authorized_write_client.get("/api/v1/objects/editable", headers=auth)
    response = authorized_write_client.put(
        "/api/v1/objects/editable",
        headers={**auth, "If-Match": detail.headers["etag"]},
        json=_asset("editable", summary="legacy secret removed").model_dump(
            mode="json"
        ),
    )

    assert response.status_code == 200
    with session_factory() as session:
        event = session.scalar(
            select(AuditEvent)
            .where(
                AuditEvent.object_id == "editable",
                AuditEvent.action == "update",
            )
            .order_by(AuditEvent.id.desc())
        )
        assert event is not None
        assert leaked_value not in event.details_json
        assert "[redacted-secret-field]" in event.details_json


def test_browser_ui_uses_same_policy_etag_csrf_and_command_audit(
    alembic_session_factory,
) -> None:
    with alembic_session_factory() as session:
        with transaction(session):
            parent = upsert_object(
                session,
                _asset("ui-parent", kind="host", label="UI Parent"),
            )
            editable = upsert_object(
                session,
                _asset("ui-editable", summary="before UI"),
            )
            principal = create_human_principal(
                session,
                login="ui.writer",
                display_name="UI Writer",
                password="ui-writer-password-with-safe-length",
            )
            create_object_grant(
                session,
                principal_id=principal.id,
                object_id=parent.id,
                role=Role.CREATOR,
                scope=GrantScope.SELF,
            )
            create_object_grant(
                session,
                principal_id=principal.id,
                object_id=editable.id,
                role=Role.EDITOR,
                scope=GrantScope.SELF,
            )
            browser = issue_browser_session(
                session,
                principal_id=principal.id,
                ttl_seconds=3600,
            )
    app = create_app()

    def override_get_session() -> Generator[Session, None, None]:
        with alembic_session_factory() as session:
            yield session

    app.dependency_overrides[get_session] = override_get_session
    with TestClient(app) as client:
        client.cookies.set(AUTH_SESSION_COOKIE_NAME, browser.value)
        client.cookies.set(AUTH_CSRF_COOKIE_NAME, browser.csrf_token)
        edit = client.get("/objects/ui-editable?edit=overview")
        assert edit.status_code == 200
        assert f'value="{browser.csrf_token}"' in edit.text
        assert 'name="if_match"' in edit.text
        etag = edit.headers["etag"]

        wrong_csrf = client.post(
            "/objects/ui-editable",
            headers={"X-Correlation-ID": "ui-csrf-correlation"},
            data={
                "csrf_token": "wrong-csrf-token",
                "if_match": etag,
                "primary_name": "must-not-apply",
            },
            follow_redirects=False,
        )
        updated = client.post(
            "/objects/ui-editable",
            headers={"X-Correlation-ID": "ui-update-correlation"},
            data={
                "csrf_token": browser.csrf_token,
                "if_match": etag,
                "primary_name": "UI Updated",
                "summary": "after UI",
            },
            follow_redirects=False,
        )

        index = client.get("/?create=1")
        assert index.status_code == 200
        assert "idempotency_key" in index.text
        created = client.post(
            "/objects",
            headers={"X-Correlation-ID": "ui-create-correlation"},
            data={
                "csrf_token": browser.csrf_token,
                "idempotency_key": "browser-create-key-0001",
                "object_id": "ui-created",
                "kind": "system",
                "primary_name": "UI Created",
                "status": "active",
                "relation_target_ref": "host:ui-parent",
                "relation_type": "hosts",
                "data_json": '{"schema_version":1}',
            },
            follow_redirects=False,
        )
        unplaced = client.post(
            "/objects",
            headers={"X-Correlation-ID": "ui-unplaced-correlation"},
            data={
                "csrf_token": browser.csrf_token,
                "idempotency_key": "browser-create-key-unplaced",
                "object_id": "ui-unplaced",
                "kind": "system",
                "primary_name": "UI Unplaced",
                "status": "active",
                "data_json": '{"schema_version":1}',
            },
            follow_redirects=False,
        )

    assert wrong_csrf.status_code == 403
    assert updated.status_code == 303
    assert created.status_code == 303, created.text
    assert unplaced.status_code == 422
    assert wrong_csrf.headers["X-Correlation-ID"] == "ui-csrf-correlation"
    assert updated.headers["X-Correlation-ID"] == "ui-update-correlation"
    assert created.headers["X-Correlation-ID"] == "ui-create-correlation"
    with alembic_session_factory() as session:
        row = session.get(CatalogObject, "ui-editable")
        assert row is not None
        assert (row.label, row.summary) == ("UI Updated", "after UI")
        assert session.get(CatalogObject, "ui-unplaced") is None
        events = session.scalars(
            select(AuditEvent)
            .where(AuditEvent.object_id.in_(["ui-editable", "ui-created"]))
            .order_by(AuditEvent.id)
        ).all()
        command_events = [
            event for event in events if event.actor == principal.id
        ]
        assert [event.action for event in command_events] == ["update", "create"]
        assert all('"channel":"ui"' in event.details_json for event in command_events)
        assert '"request_id":"ui-update-correlation"' in command_events[0].details_json
        assert '"request_id":"ui-create-correlation"' in command_events[1].details_json
        denial = session.scalar(
            select(SecurityEvent)
            .where(SecurityEvent.event_type == "browser_write_csrf")
            .order_by(SecurityEvent.id.desc())
        )
        assert denial is not None
        assert denial.outcome == "denied"
        assert denial.request_id == "ui-csrf-correlation"
