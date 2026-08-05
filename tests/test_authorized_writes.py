from __future__ import annotations

import json
from collections.abc import Generator
from concurrent.futures import ThreadPoolExecutor
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import event as sqlalchemy_event
from sqlalchemy import func, select, update
from sqlalchemy.orm import Session

from blockwart.api.deps import get_session
from blockwart.db.session import transaction
from blockwart.domain.auth import GrantScope, Permission, Role
from blockwart.main import create_app
from blockwart.mcp.server import call_tool
from blockwart.models import (
    AuditEvent,
    CatalogObject,
    IdempotencyRecord,
    ObjectComment,
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


def _successful_mcp_fetcher(client: TestClient, token: str):
    def fetch(path: str, params: dict) -> dict:
        response = client.get(
            path,
            params={key: value for key, value in params.items() if value is not None},
            headers=_authorization(token),
        )
        response.raise_for_status()
        return response.json()

    return fetch


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


def test_object_comments_are_append_only_idempotent_audience_bound_and_redacted(
    authorized_write_client: TestClient,
    authorized_write_state,
) -> None:
    session_factory, principal_id, api_token = authorized_write_state
    with session_factory() as session:
        before = session.get(CatalogObject, "editable")
        assert before is not None
        before_revision = before.revision
        before_updated_at = before.updated_at

    headers = {
        **_authorization(api_token),
        "Idempotency-Key": "object-comment-key-0001",
    }
    payload = {"body": "# Work log\n\n**Restarted** safely."}
    first = authorized_write_client.post(
        "/api/v1/objects/editable/comments",
        headers=headers,
        json=payload,
    )
    replay = authorized_write_client.post(
        "/api/v1/objects/editable/comments",
        headers=headers,
        json=payload,
    )
    conflict = authorized_write_client.post(
        "/api/v1/objects/editable/comments",
        headers=headers,
        json={"body": "different"},
    )
    spoofed = authorized_write_client.post(
        "/api/v1/objects/editable/comments",
        headers={
            **_authorization(api_token),
            "Idempotency-Key": "object-comment-key-0002",
            "X-Blockwart-Channel": "mcp",
        },
        json={"body": "spoofed origin"},
    )
    secret = authorized_write_client.post(
        "/api/v1/objects/editable/comments",
        headers={
            **_authorization(api_token),
            "Idempotency-Key": "object-comment-key-0003",
        },
        json={"body": "Bearer abcdefghijklmnopqrstuvwxyz123456"},
    )

    assert first.status_code == 201, first.text
    assert first.headers["location"] == (
        f"/objects/editable/comments#comment-{first.json()['comment']['id']}"
    )
    assert replay.status_code == 200, replay.text
    assert conflict.status_code == 409
    assert spoofed.status_code == 403
    assert secret.status_code == 409
    assert payload["body"] not in conflict.text + spoofed.text + secret.text
    assert first.json()["comment"]["body"] == payload["body"]
    assert first.json()["comment"]["format"] == "markdown"
    assert first.json()["comment"]["origin"] == "api"
    assert replay.json() == {**first.json(), "replayed": True}

    page = authorized_write_client.get(
        "/api/v1/objects/editable/comments?include_total=true",
        headers=_authorization(api_token),
    )
    context = authorized_write_client.get(
        "/api/v1/objects/editable",
        headers=_authorization(api_token),
    )
    assert page.status_code == 200
    assert page.json()["total"] == 1
    assert page.json()["items"] == [first.json()["comment"]]
    assert context.json()["recent_comments"] == [first.json()["comment"]]
    assert context.headers["etag"] == first.headers["etag"]

    rest_audit = authorized_write_client.get(
        "/api/v1/objects/editable/audit-events?include_total=true",
        headers=_authorization(api_token),
    )
    mcp_audit = call_tool(
        "blockwart.list_audit_events",
        {"object_id": "editable", "include_total": True},
        fetcher=_successful_mcp_fetcher(authorized_write_client, api_token),
    )
    mcp_audit_payload = json.loads(mcp_audit["content"][0]["text"])
    assert rest_audit.status_code == 200
    assert mcp_audit_payload == rest_audit.json()
    assert payload["body"] not in json.dumps(mcp_audit_payload)
    comment_event = next(
        item for item in mcp_audit_payload["items"] if item["action"] == "comment_create"
    )
    assert comment_event["details"]["comment_id"] == first.json()["comment"]["id"]
    assert not {"body", "before", "after"} & set(comment_event["details"])

    assert authorized_write_client.get(
        "/api/v1/objects/peer/comments",
        headers=_authorization(api_token),
    ).status_code == 404
    assert authorized_write_client.post(
        "/api/v1/objects/peer/comments",
        headers={
            **_authorization(api_token),
            "Idempotency-Key": "object-comment-key-0004",
        },
        json={"body": "denied"},
    ).status_code == 403
    assert authorized_write_client.get(
        "/api/v1/objects/missing/comments",
        headers=_authorization(api_token),
    ).status_code == 404

    with session_factory() as session:
        row = session.get(CatalogObject, "editable")
        assert row is not None
        assert row.revision == before_revision + 1
        assert row.updated_at == before_updated_at
        comments = list(session.scalars(select(ObjectComment)).all())
        assert len(comments) == 1
        events = list(
            session.scalars(
                select(AuditEvent).where(
                    AuditEvent.object_id == "editable",
                    AuditEvent.action == "comment_create",
                )
            ).all()
        )
        assert len(events) == 1
        assert payload["body"] not in events[0].details_json
        assert '"before"' not in events[0].details_json
        assert '"after"' not in events[0].details_json
        record = session.scalar(
            select(IdempotencyRecord).where(
                IdempotencyRecord.resource_id == comments[0].id
            )
        )
        assert record is not None
        assert payload["body"] not in (record.response_json or "")

        with transaction(session):
            mcp_token = issue_service_token(
                session,
                principal_id=principal_id,
                name="comments-mcp",
                audience="mcp",
            )
    mcp_added = authorized_write_client.post(
        "/api/v1/objects/editable/comments",
        headers={
            **_authorization(mcp_token.value),
            "Idempotency-Key": "object-comment-key-0005",
            "X-Blockwart-Channel": "mcp",
        },
        json={"body": "MCP work log"},
    )
    assert mcp_added.status_code == 201, mcp_added.text
    assert mcp_added.json()["comment"]["origin"] == "mcp"
    assert authorized_write_client.post(
        "/api/v1/objects/editable/comments",
        headers={
            **_authorization(mcp_token.value),
            "Idempotency-Key": "object-comment-key-0006",
        },
        json={"body": "wrong API audience"},
    ).status_code == 403


def test_object_comment_pages_are_newest_first_bounded_and_instance_scoped(
    authorized_write_client: TestClient,
    authorized_write_state,
) -> None:
    session_factory, _, api_token = authorized_write_state
    comments = []
    for index in range(7):
        response = authorized_write_client.post(
            "/api/v1/objects/editable/comments",
            headers={
                **_authorization(api_token),
                "Idempotency-Key": f"object-comment-page-key-{index:04d}",
            },
            json={"body": f"Comment {index}"},
        )
        assert response.status_code == 201, response.text
        comments.append(response.json()["comment"])

    expected = sorted(
        comments,
        key=lambda item: (item["created_at"], item["id"]),
        reverse=True,
    )
    statements: list[str] = []

    def capture_comment_sql(
        _connection,
        _cursor,
        statement,
        _parameters,
        _context,
        _executemany,
    ) -> None:
        if "object_comments" in statement:
            statements.append(statement)

    engine = session_factory.kw["bind"]
    sqlalchemy_event.listen(engine, "before_cursor_execute", capture_comment_sql)
    first = authorized_write_client.get(
        "/api/v1/objects/editable/comments",
        headers=_authorization(api_token),
        params={"limit": 2, "include_total": "true"},
    )
    sqlalchemy_event.remove(engine, "before_cursor_execute", capture_comment_sql)
    assert first.status_code == 200
    assert first.json()["items"] == expected[:2]
    assert first.json()["total"] == 7
    assert first.json()["next_cursor"]
    assert any(" LIMIT " in statement.upper() for statement in statements)
    assert any("COUNT(" in statement.upper() for statement in statements)

    second = authorized_write_client.get(
        "/api/v1/objects/editable/comments",
        headers=_authorization(api_token),
        params={"limit": 2, "cursor": first.json()["next_cursor"]},
    )
    assert second.status_code == 200
    assert second.json()["items"] == expected[2:4]
    assert second.json()["total"] is None

    context = authorized_write_client.get(
        "/api/v1/objects/editable",
        headers=_authorization(api_token),
    )
    assert context.status_code == 200
    assert context.json()["recent_comments"] == expected[:5]

    rebound = authorized_write_client.get(
        "/api/v1/objects/deletable/comments",
        headers=_authorization(api_token),
        params={"limit": 2, "cursor": first.json()["next_cursor"]},
    )
    assert rebound.status_code == 400

    with session_factory() as session:
        current = session.get(CatalogObject, "editable")
        assert current is not None
        with transaction(session):
            session.execute(
                update(CatalogObject)
                .where(CatalogObject.id == "editable")
                .values(
                    instance_id=uuid4().hex,
                    created_at=current.created_at,
                    updated_at=CatalogObject.updated_at,
                )
            )

    replacement_page = authorized_write_client.get(
        "/api/v1/objects/editable/comments?include_total=true",
        headers=_authorization(api_token),
    )
    replacement_context = authorized_write_client.get(
        "/api/v1/objects/editable",
        headers=_authorization(api_token),
    )
    assert replacement_page.status_code == 200
    assert replacement_page.json() == {
        "items": [],
        "next_cursor": None,
        "total": 0,
        "sort": "created_at",
        "direction": "desc",
    }
    assert replacement_context.status_code == 200
    assert replacement_context.json()["recent_comments"] == []


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


def test_authorized_update_rejects_projected_invalid_relationship_endpoint(
    authorized_write_client: TestClient,
    authorized_write_state,
) -> None:
    session_factory, principal_id, token = authorized_write_state
    with session_factory() as session:
        with transaction(session):
            upsert_object(
                session,
                CatalogObjectIn(
                    id="protected-sensor",
                    kind="device",
                    label="Protected sensor",
                    lifecycle="active",
                    health="healthy",
                    data={"schema_version": 1, "device": {"category": "sensor"}},
                ),
            )
            network = upsert_object(
                session,
                CatalogObjectIn(
                    id="protected-switch",
                    kind="network",
                    label="Protected switch",
                    lifecycle="active",
                    health="healthy",
                    data={"schema_version": 1, "network": {"category": "switch"}},
                ),
            )
            create_object_grant(
                session,
                principal_id=principal_id,
                object_id=network.id,
                role=Role.EDITOR,
                scope=GrantScope.SELF,
            )
            create_relationship(
                session,
                from_ref="device:protected-sensor",
                relation_type="attached_to",
                to_ref="network:protected-switch",
            )

    auth = _authorization(token)
    current = authorized_write_client.get(
        "/api/v1/objects/protected-switch",
        headers=auth,
    )
    assert current.status_code == 200
    current_revision = current.json()["revision"]
    rejected = authorized_write_client.put(
        "/api/v1/objects/protected-switch",
        headers={**auth, "If-Match": current.headers["etag"]},
        json=CatalogObjectIn(
            id="protected-switch",
            kind="network",
            label="Protected switch",
            lifecycle="active",
            health="healthy",
            data={"schema_version": 1, "network": {"category": "segment"}},
        ).model_dump(mode="json"),
    )

    assert rejected.status_code == 409
    assert rejected.json()["error"]["code"] == "conflict"
    with session_factory() as session:
        row = session.get(CatalogObject, "protected-switch")
        assert row is not None
        assert row.revision == current_revision
        assert json.loads(row.data_json)["network"]["category"] == "switch"
        assert session.scalar(
            select(func.count())
            .select_from(AuditEvent)
            .where(
                AuditEvent.object_id == "protected-switch",
                AuditEvent.action == "update",
            )
        ) == 0


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
    assert agent.json()["objects"][0]["etag"] == agent.headers["etag"]
    assert v1.json()["etag"] == v1.headers["etag"]
    assert v1.json()["etag"] == f'"rev-{revision}"'
    assert authorized_write_client.get(
        "/api/v1/objects/editable",
        headers=auth,
    ).json()["etag"] == v1.json()["etag"]


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

    mcp_audit = call_tool(
        "blockwart.list_audit_events",
        {"object_id": "editable"},
        fetcher=_successful_mcp_fetcher(authorized_write_client, token),
    )
    mcp_audit_payload = json.loads(mcp_audit["content"][0]["text"])
    assert leaked_value not in json.dumps(mcp_audit_payload)
    assert "[redacted-secret-field]" in json.dumps(mcp_audit_payload)


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
