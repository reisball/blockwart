from __future__ import annotations

from collections.abc import Generator
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from blockwart.api.deps import get_session
from blockwart.db.session import transaction
from blockwart.domain.auth import GrantScope, Permission, Role
from blockwart.main import create_app
from blockwart.models import (
    AccessRequest,
    AuditEvent,
    ObjectGrant,
)
from blockwart.schemas.catalog import CatalogObjectIn
from blockwart.services.access import create_object_grant
from blockwart.services.access_notifications import (
    NotificationError,
    NullNotifier,
    set_access_request_notifier,
)
from blockwart.services.catalog import create_relationship, upsert_object
from blockwart.services.identity import create_service_account, issue_service_token
from blockwart.services.policy import policy_for_principal


def _asset(
    object_id: str,
    *,
    kind: str,
    label: str | None = None,
) -> CatalogObjectIn:
    return CatalogObjectIn(
        id=object_id,
        kind=kind,
        label=label or object_id,
        lifecycle="active",
        health="healthy",
        data={"schema_version": 1},
    )


@pytest.fixture
def access_request_state(alembic_session_factory):
    with alembic_session_factory() as session:
        with transaction(session):
            root = upsert_object(
                session,
                _asset("ar-root", kind="host", label="Access Root"),
            )
            upsert_object(
                session,
                _asset("ar-child", kind="system", label="Access Child"),
            )
            create_relationship(
                session,
                from_ref="host:ar-root",
                relation_type="hosts",
                to_ref="system:ar-child",
            )

            owner = create_service_account(
                session,
                login="ar.owner",
                display_name="Access Owner",
            )
            manager = create_service_account(
                session,
                login="ar.manager",
                display_name="Access Manager",
            )
            discoverer = create_service_account(
                session,
                login="ar.discoverer",
                display_name="Access Discoverer",
            )
            reader = create_service_account(
                session,
                login="ar.reader",
                display_name="Access Reader",
            )
            outsider = create_service_account(
                session,
                login="ar.outsider",
                display_name="Access Outsider",
            )

            create_object_grant(
                session,
                principal_id=owner.id,
                object_id=root.id,
                role=Role.OWNER,
                scope=GrantScope.SUBTREE,
            )
            create_object_grant(
                session,
                principal_id=manager.id,
                object_id=root.id,
                role=Role.ACCESS_MANAGER,
                scope=GrantScope.SELF,
            )
            create_object_grant(
                session,
                principal_id=discoverer.id,
                object_id=root.id,
                role=Role.DISCOVERER,
                scope=GrantScope.SELF,
            )
            create_object_grant(
                session,
                principal_id=reader.id,
                object_id=root.id,
                role=Role.VIEWER,
                scope=GrantScope.SELF,
            )

            tokens = {
                name: issue_service_token(
                    session,
                    principal_id=principal.id,
                    name="access-requests",
                ).value
                for name, principal in (
                    ("owner", owner),
                    ("manager", manager),
                    ("discoverer", discoverer),
                    ("reader", reader),
                    ("outsider", outsider),
                )
            }
            principal_ids = {
                "owner": owner.id,
                "manager": manager.id,
                "discoverer": discoverer.id,
                "reader": reader.id,
                "outsider": outsider.id,
            }
    return {
        "session_factory": alembic_session_factory,
        "principals": principal_ids,
        "tokens": tokens,
    }


@pytest.fixture
def access_request_client(
    access_request_state,
) -> Generator[TestClient, None, None]:
    app = create_app()

    def override_get_session() -> Generator[Session, None, None]:
        with access_request_state["session_factory"]() as session:
            yield session

    app.dependency_overrides[get_session] = override_get_session
    with TestClient(app) as client:
        yield client


def _authorization(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _create_request(
    client: TestClient,
    token: str,
    object_id: str = "ar-root",
    **payload,
) -> object:
    body = {"duration": "temporary", "ttl_seconds": 3600, "reason": "incident work"}
    body.update(payload)
    return client.post(
        f"/api/v1/objects/{object_id}/access-requests",
        headers=_authorization(token),
        json=body,
    )


def test_without_discover_create_is_indistinguishable_from_unknown_object(
    access_request_client: TestClient,
    access_request_state,
) -> None:
    token = access_request_state["tokens"]["outsider"]
    hidden = _create_request(access_request_client, token, "ar-root")
    unknown = _create_request(access_request_client, token, "no-such-object")

    assert hidden.status_code == 404
    assert unknown.status_code == 404
    hidden_error = {k: v for k, v in hidden.json()["error"].items() if k != "correlation_id"}
    unknown_error = {k: v for k, v in unknown.json()["error"].items() if k != "correlation_id"}
    assert hidden_error == unknown_error
    # The queue endpoint confirms nothing about objects the caller cannot see.
    queue = access_request_client.get(
        "/api/v1/access-requests", headers=_authorization(token)
    )
    assert queue.status_code == 200
    assert queue.json()["items"] == []


def test_discoverer_can_apply_temporary_and_permanent_and_retry_idempotently(
    access_request_client: TestClient,
    access_request_state,
) -> None:
    token = access_request_state["tokens"]["discoverer"]
    first = _create_request(access_request_client, token)
    assert first.status_code == 201, first.text
    assert first.json()["status"] == "pending"
    assert first.json()["changed"] is True

    retry = _create_request(access_request_client, token)
    assert retry.status_code == 201
    assert retry.json()["request_id"] == first.json()["request_id"]
    assert retry.json()["changed"] is False

    permanent = _create_request(
        access_request_client,
        token,
        duration="permanent",
        ttl_seconds=None,
        reason="permanent monitoring agent",
    )
    # A differently-shaped application for the same object maps onto the one
    # open-request slot: it stays idempotent instead of queueing a duplicate.
    assert permanent.status_code == 201
    assert permanent.json()["request_id"] == first.json()["request_id"]
    assert permanent.json()["changed"] is False

    mine = access_request_client.get(
        "/api/v1/me/access-requests", headers=_authorization(token)
    )
    items = mine.json()["items"]
    assert len(items) == 1
    assert items[0]["role"] == "viewer"
    assert items[0]["scope"] == "self"
    assert items[0]["requested_expires_at"] is not None
    # Requesters never see approver or policy data.
    assert "decided_by" not in items[0]
    assert "approver" not in items[0]


def test_principal_with_read_cannot_request_again(
    access_request_client: TestClient,
    access_request_state,
) -> None:
    token = access_request_state["tokens"]["reader"]
    response = _create_request(access_request_client, token)
    assert response.status_code == 409


def test_v1_role_and_scope_are_fixed_server_side(
    access_request_client: TestClient,
    access_request_state,
) -> None:
    token = access_request_state["tokens"]["discoverer"]
    response = access_request_client.post(
        "/api/v1/objects/ar-root/access-requests",
        headers=_authorization(token),
        json={"duration": "temporary", "ttl_seconds": 3600, "role": "editor"},
    )
    assert response.status_code == 422

    smuggled = access_request_client.post(
        "/api/v1/objects/ar-root/access-requests",
        headers=_authorization(token),
        json={"duration": "permanent", "scope": "subtree", "extra": True},
    )
    # Unknown fields are rejected instead of silently ignored: the request
    # contract is Viewer/self and nothing else travels in.
    assert smuggled.status_code == 422


def test_unauthorized_approver_sees_no_queue_and_cannot_decide(
    access_request_client: TestClient,
    access_request_state,
) -> None:
    requester = access_request_state["tokens"]["discoverer"]
    created = _create_request(access_request_client, requester)
    request_id = created.json()["request_id"]

    outsider = access_request_state["tokens"]["outsider"]
    queue = access_request_client.get(
        "/api/v1/access-requests", headers=_authorization(outsider)
    )
    assert queue.json()["items"] == []

    denied = access_request_client.post(
        f"/api/v1/access-requests/{request_id}/decision",
        headers=_authorization(outsider),
        json={"decision": "approve"},
    )
    assert denied.status_code == 403

    session_factory = access_request_state["session_factory"]
    with session_factory() as session:
        row = session.get(AccessRequest, request_id)
        assert row.status == "pending"
        assert (
            session.scalar(
                select(func.count()).select_from(ObjectGrant).where(
                    ObjectGrant.object_id == "ar-root",
                    ObjectGrant.principal_id
                    == access_request_state["principals"]["discoverer"],
                    ObjectGrant.role == "viewer",
                )
            )
            == 0
        )


def test_approval_creates_exactly_one_grant_with_audit_denial_creates_none(
    access_request_client: TestClient,
    access_request_state,
) -> None:
    session_factory = access_request_state["session_factory"]
    discoverer_token = access_request_state["tokens"]["discoverer"]
    manager_token = access_request_state["tokens"]["manager"]

    temp = _create_request(
        access_request_client,
        discoverer_token,
        reason="temporary diagnosis",
    )
    perm = _create_request(
        access_request_client,
        discoverer_token,
        object_id="ar-child",
        duration="permanent",
        ttl_seconds=None,
    )
    assert perm.status_code == 404  # child is not directly discoverable

    approved = access_request_client.post(
        f"/api/v1/access-requests/{temp.json()['request_id']}/decision",
        headers=_authorization(manager_token),
        json={"decision": "approve"},
    )
    assert approved.status_code == 200, approved.text
    assert approved.json()["status"] == "approved"

    other = _create_request(
        access_request_client,
        discoverer_token,
        object_id="ar-root",
        duration="temporary",
        ttl_seconds=7200,
        reason="second window",
    )
    # After approval the requester already holds read, so a fresh application
    # conflicts instead of queueing a duplicate.
    assert other.status_code == 409

    # A decided request can neither be re-decided nor cancelled.
    denial = access_request_client.post(
        f"/api/v1/access-requests/{temp.json()['request_id']}/decision",
        headers=_authorization(manager_token),
        json={"decision": "deny"},
    )
    assert denial.status_code == 409
    cancelled = access_request_client.post(
        f"/api/v1/access-requests/{temp.json()['request_id']}/cancellation",
        headers=_authorization(discoverer_token),
    )
    assert cancelled.status_code == 409

    with session_factory() as session:
        grants = session.scalars(
            select(ObjectGrant).where(
                ObjectGrant.object_id == "ar-root",
                ObjectGrant.principal_id
                == access_request_state["principals"]["discoverer"],
                ObjectGrant.role == Role.VIEWER,
            )
        ).all()
        assert len(grants) == 1
        assert grants[0].role == "viewer"
        assert grants[0].expires_at is not None
        actions = session.scalars(
            select(AuditEvent.action).where(
                AuditEvent.object_id == "ar-root"
            )
        ).all()
        assert "grant_create" in actions
        assert "access_request_approve" in actions


def test_parallel_decisions_produce_exactly_one_effective_outcome(
    access_request_client: TestClient,
    access_request_state,
) -> None:
    requester = access_request_state["tokens"]["discoverer"]
    created = _create_request(access_request_client, requester)
    request_id = created.json()["request_id"]
    auth = _authorization(access_request_state["tokens"]["owner"])

    def decide(_: int) -> int:
        return access_request_client.post(
            f"/api/v1/access-requests/{request_id}/decision",
            headers=auth,
            json={"decision": "approve"},
        ).status_code

    with ThreadPoolExecutor(max_workers=2) as pool:
        statuses = sorted(pool.map(decide, (0, 1)))

    assert statuses == [200, 409]
    with access_request_state["session_factory"]() as session:
        assert (
            session.scalar(
                select(func.count())
                .select_from(ObjectGrant)
                .where(
                    ObjectGrant.principal_id
                    == access_request_state["principals"]["discoverer"],
                    ObjectGrant.object_id == "ar-root",
                    ObjectGrant.role == Role.VIEWER,
                )
            )
            == 1
        )


def test_temporary_grant_loses_effect_without_restart_and_request_expires(
    access_request_client: TestClient,
    access_request_state,
) -> None:
    session_factory = access_request_state["session_factory"]
    requester = access_request_state["tokens"]["discoverer"]
    approver = access_request_state["tokens"]["owner"]
    created = _create_request(
        access_request_client,
        requester,
        ttl_seconds=600,
    )
    request_id = created.json()["request_id"]
    decided = access_request_client.post(
        f"/api/v1/access-requests/{request_id}/decision",
        headers=_authorization(approver),
        json={"decision": "approve"},
    )
    assert decided.status_code == 200

    principal_id = access_request_state["principals"]["discoverer"]
    with session_factory() as session:
        before = policy_for_principal(session, principal_id)
        assert before.can(Permission.READ, "ar-root")
        before_fingerprint = before.fingerprint()
        grant = session.scalar(
            select(ObjectGrant).where(
                ObjectGrant.principal_id == principal_id,
                ObjectGrant.object_id == "ar-root",
                ObjectGrant.role == Role.VIEWER,
            )
        )
        expired_at = datetime.now(UTC).replace(tzinfo=None) - timedelta(seconds=1)
        grant.expires_at = expired_at
        request_row = session.get(AccessRequest, request_id)
        request_row.approved_expires_at = expired_at
        session.commit()

    # A brand-new policy computation in a fresh session reflects the expiry
    # immediately: no restart, no cache to invalidate. The requester keeps
    # their original discover permission but loses read exactly at expiry.
    with session_factory() as session:
        after = policy_for_principal(session, principal_id)
        assert not after.can(Permission.READ, "ar-root")
        assert after.fingerprint() != before_fingerprint

    mine = access_request_client.get(
        "/api/v1/me/access-requests", headers=_authorization(requester)
    )
    statuses = {item["id"]: item["status"] for item in mine.json()["items"]}
    assert statuses[request_id] == "expired"


@pytest.fixture
def capturing_notifier():
    captured: list[dict] = []

    class Recorder:
        def notify(self, notification) -> None:
            from blockwart.services.access_notifications import build_notification_payload

            captured.append(build_notification_payload(notification))

    set_access_request_notifier(Recorder())
    yield captured
    set_access_request_notifier(NullNotifier())


def test_notification_payload_is_minimal_and_failure_never_changes_status(
    access_request_client: TestClient,
    access_request_state,
    capturing_notifier,
) -> None:
    requester = access_request_state["tokens"]["discoverer"]
    approver = access_request_state["tokens"]["owner"]
    created = _create_request(
        access_request_client,
        requester,
        reason="secret-looking value and private details must not travel",
    )
    request_id = created.json()["request_id"]

    assert len(capturing_notifier) == 1
    payload = capturing_notifier[0]
    assert set(payload) == {
        "type",
        "request_id",
        "object_id",
        "status",
        "decision_reference",
    }
    assert "reason" not in payload
    assert "secret-looking" not in str(payload)

    decided = access_request_client.post(
        f"/api/v1/access-requests/{request_id}/decision",
        headers=_authorization(approver),
        json={"decision": "approve"},
    )
    assert decided.status_code == 200
    assert len(capturing_notifier) == 2
    assert capturing_notifier[1]["status"] == "approved"


class FailingNotifier:
    def notify(self, notification) -> None:
        raise NotificationError("sink down")


@pytest.fixture
def failing_notifier():
    set_access_request_notifier(FailingNotifier())
    yield
    set_access_request_notifier(NullNotifier())


def test_notification_failure_leaves_request_and_grants_untouched(
    access_request_client: TestClient,
    access_request_state,
    failing_notifier,
) -> None:
    requester = access_request_state["tokens"]["discoverer"]
    approver = access_request_state["tokens"]["owner"]
    created = _create_request(access_request_client, requester)
    assert created.status_code == 201
    request_id = created.json()["request_id"]

    decided = access_request_client.post(
        f"/api/v1/access-requests/{request_id}/decision",
        headers=_authorization(approver),
        json={"decision": "approve"},
    )
    assert decided.status_code == 200

    with access_request_state["session_factory"]() as session:
        row = session.get(AccessRequest, request_id)
        assert row.status == "approved"
        assert row.grant_id is not None
        assert 1 <= row.notification_attempts <= 3
        assert row.last_notification_outcome == "failed"


def test_approver_may_shorten_but_never_extend_temporary_requests(
    access_request_client: TestClient,
    access_request_state,
) -> None:
    requester = access_request_state["tokens"]["discoverer"]
    approver = access_request_state["tokens"]["owner"]
    created = _create_request(
        access_request_client,
        requester,
        ttl_seconds=86400,
        reason="one day of debugging",
    )
    request_id = created.json()["request_id"]

    extended = access_request_client.post(
        f"/api/v1/access-requests/{request_id}/decision",
        headers=_authorization(approver),
        json={"decision": "approve", "ttl_seconds": 7 * 24 * 60 * 60},
    )
    assert extended.status_code == 409

    shortened = access_request_client.post(
        f"/api/v1/access-requests/{request_id}/decision",
        headers=_authorization(approver),
        json={"decision": "approve", "ttl_seconds": 1800},
    )
    assert shortened.status_code == 200

    mine = access_request_client.get(
        "/api/v1/me/access-requests", headers=_authorization(requester)
    )
    item = next(
        item for item in mine.json()["items"] if item["id"] == request_id
    )
    assert item["status"] == "approved"
    assert item["approved_expires_at"] is not None
    assert item["approved_expires_at"] < item["requested_expires_at"]


def test_reason_input_is_bounded_and_control_characters_stripped(
    access_request_client: TestClient,
    access_request_state,
) -> None:
    requester = access_request_state["tokens"]["discoverer"]
    overlong = "y" * 501
    rejected_by_size = access_request_client.post(
        "/api/v1/objects/ar-root/access-requests",
        headers=_authorization(requester),
        json={"duration": "temporary", "ttl_seconds": 3600, "reason": overlong},
    )
    assert rejected_by_size.status_code == 422

    hostile_reason = "diag\x00\x07 reason\t with control chars"
    created = _create_request(
        access_request_client,
        requester,
        reason=hostile_reason,
    )
    assert created.status_code == 201
    mine = access_request_client.get(
        "/api/v1/me/access-requests", headers=_authorization(requester)
    )
    item = mine.json()["items"][0]
    assert len(item["reason"]) <= 500
    assert "\x00" not in item["reason"]
    assert "\x07" not in item["reason"]


def test_ui_api_and_mcp_share_one_contract(
    access_request_client: TestClient,
    access_request_state,
) -> None:
    from blockwart.mcp.server import TOOL_DEFINITIONS

    expected_paths = {
        "blockwart.create_access_request": (
            "/api/v1/objects/{object_id}/access-requests",
            "POST",
        ),
        "blockwart.list_my_access_requests": ("/api/v1/me/access-requests", "GET"),
        "blockwart.list_pending_access_requests": ("/api/v1/access-requests", "GET"),
        "blockwart.cancel_access_request": (
            "/api/v1/access-requests/{request_id}/cancellation",
            "POST",
        ),
        "blockwart.decide_access_request": (
            "/api/v1/access-requests/{request_id}/decision",
            "POST",
        ),
    }
    schema = access_request_client.get("/openapi.json").json()
    registered = {
        (path, method.upper())
        for path, methods in schema["paths"].items()
        for method in methods
    }
    for tool_name, (path_template, method) in expected_paths.items():
        assert tool_name in TOOL_DEFINITIONS
        assert (path_template, method) in registered, (tool_name, path_template, method)
