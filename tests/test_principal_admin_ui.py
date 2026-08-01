from __future__ import annotations

from collections.abc import Generator

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from blockwart.api.deps import get_session
from blockwart.db.session import transaction
from blockwart.domain.auth import GrantScope, PlatformRole, Role
from blockwart.main import create_app
from blockwart.models import (
    BrowserSession,
    ObjectGrant,
    PasswordCredential,
    Principal,
    SecurityEvent,
    ServiceToken,
)
from blockwart.schemas.catalog import CatalogObjectIn
from blockwart.services.access import create_object_grant
from blockwart.services.catalog import upsert_object
from blockwart.services.identity import (
    create_human_principal,
    create_service_account,
    issue_browser_session,
    issue_service_token,
)
from blockwart.ui.security import AUTH_CSRF_COOKIE_NAME, AUTH_SESSION_COOKIE_NAME

PASSWORD = "browser-platform-admin-password"


@pytest.fixture
def principal_admin_ui_state(alembic_session_factory):
    with alembic_session_factory() as session:
        with transaction(session):
            root = upsert_object(
                session,
                CatalogObjectIn(
                    id="ui-admin-root",
                    kind="host",
                    label="UI Admin Root",
                    lifecycle="active",
                    health="healthy",
                    data={"schema_version": 1},
                ),
            )
            admin = create_human_principal(
                session,
                login="browser.admin",
                display_name="Browser Admin",
                password=PASSWORD,
                platform_role=PlatformRole.ADMIN,
            )
            ordinary = create_human_principal(
                session,
                login="browser.ordinary",
                display_name="Browser Ordinary",
                password=PASSWORD,
            )
            target = create_service_account(
                session,
                login="browser.target",
                display_name="Browser Target",
            )
            grants = {}
            for principal_id in (admin.id, ordinary.id):
                grant = create_object_grant(
                    session,
                    principal_id=principal_id,
                    object_id=root.id,
                    role=Role.OWNER,
                    scope=GrantScope.SELF,
                )
                grants[principal_id] = grant.id
            admin_session = issue_browser_session(
                session, principal_id=admin.id, ttl_seconds=3600
            )
            ordinary_session = issue_browser_session(
                session, principal_id=ordinary.id, ttl_seconds=3600
            )
    return {
        "session_factory": alembic_session_factory,
        "target_id": target.id,
        "ordinary_id": ordinary.id,
        "ordinary_grant_id": grants[ordinary.id],
        "admin_session": admin_session,
        "ordinary_session": ordinary_session,
    }


@pytest.fixture
def principal_admin_ui_client(principal_admin_ui_state) -> Generator[TestClient, None, None]:
    app = create_app()
    sessions = principal_admin_ui_state["session_factory"]

    def override_get_session() -> Generator[Session, None, None]:
        with sessions() as session:
            yield session

    app.dependency_overrides[get_session] = override_get_session
    with TestClient(app, base_url="https://testserver") as client:
        yield client


def _login(client: TestClient, issued) -> None:
    client.cookies.set(AUTH_SESSION_COOKIE_NAME, issued.value)
    client.cookies.set(AUTH_CSRF_COOKIE_NAME, issued.csrf_token)


def _prepare_principal_update_guard(state) -> None:
    target_id = state["target_id"]
    with state["session_factory"]() as session:
        with transaction(session):
            issue_service_token(
                session,
                principal_id=target_id,
                name="principal-update-validation-guard",
            )


def _principal_update_snapshot(state) -> tuple[object, ...]:
    target_id = state["target_id"]
    with state["session_factory"]() as session:
        principal = session.get(Principal, target_id)
        assert principal is not None
        password_credentials = tuple(
            (row.password_hash, row.updated_at)
            for row in session.scalars(
                select(PasswordCredential).where(
                    PasswordCredential.principal_id == target_id
                )
            )
        )
        browser_sessions = tuple(
            (row.id, row.revoked_at, row.last_seen_at)
            for row in session.scalars(
                select(BrowserSession).where(BrowserSession.principal_id == target_id)
            )
        )
        service_tokens = tuple(
            (row.id, row.revoked_at, row.rotated_at, row.last_used_at)
            for row in session.scalars(
                select(ServiceToken).where(ServiceToken.principal_id == target_id)
            )
        )
        security_events = tuple(
            (row.id, row.event_type, row.outcome, row.details_json)
            for row in session.scalars(
                select(SecurityEvent).where(SecurityEvent.principal_id == target_id)
            )
        )
        return (
            principal.display_name,
            principal.active,
            principal.platform_role,
            principal.revision,
            password_credentials,
            browser_sessions,
            service_tokens,
            security_events,
        )


def test_admin_navigation_and_pages_are_hidden_from_non_admin(
    principal_admin_ui_client: TestClient,
    principal_admin_ui_state,
) -> None:
    _login(principal_admin_ui_client, principal_admin_ui_state["ordinary_session"])
    denied = principal_admin_ui_client.get("/admin/principals")
    assert denied.status_code == 403

    _login(principal_admin_ui_client, principal_admin_ui_state["admin_session"])
    page = principal_admin_ui_client.get("/admin/principals?lang=de")
    catalog = principal_admin_ui_client.get("/")
    assert page.status_code == 200
    assert "Benutzer &amp; Agents" in page.text
    assert "browser.target" in page.text
    assert "/admin/principals" in catalog.text


def test_admin_principal_list_exposes_exhaustive_next_cursor_navigation(
    principal_admin_ui_client: TestClient,
    principal_admin_ui_state,
) -> None:
    _login(principal_admin_ui_client, principal_admin_ui_state["admin_session"])

    first = principal_admin_ui_client.get("/admin/principals?limit=2&q=browser")

    assert first.status_code == 200
    assert 'rel="next"' in first.text
    assert "cursor=" in first.text
    assert "q=browser" in first.text


def test_admin_principal_list_rejects_invalid_principal_type_filter_safely(
    principal_admin_ui_client: TestClient,
    principal_admin_ui_state,
) -> None:
    _login(principal_admin_ui_client, principal_admin_ui_state["admin_session"])

    response = principal_admin_ui_client.get(
        "/admin/principals?principal_type=definitely-invalid"
    )

    assert response.status_code == 422
    assert "Internal Server Error" not in response.text


def test_admin_principal_list_rejects_invalid_active_filter_safely(
    principal_admin_ui_client: TestClient,
    principal_admin_ui_state,
) -> None:
    _login(principal_admin_ui_client, principal_admin_ui_state["admin_session"])

    response = principal_admin_ui_client.get("/admin/principals?active=bogus")

    assert response.status_code == 422
    assert "Internal Server Error" not in response.text


def test_admin_ui_manages_assignment_from_principal_side(
    principal_admin_ui_client: TestClient,
    principal_admin_ui_state,
) -> None:
    issued = principal_admin_ui_state["admin_session"]
    target_id = principal_admin_ui_state["target_id"]
    _login(principal_admin_ui_client, issued)

    create = principal_admin_ui_client.post(
        f"/admin/principals/{target_id}/grants",
        data={
            "csrf_token": issued.csrf_token,
            "object_id": "ui-admin-root",
            "role": "viewer",
            "scope": "self",
            "if_match": '"rev-3"',
        },
        follow_redirects=False,
    )
    detail = principal_admin_ui_client.get(f"/admin/principals/{target_id}")

    assert create.status_code == 303
    assert detail.status_code == 200
    assert "UI Admin Root" in detail.text
    assert "viewer" in detail.text


@pytest.mark.parametrize(
    ("active", "platform_role"),
    (("bogus", ""), ("active", "bogus")),
)
def test_admin_ui_rejects_invalid_principal_update_enums_without_side_effects(
    principal_admin_ui_client: TestClient,
    principal_admin_ui_state,
    active: str,
    platform_role: str,
) -> None:
    issued = principal_admin_ui_state["admin_session"]
    target_id = principal_admin_ui_state["target_id"]
    _prepare_principal_update_guard(principal_admin_ui_state)
    before = _principal_update_snapshot(principal_admin_ui_state)
    _login(principal_admin_ui_client, issued)
    response = principal_admin_ui_client.post(
        f"/admin/principals/{target_id}",
        data={
            "csrf_token": issued.csrf_token,
            "if_match": '"rev-1"',
            "display_name": "Must Not Change",
            "active": active,
            "platform_role": platform_role,
        },
        follow_redirects=False,
    )

    assert response.status_code == 422
    assert _principal_update_snapshot(principal_admin_ui_state) == before


@pytest.mark.parametrize("missing_field", ("active", "platform_role"))
def test_admin_ui_requires_complete_principal_update_without_side_effects(
    principal_admin_ui_client: TestClient,
    principal_admin_ui_state,
    missing_field: str,
) -> None:
    issued = principal_admin_ui_state["admin_session"]
    target_id = principal_admin_ui_state["target_id"]
    _prepare_principal_update_guard(principal_admin_ui_state)
    before = _principal_update_snapshot(principal_admin_ui_state)
    _login(principal_admin_ui_client, issued)
    data = {
        "csrf_token": issued.csrf_token,
        "if_match": '"rev-1"',
        "display_name": "Must Not Change",
        "active": "active",
        "platform_role": "",
    }
    del data[missing_field]

    response = principal_admin_ui_client.post(
        f"/admin/principals/{target_id}",
        data=data,
        follow_redirects=False,
    )

    assert response.status_code == 422
    assert _principal_update_snapshot(principal_admin_ui_state) == before


def test_admin_ui_discloses_new_service_token_only_in_direct_response(
    principal_admin_ui_client: TestClient,
    principal_admin_ui_state,
) -> None:
    issued = principal_admin_ui_state["admin_session"]
    target_id = principal_admin_ui_state["target_id"]
    _login(principal_admin_ui_client, issued)

    response = principal_admin_ui_client.post(
        f"/admin/principals/{target_id}/tokens",
        data={
            "csrf_token": issued.csrf_token,
            "if_match": '"rev-1"',
            "idempotency_key": "browser-token-issue-0001",
            "name": "browser-token",
            "current_admin_password": PASSWORD,
            "expires_in_seconds": "3600",
            "rotate": "0",
        },
    )
    token = response.text.split("bwst_", 1)[1].split("</code>", 1)[0]
    reload = principal_admin_ui_client.get(f"/admin/principals/{target_id}")

    assert response.status_code == 200
    assert "private, no-store" in response.headers["cache-control"]
    assert "Copy this value now" in response.text
    assert f"bwst_{token}" not in reload.text


@pytest.mark.parametrize(
    "expires_in_seconds",
    ("299", "31536001", "9" * 1000),
)
def test_admin_ui_rejects_token_expiry_outside_rest_contract_without_side_effects(
    principal_admin_ui_client: TestClient,
    principal_admin_ui_state,
    expires_in_seconds: str,
) -> None:
    issued = principal_admin_ui_state["admin_session"]
    target_id = principal_admin_ui_state["target_id"]
    sessions = principal_admin_ui_state["session_factory"]
    _login(principal_admin_ui_client, issued)

    response = principal_admin_ui_client.post(
        f"/admin/principals/{target_id}/tokens",
        data={
            "csrf_token": issued.csrf_token,
            "if_match": '"rev-1"',
            "idempotency_key": "invalid-token-expiry-0001",
            "name": "must-not-exist",
            "current_admin_password": PASSWORD,
            "expires_in_seconds": expires_in_seconds,
            "rotate": "0",
        },
    )

    assert response.status_code == 422
    assert "bwst_" not in response.text
    with sessions() as session:
        assert session.scalar(
            select(ServiceToken).where(
                ServiceToken.principal_id == target_id,
                ServiceToken.name == "must-not-exist",
            )
        ) is None
        assert session.scalar(
            select(SecurityEvent).where(
                SecurityEvent.principal_id == target_id,
                SecurityEvent.event_type.in_(
                    ("service_token_issued", "service_token_rotated")
                ),
            )
        ) is None


def test_admin_ui_rejects_invalid_token_rotation_without_side_effects(
    principal_admin_ui_client: TestClient,
    principal_admin_ui_state,
) -> None:
    issued = principal_admin_ui_state["admin_session"]
    target_id = principal_admin_ui_state["target_id"]
    before = _principal_update_snapshot(principal_admin_ui_state)
    _login(principal_admin_ui_client, issued)

    response = principal_admin_ui_client.post(
        f"/admin/principals/{target_id}/tokens",
        data={
            "csrf_token": issued.csrf_token,
            "if_match": '"rev-1"',
            "idempotency_key": "invalid-token-rotation-0001",
            "name": "must-not-exist",
            "current_admin_password": PASSWORD,
            "rotate": "bogus",
        },
    )

    assert response.status_code == 422
    assert "bwst_" not in response.text
    assert _principal_update_snapshot(principal_admin_ui_state) == before


def test_admin_ui_requires_token_rotation_without_side_effects(
    principal_admin_ui_client: TestClient,
    principal_admin_ui_state,
) -> None:
    issued = principal_admin_ui_state["admin_session"]
    target_id = principal_admin_ui_state["target_id"]
    before = _principal_update_snapshot(principal_admin_ui_state)
    _login(principal_admin_ui_client, issued)

    response = principal_admin_ui_client.post(
        f"/admin/principals/{target_id}/tokens",
        data={
            "csrf_token": issued.csrf_token,
            "if_match": '"rev-1"',
            "idempotency_key": "missing-token-rotation-0001",
            "name": "must-not-exist",
            "current_admin_password": PASSWORD,
        },
    )

    assert response.status_code == 422
    assert "bwst_" not in response.text
    assert _principal_update_snapshot(principal_admin_ui_state) == before


def test_failed_admin_reauthentication_is_durably_audited(
    principal_admin_ui_client: TestClient,
    principal_admin_ui_state,
) -> None:
    issued = principal_admin_ui_state["admin_session"]
    target_id = principal_admin_ui_state["target_id"]
    sessions = principal_admin_ui_state["session_factory"]
    _login(principal_admin_ui_client, issued)

    response = principal_admin_ui_client.post(
        f"/admin/principals/{target_id}/tokens",
        headers={"X-Correlation-ID": "admin-reauth-failure"},
        data={
            "csrf_token": issued.csrf_token,
            "if_match": '"rev-1"',
            "idempotency_key": "browser-token-denied-0001",
            "name": "denied-token",
            "current_admin_password": "definitely-not-the-password",
            "expires_in_seconds": "3600",
            "rotate": "0",
        },
    )

    assert response.status_code == 403
    with sessions() as session:
        event = session.scalar(
            select(SecurityEvent)
            .where(
                SecurityEvent.event_type == "platform_admin_reauthentication",
                SecurityEvent.outcome == "failure",
                SecurityEvent.request_id == "admin-reauth-failure",
            )
            .order_by(SecurityEvent.id.desc())
        )
        assert event is not None
        assert "password" not in event.details_json.casefold()


@pytest.mark.parametrize("operation", ("update", "revoke"))
def test_principal_side_grant_mutations_reject_cross_principal_tampering(
    principal_admin_ui_client: TestClient,
    principal_admin_ui_state,
    operation: str,
) -> None:
    issued = principal_admin_ui_state["admin_session"]
    target_id = principal_admin_ui_state["target_id"]
    ordinary_id = principal_admin_ui_state["ordinary_id"]
    grant_id = principal_admin_ui_state["ordinary_grant_id"]
    sessions = principal_admin_ui_state["session_factory"]
    _login(principal_admin_ui_client, issued)
    path = f"/admin/principals/{target_id}/grants/{grant_id}"
    data = {
        "csrf_token": issued.csrf_token,
        "object_id": "ui-admin-root",
        "if_match": '"rev-3"',
    }
    if operation == "update":
        data.update({"role": "viewer", "scope": "self"})
    else:
        path += "/revoke"

    response = principal_admin_ui_client.post(path, data=data)

    assert response.status_code == 404
    with sessions() as session:
        grant = session.get(ObjectGrant, grant_id)
        assert grant is not None
        assert grant.principal_id == ordinary_id
        assert grant.role == Role.OWNER


def test_admin_ui_labels_assignment_controls_and_announces_sensitive_feedback(
    principal_admin_ui_client: TestClient,
    principal_admin_ui_state,
) -> None:
    issued = principal_admin_ui_state["admin_session"]
    target_id = principal_admin_ui_state["target_id"]
    _login(principal_admin_ui_client, issued)
    create = principal_admin_ui_client.post(
        f"/admin/principals/{target_id}/grants",
        data={
            "csrf_token": issued.csrf_token,
            "object_id": "ui-admin-root",
            "role": "viewer",
            "scope": "self",
            "if_match": '"rev-3"',
        },
        follow_redirects=False,
    )
    assert create.status_code == 303
    detail = principal_admin_ui_client.get(f"/admin/principals/{target_id}")
    assert '<label><span class="visually-hidden">Role</span><select name="role">' in detail.text
    assert '<label><span class="visually-hidden">Scope</span><select name="scope">' in detail.text

    denied = principal_admin_ui_client.post(
        f"/admin/principals/{target_id}/tokens",
        data={
            "csrf_token": issued.csrf_token,
            "if_match": '"rev-1"',
            "idempotency_key": "accessible-denied-token-0001",
            "name": "denied",
            "current_admin_password": "wrong-password-value",
            "rotate": "0",
        },
    )
    assert denied.status_code == 403
    assert 'role="alert"' in denied.text

    success = principal_admin_ui_client.post(
        f"/admin/principals/{target_id}/tokens",
        data={
            "csrf_token": issued.csrf_token,
            "if_match": '"rev-1"',
            "idempotency_key": "accessible-issued-token-0001",
            "name": "accessible",
            "current_admin_password": PASSWORD,
            "rotate": "0",
        },
    )
    assert success.status_code == 200
    assert 'role="status"' in success.text
    assert 'aria-live="polite"' in success.text
