from __future__ import annotations

import json
from collections.abc import Generator
from concurrent.futures import ThreadPoolExecutor

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select, update
from sqlalchemy.orm import Session

from blockwart.api.deps import get_session
from blockwart.db.session import DatabaseTransactionError, transaction
from blockwart.domain.auth import CatalogRole, GrantScope, PlatformRole, Role
from blockwart.main import create_app
from blockwart.models import Principal, SecurityEvent
from blockwart.schemas.catalog import CatalogObjectIn
from blockwart.services.access import active_catalog_owner_ids, create_object_grant
from blockwart.services.catalog import upsert_object
from blockwart.services.identity import (
    create_human_principal,
    create_service_account,
    issue_browser_session,
    issue_service_token,
)
from blockwart.services.principal_management import (
    CatalogOwnerDenied,
    ManagedPrincipalConflict,
    ManagedPrincipalPreconditionFailed,
    ManagedPrincipalPreconditionRequired,
    PlatformAdminReauthenticationDenied,
    set_managed_catalog_role,
)
from blockwart.services.read_access import read_access_for_principal
from blockwart.ui.security import AUTH_CSRF_COOKIE_NAME, AUTH_SESSION_COOKIE_NAME

PASSWORD = "dual-role-admin-password"


def _object(object_id: str) -> CatalogObjectIn:
    return CatalogObjectIn(
        id=object_id,
        kind="host",
        label=object_id,
        lifecycle="active",
        health="healthy",
        data={"schema_version": 1},
    )


def _make_dual_admin(session, *, login: str, password: str = PASSWORD):
    """Create a human principal that is both platform admin and catalog owner."""
    principal = create_human_principal(
        session,
        login=login,
        display_name=login,
        password=password,
        platform_role=PlatformRole.ADMIN,
        catalog_role=CatalogRole.CATALOG_OWNER,
    )
    return principal


def _make_admin_only(session, *, login: str, password: str = PASSWORD):
    return create_human_principal(
        session,
        login=login,
        display_name=login,
        password=password,
        platform_role=PlatformRole.ADMIN,
    )


def _make_admin_service(session, *, login: str):
    return create_service_account(
        session,
        login=login,
        display_name=login,
        platform_role=PlatformRole.ADMIN,
    )


def _make_catalog_owner_only(session, *, login: str, password: str = PASSWORD):
    return create_human_principal(
        session,
        login=login,
        display_name=login,
        password=password,
        catalog_role=CatalogRole.CATALOG_OWNER,
    )


# ---------------------------------------------------------------------------
# Service-layer tests
# ---------------------------------------------------------------------------


def test_set_catalog_role_requires_dual_role_platform_admin_and_catalog_owner(
    alembic_session_factory,
) -> None:
    with alembic_session_factory() as session:
        with transaction(session):
            upsert_object(session, _object("svc-root"))
            dual = _make_dual_admin(session, login="dual.admin")
            admin_only = _make_admin_only(session, login="admin.only")
            owner_only = _make_catalog_owner_only(session, login="owner.only")
            target = create_service_account(
                session,
                login="svc.target",
                display_name="Service Target",
            )
            create_object_grant(
                session,
                principal_id=dual.id,
                object_id="svc-root",
                role=Role.OWNER,
                scope=GrantScope.SELF,
            )

        dual_access = read_access_for_principal(session, dual)
        admin_access = read_access_for_principal(session, admin_only)
        owner_access = read_access_for_principal(session, owner_only)

        with pytest.raises(CatalogOwnerDenied):
            with transaction(session):
                set_managed_catalog_role(
                    session,
                    admin_access,
                    principal_id=target.id,
                    expected_revision='"rev-1"',
                    catalog_role=CatalogRole.CATALOG_OWNER,
                    actor_password=PASSWORD,
                    channel="ui",
                )
        with pytest.raises(CatalogOwnerDenied):
            with transaction(session):
                set_managed_catalog_role(
                    session,
                    owner_access,
                    principal_id=target.id,
                    expected_revision='"rev-1"',
                    catalog_role=CatalogRole.CATALOG_OWNER,
                    actor_password=PASSWORD,
                    channel="ui",
                )

        stored = session.get(Principal, target.id)
        assert stored is not None
        assert stored.catalog_role is None
        assert stored.revision == 1

        with transaction(session):
            result = set_managed_catalog_role(
                session,
                dual_access,
                principal_id=target.id,
                expected_revision='"rev-1"',
                catalog_role=CatalogRole.CATALOG_OWNER,
                actor_password=PASSWORD,
                channel="ui",
            )
        assert result.changed is True
        assert result.principal.catalog_role == CatalogRole.CATALOG_OWNER
        assert result.principal.revision == 2


def test_set_catalog_role_denies_service_account_actors(alembic_session_factory) -> None:
    with alembic_session_factory() as session:
        with transaction(session):
            upsert_object(session, _object("svc-root"))
            dual = _make_dual_admin(session, login="dual.admin")
            create_object_grant(
                session,
                principal_id=dual.id,
                object_id="svc-root",
                role=Role.OWNER,
                scope=GrantScope.SELF,
            )
            actor_service = create_service_account(
                session,
                login="actor.svc",
                display_name="Actor Service",
                platform_role=PlatformRole.ADMIN,
                catalog_role=CatalogRole.CATALOG_OWNER,
            )
            target = create_service_account(
                session,
                login="svc.target",
                display_name="Service Target",
            )
        access = read_access_for_principal(session, actor_service)

        with pytest.raises(PlatformAdminReauthenticationDenied):
            with transaction(session):
                set_managed_catalog_role(
                    session,
                    access,
                    principal_id=target.id,
                    expected_revision='"rev-1"',
                    catalog_role=CatalogRole.CATALOG_OWNER,
                    actor_password=None,
                    channel="api",
                )
        stored = session.get(Principal, target.id)
        assert stored is not None
        assert stored.catalog_role is None


def test_set_catalog_role_requires_human_reauthentication(alembic_session_factory) -> None:
    with alembic_session_factory() as session:
        with transaction(session):
            upsert_object(session, _object("svc-root"))
            dual = _make_dual_admin(session, login="dual.admin")
            create_object_grant(
                session,
                principal_id=dual.id,
                object_id="svc-root",
                role=Role.OWNER,
                scope=GrantScope.SELF,
            )
            target = create_service_account(
                session,
                login="svc.target",
                display_name="Service Target",
            )
        access = read_access_for_principal(session, dual)

        with pytest.raises(PlatformAdminReauthenticationDenied):
            with transaction(session):
                set_managed_catalog_role(
                    session,
                    access,
                    principal_id=target.id,
                    expected_revision='"rev-1"',
                    catalog_role=CatalogRole.CATALOG_OWNER,
                    actor_password=None,
                    channel="ui",
                )
        with pytest.raises(PlatformAdminReauthenticationDenied):
            with transaction(session):
                set_managed_catalog_role(
                    session,
                    access,
                    principal_id=target.id,
                    expected_revision='"rev-1"',
                    catalog_role=CatalogRole.CATALOG_OWNER,
                    actor_password="definitely-not-the-password",
                    channel="ui",
                )
        stored = session.get(Principal, target.id)
        assert stored is not None
        assert stored.revision == 1


@pytest.mark.parametrize("missing", (True, False))
def test_set_catalog_role_requires_etag_precondition(
    alembic_session_factory, missing: bool
) -> None:
    with alembic_session_factory() as session:
        with transaction(session):
            upsert_object(session, _object("svc-root"))
            dual = _make_dual_admin(session, login="dual.admin")
            create_object_grant(
                session,
                principal_id=dual.id,
                object_id="svc-root",
                role=Role.OWNER,
                scope=GrantScope.SELF,
            )
            target = create_service_account(
                session,
                login="svc.target",
                display_name="Service Target",
            )
        access = read_access_for_principal(session, dual)
        if missing:
            with pytest.raises(ManagedPrincipalPreconditionRequired):
                with transaction(session):
                    set_managed_catalog_role(
                        session,
                        access,
                        principal_id=target.id,
                        expected_revision=None,
                        catalog_role=CatalogRole.CATALOG_OWNER,
                        actor_password=PASSWORD,
                        channel="ui",
                    )
        else:
            with pytest.raises(ManagedPrincipalPreconditionFailed):
                with transaction(session):
                    set_managed_catalog_role(
                        session,
                        access,
                        principal_id=target.id,
                        expected_revision='"rev-99"',
                        catalog_role=CatalogRole.CATALOG_OWNER,
                        actor_password=PASSWORD,
                        channel="ui",
                    )
        stored = session.get(Principal, target.id)
        assert stored is not None
        assert stored.revision == 1


def test_set_catalog_role_idempotent_noop_emits_no_audit_and_no_revision_bump(
    alembic_session_factory,
) -> None:
    with alembic_session_factory() as session:
        with transaction(session):
            upsert_object(session, _object("svc-root"))
            dual = _make_dual_admin(session, login="dual.admin")
            create_object_grant(
                session,
                principal_id=dual.id,
                object_id="svc-root",
                role=Role.OWNER,
                scope=GrantScope.SELF,
            )
            target = create_service_account(
                session,
                login="svc.target",
                display_name="Service Target",
                catalog_role=CatalogRole.CATALOG_OWNER,
            )
        access = read_access_for_principal(session, dual)
        before_events = session.scalars(
            select(SecurityEvent).where(
                SecurityEvent.event_type == "catalog_owner_role_changed"
            )
        ).all()

        with transaction(session):
            result = set_managed_catalog_role(
                session,
                access,
                principal_id=target.id,
                expected_revision='"rev-1"',
                catalog_role=CatalogRole.CATALOG_OWNER,
                actor_password=PASSWORD,
                channel="ui",
            )
        assert result.changed is False
        assert result.principal.revision == 1
        after_events = session.scalars(
            select(SecurityEvent).where(
                SecurityEvent.event_type == "catalog_owner_role_changed"
            )
        ).all()
        assert after_events == before_events


def test_set_catalog_role_assignment_writes_redacted_audit_event(
    alembic_session_factory,
) -> None:
    with alembic_session_factory() as session:
        with transaction(session):
            upsert_object(session, _object("svc-root"))
            dual = _make_dual_admin(session, login="dual.admin")
            create_object_grant(
                session,
                principal_id=dual.id,
                object_id="svc-root",
                role=Role.OWNER,
                scope=GrantScope.SELF,
            )
            target = create_service_account(
                session,
                login="svc.target",
                display_name="Service Target",
            )
        access = read_access_for_principal(session, dual)

        with transaction(session):
            result = set_managed_catalog_role(
                session,
                access,
                principal_id=target.id,
                expected_revision='"rev-1"',
                catalog_role=CatalogRole.CATALOG_OWNER,
                actor_password=PASSWORD,
                channel="ui",
                request_id="catalog-role-assign-0001",
            )
        assert result.changed is True
        assert result.principal.revision == 2

        event = session.scalar(
            select(SecurityEvent).where(
                SecurityEvent.event_type == "catalog_owner_role_changed",
                SecurityEvent.principal_id == target.id,
            )
        )
        assert event is not None
        assert event.outcome == "success"
        assert event.channel == "ui"
        assert event.request_id == "catalog-role-assign-0001"
        details = json.loads(event.details_json)
        assert details == {
            "actor_principal_id": dual.id,
            "before_catalog_role": "none",
            "after_catalog_role": "catalog_owner",
            "revision": 2,
        }
        assert PASSWORD not in event.details_json


def test_set_catalog_role_removal_with_another_owner_succeeds(
    alembic_session_factory,
) -> None:
    with alembic_session_factory() as session:
        with transaction(session):
            upsert_object(session, _object("svc-root"))
            dual = _make_dual_admin(session, login="dual.admin")
            create_object_grant(
                session,
                principal_id=dual.id,
                object_id="svc-root",
                role=Role.OWNER,
                scope=GrantScope.SELF,
            )
            target = create_service_account(
                session,
                login="svc.target",
                display_name="Service Target",
                catalog_role=CatalogRole.CATALOG_OWNER,
            )
            standby = create_service_account(
                session,
                login="svc.standby",
                display_name="Standby Owner",
                catalog_role=CatalogRole.CATALOG_OWNER,
            )
        access = read_access_for_principal(session, dual)

        with transaction(session):
            result = set_managed_catalog_role(
                session,
                access,
                principal_id=target.id,
                expected_revision='"rev-1"',
                catalog_role=None,
                actor_password=PASSWORD,
                channel="ui",
            )
        assert result.changed is True
        assert result.principal.catalog_role is None
        assert result.principal.revision == 2
        stored_standby = session.get(Principal, standby.id)
        assert stored_standby is not None
        assert stored_standby.catalog_role == CatalogRole.CATALOG_OWNER


def test_set_catalog_role_removal_of_last_owner_rejected(
    alembic_session_factory,
) -> None:
    with alembic_session_factory() as session:
        with transaction(session):
            upsert_object(session, _object("svc-root"))
            dual = _make_dual_admin(session, login="dual.admin")
            create_object_grant(
                session,
                principal_id=dual.id,
                object_id="svc-root",
                role=Role.OWNER,
                scope=GrantScope.SELF,
            )
        access = read_access_for_principal(session, dual)
        before_revision = session.get(Principal, dual.id).revision

        with pytest.raises(ManagedPrincipalConflict, match="catalog owner"):
            with transaction(session):
                set_managed_catalog_role(
                    session,
                    access,
                    principal_id=dual.id,
                    expected_revision=f'"rev-{before_revision}"',
                    catalog_role=None,
                    actor_password=PASSWORD,
                    channel="ui",
                )
        stored = session.get(Principal, dual.id)
        assert stored is not None
        assert stored.catalog_role == CatalogRole.CATALOG_OWNER
        assert stored.revision == before_revision


def test_concurrent_catalog_role_removal_cannot_orphan_the_last_owner(
    alembic_database,
) -> None:
    session_factory = alembic_database.sessions
    with session_factory() as session:
        with transaction(session):
            first = create_service_account(
                session,
                login="race.first.owner",
                display_name="First",
                catalog_role=CatalogRole.CATALOG_OWNER,
            )
            second = create_service_account(
                session,
                login="race.second.owner",
                display_name="Second",
                catalog_role=CatalogRole.CATALOG_OWNER,
            )
        owner_ids = [first.id, second.id]

    def demote(principal_id: str) -> bool:
        with session_factory() as session:
            try:
                with transaction(session):
                    session.execute(
                        update(Principal)
                        .where(Principal.id == principal_id)
                        .values(catalog_role=None)
                    )
            except DatabaseTransactionError:
                return False
        return True

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(demote, owner_ids))

    assert sorted(results) == [False, True]
    with session_factory() as session:
        assert len(active_catalog_owner_ids(session)) == 1


def test_normal_administration_cannot_mint_first_owner_when_none_exists(
    alembic_session_factory,
) -> None:
    with alembic_session_factory() as session:
        with transaction(session):
            upsert_object(session, _object("svc-root"))
            admin_only = _make_admin_only(session, login="admin.only")
            create_object_grant(
                session,
                principal_id=admin_only.id,
                object_id="svc-root",
                role=Role.OWNER,
                scope=GrantScope.SELF,
            )
            target = create_service_account(
                session,
                login="svc.target",
                display_name="Service Target",
            )
        access = read_access_for_principal(session, admin_only)
        assert active_catalog_owner_ids(session) == set()

        with pytest.raises(CatalogOwnerDenied):
            with transaction(session):
                set_managed_catalog_role(
                    session,
                    access,
                    principal_id=target.id,
                    expected_revision='"rev-1"',
                    catalog_role=CatalogRole.CATALOG_OWNER,
                    actor_password=PASSWORD,
                    channel="ui",
                )
        stored = session.get(Principal, target.id)
        assert stored is not None
        assert stored.catalog_role is None


# ---------------------------------------------------------------------------
# REST + UI integration tests
# ---------------------------------------------------------------------------


@pytest.fixture
def catalog_role_api_state(alembic_session_factory):
    with alembic_session_factory() as session:
        with transaction(session):
            upsert_object(session, _object("api-root"))
            dual = _make_dual_admin(session, login="dual.admin")
            admin_service = _make_admin_service(session, login="admin.svc")
            create_object_grant(
                session,
                principal_id=dual.id,
                object_id="api-root",
                role=Role.OWNER,
                scope=GrantScope.SELF,
            )
            dual_service = create_service_account(
                session,
                login="dual.svc",
                display_name="Dual Service",
                platform_role=PlatformRole.ADMIN,
                catalog_role=CatalogRole.CATALOG_OWNER,
            )
            target = create_service_account(
                session,
                login="svc.target",
                display_name="Service Target",
            )
            dual_token = issue_service_token(
                session, principal_id=dual_service.id, name="dual-api"
            ).value
            admin_token = issue_service_token(
                session, principal_id=admin_service.id, name="admin-only-api"
            ).value
            issued = issue_browser_session(
                session, principal_id=dual.id, ttl_seconds=3600
            )
    return {
        "session_factory": alembic_session_factory,
        "dual_id": dual.id,
        "admin_only_id": admin_service.id,
        "target_id": target.id,
        "dual_token": dual_token,
        "admin_token": admin_token,
        "issued": issued,
    }


@pytest.fixture
def catalog_role_api_client(catalog_role_api_state) -> Generator[TestClient, None, None]:
    app = create_app()
    sessions = catalog_role_api_state["session_factory"]

    def override_get_session() -> Generator[Session, None, None]:
        with sessions() as session:
            yield session

    app.dependency_overrides[get_session] = override_get_session
    with TestClient(app) as client:
        yield client


def _browser_headers(
    issued, *, if_match: str | None = None, csrf: str | None = None
) -> dict[str, str]:
    headers = {"X-CSRF-Token": csrf if csrf is not None else issued.csrf_token}
    if if_match is not None:
        headers["If-Match"] = if_match
    return headers


def _login_browser(client: TestClient, issued) -> None:
    client.cookies.set(AUTH_SESSION_COOKIE_NAME, issued.value)
    client.cookies.set(AUTH_CSRF_COOKIE_NAME, issued.csrf_token)


def test_rest_catalog_role_assigns_role_via_browser_session(
    catalog_role_api_client: TestClient,
    catalog_role_api_state,
) -> None:
    target_id = catalog_role_api_state["target_id"]
    issued = catalog_role_api_state["issued"]
    sessions = catalog_role_api_state["session_factory"]
    _login_browser(catalog_role_api_client, issued)

    response = catalog_role_api_client.post(
        f"/api/v1/admin/principals/{target_id}/catalog-role",
        headers=_browser_headers(issued, if_match='"rev-1"'),
        json={"catalog_role": "catalog_owner", "current_admin_password": PASSWORD},
    )
    assert response.status_code == 200
    assert response.json()["changed"] is True
    assert response.json()["principal"]["catalog_role"] == "catalog_owner"
    assert response.headers["etag"] == '"rev-2"'
    with sessions() as session:
        stored = session.get(Principal, target_id)
        assert stored is not None
        assert stored.catalog_role == CatalogRole.CATALOG_OWNER
        assert stored.revision == 2


def test_rest_catalog_role_removal_with_another_owner_succeeds(
    catalog_role_api_client: TestClient,
    catalog_role_api_state,
) -> None:
    target_id = catalog_role_api_state["target_id"]
    issued = catalog_role_api_state["issued"]
    sessions = catalog_role_api_state["session_factory"]
    with sessions() as session:
        with transaction(session):
            stored = session.get(Principal, target_id)
            assert stored is not None
            stored.catalog_role = CatalogRole.CATALOG_OWNER
            create_service_account(
                session,
                login="svc.standby.owner",
                display_name="Standby",
                catalog_role=CatalogRole.CATALOG_OWNER,
            )
    _login_browser(catalog_role_api_client, issued)

    response = catalog_role_api_client.post(
        f"/api/v1/admin/principals/{target_id}/catalog-role",
        headers=_browser_headers(issued, if_match='"rev-1"'),
        json={"catalog_role": None, "current_admin_password": PASSWORD},
    )
    assert response.status_code == 200
    assert response.json()["changed"] is True
    assert response.json()["principal"]["catalog_role"] is None
    with sessions() as session:
        stored = session.get(Principal, target_id)
        assert stored is not None
        assert stored.catalog_role is None
        assert stored.revision == 2


def test_rest_catalog_role_missing_etag_returns_428(
    catalog_role_api_client: TestClient,
    catalog_role_api_state,
) -> None:
    target_id = catalog_role_api_state["target_id"]
    issued = catalog_role_api_state["issued"]
    _login_browser(catalog_role_api_client, issued)

    response = catalog_role_api_client.post(
        f"/api/v1/admin/principals/{target_id}/catalog-role",
        headers=_browser_headers(issued),
        json={"catalog_role": "catalog_owner", "current_admin_password": PASSWORD},
    )
    assert response.status_code == 428


def test_rest_catalog_role_stale_etag_returns_412(
    catalog_role_api_client: TestClient,
    catalog_role_api_state,
) -> None:
    target_id = catalog_role_api_state["target_id"]
    issued = catalog_role_api_state["issued"]
    _login_browser(catalog_role_api_client, issued)

    response = catalog_role_api_client.post(
        f"/api/v1/admin/principals/{target_id}/catalog-role",
        headers=_browser_headers(issued, if_match='"rev-99"'),
        json={"catalog_role": "catalog_owner", "current_admin_password": PASSWORD},
    )
    assert response.status_code == 412


def test_rest_catalog_role_missing_or_invalid_csrf_returns_403(
    catalog_role_api_client: TestClient,
    catalog_role_api_state,
) -> None:
    target_id = catalog_role_api_state["target_id"]
    issued = catalog_role_api_state["issued"]
    sessions = catalog_role_api_state["session_factory"]
    _login_browser(catalog_role_api_client, issued)
    payload = {"catalog_role": "catalog_owner", "current_admin_password": PASSWORD}

    missing_header = catalog_role_api_client.post(
        f"/api/v1/admin/principals/{target_id}/catalog-role",
        headers={"If-Match": '"rev-1"'},
        json=payload,
    )
    assert missing_header.status_code == 403

    invalid_header = catalog_role_api_client.post(
        f"/api/v1/admin/principals/{target_id}/catalog-role",
        headers={"If-Match": '"rev-1"', "X-CSRF-Token": "definitely-not-the-csrf"},
        json=payload,
    )
    assert invalid_header.status_code == 403

    with sessions() as session:
        events = session.scalars(
            select(SecurityEvent).where(
                SecurityEvent.event_type == "browser_write_csrf",
                SecurityEvent.outcome == "denied",
                SecurityEvent.channel == "api",
            )
        ).all()
        assert len(events) >= 2
        for event in events:
            assert "csrf" not in (event.details_json or "").casefold() or "invalid_csrf" in (
                event.details_json or ""
            )
            assert issued.csrf_token not in (event.details_json or "")


def test_rest_catalog_role_absent_browser_session_returns_401(
    catalog_role_api_client: TestClient,
    catalog_role_api_state,
) -> None:
    target_id = catalog_role_api_state["target_id"]
    response = catalog_role_api_client.post(
        f"/api/v1/admin/principals/{target_id}/catalog-role",
        headers={"If-Match": '"rev-1"', "X-CSRF-Token": "any"},
        json={"catalog_role": "catalog_owner", "current_admin_password": PASSWORD},
    )
    assert response.status_code == 401


def test_rest_catalog_role_invalid_browser_session_returns_401(
    catalog_role_api_client: TestClient,
    catalog_role_api_state,
) -> None:
    target_id = catalog_role_api_state["target_id"]
    issued = catalog_role_api_state["issued"]
    catalog_role_api_client.cookies.set(AUTH_SESSION_COOKIE_NAME, "bwss_invalid.not-a-real-session")
    catalog_role_api_client.cookies.set(AUTH_CSRF_COOKIE_NAME, issued.csrf_token)

    response = catalog_role_api_client.post(
        f"/api/v1/admin/principals/{target_id}/catalog-role",
        headers={"If-Match": '"rev-1"', "X-CSRF-Token": issued.csrf_token},
        json={"catalog_role": "catalog_owner", "current_admin_password": PASSWORD},
    )
    assert response.status_code == 401


def test_rest_catalog_role_wrong_password_returns_403_and_audits_failure(
    catalog_role_api_client: TestClient,
    catalog_role_api_state,
) -> None:
    target_id = catalog_role_api_state["target_id"]
    issued = catalog_role_api_state["issued"]
    sessions = catalog_role_api_state["session_factory"]
    _login_browser(catalog_role_api_client, issued)

    response = catalog_role_api_client.post(
        f"/api/v1/admin/principals/{target_id}/catalog-role",
        headers=_browser_headers(issued, if_match='"rev-1"'),
        json={"catalog_role": "catalog_owner", "current_admin_password": "definitely-wrong"},
    )
    assert response.status_code == 403
    with sessions() as session:
        event = session.scalar(
            select(SecurityEvent).where(
                SecurityEvent.event_type == "platform_admin_reauthentication",
                SecurityEvent.outcome == "failure",
                SecurityEvent.channel == "api",
            )
        )
        assert event is not None
        assert "definitely-wrong" not in (event.details_json or "").casefold()


def test_rest_catalog_role_dual_role_denial_returns_403(
    catalog_role_api_state,
) -> None:
    sessions = catalog_role_api_state["session_factory"]
    with sessions() as session:
        with transaction(session):
            admin_only = _make_admin_only(session, login="admin.only.human")
            issued = issue_browser_session(
                session, principal_id=admin_only.id, ttl_seconds=3600
            )

    app = create_app()

    def override_get_session() -> Generator[Session, None, None]:
        with sessions() as s:
            yield s

    app.dependency_overrides[get_session] = override_get_session
    with TestClient(app) as client:
        client.cookies.set(AUTH_SESSION_COOKIE_NAME, issued.value)
        client.cookies.set(AUTH_CSRF_COOKIE_NAME, issued.csrf_token)
        response = client.post(
            f"/api/v1/admin/principals/{catalog_role_api_state['target_id']}/catalog-role",
            headers={"If-Match": '"rev-1"', "X-CSRF-Token": issued.csrf_token},
            json={"catalog_role": "catalog_owner", "current_admin_password": PASSWORD},
        )
        assert response.status_code == 403


def test_rest_catalog_role_last_owner_rejection_returns_409(
    alembic_session_factory,
) -> None:
    sessions = alembic_session_factory
    with sessions() as session:
        with transaction(session):
            upsert_object(session, _object("last-owner-root"))
            dual = _make_dual_admin(session, login="sole.dual.admin")
            create_object_grant(
                session,
                principal_id=dual.id,
                object_id="last-owner-root",
                role=Role.OWNER,
                scope=GrantScope.SELF,
            )
            issued = issue_browser_session(
                session, principal_id=dual.id, ttl_seconds=3600
            )

    app = create_app()

    def override_get_session() -> Generator[Session, None, None]:
        with sessions() as s:
            yield s

    app.dependency_overrides[get_session] = override_get_session
    with TestClient(app) as client:
        client.cookies.set(AUTH_SESSION_COOKIE_NAME, issued.value)
        client.cookies.set(AUTH_CSRF_COOKIE_NAME, issued.csrf_token)
        response = client.post(
            f"/api/v1/admin/principals/{dual.id}/catalog-role",
            headers={"If-Match": '"rev-1"', "X-CSRF-Token": issued.csrf_token},
            json={"catalog_role": None, "current_admin_password": PASSWORD},
        )
        assert response.status_code == 409
    with sessions() as session:
        stored = session.get(Principal, dual.id)
        assert stored is not None
        assert stored.catalog_role == CatalogRole.CATALOG_OWNER
        assert stored.revision == 1


def test_rest_catalog_role_idempotent_noop(
    catalog_role_api_client: TestClient,
    catalog_role_api_state,
) -> None:
    target_id = catalog_role_api_state["target_id"]
    issued = catalog_role_api_state["issued"]
    sessions = catalog_role_api_state["session_factory"]
    with sessions() as session:
        with transaction(session):
            stored = session.get(Principal, target_id)
            assert stored is not None
            stored.catalog_role = CatalogRole.CATALOG_OWNER
    _login_browser(catalog_role_api_client, issued)

    response = catalog_role_api_client.post(
        f"/api/v1/admin/principals/{target_id}/catalog-role",
        headers=_browser_headers(issued, if_match='"rev-1"'),
        json={"catalog_role": "catalog_owner", "current_admin_password": PASSWORD},
    )
    assert response.status_code == 200
    assert response.json()["changed"] is False
    assert response.headers["etag"] == '"rev-1"'


def test_rest_catalog_role_denies_service_bearer_actors(
    catalog_role_api_client: TestClient,
    catalog_role_api_state,
) -> None:
    target_id = catalog_role_api_state["target_id"]
    dual_token = catalog_role_api_state["dual_token"]
    admin_token = catalog_role_api_state["admin_token"]
    payload = {"catalog_role": "catalog_owner", "current_admin_password": PASSWORD}

    admin_bearer = catalog_role_api_client.post(
        f"/api/v1/admin/principals/{target_id}/catalog-role",
        headers={"Authorization": f"Bearer {admin_token}", "If-Match": '"rev-1"'},
        json=payload,
    )
    assert admin_bearer.status_code == 401

    dual_bearer = catalog_role_api_client.post(
        f"/api/v1/admin/principals/{target_id}/catalog-role",
        headers={"Authorization": f"Bearer {dual_token}", "If-Match": '"rev-1"'},
        json=payload,
    )
    assert dual_bearer.status_code == 401

    sessions = catalog_role_api_state["session_factory"]
    with sessions() as session:
        stored = session.get(Principal, target_id)
        assert stored is not None
        assert stored.catalog_role is None


def test_rest_other_admin_routes_remain_bearer_only(
    catalog_role_api_client: TestClient,
    catalog_role_api_state,
) -> None:
    admin_token = catalog_role_api_state["admin_token"]
    target_id = catalog_role_api_state["target_id"]
    issued = catalog_role_api_state["issued"]
    _login_browser(catalog_role_api_client, issued)

    bearer_ok = catalog_role_api_client.get(
        f"/api/v1/admin/principals/{target_id}",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert bearer_ok.status_code == 200

    browser_no_bearer = catalog_role_api_client.get(
        f"/api/v1/admin/principals/{target_id}",
    )
    assert browser_no_bearer.status_code == 401


def test_rest_principal_projection_exposes_catalog_role_and_global_authority(
    catalog_role_api_client: TestClient,
    catalog_role_api_state,
) -> None:
    target_id = catalog_role_api_state["target_id"]
    admin_token = catalog_role_api_state["admin_token"]
    sessions = catalog_role_api_state["session_factory"]
    with sessions() as session:
        with transaction(session):
            stored = session.get(Principal, target_id)
            assert stored is not None
            stored.catalog_role = CatalogRole.CATALOG_OWNER

    detail = catalog_role_api_client.get(
        f"/api/v1/admin/principals/{target_id}",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert detail.status_code == 200
    assert detail.json()["principal"]["catalog_role"] == "catalog_owner"
    authorities = detail.json()["global_authorities"]
    assert authorities == [
        {
            "source": "catalog_owner",
            "permissions": [
                "create_child",
                "delete",
                "discover",
                "manage_access",
                "read",
                "write",
            ],
        }
    ]


@pytest.fixture
def catalog_role_ui_state(alembic_session_factory):
    with alembic_session_factory() as session:
        with transaction(session):
            upsert_object(session, _object("ui-root"))
            dual = _make_dual_admin(session, login="dual.admin")
            create_object_grant(
                session,
                principal_id=dual.id,
                object_id="ui-root",
                role=Role.OWNER,
                scope=GrantScope.SELF,
            )
            target = create_service_account(
                session,
                login="svc.target",
                display_name="Service Target",
            )
            issued = issue_browser_session(
                session, principal_id=dual.id, ttl_seconds=3600
            )
    return {
        "session_factory": alembic_session_factory,
        "dual_id": dual.id,
        "target_id": target.id,
        "issued": issued,
    }


@pytest.fixture
def catalog_role_ui_client(catalog_role_ui_state) -> Generator[TestClient, None, None]:
    app = create_app()
    sessions = catalog_role_ui_state["session_factory"]

    def override_get_session() -> Generator[Session, None, None]:
        with sessions() as session:
            yield session

    app.dependency_overrides[get_session] = override_get_session
    with TestClient(app, base_url="https://testserver") as client:
        yield client


def _login(client: TestClient, issued) -> None:
    client.cookies.set(AUTH_SESSION_COOKIE_NAME, issued.value)
    client.cookies.set(AUTH_CSRF_COOKIE_NAME, issued.csrf_token)


def test_ui_catalog_role_control_assigns_role_and_shows_in_views(
    catalog_role_ui_client: TestClient,
    catalog_role_ui_state,
) -> None:
    issued = catalog_role_ui_state["issued"]
    target_id = catalog_role_ui_state["target_id"]
    sessions = catalog_role_ui_state["session_factory"]
    _login(catalog_role_ui_client, issued)

    detail = catalog_role_ui_client.get(f"/admin/principals/{target_id}")
    assert detail.status_code == 200
    assert "Catalog role" in detail.text
    assert "/catalog-role" in detail.text

    response = catalog_role_ui_client.post(
        f"/admin/principals/{target_id}/catalog-role",
        data={
            "csrf_token": issued.csrf_token,
            "if_match": '"rev-1"',
            "catalog_role": "catalog_owner",
            "current_admin_password": PASSWORD,
        },
        follow_redirects=False,
    )
    assert response.status_code == 303
    with sessions() as session:
        stored = session.get(Principal, target_id)
        assert stored is not None
        assert stored.catalog_role == CatalogRole.CATALOG_OWNER
        assert stored.revision == 2

    listing = catalog_role_ui_client.get("/admin/principals")
    assert listing.status_code == 200
    assert "Catalog role" in listing.text
    assert "Catalog owner" in listing.text

    reloaded = catalog_role_ui_client.get(f"/admin/principals/{target_id}")
    assert reloaded.status_code == 200
    assert "Catalog owner" in reloaded.text


def test_ui_catalog_role_etag_precondition_behavior(
    catalog_role_ui_client: TestClient,
    catalog_role_ui_state,
) -> None:
    issued = catalog_role_ui_state["issued"]
    target_id = catalog_role_ui_state["target_id"]
    sessions = catalog_role_ui_state["session_factory"]
    _login(catalog_role_ui_client, issued)

    stale = catalog_role_ui_client.post(
        f"/admin/principals/{target_id}/catalog-role",
        data={
            "csrf_token": issued.csrf_token,
            "if_match": '"rev-99"',
            "catalog_role": "catalog_owner",
            "current_admin_password": PASSWORD,
        },
        follow_redirects=False,
    )
    assert stale.status_code == 412
    with sessions() as session:
        stored = session.get(Principal, target_id)
        assert stored is not None
        assert stored.catalog_role is None
        assert stored.revision == 1


def test_ui_catalog_role_requires_csrf_and_reauthentication(
    catalog_role_ui_client: TestClient,
    catalog_role_ui_state,
) -> None:
    issued = catalog_role_ui_state["issued"]
    target_id = catalog_role_ui_state["target_id"]
    sessions = catalog_role_ui_state["session_factory"]
    _login(catalog_role_ui_client, issued)

    no_csrf = catalog_role_ui_client.post(
        f"/admin/principals/{target_id}/catalog-role",
        data={
            "csrf_token": "invalid-csrf",
            "if_match": '"rev-1"',
            "catalog_role": "catalog_owner",
            "current_admin_password": PASSWORD,
        },
        follow_redirects=False,
    )
    assert no_csrf.status_code == 403
    with sessions() as session:
        stored = session.get(Principal, target_id)
        assert stored is not None
        assert stored.catalog_role is None

    wrong_password = catalog_role_ui_client.post(
        f"/admin/principals/{target_id}/catalog-role",
        data={
            "csrf_token": issued.csrf_token,
            "if_match": '"rev-1"',
            "catalog_role": "catalog_owner",
            "current_admin_password": "definitely-wrong",
        },
        follow_redirects=False,
    )
    assert wrong_password.status_code == 403
    assert 'role="alert"' in wrong_password.text
    with sessions() as session:
        stored = session.get(Principal, target_id)
        assert stored is not None
        assert stored.catalog_role is None


def test_ui_catalog_role_control_is_not_folded_into_generic_principal_edit(
    catalog_role_ui_client: TestClient,
    catalog_role_ui_state,
) -> None:
    issued = catalog_role_ui_state["issued"]
    target_id = catalog_role_ui_state["target_id"]
    _login(catalog_role_ui_client, issued)

    detail = catalog_role_ui_client.get(f"/admin/principals/{target_id}")
    assert detail.status_code == 200
    account_form_start = detail.text.find('<form class="form-grid" method="post" '
                                           'action="/admin/principals/')
    catalog_form_start = detail.text.find(
        'action="/admin/principals/' + target_id + '/catalog-role"'
    )
    assert account_form_start != -1
    assert catalog_form_start != -1
    generic_form = detail.text[account_form_start:detail.text.find(
        "</form>", account_form_start
    )]
    assert "catalog_role" not in generic_form


def test_ui_catalog_role_removal_with_another_owner_succeeds(
    catalog_role_ui_state,
) -> None:
    sessions = catalog_role_ui_state["session_factory"]
    with sessions() as session:
        with transaction(session):
            target = create_service_account(
                session,
                login="svc.removable",
                display_name="Removable",
                catalog_role=CatalogRole.CATALOG_OWNER,
            )
            standby = create_service_account(
                session,
                login="svc.standby.owner",
                display_name="Standby",
                catalog_role=CatalogRole.CATALOG_OWNER,
            )

    app = create_app()

    def override_get_session() -> Generator[Session, None, None]:
        with sessions() as session:
            yield session

    app.dependency_overrides[get_session] = override_get_session
    issued = catalog_role_ui_state["issued"]
    with TestClient(app, base_url="https://testserver") as client:
        client.cookies.set(AUTH_SESSION_COOKIE_NAME, issued.value)
        client.cookies.set(AUTH_CSRF_COOKIE_NAME, issued.csrf_token)
        response = client.post(
            f"/admin/principals/{target.id}/catalog-role",
            data={
                "csrf_token": issued.csrf_token,
                "if_match": '"rev-1"',
                "catalog_role": "",
                "current_admin_password": PASSWORD,
            },
            follow_redirects=False,
        )
        assert response.status_code == 303
    with sessions() as session:
        stored = session.get(Principal, target.id)
        assert stored is not None
        assert stored.catalog_role is None
        assert stored.revision == 2
        standby_stored = session.get(Principal, standby.id)
        assert standby_stored is not None
        assert standby_stored.catalog_role == CatalogRole.CATALOG_OWNER


def test_ui_catalog_role_idempotent_noop_no_revision_bump(
    catalog_role_ui_client: TestClient,
    catalog_role_ui_state,
) -> None:
    issued = catalog_role_ui_state["issued"]
    target_id = catalog_role_ui_state["target_id"]
    sessions = catalog_role_ui_state["session_factory"]
    _login(catalog_role_ui_client, issued)
    with sessions() as session:
        with transaction(session):
            stored = session.get(Principal, target_id)
            assert stored is not None
            stored.catalog_role = CatalogRole.CATALOG_OWNER

    response = catalog_role_ui_client.post(
        f"/admin/principals/{target_id}/catalog-role",
        data={
            "csrf_token": issued.csrf_token,
            "if_match": '"rev-1"',
            "catalog_role": "catalog_owner",
            "current_admin_password": PASSWORD,
        },
        follow_redirects=False,
    )
    assert response.status_code == 303
    with sessions() as session:
        stored = session.get(Principal, target_id)
        assert stored is not None
        assert stored.catalog_role == CatalogRole.CATALOG_OWNER
        assert stored.revision == 1
        event = session.scalar(
            select(SecurityEvent).where(
                SecurityEvent.event_type == "catalog_owner_role_changed",
                SecurityEvent.principal_id == target_id,
            )
        )
        assert event is None


def test_ui_catalog_role_audit_event_is_redacted(
    catalog_role_ui_client: TestClient,
    catalog_role_ui_state,
) -> None:
    issued = catalog_role_ui_state["issued"]
    target_id = catalog_role_ui_state["target_id"]
    sessions = catalog_role_ui_state["session_factory"]
    _login(catalog_role_ui_client, issued)

    response = catalog_role_ui_client.post(
        f"/admin/principals/{target_id}/catalog-role",
        data={
            "csrf_token": issued.csrf_token,
            "if_match": '"rev-1"',
            "catalog_role": "catalog_owner",
            "current_admin_password": PASSWORD,
        },
        follow_redirects=False,
    )
    assert response.status_code == 303
    with sessions() as session:
        event = session.scalar(
            select(SecurityEvent).where(
                SecurityEvent.event_type == "catalog_owner_role_changed",
                SecurityEvent.principal_id == target_id,
            )
        )
        assert event is not None
        assert event.outcome == "success"
        assert event.channel == "ui"
        details = json.loads(event.details_json)
        assert details["before_catalog_role"] == "none"
        assert details["after_catalog_role"] == "catalog_owner"
        assert details["revision"] == 2
        assert details["actor_principal_id"] == catalog_role_ui_state["dual_id"]
        assert PASSWORD not in event.details_json


# ---------------------------------------------------------------------------
# MCP read-only visibility and absence of mutation surface
# ---------------------------------------------------------------------------


def test_mcp_has_no_catalog_role_mutation_tool() -> None:
    from blockwart.mcp.server import TOOL_DEFINITIONS

    write_tools = {
        name
        for name, tool in TOOL_DEFINITIONS.items()
        if tool.get("annotations", {}).get("readOnlyHint") is False
    }
    assert not any("catalog" in name.lower() for name in write_tools)
    assert not any(
        "catalog_role" in str(tool.get("inputSchema", {}).get("properties", {}))
        for tool in TOOL_DEFINITIONS.values()
    )


def test_mcp_admin_principal_tools_remain_read_only_get_endpoints() -> None:
    from blockwart.mcp.server import call_tool

    calls = []

    def fake_fetch(path, params):
        calls.append((path, params))
        return {"path": path, "params": params}

    call_tool(
        "blockwart.list_admin_principals",
        {"query": "kai"},
        fetcher=fake_fetch,
    )
    call_tool(
        "blockwart.get_admin_principal",
        {"principal_id": "principal/root"},
        fetcher=fake_fetch,
    )
    assert calls == [
        (
            "/api/v1/admin/principals",
            {"q": "kai", "principal_type": None, "active": None,
             "limit": 100, "cursor": None},
        ),
        ("/api/v1/admin/principals/principal%2Froot", {}),
    ]
    assert all("catalog-role" not in path for path, _ in calls)