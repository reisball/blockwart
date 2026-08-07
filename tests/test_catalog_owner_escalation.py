"""Adversarial coverage for the catalog-owner privilege-escalation paths.

Every test here fails on the parent commit. They pin three closed holes:

* credential administration (token issue, token rotation, human password reset)
  targeting a principal that currently holds the global catalog-owner role must
  pass the dual-role, human-reauthenticated gate, never the generic
  platform-admin contract or its service-account API exemption;
* the catalog-owner role can neither be parked on an inactive principal nor
  survive a generic reactivation, so global authority never appears without the
  dedicated role-change workflow and its audit;
* a dual-role authorization denial leaves exactly one redacted security event on
  both the REST and the UI path.
"""

from __future__ import annotations

import json
from collections.abc import Generator

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select, update
from sqlalchemy.orm import Session

from blockwart.api.deps import get_session
from blockwart.db.session import transaction
from blockwart.domain.auth import CatalogRole, GrantScope, PlatformRole, PrincipalType, Role
from blockwart.main import create_app
from blockwart.models import IdempotencyRecord, Principal, SecurityEvent, ServiceToken
from blockwart.schemas.catalog import CatalogObjectIn
from blockwart.services.access import create_object_grant
from blockwart.services.catalog import upsert_object
from blockwart.services.identity import (
    authenticate_browser_session,
    authenticate_password,
    create_human_principal,
    create_service_account,
    issue_browser_session,
    issue_service_token,
    principal_context,
)
from blockwart.services.principal_management import (
    CatalogOwnerDenied,
    ManagedPrincipalConflict,
    ManagedPrincipalPreconditionFailed,
    PlatformAdminReauthenticationDenied,
    issue_managed_service_token,
    reset_managed_human_password,
    set_managed_catalog_role,
    update_managed_principal,
)
from blockwart.services.read_access import read_access_for_principal
from blockwart.ui.security import AUTH_CSRF_COOKIE_NAME, AUTH_SESSION_COOKIE_NAME

PASSWORD = "catalog-owner-escalation-password"
TARGET_PASSWORD = "catalog-owner-target-password"
TTL_SECONDS = 3600


def _object(object_id: str) -> CatalogObjectIn:
    return CatalogObjectIn(
        id=object_id,
        kind="host",
        label=object_id,
        lifecycle="active",
        health="healthy",
        data={"schema_version": 1},
    )


def _escalation_fixture(session) -> dict[str, str]:
    """One active dual-role human plus the actors and targets the tests drive."""
    with transaction(session):
        upsert_object(session, _object("escalation-root"))
        dual = create_human_principal(
            session,
            login="dual.admin",
            display_name="Dual Admin",
            password=PASSWORD,
            platform_role=PlatformRole.ADMIN,
            catalog_role=CatalogRole.CATALOG_OWNER,
        )
        create_object_grant(
            session,
            principal_id=dual.id,
            object_id="escalation-root",
            role=Role.OWNER,
            scope=GrantScope.SELF,
        )
        admin_human = create_human_principal(
            session,
            login="admin.only",
            display_name="Admin Only",
            password=PASSWORD,
            platform_role=PlatformRole.ADMIN,
        )
        admin_service = create_service_account(
            session,
            login="admin.svc",
            display_name="Admin Service",
            platform_role=PlatformRole.ADMIN,
        )
        dual_service = create_service_account(
            session,
            login="dual.svc",
            display_name="Dual Service",
            platform_role=PlatformRole.ADMIN,
            catalog_role=CatalogRole.CATALOG_OWNER,
        )
        owner_service = create_service_account(
            session,
            login="owner.svc",
            display_name="Owner Service",
            catalog_role=CatalogRole.CATALOG_OWNER,
        )
        owner_human = create_human_principal(
            session,
            login="owner.human",
            display_name="Owner Human",
            password=TARGET_PASSWORD,
            catalog_role=CatalogRole.CATALOG_OWNER,
        )
        plain_service = create_service_account(
            session,
            login="plain.svc",
            display_name="Plain Service",
        )
        plain_human = create_human_principal(
            session,
            login="plain.human",
            display_name="Plain Human",
            password=TARGET_PASSWORD,
        )
    return {
        "dual_id": dual.id,
        "admin_human_id": admin_human.id,
        "admin_service_id": admin_service.id,
        "dual_service_id": dual_service.id,
        "owner_service_id": owner_service.id,
        "owner_human_id": owner_human.id,
        "plain_service_id": plain_service.id,
        "plain_human_id": plain_human.id,
    }


def _access(session, principal_id: str):
    principal = session.get(Principal, principal_id)
    assert principal is not None
    return read_access_for_principal(session, principal_context(principal))


def _state_snapshot(session, principal_id: str) -> dict[str, object]:
    row = session.get(Principal, principal_id)
    assert row is not None
    return {
        "revision": row.revision,
        "active": row.active,
        "catalog_role": row.catalog_role,
        "tokens": sorted(
            (token.name, token.token_hash, token.revoked_at is not None)
            for token in session.scalars(
                select(ServiceToken).where(ServiceToken.principal_id == principal_id)
            ).all()
        ),
        # Only success evidence: a denial legitimately adds its own denied event.
        "success_events": sorted(
            (event.event_type, event.principal_id)
            for event in session.scalars(
                select(SecurityEvent).where(SecurityEvent.outcome == "success")
            ).all()
        ),
    }


def _idempotency_count(session) -> int:
    return len(session.scalars(select(IdempotencyRecord)).all())


# ---------------------------------------------------------------------------
# 1. Credential administration targeting a catalog owner
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("audience", ["api", "mcp"])
def test_admin_only_service_account_cannot_issue_catalog_owner_token(
    alembic_session_factory,
    audience: str,
) -> None:
    with alembic_session_factory() as session:
        ids = _escalation_fixture(session)
        access = _access(session, ids["admin_service_id"])
        before = _state_snapshot(session, ids["owner_service_id"])

        with pytest.raises(CatalogOwnerDenied):
            with transaction(session):
                issue_managed_service_token(
                    session,
                    access,
                    principal_id=ids["owner_service_id"],
                    expected_revision='"rev-1"',
                    name="stolen-authority",
                    expires_at=None,
                    actor_password=None,
                    channel="api",
                    idempotency_key="escalation-token-issue-0001",
                    idempotency_ttl_seconds=TTL_SECONDS,
                    audience=audience,
                )

        assert _state_snapshot(session, ids["owner_service_id"]) == before
        assert _idempotency_count(session) == 0


@pytest.mark.parametrize("audience", ["api", "mcp"])
def test_admin_only_service_account_cannot_rotate_catalog_owner_token(
    alembic_session_factory,
    audience: str,
) -> None:
    with alembic_session_factory() as session:
        ids = _escalation_fixture(session)
        with transaction(session):
            issue_service_token(
                session,
                principal_id=ids["owner_service_id"],
                name="owner-runtime",
                audience=audience,
            )
        access = _access(session, ids["admin_service_id"])
        before = _state_snapshot(session, ids["owner_service_id"])

        with pytest.raises(CatalogOwnerDenied):
            with transaction(session):
                issue_managed_service_token(
                    session,
                    access,
                    principal_id=ids["owner_service_id"],
                    expected_revision='"rev-1"',
                    name="owner-runtime",
                    expires_at=None,
                    actor_password=None,
                    channel="api",
                    rotate=True,
                    idempotency_key="escalation-token-rotate-0001",
                    idempotency_ttl_seconds=TTL_SECONDS,
                )

        assert _state_snapshot(session, ids["owner_service_id"]) == before
        assert _idempotency_count(session) == 0


def test_dual_role_service_account_cannot_issue_catalog_owner_token_over_api(
    alembic_session_factory,
) -> None:
    """The service-account API reauthentication exemption never covers an owner target."""
    with alembic_session_factory() as session:
        ids = _escalation_fixture(session)
        access = _access(session, ids["dual_service_id"])
        before = _state_snapshot(session, ids["owner_service_id"])

        with pytest.raises(PlatformAdminReauthenticationDenied):
            with transaction(session):
                issue_managed_service_token(
                    session,
                    access,
                    principal_id=ids["owner_service_id"],
                    expected_revision='"rev-1"',
                    name="stolen-authority",
                    expires_at=None,
                    actor_password=None,
                    channel="api",
                    idempotency_key="escalation-dual-service-0001",
                    idempotency_ttl_seconds=TTL_SECONDS,
                )

        assert _state_snapshot(session, ids["owner_service_id"]) == before
        assert _idempotency_count(session) == 0


def test_admin_only_human_cannot_issue_catalog_owner_token(
    alembic_session_factory,
) -> None:
    with alembic_session_factory() as session:
        ids = _escalation_fixture(session)
        access = _access(session, ids["admin_human_id"])
        before = _state_snapshot(session, ids["owner_service_id"])

        with pytest.raises(CatalogOwnerDenied):
            with transaction(session):
                issue_managed_service_token(
                    session,
                    access,
                    principal_id=ids["owner_service_id"],
                    expected_revision='"rev-1"',
                    name="stolen-authority",
                    expires_at=None,
                    actor_password=PASSWORD,
                    channel="ui",
                    idempotency_key="escalation-admin-human-0001",
                    idempotency_ttl_seconds=TTL_SECONDS,
                )

        assert _state_snapshot(session, ids["owner_service_id"]) == before
        assert _idempotency_count(session) == 0


def test_inactive_catalog_owner_target_is_also_protected(
    alembic_session_factory,
) -> None:
    """A parked owner row still gates credential administration on the strong path."""
    with alembic_session_factory() as session:
        ids = _escalation_fixture(session)
        with transaction(session):
            session.execute(
                update(Principal)
                .where(Principal.id == ids["owner_service_id"])
                .values(active=False)
            )
        access = _access(session, ids["admin_service_id"])
        before = _state_snapshot(session, ids["owner_service_id"])

        with pytest.raises(CatalogOwnerDenied):
            with transaction(session):
                issue_managed_service_token(
                    session,
                    access,
                    principal_id=ids["owner_service_id"],
                    expected_revision='"rev-1"',
                    name="stolen-authority",
                    expires_at=None,
                    actor_password=None,
                    channel="api",
                    idempotency_key="escalation-inactive-owner-0001",
                    idempotency_ttl_seconds=TTL_SECONDS,
                )

        assert _state_snapshot(session, ids["owner_service_id"]) == before
        assert _idempotency_count(session) == 0


def test_admin_only_service_account_cannot_reset_human_catalog_owner_password(
    alembic_session_factory,
) -> None:
    with alembic_session_factory() as session:
        ids = _escalation_fixture(session)
        access = _access(session, ids["admin_service_id"])
        before = _state_snapshot(session, ids["owner_human_id"])

        with pytest.raises(CatalogOwnerDenied):
            with transaction(session):
                reset_managed_human_password(
                    session,
                    access,
                    principal_id=ids["owner_human_id"],
                    expected_revision='"rev-1"',
                    new_password="attacker-chosen-password",
                    actor_password=None,
                    channel="api",
                )

        assert _state_snapshot(session, ids["owner_human_id"]) == before
        assert (
            authenticate_password(
                session,
                login="owner.human",
                password=TARGET_PASSWORD,
                channel="ui",
            )
            is not None
        )
        assert (
            authenticate_password(
                session,
                login="owner.human",
                password="attacker-chosen-password",
                channel="ui",
            )
            is None
        )


def test_admin_only_human_cannot_reset_human_catalog_owner_password(
    alembic_session_factory,
) -> None:
    with alembic_session_factory() as session:
        ids = _escalation_fixture(session)
        access = _access(session, ids["admin_human_id"])
        before = _state_snapshot(session, ids["owner_human_id"])

        with pytest.raises(CatalogOwnerDenied):
            with transaction(session):
                reset_managed_human_password(
                    session,
                    access,
                    principal_id=ids["owner_human_id"],
                    expected_revision='"rev-1"',
                    new_password="attacker-chosen-password",
                    actor_password=PASSWORD,
                    channel="ui",
                )

        assert _state_snapshot(session, ids["owner_human_id"]) == before


@pytest.mark.parametrize("audience", ["api", "mcp"])
def test_dual_role_human_can_still_issue_catalog_owner_token(
    alembic_session_factory,
    audience: str,
) -> None:
    with alembic_session_factory() as session:
        ids = _escalation_fixture(session)
        access = _access(session, ids["dual_id"])

        with transaction(session):
            result = issue_managed_service_token(
                session,
                access,
                principal_id=ids["owner_service_id"],
                expected_revision='"rev-1"',
                name="owner-runtime",
                expires_at=None,
                actor_password=PASSWORD,
                channel="ui",
                idempotency_key="escalation-dual-human-0001",
                idempotency_ttl_seconds=TTL_SECONDS,
                audience=audience,
            )

        assert result.changed is True
        assert result.issued_token is not None
        assert result.issued_token.audience == audience
        assert result.principal.revision == 2


def test_dual_role_human_credential_administration_still_needs_password_and_etag(
    alembic_session_factory,
) -> None:
    with alembic_session_factory() as session:
        ids = _escalation_fixture(session)
        access = _access(session, ids["dual_id"])
        before = _state_snapshot(session, ids["owner_service_id"])

        with pytest.raises(PlatformAdminReauthenticationDenied):
            with transaction(session):
                issue_managed_service_token(
                    session,
                    access,
                    principal_id=ids["owner_service_id"],
                    expected_revision='"rev-1"',
                    name="owner-runtime",
                    expires_at=None,
                    actor_password="definitely-wrong",
                    channel="ui",
                    idempotency_key="escalation-wrong-password-0001",
                    idempotency_ttl_seconds=TTL_SECONDS,
                )
        assert _idempotency_count(session) == 0

        with pytest.raises(PlatformAdminReauthenticationDenied):
            with transaction(session):
                issue_managed_service_token(
                    session,
                    access,
                    principal_id=ids["owner_service_id"],
                    expected_revision='"rev-1"',
                    name="owner-runtime",
                    expires_at=None,
                    actor_password=None,
                    channel="ui",
                    idempotency_key="escalation-missing-password-0001",
                    idempotency_ttl_seconds=TTL_SECONDS,
                )
        assert _idempotency_count(session) == 0

        with pytest.raises(ManagedPrincipalPreconditionFailed):
            with transaction(session):
                issue_managed_service_token(
                    session,
                    access,
                    principal_id=ids["owner_service_id"],
                    expected_revision='"rev-9"',
                    name="owner-runtime",
                    expires_at=None,
                    actor_password=PASSWORD,
                    channel="ui",
                    idempotency_key="escalation-stale-etag-0001",
                    idempotency_ttl_seconds=TTL_SECONDS,
                )

        assert _state_snapshot(session, ids["owner_service_id"]) == before

        with pytest.raises(PlatformAdminReauthenticationDenied):
            with transaction(session):
                reset_managed_human_password(
                    session,
                    access,
                    principal_id=ids["owner_human_id"],
                    expected_revision='"rev-1"',
                    new_password="new-owner-password",
                    actor_password="definitely-wrong",
                    channel="ui",
                )
        with pytest.raises(ManagedPrincipalPreconditionFailed):
            with transaction(session):
                reset_managed_human_password(
                    session,
                    access,
                    principal_id=ids["owner_human_id"],
                    expected_revision='"rev-9"',
                    new_password="new-owner-password",
                    actor_password=PASSWORD,
                    channel="ui",
                )
        with transaction(session):
            reset_managed_human_password(
                session,
                access,
                principal_id=ids["owner_human_id"],
                expected_revision='"rev-1"',
                new_password="new-owner-password",
                actor_password=PASSWORD,
                channel="ui",
            )
        assert (
            authenticate_password(
                session,
                login="owner.human",
                password="new-owner-password",
                channel="ui",
            )
            is not None
        )


def test_non_owner_credential_administration_contract_is_unchanged(
    alembic_session_factory,
) -> None:
    """Platform-admin service accounts keep the API exemption for ordinary targets."""
    with alembic_session_factory() as session:
        ids = _escalation_fixture(session)
        service_access = _access(session, ids["admin_service_id"])
        human_access = _access(session, ids["admin_human_id"])

        with transaction(session):
            issued = issue_managed_service_token(
                session,
                service_access,
                principal_id=ids["plain_service_id"],
                expected_revision='"rev-1"',
                name="plain-runtime",
                expires_at=None,
                actor_password=None,
                channel="api",
                idempotency_key="escalation-plain-issue-0001",
                idempotency_ttl_seconds=TTL_SECONDS,
            )
        assert issued.changed is True
        assert issued.issued_token is not None

        with transaction(session):
            rotated = issue_managed_service_token(
                session,
                service_access,
                principal_id=ids["plain_service_id"],
                expected_revision='"rev-2"',
                name="plain-runtime",
                expires_at=None,
                actor_password=None,
                channel="api",
                rotate=True,
                idempotency_key="escalation-plain-rotate-0001",
                idempotency_ttl_seconds=TTL_SECONDS,
            )
        assert rotated.changed is True

        with transaction(session):
            reset = reset_managed_human_password(
                session,
                human_access,
                principal_id=ids["plain_human_id"],
                expected_revision='"rev-1"',
                new_password="rotated-plain-password",
                actor_password=PASSWORD,
                channel="ui",
            )
        assert reset.changed is True


# ---------------------------------------------------------------------------
# 2. The inactive catalog-owner parking bypass
# ---------------------------------------------------------------------------


def test_catalog_role_cannot_be_assigned_to_an_inactive_target(
    alembic_session_factory,
) -> None:
    with alembic_session_factory() as session:
        ids = _escalation_fixture(session)
        with transaction(session):
            session.execute(
                update(Principal)
                .where(Principal.id == ids["plain_service_id"])
                .values(active=False)
            )
        access = _access(session, ids["dual_id"])

        with pytest.raises(ManagedPrincipalConflict):
            with transaction(session):
                set_managed_catalog_role(
                    session,
                    access,
                    principal_id=ids["plain_service_id"],
                    expected_revision='"rev-1"',
                    catalog_role=CatalogRole.CATALOG_OWNER,
                    actor_password=PASSWORD,
                    channel="ui",
                )

        row = session.get(Principal, ids["plain_service_id"])
        assert row is not None
        assert row.catalog_role is None
        assert row.revision == 1
        assert (
            session.scalars(
                select(SecurityEvent).where(
                    SecurityEvent.event_type == "catalog_owner_role_changed"
                )
            ).all()
            == []
        )


@pytest.mark.parametrize("actor", ["admin_human_id", "admin_service_id"])
def test_preexisting_inactive_catalog_owner_cannot_be_activated_generically(
    alembic_session_factory,
    actor: str,
) -> None:
    """A legacy or raw-written parked owner row fails closed on reactivation."""
    with alembic_session_factory() as session:
        ids = _escalation_fixture(session)
        with transaction(session):
            session.execute(
                update(Principal)
                .where(Principal.id == ids["plain_service_id"])
                .values(active=False, catalog_role=CatalogRole.CATALOG_OWNER.value)
            )
        access = _access(session, ids[actor])

        with pytest.raises(ManagedPrincipalConflict):
            with transaction(session):
                update_managed_principal(
                    session,
                    access,
                    principal_id=ids["plain_service_id"],
                    expected_revision='"rev-1"',
                    display_name="Plain Service",
                    active=True,
                    platform_role=None,
                    channel="api",
                )

        row = session.get(Principal, ids["plain_service_id"])
        assert row is not None
        assert row.active is False
        assert row.revision == 1
        assert (
            session.scalars(
                select(SecurityEvent).where(
                    SecurityEvent.event_type == "principal_updated"
                )
            ).all()
            == []
        )


def test_parked_owner_can_be_activated_after_the_role_is_removed_under_the_gate(
    alembic_session_factory,
) -> None:
    """The explicit safe sequence stays available to a dual-role human."""
    with alembic_session_factory() as session:
        ids = _escalation_fixture(session)
        with transaction(session):
            session.execute(
                update(Principal)
                .where(Principal.id == ids["plain_service_id"])
                .values(active=False, catalog_role=CatalogRole.CATALOG_OWNER.value)
            )
        dual_access = _access(session, ids["dual_id"])
        admin_access = _access(session, ids["admin_service_id"])

        with transaction(session):
            removed = set_managed_catalog_role(
                session,
                dual_access,
                principal_id=ids["plain_service_id"],
                expected_revision='"rev-1"',
                catalog_role=None,
                actor_password=PASSWORD,
                channel="ui",
            )
        assert removed.changed is True

        with transaction(session):
            activated = update_managed_principal(
                session,
                admin_access,
                principal_id=ids["plain_service_id"],
                expected_revision='"rev-2"',
                display_name="Plain Service",
                active=True,
                platform_role=None,
                channel="api",
            )
        assert activated.changed is True
        row = session.get(Principal, ids["plain_service_id"])
        assert row is not None
        assert row.active is True
        assert row.catalog_role is None


def test_principal_updated_audit_includes_the_target_catalog_role(
    alembic_session_factory,
) -> None:
    with alembic_session_factory() as session:
        ids = _escalation_fixture(session)
        access = _access(session, ids["admin_service_id"])

        with transaction(session):
            update_managed_principal(
                session,
                access,
                principal_id=ids["owner_service_id"],
                expected_revision='"rev-1"',
                display_name="Owner Service Renamed",
                active=True,
                platform_role=None,
                channel="api",
            )
            update_managed_principal(
                session,
                access,
                principal_id=ids["plain_service_id"],
                expected_revision='"rev-1"',
                display_name="Plain Service Renamed",
                active=True,
                platform_role=None,
                channel="api",
            )

        details = {
            event.principal_id: json.loads(event.details_json)
            for event in session.scalars(
                select(SecurityEvent).where(
                    SecurityEvent.event_type == "principal_updated"
                )
            ).all()
        }
        assert details[ids["owner_service_id"]]["catalog_role"] == "catalog_owner"
        assert details[ids["plain_service_id"]]["catalog_role"] == "none"


def test_last_active_owner_invariant_survives_the_new_guards(
    alembic_session_factory,
) -> None:
    with alembic_session_factory() as session:
        ids = _escalation_fixture(session)
        with transaction(session):
            session.execute(
                update(Principal)
                .where(
                    Principal.id.in_(
                        (
                            ids["owner_service_id"],
                            ids["owner_human_id"],
                            ids["dual_service_id"],
                        )
                    )
                )
                .values(catalog_role=None)
            )
        access = _access(session, ids["dual_id"])

        with pytest.raises(ManagedPrincipalConflict):
            with transaction(session):
                set_managed_catalog_role(
                    session,
                    access,
                    principal_id=ids["dual_id"],
                    expected_revision='"rev-1"',
                    catalog_role=None,
                    actor_password=PASSWORD,
                    channel="ui",
                )

        row = session.get(Principal, ids["dual_id"])
        assert row is not None
        assert row.catalog_role == CatalogRole.CATALOG_OWNER


# ---------------------------------------------------------------------------
# 3. Dual-role denial auditing on the REST and UI channels
# ---------------------------------------------------------------------------


@pytest.fixture
def escalation_http_state(alembic_session_factory):
    with alembic_session_factory() as session:
        ids = _escalation_fixture(session)
        with transaction(session):
            admin_human_session = issue_browser_session(
                session,
                principal_id=ids["admin_human_id"],
                ttl_seconds=TTL_SECONDS,
            )
            dual_session = issue_browser_session(
                session,
                principal_id=ids["dual_id"],
                ttl_seconds=TTL_SECONDS,
            )
            admin_service_token = issue_service_token(
                session,
                principal_id=ids["admin_service_id"],
                name="admin-only-api",
            ).value
    return {
        **ids,
        "session_factory": alembic_session_factory,
        "admin_human_session": admin_human_session,
        "dual_session": dual_session,
        "admin_service_token": admin_service_token,
    }


@pytest.fixture
def escalation_client(escalation_http_state) -> Generator[TestClient, None, None]:
    app = create_app()
    sessions = escalation_http_state["session_factory"]

    def override_get_session() -> Generator[Session, None, None]:
        with sessions() as session:
            yield session

    app.dependency_overrides[get_session] = override_get_session
    with TestClient(app, base_url="https://testserver") as client:
        yield client


def _login(client: TestClient, issued) -> None:
    client.cookies.set(AUTH_SESSION_COOKIE_NAME, issued.value)
    client.cookies.set(AUTH_CSRF_COOKIE_NAME, issued.csrf_token)


def _denial_events(session) -> list[SecurityEvent]:
    return list(
        session.scalars(
            select(SecurityEvent).where(
                SecurityEvent.event_type == "catalog_owner_admin_authorization"
            )
        ).all()
    )


def test_rest_dual_role_denial_records_exactly_one_redacted_event(
    escalation_client: TestClient,
    escalation_http_state,
) -> None:
    issued = escalation_http_state["admin_human_session"]
    sessions = escalation_http_state["session_factory"]
    _login(escalation_client, issued)

    response = escalation_client.post(
        f"/api/v1/admin/principals/{escalation_http_state['plain_service_id']}/catalog-role",
        headers={
            "If-Match": '"rev-1"',
            "X-CSRF-Token": issued.csrf_token,
            "X-Correlation-ID": "rest-denial-correlation",
        },
        json={"catalog_role": "catalog_owner", "current_admin_password": PASSWORD},
    )

    assert response.status_code == 403
    with sessions() as session:
        events = _denial_events(session)
        assert len(events) == 1
        event = events[0]
        assert event.outcome == "denied"
        assert event.channel == "api"
        assert event.principal_id == escalation_http_state["admin_human_id"]
        assert event.request_id == "rest-denial-correlation"
        assert json.loads(event.details_json) == {"reason": "dual_role_required"}
        assert PASSWORD not in event.details_json
        assert "catalog_owner" not in event.details_json
        row = session.get(Principal, escalation_http_state["plain_service_id"])
        assert row is not None
        assert row.catalog_role is None
        assert row.revision == 1


def test_ui_dual_role_denial_records_exactly_one_redacted_event(
    escalation_client: TestClient,
    escalation_http_state,
) -> None:
    issued = escalation_http_state["admin_human_session"]
    sessions = escalation_http_state["session_factory"]
    _login(escalation_client, issued)

    response = escalation_client.post(
        f"/admin/principals/{escalation_http_state['plain_service_id']}/catalog-role",
        headers={"X-Correlation-ID": "ui-denial-correlation"},
        data={
            "csrf_token": issued.csrf_token,
            "if_match": '"rev-1"',
            "catalog_role": "catalog_owner",
            "current_admin_password": PASSWORD,
        },
        follow_redirects=False,
    )

    assert response.status_code == 403
    with sessions() as session:
        events = _denial_events(session)
        assert len(events) == 1
        event = events[0]
        assert event.outcome == "denied"
        assert event.channel == "ui"
        assert event.principal_id == escalation_http_state["admin_human_id"]
        assert event.request_id == "ui-denial-correlation"
        assert json.loads(event.details_json) == {"reason": "dual_role_required"}
        row = session.get(Principal, escalation_http_state["plain_service_id"])
        assert row is not None
        assert row.catalog_role is None
        assert row.revision == 1


def test_rest_admin_bearer_cannot_mint_catalog_owner_token(
    escalation_client: TestClient,
    escalation_http_state,
) -> None:
    sessions = escalation_http_state["session_factory"]
    owner_id = escalation_http_state["owner_service_id"]
    headers = {
        "Authorization": f"Bearer {escalation_http_state['admin_service_token']}",
        "If-Match": '"rev-1"',
        "Idempotency-Key": "rest-escalation-issue-0001",
    }

    issue = escalation_client.post(
        f"/api/v1/admin/principals/{owner_id}/tokens",
        headers=headers,
        json={"name": "stolen-authority", "audience": "mcp"},
    )
    rotate = escalation_client.post(
        f"/api/v1/admin/principals/{owner_id}/tokens/rotate",
        headers={**headers, "Idempotency-Key": "rest-escalation-rotate-0001"},
        json={"name": "stolen-authority"},
    )
    reset = escalation_client.post(
        f"/api/v1/admin/principals/{escalation_http_state['owner_human_id']}/password",
        headers={
            "Authorization": f"Bearer {escalation_http_state['admin_service_token']}",
            "If-Match": '"rev-1"',
        },
        json={"new_password": "attacker-chosen-password"},
    )

    assert issue.status_code == 403
    assert rotate.status_code == 403
    assert reset.status_code == 403
    with sessions() as session:
        assert (
            session.scalars(
                select(ServiceToken).where(ServiceToken.principal_id == owner_id)
            ).all()
            == []
        )
        assert _idempotency_count(session) == 0
        assert len(_denial_events(session)) == 3
        assert (
            authenticate_password(
                session,
                login="owner.human",
                password=TARGET_PASSWORD,
                channel="ui",
            )
            is not None
        )
        for principal_id in (owner_id, escalation_http_state["owner_human_id"]):
            row = session.get(Principal, principal_id)
            assert row is not None
            assert row.revision == 1


def test_ui_dual_role_human_can_administer_catalog_owner_credentials(
    escalation_client: TestClient,
    escalation_http_state,
) -> None:
    issued = escalation_http_state["dual_session"]
    sessions = escalation_http_state["session_factory"]
    owner_id = escalation_http_state["owner_service_id"]
    _login(escalation_client, issued)

    granted = escalation_client.post(
        f"/admin/principals/{owner_id}/tokens",
        data={
            "csrf_token": issued.csrf_token,
            "if_match": '"rev-1"',
            "idempotency_key": "ui-escalation-issue-0001",
            "name": "owner-runtime",
            "current_admin_password": PASSWORD,
            "rotate": "0",
            "audience": "mcp",
        },
    )
    denied = escalation_client.post(
        f"/admin/principals/{owner_id}/tokens",
        data={
            "csrf_token": issued.csrf_token,
            "if_match": '"rev-2"',
            "idempotency_key": "ui-escalation-issue-0002",
            "name": "second-runtime",
            "current_admin_password": "definitely-wrong",
            "rotate": "0",
        },
    )

    assert granted.status_code == 200
    assert "bwst_" in granted.text
    assert denied.status_code == 403
    with sessions() as session:
        tokens = session.scalars(
            select(ServiceToken).where(ServiceToken.principal_id == owner_id)
        ).all()
        assert [token.name for token in tokens] == ["owner-runtime"]
        assert tokens[0].audience == "mcp"
        assert _denial_events(session) == []


def test_ui_admin_only_human_denial_leaves_no_credential_or_session_state(
    escalation_client: TestClient,
    escalation_http_state,
) -> None:
    issued = escalation_http_state["admin_human_session"]
    sessions = escalation_http_state["session_factory"]
    owner_id = escalation_http_state["owner_service_id"]
    _login(escalation_client, issued)

    with sessions() as session:
        before = _state_snapshot(session, owner_id)

    response = escalation_client.post(
        f"/admin/principals/{owner_id}/tokens",
        data={
            "csrf_token": issued.csrf_token,
            "if_match": '"rev-1"',
            "idempotency_key": "ui-escalation-denied-0001",
            "name": "stolen-authority",
            "current_admin_password": PASSWORD,
            "rotate": "0",
        },
    )

    assert response.status_code == 403
    with sessions() as session:
        assert _state_snapshot(session, owner_id) == before
        assert _idempotency_count(session) == 0
        assert len(_denial_events(session)) == 1
        assert _denial_events(session)[0].channel == "ui"


def test_mcp_audience_owner_token_is_not_reachable_through_platform_admin_only(
    alembic_session_factory,
) -> None:
    """Both audiences share one gate, so neither is a side door."""
    with alembic_session_factory() as session:
        ids = _escalation_fixture(session)
        access = _access(session, ids["admin_service_id"])
        for audience, key in (("api", "aud-api-0001"), ("mcp", "aud-mcp-0001")):
            with pytest.raises(CatalogOwnerDenied):
                with transaction(session):
                    issue_managed_service_token(
                        session,
                        access,
                        principal_id=ids["owner_service_id"],
                        expected_revision='"rev-1"',
                        name=f"stolen-{audience}",
                        expires_at=None,
                        actor_password=None,
                        channel="api",
                        idempotency_key=f"escalation-audience-{key}",
                        idempotency_ttl_seconds=TTL_SECONDS,
                        audience=audience,
                    )
        assert (
            session.scalars(
                select(ServiceToken).where(
                    ServiceToken.principal_id == ids["owner_service_id"]
                )
            ).all()
            == []
        )


def test_denied_credential_administration_leaves_owner_sessions_intact(
    alembic_session_factory,
) -> None:
    with alembic_session_factory() as session:
        ids = _escalation_fixture(session)
        with transaction(session):
            owner_session = issue_browser_session(
                session,
                principal_id=ids["owner_human_id"],
                ttl_seconds=TTL_SECONDS,
            )
        access = _access(session, ids["admin_service_id"])

        with pytest.raises(CatalogOwnerDenied):
            with transaction(session):
                reset_managed_human_password(
                    session,
                    access,
                    principal_id=ids["owner_human_id"],
                    expected_revision='"rev-1"',
                    new_password="attacker-chosen-password",
                    actor_password=None,
                    channel="api",
                )

        still_valid = authenticate_browser_session(session, value=owner_session.value)
        assert still_valid is not None
        assert still_valid.id == ids["owner_human_id"]
        assert still_valid.principal_type == PrincipalType.HUMAN
