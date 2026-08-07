from __future__ import annotations

import json

import pytest
from sqlalchemy import select

from blockwart.db.session import transaction
from blockwart.domain.auth import CatalogRole, GrantScope, PlatformRole, Role
from blockwart.models import BrowserSession, Principal, SecurityEvent, ServiceToken
from blockwart.schemas.catalog import CatalogObjectIn
from blockwart.services.access import create_object_grant
from blockwart.services.catalog import upsert_object
from blockwart.services.identity import (
    create_human_principal,
    create_service_account,
    issue_browser_session,
)
from blockwart.services.principal_management import (
    ManagedPrincipalConflict,
    ManagedPrincipalPreconditionFailed,
    PlatformAdminDenied,
    issue_managed_service_token,
    query_principal_detail,
    query_principals,
    revoke_managed_service_token,
    update_managed_principal,
)
from blockwart.services.read_access import read_access_for_principal

PASSWORD = "principal-admin-password"


def _object(object_id: str) -> CatalogObjectIn:
    return CatalogObjectIn(
        id=object_id,
        kind="host",
        label=object_id,
        lifecycle="active",
        health="healthy",
        data={"schema_version": 1},
    )


def _setup(session):
    visible = upsert_object(session, _object("visible-root"))
    hidden = upsert_object(session, _object("hidden-root"))
    admin = create_human_principal(
        session,
        login="platform.admin",
        display_name="Platform Admin",
        password=PASSWORD,
        platform_role=PlatformRole.ADMIN,
    )
    target = create_service_account(
        session,
        login="managed.agent",
        display_name="Managed Agent",
    )
    non_admin = create_human_principal(
        session,
        login="ordinary.owner",
        display_name="Ordinary Owner",
        password=PASSWORD,
    )
    create_object_grant(
        session,
        principal_id=target.id,
        object_id=visible.id,
        role=Role.VIEWER,
        scope=GrantScope.SELF,
    )
    create_object_grant(
        session,
        principal_id=target.id,
        object_id=hidden.id,
        role=Role.OWNER,
        scope=GrantScope.SELF,
    )
    create_object_grant(
        session,
        principal_id=non_admin.id,
        object_id=visible.id,
        role=Role.OWNER,
        scope=GrantScope.SELF,
    )
    return admin, target, non_admin, visible


def test_platform_admin_without_object_grants_has_no_catalog_bypass(
    alembic_session_factory,
) -> None:
    with alembic_session_factory() as session:
        with transaction(session):
            admin, target, _, _ = _setup(session)
        access = read_access_for_principal(session, admin)

        detail = query_principal_detail(session, access, principal_id=target.id)

        assert detail.direct_grants == ()
        assert detail.effective_access == ()
        assert any(
            item.platform_role == PlatformRole.ADMIN
            for item in query_principals(session, access)
        )


def test_reverse_assignments_show_only_actor_manageable_objects(
    alembic_session_factory,
) -> None:
    with alembic_session_factory() as session:
        with transaction(session):
            admin, target, _, visible = _setup(session)
            create_object_grant(
                session,
                principal_id=admin.id,
                object_id=visible.id,
                role=Role.ACCESS_MANAGER,
                scope=GrantScope.SELF,
            )
        access = read_access_for_principal(session, admin)

        detail = query_principal_detail(session, access, principal_id=target.id)

        assert [grant.object_id for grant in detail.direct_grants] == ["visible-root"]
        assert [item.object_id for item in detail.effective_access] == ["visible-root"]
        assert detail.effective_access[0].sources[0].anchor_object_id == "visible-root"
        serialized = repr(detail)
        assert "hidden-root" not in serialized


def test_non_admin_cannot_query_principals(alembic_session_factory) -> None:
    with alembic_session_factory() as session:
        with transaction(session):
            _, _, non_admin, _ = _setup(session)
        access = read_access_for_principal(session, non_admin)

        with pytest.raises(PlatformAdminDenied):
            query_principals(session, access)


def test_last_admin_guard_and_stale_principal_revision(
    alembic_session_factory,
) -> None:
    with alembic_session_factory() as session:
        with transaction(session):
            admin, _, _, _ = _setup(session)
        access = read_access_for_principal(session, admin)

        with pytest.raises(ManagedPrincipalConflict, match="one active"):
            with transaction(session):
                update_managed_principal(
                    session,
                    access,
                    principal_id=admin.id,
                    expected_revision='"rev-1"',
                    display_name="Platform Admin",
                    active=False,
                    platform_role=PlatformRole.ADMIN,
                    channel="ui",
                )

        with transaction(session):
            second = create_human_principal(
                session,
                login="second.admin",
                display_name="Second Admin",
                password=PASSWORD,
                platform_role=PlatformRole.ADMIN,
            )
            result = update_managed_principal(
                session,
                access,
                principal_id=admin.id,
                expected_revision='"rev-1"',
                display_name="Renamed Admin",
                active=True,
                platform_role=PlatformRole.ADMIN,
                channel="ui",
            )
        assert result.principal.revision == 2
        assert second.is_admin

        with pytest.raises(ManagedPrincipalPreconditionFailed):
            with transaction(session):
                update_managed_principal(
                    session,
                    access,
                    principal_id=admin.id,
                    expected_revision='"rev-1"',
                    display_name="Stale",
                    active=True,
                    platform_role=PlatformRole.ADMIN,
                    channel="ui",
                )


def test_deactivation_revokes_credentials_and_token_secret_is_one_time(
    alembic_session_factory,
) -> None:
    with alembic_session_factory() as session:
        with transaction(session):
            admin, target, _, _ = _setup(session)
            issue_browser_session(session, principal_id=admin.id, ttl_seconds=600)
        access = read_access_for_principal(session, admin)

        with transaction(session):
            issued = issue_managed_service_token(
                session,
                access,
                principal_id=target.id,
                expected_revision='"rev-1"',
                name="automation",
                expires_at=None,
                actor_password=PASSWORD,
                channel="ui",
                idempotency_key="issue-managed-token-0001",
                idempotency_ttl_seconds=3600,
            )
        assert issued.issued_token is not None
        secret = issued.issued_token.value

        with transaction(session):
            replay = issue_managed_service_token(
                session,
                access,
                principal_id=target.id,
                expected_revision='"rev-1"',
                name="automation",
                expires_at=None,
                actor_password=PASSWORD,
                channel="ui",
                idempotency_key="issue-managed-token-0001",
                idempotency_ttl_seconds=3600,
            )
        assert replay.changed is False
        assert replay.issued_token is None
        assert session.scalar(select(ServiceToken).where(ServiceToken.name == "automation"))
        event_payload = " ".join(
            event.details_json
            for event in session.scalars(select(SecurityEvent)).all()
        )
        assert secret not in event_payload

        with transaction(session):
            second_admin = create_human_principal(
                session,
                login="credential.admin",
                display_name="Credential Admin",
                password=PASSWORD,
                platform_role=PlatformRole.ADMIN,
            )
            create_object_grant(
                session,
                principal_id=second_admin.id,
                object_id="hidden-root",
                role=Role.OWNER,
                scope=GrantScope.SELF,
            )
            result = update_managed_principal(
                session,
                access,
                principal_id=target.id,
                expected_revision='"rev-2"',
                display_name="Managed Agent",
                active=False,
                platform_role=None,
                channel="ui",
            )
        assert result.principal.active is False
        token = session.scalar(select(ServiceToken).where(ServiceToken.name == "automation"))
        assert token is not None and token.revoked_at is not None
        assert session.scalar(select(Principal).where(Principal.id == target.id)).active is False
        assert json.loads(
            session.scalar(
                select(SecurityEvent.details_json)
                .where(SecurityEvent.principal_id == target.id)
                .order_by(SecurityEvent.id.desc())
            )
        )["active"] == 0
        assert session.scalar(
            select(BrowserSession).where(BrowserSession.principal_id == admin.id)
        ) is not None


def test_repeated_service_token_revoke_is_revision_and_audit_noop(
    alembic_session_factory,
) -> None:
    with alembic_session_factory() as session:
        with transaction(session):
            admin, target, _, _ = _setup(session)
        access = read_access_for_principal(session, admin)
        with transaction(session):
            issue_managed_service_token(
                session,
                access,
                principal_id=target.id,
                expected_revision='"rev-1"',
                name="revoke-once",
                expires_at=None,
                actor_password=PASSWORD,
                channel="ui",
                idempotency_key="revoke-once-token-0001",
                idempotency_ttl_seconds=3600,
            )
        with transaction(session):
            first = revoke_managed_service_token(
                session,
                access,
                principal_id=target.id,
                expected_revision='"rev-2"',
                name="revoke-once",
                channel="ui",
            )
        first_audits = tuple(
            session.scalars(
                select(SecurityEvent).where(
                    SecurityEvent.principal_id == target.id,
                    SecurityEvent.event_type == "service_token_revoked",
                )
            )
        )
        assert first.changed is True
        assert first.principal.revision == 3
        assert len(first_audits) == 1

        with transaction(session):
            repeated = revoke_managed_service_token(
                session,
                access,
                principal_id=target.id,
                expected_revision='"rev-3"',
                name="revoke-once",
                channel="ui",
            )

        assert repeated.changed is False
        assert repeated.principal.revision == 3
        assert len(
            session.scalars(
                select(SecurityEvent).where(
                    SecurityEvent.principal_id == target.id,
                    SecurityEvent.event_type == "service_token_revoked",
                )
            ).all()
        ) == 1


def test_last_catalog_owner_deactivation_returns_a_safe_conflict(
    alembic_session_factory,
) -> None:
    with alembic_session_factory() as session:
        with transaction(session):
            admin, target, _, _ = _setup(session)
            stored = session.get(Principal, target.id)
            assert stored is not None
            stored.catalog_role = CatalogRole.CATALOG_OWNER
        access = read_access_for_principal(session, admin)

        with pytest.raises(ManagedPrincipalConflict, match="catalog owner"):
            with transaction(session):
                update_managed_principal(
                    session,
                    access,
                    principal_id=target.id,
                    expected_revision='"rev-1"',
                    display_name="Managed Agent",
                    active=False,
                    platform_role=None,
                    channel="ui",
                )

        stored = session.get(Principal, target.id)
        assert stored is not None
        assert stored.active is True
        assert stored.revision == 1

        with transaction(session):
            session.add(
                Principal(
                    id="00000000-0000-0000-0000-0000000000cc",
                    principal_type="service_account",
                    login="standby.catalog.owner",
                    display_name="Standby Catalog Owner",
                    active=True,
                    catalog_role=CatalogRole.CATALOG_OWNER,
                    revision=1,
                )
            )
        with transaction(session):
            result = update_managed_principal(
                session,
                access,
                principal_id=target.id,
                expected_revision='"rev-1"',
                display_name="Managed Agent",
                active=False,
                platform_role=None,
                channel="ui",
            )
        assert result.changed is True
        stored = session.get(Principal, target.id)
        assert stored is not None
        assert stored.active is False
        assert stored.catalog_role == CatalogRole.CATALOG_OWNER


def test_generic_principal_update_never_changes_the_catalog_role(
    alembic_session_factory,
) -> None:
    with alembic_session_factory() as session:
        with transaction(session):
            admin, target, _, _ = _setup(session)
            stored = session.get(Principal, target.id)
            assert stored is not None
            stored.catalog_role = CatalogRole.CATALOG_OWNER
        access = read_access_for_principal(session, admin)

        with transaction(session):
            update_managed_principal(
                session,
                access,
                principal_id=target.id,
                expected_revision='"rev-1"',
                display_name="Renamed Agent",
                active=True,
                platform_role=PlatformRole.ADMIN,
                channel="ui",
            )

        stored = session.get(Principal, target.id)
        assert stored is not None
        assert stored.display_name == "Renamed Agent"
        assert stored.platform_role == PlatformRole.ADMIN
        assert stored.catalog_role == CatalogRole.CATALOG_OWNER
