from datetime import timedelta

import pytest
from sqlalchemy import select

from blockwart.db.session import transaction
from blockwart.domain.auth import PrincipalType
from blockwart.models import (
    BrowserSession,
    LoginChallenge,
    PasswordCredential,
    SecurityEvent,
    ServiceToken,
)
from blockwart.services.identity import (
    IdentityError,
    authenticate_browser_session,
    authenticate_password,
    authenticate_service_token,
    consume_login_challenge,
    create_human_principal,
    create_service_account,
    deactivate_principal,
    issue_browser_session,
    issue_login_challenge,
    issue_service_token,
    prune_security_events,
    record_security_event,
    revoke_browser_session,
    revoke_service_token,
    rotate_service_token,
    set_human_password,
    utc_now,
    verify_browser_csrf,
)

HUMAN_PASSWORD = "correct horse battery staple"
ROTATED_PASSWORD = "rotated horse battery staple"


def test_human_password_is_argon2id_and_authentication_is_audited(
    alembic_session_factory,
) -> None:
    with alembic_session_factory() as session:
        with transaction(session):
            principal = create_human_principal(
                session,
                login="Kai.Local",
                display_name="  Kai   Local  ",
                password=HUMAN_PASSWORD,
            )

    with alembic_session_factory() as session:
        row = session.get(PasswordCredential, principal.id)
        assert row is not None
        assert row.password_hash.startswith("$argon2id$")
        assert HUMAN_PASSWORD not in row.password_hash

        with transaction(session):
            rejected = authenticate_password(
                session,
                login="unknown.user",
                password=HUMAN_PASSWORD,
            )
        with transaction(session):
            authenticated = authenticate_password(
                session,
                login="kai.local",
                password=HUMAN_PASSWORD,
            )

        assert rejected is None
        assert authenticated is not None
        assert authenticated.id == principal.id
        assert authenticated.service_token_audience is None
        events = list(
            session.scalars(
                select(SecurityEvent).order_by(SecurityEvent.id)
            ).all()
        )
        assert [event.outcome for event in events] == ["failure", "success"]
        serialized = "\n".join(event.details_json for event in events)
        assert HUMAN_PASSWORD not in serialized
        assert "unknown.user" not in serialized


def test_overlong_password_candidate_is_rejected_and_audited(
    alembic_session_factory,
) -> None:
    with alembic_session_factory() as session:
        with transaction(session):
            principal = create_human_principal(
                session,
                login="bounded.password",
                display_name="Bounded Password",
                password=HUMAN_PASSWORD,
            )
        with transaction(session):
            assert (
                authenticate_password(
                    session,
                    login=principal.login,
                    password="x" * 1025,
                )
                is None
            )

        event = session.scalar(
            select(SecurityEvent).order_by(SecurityEvent.id.desc())
        )
        assert event is not None
        assert event.outcome == "failure"
        assert "x" * 1025 not in event.details_json


def test_service_tokens_are_hashed_rotatable_expirable_and_revocable(
    alembic_session_factory,
) -> None:
    now = utc_now()
    with alembic_session_factory() as session:
        with transaction(session):
            principal = create_service_account(
                session,
                login="agent.reader",
                display_name="Agent Reader",
            )
            issued = issue_service_token(
                session,
                principal_id=principal.id,
                name="primary",
                expires_at=now + timedelta(hours=1),
                now=now,
            )

    with alembic_session_factory() as session:
        row = session.get(ServiceToken, issued.token_id)
        assert row is not None
        assert issued.value not in row.token_hash
        assert issued.value not in row.token_prefix
        assert len(row.token_hash) == 64

        with transaction(session):
            authenticated = authenticate_service_token(
                session,
                token=issued.value,
                now=now + timedelta(minutes=1),
            )
        assert authenticated == principal

        with transaction(session):
            rotated = rotate_service_token(
                session,
                principal_id=principal.id,
                name="primary",
                expires_at=now + timedelta(hours=2),
                now=now + timedelta(minutes=2),
            )
        with transaction(session):
            assert (
                authenticate_service_token(
                    session,
                    token=issued.value,
                    now=now + timedelta(minutes=3),
                )
                is None
            )
        with transaction(session):
            authenticated_rotated = authenticate_service_token(
                session,
                token=rotated.value,
                now=now + timedelta(minutes=3),
            )
            assert authenticated_rotated is not None
            assert authenticated_rotated.id == principal.id
            assert authenticated_rotated.service_token_audience == "api"
        with transaction(session):
            assert revoke_service_token(
                session,
                principal_id=principal.id,
                name="primary",
                now=now + timedelta(minutes=4),
            )
        with transaction(session):
            assert (
                authenticate_service_token(
                    session,
                    token=rotated.value,
                    now=now + timedelta(minutes=5),
                )
                is None
            )


def test_expired_token_and_deactivated_principal_fail_without_restart(
    alembic_session_factory,
) -> None:
    now = utc_now()
    with alembic_session_factory() as session:
        with transaction(session):
            principal = create_service_account(
                session,
                login="agent.expiring",
                display_name="Expiring Agent",
            )
            issued = issue_service_token(
                session,
                principal_id=principal.id,
                name="short",
                expires_at=now + timedelta(minutes=10),
                now=now,
            )
        with transaction(session):
            assert (
                authenticate_service_token(
                    session,
                    token=issued.value,
                    now=now + timedelta(minutes=11),
                )
                is None
            )
        with transaction(session):
            rotated = rotate_service_token(
                session,
                principal_id=principal.id,
                name="short",
                expires_at=now + timedelta(hours=1),
                now=now + timedelta(minutes=12),
            )
            assert deactivate_principal(
                session,
                principal_id=principal.id,
                now=now + timedelta(minutes=13),
            )
        with transaction(session):
            assert (
                authenticate_service_token(
                    session,
                    token=rotated.value,
                    now=now + timedelta(minutes=14),
                )
                is None
            )


def test_browser_session_csrf_logout_expiry_and_password_rotation(
    alembic_session_factory,
) -> None:
    now = utc_now()
    with alembic_session_factory() as session:
        with transaction(session):
            principal = create_human_principal(
                session,
                login="browser.user",
                display_name="Browser User",
                password=HUMAN_PASSWORD,
                now=now,
            )
            issued = issue_browser_session(
                session,
                principal_id=principal.id,
                ttl_seconds=300,
                now=now,
            )

        assert (
            authenticate_browser_session(
                session,
                value=issued.value,
                now=now + timedelta(seconds=299),
            )
            == principal
        )
        assert (
            verify_browser_csrf(
                session,
                session_value=issued.value,
                csrf_token=issued.csrf_token,
                now=now + timedelta(seconds=1),
            )
            == principal
        )
        assert (
            verify_browser_csrf(
                session,
                session_value=issued.value,
                csrf_token="wrong-csrf",
                now=now + timedelta(seconds=1),
            )
            is None
        )
        assert (
            authenticate_browser_session(
                session,
                value=issued.value,
                now=now + timedelta(seconds=300),
            )
            is None
        )

        with transaction(session):
            replacement = issue_browser_session(
                session,
                principal_id=principal.id,
                ttl_seconds=300,
                now=now + timedelta(minutes=6),
            )
            assert revoke_browser_session(
                session,
                value=replacement.value,
                now=now + timedelta(minutes=7),
            )
        assert (
            authenticate_browser_session(
                session,
                value=replacement.value,
                now=now + timedelta(minutes=7),
            )
            is None
        )

        with transaction(session):
            active = issue_browser_session(
                session,
                principal_id=principal.id,
                ttl_seconds=300,
                now=now + timedelta(minutes=8),
            )
            set_human_password(
                session,
                principal_id=principal.id,
                password=ROTATED_PASSWORD,
                now=now + timedelta(minutes=9),
            )
        assert authenticate_browser_session(session, value=active.value) is None
        assert all(
            row.revoked_at is not None
            for row in session.scalars(
                select(BrowserSession).where(
                    BrowserSession.principal_id == principal.id
                )
            ).all()
        )
        rotation_event = session.scalar(
            select(SecurityEvent).where(
                SecurityEvent.event_type == "password_credential_rotated"
            )
        )
        assert rotation_event is not None
        assert rotation_event.principal_id == principal.id
        assert rotation_event.details_json == "{}"


def test_password_rotation_event_and_hash_roll_back_together(
    alembic_session_factory,
) -> None:
    with alembic_session_factory() as session:
        with transaction(session):
            principal = create_human_principal(
                session,
                login="rollback.password",
                display_name="Rollback Password",
                password=HUMAN_PASSWORD,
            )
        original_hash = session.get(PasswordCredential, principal.id).password_hash

        with pytest.raises(RuntimeError, match="force rollback"):
            with transaction(session):
                set_human_password(
                    session,
                    principal_id=principal.id,
                    password=ROTATED_PASSWORD,
                )
                raise RuntimeError("force rollback")

        credential = session.get(PasswordCredential, principal.id)
        assert credential is not None
        assert credential.password_hash == original_hash
        assert (
            session.scalar(
                select(SecurityEvent).where(
                    SecurityEvent.event_type == "password_credential_rotated"
                )
            )
            is None
        )


def test_security_event_retention_removes_expired_and_oldest_overflow(
    alembic_session_factory,
) -> None:
    now = utc_now()
    with alembic_session_factory() as session:
        with transaction(session):
            for index, created_at in enumerate(
                [
                    now - timedelta(days=2),
                    now - timedelta(minutes=3),
                    now - timedelta(minutes=2),
                    now - timedelta(minutes=1),
                ]
            ):
                record_security_event(
                    session,
                    event_type=f"retention_{index}",
                    outcome="failure",
                    channel="system",
                    details={},
                    now=created_at,
                )
        with transaction(session):
            assert (
                prune_security_events(
                    session,
                    retention_days=1,
                    max_rows=2,
                    now=now,
                )
                == 2
            )

        assert [
            event.event_type
            for event in session.scalars(
                select(SecurityEvent).order_by(SecurityEvent.created_at)
            ).all()
        ] == ["retention_2", "retention_3"]


def test_login_challenge_is_one_time_and_expiring(
    alembic_session_factory,
) -> None:
    now = utc_now()
    with alembic_session_factory() as session:
        with transaction(session):
            challenge = issue_login_challenge(
                session,
                ttl_seconds=60,
                now=now,
            )
        with transaction(session):
            assert consume_login_challenge(
                session,
                cookie_value=challenge.value,
                form_value=challenge.value,
                now=now + timedelta(seconds=59),
            )
        with transaction(session):
            assert not consume_login_challenge(
                session,
                cookie_value=challenge.value,
                form_value=challenge.value,
                now=now + timedelta(seconds=59),
            )
        with transaction(session):
            expired = issue_login_challenge(
                session,
                ttl_seconds=60,
                now=now,
            )
        with transaction(session):
            assert not consume_login_challenge(
                session,
                cookie_value=expired.value,
                form_value=expired.value,
                now=now + timedelta(seconds=60),
            )
        with transaction(session):
            replacement = issue_login_challenge(
                session,
                ttl_seconds=60,
                now=now + timedelta(seconds=61),
            )
        rows = list(session.scalars(select(LoginChallenge)).all())
        assert [row.id for row in rows] == [replacement.challenge_id]


def test_security_event_rejects_secret_shaped_details(
    alembic_session_factory,
) -> None:
    with alembic_session_factory() as session:
        with pytest.raises(IdentityError, match="forbidden"):
            record_security_event(
                session,
                event_type="invalid",
                outcome="failure",
                channel="api",
                details={"token": "must-not-be-stored"},
            )


def test_principal_types_are_stable_across_identity_channels(
    alembic_session_factory,
) -> None:
    with alembic_session_factory() as session:
        with transaction(session):
            human = create_human_principal(
                session,
                login="stable.human",
                display_name="Stable Human",
                password=HUMAN_PASSWORD,
            )
            service = create_service_account(
                session,
                login="stable.service",
                display_name="Stable Service",
            )

    assert human.principal_type == PrincipalType.HUMAN
    assert service.principal_type == PrincipalType.SERVICE_ACCOUNT
