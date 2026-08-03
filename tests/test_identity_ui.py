import re
from collections.abc import Generator

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from blockwart.api.deps import get_session
from blockwart.config import Settings
from blockwart.db.session import transaction
from blockwart.main import create_app
from blockwart.models import BrowserSession, LoginChallenge, SecurityEvent
from blockwart.services.identity import create_human_principal
from blockwart.ui.auth import (
    AUTH_CSRF_COOKIE_NAME,
    AUTH_SESSION_COOKIE_NAME,
    LOGIN_CHALLENGE_COOKIE_NAME,
)

PASSWORD = "correct horse battery staple"


@pytest.fixture
def identity_session_factory(alembic_session_factory):
    with alembic_session_factory() as session:
        with transaction(session):
            principal = create_human_principal(
                session,
                login="browser.user",
                display_name="Browser User",
                password=PASSWORD,
            )
    return alembic_session_factory, principal


@pytest.fixture
def identity_client(identity_session_factory) -> Generator[TestClient, None, None]:
    session_factory, _ = identity_session_factory
    app = create_app(settings=Settings())

    def override_get_session() -> Generator[Session, None, None]:
        with session_factory() as session:
            yield session

    app.dependency_overrides[get_session] = override_get_session
    with TestClient(app, base_url="https://testserver") as client:
        yield client


def _hidden(response, name: str) -> str:
    match = re.search(
        rf'name="{re.escape(name)}" value="([^"]+)"',
        response.text,
    )
    assert match is not None
    return match.group(1)


def test_login_session_and_csrf_protected_logout(
    identity_client: TestClient,
    identity_session_factory,
) -> None:
    session_factory, principal = identity_session_factory
    login_page = identity_client.get("/auth")

    assert login_page.status_code == 200
    challenge = _hidden(login_page, "login_challenge")
    assert identity_client.cookies.get(LOGIN_CHALLENGE_COOKIE_NAME) == challenge
    assert "HttpOnly" in login_page.headers["set-cookie"]
    assert "SameSite=strict" in login_page.headers["set-cookie"]

    login = identity_client.post(
        "/auth/login",
        data={
            "login": "browser.user",
            "password": PASSWORD,
            "login_challenge": challenge,
        },
        follow_redirects=False,
    )

    assert login.status_code == 303
    assert login.headers["location"] == "/"
    assert PASSWORD not in login.text
    assert identity_client.cookies.get(AUTH_SESSION_COOKIE_NAME)
    assert identity_client.cookies.get(AUTH_CSRF_COOKIE_NAME)

    catalog = identity_client.get("/?create=1")
    settings = identity_client.get("/settings")
    assert catalog.status_code == 200
    assert 'role="dialog"' not in catalog.text
    assert "Add asset" not in catalog.text
    assert settings.status_code == 200
    assert 'href="/settings/schema"' in settings.text
    assert 'href="/admin/principals"' not in settings.text

    account = identity_client.get("/auth")
    assert account.status_code == 200
    assert "Browser User" in account.text
    assert principal.id in account.text
    assert 'class="language-switcher"' in account.text
    assert 'data-theme-value="dark"' in account.text
    assert 'data-theme-value="light"' in account.text
    csrf_token = _hidden(account, "csrf_token")

    rejected = identity_client.post(
        "/auth/logout",
        data={"csrf_token": "wrong-csrf-token"},
        follow_redirects=False,
    )
    assert rejected.status_code == 403
    assert identity_client.cookies.get(AUTH_SESSION_COOKIE_NAME)
    with session_factory() as session:
        denied = session.scalar(
            select(SecurityEvent)
            .where(SecurityEvent.event_type == "browser_logout_csrf")
            .order_by(SecurityEvent.id.desc())
        )
        assert denied is not None
        assert denied.outcome == "denied"

    logout = identity_client.post(
        "/auth/logout",
        data={"csrf_token": csrf_token},
        follow_redirects=False,
    )
    assert logout.status_code == 303
    assert AUTH_SESSION_COOKIE_NAME not in identity_client.cookies
    assert AUTH_CSRF_COOKIE_NAME not in identity_client.cookies

    with session_factory() as session:
        stored = session.scalar(
            select(BrowserSession).where(
                BrowserSession.principal_id == principal.id
            )
        )
        assert stored is not None
        assert stored.revoked_at is not None


def test_invalid_login_is_generic_and_security_event_persists(
    identity_client: TestClient,
    identity_session_factory,
) -> None:
    session_factory, _ = identity_session_factory
    page = identity_client.get("/auth")
    challenge = _hidden(page, "login_challenge")
    candidate = "definitely-not-the-password"

    response = identity_client.post(
        "/auth/login",
        headers={"X-Correlation-ID": "ui-login-correlation"},
        data={
            "login": "missing.user",
            "password": candidate,
            "login_challenge": challenge,
        },
        follow_redirects=False,
    )

    assert response.status_code == 401
    assert "login or password is invalid" in response.text.lower()
    assert "missing.user" not in response.text
    assert candidate not in response.text
    assert AUTH_SESSION_COOKIE_NAME not in identity_client.cookies
    with session_factory() as session:
        event = session.scalar(
            select(SecurityEvent)
            .where(SecurityEvent.event_type == "password_authentication")
            .order_by(SecurityEvent.id.desc())
        )
        assert event is not None
        assert event.outcome == "failure"
        assert event.request_id == "ui-login-correlation"
        assert candidate not in event.details_json
        assert "missing.user" not in event.details_json
    assert response.headers["X-Correlation-ID"] == "ui-login-correlation"


def test_login_csrf_is_one_time_and_required(
    identity_client: TestClient,
    identity_session_factory,
) -> None:
    session_factory, _ = identity_session_factory
    page = identity_client.get("/auth")
    challenge = _hidden(page, "login_challenge")

    rejected = identity_client.post(
        "/auth/login",
        data={
            "login": "browser.user",
            "password": PASSWORD,
            "login_challenge": f"{challenge}tampered",
        },
        follow_redirects=False,
    )

    assert rejected.status_code == 403
    assert AUTH_SESSION_COOKIE_NAME not in identity_client.cookies
    with session_factory() as session:
        event = session.scalar(
            select(SecurityEvent)
            .where(SecurityEvent.event_type == "login_csrf")
            .order_by(SecurityEvent.id.desc())
        )
        assert event is not None
        assert event.outcome == "denied"


def test_https_mode_marks_all_identity_cookies_secure(
    identity_session_factory,
) -> None:
    session_factory, _ = identity_session_factory
    app = create_app(settings=Settings())

    def override_get_session() -> Generator[Session, None, None]:
        with session_factory() as session:
            yield session

    app.dependency_overrides[get_session] = override_get_session
    with TestClient(app, base_url="https://testserver") as client:
        page = client.get("/auth")
        challenge = _hidden(page, "login_challenge")
        login = client.post(
            "/auth/login",
            data={
                "login": "browser.user",
                "password": PASSWORD,
                "login_challenge": challenge,
            },
            follow_redirects=False,
        )
        csrf = client.cookies.get(AUTH_CSRF_COOKIE_NAME)
        assert csrf is not None
        logout = client.post(
            "/auth/logout",
            data={"csrf_token": csrf},
            follow_redirects=False,
        )

    assert login.status_code == 303
    assert all(
        "Secure" in header
        for header in login.headers.get_list("set-cookie")
    )
    assert logout.status_code == 303
    assert all(
        "Secure" in header
        for header in logout.headers.get_list("set-cookie")
    )


def test_login_throttle_is_generic_and_aggregates_denial_events(
    identity_session_factory,
) -> None:
    session_factory, _ = identity_session_factory
    app = create_app(
        settings=Settings(
            auth_login_source_attempt_limit=1,
            auth_login_account_attempt_limit=10,
            auth_login_global_attempt_limit=10,
        )
    )

    def override_get_session() -> Generator[Session, None, None]:
        with session_factory() as session:
            yield session

    app.dependency_overrides[get_session] = override_get_session
    with TestClient(app, base_url="https://testserver") as client:
        page = client.get("/auth")
        challenge = _hidden(page, "login_challenge")
        first = client.post(
            "/auth/login",
            data={
                "login": "missing.first",
                "password": "invalid password candidate",
                "login_challenge": challenge,
            },
        )
        replacement = _hidden(first, "login_challenge")
        second = client.post(
            "/auth/login",
            data={
                "login": "missing.second",
                "password": "another invalid candidate",
                "login_challenge": replacement,
            },
        )
        third = client.post(
            "/auth/login",
            data={
                "login": "missing.third",
                "password": "third invalid candidate",
                "login_challenge": replacement,
            },
        )

    assert first.status_code == 401
    assert second.status_code == 429
    assert third.status_code == 429
    assert second.headers["retry-after"] == "60"
    assert 'name="login"' not in second.text
    combined = f"{second.text}\n{third.text}"
    assert "missing.second" not in combined
    assert "missing.third" not in combined
    with session_factory() as session:
        password_failures = session.scalars(
            select(SecurityEvent).where(
                SecurityEvent.event_type == "password_authentication"
            )
        ).all()
        throttled = session.scalars(
            select(SecurityEvent).where(
                SecurityEvent.event_type == "password_authentication_throttled"
            )
        ).all()
        assert len(password_failures) == 1
        assert len(throttled) == 1
        serialized = "\n".join(event.details_json for event in throttled)
        assert "missing.second" not in serialized
        assert "missing.third" not in serialized


def test_login_challenge_issuance_is_bounded_before_database_write(
    identity_session_factory,
) -> None:
    session_factory, _ = identity_session_factory
    app = create_app(
        settings=Settings(
            auth_login_source_challenge_limit=1,
            auth_login_global_challenge_limit=1,
        )
    )

    def override_get_session() -> Generator[Session, None, None]:
        with session_factory() as session:
            yield session

    app.dependency_overrides[get_session] = override_get_session
    with TestClient(app, base_url="https://testserver") as client:
        first = client.get("/auth")
        second = client.get("/auth")

    assert first.status_code == 200
    assert second.status_code == 429
    assert 'name="login"' not in second.text
    with session_factory() as session:
        assert len(session.scalars(select(LoginChallenge)).all()) == 1
