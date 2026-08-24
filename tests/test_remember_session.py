from __future__ import annotations

import json
import re
from collections.abc import Generator
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.orm import Session

from blockwart.api.deps import get_session
from blockwart.config import Settings
from blockwart.db.session import transaction
from blockwart.main import create_app
from blockwart.models import BrowserSession, SecurityEvent
from blockwart.services.identity import (
    BROWSER_SESSION_MODE_REMEMBER,
    BROWSER_SESSION_MODE_STANDARD,
    IdentityError,
    authenticate_browser_session,
    browser_session_mode,
    create_human_principal,
    deactivate_principal,
    issue_browser_session,
    revoke_browser_session,
    set_human_password,
    utc_now,
    verify_browser_csrf,
)
from blockwart.ui.security import (
    AUTH_CSRF_COOKIE_NAME,
    AUTH_SESSION_COOKIE_NAME,
)

PASSWORD = "correct horse battery staple"
ROTATED_PASSWORD = "rotated horse battery staple"
REMEMBER_TTL_SECONDS = 2_592_000


@pytest.fixture
def remember_session_state(alembic_session_factory):
    with alembic_session_factory() as session:
        with transaction(session):
            principal = create_human_principal(
                session,
                login="remember.user",
                display_name="Remember User",
                password=PASSWORD,
            )
    return alembic_session_factory, principal


def _app(session_factory, *, settings: Settings | None = None):
    app = create_app(settings=settings or Settings())

    def override_get_session() -> Generator[Session, None, None]:
        with session_factory() as session:
            yield session

    app.dependency_overrides[get_session] = override_get_session
    return app


def _hidden(response, name: str) -> str:
    match = re.search(rf'name="{re.escape(name)}" value="([^"]+)"', response.text)
    assert match is not None
    return match.group(1)


def _login(client: TestClient, *, remember: object | None = None, **extra: str):
    page = client.get("/auth")
    data: dict[str, object] = {
        "login": "remember.user",
        "password": PASSWORD,
        "login_challenge": _hidden(page, "login_challenge"),
        **extra,
    }
    if remember is not None:
        data["remember"] = remember
    return client.post("/auth/login", data=data, follow_redirects=False)


def _identity_cookie_headers(response) -> list[str]:
    names = (AUTH_SESSION_COOKIE_NAME, AUTH_CSRF_COOKIE_NAME)
    return [
        header
        for header in response.headers.get_list("set-cookie")
        if header.startswith(tuple(f"{name}=" for name in names))
    ]


def _assert_security_flags(header: str) -> None:
    assert "Secure" in header
    assert "HttpOnly" in header
    assert "SameSite=strict" in header
    assert "Path=/" in header


def test_browser_session_settings_are_defaulted_and_bounded() -> None:
    settings = Settings()
    assert settings.auth_session_ttl_seconds == 3600
    assert settings.auth_remember_session_ttl_seconds == REMEMBER_TTL_SECONDS
    assert Settings(auth_session_ttl_seconds=300).auth_session_ttl_seconds == 300
    assert (
        Settings(auth_remember_session_ttl_seconds=86400)
        .auth_remember_session_ttl_seconds
        == 86400
    )
    assert (
        Settings(auth_remember_session_ttl_seconds=7776000)
        .auth_remember_session_ttl_seconds
        == 7776000
    )

    for field, value in (
        ("auth_session_ttl_seconds", 299),
        ("auth_session_ttl_seconds", 3601),
        ("auth_remember_session_ttl_seconds", 86399),
        ("auth_remember_session_ttl_seconds", 7776001),
    ):
        with pytest.raises(ValidationError):
            Settings(**{field: value})


def test_browser_session_modes_are_absolute_non_sliding_and_redacted(
    remember_session_state,
) -> None:
    session_factory, principal = remember_session_state
    now = utc_now()
    with session_factory() as session:
        with transaction(session):
            standard = issue_browser_session(
                session,
                principal_id=principal.id,
                ttl_seconds=3600,
                request_id="standard-session-issue",
                now=now,
            )
            remembered = issue_browser_session(
                session,
                principal_id=principal.id,
                ttl_seconds=REMEMBER_TTL_SECONDS,
                remember=True,
                request_id="remember-session-issue",
                now=now,
            )

        assert standard.mode == BROWSER_SESSION_MODE_STANDARD
        assert standard.expires_at == now + timedelta(hours=1)
        assert remembered.mode == BROWSER_SESSION_MODE_REMEMBER
        assert remembered.expires_at == now + timedelta(seconds=REMEMBER_TTL_SECONDS)
        stored_expiry = session.get(BrowserSession, remembered.session_id).expires_at

        assert (
            authenticate_browser_session(
                session,
                value=remembered.value,
                now=remembered.expires_at - timedelta(seconds=1),
            )
            == principal
        )
        assert (
            verify_browser_csrf(
                session,
                session_value=remembered.value,
                csrf_token=remembered.csrf_token,
                now=remembered.expires_at - timedelta(seconds=1),
            )
            == principal
        )
        assert browser_session_mode(session, value=remembered.value, now=now) == "remember"
        assert session.get(BrowserSession, remembered.session_id).expires_at == stored_expiry
        assert session.get(BrowserSession, remembered.session_id).last_seen_at is None
        assert (
            authenticate_browser_session(
                session,
                value=remembered.value,
                now=remembered.expires_at,
            )
            is None
        )
        assert (
            authenticate_browser_session(
                session,
                value=standard.value,
                now=standard.expires_at,
            )
            is None
        )

        events = session.scalars(
            select(SecurityEvent).where(SecurityEvent.event_type == "browser_session_issued")
        ).all()
        assert {json.loads(event.details_json)["session_mode"] for event in events} == {
            "standard",
            "remember",
        }
        serialized = "\n".join(event.details_json for event in events)
        for secret in (
            standard.value,
            standard.csrf_token,
            remembered.value,
            remembered.csrf_token,
            session.get(BrowserSession, remembered.session_id).token_hash,
            session.get(BrowserSession, remembered.session_id).csrf_hash,
        ):
            assert secret not in serialized

        with pytest.raises(IdentityError):
            issue_browser_session(
                session,
                principal_id=principal.id,
                ttl_seconds=3601,
            )
        with pytest.raises(IdentityError):
            issue_browser_session(
                session,
                principal_id=principal.id,
                ttl_seconds=3600,
                remember=True,
            )


def test_standard_and_remember_login_cookie_headers_and_localized_default_off_ui(
    remember_session_state,
) -> None:
    session_factory, _ = remember_session_state
    settings = Settings(auth_remember_session_ttl_seconds=172800)

    with TestClient(
        _app(session_factory, settings=settings),
        base_url="https://testserver",
    ) as client:
        english = client.get("/auth")
        assert "Keep me signed in" in english.text
        assert 'name="remember" value="on"' in english.text
        assert 'name="remember" value="on" checked' not in english.text
        standard = _login(client)

    standard_headers = _identity_cookie_headers(standard)
    assert standard.status_code == 303
    assert standard.headers["cache-control"] == "no-store"
    assert len(standard_headers) == 2
    for header in standard_headers:
        _assert_security_flags(header)
        assert "Max-Age" not in header
        assert "Expires" not in header

    with TestClient(
        _app(session_factory, settings=settings),
        base_url="https://testserver",
    ) as client:
        german = client.get("/auth?lang=de")
        assert "Angemeldet bleiben" in german.text
        remembered = _login(client, remember="on")

    remember_headers = _identity_cookie_headers(remembered)
    assert remembered.status_code == 303
    assert remembered.headers["cache-control"] == "no-store"
    assert len(remember_headers) == 2
    for header in remember_headers:
        _assert_security_flags(header)
        assert "Max-Age=172800" in header

    with session_factory() as session:
        lifetimes = sorted(
            int((row.expires_at - row.created_at).total_seconds())
            for row in session.scalars(select(BrowserSession)).all()
        )
        assert lifetimes == [3600, 172800]


@pytest.mark.parametrize(
    "remember_value",
    (None, "", "true", "2592000", ["on", "on"], ["off", "on"]),
)
def test_missing_manipulated_and_duplicate_remember_values_fail_closed(
    remember_session_state,
    remember_value,
) -> None:
    session_factory, _ = remember_session_state
    with session_factory() as session:
        before = set(session.scalars(select(BrowserSession.id)).all())

    with TestClient(_app(session_factory), base_url="https://testserver") as client:
        response = _login(
            client,
            remember=remember_value,
            session_ttl_seconds="999999999",
            max_age="999999999",
            expires="never",
            secure="false",
            httponly="false",
            samesite="none",
        )

    assert response.status_code == 303
    headers = _identity_cookie_headers(response)
    assert len(headers) == 2
    for header in headers:
        _assert_security_flags(header)
        assert "Max-Age" not in header
        assert "Expires" not in header

    with session_factory() as session:
        created = session.scalar(select(BrowserSession).where(BrowserSession.id.not_in(before)))
        assert created is not None
        assert created.expires_at - created.created_at == timedelta(hours=1)


def test_remember_logout_revokes_session_clears_cookies_and_records_safe_mode(
    remember_session_state,
) -> None:
    session_factory, _ = remember_session_state
    with TestClient(_app(session_factory), base_url="https://testserver") as client:
        login = _login(client, remember="on")
        session_value = client.cookies.get(AUTH_SESSION_COOKIE_NAME)
        csrf_token = client.cookies.get(AUTH_CSRF_COOKIE_NAME)
        assert login.status_code == 303
        assert session_value is not None and csrf_token is not None
        logout = client.post(
            "/auth/logout",
            data={"csrf_token": csrf_token},
            follow_redirects=False,
        )
        assert AUTH_SESSION_COOKIE_NAME not in client.cookies
        assert AUTH_CSRF_COOKIE_NAME not in client.cookies

    assert logout.status_code == 303
    assert logout.headers["cache-control"] == "no-store"
    assert len(_identity_cookie_headers(logout)) == 2
    with session_factory() as session:
        row = session.scalar(select(BrowserSession))
        assert row is not None and row.revoked_at is not None
        events = session.scalars(
            select(SecurityEvent).where(
                SecurityEvent.event_type.in_(("browser_session_revoked", "browser_logout"))
            )
        ).all()
        assert len(events) == 2
        assert all(json.loads(event.details_json)["session_mode"] == "remember" for event in events)
        serialized = "\n".join(event.details_json for event in events)
        assert session_value not in serialized
        assert csrf_token not in serialized


@pytest.mark.parametrize("invalidation", ("password", "deactivation", "explicit", "expiry"))
def test_invalidated_remember_sessions_fail_and_clear_stale_cookies(
    remember_session_state,
    invalidation: str,
) -> None:
    session_factory, principal = remember_session_state
    now = utc_now()
    issued_at = (
        now - timedelta(seconds=REMEMBER_TTL_SECONDS + 1)
        if invalidation == "expiry"
        else now
    )
    with session_factory() as session:
        with transaction(session):
            issued = issue_browser_session(
                session,
                principal_id=principal.id,
                ttl_seconds=REMEMBER_TTL_SECONDS,
                remember=True,
                now=issued_at,
            )
        if invalidation != "expiry":
            with transaction(session):
                if invalidation == "password":
                    set_human_password(
                        session,
                        principal_id=principal.id,
                        password=ROTATED_PASSWORD,
                        channel="ui",
                        request_id="password-invalidates-remember",
                    )
                elif invalidation == "deactivation":
                    deactivate_principal(
                        session,
                        principal_id=principal.id,
                        channel="ui",
                        request_id="deactivation-invalidates-remember",
                    )
                else:
                    assert revoke_browser_session(
                        session,
                        value=issued.value,
                        channel="ui",
                        request_id="explicit-invalidates-remember",
                    )
        assert authenticate_browser_session(session, value=issued.value) is None

    with TestClient(_app(session_factory), base_url="https://testserver") as client:
        client.cookies.set(
            AUTH_SESSION_COOKIE_NAME,
            issued.value,
            domain="testserver.local",
            path="/",
        )
        client.cookies.set(
            AUTH_CSRF_COOKIE_NAME,
            issued.csrf_token,
            domain="testserver.local",
            path="/",
        )
        response = client.get("/auth")
        assert AUTH_SESSION_COOKIE_NAME not in client.cookies
        assert AUTH_CSRF_COOKIE_NAME not in client.cookies

    assert response.status_code == 200
    cleared = _identity_cookie_headers(response)
    assert len(cleared) == 2
    for header in cleared:
        _assert_security_flags(header)
        assert "Max-Age=0" in header

    with session_factory() as session:
        if invalidation == "explicit":
            event = session.scalar(
                select(SecurityEvent).where(
                    SecurityEvent.event_type == "browser_session_revoked"
                )
            )
            assert event is not None
            assert json.loads(event.details_json) == {
                "reason": "explicit",
                "session_mode": "remember",
            }
        elif invalidation in {"password", "deactivation"}:
            event = session.scalar(
                select(SecurityEvent).where(
                    SecurityEvent.event_type == "browser_sessions_revoked"
                )
            )
            assert event is not None
            details = json.loads(event.details_json)
            assert details["standard_count"] == 0
            assert details["remember_count"] == 1
