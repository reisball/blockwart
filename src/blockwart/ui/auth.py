from __future__ import annotations

import hmac
from typing import Annotated
from uuid import uuid4

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from blockwart.api.deps import get_session
from blockwart.config import Settings
from blockwart.db.session import transaction
from blockwart.services.identity import (
    authenticate_browser_session,
    authenticate_password,
    consume_login_challenge,
    issue_browser_session,
    issue_login_challenge,
    record_security_event,
    revoke_browser_session,
    verify_browser_csrf,
)
from blockwart.ui.i18n import translation_context
from blockwart.ui.paths import TEMPLATE_DIR

AUTH_SESSION_COOKIE_NAME = "blockwart_identity_session"
AUTH_CSRF_COOKIE_NAME = "blockwart_identity_csrf"
LOGIN_CHALLENGE_COOKIE_NAME = "blockwart_login_challenge"

templates = Jinja2Templates(directory=TEMPLATE_DIR)
router = APIRouter(prefix="/auth", tags=["ui"], include_in_schema=False)


@router.get("", response_class=HTMLResponse)
def auth_page(
    request: Request,
    session: Annotated[Session, Depends(get_session)],
) -> HTMLResponse:
    settings = _settings(request)
    session_value = request.cookies.get(AUTH_SESSION_COOKIE_NAME)
    principal = authenticate_browser_session(
        session,
        value=session_value,
    )
    csrf_cookie = request.cookies.get(AUTH_CSRF_COOKIE_NAME)
    csrf_valid = (
        verify_browser_csrf(
            session,
            session_value=session_value,
            csrf_token=csrf_cookie,
        )
        if principal is not None
        else None
    )
    if principal is not None and csrf_valid is not None:
        return _auth_response(
            request,
            principal=principal,
            csrf_token=csrf_cookie,
        )

    with transaction(session):
        challenge = issue_login_challenge(
            session,
            ttl_seconds=settings.auth_login_challenge_ttl_seconds,
        )
    response = _auth_response(
        request,
        login_challenge=challenge.value,
    )
    _set_login_challenge_cookie(
        response,
        settings=settings,
        value=challenge.value,
    )
    if session_value is not None:
        _delete_identity_cookies(response, settings=settings)
    return response


@router.post("/login", response_class=HTMLResponse)
def login(
    request: Request,
    login: Annotated[str, Form(max_length=128)],
    password: Annotated[str, Form(max_length=1024)],
    login_challenge: Annotated[str, Form(max_length=512)],
    session: Annotated[Session, Depends(get_session)],
):
    settings = _settings(request)
    request_id = str(uuid4())
    challenge_cookie = request.cookies.get(LOGIN_CHALLENGE_COOKIE_NAME)
    with transaction(session):
        challenge_valid = consume_login_challenge(
            session,
            cookie_value=challenge_cookie,
            form_value=login_challenge,
        )
        if not challenge_valid:
            record_security_event(
                session,
                event_type="login_csrf",
                outcome="denied",
                channel="ui",
                request_id=request_id,
                details={"reason": "invalid_challenge"},
            )
            replacement = issue_login_challenge(
                session,
                ttl_seconds=settings.auth_login_challenge_ttl_seconds,
            )
            principal = None
            issued_session = None
        else:
            principal = authenticate_password(
                session,
                login=login,
                password=password,
                channel="ui",
                request_id=request_id,
            )
            replacement = (
                issue_login_challenge(
                    session,
                    ttl_seconds=settings.auth_login_challenge_ttl_seconds,
                )
                if principal is None
                else None
            )
            issued_session = (
                issue_browser_session(
                    session,
                    principal_id=principal.id,
                    ttl_seconds=settings.auth_session_ttl_seconds,
                )
                if principal is not None
                else None
            )

    if issued_session is not None:
        response = RedirectResponse(url="/", status_code=303)
        response.set_cookie(
            key=AUTH_SESSION_COOKIE_NAME,
            value=issued_session.value,
            max_age=settings.auth_session_ttl_seconds,
            httponly=True,
            secure=settings.auth_cookie_secure,
            samesite="strict",
            path="/",
        )
        response.set_cookie(
            key=AUTH_CSRF_COOKIE_NAME,
            value=issued_session.csrf_token,
            max_age=settings.auth_session_ttl_seconds,
            httponly=True,
            secure=settings.auth_cookie_secure,
            samesite="strict",
            path="/",
        )
        response.delete_cookie(
            key=LOGIN_CHALLENGE_COOKIE_NAME,
            path="/auth",
            httponly=True,
            secure=settings.auth_cookie_secure,
            samesite="strict",
        )
        response.headers["Cache-Control"] = "no-store"
        return response

    assert replacement is not None
    i18n = translation_context(request)
    response = _auth_response(
        request,
        login_challenge=replacement.value,
        error=(
            i18n["t"]("auth.csrf_failed")
            if not challenge_valid
            else i18n["t"]("auth.login_failed")
        ),
        status_code=403 if not challenge_valid else 401,
    )
    _set_login_challenge_cookie(
        response,
        settings=settings,
        value=replacement.value,
    )
    return response


@router.post("/logout")
def logout(
    request: Request,
    csrf_token: Annotated[str, Form(max_length=256)],
    session: Annotated[Session, Depends(get_session)],
) -> RedirectResponse:
    settings = _settings(request)
    request_id = str(uuid4())
    session_value = request.cookies.get(AUTH_SESSION_COOKIE_NAME)
    csrf_cookie = request.cookies.get(AUTH_CSRF_COOKIE_NAME)
    csrf_matches_cookie = (
        csrf_cookie is not None
        and csrf_cookie != ""
        and hmac.compare_digest(csrf_cookie, csrf_token)
    )
    with transaction(session):
        principal = (
            verify_browser_csrf(
                session,
                session_value=session_value,
                csrf_token=csrf_token,
            )
            if csrf_matches_cookie
            else None
        )
        if principal is None:
            record_security_event(
                session,
                event_type="browser_logout_csrf",
                outcome="denied",
                channel="ui",
                request_id=request_id,
                details={"reason": "invalid_csrf"},
            )
        else:
            revoke_browser_session(
                session,
                value=session_value,
            )
            record_security_event(
                session,
                event_type="browser_logout",
                outcome="success",
                channel="ui",
                principal_id=principal.id,
                request_id=request_id,
                details={},
            )
    if principal is None:
        raise HTTPException(status_code=403, detail="CSRF validation failed")
    response = RedirectResponse(url="/", status_code=303)
    _delete_identity_cookies(response, settings=settings)
    response.headers["Cache-Control"] = "no-store"
    return response


def _auth_response(
    request: Request,
    *,
    principal=None,
    csrf_token: str | None = None,
    login_challenge: str | None = None,
    error: str | None = None,
    status_code: int = 200,
) -> HTMLResponse:
    i18n = translation_context(request)
    response = templates.TemplateResponse(
        request,
        "auth.html",
        context={
            "title": i18n["t"]("auth.title"),
            "principal": principal,
            "csrf_token": csrf_token,
            "login_challenge": login_challenge,
            "error": error,
            **i18n,
        },
        status_code=status_code,
    )
    response.headers["Cache-Control"] = "no-store"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response


def _set_login_challenge_cookie(
    response: HTMLResponse,
    *,
    settings: Settings,
    value: str,
) -> None:
    response.set_cookie(
        key=LOGIN_CHALLENGE_COOKIE_NAME,
        value=value,
        max_age=settings.auth_login_challenge_ttl_seconds,
        httponly=True,
        secure=settings.auth_cookie_secure,
        samesite="strict",
        path="/auth",
    )


def _delete_identity_cookies(
    response,
    *,
    settings: Settings,
) -> None:
    for name in (AUTH_SESSION_COOKIE_NAME, AUTH_CSRF_COOKIE_NAME):
        response.delete_cookie(
            key=name,
            path="/",
            httponly=True,
            secure=settings.auth_cookie_secure,
            samesite="strict",
        )


def _settings(request: Request) -> Settings:
    settings = getattr(request.app.state, "settings", None)
    if not isinstance(settings, Settings):
        raise RuntimeError("Blockwart settings are not initialized")
    return settings
