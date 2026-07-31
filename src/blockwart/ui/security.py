import hmac
from typing import Annotated

from fastapi import Depends, Form, HTTPException, Request
from sqlalchemy.orm import Session

from blockwart.api.deps import get_session
from blockwart.api.errors import request_correlation_id
from blockwart.db.session import transaction
from blockwart.services.identity import (
    authenticate_browser_session,
    record_security_event,
    verify_browser_csrf,
)
from blockwart.services.read_access import ReadAccess, read_access_for_principal

AUTH_SESSION_COOKIE_NAME = "blockwart_identity_session"
AUTH_CSRF_COOKIE_NAME = "blockwart_identity_csrf"
LOGIN_CHALLENGE_COOKIE_NAME = "blockwart_login_challenge"


def require_browser_read_access(
    request: Request,
    session: Annotated[Session, Depends(get_session)],
) -> ReadAccess:
    principal = authenticate_browser_session(
        session,
        value=request.cookies.get(AUTH_SESSION_COOKIE_NAME),
    )
    if principal is None:
        raise HTTPException(
            status_code=303,
            detail="Authentication required",
            headers={"Location": "/auth"},
        )
    access = read_access_for_principal(session, principal)
    request.state.read_access = access
    return access


def read_access_from_request(request: Request) -> ReadAccess:
    access = getattr(request.state, "read_access", None)
    if not isinstance(access, ReadAccess):
        raise RuntimeError("Authenticated read access is not initialized")
    return access


def require_browser_write_csrf(
    request: Request,
    session: Annotated[Session, Depends(get_session)],
    csrf_token: Annotated[str, Form(max_length=256)],
) -> None:
    session_value = request.cookies.get(AUTH_SESSION_COOKIE_NAME)
    csrf_cookie = request.cookies.get(AUTH_CSRF_COOKIE_NAME)
    valid = (
        csrf_cookie is not None
        and hmac.compare_digest(csrf_cookie, csrf_token)
        and verify_browser_csrf(
            session,
            session_value=session_value,
            csrf_token=csrf_token,
        )
        is not None
    )
    if valid:
        return
    access = getattr(request.state, "read_access", None)
    principal_id = (
        access.principal.id
        if isinstance(access, ReadAccess)
        else None
    )
    with transaction(session):
        record_security_event(
            session,
            event_type="browser_write_csrf",
            outcome="denied",
            channel="ui",
            principal_id=principal_id,
            request_id=request_correlation_id(request),
            details={"reason": "invalid_csrf"},
        )
    raise HTTPException(status_code=403, detail="CSRF validation failed")
