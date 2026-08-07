from __future__ import annotations

import hmac
from typing import Annotated

from fastapi import Depends, Header, HTTPException, Request, Security
from fastapi.security import APIKeyCookie
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
from blockwart.ui.security import AUTH_CSRF_COOKIE_NAME, AUTH_SESSION_COOKIE_NAME

_CSRF_HEADER = "X-CSRF-Token"
_BROWSER_SESSION_SCHEME = APIKeyCookie(
    name=AUTH_SESSION_COOKIE_NAME,
    scheme_name="BrowserSessionCookie",
    auto_error=False,
)

__all__ = [
    "AUTH_CATALOG_ROLE_CSRF_HEADER",
    "require_browser_api_write_access",
]

AUTH_CATALOG_ROLE_CSRF_HEADER = _CSRF_HEADER


def require_browser_api_write_access(
    request: Request,
    session: Annotated[Session, Depends(get_session)],
    session_value: Annotated[str | None, Security(_BROWSER_SESSION_SCHEME)] = None,
    csrf_token: Annotated[
        str | None,
        Header(alias=_CSRF_HEADER, max_length=256),
    ] = None,
) -> ReadAccess:
    """Authenticate an active human browser session for one dedicated JSON API mutation.

    This is intentionally narrow: only the catalog-role mutation uses this dependency.
    Every other `/api/v1/admin` route keeps its existing service-account bearer
    contract. A missing or invalid browser session yields a JSON `401`; a missing or
    mismatched double-submit CSRF header yields a JSON `403` with a redacted denial
    event. Cookie, header, and password values are never logged.
    """
    principal = authenticate_browser_session(session, value=session_value)
    if principal is None:
        raise HTTPException(
            status_code=401,
            detail="Authentication required",
            headers={"WWW-Authenticate": 'Cookie realm="blockwart"'},
        )
    access = read_access_for_principal(session, principal)
    request.state.read_access = access

    csrf_cookie = request.cookies.get(AUTH_CSRF_COOKIE_NAME)
    valid = (
        csrf_token is not None
        and csrf_cookie is not None
        and len(csrf_token) <= 256
        and hmac.compare_digest(csrf_token, csrf_cookie)
        and verify_browser_csrf(
            session,
            session_value=session_value,
            csrf_token=csrf_token,
        )
        is not None
    )
    if valid:
        return access
    with transaction(session):
        record_security_event(
            session,
            event_type="browser_write_csrf",
            outcome="denied",
            channel="api",
            principal_id=principal.id,
            request_id=request_correlation_id(request),
            details={"reason": "invalid_csrf"},
        )
    raise HTTPException(status_code=403, detail="CSRF validation failed")
