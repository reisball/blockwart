from typing import Annotated

from fastapi import Depends, HTTPException, Request
from sqlalchemy.orm import Session

from blockwart.api.deps import get_session
from blockwart.services.identity import authenticate_browser_session
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
