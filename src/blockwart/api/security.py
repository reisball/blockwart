from typing import Annotated

from fastapi import Depends, HTTPException, Request, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from blockwart.api.deps import get_session
from blockwart.db.session import transaction
from blockwart.services.identity import authenticate_bearer_header
from blockwart.services.read_access import ReadAccess, read_access_for_principal

bearer_scheme = HTTPBearer(auto_error=False)


def require_api_read_access(
    request: Request,
    credentials: Annotated[
        HTTPAuthorizationCredentials | None,
        Security(bearer_scheme),
    ],
    session: Annotated[Session, Depends(get_session)],
) -> ReadAccess:
    authorization = (
        f"{credentials.scheme} {credentials.credentials}"
        if credentials is not None
        else None
    )
    with transaction(session):
        principal = authenticate_bearer_header(
            session,
            authorization=authorization,
            channel="api",
            request_id=getattr(request.state, "correlation_id", None),
        )
        if principal is not None:
            access = read_access_for_principal(session, principal)
    if principal is None:
        raise HTTPException(
            status_code=401,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    request.state.read_access = access
    return access
