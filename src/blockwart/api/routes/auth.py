from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from blockwart.api.deps import get_session
from blockwart.api.errors import API_ERROR_RESPONSES
from blockwart.db.session import transaction
from blockwart.schemas.auth import PrincipalOut
from blockwart.schemas.errors import ApiErrorResponse
from blockwart.services.identity import authenticate_bearer_header

bearer_scheme = HTTPBearer(auto_error=False)
AUTH_ERROR_RESPONSES = {
    **API_ERROR_RESPONSES,
    401: {"model": ApiErrorResponse, "description": "Authentication required"},
}
router = APIRouter(
    prefix="/v1/auth",
    tags=["auth"],
    responses=AUTH_ERROR_RESPONSES,
)


@router.get("/me", response_model=PrincipalOut)
def authenticated_principal(
    request: Request,
    credentials: Annotated[
        HTTPAuthorizationCredentials | None,
        Security(bearer_scheme),
    ],
    session: Annotated[Session, Depends(get_session)],
) -> PrincipalOut:
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
    if principal is None:
        raise HTTPException(
            status_code=401,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return PrincipalOut(
        id=principal.id,
        principal_type=principal.principal_type,
        login=principal.login,
        display_name=principal.display_name,
    )
