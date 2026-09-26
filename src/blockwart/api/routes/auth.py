from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.orm import Session

from blockwart.api.deps import get_session
from blockwart.api.errors import API_ERROR_RESPONSES
from blockwart.api.security import require_api_read_access
from blockwart.domain.auth import Role
from blockwart.schemas.auth import OwnDirectGrantListOut, OwnDirectGrantOut, PrincipalOut
from blockwart.schemas.errors import ApiErrorResponse
from blockwart.services.own_grants import query_own_direct_grants
from blockwart.services.pagination import InvalidCursor
from blockwart.services.read_access import ReadAccess

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
    access: Annotated[ReadAccess, Depends(require_api_read_access)],
) -> PrincipalOut:
    principal = access.principal
    return PrincipalOut(
        id=principal.id,
        principal_type=principal.principal_type,
        login=principal.login,
        display_name=principal.display_name,
        platform_role=principal.platform_role,
        revision=principal.revision,
    )


@router.get("/me/direct-grants", response_model=OwnDirectGrantListOut)
def own_direct_grants(
    request: Request,
    session: Annotated[Session, Depends(get_session)],
    access: Annotated[ReadAccess, Depends(require_api_read_access)],
    role: Role | None = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 100,
    cursor: Annotated[
        str | None,
        Query(max_length=2048, description="Opaque cursor returned by the previous page"),
    ] = None,
) -> OwnDirectGrantListOut:
    if "principal_id" in request.query_params:
        raise HTTPException(status_code=400, detail="principal_id is not allowed")
    if cursor == "":
        raise HTTPException(status_code=400, detail="Invalid cursor")
    try:
        page = query_own_direct_grants(
            session,
            principal_id=access.principal.id,
            role=role,
            limit=limit,
            cursor=cursor,
        )
    except InvalidCursor as exc:
        raise HTTPException(status_code=400, detail="Invalid cursor") from exc
    return OwnDirectGrantListOut(
        items=[
            OwnDirectGrantOut(
                target_kind=grant.target_kind,
                target_id=grant.target_id,
                role=grant.role,
                scope=grant.scope,
            )
            for grant in page.items
        ],
        next_cursor=page.next_cursor,
    )
