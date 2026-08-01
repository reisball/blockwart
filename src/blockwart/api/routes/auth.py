from typing import Annotated

from fastapi import APIRouter, Depends

from blockwart.api.errors import API_ERROR_RESPONSES
from blockwart.api.security import require_api_read_access
from blockwart.schemas.auth import PrincipalOut
from blockwart.schemas.errors import ApiErrorResponse
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
