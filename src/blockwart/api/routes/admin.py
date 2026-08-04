from __future__ import annotations

from collections.abc import Callable
from datetime import timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, Response
from sqlalchemy.orm import Session

from blockwart.api.deps import get_session
from blockwart.api.errors import API_ERROR_RESPONSES
from blockwart.api.security import require_api_read_access
from blockwart.api.write_commands import api_write_context, execute_api_command
from blockwart.config import Settings
from blockwart.db.session import DatabaseTransactionError, transaction
from blockwart.domain.auth import PrincipalType
from blockwart.domain.timestamps import format_rfc3339_utc
from blockwart.schemas.admin import (
    PasswordResetIn,
    PrincipalAdminDetailOut,
    PrincipalAdminListOut,
    PrincipalCreateIn,
    PrincipalCredentialOut,
    PrincipalGrantCreateIn,
    PrincipalGrantUpdateIn,
    PrincipalMutationOut,
    PrincipalUpdateIn,
    ServiceTokenIssueIn,
    ServiceTokenRotateIn,
)
from blockwart.schemas.v1 import V1GrantCommandOut
from blockwart.services.identity import IdentityError, utc_now
from blockwart.services.pagination import InvalidCursor
from blockwart.services.principal_management import (
    ManagedPrincipalConflict,
    ManagedPrincipalNotFound,
    ManagedPrincipalPreconditionFailed,
    ManagedPrincipalPreconditionRequired,
    PlatformAdminDenied,
    PlatformAdminReauthenticationDenied,
    create_managed_principal,
    create_managed_principal_grant,
    issue_managed_service_token,
    query_principal_detail,
    query_principal_page,
    record_failed_platform_admin_reauthentication,
    require_platform_admin,
    reset_managed_human_password,
    revoke_managed_principal_grant,
    revoke_managed_service_token,
    update_managed_principal,
    update_managed_principal_grant,
)
from blockwart.services.read_access import ReadAccess

router = APIRouter(
    prefix="/v1/admin/principals",
    tags=["api-v1-admin"],
    responses=API_ERROR_RESPONSES,
)


@router.get("", response_model=PrincipalAdminListOut)
def list_admin_principals(
    session: Annotated[Session, Depends(get_session)],
    access: Annotated[ReadAccess, Depends(require_api_read_access)],
    q: Annotated[str | None, Query(max_length=100)] = None,
    principal_type: PrincipalType | None = None,
    active: bool | None = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 100,
    cursor: Annotated[
        str | None,
        Query(max_length=2048, description="Opaque cursor returned by the previous page"),
    ] = None,
) -> PrincipalAdminListOut:
    try:
        page = _execute_admin(
            session,
            lambda: query_principal_page(
                session,
                access,
                query=q,
                principal_type=principal_type,
                active=active,
                limit=limit,
                cursor=cursor,
            ),
            write=False,
        )
    except InvalidCursor as exc:
        raise HTTPException(status_code=400, detail="Invalid cursor") from exc
    return PrincipalAdminListOut(
        items=list(page.items),
        next_cursor=page.next_cursor,
    )


@router.post("", response_model=PrincipalMutationOut, status_code=201)
def create_admin_principal(
    payload: PrincipalCreateIn,
    request: Request,
    response: Response,
    session: Annotated[Session, Depends(get_session)],
    access: Annotated[ReadAccess, Depends(require_api_read_access)],
) -> PrincipalMutationOut:
    result = _execute_admin(
        session,
        lambda: create_managed_principal(
            session,
            access,
            principal_type=payload.principal_type,
            login=payload.login,
            display_name=payload.display_name,
            password=payload.password,
            platform_role=payload.platform_role,
            channel="api",
            request_id=_request_id(request),
        ),
    )
    response.headers["ETag"] = result.principal.etag
    response.headers["Location"] = f"/api/v1/admin/principals/{result.principal.id}"
    return PrincipalMutationOut.model_validate(result)


@router.get("/{principal_id}", response_model=PrincipalAdminDetailOut)
def get_admin_principal(
    principal_id: str,
    response: Response,
    session: Annotated[Session, Depends(get_session)],
    access: Annotated[ReadAccess, Depends(require_api_read_access)],
) -> PrincipalAdminDetailOut:
    detail = _execute_admin(
        session,
        lambda: query_principal_detail(
            session,
            access,
            principal_id=principal_id,
        ),
        write=False,
    )
    response.headers["ETag"] = detail.principal.etag
    return PrincipalAdminDetailOut.model_validate(detail)


@router.post(
    "/{principal_id}/grants",
    response_model=V1GrantCommandOut,
    status_code=201,
)
def create_admin_principal_grant(
    principal_id: str,
    payload: PrincipalGrantCreateIn,
    request: Request,
    response: Response,
    session: Annotated[Session, Depends(get_session)],
    access: Annotated[ReadAccess, Depends(require_api_read_access)],
    if_match: Annotated[str | None, Header(alias="If-Match")] = None,
) -> V1GrantCommandOut:
    _execute_admin(session, lambda: require_platform_admin(access), write=False)
    context = api_write_context(request, access)
    result = execute_api_command(
        session,
        context,
        lambda: create_managed_principal_grant(
            session,
            context,
            principal_id=principal_id,
            object_id=payload.object_id,
            role=payload.role,
            scope=payload.scope,
            expected_revision=if_match,
        ),
    )
    response.headers["ETag"] = result.etag
    return V1GrantCommandOut.model_validate(result)


@router.put(
    "/{principal_id}/grants/{grant_id}",
    response_model=V1GrantCommandOut,
)
def update_admin_principal_grant(
    principal_id: str,
    grant_id: int,
    payload: PrincipalGrantUpdateIn,
    request: Request,
    response: Response,
    session: Annotated[Session, Depends(get_session)],
    access: Annotated[ReadAccess, Depends(require_api_read_access)],
    if_match: Annotated[str | None, Header(alias="If-Match")] = None,
) -> V1GrantCommandOut:
    _execute_admin(session, lambda: require_platform_admin(access), write=False)
    context = api_write_context(request, access)
    result = execute_api_command(
        session,
        context,
        lambda: update_managed_principal_grant(
            session,
            context,
            principal_id=principal_id,
            object_id=payload.object_id,
            grant_id=grant_id,
            role=payload.role,
            scope=payload.scope,
            expected_revision=if_match,
        ),
    )
    response.headers["ETag"] = result.etag
    return V1GrantCommandOut.model_validate(result)


@router.delete(
    "/{principal_id}/grants/{grant_id}",
    response_model=V1GrantCommandOut,
)
def revoke_admin_principal_grant(
    principal_id: str,
    grant_id: int,
    request: Request,
    response: Response,
    session: Annotated[Session, Depends(get_session)],
    access: Annotated[ReadAccess, Depends(require_api_read_access)],
    object_id: Annotated[str, Query(min_length=1, max_length=128)],
    if_match: Annotated[str | None, Header(alias="If-Match")] = None,
) -> V1GrantCommandOut:
    _execute_admin(session, lambda: require_platform_admin(access), write=False)
    context = api_write_context(request, access)
    result = execute_api_command(
        session,
        context,
        lambda: revoke_managed_principal_grant(
            session,
            context,
            principal_id=principal_id,
            object_id=object_id,
            grant_id=grant_id,
            expected_revision=if_match,
        ),
    )
    response.headers["ETag"] = result.etag
    return V1GrantCommandOut.model_validate(result)


@router.put("/{principal_id}", response_model=PrincipalMutationOut)
def update_admin_principal(
    principal_id: str,
    payload: PrincipalUpdateIn,
    request: Request,
    response: Response,
    session: Annotated[Session, Depends(get_session)],
    access: Annotated[ReadAccess, Depends(require_api_read_access)],
    if_match: Annotated[str | None, Header(alias="If-Match")] = None,
) -> PrincipalMutationOut:
    result = _execute_admin(
        session,
        lambda: update_managed_principal(
            session,
            access,
            principal_id=principal_id,
            expected_revision=if_match,
            display_name=payload.display_name,
            active=payload.active,
            platform_role=payload.platform_role,
            channel="api",
            request_id=_request_id(request),
        ),
    )
    response.headers["ETag"] = result.principal.etag
    return PrincipalMutationOut.model_validate(result)


@router.post("/{principal_id}/password", response_model=PrincipalCredentialOut)
def reset_admin_principal_password(
    principal_id: str,
    payload: PasswordResetIn,
    request: Request,
    response: Response,
    session: Annotated[Session, Depends(get_session)],
    access: Annotated[ReadAccess, Depends(require_api_read_access)],
    if_match: Annotated[str | None, Header(alias="If-Match")] = None,
) -> PrincipalCredentialOut:
    result = _execute_admin(
        session,
        lambda: reset_managed_human_password(
            session,
            access,
            principal_id=principal_id,
            expected_revision=if_match,
            new_password=payload.new_password,
            actor_password=payload.current_admin_password,
            channel="api",
            request_id=_request_id(request),
        ),
    )
    response.headers["ETag"] = result.principal.etag
    return PrincipalCredentialOut(
        principal=result.principal,
        changed=result.changed,
    )


@router.post("/{principal_id}/tokens", response_model=PrincipalCredentialOut)
def issue_admin_principal_token(
    principal_id: str,
    payload: ServiceTokenIssueIn,
    request: Request,
    response: Response,
    session: Annotated[Session, Depends(get_session)],
    access: Annotated[ReadAccess, Depends(require_api_read_access)],
    if_match: Annotated[str | None, Header(alias="If-Match")] = None,
    idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
) -> PrincipalCredentialOut:
    return _token_command(
        session=session,
        access=access,
        principal_id=principal_id,
        payload=payload,
        request=request,
        response=response,
        if_match=if_match,
        idempotency_key=idempotency_key,
        rotate=False,
    )


@router.post("/{principal_id}/tokens/rotate", response_model=PrincipalCredentialOut)
def rotate_admin_principal_token(
    principal_id: str,
    payload: ServiceTokenRotateIn,
    request: Request,
    response: Response,
    session: Annotated[Session, Depends(get_session)],
    access: Annotated[ReadAccess, Depends(require_api_read_access)],
    if_match: Annotated[str | None, Header(alias="If-Match")] = None,
    idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
) -> PrincipalCredentialOut:
    return _token_command(
        session=session,
        access=access,
        principal_id=principal_id,
        payload=payload,
        request=request,
        response=response,
        if_match=if_match,
        idempotency_key=idempotency_key,
        rotate=True,
    )


@router.delete("/{principal_id}/tokens/{token_name}", response_model=PrincipalCredentialOut)
def revoke_admin_principal_token(
    principal_id: str,
    token_name: str,
    request: Request,
    response: Response,
    session: Annotated[Session, Depends(get_session)],
    access: Annotated[ReadAccess, Depends(require_api_read_access)],
    if_match: Annotated[str | None, Header(alias="If-Match")] = None,
) -> PrincipalCredentialOut:
    result = _execute_admin(
        session,
        lambda: revoke_managed_service_token(
            session,
            access,
            principal_id=principal_id,
            expected_revision=if_match,
            name=token_name,
            channel="api",
            request_id=_request_id(request),
        ),
    )
    response.headers["ETag"] = result.principal.etag
    return PrincipalCredentialOut(
        principal=result.principal,
        changed=result.changed,
    )


def _token_command(
    *,
    session: Session,
    access: ReadAccess,
    principal_id: str,
    payload: ServiceTokenIssueIn | ServiceTokenRotateIn,
    request: Request,
    response: Response,
    if_match: str | None,
    idempotency_key: str | None,
    rotate: bool,
) -> PrincipalCredentialOut:
    if idempotency_key is None:
        raise HTTPException(status_code=400, detail="Idempotency-Key is required")
    settings: Settings = request.app.state.settings
    expires_at = (
        utc_now() + timedelta(seconds=payload.expires_in_seconds)
        if payload.expires_in_seconds is not None
        else None
    )
    result = _execute_admin(
        session,
        lambda: issue_managed_service_token(
            session,
            access,
            principal_id=principal_id,
            expected_revision=if_match,
            name=payload.name,
            audience=payload.audience,
            expires_at=expires_at,
            actor_password=payload.current_admin_password,
            channel="api",
            request_id=_request_id(request),
            rotate=rotate,
            idempotency_key=idempotency_key,
            idempotency_ttl_seconds=settings.idempotency_ttl_seconds,
            idempotency_request_expiry=(
                f"ttl:{payload.expires_in_seconds}"
                if payload.expires_in_seconds is not None
                else "none"
            ),
        ),
    )
    response.headers["ETag"] = result.principal.etag
    response.headers["Cache-Control"] = "private, no-store"
    issued = result.issued_token
    return PrincipalCredentialOut(
        principal=result.principal,
        changed=result.changed,
        token=issued.value if issued is not None else None,
        token_name=issued.name if issued is not None else payload.name,
        token_audience=issued.audience if issued is not None else payload.audience,
        token_expires_at=(
            format_rfc3339_utc(issued.expires_at)
            if issued is not None and issued.expires_at is not None
            else None
        ),
        disclosure="one_time" if issued is not None else "none",
    )


def _execute_admin[T](
    session: Session,
    command: Callable[[], T],
    *,
    write: bool = True,
) -> T:
    try:
        if not write:
            return command()
        with transaction(session):
            return command()
    except PlatformAdminReauthenticationDenied as exc:
        with transaction(session):
            record_failed_platform_admin_reauthentication(session, exc)
        raise HTTPException(status_code=403, detail="Platform admin permission denied") from exc
    except PlatformAdminDenied as exc:
        raise HTTPException(status_code=403, detail="Platform admin permission denied") from exc
    except ManagedPrincipalNotFound as exc:
        raise HTTPException(status_code=404, detail="Principal not found") from exc
    except ManagedPrincipalPreconditionRequired as exc:
        raise HTTPException(status_code=428, detail=str(exc)) from exc
    except ManagedPrincipalPreconditionFailed as exc:
        raise HTTPException(status_code=412, detail=str(exc)) from exc
    except ManagedPrincipalConflict as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except IdentityError as exc:
        raise HTTPException(status_code=422, detail="Invalid identity data") from exc
    except DatabaseTransactionError as exc:
        cause = str(exc.__cause__ or "")
        if "last active platform admin" in cause:
            raise HTTPException(
                status_code=409,
                detail="At least one active platform admin is required",
            ) from exc
        raise


def _request_id(request: Request) -> str | None:
    value = getattr(request.state, "correlation_id", None)
    return value if isinstance(value, str) else None
