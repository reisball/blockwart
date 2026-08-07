from __future__ import annotations

from collections.abc import Callable
from datetime import timedelta
from typing import Annotated, Literal
from urllib.parse import urlencode
from uuid import uuid4

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from blockwart.api.deps import get_session
from blockwart.api.errors import request_correlation_id
from blockwart.db.session import DatabaseTransactionError, transaction
from blockwart.domain.auth import (
    CatalogRole,
    GrantScope,
    PlatformRole,
    PrincipalType,
    Role,
)
from blockwart.models import CatalogObject
from blockwart.schemas.admin import (
    SERVICE_TOKEN_MAX_TTL_SECONDS,
    SERVICE_TOKEN_MIN_TTL_SECONDS,
)
from blockwart.services.identity import IdentityError, utc_now
from blockwart.services.pagination import InvalidCursor
from blockwart.services.principal_management import (
    CatalogOwnerDenied,
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
    query_principals,
    reauthenticate_platform_admin,
    record_catalog_owner_denial,
    record_failed_platform_admin_reauthentication,
    reset_managed_human_password,
    revoke_managed_principal_grant,
    revoke_managed_service_token,
    set_managed_catalog_role,
    update_managed_principal,
    update_managed_principal_grant,
)
from blockwart.ui.i18n import translation_context
from blockwart.ui.paths import TEMPLATE_DIR
from blockwart.ui.security import (
    AUTH_CSRF_COOKIE_NAME,
    read_access_from_request,
    require_browser_read_access,
    require_browser_write_csrf,
)
from blockwart.ui.write_commands import execute_ui_command, ui_write_context

templates = Jinja2Templates(directory=TEMPLATE_DIR)
router = APIRouter(
    prefix="/admin/principals",
    tags=["ui"],
    include_in_schema=False,
    dependencies=[Depends(require_browser_read_access)],
)


@router.get("", response_class=HTMLResponse)
def principal_list_page(
    request: Request,
    session: Annotated[Session, Depends(get_session)],
    q: str = "",
    principal_type: str = "",
    active: str = "",
    limit: int = 100,
    cursor: str | None = None,
) -> HTMLResponse:
    access = read_access_from_request(request)
    try:
        resolved_type = PrincipalType(principal_type) if principal_type else None
    except ValueError as exc:
        raise HTTPException(status_code=422, detail="Invalid principal type") from exc
    if active not in {"", "active", "inactive"}:
        raise HTTPException(status_code=422, detail="Invalid active filter")
    resolved_active = {"active": True, "inactive": False}.get(active)
    if limit < 1 or limit > 100 or (cursor is not None and len(cursor) > 2048):
        raise HTTPException(status_code=422, detail="Invalid principal page")
    try:
        page = _execute_admin_ui(
            session,
            lambda: query_principal_page(
                session,
                access,
                query=q,
                principal_type=resolved_type,
                active=resolved_active,
                limit=limit,
                cursor=cursor,
            ),
            write=False,
        )
    except InvalidCursor as exc:
        raise HTTPException(status_code=400, detail="Invalid cursor") from exc
    next_url = None
    if page.next_cursor is not None:
        params = {
            "q": q,
            "principal_type": principal_type,
            "active": active,
            "limit": limit,
            "cursor": page.next_cursor,
        }
        next_url = f"/admin/principals?{urlencode(params)}"
    return templates.TemplateResponse(
        request,
        "principals.html",
        context={
            "title": "Blockwart · Principals",
            "items": page.items,
            "q": q,
            "principal_type_filter": principal_type,
            "active_filter": active,
            "next_url": next_url,
            "principal_types": tuple(PrincipalType),
            "platform_roles": tuple(PlatformRole),
            "catalog_roles": tuple(CatalogRole),
            "csrf_token": request.cookies.get(AUTH_CSRF_COOKIE_NAME, ""),
            **translation_context(request),
        },
    )


@router.post("", response_class=HTMLResponse, dependencies=[Depends(require_browser_write_csrf)])
def create_principal_from_ui(
    request: Request,
    session: Annotated[Session, Depends(get_session)],
    principal_type: Annotated[str, Form(max_length=32)],
    login: Annotated[str, Form(max_length=128)],
    display_name: Annotated[str, Form(max_length=255)],
    initial_password: Annotated[str, Form(max_length=1024)] = "",
    platform_role: Annotated[str, Form(max_length=32)] = "",
    current_admin_password: Annotated[str, Form(max_length=1024)] = "",
) -> HTMLResponse:
    access = read_access_from_request(request)
    try:
        with transaction(session):
            reauthenticate_platform_admin(
                session,
                access,
                password=current_admin_password,
                channel="ui",
                request_id=request_correlation_id(request),
            )
            result = create_managed_principal(
                session,
                access,
                principal_type=PrincipalType(principal_type),
                login=login,
                display_name=display_name,
                password=initial_password or None,
                platform_role=PlatformRole(platform_role) if platform_role else None,
                channel="ui",
                request_id=request_correlation_id(request),
            )
    except PlatformAdminReauthenticationDenied as exc:
        with transaction(session):
            record_failed_platform_admin_reauthentication(session, exc)
        return _principal_list_error(
            request,
            session,
            error="Platform admin permission denied",
            status_code=403,
        )
    except (IdentityError, ValueError, ManagedPrincipalConflict, PlatformAdminDenied) as exc:
        return _principal_list_error(request, session, error=str(exc))
    return RedirectResponse(
        url=f"/admin/principals/{result.principal.id}",
        status_code=303,
    )


@router.get("/{principal_id}", response_class=HTMLResponse)
def principal_detail_page(
    request: Request,
    principal_id: str,
    session: Annotated[Session, Depends(get_session)],
) -> HTMLResponse:
    return _render_principal_detail(request, session, principal_id)


@router.post(
    "/{principal_id}",
    response_class=HTMLResponse,
    dependencies=[Depends(require_browser_write_csrf)],
)
def update_principal_from_ui(
    request: Request,
    principal_id: str,
    session: Annotated[Session, Depends(get_session)],
    display_name: Annotated[str, Form(max_length=255)],
    active: Annotated[Literal["active", "inactive"], Form()],
    # A required bounded sequence preserves an explicit blank while rejecting omission/repetition.
    platform_role_values: Annotated[
        list[Literal["", "admin"]],
        Form(alias="platform_role", min_length=1, max_length=1),
    ],
    if_match: Annotated[str, Form()] = "",
) -> HTMLResponse:
    access = read_access_from_request(request)
    platform_role = platform_role_values[0]
    try:
        _execute_admin_ui(
            session,
            lambda: update_managed_principal(
                session,
                access,
                principal_id=principal_id,
                expected_revision=if_match,
                display_name=display_name,
                active=active == "active",
                platform_role=PlatformRole(platform_role) if platform_role else None,
                channel="ui",
                request_id=request_correlation_id(request),
            ),
        )
    except HTTPException as exc:
        return _render_principal_detail(
            request,
            session,
            principal_id,
            error=str(exc.detail),
            status_code=exc.status_code,
        )
    return RedirectResponse(url=f"/admin/principals/{principal_id}", status_code=303)


@router.post(
    "/{principal_id}/password",
    response_class=HTMLResponse,
    dependencies=[Depends(require_browser_write_csrf)],
)
def reset_principal_password_from_ui(
    request: Request,
    principal_id: str,
    session: Annotated[Session, Depends(get_session)],
    new_password: Annotated[str, Form(max_length=1024)],
    current_admin_password: Annotated[str, Form(max_length=1024)],
    if_match: Annotated[str, Form()],
) -> HTMLResponse:
    access = read_access_from_request(request)
    try:
        _execute_admin_ui(
            session,
            lambda: reset_managed_human_password(
                session,
                access,
                principal_id=principal_id,
                expected_revision=if_match,
                new_password=new_password,
                actor_password=current_admin_password,
                channel="ui",
                request_id=request_correlation_id(request),
            ),
        )
    except HTTPException as exc:
        return _render_principal_detail(
            request,
            session,
            principal_id,
            error=str(exc.detail),
            status_code=exc.status_code,
        )
    return RedirectResponse(url=f"/admin/principals/{principal_id}", status_code=303)


@router.post(
    "/{principal_id}/catalog-role",
    response_class=HTMLResponse,
    dependencies=[Depends(require_browser_write_csrf)],
)
def set_principal_catalog_role_from_ui(
    request: Request,
    principal_id: str,
    session: Annotated[Session, Depends(get_session)],
    current_admin_password: Annotated[str, Form(max_length=1024)],
    if_match: Annotated[str, Form()],
    catalog_role: Annotated[str, Form(max_length=32)] = "",
) -> HTMLResponse:
    access = read_access_from_request(request)
    try:
        _execute_admin_ui(
            session,
            lambda: set_managed_catalog_role(
                session,
                access,
                principal_id=principal_id,
                expected_revision=if_match,
                catalog_role=CatalogRole(catalog_role) if catalog_role else None,
                actor_password=current_admin_password,
                channel="ui",
                request_id=request_correlation_id(request),
            ),
        )
    except HTTPException as exc:
        return _render_principal_detail(
            request,
            session,
            principal_id,
            error=str(exc.detail),
            status_code=exc.status_code,
        )
    return RedirectResponse(url=f"/admin/principals/{principal_id}", status_code=303)


@router.post(
    "/{principal_id}/tokens",
    response_class=HTMLResponse,
    dependencies=[Depends(require_browser_write_csrf)],
)
def issue_principal_token_from_ui(
    request: Request,
    principal_id: str,
    session: Annotated[Session, Depends(get_session)],
    name: Annotated[str, Form(max_length=128)],
    current_admin_password: Annotated[str, Form(max_length=1024)],
    if_match: Annotated[str, Form()],
    idempotency_key: Annotated[str, Form(max_length=128)],
    rotate: Annotated[Literal["0", "1"], Form()],
    audience: Annotated[Literal["api", "mcp"] | None, Form()] = None,
    expires_in_seconds: Annotated[
        int | None,
        Form(
            ge=SERVICE_TOKEN_MIN_TTL_SECONDS,
            le=SERVICE_TOKEN_MAX_TTL_SECONDS,
        ),
    ] = None,
) -> HTMLResponse:
    access = read_access_from_request(request)
    try:
        expires_at = (
            utc_now() + timedelta(seconds=expires_in_seconds)
            if expires_in_seconds is not None
            else None
        )
        result = _execute_admin_ui(
            session,
            lambda: issue_managed_service_token(
                session,
                access,
                principal_id=principal_id,
                expected_revision=if_match,
                name=name,
                audience=audience,
                expires_at=expires_at,
                actor_password=current_admin_password,
                channel="ui",
                request_id=request_correlation_id(request),
                rotate=rotate == "1",
                idempotency_key=idempotency_key,
                idempotency_ttl_seconds=request.app.state.settings.idempotency_ttl_seconds,
                idempotency_request_expiry=(
                    f"ttl:{expires_in_seconds}"
                    if expires_in_seconds is not None
                    else "none"
                ),
            ),
        )
    except (OverflowError, ValueError):
        return _render_principal_detail(
            request,
            session,
            principal_id,
            error="Invalid token expiry",
            status_code=422,
        )
    except HTTPException as exc:
        return _render_principal_detail(
            request,
            session,
            principal_id,
            error=str(exc.detail),
            status_code=exc.status_code,
        )
    response = _render_principal_detail(
        request,
        session,
        principal_id,
        one_time_token=(
            result.issued_token.value if result.issued_token is not None else None
        ),
    )
    response.headers["Cache-Control"] = "private, no-store"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response


@router.post(
    "/{principal_id}/tokens/revoke",
    response_class=HTMLResponse,
    dependencies=[Depends(require_browser_write_csrf)],
)
def revoke_principal_token_from_ui(
    request: Request,
    principal_id: str,
    session: Annotated[Session, Depends(get_session)],
    name: Annotated[str, Form(max_length=128)],
    if_match: Annotated[str, Form()],
) -> HTMLResponse:
    access = read_access_from_request(request)
    try:
        _execute_admin_ui(
            session,
            lambda: revoke_managed_service_token(
                session,
                access,
                principal_id=principal_id,
                expected_revision=if_match,
                name=name,
                channel="ui",
                request_id=request_correlation_id(request),
            ),
        )
    except HTTPException as exc:
        return _render_principal_detail(
            request,
            session,
            principal_id,
            error=str(exc.detail),
            status_code=exc.status_code,
        )
    return RedirectResponse(url=f"/admin/principals/{principal_id}", status_code=303)


@router.post(
    "/{principal_id}/grants",
    response_class=HTMLResponse,
    dependencies=[Depends(require_browser_write_csrf)],
)
def create_principal_grant_from_ui(
    request: Request,
    principal_id: str,
    session: Annotated[Session, Depends(get_session)],
    object_id: Annotated[str, Form(max_length=128)],
    role: Annotated[str, Form(max_length=32)],
    scope: Annotated[str, Form(max_length=16)],
    if_match: Annotated[str, Form()],
) -> HTMLResponse:
    access = read_access_from_request(request)
    context = ui_write_context(request, access)
    try:
        _execute_admin_ui(session, lambda: query_principals(session, access), write=False)
        execute_ui_command(
            session,
            context,
            lambda: create_managed_principal_grant(
                session,
                context,
                principal_id=principal_id,
                object_id=object_id,
                role=Role(role),
                scope=GrantScope(scope),
                expected_revision=if_match,
            ),
        )
    except (HTTPException, ValueError) as exc:
        detail = exc.detail if isinstance(exc, HTTPException) else str(exc)
        status = exc.status_code if isinstance(exc, HTTPException) else 422
        return _render_principal_detail(
            request, session, principal_id, error=str(detail), status_code=status
        )
    return RedirectResponse(url=f"/admin/principals/{principal_id}", status_code=303)


@router.post(
    "/{principal_id}/grants/{grant_id}",
    response_class=HTMLResponse,
    dependencies=[Depends(require_browser_write_csrf)],
)
def update_principal_grant_from_ui(
    request: Request,
    principal_id: str,
    grant_id: int,
    session: Annotated[Session, Depends(get_session)],
    object_id: Annotated[str, Form(max_length=128)],
    role: Annotated[str, Form(max_length=32)],
    scope: Annotated[str, Form(max_length=16)],
    if_match: Annotated[str, Form()],
) -> HTMLResponse:
    access = read_access_from_request(request)
    context = ui_write_context(request, access)
    try:
        _execute_admin_ui(session, lambda: query_principals(session, access), write=False)
        execute_ui_command(
            session,
            context,
            lambda: update_managed_principal_grant(
                session,
                context,
                principal_id=principal_id,
                object_id=object_id,
                grant_id=grant_id,
                role=Role(role),
                scope=GrantScope(scope),
                expected_revision=if_match,
            ),
        )
    except (HTTPException, ValueError) as exc:
        detail = exc.detail if isinstance(exc, HTTPException) else str(exc)
        status = exc.status_code if isinstance(exc, HTTPException) else 422
        return _render_principal_detail(
            request, session, principal_id, error=str(detail), status_code=status
        )
    return RedirectResponse(url=f"/admin/principals/{principal_id}", status_code=303)


@router.post(
    "/{principal_id}/grants/{grant_id}/revoke",
    response_class=HTMLResponse,
    dependencies=[Depends(require_browser_write_csrf)],
)
def revoke_principal_grant_from_ui(
    request: Request,
    principal_id: str,
    grant_id: int,
    session: Annotated[Session, Depends(get_session)],
    object_id: Annotated[str, Form(max_length=128)],
    if_match: Annotated[str, Form()],
) -> HTMLResponse:
    access = read_access_from_request(request)
    context = ui_write_context(request, access)
    try:
        _execute_admin_ui(session, lambda: query_principals(session, access), write=False)
        execute_ui_command(
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
    except HTTPException as exc:
        return _render_principal_detail(
            request,
            session,
            principal_id,
            error=str(exc.detail),
            status_code=exc.status_code,
        )
    return RedirectResponse(url=f"/admin/principals/{principal_id}", status_code=303)


def _render_principal_detail(
    request: Request,
    session: Session,
    principal_id: str,
    *,
    error: str | None = None,
    one_time_token: str | None = None,
    status_code: int = 200,
) -> HTMLResponse:
    access = read_access_from_request(request)
    detail = _execute_admin_ui(
        session,
        lambda: query_principal_detail(session, access, principal_id=principal_id),
        write=False,
    )
    manageable_ids = access.policy.authorized_ids("manage_access")
    manageable_objects = session.scalars(
        select(CatalogObject)
        .where(CatalogObject.id.in_(manageable_ids))
        .order_by(CatalogObject.kind, func.lower(CatalogObject.label), CatalogObject.id)
    ).all() if manageable_ids else []
    response = templates.TemplateResponse(
        request,
        "principal_detail.html",
        context={
            "title": f"Blockwart · {detail.principal.login}",
            "detail": detail,
            "manageable_objects": manageable_objects,
            "roles": tuple(Role),
            "scopes": tuple(GrantScope),
            "platform_roles": tuple(PlatformRole),
            "catalog_roles": tuple(CatalogRole),
            "csrf_token": request.cookies.get(AUTH_CSRF_COOKIE_NAME, ""),
            "idempotency_key": f"ui-token-{uuid4()}",
            "error": error,
            "one_time_token": one_time_token,
            **translation_context(request),
        },
        status_code=status_code,
    )
    response.headers["ETag"] = detail.principal.etag
    return response


def _principal_list_error(
    request: Request,
    session: Session,
    *,
    error: str,
    status_code: int = 422,
) -> HTMLResponse:
    access = read_access_from_request(request)
    items = _execute_admin_ui(
        session,
        lambda: query_principals(session, access),
        write=False,
    )
    return templates.TemplateResponse(
        request,
        "principals.html",
        context={
            "title": "Blockwart · Principals",
            "items": items,
            "q": "",
            "principal_type_filter": "",
            "active_filter": "",
            "next_url": None,
            "principal_types": tuple(PrincipalType),
            "platform_roles": tuple(PlatformRole),
            "catalog_roles": tuple(CatalogRole),
            "csrf_token": request.cookies.get(AUTH_CSRF_COOKIE_NAME, ""),
            "error": error,
            **translation_context(request),
        },
        status_code=status_code,
    )


def _execute_admin_ui[T](
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
    except CatalogOwnerDenied as exc:
        with transaction(session):
            record_catalog_owner_denial(session, exc)
        raise HTTPException(
            status_code=403,
            detail=(
                "Catalog owner administration requires dual "
                "platform-admin and catalog-owner role"
            ),
        ) from exc
    except ManagedPrincipalNotFound as exc:
        raise HTTPException(status_code=404, detail="Principal not found") from exc
    except ManagedPrincipalPreconditionRequired as exc:
        raise HTTPException(status_code=428, detail=str(exc)) from exc
    except ManagedPrincipalPreconditionFailed as exc:
        raise HTTPException(status_code=412, detail=str(exc)) from exc
    except (ManagedPrincipalConflict, IdentityError) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except DatabaseTransactionError as exc:
        cause = str(exc.__cause__ or "")
        if "last active platform admin" in cause:
            raise HTTPException(
                status_code=409,
                detail="At least one active platform admin is required",
            ) from exc
        if "last active catalog owner" in cause:
            raise HTTPException(
                status_code=409,
                detail="At least one active catalog owner is required",
            ) from exc
        raise
