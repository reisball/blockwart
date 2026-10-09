"""Platform-admin UI for agent notice routing and delivery diagnostics (Issue #106).

The page only manages non-secret routing (service-account principal, approved
target route, subscription scope) and shows redacted delivery state. It never
renders a transport endpoint, credential, session, token, lease, or payload.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import select
from sqlalchemy.orm import Session

from blockwart.api.deps import get_session
from blockwart.api.errors import request_correlation_id
from blockwart.db.session import transaction
from blockwart.domain.agent_notices import (
    AGENT_NOTICE_TRANSPORTS,
    DELIVERY_STATUS_VALUES,
    NOTICE_EVENT_TYPES,
    NOTICE_SCOPE_VALUES,
)
from blockwart.models.auth import Principal
from blockwart.services.agent_notices import (
    AuditActor,
    SubscriptionValidationError,
    count_notice_jobs_by_status,
    create_agent_delivery_target,
    create_agent_notice_subscription,
    deactivate_agent_delivery_target,
    list_notice_jobs,
    list_notice_subscriptions,
    list_notice_targets,
    revoke_agent_notice_subscription,
)
from blockwart.services.principal_management import PlatformAdminDenied, require_platform_admin
from blockwart.ui.i18n import translation_context
from blockwart.ui.paths import TEMPLATE_DIR
from blockwart.ui.security import (
    AUTH_CSRF_COOKIE_NAME,
    read_access_from_request,
    require_browser_read_access,
    require_browser_write_csrf,
)

templates = Jinja2Templates(directory=TEMPLATE_DIR)
router = APIRouter(
    prefix="/admin/notices",
    tags=["ui"],
    include_in_schema=False,
    dependencies=[Depends(require_browser_read_access)],
)

_JOB_PAGE_LIMIT = 100


def _require_admin(request: Request) -> None:
    try:
        require_platform_admin(read_access_from_request(request))
    except PlatformAdminDenied as exc:
        raise HTTPException(status_code=403, detail="Platform admin permission denied") from exc


def _actor(request: Request) -> AuditActor:
    return AuditActor(
        principal_id=read_access_from_request(request).principal.id,
        channel="ui",
        request_id=request_correlation_id(request),
    )


def _render(
    request: Request,
    session: Session,
    *,
    status_filter: str = "",
    error: str | None = None,
    status_code: int = 200,
) -> HTMLResponse:
    service_accounts = session.scalars(
        select(Principal)
        .where(Principal.principal_type == "service_account", Principal.active.is_(True))
        .order_by(Principal.login)
    ).all()
    targets = list_notice_targets(session)
    translated = translation_context(request)
    if error is not None:
        message = translated["t"](f"notices.error.{error}")
        error = error if message == f"notices.error.{error}" else message
    return templates.TemplateResponse(
        request,
        "notices.html",
        context={
            "title": "Blockwart · Agent notices",
            "counts": count_notice_jobs_by_status(session),
            "statuses": DELIVERY_STATUS_VALUES,
            "status_filter": status_filter,
            "jobs": list_notice_jobs(
                session,
                status=status_filter or None,
                limit=_JOB_PAGE_LIMIT,
            ),
            "targets": targets,
            "active_targets": [view for view in targets if view.target.active],
            "subscriptions": list_notice_subscriptions(session),
            "service_accounts": service_accounts,
            "transports": sorted(AGENT_NOTICE_TRANSPORTS),
            "event_types": sorted(NOTICE_EVENT_TYPES),
            "scopes": sorted(NOTICE_SCOPE_VALUES),
            "csrf_token": request.cookies.get(AUTH_CSRF_COOKIE_NAME, ""),
            "error": error,
            **translated,
        },
        status_code=status_code,
    )


@router.get("", response_class=HTMLResponse)
def notices_page(
    request: Request,
    session: Annotated[Session, Depends(get_session)],
    status: str = "",
) -> HTMLResponse:
    _require_admin(request)
    if status and status not in DELIVERY_STATUS_VALUES:
        raise HTTPException(status_code=422, detail="Invalid status filter")
    return _render(request, session, status_filter=status)


def _mutate(
    request: Request,
    session: Session,
    command,
) -> HTMLResponse | RedirectResponse:
    _require_admin(request)
    try:
        with transaction(session):
            outcome = command()
    except SubscriptionValidationError as exc:
        return _render(
            request,
            session,
            error=exc.code,
            status_code=409 if exc.is_conflict else 422,
        )
    if outcome is False:
        raise HTTPException(status_code=404, detail="Resource not found")
    return RedirectResponse(url="/admin/notices", status_code=303)


@router.post(
    "/targets",
    response_class=HTMLResponse,
    dependencies=[Depends(require_browser_write_csrf)],
)
def create_target_from_ui(
    request: Request,
    session: Annotated[Session, Depends(get_session)],
    principal_id: Annotated[str, Form(max_length=36)],
    label: Annotated[str, Form(max_length=128)],
    route: Annotated[str, Form(max_length=191)],
    transport: Annotated[str, Form(max_length=32)],
):
    return _mutate(
        request,
        session,
        lambda: create_agent_delivery_target(
            session,
            principal_id=principal_id,
            label=label,
            route=route,
            transport=transport,
            actor=_actor(request),
        ),
    )


@router.post(
    "/targets/{target_id}/revoke",
    response_class=HTMLResponse,
    dependencies=[Depends(require_browser_write_csrf)],
)
def revoke_target_from_ui(
    request: Request,
    target_id: str,
    session: Annotated[Session, Depends(get_session)],
):
    return _mutate(
        request,
        session,
        lambda: deactivate_agent_delivery_target(
            session,
            target_id=target_id,
            now=datetime.now(UTC),
            actor=_actor(request),
        ),
    )


@router.post(
    "/subscriptions",
    response_class=HTMLResponse,
    dependencies=[Depends(require_browser_write_csrf)],
)
def create_subscription_from_ui(
    request: Request,
    session: Annotated[Session, Depends(get_session)],
    principal_id: Annotated[str, Form(max_length=36)],
    target_id: Annotated[str, Form(max_length=36)],
    event_type: Annotated[str, Form(max_length=64)],
    scope: Annotated[str, Form(max_length=16)],
    object_id: Annotated[str, Form(max_length=128)] = "",
):
    access = read_access_from_request(request)
    return _mutate(
        request,
        session,
        lambda: create_agent_notice_subscription(
            session,
            event_type=event_type,
            scope=scope,
            object_id=object_id.strip() or None,
            principal_id=principal_id,
            target_id=target_id,
            created_by_principal_id=access.principal.id,
            actor=_actor(request),
        ),
    )


@router.post(
    "/subscriptions/{subscription_id}/revoke",
    response_class=HTMLResponse,
    dependencies=[Depends(require_browser_write_csrf)],
)
def revoke_subscription_from_ui(
    request: Request,
    subscription_id: str,
    session: Annotated[Session, Depends(get_session)],
):
    return _mutate(
        request,
        session,
        lambda: revoke_agent_notice_subscription(
            session,
            subscription_id=subscription_id,
            now=datetime.now(UTC),
            actor=_actor(request),
        ),
    )
