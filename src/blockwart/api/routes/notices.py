from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.orm import Session

from blockwart.api.deps import get_session
from blockwart.api.errors import API_ERROR_RESPONSES, CodedHTTPException, request_correlation_id
from blockwart.api.security import require_api_read_access
from blockwart.db.session import transaction
from blockwart.models.auth import Principal
from blockwart.schemas.agent_notices import (
    AgentNoticeAcknowledgeOut,
    AgentNoticeDeliveryJobListOut,
    AgentNoticeDeliveryJobOut,
    AgentNoticeListOut,
    AgentNoticeOut,
    AgentNoticeSubscriptionIn,
    AgentNoticeSubscriptionListOut,
    AgentNoticeSubscriptionOut,
    AgentNoticeTargetIn,
    AgentNoticeTargetListOut,
    AgentNoticeTargetOut,
    NoticeStatus,
)
from blockwart.services.agent_notices import (
    AuditActor,
    NoticeJobView,
    NoticeTargetView,
    SubscriptionValidationError,
    acknowledge_agent_notice,
    create_agent_delivery_target,
    create_agent_notice_subscription,
    deactivate_agent_delivery_target,
    list_notice_jobs,
    list_notice_subscriptions,
    list_notice_targets,
    list_own_agent_notices,
    revoke_agent_notice_subscription,
)
from blockwart.services.principal_management import PlatformAdminDenied, require_platform_admin
from blockwart.services.read_access import ReadAccess

admin_router = APIRouter(
    prefix="/v1/admin/notices",
    tags=["api-v1-admin-notices"],
    responses=API_ERROR_RESPONSES,
)

agent_router = APIRouter(
    prefix="/v1/notices",
    tags=["agent-notices"],
    responses=API_ERROR_RESPONSES,
)


def _utcnow() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


# --- Admin: routing management and redacted diagnostics ---


def _require_admin(access: ReadAccess) -> None:
    try:
        require_platform_admin(access)
    except PlatformAdminDenied as exc:
        raise HTTPException(status_code=403, detail="Platform admin permission denied") from exc


def _actor(request: Request, access: ReadAccess) -> AuditActor:
    return AuditActor(
        principal_id=access.principal.id,
        channel="api",
        request_id=request_correlation_id(request),
    )


def _validation_http_error(exc: SubscriptionValidationError) -> HTTPException:
    return CodedHTTPException(
        409 if exc.is_conflict else 422,
        error_code=exc.code,
        detail=exc.code.replace("_", " "),
    )


def target_out(view: NoticeTargetView) -> AgentNoticeTargetOut:
    target = view.target
    return AgentNoticeTargetOut(
        id=target.id,
        principal_id=target.principal_id,
        principal_login=view.principal_login,
        label=target.label,
        route=target.route,
        transport=target.transport,
        active=target.active,
    )


def job_out(view: NoticeJobView) -> AgentNoticeDeliveryJobOut:
    job, event = view.job, view.event
    return AgentNoticeDeliveryJobOut(
        job_id=job.id,
        event_id=event.id,
        event_type=event.event_type,
        object_ref=event.object_id,
        status=job.status,
        attempts=job.attempts,
        next_attempt_at=job.next_attempt_at,
        expires_at=job.expires_at,
        delivered_at=job.delivered_at,
        acknowledged_at=job.acknowledged_at,
        suppressed_at=job.suppressed_at,
        last_error_code=job.last_error_code,
        last_attempt_outcome=view.last_attempt_outcome,
        created_at=job.created_at,
    )


# --- Admin: routing management and redacted diagnostics ---


@admin_router.post("/targets", response_model=AgentNoticeTargetOut, status_code=201)
def create_notice_target(
    payload: AgentNoticeTargetIn,
    request: Request,
    session: Annotated[Session, Depends(get_session)],
    access: Annotated[ReadAccess, Depends(require_api_read_access)],
) -> AgentNoticeTargetOut:
    _require_admin(access)
    try:
        with transaction(session):
            target = create_agent_delivery_target(
                session,
                principal_id=payload.principal_id,
                label=payload.label,
                route=payload.route,
                transport=payload.transport,
                actor=_actor(request, access),
            )
            login = session.get(Principal, target.principal_id)
    except SubscriptionValidationError as exc:
        raise _validation_http_error(exc) from exc
    return target_out(NoticeTargetView(target, login.login if login else None))


@admin_router.get("/targets", response_model=AgentNoticeTargetListOut)
def list_notice_target_rows(
    session: Annotated[Session, Depends(get_session)],
    access: Annotated[ReadAccess, Depends(require_api_read_access)],
) -> AgentNoticeTargetListOut:
    _require_admin(access)
    items = [target_out(view) for view in list_notice_targets(session)]
    return AgentNoticeTargetListOut(count=len(items), items=items)


@admin_router.post("/subscriptions", response_model=AgentNoticeSubscriptionOut, status_code=201)
def create_notice_subscription(
    payload: AgentNoticeSubscriptionIn,
    request: Request,
    session: Annotated[Session, Depends(get_session)],
    access: Annotated[ReadAccess, Depends(require_api_read_access)],
) -> AgentNoticeSubscriptionOut:
    _require_admin(access)
    try:
        with transaction(session):
            row = create_agent_notice_subscription(
                session,
                event_type=payload.event_type,
                scope=payload.scope,
                object_id=payload.object_id,
                principal_id=payload.principal_id,
                target_id=payload.target_id,
                created_by_principal_id=access.principal.id,
                actor=_actor(request, access),
            )
    except SubscriptionValidationError as exc:
        raise _validation_http_error(exc) from exc
    return AgentNoticeSubscriptionOut.model_validate(row, from_attributes=True)


@admin_router.get("", response_model=AgentNoticeSubscriptionListOut)
def list_notice_subscription_rows(
    session: Annotated[Session, Depends(get_session)],
    access: Annotated[ReadAccess, Depends(require_api_read_access)],
) -> AgentNoticeSubscriptionListOut:
    _require_admin(access)
    items = [
        AgentNoticeSubscriptionOut.model_validate(view.subscription, from_attributes=True)
        for view in list_notice_subscriptions(session)
    ]
    return AgentNoticeSubscriptionListOut(count=len(items), items=items)


@admin_router.delete("/targets/{target_id}", status_code=204)
def deactivate_notice_target(
    target_id: str,
    request: Request,
    session: Annotated[Session, Depends(get_session)],
    access: Annotated[ReadAccess, Depends(require_api_read_access)],
) -> None:
    _require_admin(access)
    with transaction(session):
        deactivated = deactivate_agent_delivery_target(
            session,
            target_id=target_id,
            now=_utcnow(),
            actor=_actor(request, access),
        )
    if not deactivated:
        raise HTTPException(status_code=404, detail="Target not found")


@admin_router.get("/jobs", response_model=AgentNoticeDeliveryJobListOut)
def list_notice_job_rows(
    session: Annotated[Session, Depends(get_session)],
    access: Annotated[ReadAccess, Depends(require_api_read_access)],
    status: NoticeStatus | None = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
) -> AgentNoticeDeliveryJobListOut:
    """Redacted delivery diagnostics: states only, never transport details."""
    _require_admin(access)
    items = [job_out(view) for view in list_notice_jobs(session, status=status, limit=limit)]
    return AgentNoticeDeliveryJobListOut(count=len(items), items=items)


# Registered after the fixed sub-paths so "/targets" and "/jobs" win.
@admin_router.delete("/{subscription_id}", status_code=204)
def revoke_notice_subscription(
    subscription_id: str,
    request: Request,
    session: Annotated[Session, Depends(get_session)],
    access: Annotated[ReadAccess, Depends(require_api_read_access)],
) -> None:
    _require_admin(access)
    with transaction(session):
        revoked = revoke_agent_notice_subscription(
            session,
            subscription_id=subscription_id,
            now=_utcnow(),
            actor=_actor(request, access),
        )
    if not revoked:
        raise HTTPException(status_code=404, detail="Subscription not found")


# --- Agent: authorized reads of the own delivery state plus acknowledgement ---


@agent_router.get("", response_model=AgentNoticeListOut)
def list_own_notices(
    session: Annotated[Session, Depends(get_session)],
    access: Annotated[ReadAccess, Depends(require_api_read_access)],
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
    status: NoticeStatus | None = None,
) -> AgentNoticeListOut:
    notices = [
        AgentNoticeOut(
            event_id=notice.event_id,
            event_type=notice.event_type,
            schema_version=notice.schema_version,
            object_ref=notice.object_ref,
            message=notice.message,
            blockwart_reference=notice.blockwart_reference,
            status=notice.status,
            delivered_at=notice.delivered_at,
            acknowledged_at=notice.acknowledged_at,
        )
        for notice in list_own_agent_notices(
            session,
            principal_id=access.principal.id,
            limit=limit,
            status=status,
        )
    ]
    return AgentNoticeListOut(count=len(notices), notices=notices)


@agent_router.post("/{event_id}/acknowledge", response_model=AgentNoticeAcknowledgeOut)
def acknowledge_notice(
    event_id: str,
    session: Annotated[Session, Depends(get_session)],
    access: Annotated[ReadAccess, Depends(require_api_read_access)],
) -> AgentNoticeAcknowledgeOut:
    with transaction(session):
        acknowledged, error_code = acknowledge_agent_notice(
            session,
            principal_id=access.principal.id,
            event_id=event_id,
            now=_utcnow(),
        )
    if error_code == "not_found":
        raise HTTPException(status_code=404, detail="Notice not found")
    return AgentNoticeAcknowledgeOut(acknowledged=acknowledged, error_code=error_code)
