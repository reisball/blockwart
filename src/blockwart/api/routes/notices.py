from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from blockwart.api.deps import get_session
from blockwart.api.errors import API_ERROR_RESPONSES
from blockwart.api.security import require_api_read_access
from blockwart.db.session import transaction
from blockwart.domain.agent_notices import build_release_notice_message
from blockwart.domain.auth import Permission
from blockwart.models.agent_notices import (
    AgentDeliveryJob,
    AgentDeliveryTarget,
    AgentNoticeEvent,
    AgentNoticeSubscription,
)
from blockwart.models.catalog import CatalogObject
from blockwart.schemas.agent_notices import (
    AgentNoticeAcknowledgeOut,
    AgentNoticeDeliveryJobListOut,
    AgentNoticeDeliveryJobOut,
    AgentNoticeListOut,
    AgentNoticeOut,
    AgentNoticeSubscriptionIn,
    AgentNoticeSubscriptionListOut,
    AgentNoticeSubscriptionOut,
)
from blockwart.services.agent_notices import (
    SubscriptionValidationError,
    acknowledge_agent_notice,
    create_agent_delivery_target,
    create_agent_notice_subscription,
    deactivate_agent_delivery_target,
    revoke_agent_notice_subscription,
)
from blockwart.services.principal_management import require_platform_admin
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


@admin_router.post("/targets", response_model=dict, status_code=201)
def create_notice_target(
    payload: dict,
    session: Annotated[Session, Depends(get_session)],
    access: Annotated[ReadAccess, Depends(require_api_read_access)],
) -> dict:
    require_platform_admin(access)
    try:
        with transaction(session):
            target = create_agent_delivery_target(
                session,
                principal_id=str(payload.get("principal_id", "")),
                label=str(payload.get("label", ""))[:128],
                transport=str(payload.get("transport", "")),
            )
    except SubscriptionValidationError as exc:
        raise HTTPException(status_code=422, detail=exc.code) from exc
    return {
        "id": target.id,
        "principal_id": target.principal_id,
        "label": target.label,
        "transport": target.transport,
        "active": target.active,
    }


@admin_router.post("/subscriptions", response_model=AgentNoticeSubscriptionOut, status_code=201)
def create_notice_subscription(
    payload: AgentNoticeSubscriptionIn,
    session: Annotated[Session, Depends(get_session)],
    access: Annotated[ReadAccess, Depends(require_api_read_access)],
) -> AgentNoticeSubscriptionOut:
    require_platform_admin(access)
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
            )
    except SubscriptionValidationError as exc:
        raise HTTPException(status_code=422, detail=exc.code) from exc
    return AgentNoticeSubscriptionOut.model_validate(row, from_attributes=True)


@admin_router.get("", response_model=AgentNoticeSubscriptionListOut)
def list_notice_subscriptions(
    session: Annotated[Session, Depends(get_session)],
    access: Annotated[ReadAccess, Depends(require_api_read_access)],
) -> AgentNoticeSubscriptionListOut:
    require_platform_admin(access)
    subscriptions = (
        session.query(AgentNoticeSubscription)
        .order_by(AgentNoticeSubscription.created_at)
        .all()
    )
    items = [
        AgentNoticeSubscriptionOut.model_validate(row, from_attributes=True)
        for row in subscriptions
    ]
    return AgentNoticeSubscriptionListOut(count=len(items), items=items)


@admin_router.delete("/{subscription_id}", status_code=204)
def revoke_notice_subscription(
    subscription_id: str,
    session: Annotated[Session, Depends(get_session)],
    access: Annotated[ReadAccess, Depends(require_api_read_access)],
) -> None:
    require_platform_admin(access)
    with transaction(session):
        revoked = revoke_agent_notice_subscription(
            session,
            subscription_id=subscription_id,
            now=_utcnow(),
        )
    if not revoked:
        raise HTTPException(status_code=404, detail="Subscription not found")


@admin_router.delete("/targets/{target_id}", status_code=204)
def deactivate_notice_target(
    target_id: str,
    session: Annotated[Session, Depends(get_session)],
    access: Annotated[ReadAccess, Depends(require_api_read_access)],
) -> None:
    require_platform_admin(access)
    with transaction(session):
        deactivated = deactivate_agent_delivery_target(
            session,
            target_id=target_id,
            now=_utcnow(),
        )
    if not deactivated:
        raise HTTPException(status_code=404, detail="Target not found")


@admin_router.get("/jobs", response_model=AgentNoticeDeliveryJobListOut)
def list_notice_jobs(
    session: Annotated[Session, Depends(get_session)],
    access: Annotated[ReadAccess, Depends(require_api_read_access)],
    status: str | None = Query(default=None, max_length=16),
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
) -> AgentNoticeDeliveryJobListOut:
    """Redacted delivery diagnostics: states only, never transport details."""
    require_platform_admin(access)
    query = (
        session.query(AgentDeliveryJob, AgentNoticeEvent)
        .join(AgentNoticeEvent, AgentNoticeEvent.id == AgentDeliveryJob.event_id)
        .order_by(AgentDeliveryJob.created_at, AgentDeliveryJob.id)
    )
    if status is not None:
        query = query.filter(AgentDeliveryJob.status == status)
    items = [
        AgentNoticeDeliveryJobOut(
            job_id=job.id,
            event_id=event.id,
            event_type=event.event_type,
            object_ref=f"{event.object_id}",
            status=job.status,
            attempts=job.attempts,
            next_attempt_at=job.next_attempt_at,
            expires_at=job.expires_at,
            delivered_at=job.delivered_at,
            acknowledged_at=job.acknowledged_at,
            suppressed_at=job.suppressed_at,
            last_error_code=job.last_error_code,
            created_at=job.created_at,
        )
        for job, event in query.limit(limit).all()
    ]
    return AgentNoticeDeliveryJobListOut(count=len(items), items=items)


# --- Agent: authorized reads of the own delivery state plus acknowledgement ---


def _visible_notices(
    session: Session,
    access: ReadAccess,
    *,
    limit: int,
) -> list[AgentNoticeOut]:
    rows = (
        session.query(AgentDeliveryJob, AgentNoticeEvent, AgentDeliveryTarget)
        .join(AgentNoticeEvent, AgentNoticeEvent.id == AgentDeliveryJob.event_id)
        .join(AgentDeliveryTarget, AgentDeliveryTarget.id == AgentDeliveryJob.target_id)
        .filter(AgentDeliveryTarget.principal_id == access.principal.id)
        .order_by(AgentDeliveryJob.created_at.desc(), AgentDeliveryJob.id.desc())
        .limit(limit)
        .all()
    )
    policy_snapshot = access.policy
    notices: list[AgentNoticeOut] = []
    for job, event, _target in rows:
        # Fail closed on reads too: without current read permission the notice
        # disappears entirely instead of degrading into an existence hint.
        if Permission.READ not in policy_snapshot.permissions_for(event.object_id):
            continue
        object_label = ""
        live_object = session.get(CatalogObject, event.object_id)
        if live_object is not None:
            object_label = live_object.label
        notices.append(
            AgentNoticeOut(
                event_id=event.id,
                event_type=event.event_type,
                schema_version=event.payload_version,
                object_ref=(
                    "service:" + event.object_id
                    if live_object is None
                    else f"{live_object.kind}:{live_object.id}"
                ),
                message=_notice_message(event, object_label),
                blockwart_reference=f"/api/v1/agent/objects/{event.object_id}",
                status=job.status,
                delivered_at=job.delivered_at,
            )
        )
    return notices


def _notice_message(event: AgentNoticeEvent, object_label: str) -> str:
    return build_release_notice_message(object_label or event.object_id, event.latest_tag)


@agent_router.get("", response_model=AgentNoticeListOut)
def list_own_notices(
    session: Annotated[Session, Depends(get_session)],
    access: Annotated[ReadAccess, Depends(require_api_read_access)],
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
) -> AgentNoticeListOut:
    notices = _visible_notices(session, access, limit=limit)
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
