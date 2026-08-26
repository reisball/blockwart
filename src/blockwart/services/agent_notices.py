"""Durable agent notice events, subscriptions, and delivery (Issue #106).

Safety properties implemented here:

- exactly one logical delivery job per ``(event, target)`` pair;
- authorization (principal active, service-account type, token activity,
  object read permission, subscription/target state) is re-checked directly
  before every delivery attempt and fails closed: a suppressed delivery
  leaves neither payload nor existence hint behind;
- bounded retries with exponential backoff, TTL expiry, and dead-lettering;
- at-most-once visible semantics per agent and logical event: only rows in
  ``pending`` are retried; delivered rows never re-ping; and
- redacted audit: attempts store coarse outcomes only.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from blockwart.domain.agent_notices import (
    AGENT_NOTICE_TRANSPORTS,
    NOTICE_EVENT_TYPES,
    NOTICE_SCOPE_VALUES,
    build_notice_payload,
)
from blockwart.domain.auth import Permission
from blockwart.models.agent_notices import (
    AgentDeliveryAttempt,
    AgentDeliveryJob,
    AgentDeliveryTarget,
    AgentNoticeEvent,
    AgentNoticeSubscription,
)
from blockwart.models.auth import Principal, ServiceToken
from blockwart.models.catalog import CatalogObject
from blockwart.services.notice_transport import DeliveryRequest, NoticeTransport
from blockwart.services.policy import policy_for_principal


class NoticeDeliveryPolicy:
    """Bounded retry/TTL/storm parameters. All values are server-selected."""

    def __init__(
        self,
        *,
        max_attempts: int = 5,
        ttl_seconds: int = 86400,
        backoff_base_seconds: int = 30,
        backoff_max_seconds: int = 3600,
        max_pending_jobs_per_target: int = 20,
        max_deliveries_per_run: int = 50,
    ) -> None:
        if max_attempts < 1:
            raise ValueError("max_attempts must be positive")
        self.max_attempts = max_attempts
        self.ttl_seconds = ttl_seconds
        self.backoff_base_seconds = backoff_base_seconds
        self.backoff_max_seconds = backoff_max_seconds
        self.max_pending_jobs_per_target = max_pending_jobs_per_target
        self.max_deliveries_per_run = max_deliveries_per_run

    def next_backoff_seconds(self, attempts_after_failure: int) -> int:
        shift = min(attempts_after_failure - 1, 16)
        delay = self.backoff_base_seconds * (2**shift)
        return min(delay, self.backoff_max_seconds)


@dataclass(frozen=True, slots=True)
class NoticeEventResult:
    event: AgentNoticeEvent
    created: bool


def _naive_utc(moment: datetime) -> datetime:
    if moment.tzinfo is None:
        return moment
    return moment.astimezone(UTC).replace(tzinfo=None)


def record_agent_notice_event(
    session: Session,
    *,
    event_type: str,
    object_id: str,
    dedupe_key: str,
    latest_tag: str | None = None,
    latest_version: str | None = None,
    occurred_at: datetime,
    policy: NoticeDeliveryPolicy | None = None,
) -> NoticeEventResult:
    """Insert one logical event; repeated emission is a no-op (deduplicated)."""
    if event_type not in NOTICE_EVENT_TYPES:
        raise ValueError(f"unsupported notice event type: {event_type}")
    existing = session.scalar(
        select(AgentNoticeEvent).where(
            AgentNoticeEvent.event_type == event_type,
            AgentNoticeEvent.object_id == object_id,
            AgentNoticeEvent.dedupe_key == dedupe_key,
        )
    )
    moment = _naive_utc(occurred_at)
    if existing is not None:
        return NoticeEventResult(event=existing, created=False)
    event_row = AgentNoticeEvent(
        id=str(uuid.uuid4()),
        event_type=event_type,
        object_id=object_id,
        dedupe_key=dedupe_key,
        latest_tag=latest_tag,
        latest_version=latest_version,
        occurred_at=moment,
    )
    # The unique identity is the concurrency guard: two processes emitting
    # the same logical event race, exactly one insert survives, and the
    # loser falls back to the winner's row inside a savepoint.
    try:
        with session.begin_nested():
            session.add(event_row)
            session.flush()
    except IntegrityError:
        existing = session.scalar(
            select(AgentNoticeEvent).where(
                AgentNoticeEvent.event_type == event_type,
                AgentNoticeEvent.object_id == object_id,
                AgentNoticeEvent.dedupe_key == dedupe_key,
            )
        )
        if existing is None:
            raise
        return NoticeEventResult(event=existing, created=False)
    fanout_agent_notice_jobs(
        session,
        event=event_row,
        now=moment,
        policy=policy or NoticeDeliveryPolicy(),
    )
    return NoticeEventResult(event=event_row, created=True)


def record_release_notice_event(
    session: Session,
    *,
    object_id: str,
    object_instance_id: str,
    provider: str,
    latest_tag: str | None,
    latest_version: str | None,
    observed_at: datetime,
    policy: NoticeDeliveryPolicy | None = None,
) -> NoticeEventResult | None:
    """Emit the first supported event from a fresh release observation."""
    if latest_version is None and latest_tag is None:
        return None
    dedupe_key = f"{object_instance_id}:{provider}:{latest_version or latest_tag}"
    return record_agent_notice_event(
        session,
        event_type="release_update_available",
        object_id=object_id,
        dedupe_key=dedupe_key[:191],
        latest_tag=latest_tag,
        latest_version=latest_version,
        occurred_at=observed_at,
        policy=policy,
    )


def fanout_agent_notice_jobs(
    session: Session,
    *,
    event: AgentNoticeEvent,
    now: datetime,
    policy: NoticeDeliveryPolicy,
) -> list[AgentDeliveryJob]:
    """Create exactly one pending job per matching subscription target."""
    moment = _naive_utc(now)
    subscriptions = list(
        session.scalars(
            select(AgentNoticeSubscription).where(
                AgentNoticeSubscription.active.is_(True),
                AgentNoticeSubscription.revoked_at.is_(None),
                AgentNoticeSubscription.event_type == event.event_type,
            )
        )
    )
    created: list[AgentDeliveryJob] = []
    for subscription in subscriptions:
        if subscription.scope not in NOTICE_SCOPE_VALUES:
            continue
        if subscription.scope == "object" and subscription.object_id != event.object_id:
            continue
        target = session.get(AgentDeliveryTarget, subscription.target_id)
        if target is None or not target.active:
            # No job, no hint: an inactive target simply does not exist for
            # routing purposes.
            continue
        pending_count = len(
            list(
                session.scalars(
                    select(AgentDeliveryJob.id).where(
                        AgentDeliveryJob.target_id == target.id,
                        AgentDeliveryJob.status == "pending",
                    )
                )
            )
        )
        storm_suppressed = pending_count >= policy.max_pending_jobs_per_target
        job = AgentDeliveryJob(
            event_id=event.id,
            target_id=target.id,
            subscription_id=subscription.id,
            status="suppressed" if storm_suppressed else "pending",
            attempts=0,
            next_attempt_at=moment,
            expires_at=moment + timedelta(seconds=policy.ttl_seconds),
            suppressed_at=moment if storm_suppressed else None,
            last_error_code="storm_suppressed" if storm_suppressed else None,
        )
        session.add(job)
        created.append(job)
    session.flush()
    return created


def revoke_agent_notice_subscription(
    session: Session,
    *,
    subscription_id: str,
    now: datetime,
) -> bool:
    """Revoke one subscription. Later deliveries re-check this fail-closed."""
    moment = _naive_utc(now)
    row = session.get(AgentNoticeSubscription, subscription_id)
    if row is None:
        return False
    row.active = False
    row.revoked_at = moment
    session.flush()
    return True


@dataclass(frozen=True, slots=True)
class AuthorizationState:
    allowed: bool
    error_code: str | None = None


def check_delivery_authorization(
    session: Session,
    job: AgentDeliveryJob,
    *,
    now: datetime,
) -> AuthorizationState:
    """Re-check every authorization input immediately before delivery.

    Any missing input fails closed with a safe code. The caller must treat a
    denial as if the event did not exist: no payload is built, no transport is
    touched, no existence hint is recorded outside Blockwart's own audit.
    """
    moment = _naive_utc(now)
    target = session.get(AgentDeliveryTarget, job.target_id)
    if target is None or not target.active:
        return AuthorizationState(False, "target_inactive")
    principal = session.get(Principal, target.principal_id)
    if (
        principal is None
        or not principal.active
        or principal.principal_type != "service_account"
    ):
        return AuthorizationState(False, "principal_inactive")
    active_token = session.scalar(
        select(ServiceToken.id).where(
            ServiceToken.principal_id == principal.id,
            ServiceToken.revoked_at.is_(None),
            (ServiceToken.expires_at.is_(None))
            | (ServiceToken.expires_at > moment),
        ).limit(1)
    )
    if active_token is None:
        return AuthorizationState(False, "principal_inactive")
    subscription = session.get(AgentNoticeSubscription, job.subscription_id)
    if subscription is None or not subscription.active or subscription.revoked_at is not None:
        return AuthorizationState(False, "subscription_revoked")
    live_object = session.get(CatalogObject, event_object_id(session, job))
    if live_object is None:
        return AuthorizationState(False, "read_permission_lost")
    policy_snapshot = policy_for_principal(session, principal.id)
    permissions = policy_snapshot.permissions_for(live_object.id)
    if Permission.READ not in permissions:
        return AuthorizationState(False, "read_permission_lost")
    return AuthorizationState(True)


def event_object_id(session: Session, job: AgentDeliveryJob) -> str:
    event_row = session.get(AgentNoticeEvent, job.event_id)
    if event_row is None:  # pragma: no cover - FK guarantees existence
        raise ValueError("delivery job without event")
    return event_row.object_id


def _build_job_payload(session: Session, job: AgentDeliveryJob) -> dict | None:
    event_row = session.get(AgentNoticeEvent, job.event_id)
    live_object = session.get(CatalogObject, event_row.object_id)
    if event_row is None or live_object is None:
        return None
    return build_notice_payload(
        event_id=event_row.id,
        object_ref=f"{live_object.kind}:{live_object.id}",
        object_label=live_object.label,
        latest_tag=event_row.latest_tag,
        back_reference_path=f"/api/v1/agent/objects/{live_object.id}",
    )


def deliver_due_agent_notices(
    session: Session,
    transport: NoticeTransport,
    *,
    now: datetime,
    policy: NoticeDeliveryPolicy | None = None,
) -> dict[str, int]:
    """Run one bounded delivery pass over due pending jobs."""
    active_policy = policy or NoticeDeliveryPolicy()
    moment = _naive_utc(now)
    stats = {"delivered": 0, "failed": 0, "suppressed": 0, "expired": 0, "retried": 0}
    due_jobs = list(
        session.scalars(
            select(AgentDeliveryJob)
            .where(
                AgentDeliveryJob.status == "pending",
                AgentDeliveryJob.next_attempt_at <= moment,
            )
            .order_by(AgentDeliveryJob.next_attempt_at, AgentDeliveryJob.id)
            .limit(active_policy.max_deliveries_per_run)
        )
    )
    for job in due_jobs:
        if job.expires_at <= moment:
            job.status = "expired"
            job.last_error_code = "ttl_expired"
            stats["expired"] += 1
            continue
        authorization = check_delivery_authorization(session, job, now=moment)
        if not authorization.allowed:
            job.status = "suppressed"
            job.suppressed_at = moment
            job.last_error_code = authorization.error_code
            stats["suppressed"] += 1
            continue
        payload = _build_job_payload(session, job)
        if payload is None:
            job.status = "suppressed"
            job.suppressed_at = moment
            job.last_error_code = "read_permission_lost"
            stats["suppressed"] += 1
            continue
        outcome = transport.deliver(DeliveryRequest(target_id=job.target_id, payload=payload))
        attempt_no = job.attempts + 1
        job.attempts = attempt_no
        # Audit keeps its own coarse vocabulary, separate from job error codes.
        attempt_outcome = (
            "success"
            if outcome.ok
            else {
                "transport_timeout": "timeout",
                "rate_limited": "rate_limited",
            }.get(outcome.error_code or "", "unavailable")
        )
        session.add(
            AgentDeliveryAttempt(
                job_id=job.id,
                attempt_no=attempt_no,
                outcome=attempt_outcome,
                error_code=None if outcome.ok else outcome.error_code,
                attempted_at=moment,
            )
        )
        if outcome.ok:
            job.status = "delivered"
            job.delivered_at = moment
            job.last_error_code = None
            stats["delivered"] += 1
            continue
        job.last_error_code = outcome.error_code
        retry_due = moment + timedelta(
            seconds=active_policy.next_backoff_seconds(attempt_no)
        )
        if attempt_no >= active_policy.max_attempts or retry_due > job.expires_at:
            job.status = "failed"
            job.last_error_code = job.last_error_code or "attempt_limit_reached"
            stats["failed"] += 1
        else:
            job.next_attempt_at = retry_due
            stats["retried"] += 1
    session.flush()
    return stats


def acknowledge_agent_notice(
    session: Session,
    *,
    principal_id: str,
    event_id: str,
    now: datetime,
) -> tuple[bool, str | None]:
    """Acknowledge receipt of one delivered notice.

    Acknowledgement only records receipt; it never asserts any business
    action, grant change, or approval. Only the principal that owns the
    delivered target may acknowledge it.
    """
    moment = _naive_utc(now)
    job = session.scalar(
        select(AgentDeliveryJob)
        .join(AgentDeliveryTarget, AgentDeliveryTarget.id == AgentDeliveryJob.target_id)
        .where(
            AgentDeliveryJob.event_id == event_id,
            AgentDeliveryTarget.principal_id == principal_id,
        )
    )
    if job is None:
        return False, "not_found"
    if job.status != "delivered":
        return False, f"not_acknowledgeable_status_{job.status}"
    job.status = "acknowledged"
    job.acknowledged_at = moment
    session.flush()
    return True, None


class SubscriptionValidationError(ValueError):
    """Stable rejection reason for an invalid routing assignment."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def create_agent_notice_subscription(
    session: Session,
    *,
    event_type: str,
    scope: str,
    object_id: str | None,
    principal_id: str,
    target_id: str,
    created_by_principal_id: str | None = None,
) -> AgentNoticeSubscription:
    """Explicitly route one event scope to one approved agent target.

    Both ends of the mapping are validated: the principal must be an active
    service account, and the target must be active and owned by exactly that
    principal. Display-name similarity never couples identities.
    """
    if event_type not in NOTICE_EVENT_TYPES:
        raise SubscriptionValidationError("unknown_event_type")
    if scope not in NOTICE_SCOPE_VALUES:
        raise SubscriptionValidationError("unknown_scope")
    if scope == "object" and not object_id:
        raise SubscriptionValidationError("object_scope_requires_object")
    if scope == "catalog" and object_id is not None:
        raise SubscriptionValidationError("catalog_scope_rejects_object")
    session.flush()
    principal = session.get(Principal, principal_id)
    if (
        principal is None
        or not principal.active
        or principal.principal_type != "service_account"
    ):
        raise SubscriptionValidationError("principal_not_service_account")
    target = session.get(AgentDeliveryTarget, target_id)
    if target is None or not target.active:
        raise SubscriptionValidationError("target_inactive_or_unknown")
    if target.principal_id != principal.id:
        raise SubscriptionValidationError("target_not_owned_by_principal")
    row = AgentNoticeSubscription(
        id=str(uuid.uuid4()),
        event_type=event_type,
        scope=scope,
        object_id=object_id,
        principal_id=principal.id,
        target_id=target.id,
        created_by_principal_id=created_by_principal_id,
    )
    session.add(row)
    session.flush()
    return row


def create_agent_delivery_target(
    session: Session,
    *,
    principal_id: str,
    label: str,
    transport: str,
) -> AgentDeliveryTarget:
    """Approve one addressable agent destination for a service account."""
    if transport not in AGENT_NOTICE_TRANSPORTS:
        raise SubscriptionValidationError("unknown_transport")
    # Callers may run with autoflush disabled; make pending rows visible.
    session.flush()
    principal = session.get(Principal, principal_id)
    if (
        principal is None
        or not principal.active
        or principal.principal_type != "service_account"
    ):
        raise SubscriptionValidationError("principal_not_service_account")
    row = AgentDeliveryTarget(
        id=str(uuid.uuid4()),
        principal_id=principal.id,
        label=label[:128],
        transport=transport,
    )
    session.add(row)
    session.flush()
    return row


def deactivate_agent_delivery_target(
    session: Session,
    *,
    target_id: str,
    now: datetime,
) -> bool:
    """Revoke a target. Pending deliveries fail closed on their next check."""
    row = session.get(AgentDeliveryTarget, target_id)
    if row is None:
        return False
    row.active = False
    session.flush()
    return True
