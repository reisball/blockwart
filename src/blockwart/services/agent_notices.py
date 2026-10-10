"""Durable agent notice events, subscriptions, and delivery (Issue #106).

Safety properties implemented here:

- exactly one logical delivery job per ``(event, target)`` pair;
- authorization (principal active, service-account type, token activity,
  object read permission, subscription/target state) is re-checked directly
  before every delivery attempt and fails closed: no payload is sent on
  denial; own-notice diagnostics still require current object read permission;
- bounded retries with exponential backoff, TTL expiry, and dead-lettering;
- a durable, fenced lease is committed *before* any network I/O and no
  database transaction is open while a transport runs;
- idempotent end-to-end replay: only ``pending`` rows are sent, every send of a
  job carries the same ``delivery_id``, and a receiver's duplicate
  confirmation after a lost response is recorded as the prior success; and
- redacted audit: attempts store coarse outcomes only.

Delivery is at-least-once on the wire and idempotent at the receiver. This
module does not (and cannot) promise exactly-once visibility to an agent whose
gateway ignores ``delivery_id``.
"""

from __future__ import annotations

import asyncio
import logging
import re
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import func, or_, select, update
from sqlalchemy.exc import DBAPIError, IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from blockwart.config import Settings
from blockwart.db.session import build_engine
from blockwart.domain.agent_notices import (
    AGENT_NOTICE_TRANSPORTS,
    DELIVERY_STATUS_VALUES,
    NOTICE_EVENT_TYPES,
    NOTICE_SCOPE_VALUES,
    build_notice_payload,
    build_release_notice_message,
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
from blockwart.services.identity import record_security_event
from blockwart.services.notice_transport import (
    DeliveryOutcome,
    DeliveryRequest,
    NoticeTransport,
)
from blockwart.services.policy import policy_for_principal

logger = logging.getLogger(__name__)


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
        lease_seconds: int = 60,
    ) -> None:
        if max_attempts < 1:
            raise ValueError("max_attempts must be positive")
        if lease_seconds < 5:
            raise ValueError("lease_seconds must cover at least one delivery attempt")
        if backoff_base_seconds < 1 or backoff_max_seconds < backoff_base_seconds:
            raise ValueError("backoff must be positive and bounded")
        if ttl_seconds < 1 or max_deliveries_per_run < 1:
            raise ValueError("ttl and per-run bound must be positive")
        self.lease_seconds = lease_seconds
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
    seen_targets: set[str] = set()
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
        if target.id in seen_targets:
            # Two matching subscriptions for the same target must produce one
            # job: the unique (event_id, target_id) identity would otherwise
            # fail the fan-out with an IntegrityError.
            continue
        seen_targets.add(target.id)
        pending_count = session.scalar(
            select(func.count(AgentDeliveryJob.id)).where(
                AgentDeliveryJob.target_id == target.id,
                AgentDeliveryJob.status == "pending",
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


@dataclass(frozen=True, slots=True)
class AuditActor:
    """Who performed an administrative notice change, for redacted audit."""

    principal_id: str
    channel: str = "api"
    request_id: str | None = None


def _audit_management(
    session: Session,
    actor: AuditActor | None,
    event_type: str,
    details: dict[str, object],
) -> None:
    if actor is None:
        return
    record_security_event(
        session,
        event_type=event_type,
        outcome="success",
        channel=actor.channel,
        principal_id=actor.principal_id,
        request_id=actor.request_id,
        details=details,
    )


def revoke_agent_notice_subscription(
    session: Session,
    *,
    subscription_id: str,
    now: datetime,
    actor: AuditActor | None = None,
) -> bool:
    """Revoke one subscription. Later deliveries re-check this fail-closed."""
    moment = _naive_utc(now)
    row = session.get(AgentNoticeSubscription, subscription_id)
    if row is None:
        return False
    if row.active:
        row.active = False
        row.revoked_at = moment
        session.flush()
        _audit_management(
            session,
            actor,
            "agent_notice_subscription_revoked",
            {"subscription_id": row.id, "target_id": row.target_id},
        )
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
    if principal is None or not principal.active or principal.principal_type != "service_account":
        return AuthorizationState(False, "principal_inactive")
    active_token = session.scalar(
        select(ServiceToken.id)
        .where(
            ServiceToken.principal_id == principal.id,
            ServiceToken.revoked_at.is_(None),
            (ServiceToken.expires_at.is_(None)) | (ServiceToken.expires_at > moment),
        )
        .limit(1)
    )
    if active_token is None:
        return AuthorizationState(False, "principal_inactive")
    event_row = session.get(AgentNoticeEvent, job.event_id)
    subscription = session.get(AgentNoticeSubscription, job.subscription_id)
    if (
        subscription is None
        or not subscription.active
        or subscription.revoked_at is not None
        or subscription.target_id != target.id
        or event_row is None
        or subscription.event_type != event_row.event_type
        or (subscription.scope == "object" and subscription.object_id != event_row.object_id)
    ):
        return AuthorizationState(False, "subscription_revoked")
    live_object = session.get(CatalogObject, event_row.object_id)
    if live_object is None:
        return AuthorizationState(False, "read_permission_lost")
    policy_snapshot = policy_for_principal(session, principal.id)
    permissions = policy_snapshot.permissions_for(live_object.id)
    if Permission.READ not in permissions:
        return AuthorizationState(False, "read_permission_lost")
    return AuthorizationState(True)


def _build_job_payload(session: Session, job: AgentDeliveryJob) -> dict | None:
    event_row = session.get(AgentNoticeEvent, job.event_id)
    if event_row is None:
        return None
    live_object = session.get(CatalogObject, event_row.object_id)
    if live_object is None:
        return None
    return build_notice_payload(
        event_id=event_row.id,
        object_ref=f"{live_object.kind}:{live_object.id}",
        object_label=live_object.label,
        latest_tag=event_row.latest_tag,
        back_reference_path=f"/api/v1/agent/objects/{live_object.id}",
    )


def delivery_id_for_job(job: AgentDeliveryJob) -> str:
    """Globally unique logical identity, stable across retries and restored jobs.

    Event and target UUIDs survive replay; integer primary keys are DB-local.
    New events/targets after a restore or in another DB receive fresh UUIDs.
    """
    return f"agent-notice-job-{job.event_id}-{job.target_id}"


@dataclass(frozen=True, slots=True)
class _Claim:
    """A durable lease on one job; ``token`` fences every later write."""

    job_id: int
    token: str
    attempt_no: int
    target_id: str
    expires_at: datetime
    lease_expires_at: datetime


def deliver_due_agent_notices(
    session: Session,
    transport: NoticeTransport,
    *,
    now: datetime,
    policy: NoticeDeliveryPolicy | None = None,
    worker_id: str = "inline",
    clock: Callable[[], datetime] | None = None,
) -> dict[str, int]:
    """Run one bounded delivery pass, one job at a time.

    This function owns its transactions and first commits any unit of work the
    caller left open. Per job the sequence is

    1. *claim*: a conditional UPDATE takes a fenced lease (and consumes one
       attempt of the budget) and is **committed** before anything else;
    2. *recheck*: in a fresh read, TTL, attempt budget, and the full
       authorization (target, principal, token activity, subscription, current
       object ``read`` permission) are verified and the payload is built; a
       denial suppresses the job and nothing leaves Blockwart;
    3. *send*: the transport runs with **no database transaction open**, so no
       SQLite or PostgreSQL write lock is held across network I/O; and
    4. *record*: the outcome is written by an UPDATE conditional on the lease
       token. A worker whose lease expired and was reclaimed cannot change the
       job; a crashed worker's lease expires and the job is claimable again.

    Each send carries the stable ``delivery_id``. When a response is lost, the
    retry reaches a receiver that already accepted the key and answers with a
    duplicate confirmation, recorded as the prior success. A claim consumes an
    attempt up front so a crash loop is bounded by ``max_attempts`` too.

    ``clock`` supplies real time between phases; without it the fixed ``now``
    is used throughout (deterministic tests).
    """
    active_policy = policy or NoticeDeliveryPolicy()
    if transport.timeout_seconds >= active_policy.lease_seconds:
        raise ValueError("lease_seconds must exceed the transport timeout")
    moment_of = clock or (lambda: now)
    session.commit()
    stats = {
        "delivered": 0,
        "duplicate_confirmed": 0,
        "failed": 0,
        "suppressed": 0,
        "expired": 0,
        "retried": 0,
        "lease_lost": 0,
    }
    processed: set[int] = set()
    for _ in range(active_policy.max_deliveries_per_run):
        claim = _claim_next_job(
            session,
            worker_id=worker_id,
            policy=active_policy,
            moment=_naive_utc(moment_of()),
            skip_ids=processed,
        )
        if claim is None:
            break
        processed.add(claim.job_id)
        _process_claim(session, transport, claim, active_policy, moment_of, stats)
    return stats


def _process_claim(
    session: Session,
    transport: NoticeTransport,
    claim: _Claim,
    policy: NoticeDeliveryPolicy,
    moment_of: Callable[[], datetime],
    stats: dict[str, int],
) -> None:
    try:
        decision = _prepare_attempt(session, claim, policy, _naive_utc(moment_of()))
    except DBAPIError:
        # No send on an uncertain read. Consume the claim budget and retry
        # under the same fenced outcome transaction as a transport failure.
        session.rollback()
        logger.error("notice_delivery_error code=prepare_retry job=%s", claim.job_id)
        _record_outcome(
            session,
            claim,
            DeliveryOutcome(False, "delivery_error"),
            policy,
            _naive_utc(moment_of()),
            stats,
        )
        return
    except Exception:  # noqa: BLE001 - fail closed with a stable code
        session.rollback()
        logger.error("notice_delivery_error code=prepare_failed job=%s", claim.job_id)
        decision = ("failed", "delivery_error")
    if isinstance(decision, DeliveryRequest):
        # End the read transaction: nothing is held open across the transport.
        session.rollback()
        if _naive_utc(moment_of()) >= claim.lease_expires_at:
            stats["lease_lost"] += 1
            return
        try:
            outcome = transport.deliver(decision)
        except Exception:  # noqa: BLE001 - transport boundary stays coarse
            outcome = DeliveryOutcome(ok=False, error_code="transport_unavailable")
        _record_outcome(session, claim, outcome, policy, _naive_utc(moment_of()), stats)
        return
    status, code = decision
    moment = _naive_utc(moment_of())
    values: dict[str, object] = {"status": status, "last_error_code": code}
    if status == "suppressed":
        values["suppressed_at"] = moment
    if _finish_claim(session, claim, uncount_attempt=True, fence_at=moment, **values):
        stats[status] += 1
    else:
        stats["lease_lost"] += 1


def _prepare_attempt(
    session: Session,
    claim: _Claim,
    policy: NoticeDeliveryPolicy,
    moment: datetime,
) -> DeliveryRequest | tuple[str, str]:
    """Decide, from current state only, whether this claim may send."""
    # Drop anything cached by earlier phases or jobs: every attempt judges the
    # principal, grants, and object as they are now.
    session.expire_all()
    if claim.expires_at <= moment:
        return ("expired", "ttl_expired")
    if claim.attempt_no > policy.max_attempts:
        # A crashed worker consumed the last attempt; never exceed the budget.
        return ("failed", "attempt_limit_reached")
    job = session.get(AgentDeliveryJob, claim.job_id)
    if job is None or job.lease_token != claim.token:
        return ("failed", "delivery_error")
    authorization = check_delivery_authorization(session, job, now=moment)
    if not authorization.allowed:
        return ("suppressed", authorization.error_code or "read_permission_lost")
    target = session.get(AgentDeliveryTarget, job.target_id)
    payload = _build_job_payload(session, job)
    if target is None or payload is None:
        return ("suppressed", "read_permission_lost")
    return DeliveryRequest(
        target_id=job.target_id,
        target_route=target.route,
        delivery_id=delivery_id_for_job(job),
        payload=payload,
    )


def _record_outcome(
    session: Session,
    claim: _Claim,
    outcome: DeliveryOutcome,
    policy: NoticeDeliveryPolicy,
    moment: datetime,
    stats: dict[str, int],
) -> None:
    if outcome.ok:
        attempt_outcome = "confirmed_duplicate" if outcome.duplicate else "success"
        error_code = None
        values: dict[str, object] = {
            "status": "delivered",
            "delivered_at": moment,
            "last_error_code": None,
        }
        stat = "delivered"
    else:
        error_code = outcome.error_code or "transport_unavailable"
        attempt_outcome = {
            "transport_timeout": "timeout",
            "rate_limited": "rate_limited",
        }.get(error_code, "unavailable")
        retry_due = moment + timedelta(seconds=policy.next_backoff_seconds(claim.attempt_no))
        if claim.attempt_no >= policy.max_attempts or retry_due > claim.expires_at:
            values = {"status": "failed", "last_error_code": error_code}
            stat = "failed"
        else:
            values = {"last_error_code": error_code, "next_attempt_at": retry_due}
            stat = "retried"
    if not _finish_claim(
        session, claim, uncount_attempt=False, commit=False, fence_at=moment, **values
    ):
        # The lease was lost to a reclaiming worker: its result is the record.
        session.rollback()
        stats["lease_lost"] += 1
        return
    session.add(
        AgentDeliveryAttempt(
            job_id=claim.job_id,
            attempt_no=claim.attempt_no,
            outcome=attempt_outcome,
            error_code=error_code,
            attempted_at=moment,
        )
    )
    session.commit()
    stats[stat] += 1
    if outcome.ok and outcome.duplicate:
        stats["duplicate_confirmed"] += 1


def _finish_claim(
    session: Session,
    claim: _Claim,
    *,
    uncount_attempt: bool,
    commit: bool = True,
    fence_at: datetime,
    **values: object,
) -> bool:
    """Write a result conditional on the fencing token and release the lease.

    Returns False (and changes nothing) when the lease is no longer held.
    ``uncount_attempt`` hands back the attempt a claim consumed when the job
    ended before any transport call.
    """
    assignments: dict[str, object] = {
        **values,
        "claimed_by": None,
        "claimed_at": None,
        "lease_token": None,
        "lease_expires_at": None,
    }
    if uncount_attempt:
        assignments["attempts"] = AgentDeliveryJob.attempts - 1
    result = session.execute(
        update(AgentDeliveryJob)
        .where(
            AgentDeliveryJob.id == claim.job_id,
            AgentDeliveryJob.lease_token == claim.token,
            AgentDeliveryJob.lease_expires_at > fence_at,
            AgentDeliveryJob.status == "pending",
        )
        .values(**assignments)
        .execution_options(synchronize_session=False)
    )
    won = result.rowcount == 1
    if commit:
        session.commit()
    return won


def _claim_next_job(
    session: Session,
    *,
    worker_id: str,
    policy: NoticeDeliveryPolicy,
    moment: datetime,
    skip_ids: set[int],
) -> _Claim | None:
    """Take a fenced lease on the next due job and commit it (SQLite + PostgreSQL).

    The conditional UPDATE is the concurrency guard. It compares against the
    lease state it observed, so two workers racing for one row cannot both win
    (SQLite serializes writers; PostgreSQL row-locks and re-evaluates the
    predicate). The statement touches one row and commits immediately, so no
    write lock outlives the claim. Reclaiming an expired lease records the
    abandoned attempt, which keeps a crash visible in the diagnostics.
    """
    session.rollback()
    candidates_query = (
        select(
            AgentDeliveryJob.id,
            AgentDeliveryJob.lease_token,
            AgentDeliveryJob.attempts,
            AgentDeliveryJob.target_id,
            AgentDeliveryJob.expires_at,
        )
        .where(
            AgentDeliveryJob.status == "pending",
            AgentDeliveryJob.next_attempt_at <= moment,
            or_(
                AgentDeliveryJob.lease_token.is_(None),
                AgentDeliveryJob.lease_expires_at <= moment,
            ),
        )
        .order_by(AgentDeliveryJob.next_attempt_at, AgentDeliveryJob.id)
        .limit(8)
    )
    if skip_ids:
        candidates_query = candidates_query.where(AgentDeliveryJob.id.not_in(skip_ids))
    candidates = session.execute(candidates_query).all()
    session.rollback()
    lease_end = moment + timedelta(seconds=policy.lease_seconds)
    for job_id, prior_token, prior_attempts, target_id, expires_at in candidates:
        token = uuid.uuid4().hex
        lease_observed = (
            AgentDeliveryJob.lease_token.is_(None)
            if prior_token is None
            else (
                (AgentDeliveryJob.lease_token == prior_token)
                & (AgentDeliveryJob.lease_expires_at <= moment)
            )
        )
        result = session.execute(
            update(AgentDeliveryJob)
            .where(
                AgentDeliveryJob.id == job_id,
                AgentDeliveryJob.status == "pending",
                AgentDeliveryJob.next_attempt_at <= moment,
                lease_observed,
            )
            .values(
                claimed_by=worker_id[:64],
                claimed_at=moment,
                lease_token=token,
                lease_expires_at=lease_end,
                attempts=AgentDeliveryJob.attempts + 1,
            )
            .execution_options(synchronize_session=False)
        )
        if result.rowcount != 1:
            session.rollback()
            continue
        if prior_token is not None:
            session.add(
                AgentDeliveryAttempt(
                    job_id=job_id,
                    attempt_no=prior_attempts,
                    outcome="lease_expired",
                    error_code=None,
                    attempted_at=moment,
                )
            )
        session.commit()
        return _Claim(
            job_id=job_id,
            token=token,
            attempt_no=prior_attempts + 1,
            target_id=target_id,
            expires_at=expires_at,
            lease_expires_at=lease_end,
        )
    return None


_JOB_STATUS_RANK = {
    "acknowledged": 5,
    "delivered": 4,
    "pending": 3,
    "failed": 2,
    "expired": 1,
    "suppressed": 0,
}


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
    delivered target may acknowledge it, and only while it can still read the
    object: without current ``read`` the notice does not exist for the caller.
    Repeating an acknowledgement is an idempotent success.
    """
    moment = _naive_utc(now)
    rows = session.execute(
        select(AgentDeliveryJob, AgentNoticeEvent.object_id)
        .join(AgentDeliveryTarget, AgentDeliveryTarget.id == AgentDeliveryJob.target_id)
        .join(AgentNoticeEvent, AgentNoticeEvent.id == AgentDeliveryJob.event_id)
        .where(
            AgentDeliveryJob.event_id == event_id,
            AgentDeliveryTarget.principal_id == principal_id,
        )
    ).all()
    if not rows:
        return False, "not_found"
    policy_snapshot = policy_for_principal(session, principal_id)
    if Permission.READ not in policy_snapshot.permissions_for(rows[0][1]):
        return False, "not_found"
    jobs = [job for job, _object_id in rows]
    best = max(jobs, key=lambda job: _JOB_STATUS_RANK.get(job.status, -1))
    if best.status == "acknowledged" and not any(job.status == "delivered" for job in jobs):
        return True, None
    delivered = [job for job in jobs if job.status == "delivered"]
    if not delivered:
        return False, f"not_acknowledgeable_status_{best.status}"
    for job in delivered:
        session.execute(
            update(AgentDeliveryJob)
            .where(AgentDeliveryJob.id == job.id, AgentDeliveryJob.status == "delivered")
            .values(status="acknowledged", acknowledged_at=moment)
            .execution_options(synchronize_session=False)
        )
    session.flush()
    session.expire_all()
    return True, None


@dataclass(frozen=True, slots=True)
class OwnNotice:
    """One notice as its owning agent may read it (no transport details)."""

    event_id: str
    event_type: str
    schema_version: int
    object_id: str
    object_ref: str
    message: str
    blockwart_reference: str
    status: str
    delivered_at: datetime | None
    acknowledged_at: datetime | None


_OWN_NOTICE_SCAN_LIMIT = 500


def list_own_agent_notices(
    session: Session,
    *,
    principal_id: str,
    limit: int,
    status: str | None = None,
) -> list[OwnNotice]:
    """Newest-first notices of one agent principal, fail-closed on ``read``.

    A notice whose object the principal can no longer read is omitted
    entirely: neither the item nor a count reveals that it exists. Several
    jobs of one principal for the same event (separate routes) collapse into
    one notice carrying the furthest-progressed state, so a confirmed delivery
    is never shown twice. The scan is bounded; hidden rows never starve the
    page because it keeps reading until ``limit`` visible notices are found or
    the bound is reached.
    """
    policy_snapshot = policy_for_principal(session, principal_id)
    rows = session.execute(
        select(AgentDeliveryJob, AgentNoticeEvent)
        .join(AgentNoticeEvent, AgentNoticeEvent.id == AgentDeliveryJob.event_id)
        .join(AgentDeliveryTarget, AgentDeliveryTarget.id == AgentDeliveryJob.target_id)
        .where(AgentDeliveryTarget.principal_id == principal_id)
        .order_by(AgentDeliveryJob.created_at.desc(), AgentDeliveryJob.id.desc())
        .limit(_OWN_NOTICE_SCAN_LIMIT)
    ).all()
    best: dict[str, tuple[AgentDeliveryJob, AgentNoticeEvent]] = {}
    order: list[str] = []
    for job, event in rows:
        if Permission.READ not in policy_snapshot.permissions_for(event.object_id):
            continue
        current = best.get(event.id)
        if current is None:
            order.append(event.id)
            best[event.id] = (job, event)
        elif _JOB_STATUS_RANK.get(job.status, -1) > _JOB_STATUS_RANK.get(current[0].status, -1):
            best[event.id] = (job, event)
    notices: list[OwnNotice] = []
    for event_id in order:
        job, event = best[event_id]
        if status is not None and job.status != status:
            continue
        live_object = session.get(CatalogObject, event.object_id)
        label = live_object.label if live_object is not None else event.object_id
        notices.append(
            OwnNotice(
                event_id=event.id,
                event_type=event.event_type,
                schema_version=event.payload_version,
                object_id=event.object_id,
                object_ref=(
                    f"service:{event.object_id}"
                    if live_object is None
                    else f"{live_object.kind}:{live_object.id}"
                ),
                message=build_release_notice_message(label, event.latest_tag),
                blockwart_reference=f"/api/v1/agent/objects/{event.object_id}",
                status=job.status,
                delivered_at=job.delivered_at,
                acknowledged_at=job.acknowledged_at,
            )
        )
        if len(notices) >= limit:
            break
    return notices


@dataclass(frozen=True, slots=True)
class NoticeTargetView:
    target: AgentDeliveryTarget
    principal_login: str | None


@dataclass(frozen=True, slots=True)
class NoticeSubscriptionView:
    subscription: AgentNoticeSubscription
    target_label: str | None
    principal_login: str | None


@dataclass(frozen=True, slots=True)
class NoticeJobView:
    job: AgentDeliveryJob
    event: AgentNoticeEvent
    target_label: str | None
    last_attempt_outcome: str | None
    last_attempt_at: datetime | None


def list_notice_targets(session: Session) -> list[NoticeTargetView]:
    rows = session.execute(
        select(AgentDeliveryTarget, Principal.login)
        .outerjoin(Principal, Principal.id == AgentDeliveryTarget.principal_id)
        .order_by(AgentDeliveryTarget.created_at, AgentDeliveryTarget.id)
    ).all()
    return [NoticeTargetView(target, login) for target, login in rows]


def list_notice_subscriptions(session: Session) -> list[NoticeSubscriptionView]:
    rows = session.execute(
        select(AgentNoticeSubscription, AgentDeliveryTarget.label, Principal.login)
        .outerjoin(
            AgentDeliveryTarget,
            AgentDeliveryTarget.id == AgentNoticeSubscription.target_id,
        )
        .outerjoin(Principal, Principal.id == AgentNoticeSubscription.principal_id)
        .order_by(AgentNoticeSubscription.created_at, AgentNoticeSubscription.id)
    ).all()
    return [NoticeSubscriptionView(row, label, login) for row, label, login in rows]


def list_notice_jobs(
    session: Session,
    *,
    status: str | None = None,
    limit: int = 100,
) -> list[NoticeJobView]:
    """Redacted delivery diagnostics for platform administrators."""
    query = (
        select(AgentDeliveryJob, AgentNoticeEvent, AgentDeliveryTarget.label)
        .join(AgentNoticeEvent, AgentNoticeEvent.id == AgentDeliveryJob.event_id)
        .outerjoin(AgentDeliveryTarget, AgentDeliveryTarget.id == AgentDeliveryJob.target_id)
        .order_by(AgentDeliveryJob.created_at.desc(), AgentDeliveryJob.id.desc())
        .limit(limit)
    )
    if status is not None:
        query = query.where(AgentDeliveryJob.status == status)
    rows = session.execute(query).all()
    last_attempts: dict[int, tuple[str, datetime]] = {}
    if rows:
        attempt_rows = session.execute(
            select(
                AgentDeliveryAttempt.job_id,
                AgentDeliveryAttempt.outcome,
                AgentDeliveryAttempt.attempted_at,
            )
            .where(AgentDeliveryAttempt.job_id.in_([job.id for job, _e, _l in rows]))
            .order_by(AgentDeliveryAttempt.id)
        ).all()
        for job_id, outcome, attempted_at in attempt_rows:
            last_attempts[job_id] = (outcome, attempted_at)
    return [
        NoticeJobView(
            job=job,
            event=event,
            target_label=label,
            last_attempt_outcome=last_attempts.get(job.id, (None, None))[0],
            last_attempt_at=last_attempts.get(job.id, (None, None))[1],
        )
        for job, event, label in rows
    ]


def count_notice_jobs_by_status(session: Session) -> dict[str, int]:
    counts = dict.fromkeys(DELIVERY_STATUS_VALUES, 0)
    for status, count in session.execute(
        select(AgentDeliveryJob.status, func.count(AgentDeliveryJob.id)).group_by(
            AgentDeliveryJob.status
        )
    ):
        counts[status] = count
    return counts


class SubscriptionValidationError(ValueError):
    """Stable rejection reason for an invalid routing assignment."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code

    @property
    def is_conflict(self) -> bool:
        return self.code.endswith("_already_registered")


def create_agent_notice_subscription(
    session: Session,
    *,
    event_type: str,
    scope: str,
    object_id: str | None,
    principal_id: str,
    target_id: str,
    created_by_principal_id: str | None = None,
    actor: AuditActor | None = None,
) -> AgentNoticeSubscription:
    """Explicitly route one event scope to one approved agent target.

    Both ends of the mapping are validated: the principal must be an active
    service account, and the target must be active and owned by exactly that
    principal. Display-name similarity never couples identities. The same
    routing rule cannot be registered twice while active; a database partial
    unique index backs the check so concurrent creators cannot both win.
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
    if principal is None or not principal.active or principal.principal_type != "service_account":
        raise SubscriptionValidationError("principal_not_service_account")
    target = session.get(AgentDeliveryTarget, target_id)
    if target is None or not target.active:
        raise SubscriptionValidationError("target_inactive_or_unknown")
    if target.principal_id != principal.id:
        raise SubscriptionValidationError("target_not_owned_by_principal")
    if scope == "object" and session.get(CatalogObject, object_id) is None:
        raise SubscriptionValidationError("unknown_object")
    duplicate = session.scalar(
        select(AgentNoticeSubscription.id).where(
            AgentNoticeSubscription.active.is_(True),
            AgentNoticeSubscription.event_type == event_type,
            AgentNoticeSubscription.scope == scope,
            AgentNoticeSubscription.target_id == target.id,
            (
                AgentNoticeSubscription.object_id == object_id
                if scope == "object"
                else AgentNoticeSubscription.object_id.is_(None)
            ),
        )
    )
    if duplicate is not None:
        raise SubscriptionValidationError("subscription_already_registered")
    row = AgentNoticeSubscription(
        id=str(uuid.uuid4()),
        event_type=event_type,
        scope=scope,
        object_id=object_id,
        principal_id=principal.id,
        target_id=target.id,
        created_by_principal_id=created_by_principal_id,
    )
    try:
        with session.begin_nested():
            session.add(row)
            session.flush()
    except IntegrityError as exc:
        raise SubscriptionValidationError("subscription_already_registered") from exc
    _audit_management(
        session,
        actor,
        "agent_notice_subscription_created",
        {
            "subscription_id": row.id,
            "target_id": target.id,
            "scope": scope,
            "event_type": event_type,
        },
    )
    return row


_ROUTE_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._:-]{0,190}$")


def create_agent_delivery_target(
    session: Session,
    *,
    principal_id: str,
    label: str,
    route: str,
    transport: str,
    actor: AuditActor | None = None,
) -> AgentDeliveryTarget:
    """Approve one addressable agent destination for a service account.

    ``route`` is the stable, non-secret OpenClaw routing identity (agent/
    session/inbox) the gateway uses to distinguish targets. It is never a
    credential and never a freely configurable callback URL. Routes are
    lower-case so one logical route has exactly one spelling, and one route
    can be registered at most once while active (partial unique index; a
    concurrent duplicate loses with ``route_already_registered``).
    """
    if transport not in AGENT_NOTICE_TRANSPORTS:
        raise SubscriptionValidationError("unknown_transport")
    if not _ROUTE_PATTERN.fullmatch(route or ""):
        raise SubscriptionValidationError("invalid_target_route")
    if not (label or "").strip():
        raise SubscriptionValidationError("invalid_target_label")
    # Callers may run with autoflush disabled; make pending rows visible.
    session.flush()
    principal = session.get(Principal, principal_id)
    if principal is None or not principal.active or principal.principal_type != "service_account":
        raise SubscriptionValidationError("principal_not_service_account")
    existing = session.scalar(
        select(AgentDeliveryTarget.id).where(
            AgentDeliveryTarget.active.is_(True),
            AgentDeliveryTarget.transport == transport,
            AgentDeliveryTarget.route == route,
        )
    )
    if existing is not None:
        raise SubscriptionValidationError("route_already_registered")
    row = AgentDeliveryTarget(
        id=str(uuid.uuid4()),
        principal_id=principal.id,
        label=label.strip()[:128],
        route=route,
        transport=transport,
    )
    try:
        with session.begin_nested():
            session.add(row)
            session.flush()
    except IntegrityError as exc:
        raise SubscriptionValidationError("route_already_registered") from exc
    _audit_management(
        session,
        actor,
        "agent_notice_target_created",
        {"target_id": row.id, "principal_id": principal.id, "transport": transport},
    )
    return row


def deactivate_agent_delivery_target(
    session: Session,
    *,
    target_id: str,
    now: datetime,
    actor: AuditActor | None = None,
) -> bool:
    """Revoke a target. Pending deliveries fail closed on their next check."""
    row = session.get(AgentDeliveryTarget, target_id)
    if row is None:
        return False
    if row.active:
        row.active = False
        session.flush()
        _audit_management(
            session,
            actor,
            "agent_notice_target_revoked",
            {"target_id": row.id, "principal_id": row.principal_id},
        )
    return True


async def run_notice_delivery_poller(
    settings: Settings,
    stop_event: asyncio.Event,
) -> None:
    """Periodically deliver due agent notices in the running application.

    Mirrors the release-monitoring poller: a bounded pass runs in a worker
    thread, failures are logged with a stable code, and the loop stops on the
    shared stop event. The transport is built from settings; an empty
    transport URL disables productive delivery while keeping the poller
    harmless.
    """
    from blockwart.services.notice_transport import build_notice_transport

    if not settings.notice_delivery_poller_enabled:
        return
    try:
        transport = build_notice_transport(settings)
    except (ValueError, RuntimeError):
        logger.error("notice_delivery_poller_error code=transport_invalid")
        return
    if transport is None:
        logger.error("notice_delivery_poller_error code=transport_unconfigured")
        return
    try:
        engine = build_engine(settings.database_url)
        sessions = sessionmaker(engine, expire_on_commit=False)
    except Exception:  # noqa: BLE001 - process boundary emits only a stable code
        logger.error("notice_delivery_poller_error code=initialization_failed")
        return
    policy = NoticeDeliveryPolicy(max_deliveries_per_run=settings.notice_delivery_max_per_run)
    try:
        while not stop_event.is_set():
            try:
                await asyncio.to_thread(_run_delivery_pass, sessions, transport, policy)
            except Exception:  # noqa: BLE001
                logger.error("notice_delivery_poller_error code=delivery_pass_failed")
            try:
                await asyncio.wait_for(
                    stop_event.wait(),
                    timeout=settings.notice_delivery_poll_interval_seconds,
                )
            except TimeoutError:
                pass
    finally:
        engine.dispose()


def _run_delivery_pass(
    sessions: sessionmaker[Session],
    transport: NoticeTransport,
    policy: NoticeDeliveryPolicy,
) -> None:
    with sessions() as session:
        deliver_due_agent_notices(
            session,
            transport,
            now=datetime.now(UTC),
            policy=policy,
            worker_id=f"poller-{uuid.uuid4().hex[:8]}",
            clock=lambda: _database_now(sessions),
        )


def _database_now(sessions: sessionmaker[Session]) -> datetime:
    """Fresh DB time keeps production leases/retries independent of worker skew."""
    with sessions() as session:
        return _naive_utc(session.scalar(select(func.current_timestamp())))
