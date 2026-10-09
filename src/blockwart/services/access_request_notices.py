"""Durable, bounded hints for approvers of access requests (Issue #100).

A hint tells one currently authorized approver, through one
administrator-approved agent route, that an access request is waiting. This
module is the whole delivery story and it keeps notification a separate
security domain from authorization:

- **Honest state.** Nothing is "delivered" because a no-op ran. When hints are
  switched off, or no approved route belongs to a principal that can decide
  the request, the request records ``disabled`` / ``no_route`` and no notice
  exists. Only the transport's confirmed acceptance (or a receiver's duplicate
  confirmation of the same key) moves a notice to ``delivered``.
- **Authorized recipients only.** Recipients are the active agent delivery
  targets of principals that hold ``manage_access`` on the object *now*. The
  same check is repeated directly before every attempt; a lost grant,
  deactivated principal, revoked token or revoked route suppresses the notice
  and nothing leaves Blockwart.
- **Durable and bounded.** One ``access_request_notices`` row per
  ``(request, target)`` is written in the request's own transaction. Retries
  use exponential backoff, a TTL and an attempt budget; exhausting either is
  the dead-letter state ``failed``/``expired``. Outcomes stored are coarse
  codes only.
- **No lock across the network.** A fenced lease is committed before the
  transport runs, no transaction is open while it runs, and the result is
  written by an UPDATE conditional on the lease token. A crashed worker's lease
  expires and the notice is claimable again; a late worker cannot overwrite.
- **Minimal payload.** The payload is a closed schema with a fixed message,
  the request id, the object ref and a relative reference to the
  authenticated decision surface. It never contains the requester's reason,
  identity, a token or a URL; following it cannot approve anything.
- **Independent of the request.** Notices only read request state. A failing,
  expiring or dead-lettered notice cannot change a request or a grant.

Delivery is at-least-once on the wire and idempotent at the receiver through
the globally unique ``delivery_id`` of the notice. The only shipped transport
is the loopback-only OpenClaw test gateway of the agent notice channel; there
is no configurable callback URL.
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import func, or_, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from blockwart.config import Settings
from blockwart.db.session import build_engine
from blockwart.domain.access_request_notices import (
    NOTICE_STATUS_VALUES,
    build_access_request_notice_payload,
    delivery_id_for_notice,
)
from blockwart.domain.access_requests import AccessRequestStatus
from blockwart.domain.agent_notices import AGENT_NOTICE_TRANSPORTS
from blockwart.domain.auth import Permission
from blockwart.models import (
    AccessRequest,
    AccessRequestNotice,
    AccessRequestNoticeAttempt,
    AgentDeliveryTarget,
    CatalogObject,
    Principal,
    ServiceToken,
)
from blockwart.services import clock as wall_clock
from blockwart.services.access_request_state import effective_status
from blockwart.services.agent_notices import NoticeDeliveryPolicy
from blockwart.services.notice_transport import (
    DeliveryOutcome,
    DeliveryRequest,
    NoticeTransport,
    TransportConfigError,
)
from blockwart.services.policy import PolicySnapshot, policy_for_principal

logger = logging.getLogger(__name__)

# Bounds on one request's fan-out so a large target registry can neither slow
# request creation nor flood approvers.
MAX_TARGETS_SCANNED = 200
MAX_RECIPIENTS_PER_REQUEST = 10


@dataclass(frozen=True, slots=True)
class NoticeRouting:
    """Whether hints are routed at all, and under which bounds."""

    enabled: bool
    policy: NoticeDeliveryPolicy


def notice_routing_from_settings(settings: Settings) -> NoticeRouting:
    """Hints need the explicit opt-in, a running poller and a configured transport.

    Anything less is ``disabled``: queueing notices nobody can deliver would
    only make them pile up as "pending" forever.
    """
    enabled = bool(
        settings.access_request_notices_enabled
        and settings.notice_delivery_poller_enabled
        and settings.notice_delivery_endpoint_url
    )
    return NoticeRouting(
        enabled=enabled,
        policy=NoticeDeliveryPolicy(
            max_deliveries_per_run=settings.notice_delivery_max_per_run,
        ),
    )


DISABLED_ROUTING = NoticeRouting(enabled=False, policy=NoticeDeliveryPolicy())


@dataclass(frozen=True, slots=True)
class RecipientState:
    allowed: bool
    error_code: str | None = None


def _recipient_state(
    session: Session,
    *,
    target: AgentDeliveryTarget | None,
    object_id: str,
    requester_principal_id: str,
    now: datetime,
    policies: dict[str, PolicySnapshot] | None = None,
) -> RecipientState:
    """Whether this route may be told about a request on this object right now."""
    if target is None or not target.active or target.transport not in AGENT_NOTICE_TRANSPORTS:
        return RecipientState(False, "target_inactive")
    principal = session.get(Principal, target.principal_id)
    if (
        principal is None
        or not principal.active
        or principal.principal_type != "service_account"
        or principal.id == requester_principal_id
    ):
        return RecipientState(False, "principal_inactive")
    live_token = session.scalar(
        select(ServiceToken.id)
        .where(
            ServiceToken.principal_id == principal.id,
            ServiceToken.revoked_at.is_(None),
            or_(ServiceToken.expires_at.is_(None), ServiceToken.expires_at > now),
        )
        .limit(1)
    )
    if live_token is None:
        return RecipientState(False, "principal_inactive")
    cache = policies if policies is not None else {}
    snapshot = cache.get(principal.id)
    if snapshot is None:
        snapshot = policy_for_principal(session, principal.id)
        cache[principal.id] = snapshot
    if not snapshot.can(Permission.MANAGE_ACCESS, object_id):
        return RecipientState(False, "manage_access_lost")
    return RecipientState(True)


def resolve_recipient_targets(
    session: Session,
    *,
    object_id: str,
    requester_principal_id: str,
    now: datetime,
) -> list[AgentDeliveryTarget]:
    """Approved routes of principals that can decide requests on the object now."""
    candidates = session.scalars(
        select(AgentDeliveryTarget)
        .where(
            AgentDeliveryTarget.active.is_(True),
            AgentDeliveryTarget.transport.in_(sorted(AGENT_NOTICE_TRANSPORTS)),
        )
        .order_by(AgentDeliveryTarget.created_at, AgentDeliveryTarget.id)
        .limit(MAX_TARGETS_SCANNED)
    ).all()
    policies: dict[str, PolicySnapshot] = {}
    recipients: list[AgentDeliveryTarget] = []
    for target in candidates:
        state = _recipient_state(
            session,
            target=target,
            object_id=object_id,
            requester_principal_id=requester_principal_id,
            now=now,
            policies=policies,
        )
        if state.allowed:
            recipients.append(target)
        if len(recipients) >= MAX_RECIPIENTS_PER_REQUEST:
            break
    return recipients


def plan_access_request_notices(
    session: Session,
    request: AccessRequest,
    *,
    routing: NoticeRouting,
    now: datetime,
) -> str:
    """Queue one notice per authorized recipient route; return the routing state.

    Runs inside the creating transaction so the request and its outbox rows
    commit or roll back together. The return value is ``disabled`` (hints are
    off or unconfigured), ``no_route`` (nobody authorized has an approved
    route) or ``queued`` (at least one durable notice exists). It is never
    ``delivered``: only the delivery pass can establish that.
    """
    if not routing.enabled:
        return "disabled"
    targets = resolve_recipient_targets(
        session,
        object_id=request.object_id,
        requester_principal_id=request.requester_principal_id,
        now=now,
    )
    if not targets:
        return "no_route"
    for target in targets:
        pending = session.scalar(
            select(func.count(AccessRequestNotice.id)).where(
                AccessRequestNotice.target_id == target.id,
                AccessRequestNotice.status == "pending",
            )
        )
        storm = (pending or 0) >= routing.policy.max_pending_jobs_per_target
        notice = AccessRequestNotice(
            id=str(uuid.uuid4()),
            request_id=request.id,
            target_id=target.id,
            recipient_principal_id=target.principal_id,
            status="suppressed" if storm else "pending",
            attempts=0,
            next_attempt_at=now,
            expires_at=now + timedelta(seconds=routing.policy.ttl_seconds),
            suppressed_at=now if storm else None,
            last_error_code="storm_suppressed" if storm else None,
        )
        try:
            with session.begin_nested():
                session.add(notice)
                session.flush()
        except IntegrityError:
            # Another writer already planned this (request, target) pair.
            continue
    return "queued"


def suppress_pending_notices(
    session: Session,
    request_id: str,
    *,
    now: datetime,
    error_code: str = "request_not_pending",
) -> int:
    """Stop unclaimed notices of a request that is no longer waiting.

    A notice currently leased by a worker is left to that worker's attempt-time
    re-check, which reaches the same conclusion.
    """
    result = session.execute(
        update(AccessRequestNotice)
        .where(
            AccessRequestNotice.request_id == request_id,
            AccessRequestNotice.status == "pending",
            AccessRequestNotice.lease_token.is_(None),
        )
        .values(status="suppressed", suppressed_at=now, last_error_code=error_code)
        .execution_options(synchronize_session=False)
    )
    return result.rowcount or 0


# --------------------------------------------------------------------------
# Delivery
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class _Claim:
    """A durable lease on one notice; ``token`` fences every later write."""

    notice_id: str
    token: str
    attempt_no: int
    expires_at: datetime


def _naive(moment: datetime) -> datetime:
    if moment.tzinfo is None:
        return moment
    return moment.astimezone(UTC).replace(tzinfo=None)


def deliver_due_access_request_notices(
    session: Session,
    transport: NoticeTransport,
    *,
    now: datetime,
    policy: NoticeDeliveryPolicy | None = None,
    worker_id: str = "inline",
    clock: Callable[[], datetime] | None = None,
) -> dict[str, int]:
    """Run one bounded delivery pass, one notice at a time.

    This function owns its transactions and first commits any unit of work the
    caller left open. Per notice: *claim* (fenced lease, committed first),
    *re-check* (TTL, attempt budget, request still pending, recipient still
    authorized; a denial suppresses and sends nothing), *send* (no database
    transaction open), *record* (UPDATE conditional on the lease token). A
    claim consumes one attempt up front, so a crash loop is bounded too.
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
    processed: set[str] = set()
    for _ in range(active_policy.max_deliveries_per_run):
        claim = _claim_next(
            session,
            worker_id=worker_id,
            policy=active_policy,
            moment=_naive(moment_of()),
            skip_ids=processed,
        )
        if claim is None:
            break
        processed.add(claim.notice_id)
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
        decision = _prepare_attempt(session, claim, policy, _naive(moment_of()))
    except Exception:  # noqa: BLE001 - a recheck fault must neither send nor drop the notice
        session.rollback()
        logger.error("access_request_notice_error code=prepare_failed notice=%s", claim.notice_id)
        # Treat as a transient fault: spend the attempt, retry with backoff.
        _record_outcome(
            session,
            claim,
            DeliveryOutcome(ok=False, error_code="delivery_error"),
            policy,
            _naive(moment_of()),
            stats,
        )
        return
    if isinstance(decision, DeliveryRequest):
        # End the read transaction: nothing is held open across the transport.
        session.rollback()
        try:
            outcome = transport.deliver(decision)
        except Exception:  # noqa: BLE001 - transport boundary stays coarse
            outcome = DeliveryOutcome(ok=False, error_code="transport_unavailable")
        _record_outcome(session, claim, outcome, policy, _naive(moment_of()), stats)
        return
    status, code = decision
    moment = _naive(moment_of())
    values: dict[str, object] = {"status": status, "last_error_code": code}
    if status == "suppressed":
        values["suppressed_at"] = moment
    if _finish_claim(session, claim, uncount_attempt=True, **values):
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
    # Drop anything cached by earlier phases: every attempt judges request,
    # principal, grants and route as they are now.
    session.expire_all()
    if claim.expires_at <= moment:
        return ("expired", "ttl_expired")
    if claim.attempt_no > policy.max_attempts:
        return ("failed", "attempt_limit_reached")
    notice = session.get(AccessRequestNotice, claim.notice_id)
    if notice is None or notice.lease_token != claim.token:
        return ("failed", "delivery_error")
    request = session.get(AccessRequest, notice.request_id)
    if request is None:
        return ("suppressed", "request_not_pending")
    if effective_status(session, request, now=moment) != AccessRequestStatus.PENDING:
        return ("suppressed", "request_not_pending")
    requester = session.get(Principal, request.requester_principal_id)
    catalog_object = session.get(CatalogObject, request.object_id)
    if requester is None or not requester.active or catalog_object is None:
        return ("suppressed", "request_not_pending")
    target = session.get(AgentDeliveryTarget, notice.target_id)
    state = _recipient_state(
        session,
        target=target,
        object_id=request.object_id,
        requester_principal_id=request.requester_principal_id,
        now=moment,
    )
    if not state.allowed or target is None:
        return ("suppressed", state.error_code or "manage_access_lost")
    return DeliveryRequest(
        target_id=target.id,
        target_route=target.route,
        delivery_id=delivery_id_for_notice(notice.id),
        payload=build_access_request_notice_payload(
            request_id=request.id,
            object_ref=f"{catalog_object.kind}:{catalog_object.id}",
        ),
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
    if not _finish_claim(session, claim, uncount_attempt=False, commit=False, **values):
        # The lease was lost to a reclaiming worker: its result is the record.
        session.rollback()
        stats["lease_lost"] += 1
        return
    session.add(
        AccessRequestNoticeAttempt(
            notice_id=claim.notice_id,
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
    **values: object,
) -> bool:
    """Write a result conditional on the fencing token and release the lease."""
    assignments: dict[str, object] = {
        **values,
        "claimed_by": None,
        "claimed_at": None,
        "lease_token": None,
        "lease_expires_at": None,
    }
    if uncount_attempt:
        assignments["attempts"] = AccessRequestNotice.attempts - 1
    result = session.execute(
        update(AccessRequestNotice)
        .where(
            AccessRequestNotice.id == claim.notice_id,
            AccessRequestNotice.lease_token == claim.token,
            AccessRequestNotice.status == "pending",
        )
        .values(**assignments)
        .execution_options(synchronize_session=False)
    )
    won = result.rowcount == 1
    if commit:
        session.commit()
    return won


def _claim_next(
    session: Session,
    *,
    worker_id: str,
    policy: NoticeDeliveryPolicy,
    moment: datetime,
    skip_ids: set[str],
) -> _Claim | None:
    """Take a fenced lease on the next due notice and commit it.

    The conditional UPDATE is the concurrency guard: it compares against the
    lease state it observed, so two workers racing for one row cannot both win
    on SQLite (serialized writers) or PostgreSQL (row lock, predicate
    re-evaluated). It touches one row and commits immediately, so no write
    lock outlives the claim.
    """
    session.rollback()
    candidates_query = (
        select(
            AccessRequestNotice.id,
            AccessRequestNotice.lease_token,
            AccessRequestNotice.attempts,
            AccessRequestNotice.expires_at,
        )
        .where(
            AccessRequestNotice.status == "pending",
            AccessRequestNotice.next_attempt_at <= moment,
            or_(
                AccessRequestNotice.lease_token.is_(None),
                AccessRequestNotice.lease_expires_at <= moment,
            ),
        )
        .order_by(AccessRequestNotice.next_attempt_at, AccessRequestNotice.id)
        .limit(8)
    )
    if skip_ids:
        candidates_query = candidates_query.where(AccessRequestNotice.id.not_in(skip_ids))
    candidates = session.execute(candidates_query).all()
    session.rollback()
    lease_end = moment + timedelta(seconds=policy.lease_seconds)
    for notice_id, prior_token, prior_attempts, expires_at in candidates:
        token = uuid.uuid4().hex
        lease_observed = (
            AccessRequestNotice.lease_token.is_(None)
            if prior_token is None
            else (
                (AccessRequestNotice.lease_token == prior_token)
                & (AccessRequestNotice.lease_expires_at <= moment)
            )
        )
        result = session.execute(
            update(AccessRequestNotice)
            .where(
                AccessRequestNotice.id == notice_id,
                AccessRequestNotice.status == "pending",
                AccessRequestNotice.next_attempt_at <= moment,
                lease_observed,
            )
            .values(
                claimed_by=worker_id[:64],
                claimed_at=moment,
                lease_token=token,
                lease_expires_at=lease_end,
                attempts=AccessRequestNotice.attempts + 1,
            )
            .execution_options(synchronize_session=False)
        )
        if result.rowcount != 1:
            session.rollback()
            continue
        if prior_token is not None:
            session.add(
                AccessRequestNoticeAttempt(
                    notice_id=notice_id,
                    attempt_no=prior_attempts,
                    outcome="lease_expired",
                    error_code=None,
                    attempted_at=moment,
                )
            )
        session.commit()
        return _Claim(
            notice_id=notice_id,
            token=token,
            attempt_no=prior_attempts + 1,
            expires_at=expires_at,
        )
    return None


def count_notices_by_status(session: Session) -> dict[str, int]:
    """Redacted diagnostics: how many notices sit in each state."""
    counts = dict.fromkeys(NOTICE_STATUS_VALUES, 0)
    for status, count in session.execute(
        select(AccessRequestNotice.status, func.count(AccessRequestNotice.id)).group_by(
            AccessRequestNotice.status
        )
    ):
        counts[status] = count
    return counts


# --------------------------------------------------------------------------
# Poller
# --------------------------------------------------------------------------


async def run_access_request_notice_poller(
    settings: Settings,
    stop_event: asyncio.Event,
) -> None:
    """Periodically deliver due access request hints inside the running app.

    Runs only with the explicit opt-in *and* the shared notice poller flag. A
    transport that is unconfigured or refused (non-loopback endpoint) logs one
    stable code and ends the task cleanly instead of crashing shutdown.
    """
    from blockwart.services.notice_transport import build_notice_transport

    if not (settings.access_request_notices_enabled and settings.notice_delivery_poller_enabled):
        return
    try:
        transport = build_notice_transport(settings)
    except TransportConfigError:
        logger.error("access_request_notice_poller_error code=transport_refused")
        return
    if transport is None:
        logger.error("access_request_notice_poller_error code=transport_unconfigured")
        return
    try:
        engine = build_engine(settings.database_url)
        sessions = sessionmaker(engine, expire_on_commit=False)
    except Exception:  # noqa: BLE001 - process boundary emits only a stable code
        logger.error("access_request_notice_poller_error code=initialization_failed")
        return
    policy = NoticeDeliveryPolicy(max_deliveries_per_run=settings.notice_delivery_max_per_run)
    try:
        while not stop_event.is_set():
            try:
                await asyncio.to_thread(_run_delivery_pass, sessions, transport, policy)
            except Exception:  # noqa: BLE001
                logger.error("access_request_notice_poller_error code=delivery_pass_failed")
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
        deliver_due_access_request_notices(
            session,
            transport,
            now=wall_clock.utcnow(),
            policy=policy,
            worker_id=f"poller-{uuid.uuid4().hex[:8]}",
            clock=wall_clock.utcnow,
        )
