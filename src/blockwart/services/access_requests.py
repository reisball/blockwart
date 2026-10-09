"""Access requests and temporary grants (Issue #100).

One service layer owns the whole request lifecycle so UI, REST API and MCP
share the same request, decision, policy and audit contract:

- Only authenticated, *currently active* principals apply, read, cancel or
  decide. Authentication is not trusted for this: activity is re-checked here
  against the database on every call.
- A requester must hold ``discover`` on the object *now*. Without it every
  outcome looks exactly like an unknown object, on create **and** on every
  later list/status/cancel: owning an old request never keeps an object, a
  request or a grant identifier visible after visibility is lost.
- V1 scope is exactly Viewer on ``self``, temporary or permanent.
- Approval is atomic and guarded: the request transition, exactly one matching
  grant and the audit event commit together; denial and cancellation never
  create a grant; exactly one of any set of parallel create/decide/cancel
  callers wins and the others conflict.
- Reads never write. Expiry of a requested/approved window and the loss of the
  grant behind an approval are projected on read (see
  ``services.access_request_state``) and only persisted by the explicit write
  lifecycles in this module and in grant revoke/replace.
- Only ``pending`` requests occupy the open-request slot. An approved request
  whose grant expired or was revoked can never block a replacement, and a
  replacement never rewrites the original request.
- Temporary grants lose effect in the request path once ``expires_at`` has
  passed (see ``services.policy``), independent of process restarts.
- Notifications are a separate, durable and bounded outbox
  (``services.access_request_notices``); they can never authorize or change
  anything.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from blockwart.domain.access_requests import (
    AccessRequestDuration,
    AccessRequestStatus,
)
from blockwart.domain.auth import GrantScope, Permission, Role
from blockwart.domain.timestamps import format_rfc3339_utc
from blockwart.models import AccessRequest, CatalogObject, Principal
from blockwart.services import clock
from blockwart.services.access import create_object_grant
from blockwart.services.access_request_notices import (
    DISABLED_ROUTING,
    NoticeRouting,
    plan_access_request_notices,
    suppress_pending_notices,
)
from blockwart.services.access_request_state import (
    effective_statuses,
    materialize_lapsed_requests,
    transition_request,
)
from blockwart.services.audit import add_audit_event
from blockwart.services.commands import (
    CommandAuthorizationDenied,
    CommandConflict,
    CommandNotFound,
    WriteContext,
)
from blockwart.services.policy import PolicySnapshot, policy_for_principal

# Conservative answers to the open product decisions in Issue #100. They are
# module constants instead of free-form configuration on purpose: approval
# policies stay code-reviewed, and operators adjust them by shipping a change,
# not by editing runtime state.
MIN_TEMPORARY_SECONDS = 5 * 60
MAX_TEMPORARY_SECONDS = 30 * 24 * 60 * 60
MAX_REASON_LENGTH = 500
MAX_OPEN_REQUESTS_PER_REQUESTER = 10
# Upper bounds on one list response so a long history cannot grow a read.
MAX_REQUESTER_LIST_ITEMS = 200
MAX_APPROVER_QUEUE_ITEMS = 200
_QUEUE_CHUNK = 400


def sanitize_reason(reason: str | None) -> str | None:
    """Bound untrusted input: strip control characters, cap length."""
    if reason is None:
        return None
    cleaned = "".join(
        character
        for character in reason.strip()
        if character.isprintable() or character == "\t"
    )
    cleaned = " ".join(cleaned.split())
    if not cleaned:
        return None
    return cleaned[:MAX_REASON_LENGTH]


def _validate_temporary_duration(ttl_seconds: int | None) -> timedelta:
    if ttl_seconds is None:
        raise CommandConflict("temporary requests require ttl_seconds")
    if ttl_seconds < MIN_TEMPORARY_SECONDS or ttl_seconds > MAX_TEMPORARY_SECONDS:
        raise CommandConflict(
            "ttl_seconds must be between "
            f"{MIN_TEMPORARY_SECONDS} and {MAX_TEMPORARY_SECONDS}"
        )
    return timedelta(seconds=ttl_seconds)


@dataclass(frozen=True, slots=True)
class RequesterRequestView:
    """A request as its requester sees it: no approver or policy data."""

    id: str
    object_id: str
    role: str
    scope: str
    duration: str
    status: str
    reason: str | None
    requested_expires_at: str | None
    approved_expires_at: str | None
    grant_id: int | None
    created_at: str | None


@dataclass(frozen=True, slots=True)
class ApproverRequestView:
    """A request as a currently authorized approver sees it."""

    id: str
    object_id: str
    object_label: str
    object_kind: str
    requester_login: str
    requester_display_name: str
    role: str
    scope: str
    duration: str
    status: str
    reason: str | None
    requested_expires_at: str | None
    created_at: str | None


@dataclass(frozen=True, slots=True)
class AccessRequestCommandResult:
    request_id: str
    status: str
    changed: bool


def _active_principal(session: Session, context: WriteContext) -> Principal | None:
    """The caller's principal row if, and only if, it is active right now."""
    principal = session.get(Principal, context.principal.id)
    if principal is None or not principal.active:
        return None
    return principal


def _hidden_unless_discoverable(
    policy: PolicySnapshot,
    object_id: str,
) -> None:
    if not policy.can(Permission.DISCOVER, object_id):
        raise CommandNotFound("access request not found")


def create_access_request(
    session: Session,
    context: WriteContext,
    *,
    object_id: str,
    duration: AccessRequestDuration | str,
    ttl_seconds: int | None,
    reason: str | None,
    routing: NoticeRouting = DISABLED_ROUTING,
) -> AccessRequestCommandResult:
    resolved_duration = AccessRequestDuration(duration)
    now = clock.utcnow()
    principal = _active_principal(session, context)
    principal_id = context.principal.id
    # Fresh policy: the create decision must reflect grants as they are now.
    policy = policy_for_principal(session, context.principal.id)
    catalog_object = session.get(CatalogObject, object_id)
    if (
        principal is None
        or catalog_object is None
        or not policy.can(Permission.DISCOVER, object_id)
    ):
        # Unknown, undiscoverable and inactive-caller cases are indistinguishable.
        raise CommandNotFound("catalog object not found")
    if policy.can(Permission.READ, object_id):
        raise CommandConflict("read access is already granted for this object")

    requested_expires_at: datetime | None = None
    if resolved_duration == AccessRequestDuration.TEMPORARY:
        requested_expires_at = now + _validate_temporary_duration(ttl_seconds)

    # Persist elapsed windows / vanished grants of this requester and object
    # first (an explicit write lifecycle), so a stale row can never be mistaken
    # for an open request and nothing outside this transaction has to run.
    materialize_lapsed_requests(
        session,
        requester_principal_id=principal.id,
        object_ids=(object_id,),
        now=now,
        actor="system",
    )

    existing = _pending_request(session, principal.id, object_id)
    if existing is not None:
        # A true retry: the original row and its history stay untouched.
        return AccessRequestCommandResult(
            request_id=existing.id,
            status=str(existing.status),
            changed=False,
        )

    open_count = len(
        session.scalars(
            select(AccessRequest.id).where(
                AccessRequest.requester_principal_id == principal.id,
                AccessRequest.status == AccessRequestStatus.PENDING,
            )
        ).all()
    )
    if open_count >= MAX_OPEN_REQUESTS_PER_REQUESTER:
        raise CommandConflict("too many open access requests")

    sanitized_reason = sanitize_reason(reason)
    request = AccessRequest(
        id=str(uuid.uuid4()),
        requester_principal_id=principal.id,
        object_id=object_id,
        role=Role.VIEWER,
        scope=GrantScope.SELF,
        duration=resolved_duration,
        status=AccessRequestStatus.PENDING,
        reason=sanitized_reason,
        requested_expires_at=requested_expires_at,
    )
    session.add(request)
    try:
        session.flush()
    except IntegrityError:
        # A concurrent identical request won the partial unique index. Nothing
        # else in this transaction needs to survive (the winner is returned
        # unchanged), so the whole unit is rolled back. A SAVEPOINT is avoided
        # on purpose: the SQLite driver would not have begun a transaction yet,
        # and releasing the outermost savepoint would commit it.
        session.rollback()
        winner = _pending_request(session, principal_id, object_id)
        if winner is None:
            raise
        return AccessRequestCommandResult(
            request_id=winner.id,
            status=str(winner.status),
            changed=False,
        )

    notification = plan_access_request_notices(session, request, routing=routing, now=now)
    add_audit_event(
        session,
        object_id=object_id,
        action="access_request_create",
        actor=context.principal.id,
        details={
            "actor_principal_id": context.principal.id,
            "access_request_id": request.id,
            "role": Role.VIEWER,
            "scope": GrantScope.SELF,
            "duration": resolved_duration,
            "requested_expires_at": (
                requested_expires_at.isoformat() if requested_expires_at else None
            ),
            "channel": context.channel,
            "reason_length": len(sanitized_reason) if sanitized_reason else 0,
            "notification": notification,
        },
    )
    session.flush()
    return AccessRequestCommandResult(
        request_id=request.id,
        status=str(request.status),
        changed=True,
    )


def list_my_access_requests(
    session: Session,
    context: WriteContext,
) -> tuple[RequesterRequestView, ...]:
    """The caller's requests, projected at the current time. Writes nothing.

    Only requests on objects the caller can discover *now* are returned, and
    only while the caller is active: after visibility is lost the object id,
    request state and grant id disappear exactly like an unknown object.
    """
    if _active_principal(session, context) is None:
        raise CommandNotFound("access request not found")
    now = clock.utcnow()
    policy = policy_for_principal(session, context.principal.id)
    rows = session.scalars(
        select(AccessRequest)
        .where(AccessRequest.requester_principal_id == context.principal.id)
        .order_by(AccessRequest.created_at.desc(), AccessRequest.id)
        .limit(MAX_REQUESTER_LIST_ITEMS * 4)
    ).all()
    visible = [row for row in rows if policy.can(Permission.DISCOVER, row.object_id)]
    visible = visible[:MAX_REQUESTER_LIST_ITEMS]
    effective = effective_statuses(session, visible, now=now)
    return tuple(_requester_view(row, effective[row.id]) for row in visible)


def cancel_access_request(
    session: Session,
    context: WriteContext,
    *,
    request_id: str,
) -> AccessRequestCommandResult:
    if _active_principal(session, context) is None:
        raise CommandNotFound("access request not found")
    now = clock.utcnow()
    request = session.get(AccessRequest, request_id)
    if request is None or request.requester_principal_id != context.principal.id:
        raise CommandNotFound("access request not found")
    policy = policy_for_principal(session, context.principal.id)
    _hidden_unless_discoverable(policy, request.object_id)
    effective = effective_statuses(session, [request], now=now)[request.id]
    if effective != AccessRequestStatus.PENDING:
        raise CommandConflict("only pending requests can be cancelled")
    # One guarded UPDATE: a parallel decision or cancellation that already
    # moved the row away from pending makes this caller conflict.
    if not transition_request(
        session,
        request.id,
        expected=AccessRequestStatus.PENDING,
        status=AccessRequestStatus.CANCELLED,
    ):
        raise CommandConflict("only pending requests can be cancelled")
    suppress_pending_notices(session, request.id, now=now)
    add_audit_event(
        session,
        object_id=request.object_id,
        action="access_request_cancel",
        actor=context.principal.id,
        details={
            "actor_principal_id": context.principal.id,
            "access_request_id": request.id,
            "channel": context.channel,
        },
    )
    session.flush()
    session.refresh(request)
    return AccessRequestCommandResult(
        request_id=request.id,
        status=str(request.status),
        changed=True,
    )


def list_pending_access_requests(
    session: Session,
    context: WriteContext,
) -> tuple[ApproverRequestView, ...]:
    """Open requests the caller may decide right now. Writes nothing."""
    if _active_principal(session, context) is None:
        raise CommandNotFound("access request not found")
    now = clock.utcnow()
    policy = policy_for_principal(session, context.principal.id)
    manageable_ids = sorted(policy.authorized_ids(Permission.MANAGE_ACCESS))
    if not manageable_ids:
        return ()
    rows: list[AccessRequest] = []
    for start in range(0, len(manageable_ids), _QUEUE_CHUNK):
        chunk = manageable_ids[start : start + _QUEUE_CHUNK]
        rows.extend(
            session.scalars(
                select(AccessRequest).where(
                    AccessRequest.status == AccessRequestStatus.PENDING,
                    AccessRequest.object_id.in_(chunk),
                )
            ).all()
        )
    rows.sort(key=lambda row: (row.created_at, row.id))
    effective = effective_statuses(session, rows, now=now)
    views: list[ApproverRequestView] = []
    for row in rows:
        if effective[row.id] != AccessRequestStatus.PENDING:
            continue
        catalog_object = session.get(CatalogObject, row.object_id)
        requester = session.get(Principal, row.requester_principal_id)
        if catalog_object is None or requester is None or not requester.active:
            continue
        views.append(_approver_view(row, catalog_object, requester))
        if len(views) >= MAX_APPROVER_QUEUE_ITEMS:
            break
    return tuple(views)


def decide_access_request(
    session: Session,
    context: WriteContext,
    *,
    request_id: str,
    approve: bool,
    approved_ttl_seconds: int | None = None,
) -> AccessRequestCommandResult:
    request = session.get(AccessRequest, request_id)
    if request is None:
        raise CommandNotFound("access request not found")
    now = clock.utcnow()
    # Fail closed against lost approver authorization, deactivated principals
    # and revoked grants alike: the current policy is the only authority.
    policy = policy_for_principal(session, context.principal.id)
    catalog_object = session.get(CatalogObject, request.object_id)
    if (
        _active_principal(session, context) is None
        or catalog_object is None
        or not policy.can(Permission.MANAGE_ACCESS, request.object_id)
    ):
        raise CommandAuthorizationDenied(
            object_id=request.object_id,
            permission=Permission.MANAGE_ACCESS,
        )
    requester = session.get(Principal, request.requester_principal_id)
    if requester is None or not requester.active:
        raise CommandConflict("requesting principal is no longer active")
    effective = effective_statuses(session, [request], now=now)[request.id]
    if effective != AccessRequestStatus.PENDING:
        raise CommandConflict(
            "access request was already decided"
            if request.status != AccessRequestStatus.PENDING
            else "access request window has elapsed"
        )

    approved_expires_at: datetime | None = None
    if approve:
        requester_policy = policy_for_principal(session, requester.id)
        if not requester_policy.can(Permission.DISCOVER, request.object_id):
            # The requester lost visibility after applying; approving would
            # silently restore access an administrator removed. Deny instead.
            raise CommandConflict("requesting principal can no longer discover the object")
        if requester_policy.can(Permission.READ, request.object_id):
            raise CommandConflict("read access is already granted for this object")
        approved_expires_at = _approved_expiry(
            request=request,
            approved_ttl_seconds=approved_ttl_seconds,
            now=now,
        )

    new_status = AccessRequestStatus.APPROVED if approve else AccessRequestStatus.DENIED
    # Claim the request with one guarded UPDATE that also records the outcome:
    # parallel decisions serialize at the database level, exactly one caller
    # transitions it, every concurrent caller conflicts. Everything below runs
    # in the same transaction, so a failure leaves neither a half-decided
    # request nor an orphan grant.
    if not transition_request(
        session,
        request.id,
        expected=AccessRequestStatus.PENDING,
        status=new_status,
        decided_by_principal_id=context.principal.id,
        decided_at=now,
        approved_expires_at=approved_expires_at,
    ):
        raise CommandConflict("access request was already decided")

    if approve:
        # Atomic outcome: one grant plus the request transition plus audit.
        grant = create_object_grant(
            session,
            principal_id=request.requester_principal_id,
            object_id=request.object_id,
            role=Role(request.role),
            scope=GrantScope(request.scope),
            actor_principal_id=context.principal.id,
            channel=context.channel,
            request_id=context.request_id,
            expires_at=approved_expires_at,
        )
        transition_request(
            session,
            request.id,
            expected=AccessRequestStatus.APPROVED,
            grant_id=grant.id,
        )
        add_audit_event(
            session,
            object_id=request.object_id,
            action="access_request_approve",
            actor=context.principal.id,
            details={
                "actor_principal_id": context.principal.id,
                "access_request_id": request.id,
                "target_principal_id": request.requester_principal_id,
                "grant_id": grant.id,
                "approved_expires_at": (
                    approved_expires_at.isoformat() if approved_expires_at else None
                ),
                "shortened": approved_expires_at is not None
                and request.requested_expires_at is not None
                and approved_expires_at < request.requested_expires_at,
                "channel": context.channel,
            },
        )
    else:
        add_audit_event(
            session,
            object_id=request.object_id,
            action="access_request_deny",
            actor=context.principal.id,
            details={
                "actor_principal_id": context.principal.id,
                "access_request_id": request.id,
                "target_principal_id": request.requester_principal_id,
                "channel": context.channel,
            },
        )
    suppress_pending_notices(session, request.id, now=now)
    session.flush()
    session.refresh(request)
    return AccessRequestCommandResult(
        request_id=request.id,
        status=str(new_status),
        changed=True,
    )


def _approved_expiry(
    *,
    request: AccessRequest,
    approved_ttl_seconds: int | None,
    now: datetime,
) -> datetime | None:
    """Approver-side duration shortening.

    Permanent requests may be shortened to temporary. Temporary requests may
    only be shortened; extending beyond the requested window would turn an
    approver into an escalator and is rejected.
    """
    if request.duration == AccessRequestDuration.PERMANENT:
        if approved_ttl_seconds is None:
            return None
        return now + _validate_temporary_duration(approved_ttl_seconds)
    if request.requested_expires_at is None:
        raise CommandConflict("temporary request lost its requested expiry")
    if approved_ttl_seconds is None:
        return request.requested_expires_at
    candidate = now + _validate_temporary_duration(approved_ttl_seconds)
    if candidate > request.requested_expires_at:
        raise CommandConflict("approvers may shorten but never extend a temporary request")
    return candidate


def _pending_request(
    session: Session,
    requester_principal_id: str,
    object_id: str,
) -> AccessRequest | None:
    return session.scalar(
        select(AccessRequest).where(
            AccessRequest.requester_principal_id == requester_principal_id,
            AccessRequest.object_id == object_id,
            AccessRequest.role == Role.VIEWER,
            AccessRequest.scope == GrantScope.SELF,
            AccessRequest.status == AccessRequestStatus.PENDING,
        )
    )


def _requester_view(
    row: AccessRequest,
    effective: AccessRequestStatus,
) -> RequesterRequestView:
    return RequesterRequestView(
        id=row.id,
        object_id=row.object_id,
        role=row.role,
        scope=row.scope,
        duration=row.duration,
        status=effective.value,
        reason=sanitize_reason(row.reason),
        requested_expires_at=format_rfc3339_utc(row.requested_expires_at),
        approved_expires_at=format_rfc3339_utc(row.approved_expires_at),
        grant_id=row.grant_id,
        created_at=format_rfc3339_utc(row.created_at),
    )


def _approver_view(
    row: AccessRequest,
    catalog_object: CatalogObject,
    requester: Principal,
) -> ApproverRequestView:
    return ApproverRequestView(
        id=row.id,
        object_id=row.object_id,
        object_label=catalog_object.label,
        object_kind=catalog_object.kind,
        requester_login=requester.login,
        requester_display_name=requester.display_name,
        role=row.role,
        scope=row.scope,
        duration=row.duration,
        status=AccessRequestStatus.PENDING.value,
        reason=sanitize_reason(row.reason),
        requested_expires_at=format_rfc3339_utc(row.requested_expires_at),
        created_at=format_rfc3339_utc(row.created_at),
    )
