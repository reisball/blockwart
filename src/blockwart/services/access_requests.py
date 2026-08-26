"""Access requests and temporary grants (Issue #100).

One service layer owns the whole request lifecycle so UI, REST API and MCP
share the same request, decision, policy and audit contract:

- Only authenticated active principals apply (the write context guarantees
  authentication; activity is re-checked here).
- A requester must already hold ``discover`` on the target object; without it,
  every error looks exactly like an unknown object, so no hidden existence
  leaks through create, list, or decision paths.
- V1 scope is exactly Viewer on ``self``, temporary or permanent.
- Approval is atomic: request status, exactly one matching grant, and audit
  events commit together; denial and cancellation never create a grant.
- Temporary grants lose effect in the request path once ``expires_at`` has
  passed (see ``services.policy``), independent of process restarts.
- Notifications are outbound-only hints through the adapter contract in
  ``services.access_notifications``; they are bounded, idempotent, and can
  never authorize anything.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from blockwart.domain.access_requests import (
    AccessRequestDuration,
    AccessRequestStatus,
)
from blockwart.domain.auth import GrantScope, Permission, Role
from blockwart.domain.timestamps import format_rfc3339_utc
from blockwart.models import AccessRequest, CatalogObject, Principal
from blockwart.services.access import create_object_grant
from blockwart.services.access_notifications import (
    AccessRequestNotification,
    NotificationError,
    get_access_request_notifier,
)
from blockwart.services.audit import add_audit_event
from blockwart.services.commands import (
    CommandAuthorizationDenied,
    CommandConflict,
    CommandNotFound,
    WriteContext,
)
from blockwart.services.policy import policy_for_principal

# Conservative answers to the open product decisions in Issue #100. They are
# module constants instead of free-form configuration on purpose: approval
# policies stay code-reviewed, and operators adjust them by shipping a change,
# not by editing runtime state.
MIN_TEMPORARY_SECONDS = 5 * 60
MAX_TEMPORARY_SECONDS = 30 * 24 * 60 * 60
MAX_REASON_LENGTH = 500
MAX_OPEN_REQUESTS_PER_REQUESTER = 10
MAX_NOTIFICATION_ATTEMPTS = 3
DECISION_REFERENCE = "/access-requests"

_OPEN_STATUSES = (AccessRequestStatus.PENDING, AccessRequestStatus.APPROVED)


def _utcnow() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


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


def create_access_request(
    session: Session,
    context: WriteContext,
    *,
    object_id: str,
    duration: AccessRequestDuration | str,
    ttl_seconds: int | None,
    reason: str | None,
) -> AccessRequestCommandResult:
    resolved_duration = AccessRequestDuration(duration)
    # Fresh policy: the create decision must reflect grants as they are now.
    policy = policy_for_principal(session, context.principal.id)
    catalog_object = session.get(CatalogObject, object_id)
    if catalog_object is None or not policy.can(Permission.DISCOVER, object_id):
        # Unknown and undiscoverable objects are indistinguishable.
        raise CommandNotFound("catalog object not found")
    if policy.can(Permission.READ, object_id):
        raise CommandConflict("read access is already granted for this object")

    principal = session.get(Principal, context.principal.id)
    if principal is None or not principal.active:
        raise CommandAuthorizationDenied(
            object_id=object_id,
            permission=Permission.DISCOVER,
        )

    requested_expires_at: datetime | None = None
    if resolved_duration == AccessRequestDuration.TEMPORARY:
        requested_expires_at = _utcnow() + _validate_temporary_duration(ttl_seconds)

    sanitized_reason = sanitize_reason(reason)
    existing = _open_request(session, principal.id, object_id)
    if existing is not None:
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
        # A concurrent identical request won the partial unique index.
        session.rollback()
        winner = _open_request(session, principal.id, object_id)
        if winner is None:
            raise
        return AccessRequestCommandResult(
            request_id=winner.id,
            status=str(winner.status),
            changed=False,
        )

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
        },
    )
    session.flush()
    _notify(session, request, context)
    return AccessRequestCommandResult(
        request_id=request.id,
        status=str(request.status),
        changed=True,
    )


def list_my_access_requests(
    session: Session,
    context: WriteContext,
) -> tuple[RequesterRequestView, ...]:
    _expire_due_requests_for_requester(session, context.principal.id)
    rows = session.scalars(
        select(AccessRequest)
        .where(AccessRequest.requester_principal_id == context.principal.id)
        .order_by(AccessRequest.created_at.desc(), AccessRequest.id)
    ).all()
    return tuple(_requester_view(row) for row in rows)


def cancel_access_request(
    session: Session,
    context: WriteContext,
    *,
    request_id: str,
) -> AccessRequestCommandResult:
    request = _visible_own_request(session, context, request_id=request_id)
    if request.status != AccessRequestStatus.PENDING:
        raise CommandConflict("only pending requests can be cancelled")
    request.status = AccessRequestStatus.CANCELLED
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
    return AccessRequestCommandResult(
        request_id=request.id,
        status=str(request.status),
        changed=True,
    )


def list_pending_access_requests(
    session: Session,
    context: WriteContext,
) -> tuple[ApproverRequestView, ...]:
    policy = policy_for_principal(session, context.principal.id)
    manageable_ids = policy.authorized_ids(Permission.MANAGE_ACCESS)
    if not manageable_ids:
        return ()
    _expire_due_requests(session, object_ids=manageable_ids)
    rows = session.scalars(
        select(AccessRequest)
        .where(
            AccessRequest.status == AccessRequestStatus.PENDING,
            AccessRequest.object_id.in_(manageable_ids),
        )
        .order_by(AccessRequest.created_at.asc(), AccessRequest.id)
    ).all()
    views: list[ApproverRequestView] = []
    for row in rows:
        catalog_object = session.get(CatalogObject, row.object_id)
        requester = session.get(Principal, row.requester_principal_id)
        if catalog_object is None or requester is None:
            continue
        views.append(_approver_view(row, catalog_object, requester))
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
    # Fail closed against lost approver authorization, deactivated principals,
    # and revoked grants alike: the current policy is the only authority.
    policy = policy_for_principal(session, context.principal.id)
    catalog_object = session.get(CatalogObject, request.object_id)
    if (
        catalog_object is None
        or not policy.can(Permission.MANAGE_ACCESS, request.object_id)
    ):
        raise CommandAuthorizationDenied(
            object_id=request.object_id,
            permission=Permission.MANAGE_ACCESS,
        )
    requester = session.get(Principal, request.requester_principal_id)
    if requester is None or not requester.active:
        raise CommandConflict("requesting principal is no longer active")

    # Claim the pending status with one guarded UPDATE before any other write:
    # parallel decisions serialize at the database level, exactly one caller
    # transitions the request, every concurrent caller conflicts.
    claimed = session.execute(
        update(AccessRequest)
        .where(
            AccessRequest.id == request_id,
            AccessRequest.status == AccessRequestStatus.PENDING,
        )
        .values(decided_by_principal_id=context.principal.id)
        .execution_options(synchronize_session=False)
    )
    if claimed.rowcount != 1:
        raise CommandConflict("access request was already decided")

    approved_expires_at: datetime | None = None
    if approve:
        approved_expires_at = _approved_expiry(
            session,
            request=request,
            approved_ttl_seconds=approved_ttl_seconds,
        )
        # Atomic outcome: one grant plus the request transition plus audit are
        # written in this transaction with no intermediate committed state.
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
        request.grant_id = grant.id
        request.approved_expires_at = approved_expires_at
        new_status = AccessRequestStatus.APPROVED
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
        new_status = AccessRequestStatus.DENIED
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
    # Finalize the claimed transition with the concrete target status.
    finalized = session.execute(
        update(AccessRequest)
        .where(AccessRequest.id == request_id)
        .values(status=new_status)
        .execution_options(synchronize_session=False)
    )
    if finalized.rowcount != 1:
        raise CommandConflict("access request was already decided")
    request.decided_at = _utcnow()
    request.status = new_status
    session.flush()
    _notify(session, request, context)
    return AccessRequestCommandResult(
        request_id=request.id,
        status=str(new_status),
        changed=True,
    )


def _approved_expiry(
    session: Session,
    *,
    request: AccessRequest,
    approved_ttl_seconds: int | None,
) -> datetime | None:
    """Approver-side duration shortening.

    Permanent requests may be shortened to temporary. Temporary requests may
    only be shortened; extending beyond the requested window would turn an
    approver into an escalator and is rejected.
    """
    if request.duration == AccessRequestDuration.PERMANENT:
        if approved_ttl_seconds is None:
            return None
        return _utcnow() + _validate_temporary_duration(approved_ttl_seconds)
    if request.requested_expires_at is None:
        raise CommandConflict("temporary request lost its requested expiry")
    if approved_ttl_seconds is None:
        return request.requested_expires_at
    candidate = _utcnow() + _validate_temporary_duration(approved_ttl_seconds)
    if candidate > request.requested_expires_at:
        raise CommandConflict("approvers may shorten but never extend a temporary request")
    return candidate


def _expire_due_requests_for_requester(
    session: Session,
    requester_principal_id: str,
) -> None:
    _expire_due_requests(session, requester_principal_id=requester_principal_id)


def _expire_due_requests(
    session: Session,
    *,
    requester_principal_id: str | None = None,
    object_ids: frozenset[str] | set[str] | None = None,
) -> int:
    """Mark approved requests whose grant window has passed as expired."""
    statement = select(AccessRequest).where(
        AccessRequest.status == AccessRequestStatus.APPROVED,
        AccessRequest.approved_expires_at.is_not(None),
        AccessRequest.approved_expires_at <= _utcnow(),
    )
    if requester_principal_id is not None:
        statement = statement.where(
            AccessRequest.requester_principal_id == requester_principal_id
        )
    if object_ids is not None and len(object_ids):
        statement = statement.where(AccessRequest.object_id.in_(object_ids))
    due = session.scalars(statement.order_by(AccessRequest.id)).all()
    for request in due:
        request.status = AccessRequestStatus.EXPIRED
        add_audit_event(
            session,
            object_id=request.object_id,
            action="access_request_expire",
            actor="system",
            details={
                "access_request_id": request.id,
                "expired_at": request.approved_expires_at.isoformat()
                if request.approved_expires_at
                else None,
            },
        )
    if due:
        session.flush()
    return len(due)


def _open_request(
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
            AccessRequest.status.in_(_OPEN_STATUSES),
        )
    )


def _visible_own_request(
    session: Session,
    context: WriteContext,
    *,
    request_id: str,
) -> AccessRequest:
    request = session.get(AccessRequest, request_id)
    if request is None or request.requester_principal_id != context.principal.id:
        raise CommandNotFound("access request not found")
    return request


def _requester_view(row: AccessRequest) -> RequesterRequestView:
    return RequesterRequestView(
        id=row.id,
        object_id=row.object_id,
        role=row.role,
        scope=row.scope,
        duration=row.duration,
        status=row.status,
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
        status=row.status,
        reason=sanitize_reason(row.reason),
        requested_expires_at=format_rfc3339_utc(row.requested_expires_at),
        created_at=format_rfc3339_utc(row.created_at),
    )


def _record_notification_attempt(
    session: Session,
    request: AccessRequest,
    outcome: str,
) -> None:
    if request.notification_attempts < MAX_NOTIFICATION_ATTEMPTS:
        request.notification_attempts += 1
    request.last_notification_at = _utcnow()
    request.last_notification_outcome = outcome[:32]


def _notify(
    session: Session,
    request: AccessRequest,
    context: WriteContext,
) -> None:
    """Best-effort outbound hint through the adapter contract.

    Notification failures never change request status or grants. Attempts are
    bounded by MAX_NOTIFICATION_ATTEMPTS so a broken sink cannot accumulate
    unbounded retries.
    """
    if request.notification_attempts >= MAX_NOTIFICATION_ATTEMPTS:
        return
    try:
        get_access_request_notifier().notify(
            AccessRequestNotification(
                request_id=request.id,
                object_id=request.object_id,
                status=str(request.status),
                decision_reference=DECISION_REFERENCE,
            )
        )
    except NotificationError:
        _record_notification_attempt(session, request, "failed")
    else:
        _record_notification_attempt(session, request, "delivered")
    session.flush()
