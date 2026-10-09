"""Effective access request state and its explicit write lifecycles (Issue #100).

Two separate ideas live here and must never be mixed up:

* **Projection (read side).** ``effective_statuses`` answers "what state does
  this request have *now*" from the stored row, the grant it created and the
  clock. It is pure: it flushes nothing and appends no audit, so HTTP GET and
  read-only MCP tools can use it without ever writing.
* **Materialization (write side).** ``materialize_lapsed_requests`` and
  ``end_requests_for_grant`` persist an elapsed window or a removed grant, each
  with exactly one audit event, and only inside a write lifecycle that already
  owns a transaction (create, decide, cancel, grant revoke/replace). Every
  transition is a guarded ``UPDATE ... WHERE status = <expected>`` so parallel
  lifecycles produce exactly one winner and one audit event.

The original decision columns (``decided_by``, ``decided_at``,
``approved_expires_at``, ``reason``) are never rewritten by either path.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from datetime import datetime

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from blockwart.domain.access_requests import (
    AccessRequestStatus,
    effective_access_request_status,
)
from blockwart.models import AccessRequest, ObjectGrant
from blockwart.services.audit import add_audit_event

_ENDED_ACTIONS = {
    AccessRequestStatus.EXPIRED: "access_request_expire",
    AccessRequestStatus.REVOKED: "access_request_revoke",
}


def effective_statuses(
    session: Session,
    rows: Sequence[AccessRequest],
    *,
    now: datetime,
) -> dict[str, AccessRequestStatus]:
    """Project the current status of each row. Reads only."""
    grant_ids = {row.grant_id for row in rows if row.grant_id is not None}
    grants: dict[int, ObjectGrant] = {}
    if grant_ids:
        grants = {
            grant.id: grant
            for grant in session.scalars(
                select(ObjectGrant).where(ObjectGrant.id.in_(grant_ids))
            ).all()
        }
    result: dict[str, AccessRequestStatus] = {}
    for row in rows:
        grant = grants.get(row.grant_id) if row.grant_id is not None else None
        result[row.id] = effective_access_request_status(
            status=row.status,
            duration=row.duration,
            requested_expires_at=row.requested_expires_at,
            approved_expires_at=row.approved_expires_at,
            grant_present=(
                grant is not None
                and grant.principal_id == row.requester_principal_id
                and grant.object_id == row.object_id
                and grant.role == row.role
                and grant.scope == row.scope
            ),
            grant_expires_at=grant.expires_at if grant is not None else None,
            now=now,
        )
    return result


def effective_status(
    session: Session,
    row: AccessRequest,
    *,
    now: datetime,
) -> AccessRequestStatus:
    return effective_statuses(session, [row], now=now)[row.id]


def transition_request(
    session: Session,
    request_id: str,
    *,
    expected: AccessRequestStatus,
    **values: object,
) -> bool:
    """Guarded status change; True only for the single winning caller."""
    result = session.execute(
        update(AccessRequest)
        .where(AccessRequest.id == request_id, AccessRequest.status == expected)
        .values(**values)
        .execution_options(synchronize_session=False)
    )
    return result.rowcount == 1


def _end_request(
    session: Session,
    row: AccessRequest,
    *,
    expected: AccessRequestStatus,
    status: AccessRequestStatus,
    ended_at: datetime,
    actor: str,
    cause: str,
) -> bool:
    won = transition_request(
        session,
        row.id,
        expected=expected,
        status=status,
        ended_at=ended_at,
    )
    if not won:
        return False
    add_audit_event(
        session,
        object_id=row.object_id,
        action=_ENDED_ACTIONS[status],
        actor=actor,
        details={
            "access_request_id": row.id,
            "target_principal_id": row.requester_principal_id,
            "grant_id": row.grant_id,
            "from_status": expected.value,
            "cause": cause,
            "ended_at": ended_at.isoformat(),
        },
    )
    session.expire(row)
    return True


def end_requests_for_grant(
    session: Session,
    *,
    grant_id: int,
    status: AccessRequestStatus,
    ended_at: datetime,
    actor: str,
    cause: str,
) -> int:
    """End the approved request(s) whose grant is being revoked or retired.

    Called from the grant lifecycle itself, so a revoked approval is
    persisted at the moment of revocation instead of being inferred later.
    """
    rows = session.scalars(
        select(AccessRequest)
        .where(
            AccessRequest.grant_id == grant_id,
            AccessRequest.status == AccessRequestStatus.APPROVED,
        )
        .order_by(AccessRequest.id)
    ).all()
    ended = 0
    for row in rows:
        if _end_request(
            session,
            row,
            expected=AccessRequestStatus.APPROVED,
            status=status,
            ended_at=ended_at,
            actor=actor,
            cause=cause,
        ):
            ended += 1
    return ended


def materialize_lapsed_requests(
    session: Session,
    *,
    requester_principal_id: str,
    object_ids: Iterable[str] | None = None,
    now: datetime,
    actor: str,
) -> int:
    """Persist elapsed windows and vanished grants of one requester.

    Write lifecycles call this before they decide what is "open", so a stale
    row can never block or confuse a replacement. It is never called from a
    read path.
    """
    statement = select(AccessRequest).where(
        AccessRequest.requester_principal_id == requester_principal_id,
        AccessRequest.status.in_(
            (AccessRequestStatus.PENDING, AccessRequestStatus.APPROVED)
        ),
    )
    if object_ids is not None:
        statement = statement.where(AccessRequest.object_id.in_(list(object_ids)))
    rows = session.scalars(statement.order_by(AccessRequest.id)).all()
    if not rows:
        return 0
    effective = effective_statuses(session, rows, now=now)
    grants = {
        grant.id: grant
        for grant in session.scalars(
            select(ObjectGrant).where(
                ObjectGrant.id.in_([r.grant_id for r in rows if r.grant_id is not None])
            )
        ).all()
    }
    materialized = 0
    for row in rows:
        target = effective[row.id]
        stored = AccessRequestStatus(row.status)
        if target == stored or target not in _ENDED_ACTIONS:
            continue
        if stored == AccessRequestStatus.PENDING:
            ended_at = row.requested_expires_at or now
            cause = "requested_window_elapsed"
        elif target == AccessRequestStatus.REVOKED:
            ended_at = now
            cause = "grant_removed"
        else:
            grant = grants.get(row.grant_id) if row.grant_id is not None else None
            ended_at = (
                grant.expires_at
                if grant is not None and grant.expires_at is not None
                else row.approved_expires_at or now
            )
            cause = "grant_window_elapsed"
        if _end_request(
            session,
            row,
            expected=stored,
            status=target,
            ended_at=ended_at,
            actor=actor,
            cause=cause,
        ):
            materialized += 1
    if materialized:
        session.flush()
    return materialized


def grant_is_lapsed(grant: ObjectGrant, *, now: datetime) -> bool:
    """Whether a stored grant row is an expired temporary grant (inert)."""
    return grant.expires_at is not None and grant.expires_at <= now


def end_requests_for_removed_grant(
    session: Session,
    grant: ObjectGrant,
    *,
    now: datetime,
    actor: str,
) -> int:
    """Persist the end of the approval(s) behind a grant that is being deleted.

    Call before ``session.delete(grant)`` in the same transaction: the foreign
    key clears ``access_requests.grant_id`` on delete, and the end must be
    recorded while the link still exists. Removing an already expired grant is
    ``expired``; removing a live one is ``revoked``.
    """
    lapsed = grant_is_lapsed(grant, now=now)
    return end_requests_for_grant(
        session,
        grant_id=grant.id,
        status=AccessRequestStatus.EXPIRED if lapsed else AccessRequestStatus.REVOKED,
        ended_at=grant.expires_at if lapsed and grant.expires_at else now,
        actor=actor,
        cause="grant_removed_after_expiry" if lapsed else "grant_revoked",
    )


def retire_lapsed_grant(
    session: Session,
    grant: ObjectGrant,
    *,
    now: datetime,
    actor: str,
    cause: str = "replaced_after_expiry",
) -> None:
    """Remove an expired temporary grant row so its assignment can be granted again.

    An expired grant already carries no authority; keeping the row would only
    make the next ``create`` for the same assignment a silent no-op. The
    approved request that created it is ended as ``expired`` first, so its
    history stays attached to the window that really existed, and the grant
    removal is audited with its original identity.
    """
    end_requests_for_grant(
        session,
        grant_id=grant.id,
        status=AccessRequestStatus.EXPIRED,
        ended_at=grant.expires_at or now,
        actor=actor,
        cause=cause,
    )
    add_audit_event(
        session,
        object_id=grant.object_id,
        action="grant_expire",
        actor=actor,
        details={
            "grant_id": grant.id,
            "principal_id": grant.principal_id,
            "role": grant.role,
            "scope": grant.scope,
            "expired_at": grant.expires_at.isoformat() if grant.expires_at else None,
            "cause": cause,
        },
    )
    session.delete(grant)
    session.flush()
