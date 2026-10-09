from __future__ import annotations

from datetime import datetime
from enum import StrEnum


class AccessRequestStatus(StrEnum):
    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    CANCELLED = "cancelled"
    EXPIRED = "expired"
    REVOKED = "revoked"


class AccessRequestDuration(StrEnum):
    TEMPORARY = "temporary"
    PERMANENT = "permanent"


# Honest routing outcome recorded when a request is created. A hint that was
# never routed is ``disabled`` or ``no_route``; only the outbox can ever
# report ``delivered``.
NOTIFICATION_ROUTING_STATES = ("disabled", "no_route", "queued")


def is_access_request_status(value: str) -> bool:
    try:
        AccessRequestStatus(value)
    except ValueError:
        return False
    return True


def effective_access_request_status(
    *,
    status: str,
    duration: str,
    requested_expires_at: datetime | None,
    approved_expires_at: datetime | None,
    grant_present: bool,
    grant_expires_at: datetime | None,
    now: datetime,
) -> AccessRequestStatus:
    """Project the status a request has *now*, without writing anything.

    The stored status only changes through explicit write lifecycles
    (create/decide/cancel/grant revocation). Time and grant removal are
    facts that arrive without a write, so every read answers from this pure
    projection instead of flushing them:

    - a pending temporary request whose requested window has elapsed is
      ``expired`` (it can no longer be approved);
    - an approved request whose grant is gone is ``revoked``;
    - an approved request whose grant, or approved window, has elapsed is
      ``expired``.

    Everything else is the stored status.
    """
    stored = AccessRequestStatus(status)
    if stored == AccessRequestStatus.PENDING:
        if (
            duration == AccessRequestDuration.TEMPORARY
            and requested_expires_at is not None
            and requested_expires_at <= now
        ):
            return AccessRequestStatus.EXPIRED
        return AccessRequestStatus.PENDING
    if stored == AccessRequestStatus.APPROVED:
        if not grant_present:
            return AccessRequestStatus.REVOKED
        window_end = grant_expires_at if grant_expires_at is not None else approved_expires_at
        if window_end is not None and window_end <= now:
            return AccessRequestStatus.EXPIRED
        return AccessRequestStatus.APPROVED
    return stored
