"""Vocabulary and payload contract for access request hints (Issue #100).

An access request hint tells one currently authorized approver, through one
admin-approved agent route, that a request is waiting. It is deliberately a
pointer and nothing else:

- it names the request and the object the approver is already allowed to
  manage, plus a *relative* reference to the authenticated Blockwart decision
  surface;
- it never carries the requester's reason, identity, any token, any URL that
  could act, or any object detail beyond the id; and
- following it never approves anything: a decision is only possible through
  an authenticated Blockwart session or token of a principal that holds
  ``manage_access`` on the object at that moment.
"""

from __future__ import annotations

from typing import Any

ACCESS_REQUEST_NOTICE_EVENT = "access_request_pending"
ACCESS_REQUEST_NOTICE_PAYLOAD_VERSION = 1
ACCESS_REQUEST_DECISION_REFERENCE = "/api/v1/access-requests"

# Pending is the only non-terminal state; the others are terminal.
# ``failed`` is the dead-letter state: the attempt or TTL budget is exhausted.
NOTICE_STATUS_VALUES = ("pending", "delivered", "failed", "suppressed", "expired")

NOTICE_ATTEMPT_OUTCOMES = (
    "success",
    "confirmed_duplicate",
    "timeout",
    "unavailable",
    "rate_limited",
    "lease_expired",
)

# Safe, coarse codes only: no provider, URL, credential, session or token text.
NOTICE_ERROR_CODES = (
    "transport_timeout",
    "transport_unavailable",
    "rate_limited",
    "target_inactive",
    "principal_inactive",
    "manage_access_lost",
    "request_not_pending",
    "ttl_expired",
    "attempt_limit_reached",
    "storm_suppressed",
    "delivery_error",
)

# Fixed template. It has no variable part so no requester or catalog text can
# ever reach an agent through it.
ACCESS_REQUEST_NOTICE_MESSAGE = (
    "Eine Zugriffsanfrage wartet auf Entscheidung. "
    "Details und Entscheidung nur ueber die angemeldete Blockwart-Ansicht."
)


def delivery_id_for_notice(notice_id: str) -> str:
    """Globally unique receiver-side idempotency key for one logical notice."""
    return f"access-request-notice-{notice_id}"


def build_access_request_notice_payload(
    *,
    request_id: str,
    object_ref: str,
) -> dict[str, Any]:
    """The closed minimal v1 payload. Consumers must not expect more keys."""
    return {
        "schema_version": ACCESS_REQUEST_NOTICE_PAYLOAD_VERSION,
        "event_type": ACCESS_REQUEST_NOTICE_EVENT,
        "request_id": request_id,
        "object_ref": object_ref,
        "message": ACCESS_REQUEST_NOTICE_MESSAGE,
        "blockwart_reference": ACCESS_REQUEST_DECISION_REFERENCE,
    }
