"""Generic outbound access-request notification adapter contract.

Notifications are a separate security domain from authorization.  A notifier
may point authorized approvers at an open request; it can never approve,
never create a grant, and never change a request status.  Notification
failures are recorded as bounded, idempotent attempts on the request row and
leave the request itself untouched.

The payload is deliberately minimal: request id, object id (which the
requester already revealed by applying), status, and a stable reference to
the authenticated Blockwart decision surface.  It never contains the untrusted
request reason, credentials, or hidden object details.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Protocol


class NotificationError(RuntimeError):
    """One notification delivery attempt failed."""


@dataclass(frozen=True, slots=True)
class AccessRequestNotification:
    request_id: str
    object_id: str
    status: str
    decision_reference: str


def build_notification_payload(notification: AccessRequestNotification) -> dict[str, str]:
    """Return the minimal outbound payload without secrets or reasons."""
    return {
        "type": "access_request",
        "request_id": notification.request_id,
        "object_id": notification.object_id,
        "status": notification.status,
        "decision_reference": notification.decision_reference,
    }


class AccessRequestNotifier(Protocol):
    def notify(self, notification: AccessRequestNotification) -> None:
        """Deliver one notification or raise NotificationError."""
        ...


class NullNotifier:
    """Default adapter: no outbound notification is configured."""

    def notify(self, notification: AccessRequestNotification) -> None:
        return None


class WebhookNotifier:
    """POST the minimal payload to one configured HTTP endpoint.

    The endpoint is a pure sink: whatever it replies can never substitute for
    an authenticated Blockwart decision.
    """

    def __init__(self, *, url: str, timeout_seconds: float = 5.0) -> None:
        self._url = url
        self._timeout_seconds = timeout_seconds

    def notify(self, notification: AccessRequestNotification) -> None:
        body = json.dumps(
            build_notification_payload(notification),
            ensure_ascii=False,
            sort_keys=True,
        ).encode("utf-8")
        request = urllib.request.Request(
            self._url,
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self._timeout_seconds) as response:
                if response.status >= 400:
                    raise NotificationError(f"webhook returned {response.status}")
        except urllib.error.URLError as exc:
            raise NotificationError(str(exc)) from exc


_notifier: AccessRequestNotifier = NullNotifier()


def get_access_request_notifier() -> AccessRequestNotifier:
    return _notifier


def set_access_request_notifier(notifier: AccessRequestNotifier) -> None:
    """Install a process-wide adapter. Deployment code only; tests may inject fakes."""
    global _notifier
    _notifier = notifier
