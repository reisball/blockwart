"""Transport adapter contract for agent notice delivery (Issue #106).

The contract is intentionally narrow:

- a transport receives one already data-minimized payload for one job;
- it reports a coarse outcome, never provider or credential details;
- it is not told about transactions: callers never hold a database
  transaction open while a transport runs; and
- no implementation may take freely configurable callback URLs.

Delivery is at-least-once on the wire. The stable ``delivery_id`` is the
receiver-enforced idempotency key: a receiver that has already accepted that
key answers with a *duplicate confirmation*, which Blockwart records as the
prior success (``DeliveryOutcome.duplicate``), not as a failure. A lost
response therefore never produces a second visible notice nor a false
dead-letter.

The only shipped real adapter targets an isolated OpenClaw test gateway. It
refuses every non-loopback destination by construction, never uses an
environment proxy, and never follows a redirect, so CI and tests can exercise
the full path without any productive gateway, agent turn, network, or
credential configuration. Productive transports require a separate design and
approval round.
"""

from __future__ import annotations

import http.client
import json
import math
import os
import socket
import threading
import time
from dataclasses import dataclass
from typing import Any, Protocol
from urllib.parse import urlsplit

_RESPONSE_READ_LIMIT = 4096
DUPLICATE_STATUS = "duplicate"


@dataclass(frozen=True, slots=True)
class DeliveryOutcome:
    """Coarse transport verdict. ``error_code`` uses safe vocabulary only.

    ``duplicate`` is only meaningful with ``ok``: the receiver confirmed that it
    had already accepted this ``delivery_id`` (typically after a lost response).
    """

    ok: bool
    error_code: str | None = None  # transport_timeout | transport_unavailable | rate_limited
    duplicate: bool = False


@dataclass(frozen=True, slots=True)
class DeliveryRequest:
    """Everything one delivery needs; contains no secret material.

    ``delivery_id`` is a stable receiver-enforced idempotency key (one logical
    job = one key across retries). ``target_route`` is the non-secret OpenClaw
    routing identity that lets one gateway distinguish and address targets.
    """

    target_id: str
    target_route: str
    delivery_id: str
    payload: dict[str, Any]


class NoticeTransport(Protocol):
    # Upper bound in seconds for one ``deliver`` call. The delivery lease must
    # outlive it, otherwise a slow-but-live worker would be reclaimed.
    timeout_seconds: float

    def deliver(self, request: DeliveryRequest) -> DeliveryOutcome: ...


class TransportConfigError(RuntimeError):
    """Raised when a transport would leave its bounded envelope."""


def _require_loopback_url(url: str) -> None:
    parsed = urlsplit(url)
    if parsed.scheme != "http":
        raise TransportConfigError("openclaw test gateway requires plain http on loopback")
    host = (parsed.hostname or "").casefold()
    if host not in {"127.0.0.1", "localhost", "::1"}:
        raise TransportConfigError("openclaw test gateway refuses non-loopback destinations")


class _DeadlineConnection(http.client.HTTPConnection):
    """Close the connected socket at the total deadline, including header reads."""

    def __init__(self, host: str, port: int | None, timeout: float) -> None:
        super().__init__(host, port, timeout=timeout)
        self.deadline = time.monotonic() + timeout
        self.expired = threading.Event()
        self.timer: threading.Timer | None = None

    def connect(self) -> None:
        super().connect()
        connected_socket = self.sock

        def expire() -> None:
            self.expired.set()
            try:
                connected_socket.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

        self.timer = threading.Timer(max(0, self.deadline - time.monotonic()), expire)
        self.timer.daemon = True
        self.timer.start()

    def finish(self) -> None:
        if self.timer is not None:
            self.timer.cancel()
        super().close()


def _confirms_duplicate(body: bytes, delivery_id: str) -> bool:
    """Whether a receiver body is the duplicate confirmation for this key."""
    try:
        decoded = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return False
    return (
        isinstance(decoded, dict)
        and decoded.get("status") == DUPLICATE_STATUS
        and decoded.get("delivery_id") == delivery_id
    )


class OpenClawTestGatewayTransport:
    """First OpenClaw delivery route, bound to an isolated test gateway.

    The endpoint is fixed at construction time and must be loopback HTTP.
    The bearer token is supplied by the operator harness; it is never
    persisted by Blockwart, never logged, and never placed into payloads or
    audit rows. This adapter exists so the delivery pipeline is provable end
    to end against a fake/test gateway; it performs no productive delivery.

    Receiver contract: ``2xx`` accepts the delivery. A receiver that already
    accepted the same ``delivery_id`` answers ``409`` (or ``2xx``) with the JSON
    body ``{"status": "duplicate", "delivery_id": "<same id>"}``; that is a
    confirmed prior success. Any other ``409`` is a failure.
    """

    def __init__(
        self,
        *,
        endpoint_url: str,
        timeout_seconds: float = 5.0,
        token: str | None = None,
    ) -> None:
        _require_loopback_url(endpoint_url)
        self._endpoint_url = endpoint_url
        if not math.isfinite(timeout_seconds) or timeout_seconds <= 0:
            raise TransportConfigError("transport timeout must be finite and positive")
        self.timeout_seconds = timeout_seconds
        self._token = token or None

    def deliver(
        self,
        request: DeliveryRequest,
        *,
        token: str | None = None,
    ) -> DeliveryOutcome:
        envelope = {
            "delivery_id": request.delivery_id,
            "target": request.target_route,
            "notice": request.payload,
        }
        body = json.dumps(envelope).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        bearer = token or self._token
        if bearer:
            headers["Authorization"] = f"Bearer {bearer}"
        parsed = urlsplit(self._endpoint_url)
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query
        connection = _DeadlineConnection(parsed.hostname, parsed.port, self.timeout_seconds)
        try:
            # Direct HTTPConnection uses no environment proxy and follows no redirects.
            connection.request("POST", path, body=body, headers=headers)
            response = connection.getresponse()
            response_body = response.read(_RESPONSE_READ_LIMIT)
            if connection.expired.is_set() or time.monotonic() >= connection.deadline:
                return DeliveryOutcome(ok=False, error_code="transport_timeout")
            if 200 <= response.status < 300:
                return DeliveryOutcome(
                    ok=True,
                    duplicate=_confirms_duplicate(response_body, request.delivery_id),
                )
            if response.status == 409 and _confirms_duplicate(response_body, request.delivery_id):
                return DeliveryOutcome(ok=True, duplicate=True)
            if response.status == 429:
                return DeliveryOutcome(ok=False, error_code="rate_limited")
            return DeliveryOutcome(ok=False, error_code="transport_unavailable")
        except TimeoutError:
            return DeliveryOutcome(ok=False, error_code="transport_timeout")
        except Exception:  # noqa: BLE001 - transport boundary stays coarse
            code = "transport_timeout" if connection.expired.is_set() else "transport_unavailable"
            return DeliveryOutcome(ok=False, error_code=code)
        finally:
            connection.finish()


class FakeNoticeTransport:
    """Deterministic in-memory transport for tests and diagnostics.

    It also models an idempotent receiver: the first accepted ``delivery_id``
    becomes one visible delivery, every repeat is answered with a duplicate
    confirmation and never becomes a second visible delivery.
    """

    timeout_seconds = 0.0

    def __init__(self) -> None:
        self.calls: list[DeliveryRequest] = []
        self.visible: list[DeliveryRequest] = []
        self._accepted: set[str] = set()
        self._results: list[DeliveryOutcome | _LostResponse] = []

    def enqueue_result(self, *outcomes: DeliveryOutcome) -> None:
        """Queue verdicts the receiver never acted on (nothing became visible)."""
        self._results.extend(outcomes)

    def enqueue_lost_response(self) -> None:
        """Receiver accepts the delivery but the response never reaches the sender."""
        self._results.append(_LostResponse())

    def deliver(self, request: DeliveryRequest) -> DeliveryOutcome:
        self.calls.append(request)
        queued = self._results.pop(0) if self._results else None
        if isinstance(queued, DeliveryOutcome):
            return queued
        if request.delivery_id in self._accepted:
            return DeliveryOutcome(ok=True, duplicate=True)
        self._accepted.add(request.delivery_id)
        self.visible.append(request)
        if isinstance(queued, _LostResponse):
            return DeliveryOutcome(ok=False, error_code="transport_timeout")
        return DeliveryOutcome(ok=True)


@dataclass(frozen=True, slots=True)
class _LostResponse:
    pass


def build_notice_transport(settings) -> NoticeTransport | None:
    """Build the configured notice transport, or None when unconfigured.

    The endpoint URL is read from settings; the bearer token is read from the
    environment (BLOCKWART_NOTICE_DELIVERY_TOKEN) so it never lands in
    settings, logs, or audit rows. An empty endpoint disables delivery.
    """
    endpoint = getattr(settings, "notice_delivery_endpoint_url", "")
    if not endpoint:
        return None
    token = os.environ.get("BLOCKWART_NOTICE_DELIVERY_TOKEN") or None
    return OpenClawTestGatewayTransport(endpoint_url=endpoint, token=token)
