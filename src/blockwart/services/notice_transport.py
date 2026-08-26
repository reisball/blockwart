"""Transport adapter contract for agent notice delivery (Issue #106).

The contract is intentionally narrow:

- a transport receives one already data-minimized payload for one job;
- it reports a coarse outcome, never provider or credential details; and
- no implementation may take freely configurable callback URLs.

The only shipped real adapter targets an isolated OpenClaw test gateway. It
refuses every non-loopback destination by construction, so CI and tests can
exercise the full path without any productive gateway, agent turn, network,
or credential configuration. Productive transports require a separate design
and approval round.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Protocol
from urllib.parse import urlsplit


@dataclass(frozen=True, slots=True)
class DeliveryOutcome:
    """Coarse transport verdict. ``error_code`` uses safe vocabulary only."""

    ok: bool
    error_code: str | None = None  # transport_timeout | transport_unavailable | rate_limited


@dataclass(frozen=True, slots=True)
class DeliveryRequest:
    """Everything one delivery needs; contains no secret material."""

    target_id: str
    payload: dict[str, Any]


class NoticeTransport(Protocol):
    def deliver(self, request: DeliveryRequest) -> DeliveryOutcome: ...


class TransportConfigError(RuntimeError):
    """Raised when a transport would leave its bounded envelope."""


def _require_loopback_url(url: str) -> None:
    parsed = urlsplit(url)
    if parsed.scheme != "http":
        raise TransportConfigError("openclaw test gateway requires plain http on loopback")
    host = (parsed.hostname or "").casefold()
    if host not in {"127.0.0.1", "localhost", "::1"}:
        raise TransportConfigError(
            "openclaw test gateway refuses non-loopback destinations"
        )


class OpenClawTestGatewayTransport:
    """First OpenClaw delivery route, bound to an isolated test gateway.

    The endpoint is fixed at construction time and must be loopback HTTP.
    The bearer token is passed per call by the operator harness; it is never
    persisted by Blockwart, never logged, and never placed into payloads or
    audit rows. This adapter exists so the delivery pipeline is provable end
    to end against a fake/test gateway; it performs no productive delivery.
    """

    def __init__(self, *, endpoint_url: str, timeout_seconds: float = 5.0) -> None:
        _require_loopback_url(endpoint_url)
        self._endpoint_url = endpoint_url
        self._timeout_seconds = timeout_seconds

    def deliver(
        self,
        request: DeliveryRequest,
        *,
        token: str | None = None,
    ) -> DeliveryOutcome:
        body = json.dumps(request.payload).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        http_request = urllib.request.Request(
            self._endpoint_url,
            data=body,
            headers=headers,
            method="POST",
        )
        try:
            with urllib.request.urlopen(  # noqa: S310 - loopback enforced in constructor
                http_request,
                timeout=self._timeout_seconds,
            ) as response:
                status = getattr(response, "status", 200)
            if 200 <= status < 300:
                return DeliveryOutcome(ok=True)
            return DeliveryOutcome(ok=False, error_code="transport_unavailable")
        except urllib.error.HTTPError as exc:
            if exc.code == 429:
                return DeliveryOutcome(ok=False, error_code="rate_limited")
            return DeliveryOutcome(ok=False, error_code="transport_unavailable")
        except TimeoutError:
            return DeliveryOutcome(ok=False, error_code="transport_timeout")
        except Exception:  # noqa: BLE001 - transport boundary stays coarse
            return DeliveryOutcome(ok=False, error_code="transport_unavailable")


class FakeNoticeTransport:
    """Deterministic in-memory transport for tests and diagnostics."""

    def __init__(self) -> None:
        self.calls: list[DeliveryRequest] = []
        self._results: list[DeliveryOutcome] = []

    def enqueue_result(self, *outcomes: DeliveryOutcome) -> None:
        self._results.extend(outcomes)

    def deliver(self, request: DeliveryRequest) -> DeliveryOutcome:
        self.calls.append(request)
        if self._results:
            return self._results.pop(0)
        return DeliveryOutcome(ok=True)



def build_notice_transport(settings) -> NoticeTransport | None:
    """Build the configured notice transport, or None when unconfigured.

    The endpoint URL is read from settings; the bearer token is read from the
    environment (BLOCKWART_NOTICE_DELIVERY_TOKEN) so it never lands in
    settings, logs, or audit rows. An empty endpoint disables delivery.
    """
    endpoint = getattr(settings, 'notice_delivery_endpoint_url', '')
    if not endpoint:
        return None
    token = os.environ.get('BLOCKWART_NOTICE_DELIVERY_TOKEN') or None
    transport = OpenClawTestGatewayTransport(endpoint_url=endpoint)
    if token:
        original_deliver = transport.deliver

        def deliver_with_token(request: DeliveryRequest) -> DeliveryOutcome:
            return original_deliver(request, token=token)

        transport.deliver = deliver_with_token  # type: ignore[method-assign]
    return transport
