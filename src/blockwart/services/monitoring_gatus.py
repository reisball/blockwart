"""The bounded Gatus pull adapter (``provider="gatus"``).

This adapter satisfies the primary requirement of #177: it reads the **current
Gatus status data** as the preferred source instead of relying only on the
optional push webhook. For every service configured with ``provider="gatus"``
and a ``data.monitoring.gatus.source_url``, the built-in scheduler polls the
Gatus status API and maps the matching endpoint result into a canonical
``MonitoringObservation``.

Security model (mirrors ``monitoring_probe``):

- the target is already resolved and pinned by the domain
  (``resolve_gatus_source_target``); this module never scans a URL, port, or
  path and never follows a redirect;
- the resolved address is validated against the deny-by-default policy before
  any connection;
- DNS is resolved once and every returned address is policy-checked;
- a bounded bearer token is read from the process environment
  (``BLOCKWART_GATUS_TOKEN``) — a secret never lives in catalog data;
- connect and total time, response size, and header count are bounded; the
  JSON body is read once up to a fixed cap and discarded after parsing;
- every outcome collapses to one stable, redacted error code.
"""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from time import monotonic
from typing import TYPE_CHECKING

from blockwart.domain.monitoring import MonitoringObservation
from blockwart.domain.monitoring_policy import pin_address

if TYPE_CHECKING:
    from blockwart.services.monitoring_registry import ProviderCheckRequest

_PROVIDER = "gatus"
_TOKEN_ENV = "BLOCKWART_GATUS_TOKEN"


def probe_gatus_endpoint(request: ProviderCheckRequest) -> MonitoringObservation:
    """Run one bounded GET against the Gatus status API and normalize it.

    Args:
        request: The acquisition request. ``target`` is the Gatus API URL
            resolved by the domain; ``gatus_mapping`` carries the endpoint
            identity to extract.

    Returns:
        A canonical observation: ``healthy`` when the matched endpoint reports
        success, ``down`` when it reports failure, or ``check_error`` when the
        API is unreachable, misconfigured, or the mapping cannot be resolved.
    """
    # Imported lazily to break the module cycle:
    # monitoring_registry -> monitoring_gatus -> monitoring_probe ->
    # monitoring_registry. The probe helpers live in monitoring_probe; loading
    # them here (after module init) mirrors how monitoring_registry imports
    # probe_http_target inside _register_builtin_providers.
    from blockwart.services.monitoring_probe import (
        _elapsed_ms,
        _ProbeFailure,
        _request_status_and_body,
        _resolve,
    )

    checked_at = datetime.now(UTC)
    target = request.target
    if target is None:
        return _error(checked_at, "invalid_target")
    mapping = request.gatus_mapping or {}
    endpoint = mapping.get("endpoint")
    if not endpoint:
        return _error(checked_at, "invalid_target")

    limits = request.limits
    if not limits.policy.enabled:
        return _denied(checked_at)
    if limits.policy.check_scheme(target.scheme) is not None:
        return _denied(checked_at)
    if limits.policy.check_port(target.port) is not None:
        return _denied(checked_at)

    started = monotonic()
    try:
        addresses = _resolve(
            target.host,
            target.port,
            timeout=min(
                limits.connect_timeout_ms / 1000,
                limits.total_timeout_ms / 1000,
            ),
        )
    except TimeoutError:
        return _obs(checked_at, "down", "timeout", _elapsed_ms(started))
    except OSError:
        return _obs(checked_at, "down", "dns_failed", _elapsed_ms(started))

    if limits.policy.check_target(
        scheme=target.scheme, port=target.port, addresses=addresses
    ) is not None:
        return _denied(checked_at)

    pinned = pin_address(addresses)
    if pinned is None:
        return _obs(checked_at, "check_error", "invalid_target", _elapsed_ms(started))

    token = os.environ.get(_TOKEN_ENV)
    try:
        status, body = _request_status_and_body(
            scheme=target.scheme,
            hostname=target.host,
            pinned=pinned,
            port=target.port,
            path=target.path,
            connect_timeout=limits.connect_timeout_ms / 1000,
            total_timeout=limits.total_timeout_ms / 1000,
            max_response_bytes=limits.max_response_bytes,
            authorization=f"Bearer {token}" if token else None,
        )
    except _ProbeFailure as failure:
        return _obs(checked_at, failure.state, failure.error_code, _elapsed_ms(started))

    if status < 200 or status >= 300:
        code = "http_server_error" if status >= 500 else "http_client_error"
        return _obs(checked_at, "check_error", code, _elapsed_ms(started))

    state = _extract_endpoint_state(body, endpoint, group=mapping.get("group"))
    if state is None:
        return _obs(checked_at, "check_error", "invalid_target", _elapsed_ms(started))
    return _obs(checked_at, state, None, _elapsed_ms(started))


def _extract_endpoint_state(body: bytes, endpoint: str, *, group: str | None) -> str | None:
    """Extract the current health state for one endpoint from the statuses JSON.

    The Gatus ``/api/v1/endpoints/statuses`` payload is a JSON array of
    ``{name, group, key, results: [...]}``. The latest ``result`` carries
    ``success``. Returns ``"healthy"``, ``"down"``, or ``None`` when the
    endpoint identity is absent or the payload cannot be parsed.
    """
    try:
        data = json.loads(body)
    except (ValueError, TypeError):
        return None
    if not isinstance(data, list):
        return None
    for entry in data:
        if not isinstance(entry, dict):
            continue
        if entry.get("name") != endpoint:
            continue
        if group is not None and entry.get("group") != group:
            continue
        results = entry.get("results")
        if not isinstance(results, list) or not results:
            return None
        latest = results[-1]
        if not isinstance(latest, dict):
            return None
        success = latest.get("success")
        if success is True:
            return "healthy"
        if success is False:
            return "down"
        return None
    return None


def _obs(
    checked_at: datetime, state: str, error_code: str | None, latency_ms: int
) -> MonitoringObservation:
    return MonitoringObservation(
        provider="gatus",
        state=state,
        checked_at=checked_at,
        latency_ms=latency_ms,
        error_code=error_code,
    )


def _denied(checked_at: datetime) -> MonitoringObservation:
    return MonitoringObservation(
        provider="gatus",
        state="check_error",
        checked_at=checked_at,
        error_code="policy_denied",
    )


def _error(checked_at: datetime, error_code: str) -> MonitoringObservation:
    return MonitoringObservation(
        provider="gatus",
        state="check_error",
        checked_at=checked_at,
        error_code=error_code,
    )
