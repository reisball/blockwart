"""The bounded Gatus pull adapter (``provider="gatus"``).

This adapter satisfies the primary requirement of #177: it reads the **current
Gatus status data** as the preferred source instead of relying only on an
optional push webhook. For every service configured with ``provider="gatus"``
and a complete ``data.monitoring.gatus`` identity, the built-in scheduler reads
the bound Gatus status API and maps the matching endpoint result into a
canonical ``MonitoringObservation``.

Three properties define this adapter.

**It reads a source, not the service.** Every failure while reading Gatus —
DNS, connect, TLS, timeout, HTTP status, framing, parsing, mapping — is a
*source acquisition* failure and is reported as ``check_error``. This adapter
never claims the monitored service is down on evidence it did not obtain. Only
a matched, valid Gatus result maps ``success`` to ``healthy``/``down``.

**It preserves upstream observation time.** The matched result's ``timestamp``
is the instant the observation is evidence for; the poll instant is carried
separately as the acquisition time. Re-reading an unchanged snapshot therefore
cannot refresh evidence or move last success, while acquisition cadence still
advances normally.

**Credentials are source-scoped and runtime-only.** The status URL and the
optional credential *file* are bound by the deployment to the source identity
the service names. The credential value is read at check time, used once, and
never stored, projected, logged, or attached to any other source.

Security model (mirrors ``monitoring_probe``):

- the target is the deployment-bound source URL, already admission-checked;
  this module never scans a URL, port, or path and never follows a redirect;
- the resolved address is validated against the deny-by-default policy before
  any connection, and DNS is resolved once with every answer policy-checked;
- one validated address is pinned for the socket while the original hostname
  supplies the ``Host`` header and the TLS SNI and certificate identity;
- connect and total time, response size, header count, result count, and
  credential size are bounded; the body is discarded after parsing;
- every outcome collapses to one stable, redacted error code.
"""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

from blockwart.domain.monitoring import (
    MAX_UPSTREAM_FUTURE_SKEW_SECONDS,
    MonitoringObservation,
)
from blockwart.domain.monitoring_policy import pin_address

if TYPE_CHECKING:
    from blockwart.services.monitoring_registry import ProviderCheckRequest

_PROVIDER = "gatus"

# A credential file holds one bounded API token. Anything larger is a wrong
# file rather than a token, and is refused without being read into a message.
MAX_CREDENTIAL_BYTES = 4096

# Gatus returns a rolling window of results per endpoint. The published window
# is small; reading beyond this bound would be a payload we do not trust.
MAX_ENDPOINT_RESULTS = 512

# Upstream latency is reported in nanoseconds. A value beyond a day is a broken
# or hostile field rather than a measurement, so it is dropped instead of
# stored.
MAX_UPSTREAM_LATENCY_MS = 86_400_000

_RFC3339_TIMESTAMP = re.compile(
    r"^\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[Zz]|[+-]\d{2}:\d{2})$"
)


def probe_gatus_endpoint(request: ProviderCheckRequest) -> MonitoringObservation:
    """Read one bounded Gatus status snapshot and normalize it.

    Args:
        request: The acquisition request. ``pull_source`` carries the immutable
            source binding and the group/endpoint identity to extract.

    Returns:
        A canonical observation. ``healthy``/``down`` only when a single
        matching endpoint yielded one unambiguous latest valid result;
        ``check_error`` with a stable redacted code for every configuration,
        transport, payload, mapping, or timestamp problem.
    """
    # Imported lazily to break the module cycle:
    # monitoring_registry -> monitoring_gatus -> monitoring_probe ->
    # monitoring_registry. The probe helpers live in monitoring_probe; loading
    # them here (after module init) mirrors how monitoring_registry imports
    # probe_http_target inside _register_builtin_providers.
    from blockwart.services.monitoring_probe import (
        _ProbeFailure,
        _request_status_and_body,
        _resolve,
    )

    received_at = datetime.now(UTC)
    binding = request.pull_source
    if binding is None or not binding.endpoint:
        # The scheduler resolves the binding, so an absent one means the
        # service names no usable source identity for this deployment.
        return _error(received_at, "source_unconfigured")
    source = binding.source

    limits = request.limits
    if not limits.policy.enabled:
        return _error(received_at, "policy_denied")
    if limits.policy.check_scheme(source.scheme) is not None:
        return _error(received_at, "policy_denied")
    if limits.policy.check_port(source.port) is not None:
        return _error(received_at, "policy_denied")

    credential = _read_credential(binding.credential_file)
    if credential is _CREDENTIAL_UNREADABLE:
        # A source that declares a credential must present it. Sending an
        # anonymous request instead would silently downgrade the contract.
        return _error(received_at, "source_unconfigured")

    try:
        addresses = _resolve(
            source.host,
            source.port,
            timeout=min(
                limits.connect_timeout_ms / 1000,
                limits.total_timeout_ms / 1000,
            ),
        )
    except TimeoutError:
        return _error(received_at, "timeout")
    except OSError:
        return _error(received_at, "dns_failed")

    if limits.policy.check_target(
        scheme=source.scheme, port=source.port, addresses=addresses
    ) is not None:
        return _error(received_at, "policy_denied")

    pinned = pin_address(addresses)
    if pinned is None:
        return _error(received_at, "policy_denied")

    try:
        status, body = _request_status_and_body(
            scheme=source.scheme,
            hostname=source.host,
            pinned=pinned,
            port=source.port,
            path=source.path,
            connect_timeout=limits.connect_timeout_ms / 1000,
            total_timeout=limits.total_timeout_ms / 1000,
            max_response_bytes=limits.max_response_bytes,
            authorization=f"Bearer {credential}" if credential else None,
        )
    except _ProbeFailure as failure:
        # A transport failure reaching Gatus says nothing about the monitored
        # service, so the probe's "down" verdict is deliberately not reused.
        return _error(received_at, failure.error_code)

    if status < 200 or status >= 300:
        code = "http_server_error" if status >= 500 else "http_client_error"
        return _error(received_at, code)

    return _observation_from_body(
        body,
        group=binding.group,
        endpoint=binding.endpoint,
        received_at=received_at,
    )


def _observation_from_body(
    body: bytes,
    *,
    group: str,
    endpoint: str,
    received_at: datetime,
) -> MonitoringObservation:
    """Map one Gatus statuses payload to a canonical observation.

    The payload of ``/api/v1/endpoints/statuses`` is a JSON array of
    ``{name, group, results: [...]}``. Selection is by explicit
    ``group`` + ``name`` identity only.
    """

    try:
        parsed = json.loads(body)
    except (ValueError, TypeError):
        return _error(received_at, "source_unreadable")
    if not isinstance(parsed, list):
        return _error(received_at, "source_unreadable")

    matches = [
        entry
        for entry in parsed
        if isinstance(entry, dict)
        and entry.get("name") == endpoint
        and _entry_group(entry) == group
    ]
    if not matches:
        return _error(received_at, "mapping_missing")
    if len(matches) > 1:
        # Two entries answering to one identity make the mapping ambiguous.
        # Picking either would publish a guess as evidence.
        return _error(received_at, "mapping_ambiguous")

    results = matches[0].get("results")
    if not isinstance(results, list) or not results:
        return _error(received_at, "source_unreadable")
    if len(results) > MAX_ENDPOINT_RESULTS:
        return _error(received_at, "source_unreadable")

    latest: datetime | None = None
    candidates: list[dict[str, Any]] = []
    invalid_timestamp = False
    for result in results:
        if not isinstance(result, dict) or not isinstance(result.get("success"), bool):
            continue
        observed_at = _parse_timestamp(result.get("timestamp"))
        if observed_at is None:
            invalid_timestamp = True
            continue
        if observed_at > received_at + timedelta(seconds=MAX_UPSTREAM_FUTURE_SKEW_SECONDS):
            # A materially future observation is a broken or hostile clock. It
            # is never accepted, because storing it would make the evidence
            # look fresh for as long as the skew lasts.
            invalid_timestamp = True
            continue
        if latest is None or observed_at > latest:
            latest = observed_at
            candidates = [result]
        elif observed_at == latest:
            candidates.append(result)

    if latest is None:
        # Every result was unusable. Distinguish a payload we could not read at
        # all from one whose timestamps were invalid or skewed.
        return _error(
            received_at,
            "invalid_observation_time" if invalid_timestamp else "source_unreadable",
        )
    canonical_candidates = {
        (
            bool(result["success"]),
            _bounded_status(result),
            _bounded_latency(result),
        )
        for result in candidates
    }
    if len(canonical_candidates) > 1:
        # Two results share the latest instant but disagree on evidence the
        # canonical contract supports. There is no deterministic winner, so
        # no service-state claim is written.
        return _error(received_at, "mapping_ambiguous")

    success, status, latency_ms = canonical_candidates.pop()
    return MonitoringObservation(
        provider=_PROVIDER,
        state="healthy" if success else "down",
        checked_at=latest,
        received_at=received_at,
        http_status=status,
        latency_ms=latency_ms,
    )


def _entry_group(entry: dict[str, Any]) -> str:
    group = entry.get("group")
    return group if isinstance(group, str) else ""


def _parse_timestamp(value: Any) -> datetime | None:
    """Parse one aware RFC 3339 upstream observation instant.

    A naive, malformed, over-long, or non-string timestamp is rejected: an
    instant without a zone cannot be compared against this server's clock, and
    guessing a zone would silently shift the evidence.
    """

    if not isinstance(value, str) or not 1 <= len(value) <= 64:
        return None
    text = value.strip()
    if _RFC3339_TIMESTAMP.fullmatch(text) is None:
        return None
    if text.endswith(("Z", "z")):
        text = f"{text[:-1]}+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(UTC)


def _bounded_status(result: dict[str, Any]) -> int | None:
    """Read the upstream HTTP status, keeping only a contract-legal value."""

    status = result.get("status")
    if isinstance(status, bool) or not isinstance(status, int):
        return None
    return status if 100 <= status <= 599 else None


def _bounded_latency(result: dict[str, Any]) -> int | None:
    """Convert the upstream nanosecond duration to bounded milliseconds."""

    duration = result.get("duration")
    if isinstance(duration, bool) or not isinstance(duration, int):
        return None
    if duration < 0:
        return None
    latency_ms = duration // 1_000_000
    return latency_ms if latency_ms <= MAX_UPSTREAM_LATENCY_MS else None


class _CredentialUnreadable:
    """Sentinel: a credential was required but could not be obtained."""

    __slots__ = ()


_CREDENTIAL_UNREADABLE = _CredentialUnreadable()


def _read_credential(path: str | None) -> str | None | _CredentialUnreadable:
    """Read one bounded credential from its source-scoped file.

    Returns ``None`` when the source declares no credential, the token when it
    declares a readable one, and the unreadable sentinel otherwise. The value
    is never logged, and no exception text — which could contain the path or
    file contents — is propagated.
    """

    if not path:
        return None
    try:
        with open(path, "rb") as handle:
            raw = handle.read(MAX_CREDENTIAL_BYTES + 1)
    except OSError:
        return _CREDENTIAL_UNREADABLE
    if len(raw) > MAX_CREDENTIAL_BYTES:
        return _CREDENTIAL_UNREADABLE
    try:
        token = raw.decode("utf-8").strip()
    except UnicodeDecodeError:
        return _CREDENTIAL_UNREADABLE
    if not token or any(not 33 <= ord(character) <= 126 for character in token):
        # Only visible ASCII can occupy one Authorization field value. An
        # empty file is a secret that has not been provisioned yet.
        return _CREDENTIAL_UNREADABLE
    return token


def _error(received_at: datetime, error_code: str) -> MonitoringObservation:
    """Build the one shape every acquisition failure collapses to.

    The instant is the poll instant: a failed acquisition is evidence about
    this deployment's check, not about the monitored service, so it carries no
    upstream latency or status.
    """

    return MonitoringObservation(
        provider=_PROVIDER,
        state="check_error",
        checked_at=received_at,
        received_at=received_at,
        error_code=error_code,
    )
