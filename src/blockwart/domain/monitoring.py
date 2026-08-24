"""Provider-neutral service monitoring contract.

Blockwart separates three concerns that later monitoring solutions must not
re-invent:

- **Configuration** is embedded business data of one ``service`` catalog object
  at ``data.monitoring``.  It selects a provider, an interval, and whether the
  service is monitored at all.  Absent configuration is exactly ``enabled=false``.
- **Target resolution** is a pure function of the service's canonical endpoint
  contract.  It never performs discovery, scanning, or a network call, and it
  reports a stable configuration diagnostic instead of guessing.
- **Observation** is the canonical, vendor-neutral result of one check.  Both
  the built-in HTTP(S) probe and the Gatus pull adapter write the same shape
  through the same ingestion seam and therefore share catalog, UI, REST,
  Agent, MCP, freshness, and maintenance semantics.

Nothing in this module performs I/O.  Acquisition lives behind the narrow
adapter boundary in ``blockwart.services.monitoring_registry``.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from copy import deepcopy
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from typing import Any, Literal
from urllib.parse import quote, urlsplit

from blockwart.domain.asset_state import AssetHealth
from blockwart.domain.interfaces import (
    InterfaceContractError,
    normalize_interface_data,
)
from blockwart.domain.timestamps import format_rfc3339_utc

MonitoringProvider = Literal["builtin_http", "gatus"]
MonitoringState = Literal["unknown", "healthy", "down", "check_error"]
MonitoringFreshness = Literal["pending", "fresh", "stale"]
MonitoringTargetSource = Literal["endpoint_health_url", "derived_health_path"]
MonitoringDiagnostic = Literal[
    "ambiguous_health_url",
    "ambiguous_endpoints",
    "incomplete_endpoint",
    "invalid_endpoints",
    "invalid_health_url",
    "invalid_monitoring_config",
    "missing_gatus_source",
    "no_http_endpoint",
    "unknown_gatus_source",
]
MonitoringErrorCode = Literal[
    "connect_failed",
    "dns_failed",
    "http_client_error",
    "http_server_error",
    "invalid_observation_time",
    "invalid_target",
    "mapping_ambiguous",
    "mapping_missing",
    "policy_denied",
    "probe_failed",
    "redirect_not_supported",
    "response_too_large",
    "source_unconfigured",
    "source_unreadable",
    "timeout",
    "tls_failed",
]

# The provider identity is explicit and closed.  A later provider (for example
# another adapter adds exactly one value here plus one
# adapter registration; no read model, freshness rule, or maintenance rule
# changes with it.
MONITORING_PROVIDER_VALUES: tuple[str, ...] = ("builtin_http", "gatus")
MONITORING_PROVIDERS = frozenset(MONITORING_PROVIDER_VALUES)
DEFAULT_MONITORING_PROVIDER = "builtin_http"

MONITORING_STATE_VALUES: tuple[str, ...] = (
    "unknown",
    "healthy",
    "down",
    "check_error",
)
MONITORING_STATES = frozenset(MONITORING_STATE_VALUES)
MONITORING_FRESHNESS_VALUES: tuple[str, ...] = ("pending", "fresh", "stale")

# The server-wide default interval and the bounds a per-service override may
# use.  They are part of the published contract, not a deployment detail.
DEFAULT_MONITORING_INTERVAL_SECONDS = 300
MIN_MONITORING_INTERVAL_SECONDS = 60
MAX_MONITORING_INTERVAL_SECONDS = 86400

# A pull adapter trusts an upstream observation instant, so it must bound how
# far ahead of this server that instant may be. Anything beyond this window is
# a broken or hostile clock rather than evidence, and is rejected outright.
MAX_UPSTREAM_FUTURE_SKEW_SECONDS = 120
MONITORING_DOCUMENT_KEYS = frozenset({"enabled", "provider", "interval_seconds", "gatus"})

# The Gatus sub-document is closed and complete: all three identity fields are
# required together, so a partial document can never silently match a different
# Gatus entry. ``group`` may be the empty string for Gatus's ungrouped
# endpoints, which keeps "ungrouped" an explicit choice rather than an omission.
GATUS_DOCUMENT_KEYS = frozenset({"source", "group", "endpoint"})
MAX_GATUS_SOURCE_NAME_LENGTH = 32
MAX_GATUS_GROUP_LENGTH = 128
MAX_GATUS_ENDPOINT_LENGTH = 128
_GATUS_SOURCE_NAME = re.compile(r"^[a-z0-9][a-z0-9._-]*$")


def valid_gatus_source_name(value: str) -> bool:
    """Whether ``value`` is a well-formed Gatus source identity.

    The identity is deliberately narrow — lowercase, bounded, and free of any
    URL syntax — so a source name can never smuggle a host, a port, or a path
    into the runtime binding.
    """

    return (
        1 <= len(value) <= MAX_GATUS_SOURCE_NAME_LENGTH
        and _GATUS_SOURCE_NAME.match(value) is not None
    )

# Stable, redacted configuration diagnostics.  They describe the catalog record
# a reader can already see; they never contain a resolver, socket, TLS, or
# upstream error string.
MONITORING_DIAGNOSTIC_VALUES: tuple[str, ...] = (
    "ambiguous_health_url",
    "ambiguous_endpoints",
    "incomplete_endpoint",
    "invalid_endpoints",
    "invalid_health_url",
    "invalid_monitoring_config",
    "no_http_endpoint",
    # Gatus pull configuration. They describe the catalog record and the
    # deployment binding a reader may already see; they never name the bound
    # status URL, its host, or any credential.
    "missing_gatus_source",
    "unknown_gatus_source",
)
MONITORING_DIAGNOSTICS = frozenset(MONITORING_DIAGNOSTIC_VALUES)

# Stable, redacted probe error codes.  Adapters may only report one of these.
MONITORING_ERROR_CODE_VALUES: tuple[str, ...] = (
    "connect_failed",
    "dns_failed",
    "http_client_error",
    "http_server_error",
    "invalid_target",
    "policy_denied",
    "probe_failed",
    "redirect_not_supported",
    "response_too_large",
    "timeout",
    "tls_failed",
    # Pull-source acquisition. A pull adapter reads a third-party status
    # source, so it can fail in ways the built-in probe cannot. None of these
    # is a claim that the monitored service is down: they all say that this
    # deployment could not obtain usable evidence about it.
    "invalid_observation_time",
    "mapping_ambiguous",
    "mapping_missing",
    "source_unconfigured",
    "source_unreadable",
)
MONITORING_ERROR_CODES = frozenset(MONITORING_ERROR_CODE_VALUES)

_HTTP_SCHEMES = frozenset({"http", "https"})
_SCHEME_DEFAULT_PORTS = {"http": 80, "https": 443}
_DERIVED_HEALTH_PATH = "/health"


@dataclass(frozen=True, slots=True)
class MonitoringConfig:
    """The effective monitoring configuration of one service."""

    enabled: bool = False
    provider: str | None = DEFAULT_MONITORING_PROVIDER
    interval_seconds: int | None = DEFAULT_MONITORING_INTERVAL_SECONDS
    # True when the service stores an explicit interval override.  The server
    # default applies otherwise, so changing it moves every non-overriding
    # service without a catalog write.
    interval_overridden: bool = False
    valid: bool = True


@dataclass(frozen=True, slots=True)
class MonitoringTarget:
    """One deterministically resolved, bounded HTTP(S) GET target."""

    url: str
    scheme: str
    host: str
    port: int
    path: str
    source: MonitoringTargetSource
    endpoint_id: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "scheme": self.scheme,
            "host": self.host,
            "port": self.port,
            "path": self.path,
            "source": self.source,
            "endpoint_id": self.endpoint_id,
        }


@dataclass(frozen=True, slots=True)
class ParsedHttpUrl:
    """One bounded, admission-checked HTTP(S) URL split into its socket parts."""

    url: str
    scheme: str
    host: str
    port: int
    path: str


@dataclass(frozen=True, slots=True)
class MonitoringTargetResolution:
    target: MonitoringTarget | None
    diagnostic: MonitoringDiagnostic | None = None


@dataclass(frozen=True, slots=True)
class GatusMapping:
    """The stable Gatus identity one service declares in catalog data.

    It is deliberately an *identity*, never a location: ``source`` names a
    deployment-bound status source, and ``group``/``endpoint`` name one entry
    inside it. No URL, host, port, or credential is expressible here, so
    catalog data can never choose which host receives a credential.

    ``group`` may be the empty string, which selects Gatus's ungrouped
    endpoints explicitly rather than by omission.
    """

    source: str
    group: str
    endpoint: str


@dataclass(frozen=True, slots=True)
class GatusMappingResolution:
    mapping: GatusMapping | None
    diagnostic: MonitoringDiagnostic | None = None


@dataclass(frozen=True, slots=True)
class MonitoringObservation:
    """One canonical, provider-neutral observation.

    Every provider produces exactly this shape.  ``provider`` is the explicit
    identity of the adapter that acquired it, so two providers can observe the
    same service without overwriting each other.

    Two instants are distinguished on purpose:

    - ``checked_at`` is the instant this observation is **evidence for**. A
      probing adapter checks the service itself, so it is the probe instant.
      A pull adapter reads evidence a third-party source produced earlier, so
      it is that upstream observation instant — never the poll instant. This
      is the value freshness is computed from, so re-reading an old upstream
      snapshot can never present it as a current claim.
    - ``received_at`` is the instant **this deployment acquired** the evidence.
      It only ever drives acquisition cadence, so an old upstream snapshot
      cannot make a service permanently due and produce a tight polling loop.
      It defaults to ``checked_at``, which is exactly right for an adapter that
      observes and acquires in the same step.
    """

    provider: str
    state: MonitoringState
    checked_at: datetime
    http_status: int | None = None
    latency_ms: int | None = None
    error_code: MonitoringErrorCode | None = None
    received_at: datetime | None = None

    @property
    def acquired_at(self) -> datetime:
        """The acquisition instant, defaulting to the observation instant."""

        return self.received_at if self.received_at is not None else self.checked_at

    def __post_init__(self) -> None:
        if self.provider not in MONITORING_PROVIDERS:
            raise ValueError("unknown monitoring provider")
        if self.state not in MONITORING_STATES:
            raise ValueError("unknown monitoring state")
        if self.error_code is not None and self.error_code not in MONITORING_ERROR_CODES:
            raise ValueError("unknown monitoring error code")
        if self.http_status is not None and not 100 <= self.http_status <= 599:
            raise ValueError("http status is out of range")
        if self.latency_ms is not None and self.latency_ms < 0:
            raise ValueError("latency must not be negative")
        if self.state == "healthy" and self.error_code is not None:
            raise ValueError("a healthy observation cannot carry an error code")
        if self.state == "check_error" and self.error_code is None:
            raise ValueError("a check error observation requires an error code")


@dataclass(frozen=True, slots=True)
class MonitoringRecord:
    """The persisted observation state of one service/provider pair.

    ``last_checked_at`` is the stored evidence instant and ``last_received_at``
    the stored acquisition instant; they are equal for every adapter that
    observes what it acquires. ``last_received_at`` is nullable because rows
    written before the pull contract existed only ever carried one instant.
    """

    provider: str
    state: MonitoringState
    http_status: int | None
    latency_ms: int | None
    error_code: str | None
    last_checked_at: datetime | None
    last_success_at: datetime | None
    next_due_at: datetime | None
    object_instance_id: str | None = None
    last_received_at: datetime | None = None

    @property
    def acquired_at(self) -> datetime | None:
        """The acquisition instant, falling back to the evidence instant."""

        return self.last_received_at or self.last_checked_at


def read_monitoring_config(
    data: Mapping[str, Any],
    *,
    default_interval_seconds: int = DEFAULT_MONITORING_INTERVAL_SECONDS,
) -> MonitoringConfig:
    """Read one service's effective monitoring configuration.

    An absent document is the backward-compatible disabled configuration.
    A present malformed document is instead an explicit invalid configuration:
    it receives no provider or interval fallback and can never become probe
    work. Reads remain total for legacy or hand-edited database rows.
    """

    if "monitoring" not in data:
        return MonitoringConfig(
            interval_seconds=_bounded_interval(default_interval_seconds),
        )
    document = data.get("monitoring")
    enabled = isinstance(document, Mapping) and document.get("enabled") is True
    if not isinstance(document, Mapping) or not _valid_monitoring_document(document):
        return MonitoringConfig(
            enabled=enabled,
            provider=None,
            interval_seconds=None,
            valid=False,
        )
    provider = document.get("provider", DEFAULT_MONITORING_PROVIDER)
    assert isinstance(provider, str)
    raw_interval = document.get("interval_seconds")
    overridden = raw_interval is not None
    interval = (
        int(raw_interval)
        if overridden
        else _bounded_interval(default_interval_seconds)
    )
    return MonitoringConfig(
        enabled=enabled,
        provider=provider,
        interval_seconds=interval,
        interval_overridden=overridden,
    )


def normalize_service_monitoring(data: Mapping[str, Any]) -> dict[str, Any]:
    """Return data with a canonical monitoring document.

    An absent document stays absent, so every existing service record remains
    byte-for-byte identical after an upgrade.  A present document is left
    structurally intact for the schema validator to reject with an exact field
    path; only ``provider`` whitespace is trimmed.
    """

    normalized = deepcopy(dict(data))
    document = normalized.get("monitoring")
    if not isinstance(document, dict):
        return normalized
    provider = document.get("provider")
    if isinstance(provider, str):
        document["provider"] = provider.strip()
    gatus = document.get("gatus")
    if isinstance(gatus, dict):
        for key in ("source", "group", "endpoint"):
            value = gatus.get(key)
            if isinstance(value, str):
                gatus[key] = value.strip()
    return normalized


def service_monitoring_violations(
    data: Mapping[str, Any],
) -> tuple[tuple[str, str], ...]:
    """Return ``(path, message)`` violations after declarative field checks."""

    document = data.get("monitoring")
    if document is None or not isinstance(document, Mapping):
        return ()
    if "enabled" not in document:
        return (
            (
                "data.monitoring.enabled",
                "is required when data.monitoring is present",
            ),
        )
    gatus = document.get("gatus")
    if document.get("provider") == "gatus" and not isinstance(gatus, Mapping):
        return (
            (
                "data.monitoring.gatus",
                "is required when data.monitoring.provider is gatus",
            ),
        )
    if isinstance(gatus, Mapping):
        for key in sorted(GATUS_DOCUMENT_KEYS):
            if key not in gatus:
                return (
                    (
                        f"data.monitoring.gatus.{key}",
                        "is required when data.monitoring.gatus is present",
                    ),
                )
    return ()


def resolve_monitoring_target(
    data: Mapping[str, Any],
    *,
    object_id: str = "<service>",
) -> MonitoringTargetResolution:
    """Resolve exactly one effective target from the canonical endpoints.

    The precedence is fixed:

    1. an explicit canonical endpoint ``health_url``;
    2. otherwise a derived ``/health`` path, and only when exactly one suitable
       HTTP(S) endpoint provides a complete origin and port.

    Anything ambiguous or incomplete produces a stable diagnostic.  This
    function never resolves DNS, opens a socket, or probes a path.
    """

    try:
        normalized = normalize_interface_data(
            dict(data),
            kind="service",
            object_id=object_id,
            allow_legacy=True,
        ).data
    except InterfaceContractError:
        return MonitoringTargetResolution(None, "invalid_endpoints")

    endpoints = [
        endpoint
        for endpoint in normalized.get("endpoints", [])
        if isinstance(endpoint, Mapping)
    ]

    declared = [
        endpoint
        for endpoint in endpoints
        if isinstance(endpoint.get("health_url"), str)
        and endpoint["health_url"].strip()
    ]
    if len(declared) > 1:
        return MonitoringTargetResolution(None, "ambiguous_health_url")
    if declared:
        parsed = [
            (endpoint, _parse_health_url(str(endpoint["health_url"])))
            for endpoint in declared
        ]
        if any(target is None for _, target in parsed):
            return MonitoringTargetResolution(None, "invalid_health_url")
        endpoint, target = parsed[0]
        assert target is not None
        return MonitoringTargetResolution(
            MonitoringTarget(
                url=target.url,
                scheme=target.scheme,
                host=target.host,
                port=target.port,
                path=target.path,
                source="endpoint_health_url",
                endpoint_id=str(endpoint.get("id") or ""),
            )
        )

    http_endpoints = [
        endpoint
        for endpoint in endpoints
        if str(endpoint.get("protocol") or "").lower() in _HTTP_SCHEMES
    ]
    if not http_endpoints:
        return MonitoringTargetResolution(None, "no_http_endpoint")
    if any(_endpoint_origin(endpoint) is None for endpoint in http_endpoints):
        return MonitoringTargetResolution(None, "incomplete_endpoint")
    if len(http_endpoints) != 1:
        return MonitoringTargetResolution(None, "ambiguous_endpoints")
    endpoint = http_endpoints[0]
    origin = _endpoint_origin(endpoint)
    assert origin is not None
    scheme, host, port = origin
    return MonitoringTargetResolution(
        MonitoringTarget(
            url=f"{scheme}://{_authority(host, port, scheme)}{_DERIVED_HEALTH_PATH}",
            scheme=scheme,
            host=host,
            port=port,
            path=_DERIVED_HEALTH_PATH,
            source="derived_health_path",
            endpoint_id=str(endpoint.get("id") or ""),
        )
    )



def read_gatus_mapping(
    data: Mapping[str, Any],
    *,
    object_id: str = "<service>",
) -> GatusMappingResolution:
    """Read the Gatus identity one service declares, or a stable diagnostic.

    This is the Gatus counterpart to ``resolve_monitoring_target`` and it is
    deliberately *not* a target resolution: catalog data names a source, a
    group, and an endpoint, and the deployment — not the catalog — decides
    which status URL and which credential that source identity binds to.

    Args:
        data: The service's catalog data document.
        object_id: The service id, accepted for signature symmetry with
            ``resolve_monitoring_target``; it never appears in a diagnostic.

    Returns:
        The complete bounded identity, or ``missing_gatus_source`` when the
        document is absent, malformed, or incomplete. Any incomplete identity
        fails closed rather than matching a Gatus entry by omission.
    """

    del object_id
    document = data.get("monitoring") if isinstance(data, Mapping) else None
    gatus = document.get("gatus") if isinstance(document, Mapping) else None
    if not isinstance(gatus, Mapping):
        return GatusMappingResolution(None, "missing_gatus_source")
    if set(gatus) != GATUS_DOCUMENT_KEYS:
        return GatusMappingResolution(None, "missing_gatus_source")
    source = gatus.get("source")
    group = gatus.get("group")
    endpoint = gatus.get("endpoint")
    if not isinstance(source, str) or not isinstance(group, str):
        return GatusMappingResolution(None, "missing_gatus_source")
    if not isinstance(endpoint, str):
        return GatusMappingResolution(None, "missing_gatus_source")
    source = source.strip()
    endpoint = endpoint.strip()
    if not valid_gatus_source_name(source) or not endpoint:
        return GatusMappingResolution(None, "missing_gatus_source")
    if len(endpoint) > MAX_GATUS_ENDPOINT_LENGTH or len(group) > MAX_GATUS_GROUP_LENGTH:
        return GatusMappingResolution(None, "missing_gatus_source")
    return GatusMappingResolution(
        GatusMapping(source=source, group=group.strip(), endpoint=endpoint)
    )


def freshness_for(
    record: MonitoringRecord | None,
    *,
    interval_seconds: int,
    now: datetime,
    expires_at: datetime | None = None,
) -> MonitoringFreshness:
    """Classify how current a stored observation is.

    Freshness is a statement about the **evidence**, never about how recently
    this deployment ran a check. ``expires_at`` names the instant the evidence
    stops being current; callers that separate acquisition cadence from
    evidence age pass it explicitly. Without it the stored due time — which
    equals the evidence expiry for every adapter that observes what it
    acquires — is used.
    """

    if record is None or record.last_checked_at is None:
        return "pending"
    due = expires_at or record.next_due_at
    if due is None:
        due = record.last_checked_at + timedelta(seconds=interval_seconds)
    if _aware(now) > _aware(due):
        return "stale"
    return "fresh"


def scheduled_next_due(
    checked_at: datetime,
    *,
    object_id: str,
    object_instance_id: str | None,
    provider: str,
    interval_seconds: int,
    jitter_seconds: int,
) -> datetime:
    """Return the stable due time for one observation and current interval.

    Jitter is derived from immutable observation identity instead of process
    randomness. Every process therefore reconciles an interval change to the
    same value, including after restart, while still spreading checks over the
    configured bounded window.
    """

    checked = _aware(checked_at)
    key = "\x1f".join(
        (
            object_id,
            object_instance_id or "",
            provider,
            checked.astimezone(UTC).isoformat(timespec="microseconds"),
        )
    )
    jitter = _stable_jitter(key, jitter_seconds)
    return checked + timedelta(seconds=interval_seconds + jitter)


def effective_state(
    record: MonitoringRecord | None,
    freshness: MonitoringFreshness,
) -> MonitoringState:
    """Return the state a reader may rely on right now.

    A pending or stale observation is deliberately ``unknown``: an old result
    must never be published as a current claim about the service.
    """

    if record is None or freshness in {"pending", "stale"}:
        return "unknown"
    return record.state


def effective_health(
    *,
    catalog_health: str | None,
    enabled: bool,
    state: MonitoringState,
) -> AssetHealth | None:
    """Combine manual catalog health with the effective observation.

    Manual ``maintenance`` always wins, so an operator can silence a monitored
    service without losing its last observation. A pending, stale, or
    diagnostic check is effective ``unknown`` rather than copying a manual
    healthy/down claim into automated state.
    """

    manual = catalog_health if catalog_health in {
        "unknown",
        "healthy",
        "degraded",
        "down",
        "maintenance",
    } else None
    if manual == "maintenance":
        return "maintenance"
    if not enabled:
        return manual
    if state == "healthy":
        return "healthy"
    if state == "down":
        return "down"
    return "unknown"


def monitoring_view(
    *,
    data: Mapping[str, Any],
    object_id: str,
    catalog_health: str | None,
    record: MonitoringRecord | None,
    now: datetime,
    default_interval_seconds: int = DEFAULT_MONITORING_INTERVAL_SECONDS,
    jitter_seconds: int = 0,
    known_gatus_sources: frozenset[str] = frozenset(),
) -> dict[str, Any]:
    """Build the one authorized monitoring projection every surface shares.

    The result contains only provider-neutral fields.  A vendor-specific
    payload never reaches this projection, so adding a provider cannot change
    the published read contract.

    ``known_gatus_sources`` names the status sources this deployment binds. It
    is used only to report the ``unknown_gatus_source`` configuration
    diagnostic; the bound URL, its host, and its credential are deployment
    state and never enter the projection.
    """

    config = read_monitoring_config(
        data,
        default_interval_seconds=default_interval_seconds,
    )
    if not config.valid:
        return {
            "enabled": config.enabled,
            "provider": None,
            "interval_seconds": None,
            "interval_overridden": False,
            "target": None,
            "diagnostic": "invalid_monitoring_config",
            "state": "check_error",
            "observed_state": "unknown",
            "freshness": "pending",
            "http_status": None,
            "latency_ms": None,
            "error_code": None,
            "last_checked_at": None,
            "last_received_at": None,
            "last_success_at": None,
            "next_due_at": None,
            "effective_health": effective_health(
                catalog_health=catalog_health,
                enabled=config.enabled,
                state="check_error",
            ),
        }
    assert config.provider is not None
    assert config.interval_seconds is not None
    if config.provider == "gatus":
        # A pull provider observes through a deployment-bound status source.
        # Publishing that source's URL would expose a private instance
        # endpoint to every reader of the service, so the projection carries
        # the configuration diagnostic and no target at all.
        target = None
        diagnostic = _gatus_diagnostic(data, known_gatus_sources)
    else:
        resolution = resolve_monitoring_target(data, object_id=object_id)
        target = resolution.target.as_dict() if resolution.target else None
        diagnostic = resolution.diagnostic
    matching = record if record is not None and record.provider == config.provider else None
    evidence_expires_at: datetime | None = None
    if matching is not None and matching.last_checked_at is not None:
        # Evidence expiry follows the instant the observation is evidence for,
        # so an old upstream snapshot goes stale on schedule no matter how
        # often this deployment re-reads it.
        evidence_expires_at = scheduled_next_due(
            matching.last_checked_at,
            object_id=object_id,
            object_instance_id=matching.object_instance_id,
            provider=config.provider,
            interval_seconds=config.interval_seconds,
            jitter_seconds=jitter_seconds,
        )
        # The published due time is the acquisition schedule, which follows the
        # instant this deployment last acquired evidence. The two coincide for
        # every adapter that observes what it acquires.
        acquired_at = matching.acquired_at
        assert acquired_at is not None
        matching = MonitoringRecord(
            provider=matching.provider,
            state=matching.state,
            http_status=matching.http_status,
            latency_ms=matching.latency_ms,
            error_code=matching.error_code,
            last_checked_at=matching.last_checked_at,
            last_success_at=matching.last_success_at,
            next_due_at=scheduled_next_due(
                acquired_at,
                object_id=object_id,
                object_instance_id=matching.object_instance_id,
                provider=config.provider,
                interval_seconds=config.interval_seconds,
                jitter_seconds=jitter_seconds,
            ),
            object_instance_id=matching.object_instance_id,
            last_received_at=matching.last_received_at,
        )
    freshness = freshness_for(
        matching,
        interval_seconds=config.interval_seconds,
        now=now,
        expires_at=evidence_expires_at,
    )
    state = effective_state(matching, freshness)
    return {
        "enabled": config.enabled,
        "provider": config.provider,
        "interval_seconds": config.interval_seconds,
        "interval_overridden": config.interval_overridden,
        "target": target,
        "diagnostic": diagnostic,
        "state": state,
        "observed_state": matching.state if matching is not None else "unknown",
        "freshness": freshness,
        "http_status": matching.http_status if matching is not None else None,
        "latency_ms": matching.latency_ms if matching is not None else None,
        "error_code": matching.error_code if matching is not None else None,
        "last_checked_at": format_rfc3339_utc(
            matching.last_checked_at if matching is not None else None
        ),
        "last_received_at": format_rfc3339_utc(
            matching.acquired_at if matching is not None else None
        ),
        "last_success_at": format_rfc3339_utc(
            matching.last_success_at if matching is not None else None
        ),
        "next_due_at": format_rfc3339_utc(
            matching.next_due_at if matching is not None else None
        ),
        "effective_health": effective_health(
            catalog_health=catalog_health,
            enabled=config.enabled,
            state=state,
        ),
    }


def _gatus_diagnostic(
    data: Mapping[str, Any],
    known_gatus_sources: frozenset[str],
) -> MonitoringDiagnostic | None:
    resolution = read_gatus_mapping(data)
    if resolution.mapping is None:
        return resolution.diagnostic
    if resolution.mapping.source not in known_gatus_sources:
        return "unknown_gatus_source"
    return None


def service_monitoring_contract_projection() -> dict[str, Any]:
    """Publish the machine-readable monitoring contract."""

    return {
        "storage_path": "data.monitoring",
        "absent_configuration": "disabled",
        "providers": list(MONITORING_PROVIDER_VALUES),
        "default_provider": DEFAULT_MONITORING_PROVIDER,
        "states": list(MONITORING_STATE_VALUES),
        "freshness": list(MONITORING_FRESHNESS_VALUES),
        "diagnostics": list(MONITORING_DIAGNOSTIC_VALUES),
        "error_codes": list(MONITORING_ERROR_CODE_VALUES),
        "interval_seconds": {
            "default": DEFAULT_MONITORING_INTERVAL_SECONDS,
            "minimum": MIN_MONITORING_INTERVAL_SECONDS,
            "maximum": MAX_MONITORING_INTERVAL_SECONDS,
            "server_default_configurable": True,
        },
        "target_resolution": {
            "precedence": ["endpoint_health_url", "derived_health_path"],
            "derived_path": _DERIVED_HEALTH_PATH,
            "requires_single_complete_http_endpoint": True,
            "discovery_or_scanning": False,
        },
        "observation_time": {
            "observed_at_field": "last_checked_at",
            "received_at_field": "last_received_at",
            "freshness_follows": "last_checked_at",
            "acquisition_cadence_follows": "last_received_at",
            "upstream_observation_time_preserved": True,
            "max_future_skew_seconds": MAX_UPSTREAM_FUTURE_SKEW_SECONDS,
        },
        "probe": {
            "methods": ["GET"],
            "schemes": sorted(_HTTP_SCHEMES),
            "authenticated": False,
            "redirects_followed": False,
            "response_body_stored": False,
            "allowlist": "deny_by_default",
        },
        "pull_sources": {
            "gatus": {
                "identity_path": "data.monitoring.gatus",
                "identity_fields": sorted(GATUS_DOCUMENT_KEYS),
                "source_url_in_catalog_data": False,
                "credential_in_catalog_data": False,
                "credential_binding": "deployment_source_scoped_file",
                "source_url_published": False,
            }
        },
        "result_semantics": {
            "2xx": "healthy",
            "3xx": "check_error",
            "4xx": "check_error",
            "5xx": "down",
            "timeout": "down",
            "connect_failure": "down",
            "tls_failure": "down",
            "policy_denied": "check_error",
            "missing_or_invalid_configuration": "check_error",
            "before_first_check": "unknown",
            "overdue": "unknown",
        },
        "maintenance_precedence": True,
        "inheritance": {
            "visibility": True,
            "rbac": True,
            "advances_object_revision": False,
            "advances_business_updated_at": False,
            "object_audit_per_check": False,
        },
    }


def _bounded_interval(value: int) -> int:
    return max(
        MIN_MONITORING_INTERVAL_SECONDS,
        min(MAX_MONITORING_INTERVAL_SECONDS, int(value)),
    )


def _valid_monitoring_document(document: Mapping[str, Any]) -> bool:
    if not set(document).issubset(MONITORING_DOCUMENT_KEYS):
        return False
    if not isinstance(document.get("enabled"), bool):
        return False
    provider = document.get("provider", DEFAULT_MONITORING_PROVIDER)
    if not isinstance(provider, str) or provider not in MONITORING_PROVIDERS:
        return False
    if "gatus" in document and not _valid_gatus_document(document["gatus"]):
        return False
    if "interval_seconds" not in document:
        return True
    interval = document.get("interval_seconds")
    return (
        isinstance(interval, int)
        and not isinstance(interval, bool)
        and MIN_MONITORING_INTERVAL_SECONDS
        <= interval
        <= MAX_MONITORING_INTERVAL_SECONDS
    )


def _valid_gatus_document(value: Any) -> bool:
    """Whether a stored Gatus sub-document is complete and in bounds.

    A hand-edited or legacy row with a malformed sub-document is an explicit
    invalid configuration rather than a partially usable one, so it can never
    become probe work.
    """

    if not isinstance(value, Mapping) or set(value) != GATUS_DOCUMENT_KEYS:
        return False
    source = value.get("source")
    group = value.get("group")
    endpoint = value.get("endpoint")
    if not isinstance(source, str) or not isinstance(group, str):
        return False
    if not isinstance(endpoint, str):
        return False
    return (
        valid_gatus_source_name(source.strip())
        and bool(endpoint.strip())
        and len(endpoint) <= MAX_GATUS_ENDPOINT_LENGTH
        and len(group) <= MAX_GATUS_GROUP_LENGTH
    )


def _stable_jitter(key: str, jitter_seconds: int) -> int:
    if jitter_seconds <= 0:
        return 0
    digest = sha256(key.encode("utf-8")).digest()
    return int.from_bytes(digest[:8], "big") % (jitter_seconds + 1)


def _endpoint_origin(endpoint: Mapping[str, Any]) -> tuple[str, str, int] | None:
    scheme = str(endpoint.get("protocol") or "").lower()
    if scheme not in _HTTP_SCHEMES:
        return None
    host = endpoint.get("host")
    if not isinstance(host, str) or not _is_plain_host(host):
        return None
    canonical_host = _canonical_host(host)
    if canonical_host is None:
        return None
    port = endpoint.get("port")
    if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
        return None
    return scheme, canonical_host, port


def parse_bounded_http_url(value: str) -> ParsedHttpUrl | None:
    """Parse one bounded HTTP(S) URL, or return ``None`` when it is unusable.

    This is the single URL admission rule Blockwart applies before any outbound
    monitoring connection. It rejects a non-HTTP scheme, userinfo, a fragment,
    a control character, an over-long value, an embedded port in the host, and
    any host that is not a canonical DNS name or IP literal. It never performs
    DNS, opens a socket, or contacts the URL.

    Both the endpoint ``health_url`` contract and the deployment-bound Gatus
    status sources use it, so a catalog-declared URL and an operator-declared
    URL are admitted under exactly the same rule.
    """

    if len(value) > 512 or any(ord(character) < 32 or ord(character) == 127 for character in value):
        return None
    try:
        parsed = urlsplit(value.strip())
    except ValueError:
        return None
    scheme = (parsed.scheme or "").lower()
    if scheme not in _HTTP_SCHEMES:
        return None
    if parsed.username or parsed.password or parsed.fragment:
        return None
    hostname = parsed.hostname
    if not hostname or not _is_plain_host(hostname):
        return None
    try:
        port = parsed.port
    except ValueError:
        return None
    if port is None:
        port = _SCHEME_DEFAULT_PORTS[scheme]
    if not 1 <= port <= 65535:
        return None
    host = _canonical_host(hostname)
    if host is None:
        return None
    path = quote(parsed.path or "/", safe="/%:@!$&'()*+,;=-._~")
    if not path.startswith("/"):
        return None
    encoded_query = quote(parsed.query, safe="%:@!$&'()*+,;=/?-._~")
    query = f"?{encoded_query}" if encoded_query else ""
    return ParsedHttpUrl(
        url=f"{scheme}://{_authority(host, port, scheme)}{path}{query}",
        scheme=scheme,
        host=host,
        port=port,
        path=f"{path}{query}",
    )


def _parse_health_url(value: str) -> MonitoringTarget | None:
    parsed = parse_bounded_http_url(value)
    if parsed is None:
        return None
    return MonitoringTarget(
        url=parsed.url,
        scheme=parsed.scheme,
        host=parsed.host,
        port=parsed.port,
        path=parsed.path,
        source="endpoint_health_url",
        endpoint_id="",
    )


def _authority(host: str, port: int, scheme: str) -> str:
    rendered = f"[{host}]" if ":" in host else host
    if _SCHEME_DEFAULT_PORTS[scheme] == port:
        return rendered
    return f"{rendered}:{port}"


def _is_plain_host(value: str) -> bool:
    """Accept a hostname or IP literal, never an embedded port, path, or userinfo."""

    host = value.strip()
    if not host or len(host) > 255:
        return False
    if any(character in host for character in " \t/\\?#@"):
        return False
    if ":" in host:
        # Only a bracketed or bare IPv6 literal may contain a colon; a
        # "host:port" string is an incomplete endpoint, not a host.
        return all(part == "" or _is_hex_group(part) for part in host.split(":"))
    return True


def _canonical_host(value: str) -> str | None:
    """Return an ASCII DNS name or normalized IP literal for socket/TLS use."""

    from ipaddress import ip_address

    try:
        return ip_address(value).compressed
    except ValueError:
        pass
    try:
        host = value.rstrip(".").encode("idna").decode("ascii").lower()
    except UnicodeError:
        return None
    if not host or len(host) > 253:
        return None
    labels = host.split(".")
    if any(
        not label
        or len(label) > 63
        or label.startswith("-")
        or label.endswith("-")
        or any(not (character.isalnum() or character == "-") for character in label)
        for label in labels
    ):
        return None
    return host


def _is_hex_group(value: str) -> bool:
    if len(value) > 4:
        return all(character.isdigit() or character == "." for character in value)
    return all(character in "0123456789abcdefABCDEF" for character in value)


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)
