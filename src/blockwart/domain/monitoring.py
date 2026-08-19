"""Provider-neutral service monitoring contract.

Blockwart separates three concerns that later monitoring solutions must not
re-invent:

- **Configuration** is embedded business data of one ``service`` catalog object
  at ``data.monitoring``.  It selects a provider, an interval, and whether the
  service is monitored at all.  Absent configuration is exactly ``enabled=false``.
- **Target resolution** is a pure function of the service's canonical endpoint
  contract.  It never performs discovery, scanning, or a network call, and it
  reports a stable configuration diagnostic instead of guessing.
- **Observation** is the canonical, vendor-neutral result of one check.  The
  built-in HTTP(S) probe is only the first provider; a later receiver such as
  Gatus writes the same observation shape through the same ingestion seam and
  therefore inherits catalog, UI, REST, Agent, MCP, freshness, and maintenance
  semantics without duplicating them.

Nothing in this module performs I/O.  Acquisition lives behind the narrow
adapter boundary in ``blockwart.services.monitoring_registry``.
"""

from __future__ import annotations

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

MonitoringProvider = Literal["builtin_http"]
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
    "no_http_endpoint",
]
MonitoringErrorCode = Literal[
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
]

# The provider identity is explicit and closed.  A later provider (for example
# the Gatus receiver tracked in #177) adds exactly one value here plus one
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
MONITORING_DOCUMENT_KEYS = frozenset({"enabled", "provider", "interval_seconds"})

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
class MonitoringTargetResolution:
    target: MonitoringTarget | None
    diagnostic: MonitoringDiagnostic | None = None


@dataclass(frozen=True, slots=True)
class MonitoringObservation:
    """One canonical, provider-neutral observation.

    Every provider produces exactly this shape.  ``provider`` is the explicit
    identity of the adapter that acquired it, so two providers can observe the
    same service without overwriting each other.
    """

    provider: str
    state: MonitoringState
    checked_at: datetime
    http_status: int | None = None
    latency_ms: int | None = None
    error_code: MonitoringErrorCode | None = None

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
    """The persisted observation state of one service/provider pair."""

    provider: str
    state: MonitoringState
    http_status: int | None
    latency_ms: int | None
    error_code: str | None
    last_checked_at: datetime | None
    last_success_at: datetime | None
    next_due_at: datetime | None
    object_instance_id: str | None = None


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
    interval = int(raw_interval) if overridden else _bounded_interval(default_interval_seconds)
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
        endpoint for endpoint in normalized.get("endpoints", []) if isinstance(endpoint, Mapping)
    ]

    declared = [
        endpoint
        for endpoint in endpoints
        if isinstance(endpoint.get("health_url"), str) and endpoint["health_url"].strip()
    ]
    if len(declared) > 1:
        return MonitoringTargetResolution(None, "ambiguous_health_url")
    if declared:
        parsed = [
            (endpoint, _parse_health_url(str(endpoint["health_url"]))) for endpoint in declared
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


def freshness_for(
    record: MonitoringRecord | None,
    *,
    interval_seconds: int,
    now: datetime,
) -> MonitoringFreshness:
    """Classify how current a stored observation is."""

    if record is None or record.last_checked_at is None:
        return "pending"
    due = record.next_due_at
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

    manual = (
        catalog_health
        if catalog_health
        in {
            "unknown",
            "healthy",
            "degraded",
            "down",
            "maintenance",
        }
        else None
    )
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
) -> dict[str, Any]:
    """Build the one authorized monitoring projection every surface shares.

    The result contains only provider-neutral fields.  A vendor-specific
    payload never reaches this projection, so adding a provider cannot change
    the published read contract.
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
    resolution = resolve_monitoring_target(data, object_id=object_id)
    matching = record if record is not None and record.provider == config.provider else None
    if matching is not None and matching.last_checked_at is not None:
        effective_due = scheduled_next_due(
            matching.last_checked_at,
            object_id=object_id,
            object_instance_id=matching.object_instance_id,
            provider=config.provider,
            interval_seconds=config.interval_seconds,
            jitter_seconds=jitter_seconds,
        )
        matching = MonitoringRecord(
            provider=matching.provider,
            state=matching.state,
            http_status=matching.http_status,
            latency_ms=matching.latency_ms,
            error_code=matching.error_code,
            last_checked_at=matching.last_checked_at,
            last_success_at=matching.last_success_at,
            next_due_at=effective_due,
            object_instance_id=matching.object_instance_id,
        )
    freshness = freshness_for(
        matching,
        interval_seconds=config.interval_seconds,
        now=now,
    )
    state = effective_state(matching, freshness)
    return {
        "enabled": config.enabled,
        "provider": config.provider,
        "interval_seconds": config.interval_seconds,
        "interval_overridden": config.interval_overridden,
        "target": resolution.target.as_dict() if resolution.target else None,
        "diagnostic": resolution.diagnostic,
        "state": state,
        "observed_state": matching.state if matching is not None else "unknown",
        "freshness": freshness,
        "http_status": matching.http_status if matching is not None else None,
        "latency_ms": matching.latency_ms if matching is not None else None,
        "error_code": matching.error_code if matching is not None else None,
        "last_checked_at": format_rfc3339_utc(
            matching.last_checked_at if matching is not None else None
        ),
        "last_success_at": format_rfc3339_utc(
            matching.last_success_at if matching is not None else None
        ),
        "next_due_at": format_rfc3339_utc(matching.next_due_at if matching is not None else None),
        "effective_health": effective_health(
            catalog_health=catalog_health,
            enabled=config.enabled,
            state=state,
        ),
    }


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
        "probe": {
            "methods": ["GET"],
            "schemes": sorted(_HTTP_SCHEMES),
            "authenticated": False,
            "redirects_followed": False,
            "response_body_stored": False,
            "allowlist": "deny_by_default",
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
    if "interval_seconds" not in document:
        return True
    interval = document.get("interval_seconds")
    return (
        isinstance(interval, int)
        and not isinstance(interval, bool)
        and MIN_MONITORING_INTERVAL_SECONDS <= interval <= MAX_MONITORING_INTERVAL_SECONDS
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


def _parse_health_url(value: str) -> MonitoringTarget | None:
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
    return MonitoringTarget(
        url=f"{scheme}://{_authority(host, port, scheme)}{path}{query}",
        scheme=scheme,
        host=host,
        port=port,
        path=f"{path}{query}",
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
