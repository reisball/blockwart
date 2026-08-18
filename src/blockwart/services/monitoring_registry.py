"""The narrow adapter boundary between providers and the observation layer.

Acquisition is the only provider-specific part of monitoring. Everything after
it — storage, freshness, maintenance precedence, authorization, and the
catalog/UI/REST/Agent/MCP projections — is provider-neutral and lives outside
this module.

A later solution such as Gatus registers one spec here (or, for a push-based
receiver, registers with ``polling=False`` and calls the ingestion seam in
``blockwart.services.monitoring``). It does not touch any read model.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from blockwart.domain.monitoring import (
    MONITORING_PROVIDERS,
    MonitoringObservation,
    MonitoringTarget,
)
from blockwart.domain.monitoring_policy import TargetPolicy


@dataclass(frozen=True, slots=True)
class ProbeLimits:
    """The bounded execution envelope every acquisition adapter must honor."""

    policy: TargetPolicy
    connect_timeout_ms: int = 2000
    total_timeout_ms: int = 5000
    max_response_bytes: int = 65536


@dataclass(frozen=True, slots=True)
class ProviderCheckRequest:
    """One acquisition request for exactly one service.

    ``target`` is already resolved and ``diagnostic`` already explains why it
    could not be. An adapter never inspects catalog data, resolves a second
    target, or falls back to another endpoint.
    """

    object_id: str
    target: MonitoringTarget | None
    diagnostic: str | None
    limits: ProbeLimits


MonitoringAcquire = Callable[[ProviderCheckRequest], MonitoringObservation]


@dataclass(frozen=True, slots=True)
class MonitoringProviderSpec:
    provider: str
    # Whether the built-in database-backed scheduler drives this provider. A
    # push-based receiver sets this to False and keeps no lease.
    polling: bool
    acquire: MonitoringAcquire | None = None
    description: str = ""


_REGISTRY: dict[str, MonitoringProviderSpec] = {}


class UnknownMonitoringProviderError(LookupError):
    """The requested provider is not registered in this deployment."""


def register_provider(spec: MonitoringProviderSpec) -> None:
    if spec.provider not in MONITORING_PROVIDERS:
        raise ValueError(f"unknown monitoring provider: {spec.provider}")
    if spec.polling and spec.acquire is None:
        raise ValueError("a polling provider must supply an acquisition adapter")
    _REGISTRY[spec.provider] = spec


def get_provider(provider: str) -> MonitoringProviderSpec:
    try:
        return _REGISTRY[provider]
    except KeyError as exc:
        raise UnknownMonitoringProviderError(provider) from exc


def has_provider(provider: str) -> bool:
    return provider in _REGISTRY


def polling_providers() -> tuple[str, ...]:
    return tuple(
        sorted(name for name, spec in _REGISTRY.items() if spec.polling)
    )


def registered_providers() -> tuple[str, ...]:
    return tuple(sorted(_REGISTRY))


def _register_builtin_providers() -> None:
    # Imported lazily so the registry module stays importable from the pure
    # domain tests without pulling in socket and TLS machinery.
    from blockwart.services.monitoring_probe import probe_http_target

    register_provider(
        MonitoringProviderSpec(
            provider="builtin_http",
            polling=True,
            acquire=probe_http_target,
            description=(
                "Bounded unauthenticated HTTP(S) GET against one allowlisted target."
            ),
        )
    )


_register_builtin_providers()
