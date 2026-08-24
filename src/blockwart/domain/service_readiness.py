"""Canonical service-readiness vocabulary.

Criticality is an explicit operator assertion. It is deliberately not inferred
from a service name, prose, tags, health, or monitoring state. Missing
criticality preserves the historical meaning and resolves to ``standard``.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Literal, get_args

ServiceCriticality = Literal["standard", "critical"]
SERVICE_CRITICALITY_VALUES: tuple[str, ...] = get_args(ServiceCriticality)
SERVICE_CRITICALITIES = frozenset(SERVICE_CRITICALITY_VALUES)


def service_criticality(data: Mapping[str, Any]) -> ServiceCriticality:
    """Resolve one schema-valid service document without guessing."""
    return "critical" if data.get("criticality") == "critical" else "standard"
