from dataclasses import dataclass
from typing import Literal, cast

AssetLifecycle = Literal["planned", "active", "retired"]
AssetHealth = Literal["unknown", "healthy", "degraded", "down", "maintenance"]
LegacyObjectStatus = Literal["active", "inactive", "deleted"]

ASSET_KINDS = frozenset({"host", "system", "netzwerk", "service"})
ASSET_LIFECYCLES: tuple[AssetLifecycle, ...] = ("planned", "active", "retired")
ASSET_HEALTH_VALUES: tuple[AssetHealth, ...] = (
    "unknown",
    "healthy",
    "degraded",
    "down",
    "maintenance",
)


@dataclass(frozen=True)
class AssetState:
    lifecycle: AssetLifecycle
    health: AssetHealth
    status: LegacyObjectStatus


def is_asset_kind(kind: str) -> bool:
    return kind in ASSET_KINDS


def state_from_legacy_status(status: str | None) -> AssetState:
    if status == "active":
        return AssetState("active", "unknown", "active")
    if status == "deleted":
        return AssetState("retired", "unknown", "deleted")
    if status is None or not status.strip() or status == "unknown":
        return AssetState("active", "unknown", "active")
    return AssetState("planned", "unknown", "inactive")


def status_from_asset_state(
    lifecycle: AssetLifecycle,
    health: AssetHealth,
) -> LegacyObjectStatus:
    if lifecycle == "retired":
        return "deleted"
    if lifecycle == "planned" or health in {"down", "maintenance"}:
        return "inactive"
    return "active"


def state_from_record(
    *,
    kind: str,
    status: str | None,
    lifecycle: str | None,
    health: str | None,
) -> AssetState | None:
    if not is_asset_kind(kind):
        return None
    if lifecycle in ASSET_LIFECYCLES and health in ASSET_HEALTH_VALUES:
        typed_lifecycle = cast(AssetLifecycle, lifecycle)
        typed_health = cast(AssetHealth, health)
        return AssetState(
            typed_lifecycle,
            typed_health,
            status_from_asset_state(typed_lifecycle, typed_health),
        )
    return state_from_legacy_status(status)


def resolve_asset_state(
    *,
    kind: str,
    status: str,
    lifecycle: AssetLifecycle | None,
    health: AssetHealth | None,
    current: AssetState | None = None,
) -> AssetState | None:
    if not is_asset_kind(kind):
        if lifecycle is not None or health is not None:
            raise ValueError("lifecycle and health are only valid for asset kinds")
        return None

    if lifecycle is None and health is None:
        if current is not None and status == current.status:
            return current
        return state_from_legacy_status(status)

    target_lifecycle = lifecycle
    if target_lifecycle is None:
        target_lifecycle = (
            current.lifecycle if current is not None else state_from_legacy_status(status).lifecycle
        )

    target_health = health
    if target_health is None:
        target_health = (
            current.health
            if current is not None and target_lifecycle == current.lifecycle
            else "unknown"
        )

    return AssetState(
        target_lifecycle,
        target_health,
        status_from_asset_state(target_lifecycle, target_health),
    )
