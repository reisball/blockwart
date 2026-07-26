import pytest

from blockwart.domain.asset_state import (
    AssetState,
    resolve_asset_state,
    state_from_legacy_status,
    status_from_asset_state,
)


@pytest.mark.parametrize(
    ("status", "expected"),
    [
        ("active", AssetState("active", "unknown", "active")),
        ("inactive", AssetState("planned", "unknown", "inactive")),
        ("deleted", AssetState("retired", "unknown", "deleted")),
        ("unknown", AssetState("active", "unknown", "active")),
    ],
)
def test_legacy_status_mapping_is_deterministic(
    status: str,
    expected: AssetState,
) -> None:
    assert state_from_legacy_status(status) == expected


@pytest.mark.parametrize(
    ("lifecycle", "health", "status"),
    [
        ("planned", "unknown", "inactive"),
        ("active", "unknown", "active"),
        ("active", "healthy", "active"),
        ("active", "degraded", "active"),
        ("active", "down", "inactive"),
        ("active", "maintenance", "inactive"),
        ("retired", "unknown", "deleted"),
    ],
)
def test_compatibility_status_is_derived_from_both_dimensions(
    lifecycle,
    health,
    status,
) -> None:
    assert status_from_asset_state(lifecycle, health) == status


def test_legacy_write_preserves_current_state_until_status_changes() -> None:
    current = AssetState("active", "healthy", "active")

    unchanged = resolve_asset_state(
        kind="service",
        status="active",
        lifecycle=None,
        health=None,
        current=current,
    )
    changed = resolve_asset_state(
        kind="service",
        status="inactive",
        lifecycle=None,
        health=None,
        current=current,
    )

    assert unchanged == current
    assert changed == AssetState("planned", "unknown", "inactive")


def test_non_asset_state_fields_are_rejected() -> None:
    with pytest.raises(ValueError, match="only valid for asset kinds"):
        resolve_asset_state(
            kind="runbook",
            status="active",
            lifecycle="active",
            health="unknown",
        )
