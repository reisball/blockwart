from types import SimpleNamespace

import pytest

from blockwart.domain.placement import (
    PlacementError,
    PlacementGraph,
    placement_state,
    validate_placement_metadata,
    validate_placement_pair,
)


def _object(object_id: str, kind: str) -> SimpleNamespace:
    return SimpleNamespace(
        id=object_id,
        kind=kind,
        label=object_id,
        status="active",
    )


def _relationship(
    from_ref: str,
    relation_type: str,
    to_ref: str,
) -> SimpleNamespace:
    return SimpleNamespace(
        from_ref=from_ref,
        relation_type=relation_type,
        to_ref=to_ref,
    )


def test_canonical_placement_graph_resolves_both_supported_hierarchies() -> None:
    objects = [
        _object("hardware", "host"),
        _object("runtime", "system"),
        _object("runtime-api", "service"),
        _object("hardware-console", "service"),
    ]
    graph = PlacementGraph(
        objects,
        [
            _relationship("host:hardware", "hosts", "system:runtime"),
            _relationship("system:runtime", "hosts", "service:runtime-api"),
            _relationship("host:hardware", "hosts", "service:hardware-console"),
        ],
    )

    assert graph.parent_path_refs("service:runtime-api") == [
        "host:hardware",
        "system:runtime",
    ]
    assert graph.parent_path_refs("service:hardware-console") == ["host:hardware"]
    assert graph.children_refs("host:hardware") == [
        "service:hardware-console",
        "system:runtime",
    ]


def test_canonical_placement_ignores_legacy_sources() -> None:
    objects = [
        _object("runtime", "system"),
        _object("api", "service"),
    ]
    graph = PlacementGraph(
        objects,
        [_relationship("system:runtime", "provides", "service:api")],
    )

    assert graph.parent_ref("service:api") is None
    assert graph.parent_path_refs("service:api") == []


def test_canonical_placement_fails_closed_for_multiple_parents() -> None:
    objects = [
        _object("hardware-a", "host"),
        _object("hardware-b", "host"),
        _object("runtime", "system"),
    ]
    graph = PlacementGraph(
        objects,
        [
            _relationship("host:hardware-a", "hosts", "system:runtime"),
            _relationship("host:hardware-b", "hosts", "system:runtime"),
        ],
    )

    with pytest.raises(PlacementError, match="multiple placement parents"):
        graph.parent_ref("system:runtime")


@pytest.mark.parametrize(
    ("parent_kind", "child_kind"),
    [
        ("host", "system"),
        ("host", "service"),
        ("system", "service"),
    ],
)
def test_supported_placement_pairs(parent_kind: str, child_kind: str) -> None:
    validate_placement_pair(parent_kind, child_kind)


@pytest.mark.parametrize(
    ("parent_kind", "child_kind"),
    [
        ("system", "system"),
        ("service", "service"),
        ("netzwerk", "system"),
        ("host", "host"),
    ],
)
def test_unsupported_placement_pairs_are_rejected(
    parent_kind: str,
    child_kind: str,
) -> None:
    with pytest.raises(PlacementError, match="unsupported placement"):
        validate_placement_pair(parent_kind, child_kind)


def test_placement_state_distinguishes_root_assigned_unassigned_and_unknown() -> None:
    assert placement_state(kind="host", parent_ref=None, data={}) == "root"
    assert (
        placement_state(
            kind="system",
            parent_ref="host:hardware",
            data={},
        )
        == "assigned"
    )
    assert (
        placement_state(
            kind="service",
            parent_ref=None,
            data={"placement": {"state": "unassigned"}},
        )
        == "unassigned"
    )
    assert placement_state(kind="service", parent_ref=None, data={}) == "unknown"
    assert placement_state(kind="netzwerk", parent_ref=None, data={}) is None


def test_placement_metadata_accepts_only_explicit_unassigned_assets() -> None:
    validate_placement_metadata(
        {
            "placement": {
                "state": "unassigned",
                "reason": "Pending inventory decision",
            }
        },
        kind="service",
    )

    with pytest.raises(ValueError, match="must be unassigned"):
        validate_placement_metadata(
            {"placement": {"state": "assigned"}},
            kind="service",
        )
    with pytest.raises(ValueError, match="only for system and service"):
        validate_placement_metadata(
            {"placement": {"state": "unassigned"}},
            kind="host",
        )
