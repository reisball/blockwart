from __future__ import annotations

import json
from collections.abc import Generator
from contextlib import contextmanager

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from blockwart.api.deps import get_session
from blockwart.db.session import transaction
from blockwart.domain.auth import Permission, PrincipalContext, PrincipalType
from blockwart.main import create_app
from blockwart.schemas.catalog import CatalogObjectIn
from blockwart.services.catalog import create_relationship, upsert_object
from blockwart.services.policy import PolicySnapshot
from blockwart.services.queries import query_network_topology
from blockwart.services.read_access import ReadAccess


def _network_payload(object_id: str, category: str) -> CatalogObjectIn:
    return CatalogObjectIn(
        id=object_id,
        kind="network",
        label=object_id.replace("-", " ").title(),
        lifecycle="active",
        health="healthy",
        data={
            "schema_version": 1,
            "network": {"category": category},
        },
    )


def _install_topology(session: Session) -> None:
    for payload in (
        CatalogObjectIn(
            id="topology-host",
            kind="host",
            label="Topology Host",
            lifecycle="active",
            health="healthy",
            data={"schema_version": 1},
        ),
        CatalogObjectIn(
            id="topology-system",
            kind="system",
            label="Topology System",
            lifecycle="active",
            health="healthy",
            data={"schema_version": 1},
        ),
        CatalogObjectIn(
            id="topology-service",
            kind="service",
            label="Topology Service",
            lifecycle="active",
            health="healthy",
            data={"schema_version": 1},
        ),
        CatalogObjectIn(
            id="unassigned-service",
            kind="service",
            label="Unassigned Service",
            lifecycle="active",
            health="healthy",
            data={
                "schema_version": 1,
                "placement": {"state": "unassigned", "reason": "test"},
            },
        ),
        _network_payload("edge-switch", "switch"),
        _network_payload("mesh-node", "mesh"),
        _network_payload("core-router", "router"),
        _network_payload("system-ap", "access_point"),
    ):
        upsert_object(session, payload)
    for from_ref, relation_type, to_ref, metadata in (
        ("host:topology-host", "hosts", "system:topology-system", None),
        ("system:topology-system", "hosts", "service:topology-service", None),
        (
            "host:topology-host",
            "attached_to",
            "network:edge-switch",
            {"link_kind": "ethernet", "primary": True},
        ),
        (
            "network:edge-switch",
            "uplinks_to",
            "network:mesh-node",
            {"link_kind": "ethernet", "primary": True},
        ),
        (
            "network:edge-switch",
            "uplinks_to",
            "network:core-router",
            {"link_kind": "ethernet"},
        ),
        (
            "network:mesh-node",
            "uplinks_to",
            "network:core-router",
            {"link_kind": "mesh", "mode": "mesh"},
        ),
    ):
        create_relationship(
            session,
            from_ref=from_ref,
            relation_type=relation_type,
            to_ref=to_ref,
            metadata=metadata,
        )


@contextmanager
def _client(
    alembic_session_factory,
    install_unrestricted_read_access,
) -> Generator[TestClient, None, None]:
    app = create_app()
    install_unrestricted_read_access(app)

    def override_get_session():
        with alembic_session_factory() as session:
            yield session

    app.dependency_overrides[get_session] = override_get_session
    with TestClient(app) as client:
        yield client


def test_network_topology_resolves_inheritance_alternatives_and_agent_parity(
    alembic_session_factory,
    install_unrestricted_read_access,
) -> None:
    with alembic_session_factory() as session:
        with transaction(session):
            _install_topology(session)

    with _client(alembic_session_factory, install_unrestricted_read_access) as client:
        v1 = client.get("/api/v1/objects/topology-service/network-topology")
        agent = client.get("/api/agent/objects/topology-service/network-topology")

        assert v1.status_code == 200
        assert agent.status_code == 200
        assert agent.json() == v1.json()
        payload = v1.json()
        assert payload["object_ref"] == "service:topology-service"
        assert payload["resolution"] == "inherited"
        assert payload["resolution_source"] == "placement_host"
        assert payload["resolution_source_ref"] == "host:topology-host"
        assert payload["placement_path"] == [
            "host:topology-host",
            "system:topology-system",
        ]
        assert payload["status"] == "complete"
        assert payload["truncated"] is False
        assert payload["paths"] == [
            {
                "refs": [
                    "service:topology-service",
                    "system:topology-system",
                    "host:topology-host",
                    "network:edge-switch",
                    "network:mesh-node",
                    "network:core-router",
                ],
                "status": "complete",
            },
            {
                "refs": [
                    "service:topology-service",
                    "system:topology-system",
                    "host:topology-host",
                    "network:edge-switch",
                    "network:core-router",
                ],
                "status": "complete",
            },
        ]

        unassigned = client.get(
            "/api/v1/objects/unassigned-service/network-topology"
        ).json()
        assert unassigned["status"] == "unconnected"
        assert unassigned["paths"] == []

        router = client.get("/api/v1/objects/core-router/network-topology").json()
        assert router["resolution"] == "direct"
        assert router["resolution_source"] == "network"
        assert router["paths"] == [
            {"refs": ["network:core-router"], "status": "complete"}
        ]

    with alembic_session_factory() as session:
        with transaction(session):
            create_relationship(
                session,
                from_ref="system:topology-system",
                relation_type="attached_to",
                to_ref="network:system-ap",
                metadata={"link_kind": "wifi"},
            )

    with _client(alembic_session_factory, install_unrestricted_read_access) as client:
        override = client.get(
            "/api/v1/objects/topology-service/network-topology"
        ).json()
        assert override["resolution"] == "inherited"
        assert override["resolution_source"] == "system"
        assert override["resolution_source_ref"] == "system:topology-system"
        assert override["status"] == "incomplete"
        assert override["paths"] == [
            {
                "refs": [
                    "service:topology-service",
                    "system:topology-system",
                    "network:system-ap",
                ],
                "status": "incomplete",
            }
        ]


def test_network_topology_stops_before_unreadable_network_neighbors(
    alembic_session_factory,
) -> None:
    with alembic_session_factory() as session:
        with transaction(session):
            _install_topology(session)
            create_relationship(
                session,
                from_ref="system:topology-system",
                relation_type="attached_to",
                to_ref="network:system-ap",
                metadata={"link_kind": "wifi"},
            )
        permissions = {
            object_id: frozenset({Permission.DISCOVER, Permission.READ})
            for object_id in (
                "topology-host",
                "topology-system",
                "topology-service",
                "edge-switch",
            )
        }
        access = ReadAccess(
            principal=PrincipalContext(
                id="network-reader",
                principal_type=PrincipalType.SERVICE_ACCOUNT,
                login="network-reader",
                display_name="Network Reader",
            ),
            policy=PolicySnapshot(
                principal_id="network-reader",
                _permissions=permissions,
                _grants={},
            ),
        )
        topology = query_network_topology(session, "topology-service", access)

        assert topology is not None
        assert topology["status"] == "incomplete"
        assert topology["resolution"] == "inherited"
        assert topology["resolution_source"] == "placement_host"
        assert topology["resolution_source_ref"] == "host:topology-host"
        serialized = json.dumps(topology, sort_keys=True)
        assert "edge-switch" in serialized
        assert "system-ap" not in serialized
        assert "mesh-node" not in serialized
        assert "core-router" not in serialized
        assert topology["paths"] == [
            {
                "refs": [
                    "service:topology-service",
                    "system:topology-system",
                    "host:topology-host",
                    "network:edge-switch",
                ],
                "status": "incomplete",
            }
        ]

        discover_only = ReadAccess(
            principal=access.principal,
            policy=PolicySnapshot(
                principal_id="network-reader",
                _permissions={
                    "topology-service": frozenset({Permission.DISCOVER})
                },
                _grants={},
            ),
        )
        assert query_network_topology(
            session,
            "topology-service",
            discover_only,
        ) is None


def test_network_topology_reports_truncation_without_dangling_edges(
    alembic_session_factory,
    unrestricted_read_access,
) -> None:
    with alembic_session_factory() as session:
        with transaction(session):
            _install_topology(session)
        topology = query_network_topology(
            session,
            "topology-service",
            unrestricted_read_access(session),
            max_nodes=5,
        )

        assert topology is not None
        assert topology["truncated"] is True
        assert topology["status"] == "incomplete"
        node_refs = {node["ref"] for node in topology["nodes"]}
        assert len(node_refs) <= 5
        assert topology["paths"] == [
            {
                "refs": [
                    "service:topology-service",
                    "system:topology-system",
                    "host:topology-host",
                    "network:edge-switch",
                    "network:core-router",
                ],
                "status": "complete",
            }
        ]
        assert all(
            edge["from_ref"] in node_refs and edge["to_ref"] in node_refs
            for edge in topology["edges"]
        )
