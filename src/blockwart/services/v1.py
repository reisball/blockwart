from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy.orm import Session

from blockwart.schemas.v1 import SortDirection
from blockwart.services.pagination import paginate_items
from blockwart.services.queries import (
    AuditEventReadModel,
    DeviceGraphReadModel,
    NetworkTopologyReadModel,
    RelationshipReadModel,
    TopologyReadModel,
    query_catalog_detail,
    query_catalog_topology,
    query_device_graph,
    query_network_topology,
)
from blockwart.services.read_access import ReadAccess


@dataclass(frozen=True, slots=True)
class DeviceGraphResource:
    object_ref: str
    graph: DeviceGraphReadModel


@dataclass(frozen=True, slots=True)
class NetworkTopologyResource:
    object_ref: str
    topology: NetworkTopologyReadModel


@dataclass(frozen=True, slots=True)
class RelationshipPage:
    items: list[RelationshipReadModel]
    next_cursor: str | None
    total: int | None


@dataclass(frozen=True, slots=True)
class AuditPage:
    items: list[AuditEventReadModel]
    next_cursor: str | None
    total: int | None


@dataclass(frozen=True, slots=True)
class TopologyResource:
    object_ref: str
    topology: TopologyReadModel


def query_relationship_page(
    session: Session,
    object_id: str,
    access: ReadAccess,
    *,
    limit: int,
    cursor: str | None,
    direction: SortDirection,
    include_total: bool,
) -> RelationshipPage | None:
    detail = query_catalog_detail(session, object_id, access)
    if detail is None:
        return None
    page = paginate_items(
        detail.relationships,
        key=lambda item: (
            item["relation_type"].casefold(),
            f"{item['from_ref']}\0{item['to_ref']}",
        ),
        limit=limit,
        resource=f"objects/{object_id}/relationships",
        sort="relation_type",
        direction=direction,
        query={
            "access": access.cursor_scope,
            "object_id": object_id,
        },
        cursor=cursor,
        include_total=include_total,
    )
    return RelationshipPage(
        items=page.items,
        next_cursor=page.next_cursor,
        total=page.total,
    )


def query_audit_page(
    session: Session,
    object_id: str,
    access: ReadAccess,
    *,
    limit: int,
    cursor: str | None,
    direction: SortDirection,
    include_total: bool,
) -> AuditPage | None:
    detail = query_catalog_detail(session, object_id, access)
    if detail is None or detail.catalog_object.visibility != "detail":
        return None
    page = paginate_items(
        detail.audit_events,
        key=lambda item: (
            item["created_at"],
            f"{item['id']:020d}",
        ),
        limit=limit,
        resource=f"objects/{object_id}/audit-events",
        sort="created_at",
        direction=direction,
        query={
            "access": access.cursor_scope,
            "object_id": object_id,
        },
        cursor=cursor,
        include_total=include_total,
    )
    return AuditPage(
        items=page.items,
        next_cursor=page.next_cursor,
        total=page.total,
    )


def query_topology_resource(
    session: Session,
    object_id: str,
    access: ReadAccess,
) -> TopologyResource | None:
    result = query_catalog_topology(session, object_id, access)
    if result is None:
        return None
    object_ref, topology = result
    return TopologyResource(object_ref=object_ref, topology=topology)


def query_device_graph_resource(
    session: Session,
    object_id: str,
    access: ReadAccess,
) -> DeviceGraphResource | None:
    graph = query_device_graph(session, object_id, access)
    if graph is None:
        return None
    return DeviceGraphResource(object_ref=graph["object_ref"], graph=graph)


def query_network_topology_resource(
    session: Session,
    object_id: str,
    access: ReadAccess,
) -> NetworkTopologyResource | None:
    topology = query_network_topology(session, object_id, access)
    if topology is None:
        return None
    return NetworkTopologyResource(
        object_ref=topology["object_ref"],
        topology=topology,
    )
