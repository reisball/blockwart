from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy.orm import Session

from blockwart.schemas.v1 import SortDirection
from blockwart.services.pagination import paginate_items
from blockwart.services.queries import (
    AuditEventReadModel,
    RelationshipReadModel,
    TopologyReadModel,
    query_catalog_detail,
    query_catalog_topology,
)


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
    *,
    limit: int,
    cursor: str | None,
    direction: SortDirection,
    include_total: bool,
) -> RelationshipPage | None:
    detail = query_catalog_detail(session, object_id)
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
        query={"object_id": object_id},
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
    *,
    limit: int,
    cursor: str | None,
    direction: SortDirection,
    include_total: bool,
) -> AuditPage | None:
    detail = query_catalog_detail(session, object_id)
    if detail is None:
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
        query={"object_id": object_id},
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
) -> TopologyResource | None:
    result = query_catalog_topology(session, object_id)
    if result is None:
        return None
    object_ref, topology = result
    return TopologyResource(object_ref=object_ref, topology=topology)
