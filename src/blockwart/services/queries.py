from __future__ import annotations

import json
from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Literal, NotRequired, TypedDict

from sqlalchemy import select
from sqlalchemy.orm import Session

from blockwart.domain.asset_state import AssetHealth, AssetLifecycle
from blockwart.domain.auth import ObjectVisibility, Permission
from blockwart.domain.placement import PlacementGraph
from blockwart.domain.ui_schema import get_ui_schema
from blockwart.models import Relationship
from blockwart.schemas.catalog import (
    PUBLIC_OBJECT_KINDS,
    CatalogAssetNode,
    CatalogAssetReadNode,
    CatalogAssetStubNode,
    CatalogObjectOut,
    CatalogObjectReadOut,
    CatalogObjectStubOut,
)
from blockwart.services.catalog import (
    list_audit_events_for_object,
    list_objects,
)
from blockwart.services.read_access import ReadAccess

PUBLIC_KIND_PRIORITY = {
    kind: index for index, kind in enumerate(PUBLIC_OBJECT_KINDS)
}


class RelationshipReadModel(TypedDict):
    from_ref: str
    relation_type: str
    to_ref: str


class RelatedRelationshipReadModel(RelationshipReadModel):
    other_ref: str
    other_id: str
    other_kind: str
    other_label: str
    other_status: str
    other_data: dict[str, Any]


class RelationshipPortReadModel(TypedDict):
    label: str
    value: str


class TopologyNodeReadModel(TypedDict):
    ref: str
    id: str
    kind: str
    label: str
    visibility: Literal["stub", "detail"]
    capabilities: list[Permission]
    status: NotRequired[str]
    data: NotRequired[dict[str, Any]]
    ports: NotRequired[list[RelationshipPortReadModel]]


class TopologyChainReadModel(TypedDict):
    hosts: list[TopologyNodeReadModel]
    systems: list[TopologyNodeReadModel]
    services: list[TopologyNodeReadModel]


class TopologyReadModel(TypedDict):
    chains: list[TopologyChainReadModel]


class RelationshipCardReadModel(RelatedRelationshipReadModel):
    left: TopologyNodeReadModel
    right: TopologyNodeReadModel
    current_side: Literal["left", "right"]


class ObjectRelationshipsReadModel(TypedDict):
    relationships: list[RelationshipCardReadModel]
    topology: TopologyReadModel


class ExplorerAssetDetailReadModel(TypedDict):
    ref: str
    id: str
    kind: str
    label: str
    labels: list[str]
    summary: str
    status: str
    lifecycle: str
    health: str
    address: str
    platform: str
    endpoint: str
    updated_at: str
    visibility: Literal["stub", "detail"]
    capabilities: list[Permission]


class ExplorerAssetStubReadModel(TypedDict):
    ref: str
    id: str
    kind: str
    label: str
    visibility: Literal["stub"]
    capabilities: list[Permission]


ExplorerAssetReadModel = ExplorerAssetDetailReadModel | ExplorerAssetStubReadModel


class ExplorerSystemBranchReadModel(TypedDict):
    system: ExplorerAssetReadModel
    services: list[ExplorerAssetReadModel]


class ExplorerClusterReadModel(TypedDict):
    host: ExplorerAssetReadModel
    systems: list[ExplorerSystemBranchReadModel]
    direct_services: list[ExplorerAssetReadModel]


class ExplorerStandaloneSystemReadModel(TypedDict):
    system: ExplorerAssetReadModel
    services: list[ExplorerAssetReadModel]


class ExplorerReadModel(TypedDict):
    clusters: list[ExplorerClusterReadModel]
    standalone_systems: list[ExplorerStandaloneSystemReadModel]
    standalone_services: list[ExplorerAssetReadModel]
    networks: list[ExplorerAssetReadModel]
    assets: dict[str, ExplorerAssetReadModel]


class AuditEventReadModel(TypedDict):
    id: int
    action: str
    actor: str
    summary: str
    details: dict[str, Any]
    created_at: str


@dataclass(frozen=True, slots=True)
class CatalogBrowseReadModel:
    objects: list[CatalogObjectReadOut]
    all_objects: list[CatalogObjectReadOut]
    systems: list[CatalogObjectReadOut]
    relation_targets: list[CatalogObjectReadOut]
    display_names: dict[str, str]
    object_counts: Counter[str]
    health_counts: Counter[str]
    total_objects: int
    index_relationships: dict[str, ObjectRelationshipsReadModel]
    explorer: ExplorerReadModel


@dataclass(frozen=True, slots=True)
class CatalogDetailReadModel:
    catalog_object: CatalogObjectReadOut
    all_objects: list[CatalogObjectReadOut]
    object_map: dict[str, CatalogObjectReadOut]
    relationships: list[RelationshipReadModel]
    relationship_groups: dict[str, list[RelatedRelationshipReadModel]]
    relationship_targets: list[CatalogObjectReadOut]
    audit_events: list[AuditEventReadModel]


def list_catalog_objects(
    session: Session,
    access: ReadAccess,
    *,
    lifecycle: AssetLifecycle | None = None,
    health: AssetHealth | None = None,
) -> list[CatalogObjectReadOut]:
    """Return the canonical catalog read model used by the JSON API."""
    projected_objects = [
        projected
        for catalog_object in list_objects(session)
        if (projected := _project_catalog_object(catalog_object, access)) is not None
    ]
    if lifecycle is None and health is None:
        return projected_objects
    return [
        catalog_object
        for catalog_object in projected_objects
        if catalog_object.visibility == ObjectVisibility.DETAIL
        and (lifecycle is None or catalog_object.lifecycle == lifecycle)
        and (health is None or catalog_object.health == health)
    ]


def get_catalog_object(
    session: Session,
    object_id: str,
    access: ReadAccess,
) -> CatalogObjectReadOut | None:
    """Return one canonical catalog read model used by the JSON API."""
    catalog_object = next(
        (
            candidate
            for candidate in list_objects(session)
            if candidate.id == object_id
        ),
        None,
    )
    if catalog_object is None:
        return None
    return _project_catalog_object(catalog_object, access)


def query_catalog_browse(
    session: Session,
    access: ReadAccess,
    *,
    query: str | None = None,
    kind: str | None = None,
) -> CatalogBrowseReadModel:
    """Build the public catalog explorer model without FastAPI dependencies."""
    all_objects = sort_for_browse(list_catalog_objects(session, access))
    public_objects = visible_objects(all_objects)
    normalized_query = query.strip() if query else ""
    matching_ids = (
        _matching_object_ids(all_objects, normalized_query)
        if normalized_query
        else None
    )
    objects = [
        catalog_object
        for catalog_object in public_objects
        if (kind is None or catalog_object.kind == kind)
        and (matching_ids is None or catalog_object.id in matching_ids)
    ]
    systems = [
        catalog_object
        for catalog_object in all_objects
        if catalog_object.kind == "system"
    ]
    relationships = _list_relationships(session, access)
    object_map = {
        f"{catalog_object.kind}:{catalog_object.id}": catalog_object
        for catalog_object in all_objects
    }
    object_counts = Counter(catalog_object.kind for catalog_object in public_objects)
    health_counts = Counter(
        str(catalog_object.health or "unknown")
        for catalog_object in public_objects
        if catalog_object.visibility == ObjectVisibility.DETAIL
    )
    included_refs = (
        {
            f"{catalog_object.kind}:{catalog_object.id}"
            for catalog_object in objects
        }
        if normalized_query or kind is not None
        else None
    )
    return CatalogBrowseReadModel(
        objects=objects,
        all_objects=all_objects,
        systems=systems,
        relation_targets=public_objects,
        display_names={
            catalog_object.id: primary_name_value(catalog_object)
            for catalog_object in all_objects
        },
        object_counts=object_counts,
        health_counts=health_counts,
        total_objects=sum(object_counts.values()),
        index_relationships=_index_relationship_cards(
            objects,
            relationships,
            object_map,
        ),
        explorer=build_explorer_read_model(
            public_objects,
            relationships,
            included_refs=included_refs,
        ),
    )


def query_catalog_detail(
    session: Session,
    object_id: str,
    access: ReadAccess,
) -> CatalogDetailReadModel | None:
    """Build the object detail model without FastAPI or template dependencies."""
    all_objects = sort_for_browse(list_catalog_objects(session, access))
    catalog_object = next(
        (
            candidate
            for candidate in all_objects
            if candidate.id == object_id
        ),
        None,
    )
    if catalog_object is None:
        return None
    object_map = {
        f"{candidate.kind}:{candidate.id}": candidate
        for candidate in all_objects
    }
    all_relationships = _list_relationships(session, access)
    object_ref = f"{catalog_object.kind}:{catalog_object.id}"
    relationships = [
        relationship
        for relationship in all_relationships
        if relationship["from_ref"] == object_ref
        or relationship["to_ref"] == object_ref
    ]
    relationship_groups = group_relationships(
        catalog_object,
        relationships,
        object_map,
    )
    audit_events = (
        list_audit_events_for_object(
            session,
            catalog_object.id,
        )
        if catalog_object.visibility == ObjectVisibility.DETAIL
        else []
    )
    return CatalogDetailReadModel(
        catalog_object=catalog_object,
        all_objects=all_objects,
        object_map=object_map,
        relationships=relationships,
        relationship_groups=relationship_groups,
        relationship_targets=[
            candidate
            for candidate in visible_objects(all_objects)
            if candidate.id != catalog_object.id
        ],
        audit_events=[
            {
                "id": int(event["id"]),
                "action": event["action"],
                "actor": event["actor"],
                "summary": event["summary"],
                "details": event["details"],
                "created_at": event["created_at"],
            }
            for event in audit_events
        ],
    )


def query_catalog_topology(
    session: Session,
    object_id: str,
    access: ReadAccess,
) -> tuple[str, TopologyReadModel] | None:
    """Return one canonical topology resource without UI dependencies."""
    all_objects = sort_for_browse(list_catalog_objects(session, access))
    catalog_object = next(
        (
            candidate
            for candidate in all_objects
            if candidate.id == object_id
        ),
        None,
    )
    if catalog_object is None:
        return None
    object_map = {
        f"{candidate.kind}:{candidate.id}": candidate
        for candidate in all_objects
    }
    relationships = _list_relationships(session, access)
    object_ref = f"{catalog_object.kind}:{catalog_object.id}"
    return (
        object_ref,
        build_topology_read_model(
            catalog_object,
            relationships,
            object_map,
        ),
    )


def build_topology_read_model(
    catalog_object: CatalogObjectReadOut,
    relationships: list[RelationshipReadModel],
    object_map: dict[str, CatalogObjectReadOut],
) -> TopologyReadModel:
    """Resolve one UI/API-neutral placement topology from the canonical graph."""
    current_ref = f"{catalog_object.kind}:{catalog_object.id}"
    placement_graph = PlacementGraph(object_map.values(), relationships)

    if catalog_object.kind == "service":
        parent_path = placement_graph.parent_path_refs(current_ref)
        host_refs = [ref for ref in parent_path if ref.startswith("host:")]
        system_refs = [ref for ref in parent_path if ref.startswith("system:")]
        return {
            "chains": [
                {
                    "hosts": _relationship_nodes(host_refs, object_map),
                    "systems": _relationship_nodes(system_refs, object_map),
                    "services": [
                        _relationship_node(current_ref, catalog_object)
                    ],
                }
            ]
        }

    if catalog_object.kind == "host":
        child_refs = placement_graph.children_refs(current_ref)
        system_refs = [
            ref for ref in child_refs if ref.startswith("system:")
        ]
        direct_service_refs = [
            ref for ref in child_refs if ref.startswith("service:")
        ]
        service_refs = _unique_refs(
            [
                *direct_service_refs,
                *[
                    service_ref
                    for system_ref in system_refs
                    for service_ref in placement_graph.children_refs(system_ref)
                    if service_ref.startswith("service:")
                ],
            ]
        )
        return {
            "chains": [
                {
                    "hosts": [
                        _relationship_node(current_ref, catalog_object)
                    ],
                    "systems": _relationship_nodes(system_refs, object_map),
                    "services": _relationship_nodes(service_refs, object_map),
                }
            ]
        }

    if catalog_object.kind == "system":
        host_refs = [
            ref
            for ref in placement_graph.parent_path_refs(current_ref)
            if ref.startswith("host:")
        ]
        service_refs = [
            ref
            for ref in placement_graph.children_refs(current_ref)
            if ref.startswith("service:")
        ]
        return {
            "chains": [
                {
                    "hosts": _relationship_nodes(host_refs, object_map),
                    "systems": [
                        _relationship_node(current_ref, catalog_object)
                    ],
                    "services": _relationship_nodes(service_refs, object_map),
                }
            ]
        }

    return {"chains": []}


def build_explorer_read_model(
    objects: list[CatalogObjectReadOut],
    relationships: list[RelationshipReadModel],
    *,
    included_refs: set[str] | None = None,
) -> ExplorerReadModel:
    """Build the shared catalog/topology hierarchy from canonical placement."""
    object_map = {
        f"{catalog_object.kind}:{catalog_object.id}": catalog_object
        for catalog_object in objects
    }
    graph = PlacementGraph(object_map.values(), relationships)
    assets = {
        ref: _explorer_asset(catalog_object)
        for ref, catalog_object in object_map.items()
    }

    def is_included(ref: str) -> bool:
        return included_refs is None or ref in included_refs

    clusters: list[ExplorerClusterReadModel] = []
    placed_system_refs: set[str] = set()
    placed_service_refs: set[str] = set()
    for host_ref in _refs_for_kind(objects, "host"):
        host_is_included = is_included(host_ref)
        system_branches: list[ExplorerSystemBranchReadModel] = []
        direct_services: list[ExplorerAssetReadModel] = []
        for child_ref in graph.children_refs(host_ref):
            if child_ref.startswith("system:"):
                system_is_included = is_included(child_ref)
                placed_system_refs.add(child_ref)
                service_refs = [
                    ref
                    for ref in graph.children_refs(child_ref)
                    if ref.startswith("service:")
                ]
                placed_service_refs.update(service_refs)
                visible_services = [
                    assets[ref]
                    for ref in service_refs
                    if (
                        included_refs is None
                        or host_is_included
                        or system_is_included
                        or ref in included_refs
                    )
                ]
                if host_is_included or system_is_included or visible_services:
                    system_branches.append(
                        {
                            "system": assets[child_ref],
                            "services": visible_services,
                        }
                    )
            elif child_ref.startswith("service:"):
                placed_service_refs.add(child_ref)
                if host_is_included or is_included(child_ref):
                    direct_services.append(assets[child_ref])
        if host_is_included or system_branches or direct_services:
            clusters.append(
                {
                    "host": assets[host_ref],
                    "systems": system_branches,
                    "direct_services": direct_services,
                }
            )

    standalone_systems: list[ExplorerStandaloneSystemReadModel] = []
    for system_ref in _refs_for_kind(objects, "system"):
        if system_ref in placed_system_refs:
            continue
        system_is_included = is_included(system_ref)
        service_refs = [
            ref
            for ref in graph.children_refs(system_ref)
            if ref.startswith("service:")
        ]
        placed_service_refs.update(service_refs)
        visible_services = [
            assets[ref]
            for ref in service_refs
            if (
                included_refs is None
                or system_is_included
                or ref in included_refs
            )
        ]
        if system_is_included or visible_services:
            standalone_systems.append(
                {
                    "system": assets[system_ref],
                    "services": visible_services,
                }
            )

    standalone_services = [
        assets[service_ref]
        for service_ref in _refs_for_kind(objects, "service")
        if service_ref not in placed_service_refs and is_included(service_ref)
    ]
    networks = [
        assets[network_ref]
        for network_ref in _refs_for_kind(objects, "network")
        if is_included(network_ref)
    ]
    visible_refs = set(included_refs or assets)
    for cluster in clusters:
        visible_refs.add(cluster["host"]["ref"])
        visible_refs.update(
            service["ref"]
            for service in cluster["direct_services"]
        )
        for branch in cluster["systems"]:
            visible_refs.add(branch["system"]["ref"])
            visible_refs.update(
                service["ref"] for service in branch["services"]
            )
    for branch in standalone_systems:
        visible_refs.add(branch["system"]["ref"])
        visible_refs.update(
            service["ref"] for service in branch["services"]
        )
    visible_refs.update(service["ref"] for service in standalone_services)
    visible_refs.update(network["ref"] for network in networks)
    return {
        "clusters": clusters,
        "standalone_systems": standalone_systems,
        "standalone_services": standalone_services,
        "networks": networks,
        "assets": {
            ref: asset
            for ref, asset in assets.items()
            if ref in visible_refs
        },
    }


def group_relationships(
    catalog_object: CatalogObjectReadOut,
    relationships: list[RelationshipReadModel],
    object_map: dict[str, CatalogObjectReadOut],
) -> dict[str, list[RelatedRelationshipReadModel]]:
    current_ref = f"{catalog_object.kind}:{catalog_object.id}"
    grouped: dict[str, list[RelatedRelationshipReadModel]] = {}
    for relationship in relationships:
        direction = (
            "outbound"
            if relationship["from_ref"] == current_ref
            else "inbound"
        )
        other_ref = (
            relationship["to_ref"]
            if direction == "outbound"
            else relationship["from_ref"]
        )
        other_object = object_map.get(other_ref)
        grouped.setdefault(direction, []).append(
            {
                **relationship,
                "other_ref": other_ref,
                "other_id": object_id_from_ref(other_ref),
                "other_kind": (
                    other_object.kind
                    if other_object
                    else other_ref.split(":", 1)[0]
                ),
                "other_label": (
                    primary_name_value(other_object)
                    if other_object
                    else other_ref
                ),
                "other_status": _object_status(other_object),
                "other_data": _object_data(other_object),
            }
        )
    return grouped


def primary_name_value(catalog_object: CatalogObjectReadOut) -> str:
    if catalog_object.visibility == ObjectVisibility.STUB:
        return catalog_object.label
    schema = get_ui_schema(catalog_object.kind)
    if schema.primary_name_storage == "network_hostname":
        network = catalog_object.data.get("network")
        if isinstance(network, Mapping):
            hostnames = network.get("hostnames")
            if isinstance(hostnames, list) and hostnames:
                return str(hostnames[0])
    return catalog_object.label


def sort_for_browse(
    objects: list[CatalogObjectReadOut],
) -> list[CatalogObjectReadOut]:
    return sorted(
        objects,
        key=lambda catalog_object: (
            PUBLIC_KIND_PRIORITY.get(
                catalog_object.kind,
                len(PUBLIC_KIND_PRIORITY),
            ),
            catalog_object.label.casefold(),
            catalog_object.id.casefold(),
        ),
    )


def visible_objects(
    objects: list[CatalogObjectReadOut],
) -> list[CatalogObjectReadOut]:
    return sort_for_browse(
        [
            catalog_object
            for catalog_object in objects
            if catalog_object.kind in PUBLIC_OBJECT_KINDS
        ]
    )


def object_id_from_ref(value: str) -> str:
    if ":" not in value:
        return value
    return value.split(":", 1)[1]


def _matching_object_ids(
    objects: list[CatalogObjectReadOut],
    query: str,
) -> set[str]:
    term = query.casefold()
    matches: set[str] = set()
    for catalog_object in objects:
        values = [
            catalog_object.id,
            catalog_object.kind,
            catalog_object.label,
        ]
        if catalog_object.visibility == ObjectVisibility.DETAIL:
            values.extend(
                [
                    catalog_object.summary or "",
                    json.dumps(catalog_object.data, sort_keys=True),
                    json.dumps(
                        catalog_object.provenance.model_dump(mode="json"),
                        sort_keys=True,
                    ),
                ]
            )
        if any(term in value.casefold() for value in values):
            matches.add(catalog_object.id)
    return matches


def _list_relationships(
    session: Session,
    access: ReadAccess,
) -> list[RelationshipReadModel]:
    rows = session.scalars(
        select(Relationship).order_by(
            Relationship.relation_type,
            Relationship.from_ref,
            Relationship.to_ref,
        )
    ).all()
    relationships: list[RelationshipReadModel] = []
    for row in rows:
        from_id = object_id_from_ref(row.from_ref)
        to_id = object_id_from_ref(row.to_ref)
        required_permission = (
            Permission.DISCOVER
            if row.relation_type == "hosts"
            else Permission.READ
        )
        if not (
            access.policy.can(required_permission, from_id)
            and access.policy.can(required_permission, to_id)
        ):
            continue
        relationships.append(
            {
                "from_ref": row.from_ref,
                "relation_type": row.relation_type,
                "to_ref": row.to_ref,
            }
        )
    return relationships


def _index_relationship_cards(
    objects: list[CatalogObjectReadOut],
    relationships: list[RelationshipReadModel],
    object_map: dict[str, CatalogObjectReadOut],
) -> dict[str, ObjectRelationshipsReadModel]:
    cards: dict[str, ObjectRelationshipsReadModel] = {}
    for catalog_object in objects:
        object_ref = f"{catalog_object.kind}:{catalog_object.id}"
        object_relationships = [
            relationship
            for relationship in relationships
            if relationship["from_ref"] == object_ref
            or relationship["to_ref"] == object_ref
        ]
        grouped = group_relationships(
            catalog_object,
            object_relationships,
            object_map,
        )
        cards[catalog_object.id] = {
            "relationships": _relationship_display_cards(
                catalog_object,
                grouped,
                object_map,
            ),
            "topology": build_topology_read_model(
                catalog_object,
                relationships,
                object_map,
            ),
        }
    return cards


def _unique_refs(values: list[str]) -> list[str]:
    seen: set[str] = set()
    unique: list[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        unique.append(value)
    return unique


def _relationship_nodes(
    refs: list[str],
    object_map: dict[str, CatalogObjectReadOut],
) -> list[TopologyNodeReadModel]:
    return [
        _relationship_node(ref, object_map.get(ref))
        for ref in refs
    ]


def _relationship_display_sort_key(
    card: RelationshipCardReadModel,
) -> tuple[int, str, str]:
    left_kind = card["left"]["kind"]
    right_kind = card["right"]["kind"]
    is_system_service = (
        left_kind == "system" and right_kind == "service"
    )
    return (
        0 if is_system_service else 1,
        card["left"]["label"],
        card["right"]["label"],
    )


def _relationship_display_cards(
    catalog_object: CatalogObjectReadOut,
    grouped: dict[str, list[RelatedRelationshipReadModel]],
    object_map: dict[str, CatalogObjectReadOut],
) -> list[RelationshipCardReadModel]:
    cards: list[RelationshipCardReadModel] = []
    current_ref = f"{catalog_object.kind}:{catalog_object.id}"
    for relationship in [
        relationship
        for direction in ("outbound", "inbound")
        for relationship in grouped.get(direction, [])
    ]:
        from_ref = relationship["from_ref"]
        to_ref = relationship["to_ref"]
        from_object = object_map.get(from_ref)
        to_object = object_map.get(to_ref)
        left_ref, right_ref = _system_service_refs(
            from_ref,
            to_ref,
            from_object,
            to_object,
        )
        cards.append(
            {
                **relationship,
                "left": _relationship_node(
                    left_ref,
                    object_map.get(left_ref),
                ),
                "right": _relationship_node(
                    right_ref,
                    object_map.get(right_ref),
                ),
                "current_side": (
                    "left" if left_ref == current_ref else "right"
                ),
            }
        )
    return sorted(cards, key=_relationship_display_sort_key)


def _system_service_refs(
    from_ref: str,
    to_ref: str,
    from_object: CatalogObjectReadOut | None,
    to_object: CatalogObjectReadOut | None,
) -> tuple[str, str]:
    if from_object is not None and to_object is not None:
        if (
            from_object.kind == "system"
            and to_object.kind == "service"
        ):
            return from_ref, to_ref
        if (
            from_object.kind == "service"
            and to_object.kind == "system"
        ):
            return to_ref, from_ref
    if (
        from_ref.startswith("system:")
        and to_ref.startswith("service:")
    ):
        return from_ref, to_ref
    if (
        from_ref.startswith("service:")
        and to_ref.startswith("system:")
    ):
        return to_ref, from_ref
    return from_ref, to_ref


def _relationship_node(
    ref: str,
    catalog_object: CatalogObjectReadOut | None,
) -> TopologyNodeReadModel:
    kind = (
        catalog_object.kind
        if catalog_object
        else ref.split(":", 1)[0]
    )
    node: TopologyNodeReadModel = {
        "ref": ref,
        "id": (
            catalog_object.id
            if catalog_object
            else object_id_from_ref(ref)
        ),
        "kind": kind,
        "label": (
            primary_name_value(catalog_object)
            if catalog_object
            else ref
        ),
        "visibility": (
            catalog_object.visibility
            if catalog_object is not None
            else ObjectVisibility.STUB
        ),
        "capabilities": (
            catalog_object.capabilities
            if catalog_object is not None
            else []
        ),
    }
    if (
        catalog_object is not None
        and catalog_object.visibility == ObjectVisibility.DETAIL
    ):
        node.update(
            {
                "status": catalog_object.status,
                "data": catalog_object.data,
                "ports": _relationship_node_ports(catalog_object),
            }
        )
    return node


def _relationship_node_ports(
    catalog_object: CatalogObjectReadOut | None,
) -> list[RelationshipPortReadModel]:
    if (
        catalog_object is None
        or catalog_object.visibility != ObjectVisibility.DETAIL
        or catalog_object.kind != "service"
    ):
        return []
    ports: list[RelationshipPortReadModel] = []
    for endpoint in _list_of_mappings(
        catalog_object.data.get("endpoints")
    ):
        port = endpoint.get("port")
        if port is None:
            continue
        protocol = str(endpoint.get("protocol") or "tcp")
        ports.append(
            {
                "label": "service",
                "value": f"{port}/{protocol}",
            }
        )
    return ports


def _refs_for_kind(
    objects: list[CatalogObjectReadOut],
    kind: str,
) -> list[str]:
    return [
        f"{catalog_object.kind}:{catalog_object.id}"
        for catalog_object in objects
        if catalog_object.kind == kind
    ]


def _explorer_asset(
    catalog_object: CatalogObjectReadOut,
) -> ExplorerAssetReadModel:
    if catalog_object.visibility == ObjectVisibility.STUB:
        return {
            "ref": f"{catalog_object.kind}:{catalog_object.id}",
            "id": catalog_object.id,
            "kind": catalog_object.kind,
            "label": catalog_object.label,
            "visibility": ObjectVisibility.STUB,
            "capabilities": catalog_object.capabilities,
        }
    network = catalog_object.data.get("network")
    addresses = (
        _list_of_mappings(network.get("addresses"))
        if isinstance(network, Mapping)
        else []
    )
    endpoints = _list_of_mappings(catalog_object.data.get("endpoints"))
    first_address = str(addresses[0].get("ip") or "") if addresses else ""
    first_endpoint = endpoints[0] if endpoints else {}
    endpoint_type = str(first_endpoint.get("type") or "")
    endpoint_port = first_endpoint.get("port")
    endpoint = endpoint_type
    if endpoint_port is not None:
        endpoint = f"{endpoint_type} :{endpoint_port}".strip()
    platform = str(
        catalog_object.data.get("platform")
        or catalog_object.data.get("type")
        or ""
    )
    raw_labels = catalog_object.data.get("labels")
    labels = (
        [str(label) for label in raw_labels if isinstance(label, str)]
        if isinstance(raw_labels, list)
        else []
    )
    return {
        "ref": f"{catalog_object.kind}:{catalog_object.id}",
        "id": catalog_object.id,
        "kind": catalog_object.kind,
        "label": primary_name_value(catalog_object),
        "labels": labels,
        "summary": catalog_object.summary or "",
        "status": catalog_object.status,
        "lifecycle": str(catalog_object.lifecycle or ""),
        "health": str(catalog_object.health or "unknown"),
        "address": first_address,
        "platform": platform,
        "endpoint": endpoint,
        "updated_at": catalog_object.last_changed
        or catalog_object.updated_at
        or "",
        "visibility": ObjectVisibility.DETAIL,
        "capabilities": catalog_object.capabilities,
    }


def _project_catalog_object(
    catalog_object: CatalogObjectOut,
    access: ReadAccess,
) -> CatalogObjectReadOut | None:
    visibility = access.policy.visibility_for(catalog_object.id)
    if visibility == ObjectVisibility.NONE:
        return None
    capabilities = access.capabilities_for(catalog_object.id)
    visible_parent_path: list[CatalogAssetReadNode] = []
    for node in reversed(catalog_object.parent_path):
        if not access.policy.can(Permission.DISCOVER, node.id):
            break
        visible_parent_path.append(_project_parent_node(node, access))
    visible_parent_path.reverse()
    placement_state = catalog_object.placement_state
    if (
        placement_state == "assigned"
        and (
            not visible_parent_path
            or not catalog_object.parent_path
            or visible_parent_path[-1].id != catalog_object.parent_path[-1].id
        )
    ):
        placement_state = "unknown"
    if visibility == ObjectVisibility.DETAIL:
        return catalog_object.model_copy(
            update={
                "visibility": ObjectVisibility.DETAIL,
                "capabilities": capabilities,
                "parent_path": visible_parent_path,
                "placement_state": placement_state,
            }
        )
    return CatalogObjectStubOut(
        id=catalog_object.id,
        kind=catalog_object.kind,
        label=catalog_object.label,
        capabilities=capabilities,
        parent_path=visible_parent_path,
        placement_state=placement_state,
    )


def _project_parent_node(
    node: CatalogAssetReadNode,
    access: ReadAccess,
) -> CatalogAssetReadNode:
    capabilities = access.capabilities_for(node.id)
    if access.policy.can(Permission.READ, node.id):
        return CatalogAssetNode(
            capabilities=capabilities,
            ref=node.ref,
            id=node.id,
            kind=node.kind,
            label=node.label,
            status=node.status if isinstance(node, CatalogAssetNode) else "",
        )
    return CatalogAssetStubNode(
        capabilities=capabilities,
        ref=node.ref,
        id=node.id,
        kind=node.kind,
        label=node.label,
    )


def _object_status(catalog_object: CatalogObjectReadOut | None) -> str:
    if (
        catalog_object is not None
        and catalog_object.visibility == ObjectVisibility.DETAIL
    ):
        return catalog_object.status
    return ""


def _object_data(catalog_object: CatalogObjectReadOut | None) -> dict[str, Any]:
    if (
        catalog_object is not None
        and catalog_object.visibility == ObjectVisibility.DETAIL
    ):
        return catalog_object.data
    return {}


def _list_of_mappings(value: Any) -> list[Mapping[str, Any]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, Mapping)]
