from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from ipaddress import ip_address
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from blockwart.domain.asset_state import (
    AssetHealth,
    AssetLifecycle,
    state_from_record,
)
from blockwart.domain.auth import ObjectVisibility, Permission
from blockwart.domain.catalog_data import CatalogDataRead
from blockwart.domain.decisions import (
    DecisionStatus,
    decision_matches_filters,
    project_authorized_decision_data,
    validate_applies_to_filter,
)
from blockwart.domain.interfaces import (
    InterfaceContractError,
    normalize_interface_data,
)
from blockwart.domain.placement import PlacementGraph, placement_state
from blockwart.domain.projects import (
    ProjectCategory,
    ProjectStatus,
    project_authorized_data,
    project_matches_filters,
    validate_related_object_filter,
)
from blockwart.domain.provenance import (
    CatalogProvenanceOut,
    SourceType,
    load_provenance,
    provenance_for_read,
)
from blockwart.domain.security import redact_secret_values
from blockwart.domain.timestamps import format_rfc3339_utc
from blockwart.models import CatalogObject, Relationship
from blockwart.schemas.agent import (
    AgentAssetNode,
    AgentAssetReadNode,
    AgentAssetStubNode,
    AgentCatalogConcealed,
    AgentCatalogContextRead,
    AgentCatalogObjectContext,
    AgentCatalogObjectRead,
    AgentCatalogObjectStub,
    AgentCatalogObjectSummary,
    AgentRelationshipOut,
)
from blockwart.schemas.catalog import CatalogRecordDiagnostic, ObjectKind
from blockwart.schemas.comments import CommentOut
from blockwart.schemas.v1 import ObjectSortField, SortDirection
from blockwart.services.commands import revision_etag
from blockwart.services.comments import (
    recent_comments_for_object,
    recent_comments_for_objects,
)
from blockwart.services.pagination import CursorPage, paginate_items
from blockwart.services.read_access import ReadAccess
from blockwart.services.record_integrity import read_catalog_record_data


@dataclass(frozen=True, slots=True)
class AgentObjectPage:
    items: list[AgentCatalogObjectRead]
    next_cursor: str | None
    total: int | None


@dataclass(frozen=True, slots=True)
class AgentContextPage:
    items: list[AgentCatalogContextRead]
    next_cursor: str | None
    total: int | None


@dataclass(frozen=True, slots=True)
class _AgentRowsPage:
    resolver: _AgentCatalogResolver
    page: CursorPage[CatalogObject]


def query_agent_objects_page(
    session: Session,
    access: ReadAccess,
    *,
    query: str | None = None,
    kind: ObjectKind | None = None,
    parent: str | None = None,
    ip: str | None = None,
    port: int | None = None,
    endpoint_type: str | None = None,
    protocol: str | None = None,
    exposure: str | None = None,
    status: str | None = None,
    decision_status: DecisionStatus | None = None,
    applies_to: str | None = None,
    project_category: ProjectCategory | None = None,
    project_status: ProjectStatus | None = None,
    related_object: str | None = None,
    lifecycle: AssetLifecycle | None = None,
    health: AssetHealth | None = None,
    source_type: SourceType | None = None,
    stale: bool | None = None,
    limit: int = 50,
    cursor: str | None = None,
    sort: ObjectSortField = "id",
    direction: SortDirection = "asc",
    include_total: bool = False,
) -> AgentObjectPage:
    """Return one stable v1 page of sanitized catalog summaries."""
    rows_page = _query_agent_rows_page(
        session,
        access,
        query=query,
        kind=kind,
        parent=parent,
        ip=ip,
        port=port,
        endpoint_type=endpoint_type,
        protocol=protocol,
        exposure=exposure,
        status=status,
        decision_status=decision_status,
        applies_to=applies_to,
        project_category=project_category,
        project_status=project_status,
        related_object=related_object,
        lifecycle=lifecycle,
        health=health,
        source_type=source_type,
        stale=stale,
        limit=limit,
        cursor=cursor,
        sort=sort,
        direction=direction,
        include_total=include_total,
        resource="objects",
    )
    return AgentObjectPage(
        items=[
            rows_page.resolver.summary(catalog_object)
            for catalog_object in rows_page.page.items
        ],
        next_cursor=rows_page.page.next_cursor,
        total=rows_page.page.total,
    )


def query_agent_context_page(
    session: Session,
    access: ReadAccess,
    *,
    query: str | None = None,
    kind: ObjectKind | None = None,
    parent: str | None = None,
    ip: str | None = None,
    port: int | None = None,
    endpoint_type: str | None = None,
    protocol: str | None = None,
    exposure: str | None = None,
    status: str | None = None,
    decision_status: DecisionStatus | None = None,
    applies_to: str | None = None,
    project_category: ProjectCategory | None = None,
    project_status: ProjectStatus | None = None,
    related_object: str | None = None,
    lifecycle: AssetLifecycle | None = None,
    health: AssetHealth | None = None,
    source_type: SourceType | None = None,
    stale: bool | None = None,
    limit: int = 20,
    cursor: str | None = None,
    sort: ObjectSortField = "id",
    direction: SortDirection = "asc",
    include_total: bool = False,
) -> AgentContextPage:
    """Return one stable v1 page of sanitized object contexts."""
    rows_page = _query_agent_rows_page(
        session,
        access,
        query=query,
        kind=kind,
        parent=parent,
        ip=ip,
        port=port,
        endpoint_type=endpoint_type,
        protocol=protocol,
        exposure=exposure,
        status=status,
        decision_status=decision_status,
        applies_to=applies_to,
        project_category=project_category,
        project_status=project_status,
        related_object=related_object,
        lifecycle=lifecycle,
        health=health,
        source_type=source_type,
        stale=stale,
        limit=limit,
        cursor=cursor,
        sort=sort,
        direction=direction,
        include_total=include_total,
        resource="context",
    )
    return AgentContextPage(
        items=[
            rows_page.resolver.context(catalog_object)
            for catalog_object in rows_page.page.items
        ],
        next_cursor=rows_page.page.next_cursor,
        total=rows_page.page.total,
    )


def search_agent_objects(
    session: Session,
    access: ReadAccess,
    *,
    query: str | None = None,
    kind: ObjectKind | None = None,
    parent: str | None = None,
    ip: str | None = None,
    port: int | None = None,
    endpoint_type: str | None = None,
    protocol: str | None = None,
    exposure: str | None = None,
    status: str | None = None,
    decision_status: DecisionStatus | None = None,
    applies_to: str | None = None,
    project_category: ProjectCategory | None = None,
    project_status: ProjectStatus | None = None,
    related_object: str | None = None,
    lifecycle: AssetLifecycle | None = None,
    health: AssetHealth | None = None,
    source_type: SourceType | None = None,
    stale: bool | None = None,
    limit: int = 10,
) -> list[AgentCatalogObjectRead]:
    return query_agent_objects_page(
        session,
        access,
        query=query,
        kind=kind,
        parent=parent,
        ip=ip,
        port=port,
        endpoint_type=endpoint_type,
        protocol=protocol,
        exposure=exposure,
        status=status,
        decision_status=decision_status,
        applies_to=applies_to,
        project_category=project_category,
        project_status=project_status,
        related_object=related_object,
        lifecycle=lifecycle,
        health=health,
        source_type=source_type,
        stale=stale,
        limit=limit,
        sort="kind",
    ).items


@dataclass(frozen=True, slots=True)
class AgentObjectContextBatch:
    items: list[AgentCatalogContextRead | AgentCatalogConcealed]


def get_agent_object_context(
    session: Session,
    object_id: str,
    access: ReadAccess,
) -> AgentCatalogContextRead | None:
    resolver = _AgentCatalogResolver(session, access)
    catalog_object = resolver.object_by_id.get(object_id)
    if (
        catalog_object is None
        or access.policy.visibility_for(object_id) == ObjectVisibility.NONE
    ):
        return None
    return resolver.context(catalog_object)


def query_agent_object_contexts(
    session: Session,
    access: ReadAccess,
    object_ids: list[str],
) -> AgentObjectContextBatch:
    """Return authorized contexts for a bounded list of known object ids.

    Duplicate ids keep their first input position. Each unique id resolves to
    exactly one result item in input order: a full detail context (with
    write-ready etag and prefetched recent comments) when the caller can read
    it, a strict stub when the caller can only discover it, or a concealed
    placeholder when the caller cannot discover it or the id does not exist.
    Concealed and missing ids stay indistinguishable: the placeholder carries
    only the requested id. Objects, relationships, and the five newest comments
    for every authorized detail object are loaded in bounded snapshots so
    database access does not grow per requested id.

    Missing and existing-but-concealed ids receive equivalent bounded
    policy-shaped work: ``visibility_for`` is called for every requested id
    regardless of whether the object row exists, so the two cases do not take
    observably different shortcuts.
    """
    resolver = _AgentCatalogResolver(session, access)
    ordered_unique_ids: list[str] = []
    seen: set[str] = set()
    for object_id in object_ids:
        if object_id not in seen:
            seen.add(object_id)
            ordered_unique_ids.append(object_id)
    detail_objects: list[CatalogObject] = []
    by_id: dict[str, AgentCatalogContextRead | AgentCatalogConcealed] = {}
    for object_id in ordered_unique_ids:
        catalog_object = resolver.object_by_id.get(object_id)
        visibility = access.policy.visibility_for(object_id)
        if catalog_object is None or visibility == ObjectVisibility.NONE:
            by_id[object_id] = AgentCatalogConcealed(id=object_id)
        elif visibility == ObjectVisibility.STUB:
            by_id[object_id] = resolver.stub(catalog_object)
        else:
            detail_objects.append(catalog_object)
    recent_comments = resolver.prefetch_recent_comments(detail_objects)
    for catalog_object in detail_objects:
        by_id[catalog_object.id] = resolver.context_with_comments(
            catalog_object, recent_comments
        )
    ordered_items = [by_id[object_id] for object_id in ordered_unique_ids]
    return AgentObjectContextBatch(items=ordered_items)


def build_agent_context(
    session: Session,
    access: ReadAccess,
    *,
    query: str | None = None,
    kind: ObjectKind | None = None,
    parent: str | None = None,
    ip: str | None = None,
    port: int | None = None,
    endpoint_type: str | None = None,
    protocol: str | None = None,
    exposure: str | None = None,
    status: str | None = None,
    decision_status: DecisionStatus | None = None,
    applies_to: str | None = None,
    project_category: ProjectCategory | None = None,
    project_status: ProjectStatus | None = None,
    related_object: str | None = None,
    lifecycle: AssetLifecycle | None = None,
    health: AssetHealth | None = None,
    source_type: SourceType | None = None,
    stale: bool | None = None,
    limit: int = 5,
) -> list[AgentCatalogContextRead]:
    return query_agent_context_page(
        session,
        access,
        query=query,
        kind=kind,
        parent=parent,
        ip=ip,
        port=port,
        endpoint_type=endpoint_type,
        protocol=protocol,
        exposure=exposure,
        status=status,
        decision_status=decision_status,
        applies_to=applies_to,
        project_category=project_category,
        project_status=project_status,
        related_object=related_object,
        lifecycle=lifecycle,
        health=health,
        source_type=source_type,
        stale=stale,
        limit=limit,
        sort="kind",
    ).items


def _query_agent_rows_page(
    session: Session,
    access: ReadAccess,
    *,
    query: str | None,
    kind: ObjectKind | None,
    parent: str | None,
    ip: str | None,
    port: int | None,
    endpoint_type: str | None,
    protocol: str | None,
    exposure: str | None,
    status: str | None,
    decision_status: DecisionStatus | None,
    applies_to: str | None,
    project_category: ProjectCategory | None,
    project_status: ProjectStatus | None,
    related_object: str | None,
    lifecycle: AssetLifecycle | None,
    health: AssetHealth | None,
    source_type: SourceType | None,
    stale: bool | None,
    limit: int,
    cursor: str | None,
    sort: ObjectSortField,
    direction: SortDirection,
    include_total: bool,
    resource: str,
) -> _AgentRowsPage:
    resolver = _AgentCatalogResolver(session, access)
    objects = resolver.search(
        query=query,
        kind=kind,
        parent=parent,
        ip=ip,
        port=port,
        endpoint_type=endpoint_type,
        protocol=protocol,
        exposure=exposure,
        status=status,
        decision_status=decision_status,
        applies_to=applies_to,
        project_category=project_category,
        project_status=project_status,
        related_object=related_object,
        lifecycle=lifecycle,
        health=health,
        source_type=source_type,
        stale=stale,
        limit=None,
    )
    page = paginate_items(
        objects,
        key=lambda catalog_object: _object_sort_key(
            catalog_object,
            sort,
            access,
        ),
        limit=limit,
        resource=resource,
        sort=sort,
        direction=direction,
        query={
            "access": access.cursor_scope,
            "endpoint_type": _normalized_filter(endpoint_type),
            "exposure": _normalized_filter(exposure),
            "health": health,
            "ip": ip,
            "kind": kind,
            "lifecycle": lifecycle,
            "parent": parent,
            "port": port,
            "protocol": _normalized_filter(protocol),
            "q": query.strip().casefold() if query else None,
            "status": _normalized_filter(status),
            "decision_status": decision_status,
            "applies_to": applies_to,
            "project_category": project_category,
            "project_status": project_status,
            "related_object": related_object,
            "source_type": source_type,
            "stale": stale,
        },
        cursor=cursor,
        include_total=include_total,
    )
    return _AgentRowsPage(resolver=resolver, page=page)


class _AgentCatalogResolver:
    def __init__(self, session: Session, access: ReadAccess) -> None:
        self.session = session
        self.access = access
        self.now = datetime.now(UTC)
        self.objects = list(
            session.scalars(
                select(CatalogObject).order_by(CatalogObject.kind, CatalogObject.label)
            ).all()
        )
        self.object_by_id = {obj.id: obj for obj in self.objects}
        self.object_by_ref = {_object_ref(obj): obj for obj in self.objects}
        self.relationships = list(
            session.scalars(
                select(Relationship).order_by(
                    Relationship.relation_type,
                    Relationship.from_ref,
                    Relationship.to_ref,
                )
            ).all()
        )
        self.placements = PlacementGraph(self.objects, self.relationships)

    def search(
        self,
        *,
        query: str | None,
        kind: ObjectKind | None,
        parent: str | None,
        ip: str | None,
        port: int | None,
        endpoint_type: str | None,
        protocol: str | None,
        exposure: str | None,
        status: str | None,
        decision_status: DecisionStatus | None,
        applies_to: str | None,
        project_category: ProjectCategory | None,
        project_status: ProjectStatus | None,
        related_object: str | None,
        lifecycle: AssetLifecycle | None,
        health: AssetHealth | None,
        source_type: SourceType | None,
        stale: bool | None,
        limit: int | None,
    ) -> list[CatalogObject]:
        matches: list[CatalogObject] = []
        normalized_query = query.strip() if query else ""
        query_term = normalized_query.casefold() if normalized_query else None
        parsed_applies_to = (
            validate_applies_to_filter(applies_to) if applies_to is not None else None
        )
        if parsed_applies_to is not None and not self.access.policy.can(
            Permission.DISCOVER,
            parsed_applies_to.object_id,
        ):
            return []
        parsed_related_object = (
            validate_related_object_filter(related_object)
            if related_object is not None
            else None
        )
        if parsed_related_object is not None and not self.access.policy.can(
            Permission.DISCOVER,
            parsed_related_object.object_id,
        ):
            return []
        candidate_ids = self._candidate_ids(
            kind=kind,
        )
        for obj in self.objects:
            visibility = self.access.policy.visibility_for(obj.id)
            if visibility == ObjectVisibility.NONE:
                continue
            can_read = visibility == ObjectVisibility.DETAIL
            if obj.id not in candidate_ids:
                continue
            data = _safe_object_data(obj)
            if can_read:
                data = self._project_knowledge_data(obj.kind, data)
            state = state_from_record(
                kind=obj.kind,
                status=obj.status,
                lifecycle=obj.lifecycle,
                health=obj.health,
            )
            if query_term and not (
                _matches_query(obj, data, query_term)
                if can_read
                else _matches_stub_query(obj, query_term)
            ):
                continue
            if (
                (
                    status
                    or decision_status
                    or applies_to
                    or project_category
                    or project_status
                    or related_object
                    or lifecycle
                    or health
                    or ip
                    or port is not None
                    or endpoint_type
                    or protocol
                    or exposure
                    or source_type is not None
                    or stale is not None
                )
                and not can_read
            ):
                continue
            if status and obj.status.casefold() != status.casefold():
                continue
            if decision_status is not None or applies_to is not None:
                if obj.kind != "decision" or not decision_matches_filters(
                    data,
                    decision_status=decision_status,
                    applies_to=applies_to,
                ):
                    continue
            if (
                project_category is not None
                or project_status is not None
                or related_object is not None
            ):
                if obj.kind != "project" or not project_matches_filters(
                    data,
                    project_category=project_category,
                    project_status=project_status,
                    related_object=related_object,
                ):
                    continue
            if lifecycle and (state is None or state.lifecycle != lifecycle):
                continue
            if health and (state is None or state.health != health):
                continue
            if source_type is not None or stale is not None:
                provenance = self.provenance(obj)
                if (
                    source_type is not None
                    and provenance.source_type != source_type
                ):
                    continue
                if stale is not None and provenance.is_stale is not stale:
                    continue
            if parent and parent not in self.visible_parent_path_refs(obj):
                continue
            if ip and ip not in self.resolved_ips(obj):
                continue
            if port is not None and port not in self.ports(obj):
                continue
            endpoints = self.endpoints(obj)
            if endpoint_type and not _endpoint_value_matches(
                endpoints,
                "type",
                endpoint_type,
            ):
                continue
            if protocol and not _endpoint_value_matches(
                endpoints,
                "protocol",
                protocol,
            ):
                continue
            if exposure and not _endpoint_value_matches(
                endpoints,
                "exposure",
                exposure,
            ):
                continue
            matches.append(obj)
            if limit is not None and len(matches) == limit:
                break
        return matches

    def _project_knowledge_data(
        self,
        kind: str,
        data: dict[str, Any],
    ) -> dict[str, Any]:
        """Drop typed knowledge links whose targets the reader cannot discover."""
        if kind == "decision":
            return project_authorized_decision_data(
                data,
                can_discover=self._can_discover,
            )
        if kind == "project":
            return project_authorized_data(data, can_discover=self._can_discover)
        return data

    def _can_discover(self, object_id: str) -> bool:
        return self.access.policy.can(Permission.DISCOVER, object_id)

    def _candidate_ids(
        self,
        *,
        kind: ObjectKind | None,
    ) -> set[str]:
        statement = select(CatalogObject.id)
        if kind:
            statement = statement.where(CatalogObject.kind == kind)
        return set(self.session.scalars(statement).all())

    def summary(self, obj: CatalogObject) -> AgentCatalogObjectRead:
        if self.access.policy.visibility_for(obj.id) == ObjectVisibility.STUB:
            return self.stub(obj)
        record = _safe_object_record(obj)
        data = record.data
        projected_knowledge_data = self._project_knowledge_data(obj.kind, data)
        state = state_from_record(
            kind=obj.kind,
            status=obj.status,
            lifecycle=obj.lifecycle,
            health=obj.health,
        )
        parent_ref = self.canonical_parent_ref(obj)
        parent = self.node(parent_ref) if parent_ref else None
        endpoints = self.endpoints(obj)
        resolved_placement_state = placement_state(
            kind=obj.kind,
            parent_ref=parent_ref if parent is not None else None,
            data=data,
        )
        if parent_ref is not None and parent is None:
            resolved_placement_state = "unknown"
        return AgentCatalogObjectSummary(
            capabilities=self.access.capabilities_for(obj.id),
            ref=_object_ref(obj),
            id=obj.id,
            kind=obj.kind,
            label=obj.label,
            status=state.status if state is not None else obj.status,
            revision=obj.revision,
            summary=obj.summary,
            parent=parent,
            ips=self.resolved_ips(obj),
            hostnames=self.resolved_hostnames(obj),
            primary_endpoint=endpoints[0] if endpoints else None,
            lifecycle=state.lifecycle if state is not None else None,
            health=state.health if state is not None else None,
            decision_status=(
                projected_knowledge_data.get("decision_status")
                if obj.kind == "decision"
                else None
            ),
            applies_to=(
                _string_list(projected_knowledge_data.get("applies_to"))
                if obj.kind == "decision"
                else []
            ),
            project_category=(
                projected_knowledge_data.get("category")
                if obj.kind == "project"
                else None
            ),
            project_status=(
                projected_knowledge_data.get("project_status")
                if obj.kind == "project"
                else None
            ),
            related_assets=(
                _string_list(projected_knowledge_data.get("related_assets"))
                if obj.kind == "project"
                else []
            ),
            placement_state=resolved_placement_state,
            record_state=record.record_state,
            diagnostics=[
                CatalogRecordDiagnostic(
                    code=diagnostic.code,
                    object_id=diagnostic.object_id,
                    message=diagnostic.message,
                )
                for diagnostic in record.diagnostics
            ],
            provenance=self.provenance(obj),
        )

    def provenance(self, obj: CatalogObject) -> CatalogProvenanceOut:
        provenance, _ = load_provenance(obj.provenance_json)
        return provenance_for_read(provenance, now=self.now)

    def context(self, obj: CatalogObject) -> AgentCatalogContextRead:
        if self.access.policy.visibility_for(obj.id) == ObjectVisibility.STUB:
            return self.stub(obj)
        return self.context_with_comments(
            obj,
            {obj.id: recent_comments_for_object(self.session, obj, limit=5)},
        )

    def context_with_comments(
        self,
        obj: CatalogObject,
        recent_comments: dict[str, list[CommentOut]],
    ) -> AgentCatalogObjectContext:
        data = self._project_knowledge_data(obj.kind, _safe_object_data(obj))
        object_ref = _object_ref(obj)
        relationships = [
            AgentRelationshipOut(
                from_ref=row.from_ref,
                relation_type=row.relation_type,
                to_ref=row.to_ref,
            )
            for row in self.relationships
            if (
                (row.from_ref == object_ref or row.to_ref == object_ref)
                and self.relationship_visible(row)
            )
        ]
        return AgentCatalogObjectContext(
            **self.summary(obj).model_dump(),
            etag=revision_etag(obj.revision),
            data=data,
            relationships=relationships,
            parent_path=[
                node
                for parent_ref in self.visible_parent_path_refs(obj)
                if (node := self.node(parent_ref)) is not None
            ],
            children=[
                node
                for child_ref in self.placements.children_refs(object_ref)
                if (node := self.node(child_ref)) is not None
            ],
            endpoints=self.endpoints(obj),
            source_references=[
                dict(reference) for reference in _mapping_list(data.get("source_references"))
            ],
            updated_at=format_rfc3339_utc(obj.updated_at),
            dependencies=self.dependencies(object_ref),
            credential_references=sorted(_collect_credential_references(data)),
            recent_comments=recent_comments.get(obj.id, []),
        )

    def prefetch_recent_comments(
        self,
        objects: list[CatalogObject],
    ) -> dict[str, list[CommentOut]]:
        if not objects:
            return {}
        return recent_comments_for_objects(self.session, objects, limit=5)

    def stub(self, obj: CatalogObject) -> AgentCatalogObjectStub:
        object_ref = _object_ref(obj)
        parent_ref = self.canonical_parent_ref(obj)
        visible_parent_refs = self.visible_parent_path_refs(obj)
        visible_parent = (
            parent_ref
            if parent_ref in visible_parent_refs
            else None
        )
        state = placement_state(
            kind=obj.kind,
            parent_ref=visible_parent,
            data=_safe_object_data(obj),
        )
        if parent_ref is not None and visible_parent is None:
            state = "unknown"
        return AgentCatalogObjectStub(
            capabilities=self.access.capabilities_for(obj.id),
            ref=object_ref,
            id=obj.id,
            kind=obj.kind,
            label=obj.label,
            parent=self.node(visible_parent) if visible_parent else None,
            parent_path=[
                node
                for ancestor_ref in visible_parent_refs
                if (node := self.node(ancestor_ref)) is not None
            ],
            placement_state=state,
        )

    def node(self, object_ref: str) -> AgentAssetReadNode | None:
        obj = self.object_by_ref.get(object_ref)
        if (
            obj is None
            or not self.access.policy.can(Permission.DISCOVER, obj.id)
        ):
            return None
        capabilities = self.access.capabilities_for(obj.id)
        if not self.access.policy.can(Permission.READ, obj.id):
            return AgentAssetStubNode(
                capabilities=capabilities,
                ref=object_ref,
                id=obj.id,
                kind=obj.kind,
                label=obj.label,
            )
        return AgentAssetNode(
            capabilities=capabilities,
            ref=object_ref,
            id=obj.id,
            kind=obj.kind,
            label=obj.label,
            status=obj.status,
        )

    def canonical_parent_ref(self, obj: CatalogObject) -> str | None:
        return self.placements.parent_ref(_object_ref(obj))

    def parent_path_refs(self, obj: CatalogObject) -> list[str]:
        return self.placements.parent_path_refs(_object_ref(obj))

    def visible_parent_path_refs(self, obj: CatalogObject) -> list[str]:
        return self._parent_path_refs_with_permission(obj, Permission.DISCOVER)

    def readable_parent_path_refs(self, obj: CatalogObject) -> list[str]:
        return self._parent_path_refs_with_permission(obj, Permission.READ)

    def _parent_path_refs_with_permission(
        self,
        obj: CatalogObject,
        permission: Permission,
    ) -> list[str]:
        authorized: list[str] = []
        for object_ref in reversed(self.parent_path_refs(obj)):
            ancestor = self.object_by_ref.get(object_ref)
            if (
                ancestor is None
                or not self.access.policy.can(permission, ancestor.id)
            ):
                break
            authorized.append(object_ref)
        authorized.reverse()
        return authorized

    def endpoints(self, obj: CatalogObject) -> list[dict[str, Any]]:
        data = _safe_object_data(obj)
        try:
            normalized = normalize_interface_data(
                data,
                kind=obj.kind,
                object_id=obj.id,
                allow_legacy=True,
            ).data
        except InterfaceContractError:
            return []
        return [
            dict(endpoint)
            for endpoint in _mapping_list(normalized.get("endpoints"))
        ]

    def resolved_ips(self, obj: CatalogObject) -> list[str]:
        own_ips = _object_ips(_safe_object_data(obj), self.endpoints(obj))
        if own_ips:
            return own_ips
        for parent_ref in reversed(self.readable_parent_path_refs(obj)):
            parent = self.object_by_ref.get(parent_ref)
            if parent is None:
                continue
            parent_ips = _object_ips(_safe_object_data(parent), self.endpoints(parent))
            if parent_ips:
                return parent_ips
        return []

    def resolved_hostnames(self, obj: CatalogObject) -> list[str]:
        own_hostnames = _object_hostnames(_safe_object_data(obj), self.endpoints(obj))
        if own_hostnames:
            return own_hostnames
        for parent_ref in reversed(self.readable_parent_path_refs(obj)):
            parent = self.object_by_ref.get(parent_ref)
            if parent is None:
                continue
            parent_hostnames = _object_hostnames(
                _safe_object_data(parent),
                self.endpoints(parent),
            )
            if parent_hostnames:
                return parent_hostnames
        return []

    def ports(self, obj: CatalogObject) -> set[int]:
        ports = {
            endpoint["port"]
            for endpoint in self.endpoints(obj)
            if isinstance(endpoint.get("port"), int)
        }
        for port_entry in _mapping_list(_safe_object_data(obj).get("ports")):
            port_value = port_entry.get("port")
            if isinstance(port_value, int) and not isinstance(port_value, bool):
                ports.add(port_value)
        return ports

    def dependencies(self, object_ref: str) -> dict[str, list[str]]:
        upstream = sorted(
            {
                relationship.to_ref
                for relationship in self.relationships
                if relationship.relation_type == "depends_on"
                and relationship.from_ref == object_ref
                and self.relationship_visible(relationship)
            }
        )
        downstream = sorted(
            {
                relationship.from_ref
                for relationship in self.relationships
                if relationship.relation_type == "depends_on"
                and relationship.to_ref == object_ref
                and self.relationship_visible(relationship)
            }
        )
        if not upstream and not downstream:
            return {}
        return {"upstream": upstream, "downstream": downstream}

    def relationship_visible(self, relationship: Relationship) -> bool:
        from_object = self.object_by_ref.get(relationship.from_ref)
        to_object = self.object_by_ref.get(relationship.to_ref)
        if from_object is None or to_object is None:
            return False
        permission = (
            Permission.DISCOVER
            if relationship.relation_type == "hosts"
            else Permission.READ
        )
        return (
            self.access.policy.can(permission, from_object.id)
            and self.access.policy.can(permission, to_object.id)
        )


def _safe_object_data(obj: CatalogObject) -> dict[str, Any]:
    return _safe_object_record(obj).data


def _safe_object_record(obj: CatalogObject) -> CatalogDataRead:
    record = read_catalog_record_data(obj, retain_schema_invalid_data=True)
    sanitized = redact_secret_values(record.data)
    return CatalogDataRead(
        data=sanitized if isinstance(sanitized, dict) else {},
        record_state=record.record_state,
        diagnostics=record.diagnostics,
    )


def _matches_query(obj: CatalogObject, data: Mapping[str, Any], query_term: str) -> bool:
    values = [
        obj.id,
        obj.label,
        obj.summary or "",
        json.dumps(data, sort_keys=True),
        obj.provenance_json,
    ]
    return any(query_term in value.casefold() for value in values)


def _matches_stub_query(obj: CatalogObject, query_term: str) -> bool:
    return any(
        query_term in value.casefold()
        for value in (obj.id, obj.kind, obj.label)
    )


def _endpoint_value_matches(
    endpoints: list[dict[str, Any]],
    field: str,
    expected: str,
) -> bool:
    return any(
        isinstance(value := endpoint.get(field), str)
        and value.casefold() == expected.casefold()
        for endpoint in endpoints
    )


def _object_ref(obj: CatalogObject) -> str:
    return f"{obj.kind}:{obj.id}"


def _object_sort_key(
    obj: CatalogObject,
    sort: ObjectSortField,
    access: ReadAccess,
) -> tuple[str, str]:
    if sort == "label":
        return obj.label.casefold(), obj.id
    if sort == "kind":
        return obj.kind.casefold(), f"{obj.label.casefold()}\0{obj.id}"
    if sort == "updated_at":
        updated_at = (
            format_rfc3339_utc(obj.updated_at) or ""
            if access.policy.can(Permission.READ, obj.id)
            else ""
        )
        return updated_at, obj.id
    return obj.id.casefold(), obj.id


def _normalized_filter(value: str | None) -> str | None:
    return value.casefold() if value else None


def _optional_text(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


def _mapping_list(value: Any) -> list[Mapping[str, Any]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, Mapping)]


def _object_ips(data: Mapping[str, Any], endpoints: list[dict[str, Any]]) -> list[str]:
    candidates: list[Any] = []
    network = data.get("network")
    if isinstance(network, Mapping):
        candidates.extend(
            address.get("ip") for address in _mapping_list(network.get("addresses"))
        )
    candidates.extend(endpoint.get("host") for endpoint in endpoints)
    return _unique_strings(value for value in candidates if _is_ip(value))


def _object_hostnames(data: Mapping[str, Any], endpoints: list[dict[str, Any]]) -> list[str]:
    candidates: list[Any] = []
    network = data.get("network")
    if isinstance(network, Mapping):
        hostnames = network.get("hostnames")
        if isinstance(hostnames, list):
            candidates.extend(hostnames)
    candidates.extend(endpoint.get("host") for endpoint in endpoints)
    return _unique_strings(
        value for value in candidates if isinstance(value, str) and not _is_ip(value)
    )


def _is_ip(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    try:
        ip_address(value)
    except ValueError:
        return False
    return True


def _string_list(values: Any) -> list[str]:
    """Project one authorized typed-reference array onto its readable strings."""
    if not isinstance(values, list):
        return []
    return [value for value in values if isinstance(value, str)]


def _unique_strings(values: Any) -> list[str]:
    unique: list[str] = []
    for value in values:
        if isinstance(value, str) and value not in unique:
            unique.append(value)
    return unique




def _collect_credential_references(value: Any) -> set[str]:
    references: set[str] = set()
    if isinstance(value, Mapping):
        for key, child in value.items():
            if key == "credential_references" and isinstance(child, list):
                references.update(item for item in child if _is_credential_reference(item))
            elif _is_credential_reference(child):
                references.add(child)
            references.update(_collect_credential_references(child))
    elif isinstance(value, list):
        for item in value:
            if _is_credential_reference(item):
                references.add(item)
            references.update(_collect_credential_references(item))
    return references


def _is_credential_reference(value: Any) -> bool:
    return isinstance(value, str) and value.startswith("credential_reference:")
