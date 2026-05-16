import json
from collections.abc import Mapping
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from blockwart.domain.security import FORBIDDEN_SECRET_KEYS, looks_like_secret
from blockwart.models import CatalogObject, Relationship
from blockwart.schemas.agent import (
    AgentCatalogObjectContext,
    AgentCatalogObjectSummary,
    AgentRelationshipOut,
)
from blockwart.schemas.catalog import ObjectKind

REDACTED = "[redacted-secret-field]"


def search_agent_objects(
    session: Session,
    *,
    query: str | None = None,
    kind: ObjectKind | None = None,
    limit: int = 10,
) -> list[AgentCatalogObjectSummary]:
    objects = _search_raw_objects(session, query=query, kind=kind, limit=limit)
    return [_to_agent_summary(obj) for obj in objects]


def get_agent_object_context(
    session: Session,
    object_id: str,
) -> AgentCatalogObjectContext | None:
    catalog_object = session.get(CatalogObject, object_id)
    if catalog_object is None:
        return None
    return _to_agent_context(session, catalog_object)


def build_agent_context(
    session: Session,
    *,
    query: str | None = None,
    kind: ObjectKind | None = None,
    limit: int = 5,
) -> list[AgentCatalogObjectContext]:
    objects = _search_raw_objects(session, query=query, kind=kind, limit=limit)
    return [_to_agent_context(session, obj) for obj in objects]


def _search_raw_objects(
    session: Session,
    *,
    query: str | None,
    kind: ObjectKind | None,
    limit: int,
) -> list[CatalogObject]:
    statement = select(CatalogObject)
    if kind:
        statement = statement.where(CatalogObject.kind == kind)
    if query:
        term = f"%{query.lower()}%"
        statement = statement.where(
            CatalogObject.id.ilike(term)
            | CatalogObject.label.ilike(term)
            | CatalogObject.summary.ilike(term)
            | CatalogObject.data_json.ilike(term)
        )
    statement = statement.order_by(CatalogObject.kind, CatalogObject.label).limit(limit)
    return list(session.scalars(statement).all())


def _to_agent_summary(obj: CatalogObject) -> AgentCatalogObjectSummary:
    return AgentCatalogObjectSummary(
        ref=f"{obj.kind}:{obj.id}",
        id=obj.id,
        kind=obj.kind,
        label=obj.label,
        status=obj.status,
        summary=obj.summary,
    )


def _to_agent_context(session: Session, obj: CatalogObject) -> AgentCatalogObjectContext:
    relationships = _list_agent_relationships(session, obj)
    safe_data = _sanitize_for_agent(json.loads(obj.data_json))
    return AgentCatalogObjectContext(
        **_to_agent_summary(obj).model_dump(),
        data=safe_data,
        relationships=relationships,
        credential_references=sorted(_collect_credential_references(safe_data)),
    )


def _list_agent_relationships(session: Session, obj: CatalogObject) -> list[AgentRelationshipOut]:
    object_ref = f"{obj.kind}:{obj.id}"
    statement = (
        select(Relationship)
        .where((Relationship.from_ref == object_ref) | (Relationship.to_ref == object_ref))
        .order_by(Relationship.relation_type, Relationship.from_ref, Relationship.to_ref)
    )
    rows = session.scalars(statement).all()
    return [
        AgentRelationshipOut(
            from_ref=row.from_ref,
            relation_type=row.relation_type,
            to_ref=row.to_ref,
        )
        for row in rows
    ]


def _sanitize_for_agent(value: Any) -> Any:
    if isinstance(value, Mapping):
        safe: dict[str, Any] = {}
        for key, child in value.items():
            key_text = str(key)
            if key_text.lower() in FORBIDDEN_SECRET_KEYS:
                safe[key_text] = REDACTED
                continue
            safe[key_text] = _sanitize_for_agent(child)
        return safe
    if isinstance(value, list):
        return [_sanitize_for_agent(item) for item in value]
    if isinstance(value, str) and looks_like_secret(value):
        return REDACTED
    return value


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
