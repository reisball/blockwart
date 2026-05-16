import json
from datetime import UTC, datetime

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from blockwart.models import AuditEvent, CatalogObject, Relationship
from blockwart.schemas.catalog import CatalogObjectIn, CatalogObjectOut


def _to_schema(row: CatalogObject) -> CatalogObjectOut:
    updated_at = _format_timestamp(row.updated_at)
    return CatalogObjectOut(
        id=row.id,
        kind=row.kind,  # type: ignore[arg-type]
        label=row.label,
        status=_normalize_status(row.status),
        summary=row.summary,
        data=json.loads(row.data_json),
        created_at=_format_timestamp(row.created_at),
        updated_at=updated_at,
        last_changed=updated_at,
    )


def _normalize_status(status: str | None) -> str:
    if status in {"active", "inactive", "deleted"}:
        return status
    if status in {"partial", "unknown", "", None}:
        return "inactive"
    return "inactive"


def _format_timestamp(value: datetime | None) -> str | None:
    if value is None:
        return None
    return value.isoformat(timespec="microseconds")


def _now() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


def _write_audit(session: Session, object_id: str | None, action: str, summary: str) -> None:
    session.add(
        AuditEvent(
            object_id=object_id,
            action=action,
            actor="system",
            summary=summary,
        )
    )


def list_objects(session: Session) -> list[CatalogObjectOut]:
    statement = select(CatalogObject).order_by(CatalogObject.kind, CatalogObject.label)
    rows = session.scalars(statement).all()
    return [_to_schema(row) for row in rows]


def search_objects(
    session: Session,
    *,
    query: str | None = None,
    kind: str | None = None,
) -> list[CatalogObjectOut]:
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
    statement = statement.order_by(CatalogObject.kind, CatalogObject.label)
    rows = session.scalars(statement).all()
    return [_to_schema(row) for row in rows]


def get_object(session: Session, object_id: str) -> CatalogObjectOut | None:
    row = session.get(CatalogObject, object_id)
    if row is None:
        return None
    return _to_schema(row)


def list_relationships_for_object(
    session: Session,
    catalog_object: CatalogObjectOut,
) -> list[dict[str, str]]:
    object_ref = f"{catalog_object.kind}:{catalog_object.id}"
    statement = (
        select(Relationship)
        .where((Relationship.from_ref == object_ref) | (Relationship.to_ref == object_ref))
        .order_by(Relationship.relation_type, Relationship.from_ref, Relationship.to_ref)
    )
    rows = session.scalars(statement).all()
    return [
        {
            "from_ref": row.from_ref,
            "relation_type": row.relation_type,
            "to_ref": row.to_ref,
        }
        for row in rows
    ]


def create_relationship(
    session: Session,
    *,
    from_ref: str,
    relation_type: str,
    to_ref: str,
) -> dict[str, str]:
    existing = session.scalar(
        select(Relationship).where(
            Relationship.from_ref == from_ref,
            Relationship.relation_type == relation_type,
            Relationship.to_ref == to_ref,
        )
    )
    if existing is None:
        changed_at = _now()
        session.add(
            Relationship(
                from_ref=from_ref,
                relation_type=relation_type,
                to_ref=to_ref,
            )
        )
        _write_audit(
            session,
            None,
            "relationship_create",
            f"Create relationship {from_ref} {relation_type} {to_ref}",
        )
        _touch_objects_for_refs(session, [from_ref, to_ref], changed_at)
        session.commit()
    return {"from_ref": from_ref, "relation_type": relation_type, "to_ref": to_ref}


def upsert_object(session: Session, payload: CatalogObjectIn) -> CatalogObjectOut:
    row = session.get(CatalogObject, payload.id)
    data_json = json.dumps(payload.data, sort_keys=True)
    changed_at = _now()
    if row is None:
        action = "create"
        row = CatalogObject(
            id=payload.id,
            kind=payload.kind,
            label=payload.label,
            status=payload.status,
            summary=payload.summary,
            data_json=data_json,
            created_at=changed_at,
            updated_at=changed_at,
        )
        session.add(row)
    else:
        action = "update"
        row.kind = payload.kind
        row.label = payload.label
        row.status = payload.status
        row.summary = payload.summary
        row.data_json = data_json
        row.updated_at = changed_at

    summary = f"{action.title()} catalog object {payload.kind}:{payload.id}"
    _write_audit(session, payload.id, action, summary)
    session.commit()
    session.refresh(row)
    return _to_schema(row)


def delete_object(session: Session, object_id: str) -> bool:
    row = session.get(CatalogObject, object_id)
    if row is None:
        return False

    kind = row.kind
    object_ref = f"{kind}:{object_id}"
    session.execute(
        delete(Relationship).where(
            (Relationship.from_ref == object_ref) | (Relationship.to_ref == object_ref)
        )
    )
    session.delete(row)
    _write_audit(session, object_id, "delete", f"Delete catalog object {object_ref}")
    session.commit()
    return True


def _touch_objects_for_refs(session: Session, refs: list[str], changed_at: datetime) -> None:
    for ref in refs:
        if ":" not in ref:
            continue
        _, object_id = ref.split(":", 1)
        row = session.get(CatalogObject, object_id)
        if row is not None:
            row.updated_at = changed_at
