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


def list_audit_events_for_object(session: Session, object_id: str) -> list[dict[str, str]]:
    statement = (
        select(AuditEvent)
        .where(AuditEvent.object_id == object_id)
        .order_by(AuditEvent.created_at.desc(), AuditEvent.id.desc())
    )
    return [
        {
            "action": row.action,
            "actor": row.actor,
            "summary": _audit_summary(row.summary),
            "created_at": _format_log_timestamp(row.created_at),
        }
        for row in session.scalars(statement).all()
    ]


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
        audit_summary = f"Objekt erstellt: {payload.kind}:{payload.id}"
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
        audit_summary = _update_summary(row, payload, data_json)
        row.kind = payload.kind
        row.label = payload.label
        row.status = payload.status
        row.summary = payload.summary
        row.data_json = data_json
        row.updated_at = changed_at

    _write_audit(session, payload.id, action, audit_summary)
    session.commit()
    session.refresh(row)
    return _to_schema(row)


def _update_summary(row: CatalogObject, payload: CatalogObjectIn, data_json: str) -> str:
    changes: list[str] = []
    if row.kind != payload.kind:
        changes.append(_field_change("Typ", row.kind, payload.kind))
    if row.label != payload.label:
        changes.append(_field_change("Hostname", row.label, payload.label))
    if _normalize_status(row.status) != _normalize_status(payload.status):
        changes.append(_field_change("Status", _normalize_status(row.status), payload.status))
    if (row.summary or "") != (payload.summary or ""):
        changes.append(_field_change("Kurzbeschreibung", row.summary or "", payload.summary or ""))

    old_data = json.loads(row.data_json or "{}")
    if old_data != payload.data:
        changes.extend(_data_changes(old_data, payload.data))
    if not changes and row.data_json != data_json:
        changes.append("Daten wurden geändert")
    return "; ".join(changes) if changes else f"Objekt aktualisiert: {payload.kind}:{payload.id}"


def _format_log_timestamp(value: datetime | None) -> str:
    if value is None:
        return ""
    return value.strftime("%Y-%m-%d %H:%M:%S")


def _audit_summary(summary: str) -> str:
    if summary.startswith("Create catalog object "):
        return f"Objekt erstellt: {summary.removeprefix('Create catalog object ')}"
    if summary.startswith("Update catalog object "):
        return f"Objekt aktualisiert: {summary.removeprefix('Update catalog object ')}"
    if summary.startswith("Delete catalog object "):
        return f"Objekt gelöscht: {summary.removeprefix('Delete catalog object ')}"
    return summary


def _data_changes(old_data: dict, new_data: dict) -> list[str]:
    return _nested_data_changes(old_data, new_data)


def _nested_data_changes(old_value: object, new_value: object, path: str = "") -> list[str]:
    if old_value == new_value:
        return []
    if isinstance(old_value, dict) and new_value is None:
        return _nested_data_changes(old_value, {}, path)
    if old_value is None and isinstance(new_value, dict):
        return _nested_data_changes({}, new_value, path)
    if isinstance(old_value, dict) and isinstance(new_value, dict):
        changes: list[str] = []
        for key in sorted(set(old_value) | set(new_value)):
            child_path = f"{path}.{key}" if path else str(key)
            changes.extend(
                _nested_data_changes(
                    old_value.get(key),
                    new_value.get(key),
                    child_path,
                )
            )
        return changes
    label = _data_field_label(path)
    if _is_scalar_audit_value(old_value) and _is_scalar_audit_value(new_value):
        return [_field_change(label, _audit_scalar(old_value), _audit_scalar(new_value))]
    return [f"Feld {label} wurde geändert"]


def _is_scalar_audit_value(value: object) -> bool:
    return value is None or isinstance(value, str | int | float | bool)


def _audit_scalar(value: object) -> str:
    if value is None:
        return ""
    return str(value)


def _data_field_label(path: str) -> str:
    labels = {
        "access_methods": "Zugriff",
        "comment": "Kommentar",
        "container": "Container",
        "container.id": "Container ID",
        "container.label": "Container Label",
        "endpoints": "Endpoints",
        "hardware": "Hardware",
        "hardware.cpu": "CPU",
        "hardware.cpu.cores": "CPU Cores",
        "hardware.cpu.name": "CPU Name",
        "hardware.cpu.vendor": "CPU Hersteller",
        "hardware.gpu": "GPU",
        "hardware.memory": "Memory",
        "hardware.model": "Modell",
        "hardware.storage": "Storage / HDD",
        "labels": "Label",
        "network": "Netzwerk",
        "network.addresses": "Netzwerkadressen",
        "network.hostnames": "Hostname",
        "network.interfaces": "Netzwerkinterfaces",
        "platform": "Plattform",
        "ports": "Ports",
        "system_id": "System",
    }
    return labels.get(path, path or "Daten")


def _field_change(field: str, old_value: str | None, new_value: str | None) -> str:
    old_display = _display_value(old_value)
    new_display = _display_value(new_value)
    return f"Feld {field} wurde von {old_display} auf {new_display} geändert"


def _display_value(value: str | None) -> str:
    text = (value or "").strip()
    if not text:
        return "leer"
    if len(text) > 80:
        return f"{text[:77]}..."
    return text


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
    _write_audit(session, object_id, "delete", f"Objekt gelöscht: {object_ref}")
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
