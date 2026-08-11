import json
from collections.abc import Mapping
from datetime import UTC, datetime

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from blockwart.domain.asset_state import (
    AssetHealth,
    AssetLifecycle,
    AssetState,
    resolve_asset_state,
    state_from_record,
)
from blockwart.domain.decisions import validate_decision_integrity
from blockwart.domain.placement import (
    CANONICAL_PLACEMENT_RELATION_TYPE,
    PlacementError,
    PlacementGraph,
    is_explicitly_unassigned,
    placement_state,
)
from blockwart.domain.provenance import (
    dump_provenance,
    load_provenance,
    provenance_for_read,
)
from blockwart.domain.relationships import (
    EndpointDescriptor,
    RelationshipDiagnostic,
    RelationshipIntegrityError,
    canonical_relationship_metadata_json,
    diagnose_relationship_integrity,
    endpoint_descriptor_map,
    iter_typed_reference_strings,
    validate_data_references,
    validate_relationship,
    validate_relationship_collection,
)
from blockwart.domain.timestamps import format_rfc3339_utc
from blockwart.models import AuditEvent, CatalogObject, Relationship
from blockwart.schemas.catalog import (
    CatalogAssetNode,
    CatalogObjectIn,
    CatalogObjectOut,
    CatalogRecordDiagnostic,
)
from blockwart.services.access import (
    active_owner_covered_object_ids,
    ensure_owner_coverage_preserved,
)
from blockwart.services.audit import (
    add_audit_event,
    load_audit_details,
    render_audit_summary_english,
)
from blockwart.services.record_integrity import read_catalog_record_data


def _to_schema(
    row: CatalogObject,
    placement_graph: PlacementGraph | None = None,
) -> CatalogObjectOut:
    asset_state = state_from_record(
        kind=row.kind,
        status=row.status,
        lifecycle=row.lifecycle,
        health=row.health,
    )
    updated_at = format_rfc3339_utc(row.updated_at)
    record = read_catalog_record_data(row)
    provenance, _ = load_provenance(row.provenance_json)
    data = record.data
    parent_path = []
    parent_ref = None
    if placement_graph is not None:
        parent_ref = placement_graph.parent_ref(_object_ref(row))
        parent_path = [
            _placement_node(placement_graph, parent_ref)
            for parent_ref in placement_graph.parent_path_refs(_object_ref(row))
        ]
    return CatalogObjectOut(
        id=row.id,
        kind=row.kind,  # type: ignore[arg-type]
        label=row.label,
        status=asset_state.status if asset_state is not None else _normalize_status(row.status),
        lifecycle=asset_state.lifecycle if asset_state is not None else None,
        health=asset_state.health if asset_state is not None else None,
        summary=row.summary,
        data=data,
        provenance=provenance_for_read(provenance),
        revision=row.revision,
        created_at=format_rfc3339_utc(row.created_at),
        updated_at=updated_at,
        last_changed=updated_at,
        parent_path=parent_path,
        placement_state=placement_state(
            kind=row.kind,
            parent_ref=parent_ref,
            data=data,
        ),
        record_state=record.record_state,
        diagnostics=[
            CatalogRecordDiagnostic(
                code=diagnostic.code,
                object_id=diagnostic.object_id,
                message=diagnostic.message,
            )
            for diagnostic in record.diagnostics
        ],
    )


def _placement_node(
    placement_graph: PlacementGraph,
    object_ref: str,
) -> CatalogAssetNode:
    row = placement_graph.object_by_ref[object_ref]
    return CatalogAssetNode(
        ref=object_ref,
        id=row.id,
        kind=row.kind,  # type: ignore[arg-type]
        label=row.label,
        status=row.status,
    )


def _object_ref(row: CatalogObject) -> str:
    return f"{row.kind}:{row.id}"


def _schemas_with_placement(
    session: Session,
    rows: list[CatalogObject],
) -> list[CatalogObjectOut]:
    all_objects = list(
        session.scalars(
            select(CatalogObject).order_by(CatalogObject.kind, CatalogObject.label)
        ).all()
    )
    relationships = list(
        session.scalars(
            select(Relationship).order_by(
                Relationship.relation_type,
                Relationship.from_ref,
                Relationship.to_ref,
            )
        ).all()
    )
    placement_graph = PlacementGraph(all_objects, relationships)
    return [_to_schema(row, placement_graph) for row in rows]


def _normalize_status(status: str | None) -> str:
    if status in {"active", "inactive", "deleted"}:
        return status
    if status in {"partial", "unknown", "", None}:
        return "inactive"
    return "inactive"


def _now() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


def _write_audit(
    session: Session,
    object_id: str | None,
    action: str,
    details: Mapping[str, object] | None = None,
    *,
    actor: str = "system",
) -> None:
    add_audit_event(
        session,
        object_id=object_id,
        action=action,
        actor=actor,
        details=details,
    )


def list_audit_events_for_object(
    session: Session,
    object_id: str,
) -> list[dict[str, object]]:
    statement = (
        select(AuditEvent)
        .where(AuditEvent.object_id == object_id)
        .order_by(AuditEvent.created_at.desc(), AuditEvent.id.desc())
    )
    events: list[dict[str, object]] = []
    for row in session.scalars(statement).all():
        details = load_audit_details(row)
        events.append(
            {
                "id": row.id,
                "action": row.action,
                "actor": row.actor,
                "summary": render_audit_summary_english(
                    row.action,
                    details,
                    legacy_summary=row.summary,
                ),
                "details": details,
                "created_at": _format_log_timestamp(row.created_at),
            }
        )
    return events


def list_objects(
    session: Session,
    *,
    lifecycle: AssetLifecycle | None = None,
    health: AssetHealth | None = None,
) -> list[CatalogObjectOut]:
    statement = select(CatalogObject).order_by(CatalogObject.kind, CatalogObject.label)
    rows = list(session.scalars(statement).all())
    rows = _filter_asset_state(rows, lifecycle=lifecycle, health=health)
    return _schemas_with_placement(session, rows)


def search_objects(
    session: Session,
    *,
    query: str | None = None,
    kind: str | None = None,
    lifecycle: AssetLifecycle | None = None,
    health: AssetHealth | None = None,
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
    rows = list(session.scalars(statement).all())
    rows = _filter_asset_state(rows, lifecycle=lifecycle, health=health)
    return _schemas_with_placement(session, rows)


def _filter_asset_state(
    rows: list[CatalogObject],
    *,
    lifecycle: AssetLifecycle | None,
    health: AssetHealth | None,
) -> list[CatalogObject]:
    if lifecycle is None and health is None:
        return rows
    matches: list[CatalogObject] = []
    for row in rows:
        state = state_from_record(
            kind=row.kind,
            status=row.status,
            lifecycle=row.lifecycle,
            health=row.health,
        )
        if state is None:
            continue
        if lifecycle is not None and state.lifecycle != lifecycle:
            continue
        if health is not None and state.health != health:
            continue
        matches.append(row)
    return matches


def get_object(session: Session, object_id: str) -> CatalogObjectOut | None:
    row = session.get(CatalogObject, object_id)
    if row is None:
        return None
    return _schemas_with_placement(session, [row])[0]


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
    metadata: Mapping[str, object] | None = None,
    audit_action: str = "relationship_create",
    audit_actor: str = "system",
    write_audit: bool = True,
    touch_revisions: bool = True,
) -> dict[str, str]:
    endpoints = current_endpoint_descriptors(session)
    metadata_json = canonical_relationship_metadata_json(relation_type, metadata)
    validate_relationship(
        from_ref=from_ref,
        relation_type=relation_type,
        to_ref=to_ref,
        endpoints=endpoints,
    )
    existing = session.scalar(
        select(Relationship).where(
            Relationship.from_ref == from_ref,
            Relationship.relation_type == relation_type,
            Relationship.to_ref == to_ref,
        )
    )
    if existing is not None and existing.metadata_json != metadata_json:
        raise RelationshipIntegrityError(
            "relationship_metadata_conflict",
            "relationship already exists with different metadata",
        )
    if relation_type == CANONICAL_PLACEMENT_RELATION_TYPE:
        _validate_placement_relationship(
            session,
            parent_ref=from_ref,
            child_ref=to_ref,
        )
    relationship_rows = list(
        session.scalars(
            select(Relationship).order_by(
                Relationship.id,
                Relationship.from_ref,
                Relationship.relation_type,
                Relationship.to_ref,
            )
        ).all()
    )
    if existing is None:
        relationship_rows.append(
            {
                "from_ref": from_ref,
                "relation_type": relation_type,
                "to_ref": to_ref,
                "metadata_json": metadata_json,
            }
        )
    validate_relationship_collection(relationship_rows, endpoints)
    changed_at = _now()
    cleared_unassigned = False
    if relation_type == CANONICAL_PLACEMENT_RELATION_TYPE:
        cleared_unassigned = _clear_explicit_unassigned_state(
            session,
            child_ref=to_ref,
            changed_at=changed_at,
            write_audit=write_audit,
        )
    if existing is not None:
        if cleared_unassigned:
            touch_objects_for_refs(session, [to_ref], changed_at)
        session.flush()
        return {"from_ref": from_ref, "relation_type": relation_type, "to_ref": to_ref}
    session.add(
        Relationship(
            from_ref=from_ref,
            relation_type=relation_type,
            to_ref=to_ref,
            metadata_json=metadata_json,
        )
    )
    if write_audit:
        _write_audit(
            session,
            None,
            audit_action,
            {
                "from_ref": from_ref,
                "relation_type": relation_type,
                "to_ref": to_ref,
            },
            actor=audit_actor,
        )
    if touch_revisions:
        touch_objects_for_refs(session, [from_ref, to_ref], changed_at)
    session.flush()
    return {"from_ref": from_ref, "relation_type": relation_type, "to_ref": to_ref}


def _clear_explicit_unassigned_state(
    session: Session,
    *,
    child_ref: str,
    changed_at: datetime,
    write_audit: bool = True,
) -> bool:
    _, child_id = child_ref.split(":", 1)
    row = session.get(CatalogObject, child_id)
    if row is None:
        return False
    data = json.loads(row.data_json)
    if not is_explicitly_unassigned(data):
        return False
    data.pop("placement", None)
    row.data_json = json.dumps(data, sort_keys=True)
    row.updated_at = changed_at
    if write_audit:
        _write_audit(
            session,
            child_id,
            "placement_assign",
            {"child_ref": child_ref},
        )
    return True


def delete_relationship(
    session: Session,
    relationship_id: int,
    *,
    audit_action: str = "relationship_delete",
    audit_actor: str = "system",
    enforce_owner_coverage: bool = True,
    write_audit: bool = True,
    touch_revisions: bool = True,
) -> bool:
    row = session.get(Relationship, relationship_id)
    if row is None:
        return False
    previously_covered_ids = (
        active_owner_covered_object_ids(session)
        if (
            enforce_owner_coverage
            and row.relation_type == CANONICAL_PLACEMENT_RELATION_TYPE
        )
        else set()
    )
    from_ref = row.from_ref
    relation_type = row.relation_type
    to_ref = row.to_ref
    session.delete(row)
    if touch_revisions:
        touch_objects_for_refs(session, [from_ref, to_ref], _now())
    if write_audit:
        _write_audit(
            session,
            None,
            audit_action,
            {
                "from_ref": from_ref,
                "relation_type": relation_type,
                "to_ref": to_ref,
            },
            actor=audit_actor,
        )
    session.flush()
    if previously_covered_ids:
        ensure_owner_coverage_preserved(
            session,
            previously_covered_ids=previously_covered_ids,
        )
    return True


def _validate_placement_relationship(
    session: Session,
    *,
    parent_ref: str,
    child_ref: str,
) -> None:
    existing_parent = session.scalar(
        select(Relationship).where(
            Relationship.relation_type == CANONICAL_PLACEMENT_RELATION_TYPE,
            Relationship.to_ref == child_ref,
            Relationship.from_ref != parent_ref,
        )
    )
    if existing_parent is not None:
        raise PlacementError(
            f"{child_ref} already has placement parent {existing_parent.from_ref}"
        )


def upsert_object(
    session: Session,
    payload: CatalogObjectIn,
    *,
    known_object_kinds: Mapping[str, str] | None = None,
    expected_revision: int | None = None,
    write_audit: bool = True,
) -> CatalogObjectOut:
    row = session.get(CatalogObject, payload.id)
    object_kinds = current_object_kinds(session)
    if known_object_kinds is not None:
        object_kinds.update(known_object_kinds)
    object_kinds[payload.id] = payload.kind
    validate_data_references(
        payload.data,
        object_kinds,
        object_id=payload.id,
    )
    if payload.kind == "decision":
        validate_decision_integrity(
            session.scalars(
                select(CatalogObject).where(CatalogObject.kind == "decision")
            ).all(),
            object_id=payload.id,
            data=payload.data,
        )
    if row is not None and row.kind != payload.kind:
        ensure_kind_change_allowed(session, row, payload.kind)
    if row is not None:
        ensure_projected_relationship_endpoints_valid(session, row, payload)
    current_state = (
        state_from_record(
            kind=row.kind,
            status=row.status,
            lifecycle=row.lifecycle,
            health=row.health,
        )
        if row is not None
        else None
    )
    target_state = resolve_asset_state(
        kind=payload.kind,
        status=payload.status,
        lifecycle=payload.lifecycle,
        health=payload.health,
        current=current_state,
    )
    target_status = target_state.status if target_state is not None else payload.status
    data_json = json.dumps(payload.data, sort_keys=True)
    provenance_json = dump_provenance(payload.provenance)
    if row is not None and expected_revision is not None and row.revision != expected_revision:
        raise RevisionConflict("catalog object revision does not match")
    if row is not None and _object_matches_target(
        row,
        payload,
        data_json,
        provenance_json,
        target_state=target_state,
        target_status=target_status,
    ):
        return _to_schema(row)
    changed_at = _now()
    if row is None:
        action = "create"
        audit_details: dict[str, object] = {
            "object_ref": f"{payload.kind}:{payload.id}",
        }
        row = CatalogObject(
            id=payload.id,
            kind=payload.kind,
            label=payload.label,
            status=target_status,
            lifecycle=target_state.lifecycle if target_state is not None else None,
            health=target_state.health if target_state is not None else None,
            summary=payload.summary,
            data_json=data_json,
            provenance_json=provenance_json,
            created_at=changed_at,
            updated_at=changed_at,
        )
        session.add(row)
    else:
        action = "update"
        audit_details = _update_audit_details(
            row,
            payload,
            data_json,
            provenance_json,
            target_state=target_state,
            target_status=target_status,
        )
        if expected_revision is None:
            row.kind = payload.kind
            row.label = payload.label
            row.status = target_status
            row.lifecycle = target_state.lifecycle if target_state is not None else None
            row.health = target_state.health if target_state is not None else None
            row.summary = payload.summary
            row.data_json = data_json
            row.provenance_json = provenance_json
            row.revision += 1
            row.updated_at = changed_at
        else:
            result = session.execute(
                update(CatalogObject)
                .where(
                    CatalogObject.id == payload.id,
                    CatalogObject.revision == expected_revision,
                )
                .values(
                    kind=payload.kind,
                    label=payload.label,
                    status=target_status,
                    lifecycle=target_state.lifecycle if target_state is not None else None,
                    health=target_state.health if target_state is not None else None,
                    summary=payload.summary,
                    data_json=data_json,
                    provenance_json=provenance_json,
                    revision=CatalogObject.revision + 1,
                    updated_at=changed_at,
                )
                .execution_options(synchronize_session=False)
            )
            if result.rowcount != 1:
                raise RevisionConflict("catalog object revision does not match")
            session.expire(row)

    if write_audit:
        _write_audit(session, payload.id, action, audit_details)
    session.flush()
    session.refresh(row)
    return _to_schema(row)


def ensure_projected_relationship_endpoints_valid(
    session: Session,
    row: CatalogObject,
    payload: CatalogObjectIn,
) -> None:
    try:
        current_data = json.loads(row.data_json)
    except (TypeError, json.JSONDecodeError):
        current_data = None
    if row.kind == payload.kind and current_data == payload.data:
        return

    object_refs = tuple(sorted({f"{row.kind}:{row.id}", f"{payload.kind}:{payload.id}"}))
    relationship_rows = list(
        session.scalars(
            select(Relationship)
            .where(
                Relationship.from_ref.in_(object_refs)
                | Relationship.to_ref.in_(object_refs)
            )
            .order_by(
                Relationship.id,
                Relationship.from_ref,
                Relationship.relation_type,
                Relationship.to_ref,
            )
        ).all()
    )
    if not relationship_rows:
        return

    endpoint_ids = {
        reference.split(":", 1)[1]
        for relationship in relationship_rows
        for reference in (relationship.from_ref, relationship.to_ref)
    }
    endpoint_rows = list(
        session.scalars(
            select(CatalogObject)
            .where(CatalogObject.id.in_(sorted(endpoint_ids)))
            .order_by(CatalogObject.id)
        ).all()
    )
    projected_rows: list[CatalogObject | dict[str, object]] = [
        (
            {
                "id": payload.id,
                "kind": payload.kind,
                "data": payload.data,
            }
            if endpoint_row.id == payload.id
            else endpoint_row
        )
        for endpoint_row in endpoint_rows
    ]
    endpoints = endpoint_descriptor_map(projected_rows)
    validate_relationship_collection(relationship_rows, endpoints)


def _object_matches_target(
    row: CatalogObject,
    payload: CatalogObjectIn,
    data_json: str,
    provenance_json: str,
    *,
    target_state: AssetState | None,
    target_status: str,
) -> bool:
    return (
        row.kind == payload.kind
        and row.label == payload.label
        and row.status == target_status
        and row.lifecycle == (target_state.lifecycle if target_state is not None else None)
        and row.health == (target_state.health if target_state is not None else None)
        and row.summary == payload.summary
        and row.data_json == data_json
        and row.provenance_json == provenance_json
    )


def _update_audit_details(
    row: CatalogObject,
    payload: CatalogObjectIn,
    data_json: str,
    provenance_json: str,
    *,
    target_state: AssetState | None,
    target_status: str,
) -> dict[str, object]:
    changes: list[dict[str, object]] = []
    current_state = state_from_record(
        kind=row.kind,
        status=row.status,
        lifecycle=row.lifecycle,
        health=row.health,
    )
    if row.kind != payload.kind:
        changes.append(_field_change("kind", row.kind, payload.kind))
    if row.label != payload.label:
        changes.append(_field_change("label", row.label, payload.label))
    if current_state is not None or target_state is not None:
        if (
            current_state is None
            or target_state is None
            or current_state.lifecycle != target_state.lifecycle
        ):
            changes.append(
                _field_change(
                    "lifecycle",
                    current_state.lifecycle if current_state is not None else "",
                    target_state.lifecycle if target_state is not None else "",
                )
            )
        if (
            current_state is None
            or target_state is None
            or current_state.health != target_state.health
        ):
            changes.append(
                _field_change(
                    "health",
                    current_state.health if current_state is not None else "",
                    target_state.health if target_state is not None else "",
                )
            )
    elif _normalize_status(row.status) != _normalize_status(target_status):
        changes.append(
            _field_change("status", _normalize_status(row.status), target_status)
        )
    if (row.summary or "") != (payload.summary or ""):
        changes.append(_field_change("summary", row.summary or "", payload.summary or ""))

    old_data = json.loads(row.data_json or "{}")
    if old_data != payload.data:
        changes.extend(_data_changes(old_data, payload.data))
    if not changes and row.data_json != data_json:
        changes.append({"field": "data", "value_change": False})
    if row.provenance_json != provenance_json:
        changes.append({"field": "provenance", "value_change": False})
    return {
        "object_ref": f"{payload.kind}:{payload.id}",
        "changes": changes,
    }


def _format_log_timestamp(value: datetime | None) -> str:
    return format_rfc3339_utc(value) or ""


def _data_changes(old_data: dict, new_data: dict) -> list[dict[str, object]]:
    return _nested_data_changes(old_data, new_data)


def _nested_data_changes(
    old_value: object,
    new_value: object,
    path: str = "",
) -> list[dict[str, object]]:
    if old_value == new_value:
        return []
    if isinstance(old_value, dict) and new_value is None:
        return _nested_data_changes(old_value, {}, path)
    if old_value is None and isinstance(new_value, dict):
        return _nested_data_changes({}, new_value, path)
    if isinstance(old_value, dict) and isinstance(new_value, dict):
        changes: list[dict[str, object]] = []
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
    if _is_scalar_audit_value(old_value) and _is_scalar_audit_value(new_value):
        return [
            _field_change(
                path or "data",
                _audit_scalar(old_value),
                _audit_scalar(new_value),
            )
        ]
    return [{"field": path or "data", "value_change": False}]


def _is_scalar_audit_value(value: object) -> bool:
    return value is None or isinstance(value, str | int | float | bool)


def _audit_scalar(value: object) -> str:
    if value is None:
        return ""
    return str(value)


def _field_change(
    field: str,
    old_value: str | None,
    new_value: str | None,
) -> dict[str, object]:
    return {
        "field": field,
        "old": _audit_display_value(old_value),
        "new": _audit_display_value(new_value),
        "value_change": True,
    }


def _audit_display_value(value: str | None) -> str:
    text = (value or "").strip()
    if len(text) > 80:
        return f"{text[:77]}..."
    return text


def delete_object(
    session: Session,
    object_id: str,
    *,
    write_audit: bool = True,
) -> bool:
    row = session.get(CatalogObject, object_id)
    if row is None:
        return False

    kind = row.kind
    object_ref = f"{kind}:{object_id}"
    blockers = _reference_blockers(session, object_ref)
    if blockers:
        raise RelationshipIntegrityError(
            "delete_referenced_object",
            f"cannot delete {object_ref}: {len(blockers)} typed reference(s) still exist",
        )
    session.delete(row)
    if write_audit:
        _write_audit(session, object_id, "delete", {"object_ref": object_ref})
    session.flush()
    return True


def touch_objects_for_refs(session: Session, refs: list[str], changed_at: datetime) -> None:
    object_ids = {
        ref.split(":", 1)[1]
        for ref in refs
        if ":" in ref
    }
    for object_id in object_ids:
        row = session.get(CatalogObject, object_id)
        if row is not None:
            row.revision += 1
            row.updated_at = changed_at


class RevisionConflict(RuntimeError):
    """An optimistic catalog-object revision did not match."""


def relationship_diagnostics(session: Session) -> list[RelationshipDiagnostic]:
    objects = list(session.scalars(select(CatalogObject).order_by(CatalogObject.id)).all())
    relationships = list(
        session.scalars(
            select(Relationship).order_by(
                Relationship.id,
                Relationship.from_ref,
                Relationship.relation_type,
                Relationship.to_ref,
            )
        ).all()
    )
    return diagnose_relationship_integrity(objects, relationships)


def current_object_kinds(session: Session) -> dict[str, str]:
    rows = session.execute(select(CatalogObject.id, CatalogObject.kind)).all()
    return {str(object_id): str(kind) for object_id, kind in rows}


def current_endpoint_descriptors(session: Session) -> dict[str, EndpointDescriptor]:
    rows = session.scalars(select(CatalogObject).order_by(CatalogObject.id)).all()
    return endpoint_descriptor_map(rows)


def ensure_kind_change_allowed(
    session: Session,
    row: CatalogObject,
    new_kind: str,
) -> None:
    if row.kind == new_kind:
        return
    old_ref = f"{row.kind}:{row.id}"
    blockers = _reference_blockers(session, old_ref)
    if blockers:
        raise RelationshipIntegrityError(
            "kind_change_referenced",
            f"cannot change {old_ref} to {new_kind}: "
            f"{len(blockers)} typed reference(s) still exist",
        )


def _reference_blockers(session: Session, object_ref: str) -> list[str]:
    blockers = [
        f"relationship:{row.id}"
        for row in session.scalars(
            select(Relationship).where(
                (Relationship.from_ref == object_ref)
                | (Relationship.to_ref == object_ref)
            )
        ).all()
    ]
    for row in session.scalars(select(CatalogObject).order_by(CatalogObject.id)).all():
        try:
            data = json.loads(row.data_json)
        except (TypeError, json.JSONDecodeError):
            blockers.append(f"catalog_object:{row.id}:invalid_json")
            continue
        if object_ref in iter_typed_reference_strings(data):
            blockers.append(f"catalog_object:{row.id}")
    return blockers
