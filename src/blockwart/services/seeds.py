import json
from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml
from sqlalchemy import select
from sqlalchemy.orm import Session

from blockwart.domain.asset_state import resolve_asset_state, state_from_record
from blockwart.domain.relationships import (
    dependency_relationships_from_data,
    validate_data_references,
    validate_relationship,
    validate_relationship_collection,
)
from blockwart.models import AuditEvent, CatalogObject, Relationship
from blockwart.schemas.catalog import CatalogObjectIn
from blockwart.services.catalog import ensure_kind_change_allowed


@dataclass(frozen=True)
class SeedImportResult:
    objects_imported: int
    relationships_imported: int


def import_seed_file(session: Session, path: str | Path) -> SeedImportResult:
    seed_path = Path(path)
    payload = yaml.safe_load(seed_path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("Seed file must contain a mapping")
    return import_seed_payload(session, payload)


def import_seed_payload(session: Session, payload: dict[str, Any]) -> SeedImportResult:
    if payload.get("schema_version") != 1:
        raise ValueError("Unsupported seed schema_version")

    raw_objects = payload.get("objects")
    if not isinstance(raw_objects, list):
        raise ValueError("Seed payload must contain an objects list")

    normalized_objects, dependency_relationships = _normalize_legacy_dependencies(raw_objects)
    objects = [_validate_object(raw_object) for raw_object in normalized_objects]
    object_ids = [obj.id for obj in objects]
    if len(object_ids) != len(set(object_ids)):
        raise ValueError("Seed object ids must be globally unique across kinds")
    object_kinds = {obj.id: obj.kind for obj in objects}
    _validate_typed_references(objects, object_kinds)

    raw_relationships = payload.get("relationships", [])
    if not isinstance(raw_relationships, list):
        raise ValueError("Seed relationships must be a list")
    relationships = [
        _validate_relationship(item, object_kinds)
        for item in [*raw_relationships, *_deduplicate_relationships(dependency_relationships)]
    ]
    validate_relationship_collection(relationships, object_kinds)

    for obj in objects:
        row = session.get(CatalogObject, obj.id)
        data_json = json.dumps(obj.data, sort_keys=True)
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
            kind=obj.kind,
            status=obj.status,
            lifecycle=obj.lifecycle,
            health=obj.health,
            current=current_state,
        )
        target_status = target_state.status if target_state is not None else obj.status
        if row is None:
            session.add(
                CatalogObject(
                    id=obj.id,
                    kind=obj.kind,
                    label=obj.label,
                    status=target_status,
                    lifecycle=target_state.lifecycle if target_state is not None else None,
                    health=target_state.health if target_state is not None else None,
                    summary=obj.summary,
                    data_json=data_json,
                )
            )
            _write_seed_audit(session, obj.id, "seed_create", f"Seed create {obj.kind}:{obj.id}")
            continue

        ensure_kind_change_allowed(session, row, obj.kind)
        row.kind = obj.kind
        row.label = obj.label
        row.status = target_status
        row.lifecycle = target_state.lifecycle if target_state is not None else None
        row.health = target_state.health if target_state is not None else None
        row.summary = obj.summary
        row.data_json = data_json
        _write_seed_audit(session, obj.id, "seed_update", f"Seed update {obj.kind}:{obj.id}")

    inserted_relationships = 0
    for relationship in relationships:
        exists = session.scalar(
            select(Relationship).where(
                Relationship.from_ref == relationship["from_ref"],
                Relationship.relation_type == relationship["relation_type"],
                Relationship.to_ref == relationship["to_ref"],
            )
        )
        if exists is None:
            session.add(Relationship(**relationship))
            inserted_relationships += 1
            relationship_summary = (
                f"{relationship['from_ref']} "
                f"{relationship['relation_type']} "
                f"{relationship['to_ref']}"
            )
            _write_seed_audit(
                session,
                None,
                "seed_relationship_create",
                f"Seed relationship {relationship_summary}",
            )

    session.flush()
    return SeedImportResult(
        objects_imported=len(objects),
        relationships_imported=inserted_relationships,
    )


def _write_seed_audit(session: Session, object_id: str | None, action: str, summary: str) -> None:
    session.add(
        AuditEvent(
            object_id=object_id,
            action=action,
            actor="seed-import",
            summary=summary,
        )
    )


def _validate_object(raw_object: Any) -> CatalogObjectIn:
    if not isinstance(raw_object, dict):
        raise ValueError("Seed object must be a mapping")
    return CatalogObjectIn.model_validate(raw_object)


def _validate_relationship(
    raw_relationship: Any,
    object_kinds: dict[str, str],
) -> dict[str, str]:
    if not isinstance(raw_relationship, dict):
        raise ValueError("Seed relationship must be a mapping")

    from_ref = raw_relationship.get("from_ref")
    relation_type = raw_relationship.get("relation_type")
    to_ref = raw_relationship.get("to_ref")
    if not all(isinstance(value, str) and value for value in (from_ref, relation_type, to_ref)):
        raise ValueError("Seed relationship requires from_ref, relation_type, and to_ref")

    validate_relationship(
        from_ref=from_ref,
        relation_type=relation_type,
        to_ref=to_ref,
        object_kinds=object_kinds,
    )

    return {"from_ref": from_ref, "relation_type": relation_type, "to_ref": to_ref}


def _validate_typed_references(
    objects: list[CatalogObjectIn],
    object_kinds: dict[str, str],
) -> None:
    for obj in objects:
        validate_data_references(obj.data, object_kinds, object_id=obj.id)


def _normalize_legacy_dependencies(
    raw_objects: list[Any],
) -> tuple[list[Any], list[dict[str, str]]]:
    normalized_objects: list[Any] = []
    relationships: list[dict[str, str]] = []
    for raw_object in raw_objects:
        if not isinstance(raw_object, dict):
            normalized_objects.append(raw_object)
            continue
        normalized = deepcopy(raw_object)
        data = normalized.get("data")
        object_id = normalized.get("id")
        kind = normalized.get("kind")
        if (
            isinstance(data, dict)
            and isinstance(object_id, str)
            and isinstance(kind, str)
            and "dependencies" in data
        ):
            relationships.extend(
                dependency_relationships_from_data(
                    owner_ref=f"{kind}:{object_id}",
                    data=data,
                )
            )
            data.pop("dependencies", None)
        normalized_objects.append(normalized)
    return normalized_objects, relationships


def _deduplicate_relationships(
    relationships: list[dict[str, str]],
) -> list[dict[str, str]]:
    unique: list[dict[str, str]] = []
    seen: set[tuple[str, str, str]] = set()
    for relationship in relationships:
        triplet = (
            relationship["from_ref"],
            relationship["relation_type"],
            relationship["to_ref"],
        )
        if triplet in seen:
            continue
        seen.add(triplet)
        unique.append(relationship)
    return unique
