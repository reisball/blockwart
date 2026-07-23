import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml
from sqlalchemy import select
from sqlalchemy.orm import Session

from blockwart.domain.references import VALID_REFERENCE_KINDS, TypedReference
from blockwart.models import AuditEvent, CatalogObject, Relationship
from blockwart.schemas.catalog import CatalogObjectIn


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

    objects = [_validate_object(raw_object) for raw_object in raw_objects]
    object_refs = {f"{obj.kind}:{obj.id}" for obj in objects}
    _validate_typed_references(objects, object_refs)

    raw_relationships = payload.get("relationships", [])
    if not isinstance(raw_relationships, list):
        raise ValueError("Seed relationships must be a list")
    relationships = [_validate_relationship(item, object_refs) for item in raw_relationships]

    for obj in objects:
        row = session.get(CatalogObject, obj.id)
        data_json = json.dumps(obj.data, sort_keys=True)
        if row is None:
            session.add(
                CatalogObject(
                    id=obj.id,
                    kind=obj.kind,
                    label=obj.label,
                    status=obj.status,
                    summary=obj.summary,
                    data_json=data_json,
                )
            )
            _write_seed_audit(session, obj.id, "seed_create", f"Seed create {obj.kind}:{obj.id}")
            continue

        row.kind = obj.kind
        row.label = obj.label
        row.status = obj.status
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


def _validate_relationship(raw_relationship: Any, object_refs: set[str]) -> dict[str, str]:
    if not isinstance(raw_relationship, dict):
        raise ValueError("Seed relationship must be a mapping")

    from_ref = raw_relationship.get("from_ref")
    relation_type = raw_relationship.get("relation_type")
    to_ref = raw_relationship.get("to_ref")
    if not all(isinstance(value, str) and value for value in (from_ref, relation_type, to_ref)):
        raise ValueError("Seed relationship requires from_ref, relation_type, and to_ref")

    parsed_from = TypedReference.parse(from_ref)
    parsed_to = TypedReference.parse(to_ref)
    for ref in (str(parsed_from), str(parsed_to)):
        if ref not in object_refs:
            raise ValueError(f"Seed relationship references missing object: {ref}")

    return {"from_ref": from_ref, "relation_type": relation_type, "to_ref": to_ref}


def _validate_typed_references(objects: list[CatalogObjectIn], object_refs: set[str]) -> None:
    for obj in objects:
        for ref in _iter_typed_reference_strings(obj.model_dump()):
            TypedReference.parse(ref)
            if ref not in object_refs:
                raise ValueError(f"Seed object {obj.id!r} references missing object: {ref}")


def _iter_typed_reference_strings(value: Any) -> list[str]:
    refs: list[str] = []
    if isinstance(value, dict):
        for child in value.values():
            refs.extend(_iter_typed_reference_strings(child))
        return refs

    if isinstance(value, list):
        for child in value:
            refs.extend(_iter_typed_reference_strings(child))
        return refs

    if isinstance(value, str) and any(
        value.startswith(f"{kind}:") for kind in VALID_REFERENCE_KINDS
    ):
        refs.append(value)
    return refs
