"""Derived, bounded Project access metadata; never resolve reference content."""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from urllib.parse import quote

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from blockwart.domain.auth import ObjectVisibility
from blockwart.domain.references import TypedReference
from blockwart.models import CatalogObject, ProjectRecord
from blockwart.schemas.agent import (
    ProjectAccessCredentialPreview,
    ProjectAccessPreview,
    ProjectAccessPreviewItem,
)
from blockwart.services.read_access import ReadAccess
from blockwart.services.record_integrity import read_catalog_record_data

PREVIEW_LIMIT = 5


def project_access_previews(
    session: Session,
    access: ReadAccess,
    projects: Sequence[CatalogObject],
    *,
    object_by_ref: Mapping[str, CatalogObject] | None = None,
) -> dict[str, ProjectAccessPreview]:
    projects = [
        obj
        for obj in projects
        if obj.kind == "project" and access.policy.visibility_for(obj.id) == ObjectVisibility.DETAIL
    ]
    if not projects:
        return {}
    # Rank only these authorized project instances. Transfer at most limit + 1
    # rows per project, sharing the access collection's (created_at, id) order.
    ranked = (
        select(
            ProjectRecord.project_instance_id,
            ProjectRecord.id,
            ProjectRecord.data_json,
            func.row_number()
            .over(
                partition_by=ProjectRecord.project_instance_id,
                order_by=(ProjectRecord.created_at, ProjectRecord.id),
            )
            .label("position"),
        )
        .where(
            ProjectRecord.project_instance_id.in_([obj.instance_id for obj in projects]),
            ProjectRecord.kind == "access",
        )
        .subquery()
    )
    rows = session.execute(
        select(ranked)
        .where(
            ranked.c.position <= PREVIEW_LIMIT + 1,
        )
        .order_by(ranked.c.project_instance_id, ranked.c.position)
    ).all()
    grouped: dict[str, list] = {obj.instance_id: [] for obj in projects}
    for row in rows:
        grouped[row.project_instance_id].append(row)
    # Fetch metadata objects once for UI callers; agent resolvers reuse their
    # existing snapshot. A hidden/missing reference is equivalent to no reference.
    if object_by_ref is None:
        ids = set()
        for group in grouped.values():
            for row in group[:PREVIEW_LIMIT]:
                ref = _credential_ref(json.loads(row.data_json))
                if ref and access.policy.visibility_for(ref.object_id) == ObjectVisibility.DETAIL:
                    ids.add(ref.object_id)
        objects = (
            session.scalars(select(CatalogObject).where(CatalogObject.id.in_(ids))).all()
            if ids
            else []
        )
        object_by_ref = {f"{obj.kind}:{obj.id}": obj for obj in objects}
    result = {}
    for project in projects:
        path = quote(project.id, safe="")
        items = []
        for row in grouped[project.instance_id][:PREVIEW_LIMIT]:
            data = json.loads(row.data_json)
            credential = None
            ref = _credential_ref(data)
            if ref and access.policy.visibility_for(ref.object_id) == ObjectVisibility.DETAIL:
                obj = object_by_ref.get(str(ref))
                if obj is not None and obj.kind == "credential_reference":
                    # Explicit metadata allowlist: do not project data.reference,
                    # provider locators, handling rules or secret-content rights.
                    metadata = read_catalog_record_data(obj).data
                    credential = ProjectAccessCredentialPreview(
                        ref=str(ref),
                        label=obj.label,
                        href=f"/objects/{quote(obj.id, safe='')}",
                        access_type=metadata.get("scope", {}).get("access_type"),
                    )
            items.append(
                ProjectAccessPreviewItem(
                    id=row.id,
                    title=data.get("title", ""),
                    purpose=data.get("purpose", ""),
                    url=data.get("url"),
                    href=f"/projects/{path}/workspace/record/{row.id}",
                    credential=credential,
                )
            )
        result[project.id] = ProjectAccessPreview(
            items=items,
            has_more=len(grouped[project.instance_id]) > PREVIEW_LIMIT,
            collection_href=f"/projects/{path}/workspace?kind=access",
            collection_api_path=f"/api/v1/projects/{path}/workspace/access",
        )
    return result


def _credential_ref(data: dict) -> TypedReference | None:
    try:
        ref = TypedReference.parse(data.get("credential_reference") or "")
    except ValueError:
        return None
    return ref if ref.kind == "credential_reference" else None
