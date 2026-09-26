from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from sqlalchemy import select
from sqlalchemy.orm import Session

from blockwart.domain.auth import GrantScope, Role
from blockwart.models import CatalogObject, ObjectGrant
from blockwart.services.pagination import CursorPage, paginate_items

TargetKind = Literal["catalog_object", "project"]

_RESOURCE = "auth.me.direct-grants"
_SORT = "target_id"
PROJECT_KIND = "project"


@dataclass(frozen=True, slots=True)
class OwnDirectGrant:
    target_kind: TargetKind
    target_id: str
    role: Role
    scope: GrantScope


def query_own_direct_grants(
    session: Session,
    *,
    principal_id: str,
    role: Role | None,
    limit: int,
    cursor: str | None,
) -> CursorPage[OwnDirectGrant]:
    """Page the caller's own direct grants; `principal_id` must come from authentication.

    Only rows whose `principal_id` equals the caller are read. Ordering is
    `(target_id, role, scope)`, which is unique per grant, and the cursor is a
    keyset position bound to the role filter, so pages never repeat or skip a
    grant that exists throughout the traversal.
    """
    statement = (
        select(ObjectGrant.object_id, ObjectGrant.role, ObjectGrant.scope, CatalogObject.kind)
        .join(CatalogObject, CatalogObject.id == ObjectGrant.object_id)
        .where(ObjectGrant.principal_id == principal_id)
    )
    if role is not None:
        statement = statement.where(ObjectGrant.role == role.value)
    grants = [
        OwnDirectGrant(
            target_kind="project" if kind == PROJECT_KIND else "catalog_object",
            target_id=object_id,
            role=Role(grant_role),
            scope=GrantScope(scope),
        )
        for object_id, grant_role, scope, kind in session.execute(statement).all()
    ]
    return paginate_items(
        grants,
        key=lambda grant: (grant.target_id, f"{grant.role.value}:{grant.scope.value}"),
        limit=limit,
        resource=_RESOURCE,
        sort=_SORT,
        direction="asc",
        query={"principal_id": principal_id, "role": role.value if role is not None else None},
        cursor=cursor,
        include_total=False,
    )
