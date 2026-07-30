from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from dataclasses import dataclass

from sqlalchemy import and_, literal, select
from sqlalchemy.orm import Session, aliased

from blockwart.domain.auth import (
    GrantScope,
    ObjectVisibility,
    Permission,
    Role,
    permissions_for_role,
)
from blockwart.domain.placement import CANONICAL_PLACEMENT_RELATION_TYPE
from blockwart.models import CatalogObject, ObjectGrant, Principal, Relationship


class AuthorizationDenied(PermissionError):
    """The principal does not have the requested object permission."""


@dataclass(frozen=True)
class EffectiveGrant:
    grant_id: int
    anchor_object_id: str
    object_id: str
    role: Role
    scope: GrantScope


@dataclass(frozen=True)
class PolicySnapshot:
    principal_id: str
    _permissions: dict[str, frozenset[Permission]]
    _grants: dict[str, tuple[EffectiveGrant, ...]]

    def permissions_for(self, object_id: str) -> frozenset[Permission]:
        return self._permissions.get(object_id, frozenset())

    def grants_for(self, object_id: str) -> tuple[EffectiveGrant, ...]:
        return self._grants.get(object_id, ())

    def can(
        self,
        permission: Permission | str,
        object_id: str,
    ) -> bool:
        return Permission(permission) in self.permissions_for(object_id)

    def require(
        self,
        permission: Permission | str,
        object_id: str,
    ) -> None:
        if not self.can(permission, object_id):
            raise AuthorizationDenied("object permission denied")

    def authorized_ids(
        self,
        permission: Permission | str,
    ) -> frozenset[str]:
        resolved = Permission(permission)
        return frozenset(
            object_id
            for object_id, permissions in self._permissions.items()
            if resolved in permissions
        )

    def visibility_for(self, object_id: str) -> ObjectVisibility:
        permissions = self.permissions_for(object_id)
        if Permission.READ in permissions:
            return ObjectVisibility.DETAIL
        if Permission.DISCOVER in permissions:
            return ObjectVisibility.STUB
        return ObjectVisibility.NONE

    def fingerprint(self) -> str:
        """Bind cursors and principal-scoped read state to this exact policy."""
        payload = [
            {
                "object_id": object_id,
                "permissions": sorted(permission.value for permission in permissions),
                "grants": [
                    {
                        "anchor": grant.anchor_object_id,
                        "grant_id": grant.grant_id,
                        "role": grant.role.value,
                        "scope": grant.scope.value,
                    }
                    for grant in self.grants_for(object_id)
                ],
            }
            for object_id, permissions in sorted(self._permissions.items())
        ]
        serialized = json.dumps(
            payload,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()[:24]


def policy_for_principal(
    session: Session,
    principal_id: str,
) -> PolicySnapshot:
    child = aliased(CatalogObject)
    object_ref = CatalogObject.kind + literal(":") + CatalogObject.id
    child_ref = child.kind + literal(":") + child.id
    roots = (
        select(
            ObjectGrant.id.label("grant_id"),
            ObjectGrant.object_id.label("anchor_object_id"),
            CatalogObject.id.label("object_id"),
            object_ref.label("object_ref"),
            CatalogObject.kind.label("object_kind"),
            ObjectGrant.role.label("role"),
            ObjectGrant.scope.label("scope"),
        )
        .join(
            Principal,
            Principal.id == ObjectGrant.principal_id,
        )
        .join(
            CatalogObject,
            CatalogObject.id == ObjectGrant.object_id,
        )
        .where(
            ObjectGrant.principal_id == principal_id,
            Principal.active.is_(True),
        )
    )
    reach = roots.cte("authorized_object_reach", recursive=True)
    descendants = (
        select(
            reach.c.grant_id,
            reach.c.anchor_object_id,
            child.id.label("object_id"),
            child_ref.label("object_ref"),
            child.kind.label("object_kind"),
            reach.c.role,
            reach.c.scope,
        )
        .select_from(reach)
        .join(
            Relationship,
            and_(
                reach.c.scope == GrantScope.SUBTREE,
                Relationship.relation_type == CANONICAL_PLACEMENT_RELATION_TYPE,
                Relationship.from_ref == reach.c.object_ref,
            ),
        )
        .join(child, Relationship.to_ref == child_ref)
        .where(
            (
                (reach.c.object_kind == "host")
                & child.kind.in_(("system", "service"))
            )
            | (
                (reach.c.object_kind == "system")
                & (child.kind == "service")
            )
        )
    )
    reach = reach.union(descendants)
    rows = session.execute(
        select(
            reach.c.grant_id,
            reach.c.anchor_object_id,
            reach.c.object_id,
            reach.c.role,
            reach.c.scope,
        )
        .distinct()
        .order_by(
            reach.c.object_id,
            reach.c.grant_id,
        )
    ).all()

    permissions_by_object: dict[str, set[Permission]] = defaultdict(set)
    grants_by_object: dict[str, list[EffectiveGrant]] = defaultdict(list)
    for row in rows:
        role = Role(str(row.role))
        scope = GrantScope(str(row.scope))
        object_id = str(row.object_id)
        permissions_by_object[object_id].update(permissions_for_role(role))
        grants_by_object[object_id].append(
            EffectiveGrant(
                grant_id=int(row.grant_id),
                anchor_object_id=str(row.anchor_object_id),
                object_id=object_id,
                role=role,
                scope=scope,
            )
        )
    return PolicySnapshot(
        principal_id=principal_id,
        _permissions={
            object_id: frozenset(permissions)
            for object_id, permissions in permissions_by_object.items()
        },
        _grants={
            object_id: tuple(grants)
            for object_id, grants in grants_by_object.items()
        },
    )
