from __future__ import annotations

from sqlalchemy import and_, literal, select
from sqlalchemy.orm import Session, aliased

from blockwart.domain.auth import GrantScope, Role
from blockwart.domain.placement import CANONICAL_PLACEMENT_RELATION_TYPE
from blockwart.models import CatalogObject, ObjectGrant, Principal, Relationship
from blockwart.services.audit import add_audit_event


class AccessGrantError(ValueError):
    """Stable domain error for invalid object-grant mutations."""


class LastOwnerError(AccessGrantError):
    """Removing the grant would leave an object without an effective owner."""


def create_object_grant(
    session: Session,
    *,
    principal_id: str,
    object_id: str,
    role: Role | str,
    scope: GrantScope | str,
    actor_principal_id: str | None = None,
    channel: str = "system",
    request_id: str | None = None,
) -> ObjectGrant:
    resolved_role = Role(role)
    resolved_scope = GrantScope(scope)
    principal = session.get(Principal, principal_id)
    catalog_object = session.get(CatalogObject, object_id)
    if principal is None:
        raise AccessGrantError("principal not found")
    if catalog_object is None:
        raise AccessGrantError("catalog object not found")
    if actor_principal_id is not None and session.get(Principal, actor_principal_id) is None:
        raise AccessGrantError("actor principal not found")
    existing = session.scalar(
        select(ObjectGrant).where(
            ObjectGrant.principal_id == principal_id,
            ObjectGrant.object_id == object_id,
            ObjectGrant.role == resolved_role,
            ObjectGrant.scope == resolved_scope,
        )
    )
    if existing is not None:
        return existing

    old_revision = catalog_object.revision
    catalog_object.revision += 1
    grant = ObjectGrant(
        principal_id=principal_id,
        object_id=object_id,
        role=resolved_role,
        scope=resolved_scope,
        created_by_principal_id=actor_principal_id,
    )
    session.add(grant)
    session.flush()
    add_audit_event(
        session,
        object_id=object_id,
        action="grant_create",
        actor=actor_principal_id or "system",
        details={
            "principal_id": principal_id,
            "role": resolved_role,
            "scope": resolved_scope,
            "channel": channel,
            "request_id": request_id,
            "old_revision": old_revision,
            "new_revision": catalog_object.revision,
        },
    )
    session.flush()
    return grant


def revoke_object_grant(
    session: Session,
    *,
    grant_id: int,
    actor_principal_id: str | None = None,
    channel: str = "system",
    request_id: str | None = None,
) -> bool:
    grant = session.get(ObjectGrant, grant_id)
    if grant is None:
        return False
    principal = session.get(Principal, grant.principal_id)
    if (
        grant.role == Role.OWNER
        and principal is not None
        and principal.active
    ):
        affected_ids = _grant_affected_object_ids(session, grant)
        covered_ids = _remaining_owner_covered_object_ids(
            session,
            excluded_grant_id=grant.id,
        )
        if affected_ids - covered_ids:
            raise LastOwnerError("owner grant removal would orphan object access")

    catalog_object = session.get(CatalogObject, grant.object_id)
    if catalog_object is None:
        raise AccessGrantError("catalog object not found")
    old_revision = catalog_object.revision
    catalog_object.revision += 1
    details = {
        "principal_id": grant.principal_id,
        "role": grant.role,
        "scope": grant.scope,
        "channel": channel,
        "request_id": request_id,
        "old_revision": old_revision,
        "new_revision": catalog_object.revision,
    }
    session.delete(grant)
    add_audit_event(
        session,
        object_id=catalog_object.id,
        action="grant_revoke",
        actor=actor_principal_id or "system",
        details=details,
    )
    session.flush()
    return True


def _grant_affected_object_ids(
    session: Session,
    grant: ObjectGrant,
) -> set[str]:
    if grant.scope == GrantScope.SELF:
        return {grant.object_id}
    catalog_object = session.get(CatalogObject, grant.object_id)
    if catalog_object is None:
        return set()
    reach = _subtree_cte(
        select(
            CatalogObject.id.label("object_id"),
            (CatalogObject.kind + literal(":") + CatalogObject.id).label("object_ref"),
            CatalogObject.kind.label("object_kind"),
        ).where(CatalogObject.id == grant.object_id),
        name="grant_affected_reach",
    )
    return set(session.scalars(select(reach.c.object_id).distinct()).all())


def _remaining_owner_covered_object_ids(
    session: Session,
    *,
    excluded_grant_id: int,
) -> set[str]:
    roots = (
        select(
            CatalogObject.id.label("object_id"),
            (CatalogObject.kind + literal(":") + CatalogObject.id).label("object_ref"),
            CatalogObject.kind.label("object_kind"),
            ObjectGrant.scope.label("scope"),
        )
        .join(ObjectGrant, ObjectGrant.object_id == CatalogObject.id)
        .join(Principal, Principal.id == ObjectGrant.principal_id)
        .where(
            ObjectGrant.role == Role.OWNER,
            ObjectGrant.id != excluded_grant_id,
            Principal.active.is_(True),
        )
    )
    reach = _subtree_cte(
        roots,
        name="remaining_owner_reach",
        scope_column=True,
    )
    return set(session.scalars(select(reach.c.object_id).distinct()).all())


def _subtree_cte(
    roots,
    *,
    name: str,
    scope_column: bool = False,
):
    child = aliased(CatalogObject)
    child_ref = child.kind + literal(":") + child.id
    reach = roots.cte(name, recursive=True)
    columns = [
        child.id.label("object_id"),
        child_ref.label("object_ref"),
        child.kind.label("object_kind"),
    ]
    if scope_column:
        columns.append(reach.c.scope)
    join_conditions = [
        Relationship.relation_type == CANONICAL_PLACEMENT_RELATION_TYPE,
        Relationship.from_ref == reach.c.object_ref,
    ]
    if scope_column:
        join_conditions.append(reach.c.scope == GrantScope.SUBTREE)
    descendants = (
        select(*columns)
        .select_from(reach)
        .join(Relationship, and_(*join_conditions))
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
    return reach.union(descendants)
