from __future__ import annotations

from collections.abc import Iterable

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
    ensure_owner_coverage_after_exclusions(
        session,
        excluded_grant_ids=(grant.id,),
    )

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


def ensure_principal_deactivation_preserves_owner_coverage(
    session: Session,
    *,
    principal_id: str,
) -> None:
    ensure_owner_coverage_after_exclusions(
        session,
        excluded_principal_ids=(principal_id,),
    )


def ensure_owner_coverage_after_exclusions(
    session: Session,
    *,
    excluded_grant_ids: Iterable[int] = (),
    excluded_principal_ids: Iterable[str] = (),
) -> None:
    excluded_grants = frozenset(excluded_grant_ids)
    excluded_principals = frozenset(excluded_principal_ids)
    active_owner_grants = _locked_active_owner_grants(session)
    affected_grants = [
        grant
        for grant in active_owner_grants
        if (
            grant.id in excluded_grants
            or grant.principal_id in excluded_principals
        )
    ]
    affected_ids = {
        object_id
        for grant in affected_grants
        for object_id in _grant_affected_object_ids(session, grant)
    }
    if not affected_ids:
        return
    covered_ids = active_owner_covered_object_ids(
        session,
        excluded_grant_ids=excluded_grants,
        excluded_principal_ids=excluded_principals,
    )
    if affected_ids - covered_ids:
        raise LastOwnerError("owner change would orphan object access")


def active_owner_covered_object_ids(
    session: Session,
    *,
    excluded_grant_ids: Iterable[int] = (),
    excluded_principal_ids: Iterable[str] = (),
) -> set[str]:
    excluded_grants = frozenset(excluded_grant_ids)
    excluded_principals = frozenset(excluded_principal_ids)
    _locked_active_owner_grants(session)
    list(
        session.scalars(
            select(Relationship)
            .where(
                Relationship.relation_type
                == CANONICAL_PLACEMENT_RELATION_TYPE
            )
            .order_by(Relationship.id)
            .with_for_update()
        ).all()
    )
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
            Principal.active.is_(True),
        )
    )
    if excluded_grants:
        roots = roots.where(ObjectGrant.id.not_in(excluded_grants))
    if excluded_principals:
        roots = roots.where(ObjectGrant.principal_id.not_in(excluded_principals))
    reach = _subtree_cte(
        roots,
        name="active_owner_reach",
        scope_column=True,
    )
    return set(session.scalars(select(reach.c.object_id).distinct()).all())


def ensure_owner_coverage_preserved(
    session: Session,
    *,
    previously_covered_ids: Iterable[str],
) -> None:
    previous = frozenset(previously_covered_ids)
    if not previous:
        return
    existing_ids = set(
        session.scalars(
            select(CatalogObject.id).where(CatalogObject.id.in_(previous))
        ).all()
    )
    lost_ids = existing_ids - active_owner_covered_object_ids(session)
    if lost_ids:
        raise LastOwnerError("placement change would orphan object access")


def _locked_active_owner_grants(
    session: Session,
) -> list[ObjectGrant]:
    statement = (
        select(ObjectGrant)
        .join(Principal, Principal.id == ObjectGrant.principal_id)
        .where(
            ObjectGrant.role == Role.OWNER,
            Principal.active.is_(True),
        )
        .order_by(ObjectGrant.id)
        .with_for_update()
    )
    return list(session.scalars(statement).all())


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
