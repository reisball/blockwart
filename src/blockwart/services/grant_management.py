from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Literal

from sqlalchemy import func, or_, select, update
from sqlalchemy.orm import Session

from blockwart.domain.auth import CatalogRole, GrantScope, Permission, Role
from blockwart.domain.timestamps import format_rfc3339_utc
from blockwart.models import CatalogObject, ObjectGrant, Principal
from blockwart.services.access import (
    LastOwnerError,
    ensure_owner_coverage_preserved,
    grant_scope_object_ids,
    lock_owner_coverage_state,
    lock_principal_rows,
)
from blockwart.services.audit import add_audit_event
from blockwart.services.commands import (
    CommandAuthorizationDenied,
    CommandConflict,
    CommandNotFound,
    CommandPreconditionFailed,
    WriteContext,
    parse_if_match,
    revision_etag,
)
from blockwart.services.identity import record_security_event
from blockwart.services.ownership import (
    InitialOwnerError,
    ObjectOwnerCoverage,
    assign_initial_owner,
    object_owner_coverage,
    resolve_owner_principal,
)
from blockwart.services.policy import policy_for_principal

# Stable structured reasons published through REST, MCP, and the UI. A healthy
# object's Owner-source requirement and the ownerless recovery path are
# deliberately different codes, so a caller never has to guess from a generic
# denial whether to ask an Owner or a catalog owner.
OWNER_REQUIRED_TO_MANAGE_OWNER_GRANTS = "owner_required_to_manage_owner_grants"
OBJECT_HAS_NO_OWNER_USE_ADOPTION_FLOW = "object_has_no_owner_use_adoption_flow"
ADOPTION_REQUIRES_CATALOG_OWNER = "adoption_requires_catalog_owner"
OBJECT_HAS_OWNER_COVERAGE = "object_has_owner_coverage"
OWNER_ADOPTION_ACTION = "owner_adopt"


@dataclass(frozen=True, slots=True)
class PrincipalSummary:
    id: str
    login: str
    display_name: str
    principal_type: str
    active: bool


@dataclass(frozen=True, slots=True)
class DirectGrantView:
    id: int
    principal: PrincipalSummary
    role: Role
    scope: GrantScope
    created_at: str
    updated_at: str


@dataclass(frozen=True, slots=True)
class EffectiveGrantSource:
    grant_id: int
    anchor_object_id: str
    anchor_object_kind: str
    anchor_object_label: str
    role: Role
    scope: GrantScope
    direct: bool


@dataclass(frozen=True, slots=True)
class EffectivePrincipalAccess:
    principal: PrincipalSummary
    permissions: tuple[Permission, ...]
    sources: tuple[EffectiveGrantSource, ...]


@dataclass(frozen=True, slots=True)
class OwnerCoverageView:
    """The object's Owner sources as the ownerless recovery flow needs them.

    Counts cover active object Owner grants only; a global catalog role is
    never an Owner source and never appears here.
    """

    state: Literal["owned", "ownerless"]
    direct_active_owner_grants: int
    inherited_active_owner_grants: int
    inactive_direct_owner_grants: int
    actor_has_owner_source: bool
    adoption_available: bool


@dataclass(frozen=True, slots=True)
class ObjectAccessView:
    object_id: str
    revision: int
    etag: str
    direct_grants: tuple[DirectGrantView, ...]
    effective_access: tuple[EffectivePrincipalAccess, ...]
    owner_coverage: OwnerCoverageView


@dataclass(frozen=True, slots=True)
class ScopePreviewObject:
    id: str
    kind: str
    label: str
    direct: bool


@dataclass(frozen=True, slots=True)
class GrantScopePreview:
    object_id: str
    scope: GrantScope
    affected_objects: tuple[ScopePreviewObject, ...]


@dataclass(frozen=True, slots=True)
class GrantCommandResult:
    object_id: str
    revision: int
    etag: str
    changed: bool
    grant: DirectGrantView | None = None
    revoked_grant_id: int | None = None


@dataclass(frozen=True, slots=True)
class OwnerAdoptionResult:
    object_id: str
    revision: int
    etag: str
    changed: bool
    grant: DirectGrantView
    previous_owner_count: int
    inactive_direct_owner_grants: int


def query_object_access(
    session: Session,
    context: WriteContext,
    *,
    object_id: str,
) -> ObjectAccessView:
    row = _require_manage_access(session, context, object_id=object_id)
    direct_rows = session.execute(
        select(ObjectGrant, Principal)
        .join(Principal, Principal.id == ObjectGrant.principal_id)
        .where(ObjectGrant.object_id == object_id)
        .order_by(func.lower(Principal.login), Principal.id, ObjectGrant.id)
    ).all()
    direct_grants = tuple(
        _direct_grant_view(grant, principal)
        for grant, principal in direct_rows
    )

    active_principals = session.scalars(
        select(Principal)
        .join(ObjectGrant, ObjectGrant.principal_id == Principal.id)
        .where(Principal.active.is_(True))
        .distinct()
        .order_by(func.lower(Principal.login), Principal.id)
    ).all()
    anchor_cache: dict[str, CatalogObject] = {}
    effective_access: list[EffectivePrincipalAccess] = []
    for principal in active_principals:
        policy = policy_for_principal(session, principal.id)
        permissions = policy.permissions_for(object_id)
        if not permissions:
            continue
        sources: list[EffectiveGrantSource] = []
        for effective_grant in policy.grants_for(object_id):
            anchor = anchor_cache.get(effective_grant.anchor_object_id)
            if anchor is None:
                anchor = session.get(CatalogObject, effective_grant.anchor_object_id)
                if anchor is None:
                    continue
                anchor_cache[anchor.id] = anchor
            sources.append(
                EffectiveGrantSource(
                    grant_id=effective_grant.grant_id,
                    anchor_object_id=anchor.id,
                    anchor_object_kind=anchor.kind,
                    anchor_object_label=anchor.label,
                    role=effective_grant.role,
                    scope=effective_grant.scope,
                    direct=anchor.id == object_id,
                )
            )
        effective_access.append(
            EffectivePrincipalAccess(
                principal=_principal_summary(principal),
                permissions=tuple(
                    permission
                    for permission in Permission
                    if permission in permissions
                ),
                sources=tuple(
                    sorted(
                        sources,
                        key=lambda source: (
                            not source.direct,
                            source.anchor_object_id,
                            source.grant_id,
                        ),
                    )
                ),
            )
        )
    coverage = object_owner_coverage(session, object_id, lock=False)
    return ObjectAccessView(
        object_id=row.id,
        revision=row.revision,
        etag=revision_etag(row.revision),
        direct_grants=direct_grants,
        effective_access=tuple(effective_access),
        owner_coverage=OwnerCoverageView(
            state="ownerless" if coverage.ownerless else "owned",
            direct_active_owner_grants=coverage.direct_active_owner_grants,
            inherited_active_owner_grants=coverage.inherited_active_owner_grants,
            inactive_direct_owner_grants=coverage.inactive_direct_owner_grants,
            actor_has_owner_source=actor_can_manage_owner_grants(
                context,
                object_id=object_id,
            ),
            adoption_available=(
                coverage.ownerless and _holds_adoption_authority(session, context)
            ),
        ),
    )


def search_manageable_principals(
    session: Session,
    context: WriteContext,
    *,
    object_id: str,
    query: str,
    limit: int = 20,
) -> tuple[PrincipalSummary, ...]:
    _require_manage_access(session, context, object_id=object_id)
    normalized = query.strip()
    if len(normalized) < 2 or len(normalized) > 100:
        raise CommandConflict("principal search requires 2 to 100 characters")
    if limit < 1 or limit > 20:
        raise CommandConflict("principal search limit must be between 1 and 20")
    folded = normalized.casefold()
    principals = session.scalars(
        select(Principal)
        .where(
            Principal.active.is_(True),
            or_(
                Principal.login.contains(normalized, autoescape=True),
                func.lower(Principal.display_name).contains(
                    folded,
                    autoescape=True,
                ),
            ),
        )
        .order_by(func.lower(Principal.login), Principal.id)
        .limit(limit)
    ).all()
    return tuple(_principal_summary(principal) for principal in principals)


def preview_grant_scope(
    session: Session,
    context: WriteContext,
    *,
    object_id: str,
    scope: GrantScope | str,
) -> GrantScopePreview:
    _require_manage_access(session, context, object_id=object_id)
    resolved_scope = GrantScope(scope)
    affected_ids = grant_scope_object_ids(
        session,
        object_id=object_id,
        scope=resolved_scope,
    )
    rows = session.scalars(
        select(CatalogObject)
        .where(CatalogObject.id.in_(affected_ids))
        .order_by(CatalogObject.kind, func.lower(CatalogObject.label), CatalogObject.id)
    ).all()
    return GrantScopePreview(
        object_id=object_id,
        scope=resolved_scope,
        affected_objects=tuple(
            ScopePreviewObject(
                id=row.id,
                kind=row.kind,
                label=row.label,
                direct=row.id == object_id,
            )
            for row in rows
        ),
    )


def adopt_ownerless_object(
    session: Session,
    context: WriteContext,
    *,
    object_id: str,
    principal_id: str,
    expected_revision: int | str | None,
) -> OwnerAdoptionResult:
    """Assign the first Owner to one legacy object that has none.

    This is the narrow, audited recovery for an object that no active direct
    or inherited Owner grant reaches, where ordinary grant management
    deadlocks because only an Owner may add an Owner. It is deliberately not
    a general administrative bypass:

    - only an active ``catalog_owner`` on a trusted channel may call it;
    - it requires the object's current strong ETag;
    - it assigns exactly one direct ``Owner/self`` grant to one active target
      principal and advances the object revision;
    - it refuses as soon as any active direct or inherited Owner grant exists,
      so a healthy object's Owner-only rules are never weakened.

    The revision claim is a compare-and-set on the object row, so of two
    concurrent adoptions exactly one succeeds and the other fails the ETag
    precondition; a later retry with the fresh ETag deterministically receives
    ``object_has_owner_coverage``.
    """
    lock_owner_coverage_state(
        session,
        extra_principal_ids=(context.principal.id, principal_id),
    )
    _require_adoption_authority(session, context, object_id=object_id)
    row = session.get(CatalogObject, object_id)
    if row is None:
        raise CommandNotFound("catalog object not found")
    revision = _expected_revision(expected_revision)
    if row.revision != revision:
        raise CommandPreconditionFailed("object revision changed")
    try:
        resolve_owner_principal(session, principal_id)
    except InitialOwnerError as exc:
        raise CommandConflict(str(exc), code=exc.code) from exc
    object_ref = f"{row.kind}:{row.id}"

    # Claim the revision before judging coverage. A concurrent adoption with
    # the same ETag therefore always loses at this compare-and-set with the
    # ETag precondition, never at a lock-timing-dependent later check, and the
    # coverage below is read while this transaction holds the object row.
    new_revision = _claim_object_revision(
        session,
        object_id=object_id,
        expected_revision=revision,
    )
    coverage = object_owner_coverage(session, object_id, lock=True)
    _require_ownerless(coverage)
    try:
        grant = assign_initial_owner(
            session,
            object_id=object_id,
            owner_principal_id=principal_id,
            created_by_principal_id=context.principal.id,
        )
    except InitialOwnerError as exc:
        raise CommandConflict(str(exc), code=exc.code) from exc
    target = session.get(Principal, principal_id)
    if target is None:
        raise CommandConflict("grant principal does not exist")
    add_audit_event(
        session,
        object_id=object_id,
        action=OWNER_ADOPTION_ACTION,
        actor=context.principal.id,
        details={
            "actor_principal_id": context.principal.id,
            "actor_login": context.principal.login,
            "catalog_authority": CatalogRole.CATALOG_OWNER.value,
            "target_principal_id": target.id,
            "target_login": target.login,
            "channel": context.channel,
            "request_id": context.request_id,
            "object_ref": object_ref,
            "old_revision": revision,
            "new_revision": new_revision,
            "previous_owner_count": coverage.active_owner_grants,
            "previous_direct_owner_count": coverage.direct_active_owner_grants,
            "previous_inherited_owner_count": coverage.inherited_active_owner_grants,
            "inactive_direct_owner_grants": coverage.inactive_direct_owner_grants,
            "before": None,
            "after": _grant_snapshot(grant),
        },
    )
    record_security_event(
        session,
        event_type="ownerless_object_adoption",
        outcome="success",
        channel=context.channel,
        principal_id=context.principal.id,
        request_id=context.request_id,
        details={
            "object_id": object_id,
            "target_principal_id": target.id,
            "grant_id": grant.id,
            "new_revision": new_revision,
        },
    )
    session.flush()
    session.refresh(grant)
    return OwnerAdoptionResult(
        object_id=object_id,
        revision=new_revision,
        etag=revision_etag(new_revision),
        changed=True,
        grant=_direct_grant_view(grant, target),
        previous_owner_count=coverage.active_owner_grants,
        inactive_direct_owner_grants=coverage.inactive_direct_owner_grants,
    )


def create_managed_grant(
    session: Session,
    context: WriteContext,
    *,
    object_id: str,
    principal_id: str,
    role: Role | str,
    scope: GrantScope | str,
    expected_revision: int | str | None,
) -> GrantCommandResult:
    row = _require_manage_access(
        session,
        context,
        object_id=object_id,
        refresh_policy=True,
    )
    resolved_role = Role(role)
    resolved_scope = GrantScope(scope)
    _require_owner_for_owner_grant(
        session,
        context,
        object_id=object_id,
        roles=(resolved_role,),
    )
    target = _active_target_principal(session, principal_id)
    revision = _expected_revision(expected_revision)
    if row.revision != revision:
        raise CommandPreconditionFailed("object revision changed")
    existing = session.scalar(
        select(ObjectGrant).where(
            ObjectGrant.principal_id == principal_id,
            ObjectGrant.object_id == object_id,
            ObjectGrant.role == resolved_role,
            ObjectGrant.scope == resolved_scope,
        )
    )
    if existing is not None:
        return GrantCommandResult(
            object_id=object_id,
            revision=row.revision,
            etag=revision_etag(row.revision),
            changed=False,
            grant=_direct_grant_view(existing, target),
        )

    new_revision = _claim_object_revision(
        session,
        object_id=object_id,
        expected_revision=revision,
    )
    grant = ObjectGrant(
        principal_id=target.id,
        object_id=object_id,
        role=resolved_role,
        scope=resolved_scope,
        created_by_principal_id=context.principal.id,
    )
    session.add(grant)
    session.flush()
    after = _grant_snapshot(grant)
    _write_grant_audit(
        session,
        context,
        object_id=object_id,
        action="grant_create",
        target_principal_id=target.id,
        old_revision=revision,
        new_revision=new_revision,
        before=None,
        after=after,
    )
    session.refresh(grant)
    return GrantCommandResult(
        object_id=object_id,
        revision=new_revision,
        etag=revision_etag(new_revision),
        changed=True,
        grant=_direct_grant_view(grant, target),
    )


def update_managed_grant(
    session: Session,
    context: WriteContext,
    *,
    object_id: str,
    grant_id: int,
    role: Role | str,
    scope: GrantScope | str,
    expected_revision: int | str | None,
    expected_principal_id: str | None = None,
) -> GrantCommandResult:
    row = _require_manage_access(
        session,
        context,
        object_id=object_id,
        refresh_policy=True,
    )
    grant = _direct_grant(session, object_id=object_id, grant_id=grant_id)
    if (
        expected_principal_id is not None
        and grant.principal_id != expected_principal_id
    ):
        raise CommandNotFound("direct grant not found")
    resolved_role = Role(role)
    resolved_scope = GrantScope(scope)
    _require_owner_for_owner_grant(
        session,
        context,
        object_id=object_id,
        roles=(Role(grant.role), resolved_role),
    )
    revision = _expected_revision(expected_revision)
    if row.revision != revision:
        raise CommandPreconditionFailed("object revision changed")
    if Role.OWNER in (Role(grant.role), resolved_role):
        lock_owner_coverage_state(
            session,
            extra_principal_ids=(context.principal.id, grant.principal_id),
        )
    target = session.get(Principal, grant.principal_id)
    if target is None:
        raise CommandConflict("grant principal does not exist")
    if grant.role == resolved_role and grant.scope == resolved_scope:
        return GrantCommandResult(
            object_id=object_id,
            revision=row.revision,
            etag=revision_etag(row.revision),
            changed=False,
            grant=_direct_grant_view(grant, target),
        )
    duplicate = session.scalar(
        select(ObjectGrant).where(
            ObjectGrant.id != grant.id,
            ObjectGrant.principal_id == grant.principal_id,
            ObjectGrant.object_id == object_id,
            ObjectGrant.role == resolved_role,
            ObjectGrant.scope == resolved_scope,
        )
    )
    if duplicate is not None:
        raise CommandConflict("an equivalent direct grant already exists")

    before = _grant_snapshot(grant)
    previously_owned = (
        grant_scope_object_ids(
            session,
            object_id=object_id,
            scope=GrantScope(grant.scope),
        )
        if grant.role == Role.OWNER and target.active
        else set()
    )
    new_revision = _claim_object_revision(
        session,
        object_id=object_id,
        expected_revision=revision,
    )
    grant.role = resolved_role
    grant.scope = resolved_scope
    session.flush()
    try:
        ensure_owner_coverage_preserved(
            session,
            previously_covered_ids=previously_owned,
        )
        _ensure_no_self_lockout(
            session,
            context,
            object_id=object_id,
            target_principal_id=target.id,
        )
    except LastOwnerError as exc:
        raise CommandConflict(str(exc)) from exc
    after = _grant_snapshot(grant)
    _write_grant_audit(
        session,
        context,
        object_id=object_id,
        action="grant_update",
        target_principal_id=target.id,
        old_revision=revision,
        new_revision=new_revision,
        before=before,
        after=after,
    )
    session.refresh(grant)
    return GrantCommandResult(
        object_id=object_id,
        revision=new_revision,
        etag=revision_etag(new_revision),
        changed=True,
        grant=_direct_grant_view(grant, target),
    )


def revoke_managed_grant(
    session: Session,
    context: WriteContext,
    *,
    object_id: str,
    grant_id: int,
    expected_revision: int | str | None,
    expected_principal_id: str | None = None,
) -> GrantCommandResult:
    row = _require_manage_access(
        session,
        context,
        object_id=object_id,
        refresh_policy=True,
    )
    grant = _direct_grant(session, object_id=object_id, grant_id=grant_id)
    if (
        expected_principal_id is not None
        and grant.principal_id != expected_principal_id
    ):
        raise CommandNotFound("direct grant not found")
    _require_owner_for_owner_grant(
        session,
        context,
        object_id=object_id,
        roles=(Role(grant.role),),
    )
    revision = _expected_revision(expected_revision)
    if row.revision != revision:
        raise CommandPreconditionFailed("object revision changed")
    if grant.role == Role.OWNER:
        lock_owner_coverage_state(
            session,
            extra_principal_ids=(context.principal.id, grant.principal_id),
        )
    target = session.get(Principal, grant.principal_id)
    if target is None:
        raise CommandConflict("grant principal does not exist")
    before = _grant_snapshot(grant)
    previously_owned = (
        grant_scope_object_ids(
            session,
            object_id=object_id,
            scope=GrantScope(grant.scope),
        )
        if grant.role == Role.OWNER and target.active
        else set()
    )
    new_revision = _claim_object_revision(
        session,
        object_id=object_id,
        expected_revision=revision,
    )
    session.delete(grant)
    session.flush()
    try:
        ensure_owner_coverage_preserved(
            session,
            previously_covered_ids=previously_owned,
        )
        _ensure_no_self_lockout(
            session,
            context,
            object_id=object_id,
            target_principal_id=target.id,
        )
    except LastOwnerError as exc:
        raise CommandConflict(str(exc)) from exc
    _write_grant_audit(
        session,
        context,
        object_id=object_id,
        action="grant_revoke",
        target_principal_id=target.id,
        old_revision=revision,
        new_revision=new_revision,
        before=before,
        after=None,
    )
    return GrantCommandResult(
        object_id=object_id,
        revision=new_revision,
        etag=revision_etag(new_revision),
        changed=True,
        revoked_grant_id=grant_id,
    )


def actor_can_manage_owner_grants(
    context: WriteContext,
    *,
    object_id: str,
) -> bool:
    return any(
        grant.role == Role.OWNER
        for grant in context.policy.grants_for(object_id)
    )


def _require_manage_access(
    session: Session,
    context: WriteContext,
    *,
    object_id: str,
    refresh_policy: bool = False,
) -> CatalogObject:
    policy = (
        policy_for_principal(session, context.principal.id)
        if refresh_policy
        else context.policy
    )
    row = session.get(CatalogObject, object_id)
    if row is None or not policy.can(Permission.DISCOVER, object_id):
        raise CommandNotFound("catalog object not found")
    if not policy.can(Permission.MANAGE_ACCESS, object_id):
        raise CommandAuthorizationDenied(
            object_id=object_id,
            permission=Permission.MANAGE_ACCESS,
        )
    return row


def _require_owner_for_owner_grant(
    session: Session,
    context: WriteContext,
    *,
    object_id: str,
    roles: tuple[Role, ...],
) -> None:
    if Role.OWNER not in roles:
        return
    policy = policy_for_principal(session, context.principal.id)
    if any(
        grant.role == Role.OWNER
        for grant in policy.grants_for(object_id)
    ):
        return
    # Both outcomes stay denials; only the published reason differs. The
    # actor already holds manage_access here, so it may learn whether the
    # object has any Owner at all.
    if object_owner_coverage(session, object_id, lock=False).ownerless:
        raise CommandAuthorizationDenied(
            object_id=object_id,
            permission=Permission.MANAGE_ACCESS,
            code=OBJECT_HAS_NO_OWNER_USE_ADOPTION_FLOW,
            message=(
                "the object has no active Owner; a catalog owner must use the "
                "ownerless-object adoption flow"
            ),
        )
    raise CommandAuthorizationDenied(
        object_id=object_id,
        permission=Permission.MANAGE_ACCESS,
        code=OWNER_REQUIRED_TO_MANAGE_OWNER_GRANTS,
        message=(
            "an effective Owner grant on this object is required to add, "
            "change, or remove Owner grants"
        ),
    )


def _holds_adoption_authority(session: Session, context: WriteContext) -> bool:
    """Whether the actor may adopt ownerless objects, re-read from the database.

    Adoption is catalog administration, so it needs the global catalog-owner
    role, not an object grant and not the separate platform-admin axis. The
    trusted channel must also match the token audience, exactly like root
    creation: browser actors carry no service-token audience, while api/mcp
    actors must hold the matching one.
    """
    if context.channel == "ui":
        trusted_origin = context.principal.service_token_audience is None
    else:
        trusted_origin = context.principal.service_token_audience == context.channel
    actor = session.get(Principal, context.principal.id)
    return (
        trusted_origin
        and actor is not None
        and actor.active
        and actor.catalog_role == CatalogRole.CATALOG_OWNER
    )


def _require_adoption_authority(
    session: Session,
    context: WriteContext,
    *,
    object_id: str,
) -> None:
    if not _holds_adoption_authority(session, context):
        raise CommandAuthorizationDenied(
            object_id=object_id,
            permission=Permission.MANAGE_ACCESS,
            code=ADOPTION_REQUIRES_CATALOG_OWNER,
            message="only an active catalog owner may adopt an ownerless object",
        )


def _require_ownerless(coverage: ObjectOwnerCoverage) -> None:
    if not coverage.ownerless:
        raise CommandConflict(
            "the object already has active Owner coverage; use ordinary Owner "
            "grant management",
            code=OBJECT_HAS_OWNER_COVERAGE,
        )


def _active_target_principal(session: Session, principal_id: str) -> Principal:
    principal = lock_principal_rows(session, (principal_id,)).get(principal_id)
    if principal is None or not principal.active:
        raise CommandConflict("active principal not found")
    return principal


def _direct_grant(
    session: Session,
    *,
    object_id: str,
    grant_id: int,
) -> ObjectGrant:
    grant = session.scalar(
        select(ObjectGrant).where(
            ObjectGrant.id == grant_id,
            ObjectGrant.object_id == object_id,
        )
    )
    if grant is None:
        raise CommandNotFound("direct grant not found")
    return grant


def _expected_revision(value: int | str | None) -> int:
    if isinstance(value, int):
        if value < 1:
            raise CommandPreconditionFailed("object revision must be positive")
        return value
    return parse_if_match(value)


def _claim_object_revision(
    session: Session,
    *,
    object_id: str,
    expected_revision: int,
) -> int:
    result = session.execute(
        update(CatalogObject)
        .where(
            CatalogObject.id == object_id,
            CatalogObject.revision == expected_revision,
        )
        .values(
            revision=CatalogObject.revision + 1,
            updated_at=datetime.now(UTC).replace(tzinfo=None),
        )
        .execution_options(synchronize_session=False)
    )
    if result.rowcount != 1:
        raise CommandPreconditionFailed("object revision changed")
    session.expire_all()
    return expected_revision + 1


def _ensure_no_self_lockout(
    session: Session,
    context: WriteContext,
    *,
    object_id: str,
    target_principal_id: str,
) -> None:
    if target_principal_id != context.principal.id:
        return
    refreshed_policy = policy_for_principal(session, context.principal.id)
    if not refreshed_policy.can(Permission.MANAGE_ACCESS, object_id):
        raise CommandConflict("grant change would remove the actor's access management permission")


def _write_grant_audit(
    session: Session,
    context: WriteContext,
    *,
    object_id: str,
    action: str,
    target_principal_id: str,
    old_revision: int,
    new_revision: int,
    before: dict[str, object] | None,
    after: dict[str, object] | None,
) -> None:
    add_audit_event(
        session,
        object_id=object_id,
        action=action,
        actor=context.principal.id,
        details={
            "actor_principal_id": context.principal.id,
            "actor_login": context.principal.login,
            "target_principal_id": target_principal_id,
            "channel": context.channel,
            "request_id": context.request_id,
            "old_revision": old_revision,
            "new_revision": new_revision,
            "before": before,
            "after": after,
        },
    )
    session.flush()


def _grant_snapshot(grant: ObjectGrant) -> dict[str, object]:
    return {
        "grant_id": grant.id,
        "principal_id": grant.principal_id,
        "object_id": grant.object_id,
        "role": str(grant.role),
        "scope": str(grant.scope),
    }


def _direct_grant_view(
    grant: ObjectGrant,
    principal: Principal,
) -> DirectGrantView:
    return DirectGrantView(
        id=grant.id,
        principal=_principal_summary(principal),
        role=Role(grant.role),
        scope=GrantScope(grant.scope),
        created_at=format_rfc3339_utc(grant.created_at) or "",
        updated_at=format_rfc3339_utc(grant.updated_at) or "",
    )


def _principal_summary(principal: Principal) -> PrincipalSummary:
    return PrincipalSummary(
        id=principal.id,
        login=principal.login,
        display_name=principal.display_name,
        principal_type=principal.principal_type,
        active=principal.active,
    )
