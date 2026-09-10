"""The catalog ownership invariant: first-Owner assignment and its detection.

Every catalog object must be reachable by at least one active *object* Owner
grant, either directly or through a canonical subtree grant. A global
``catalog_owner`` administers the whole catalog, but it is deliberately not an
object Owner source: it can neither add, change, nor remove Owner grants
through ordinary grant management, and it never masks a missing Owner here.

This module is the one place that

- assigns the first direct ``Owner/self`` grant inside an object's creation
  transaction. The REST, MCP, and UI create commands, the seed and Markdown
  imports, and reviewed Knowledge apply all call :func:`assign_initial_owner`,
  so no supported path can commit an object without its Owner;
- resolves the explicit owner identity an import or seed must name;
- measures one object's active direct and inherited Owner grant coverage;
- lists legacy ownerless objects read-only, without ever guessing an owner
  from unrelated effective permissions.

The audited recovery command for legacy objects lives in grant management,
because it is an access-management write with its own authority rules.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Literal

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from blockwart.domain.auth import CatalogRole, GrantScope, Role
from blockwart.domain.placement import CANONICAL_PLACEMENT_RELATION_TYPE
from blockwart.domain.provenance import load_provenance
from blockwart.models import CatalogObject, ObjectGrant, Principal, Relationship
from blockwart.services.access import (
    AccessGrantError,
    inherited_owner_grant_ids,
    lock_owner_coverage_state,
    lock_principal_rows,
    owner_grant_covered_object_ids,
)
from blockwart.services.identity import IdentityError, principal_by_login

OwnerlessPlacement = Literal["top_level", "placed"]

# Stable machine codes. They are published by the CLI and mapped onto the
# structured REST, MCP, and UI error reasons, so they must never be renamed.
OWNER_PRINCIPAL_REQUIRED = "owner_principal_required"
OWNER_PRINCIPAL_INACTIVE = "owner_principal_inactive"
INITIAL_OWNER_OBJECT_MISSING = "initial_owner_object_missing"
INITIAL_OWNER_ALREADY_PRESENT = "initial_owner_already_present"
INITIAL_OWNER_MISSING = "initial_owner_missing"
ADOPTION_BLOCKER_CATALOG_OWNER_MISSING = "catalog_owner_missing"


class InitialOwnerError(AccessGrantError):
    """A new or adopted object cannot receive its first direct Owner grant."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True, slots=True)
class ObjectOwnerCoverage:
    """Active object Owner grants that reach one object; catalog roles excluded."""

    object_id: str
    direct_active_owner_grants: int
    inherited_active_owner_grants: int
    inactive_direct_owner_grants: int

    @property
    def active_owner_grants(self) -> int:
        return self.direct_active_owner_grants + self.inherited_active_owner_grants

    @property
    def ownerless(self) -> bool:
        return self.active_owner_grants == 0


@dataclass(frozen=True, slots=True)
class OwnerlessObjectReport:
    """Safe identifying and recovery context for one ownerless object."""

    object_id: str
    kind: str
    label: str
    revision: int
    placement: OwnerlessPlacement
    inactive_direct_owner_grants: int
    provenance_source_type: str
    provenance_source_ref: str | None
    adoption_possible: bool
    adoption_blocker: str | None
    direct_active_owner_grants: int = 0
    inherited_active_owner_grants: int = 0

    @property
    def ref(self) -> str:
        return f"{self.kind}:{self.object_id}"


def resolve_owner_principal(
    session: Session,
    principal_id: str | None,
    *,
    include_owner_coverage_locks: bool = False,
) -> Principal:
    """Lock and return the explicit active principal that will own new objects.

    Bulk replacement imports also request the complete coverage lock protocol
    so their later coverage snapshot shares deactivation's deterministic order.
    """
    if principal_id is None or not principal_id.strip():
        raise InitialOwnerError(
            OWNER_PRINCIPAL_REQUIRED,
            "an explicit owner principal is required",
        )
    if include_owner_coverage_locks:
        lock_owner_coverage_state(
            session,
            extra_principal_ids=(principal_id,),
        )
        principal = session.get(Principal, principal_id)
    else:
        principal = lock_principal_rows(session, (principal_id,)).get(principal_id)
    if principal is None or not principal.active:
        raise InitialOwnerError(
            OWNER_PRINCIPAL_INACTIVE,
            "the owner principal must exist and be active",
        )
    return principal


def resolve_owner_login(session: Session, login: str | None) -> Principal:
    """Resolve an operator-supplied owner login for a protected import command."""
    if login is None or not login.strip():
        raise InitialOwnerError(
            OWNER_PRINCIPAL_REQUIRED,
            "an explicit owner principal is required",
        )
    try:
        principal = principal_by_login(session, login)
    except IdentityError:
        principal = None
    if principal is None:
        raise InitialOwnerError(
            OWNER_PRINCIPAL_INACTIVE,
            "the owner principal must exist and be active",
        )
    return resolve_owner_principal(session, principal.id)


def assign_initial_owner(
    session: Session,
    *,
    object_id: str,
    owner_principal_id: str | None,
    created_by_principal_id: str | None,
) -> ObjectGrant:
    """Write the one direct ``Owner/self`` grant an object starts its life with.

    The caller's transaction owns the object row, its revision, and its audit
    event. Any error raised here aborts that whole transaction, so an object
    can never commit without its first Owner. The object must not already have
    an active direct Owner: this primitive is never a second-owner shortcut.
    """
    principal = resolve_owner_principal(session, owner_principal_id)
    if session.get(CatalogObject, object_id) is None:
        raise InitialOwnerError(
            INITIAL_OWNER_OBJECT_MISSING,
            "catalog object not found",
        )
    existing = session.scalar(
        select(ObjectGrant.id)
        .join(Principal, Principal.id == ObjectGrant.principal_id)
        .where(
            ObjectGrant.object_id == object_id,
            ObjectGrant.role == Role.OWNER,
            Principal.active.is_(True),
        )
        .limit(1)
    )
    if existing is not None:
        raise InitialOwnerError(
            INITIAL_OWNER_ALREADY_PRESENT,
            "catalog object already has an active direct Owner grant",
        )
    grant = ObjectGrant(
        principal_id=principal.id,
        object_id=object_id,
        role=Role.OWNER,
        scope=GrantScope.SELF,
        created_by_principal_id=created_by_principal_id,
    )
    session.add(grant)
    session.flush()
    return grant


def ensure_objects_directly_owned(
    session: Session,
    object_ids: Iterable[str],
) -> None:
    """Prove, before commit, that every created object carries its Owner/self grant."""
    expected = set(object_ids)
    if not expected:
        return
    owned = set(
        session.scalars(
            select(ObjectGrant.object_id)
            .join(Principal, Principal.id == ObjectGrant.principal_id)
            .where(
                ObjectGrant.object_id.in_(sorted(expected)),
                ObjectGrant.role == Role.OWNER,
                ObjectGrant.scope == GrantScope.SELF,
                Principal.active.is_(True),
            )
        ).all()
    )
    if expected - owned:
        raise InitialOwnerError(
            INITIAL_OWNER_MISSING,
            "a created object has no active direct Owner grant",
        )


def object_owner_coverage(
    session: Session,
    object_id: str,
    *,
    lock: bool,
) -> ObjectOwnerCoverage:
    """Count the active Owner grants that reach ``object_id``.

    With ``lock`` the Owner grants and canonical placement edges are locked
    first (PostgreSQL), so the answer cannot race another Owner-coverage
    decision. Read paths pass ``lock=False``.
    """
    if lock:
        lock_owner_coverage_state(session)
    direct_counts = dict(
        session.execute(
            select(Principal.active, func.count(ObjectGrant.id))
            .join(Principal, Principal.id == ObjectGrant.principal_id)
            .where(
                ObjectGrant.object_id == object_id,
                ObjectGrant.role == Role.OWNER,
            )
            .group_by(Principal.active)
        ).all()
    )
    return ObjectOwnerCoverage(
        object_id=object_id,
        direct_active_owner_grants=int(direct_counts.get(True, 0)),
        inherited_active_owner_grants=len(
            inherited_owner_grant_ids(session, object_id=object_id)
        ),
        inactive_direct_owner_grants=int(direct_counts.get(False, 0)),
    )


def ownerless_object_ids(session: Session) -> set[str]:
    """Return every object without active direct or inherited Owner grant coverage."""
    all_ids = set(session.scalars(select(CatalogObject.id)).all())
    return all_ids - owner_grant_covered_object_ids(session, lock=False)


def find_ownerless_objects(session: Session) -> tuple[OwnerlessObjectReport, ...]:
    """Read-only legacy report of every ownerless object, in stable order.

    It never writes, locks, or proposes an owner. Adoption is reported as
    possible only while an active catalog owner exists to perform it through
    the audited adoption command.
    """
    ownerless_ids = ownerless_object_ids(session)
    if not ownerless_ids:
        return ()
    rows = session.scalars(
        select(CatalogObject)
        .where(CatalogObject.id.in_(sorted(ownerless_ids)))
        .order_by(CatalogObject.kind, CatalogObject.id)
    ).all()
    placed_refs = set(
        session.scalars(
            select(Relationship.to_ref).where(
                Relationship.relation_type == CANONICAL_PLACEMENT_RELATION_TYPE
            )
        ).all()
    )
    inactive_counts = dict(
        session.execute(
            select(ObjectGrant.object_id, func.count(ObjectGrant.id))
            .join(Principal, Principal.id == ObjectGrant.principal_id)
            .where(
                ObjectGrant.object_id.in_(sorted(ownerless_ids)),
                ObjectGrant.role == Role.OWNER,
                Principal.active.is_(False),
            )
            .group_by(ObjectGrant.object_id)
        ).all()
    )
    catalog_owner_present = (
        session.scalar(
            select(Principal.id)
            .where(
                Principal.active.is_(True),
                Principal.catalog_role == CatalogRole.CATALOG_OWNER,
            )
            .limit(1)
        )
        is not None
    )
    reports: list[OwnerlessObjectReport] = []
    for row in rows:
        provenance, _valid = load_provenance(row.provenance_json)
        reports.append(
            OwnerlessObjectReport(
                object_id=row.id,
                kind=row.kind,
                label=row.label,
                revision=row.revision,
                placement=(
                    "placed" if f"{row.kind}:{row.id}" in placed_refs else "top_level"
                ),
                inactive_direct_owner_grants=int(inactive_counts.get(row.id, 0)),
                provenance_source_type=provenance.source_type,
                provenance_source_ref=provenance.source_ref,
                adoption_possible=catalog_owner_present,
                adoption_blocker=(
                    None
                    if catalog_owner_present
                    else ADOPTION_BLOCKER_CATALOG_OWNER_MISSING
                ),
            )
        )
    return tuple(reports)
