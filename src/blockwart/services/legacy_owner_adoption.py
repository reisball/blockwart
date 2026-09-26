"""Protected pre-start adoption of legacy ownerless objects (#242).

The ownership invariant keeps readiness closed while any catalog object lacks
active object Owner grant coverage, so an upgraded legacy catalog with
ownerless objects cannot start and cannot reach the regular adoption command.
This module is the supported offline repair for exactly that state. It runs
through ``blockwart-db adopt-owners`` against the database directly and never
touches readiness:

- the operator names an explicit target principal and an audit reason; nothing
  infers, guesses, or auto-selects an owner;
- the target must be an existing active principal, exactly like the online
  adoption command; it needs no catalog role, because the administrative
  authority is the trusted operator running the protected CLI;
- a preview lists the exact ownerless set and binds it, with each object's
  revision and the target, into a plan digest;
- apply takes the shared Owner-coverage locks, recomputes the set, fails closed
  on any drift from the reviewed digest, claims every object revision in ID
  order, and writes exactly one direct ``Owner/self`` grant per object through
  :func:`assign_initial_owner`, all in one transaction;
- a catalog that no longer has ownerless objects is a no-op that writes nothing.

Object identity, kind, label, data, placement, relationships, and every existing
grant are left untouched; only the revision (the access ETag) advances, exactly
like the online adoption command.
"""

from __future__ import annotations

import hashlib
import json
import unicodedata
from collections import Counter
from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import uuid4

from sqlalchemy import func, select, text, update
from sqlalchemy.orm import Session

from blockwart.domain.auth import Role
from blockwart.domain.security import looks_like_secret
from blockwart.models import CatalogObject, ObjectGrant, Principal
from blockwart.services.access import AccessGrantError, lock_owner_coverage_state
from blockwart.services.audit import add_audit_event
from blockwart.services.grant_management import OWNER_ADOPTION_ACTION
from blockwart.services.identity import (
    REQUEST_ID_PATTERN,
    IdentityError,
    normalize_login,
    principal_by_login,
    record_security_event,
)
from blockwart.services.ownership import (
    OWNER_PRINCIPAL_INACTIVE,
    OWNER_PRINCIPAL_REQUIRED,
    InitialOwnerError,
    assign_initial_owner,
    ensure_objects_directly_owned,
    ownerless_object_ids,
)

LEGACY_OWNER_ADOPTION_ACTION = "legacy_owner_adoption"
PROTECTED_CLI_ACTOR = "protected_cli"
MAX_REASON_LENGTH = 500

# Stable machine codes printed by the CLI; they must never be renamed.
OWNER_PRINCIPAL_MALFORMED = "owner_principal_malformed"
ADOPTION_REASON_REQUIRED = "adoption_reason_required"
ADOPTION_REASON_INVALID = "adoption_reason_invalid"
ADOPTION_REQUEST_ID_INVALID = "adoption_request_id_invalid"
ADOPTION_PLAN_DIGEST_REQUIRED = "adoption_plan_digest_required"
ADOPTION_PLAN_DRIFT = "adoption_plan_drift"

_PLAN_DIGEST_DOMAIN = b"blockwart:legacy-owner-adoption:v1\n"


class LegacyOwnerAdoptionError(AccessGrantError):
    """The offline adoption request is invalid or no longer matches its plan."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True, slots=True)
class AdoptionRequest:
    """Validated operator input; checked before any database access."""

    owner_login: str
    reason: str
    request_id: str | None = None
    expected_plan_digest: str | None = None


@dataclass(frozen=True, slots=True)
class AdoptionCandidate:
    object_id: str
    kind: str
    revision: int

    @property
    def ref(self) -> str:
        return f"{self.kind}:{self.object_id}"


@dataclass(frozen=True, slots=True)
class AdoptionPlan:
    """The exact ownerless set for one explicit target, in object-ID order."""

    target_principal_id: str
    target_login: str
    candidates: tuple[AdoptionCandidate, ...]

    @property
    def counts_by_kind(self) -> dict[str, int]:
        return dict(sorted(Counter(item.kind for item in self.candidates).items()))

    @property
    def plan_digest(self) -> str:
        payload = {
            "target_principal_id": self.target_principal_id,
            "objects": [
                {"id": item.object_id, "kind": item.kind, "revision": item.revision}
                for item in self.candidates
            ],
        }
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return "sha256:" + hashlib.sha256(
            _PLAN_DIGEST_DOMAIN + encoded.encode("utf-8")
        ).hexdigest()


@dataclass(frozen=True, slots=True)
class AdoptedObject:
    object_id: str
    kind: str
    grant_id: int
    old_revision: int
    new_revision: int

    @property
    def ref(self) -> str:
        return f"{self.kind}:{self.object_id}"


@dataclass(frozen=True, slots=True)
class AdoptionResult:
    plan: AdoptionPlan
    adopted: tuple[AdoptedObject, ...]
    request_id: str | None


def validate_adoption_request(
    *,
    owner_login: str | None,
    reason: str | None,
    request_id: str | None = None,
    expected_plan_digest: str | None = None,
    apply: bool = False,
) -> AdoptionRequest:
    """Reject malformed operator input before the database is opened."""
    if owner_login is None or not owner_login.strip():
        raise LegacyOwnerAdoptionError(
            OWNER_PRINCIPAL_REQUIRED,
            "an explicit owner principal is required",
        )
    try:
        login = normalize_login(owner_login)
    except IdentityError as exc:
        raise LegacyOwnerAdoptionError(
            OWNER_PRINCIPAL_MALFORMED,
            "the owner login is malformed",
        ) from exc
    if reason is None or not reason.strip():
        raise LegacyOwnerAdoptionError(
            ADOPTION_REASON_REQUIRED,
            "an explicit audit reason is required",
        )
    normalized_reason = reason.strip()
    if (
        len(normalized_reason) > MAX_REASON_LENGTH
        or any(unicodedata.category(char).startswith("C") for char in normalized_reason)
        or looks_like_secret(normalized_reason)
    ):
        raise LegacyOwnerAdoptionError(
            ADOPTION_REASON_INVALID,
            "the audit reason must be one printable line of at most "
            f"{MAX_REASON_LENGTH} characters without secret-shaped content",
        )
    if request_id is not None and not REQUEST_ID_PATTERN.fullmatch(request_id):
        raise LegacyOwnerAdoptionError(
            ADOPTION_REQUEST_ID_INVALID,
            "the request ID must be 1-64 letters, digits, dots, dashes, or underscores",
        )
    if apply and (expected_plan_digest is None or not expected_plan_digest.strip()):
        raise LegacyOwnerAdoptionError(
            ADOPTION_PLAN_DIGEST_REQUIRED,
            "apply requires the plan digest printed by the preview",
        )
    return AdoptionRequest(
        owner_login=login,
        reason=normalized_reason,
        request_id=request_id,
        expected_plan_digest=(
            expected_plan_digest.strip() if expected_plan_digest is not None else None
        ),
    )


def preview_legacy_owner_adoption(
    session: Session,
    request: AdoptionRequest,
) -> AdoptionPlan:
    """Return the exact ownerless set for the target; never locks or writes."""
    principal = _eligible_target(principal_by_login(session, request.owner_login))
    return _current_plan(session, principal)


def apply_legacy_owner_adoption(
    session: Session,
    request: AdoptionRequest,
) -> AdoptionResult:
    """Adopt the reviewed ownerless set inside the caller's single transaction.

    The caller commits or rolls back; any error raised here leaves no grant,
    revision, or audit behind.
    """
    if request.expected_plan_digest is None:
        raise LegacyOwnerAdoptionError(
            ADOPTION_PLAN_DIGEST_REQUIRED,
            "apply requires the plan digest printed by the preview",
        )
    _begin_write_transaction(session)
    principal = _eligible_target(principal_by_login(session, request.owner_login))
    # Principals, then active Owner grants, then canonical placements: the one
    # global order every Owner-coverage writer shares. The target is re-read
    # under its lock, so a concurrent deactivation is honored.
    lock_owner_coverage_state(session, extra_principal_ids=(principal.id,))
    _eligible_target(principal)

    plan = _current_plan(session, principal)
    if not plan.candidates:
        return AdoptionResult(plan=plan, adopted=(), request_id=request.request_id)
    if plan.plan_digest != request.expected_plan_digest:
        raise LegacyOwnerAdoptionError(
            ADOPTION_PLAN_DRIFT,
            "the ownerless set changed since the preview; preview again",
        )

    request_id = request.request_id or str(uuid4())
    inactive_counts = _inactive_direct_owner_counts(session, plan)
    now = datetime.now(UTC).replace(tzinfo=None)
    # Claim every revision in object-ID order before writing a grant. Any
    # concurrent data write, delete, or adoption changes the revision and
    # fails the whole transaction closed.
    for candidate in plan.candidates:
        claimed = session.execute(
            update(CatalogObject)
            .where(
                CatalogObject.id == candidate.object_id,
                CatalogObject.revision == candidate.revision,
            )
            .values(revision=CatalogObject.revision + 1, updated_at=now)
            .execution_options(synchronize_session=False)
        )
        if claimed.rowcount != 1:
            raise LegacyOwnerAdoptionError(
                ADOPTION_PLAN_DRIFT,
                "a planned object changed during apply; preview again",
            )
    session.expire_all()

    adopted: list[AdoptedObject] = []
    for candidate in plan.candidates:
        try:
            grant = assign_initial_owner(
                session,
                object_id=candidate.object_id,
                owner_principal_id=principal.id,
                created_by_principal_id=None,
            )
        except InitialOwnerError as exc:
            raise LegacyOwnerAdoptionError(ADOPTION_PLAN_DRIFT, str(exc)) from exc
        adopted.append(
            AdoptedObject(
                object_id=candidate.object_id,
                kind=candidate.kind,
                grant_id=grant.id,
                old_revision=candidate.revision,
                new_revision=candidate.revision + 1,
            )
        )

    adopted_ids = [item.object_id for item in adopted]
    ensure_objects_directly_owned(session, adopted_ids)
    if ownerless_object_ids(session):
        raise LegacyOwnerAdoptionError(
            ADOPTION_PLAN_DRIFT,
            "ownerless objects remain after apply; preview again",
        )

    evidence = {
        "operation": LEGACY_OWNER_ADOPTION_ACTION,
        "actor": PROTECTED_CLI_ACTOR,
        "channel": "cli",
        "request_id": request_id,
        "reason": request.reason,
        "target_principal_id": principal.id,
        "target_login": principal.login,
        "target_catalog_role": principal.catalog_role,
        "plan_digest": plan.plan_digest,
    }
    for item in adopted:
        add_audit_event(
            session,
            object_id=item.object_id,
            action=OWNER_ADOPTION_ACTION,
            actor=PROTECTED_CLI_ACTOR,
            details={
                **evidence,
                "object_ref": item.ref,
                "old_revision": item.old_revision,
                "new_revision": item.new_revision,
                "previous_owner_count": 0,
                "previous_direct_owner_count": 0,
                "previous_inherited_owner_count": 0,
                "inactive_direct_owner_grants": inactive_counts.get(item.object_id, 0),
                "before": None,
                "after": {
                    "grant_id": item.grant_id,
                    "principal_id": principal.id,
                    "object_id": item.object_id,
                    "role": "owner",
                    "scope": "self",
                },
            },
        )
    add_audit_event(
        session,
        object_id=None,
        action=LEGACY_OWNER_ADOPTION_ACTION,
        actor=PROTECTED_CLI_ACTOR,
        details={
            **evidence,
            "adopted": len(adopted),
            "counts_by_kind": plan.counts_by_kind,
            "object_ids": adopted_ids,
            "grant_ids": [item.grant_id for item in adopted],
        },
    )
    record_security_event(
        session,
        event_type=LEGACY_OWNER_ADOPTION_ACTION,
        outcome="success",
        channel="cli",
        principal_id=principal.id,
        request_id=request_id,
        details={
            "actor": PROTECTED_CLI_ACTOR,
            "target_principal_id": principal.id,
            "plan_digest": plan.plan_digest,
            "adopted": len(adopted),
            "counts_by_kind": plan.counts_by_kind,
        },
    )
    session.flush()
    return AdoptionResult(plan=plan, adopted=tuple(adopted), request_id=request_id)


def _eligible_target(principal: Principal | None) -> Principal:
    if principal is None or not principal.active:
        raise LegacyOwnerAdoptionError(
            OWNER_PRINCIPAL_INACTIVE,
            "the owner principal must exist and be active",
        )
    return principal


def _current_plan(session: Session, principal: Principal) -> AdoptionPlan:
    ownerless = ownerless_object_ids(session)
    rows = session.execute(
        select(CatalogObject.id, CatalogObject.kind, CatalogObject.revision).order_by(
            CatalogObject.id
        )
    ).all()
    return AdoptionPlan(
        target_principal_id=principal.id,
        target_login=principal.login,
        candidates=tuple(
            AdoptionCandidate(object_id=row.id, kind=row.kind, revision=row.revision)
            for row in rows
            if row.id in ownerless
        ),
    )


def _inactive_direct_owner_counts(session: Session, plan: AdoptionPlan) -> dict[str, int]:
    planned = {item.object_id for item in plan.candidates}
    rows = session.execute(
        select(ObjectGrant.object_id, func.count(ObjectGrant.id))
        .join(Principal, Principal.id == ObjectGrant.principal_id)
        .where(ObjectGrant.role == Role.OWNER, Principal.active.is_(False))
        .group_by(ObjectGrant.object_id)
    ).all()
    return {str(object_id): int(count) for object_id, count in rows if object_id in planned}


def _begin_write_transaction(session: Session) -> None:
    """Take SQLite's single writer lock before the first read of the snapshot.

    PostgreSQL relies on the row locks of the shared coverage protocol instead.
    """
    if session.get_bind().dialect.name == "sqlite":
        session.execute(text("BEGIN IMMEDIATE"))
