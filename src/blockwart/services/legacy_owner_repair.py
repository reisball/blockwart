"""Transactional pre-start repair for legacy ownerless catalogs."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from collections import Counter
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session

from blockwart.domain.auth import CatalogRole, GrantScope, Role
from blockwart.domain.security import find_secret_violations
from blockwart.models import CatalogObject, ObjectGrant, Principal, Relationship
from blockwart.services.access import (
    ensure_complete_owner_coverage,
    lock_owner_coverage_state,
)
from blockwart.services.audit import add_audit_event
from blockwart.services.identity import (
    IdentityError,
    normalize_login,
    principal_by_login,
    record_security_event,
)
from blockwart.services.ownership import find_ownerless_objects

LEGACY_OWNER_REPAIR_ACTION = "legacy_owner_repair"
LEGACY_OWNER_REPAIR_VERSION = 1
PLAN_DIGEST_PATTERN = re.compile(r"^[0-9a-f]{64}$")
REQUEST_ID_PATTERN = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
MAX_REASON_LENGTH = 500


class LegacyOwnerRepairError(ValueError):
    """Stable, non-sensitive failure from the administrative repair path."""

    def __init__(self, code: str) -> None:
        super().__init__("legacy Owner repair rejected")
        self.code = code


@dataclass(frozen=True, slots=True)
class LegacyOwnerRepairObject:
    object_id: str
    kind: str
    revision: int

    @property
    def ref(self) -> str:
        return f"{self.kind}:{self.object_id}"


@dataclass(frozen=True, slots=True)
class LegacyOwnerRepairPlan:
    actor_principal_id: str
    actor_login: str
    target_principal_id: str
    target_login: str
    reason: str
    request_id: str
    objects: tuple[LegacyOwnerRepairObject, ...]
    counts_by_kind: tuple[tuple[str, int], ...]
    plan_digest: str


@dataclass(frozen=True, slots=True)
class LegacyOwnerRepairResult:
    plan: LegacyOwnerRepairPlan
    repaired: int
    remaining: int


def build_legacy_owner_repair_plan(
    session: Session,
    *,
    actor_login: str,
    target_login: str,
    reason: str,
    request_id: str,
    lock: bool = False,
) -> LegacyOwnerRepairPlan:
    """Validate authority and return an exact, mutation-free repair plan."""
    normalized_actor = _normalize_principal_login(actor_login, "repair_actor_malformed")
    normalized_target = _normalize_principal_login(target_login, "repair_target_malformed")
    normalized_reason = _normalize_reason(reason)
    normalized_request_id = _normalize_request_id(request_id)

    if lock:
        actor_id = _principal_id_for_login(session, normalized_actor)
        target_id = _principal_id_for_login(session, normalized_target)
        lock_owner_coverage_state(
            session,
            extra_principal_ids=tuple(
                principal_id
                for principal_id in (actor_id, target_id)
                if principal_id is not None
            ),
        )
        _lock_remaining_repair_rows(session)

    actor = _resolve_actor(session, normalized_actor)
    target = _resolve_target(session, normalized_target)
    reports = find_ownerless_objects(session)
    objects = tuple(
        LegacyOwnerRepairObject(
            object_id=report.object_id,
            kind=report.kind,
            revision=report.revision,
        )
        for report in reports
    )
    counts_by_kind = tuple(sorted(Counter(item.kind for item in objects).items()))
    digest_payload = {
        "actor_principal_id": actor.id,
        "catalog_state": _catalog_state(session),
        "object_grant_state": _object_grant_state(session),
        "ownerless_objects": [
            {
                "kind": item.kind,
                "object_id": item.object_id,
                "revision": item.revision,
            }
            for item in objects
        ],
        "principal_state": _principal_state(session),
        "reason": normalized_reason,
        "relationship_state": _relationship_state(session),
        "request_id": normalized_request_id,
        "target_principal_id": target.id,
        "version": LEGACY_OWNER_REPAIR_VERSION,
    }
    plan_digest = hashlib.sha256(_canonical_json(digest_payload).encode()).hexdigest()
    return LegacyOwnerRepairPlan(
        actor_principal_id=actor.id,
        actor_login=actor.login,
        target_principal_id=target.id,
        target_login=target.login,
        reason=normalized_reason,
        request_id=normalized_request_id,
        objects=objects,
        counts_by_kind=counts_by_kind,
        plan_digest=plan_digest,
    )


def apply_legacy_owner_repair(
    session: Session,
    *,
    actor_login: str,
    target_login: str,
    reason: str,
    request_id: str,
    expected_plan_digest: str,
) -> LegacyOwnerRepairResult:
    """Apply one reviewed plan inside the caller's serializable transaction."""
    expected_digest = _normalize_plan_digest(expected_plan_digest)
    plan = build_legacy_owner_repair_plan(
        session,
        actor_login=actor_login,
        target_login=target_login,
        reason=reason,
        request_id=request_id,
        lock=True,
    )
    if not hmac.compare_digest(plan.plan_digest, expected_digest):
        raise LegacyOwnerRepairError("repair_plan_drift")
    if not plan.objects:
        return LegacyOwnerRepairResult(plan=plan, repaired=0, remaining=0)

    for item in plan.objects:
        row = session.get(CatalogObject, item.object_id)
        if row is None or row.revision != item.revision:
            raise LegacyOwnerRepairError("repair_plan_drift")
        row.revision += 1
        session.add(
            ObjectGrant(
                principal_id=plan.target_principal_id,
                object_id=item.object_id,
                role=Role.OWNER,
                scope=GrantScope.SELF,
                created_by_principal_id=plan.actor_principal_id,
            )
        )
    session.flush()
    ensure_complete_owner_coverage(session)

    object_ids = [item.object_id for item in plan.objects]
    counts_by_kind = dict(plan.counts_by_kind)
    audit_details = {
        "actor_login": plan.actor_login,
        "actor_principal_id": plan.actor_principal_id,
        "channel": "cli",
        "counts_by_kind": counts_by_kind,
        "object_ids": object_ids,
        "plan_digest": plan.plan_digest,
        "reason": plan.reason,
        "repaired_count": len(object_ids),
        "request_id": plan.request_id,
        "target_login": plan.target_login,
        "target_principal_id": plan.target_principal_id,
    }
    add_audit_event(
        session,
        object_id=None,
        action=LEGACY_OWNER_REPAIR_ACTION,
        actor=plan.actor_principal_id,
        details=audit_details,
    )
    record_security_event(
        session,
        event_type=LEGACY_OWNER_REPAIR_ACTION,
        outcome="success",
        channel="cli",
        principal_id=plan.actor_principal_id,
        request_id=plan.request_id,
        details={
            "counts_by_kind": counts_by_kind,
            "plan_digest": plan.plan_digest,
            "reason": plan.reason,
            "target_principal_id": plan.target_principal_id,
        },
    )
    session.flush()
    remaining = len(find_ownerless_objects(session))
    if remaining:
        raise LegacyOwnerRepairError("repair_owner_coverage_incomplete")
    return LegacyOwnerRepairResult(
        plan=plan,
        repaired=len(plan.objects),
        remaining=remaining,
    )


def _normalize_principal_login(value: str, code: str) -> str:
    try:
        return normalize_login(value)
    except (AttributeError, IdentityError) as exc:
        raise LegacyOwnerRepairError(code) from exc


def _normalize_reason(value: str) -> str:
    normalized = value.strip() if isinstance(value, str) else ""
    if (
        not normalized
        or len(normalized) > MAX_REASON_LENGTH
        or any(ord(character) < 32 or ord(character) == 127 for character in normalized)
        or find_secret_violations({"audit_reason": normalized})
    ):
        raise LegacyOwnerRepairError("repair_reason_invalid")
    return normalized


def _normalize_request_id(value: str) -> str:
    normalized = value.strip() if isinstance(value, str) else ""
    if not REQUEST_ID_PATTERN.fullmatch(normalized):
        raise LegacyOwnerRepairError("repair_request_id_invalid")
    return normalized


def _normalize_plan_digest(value: str) -> str:
    normalized = value.strip().lower() if isinstance(value, str) else ""
    if not PLAN_DIGEST_PATTERN.fullmatch(normalized):
        raise LegacyOwnerRepairError("repair_plan_digest_invalid")
    return normalized


def _principal_id_for_login(session: Session, login: str) -> str | None:
    principal = principal_by_login(session, login)
    return principal.id if principal is not None else None


def _resolve_actor(session: Session, login: str) -> Principal:
    principal = principal_by_login(session, login)
    if principal is None or not principal.active:
        raise LegacyOwnerRepairError("repair_actor_inactive")
    if principal.catalog_role != CatalogRole.CATALOG_OWNER:
        raise LegacyOwnerRepairError("repair_actor_unauthorized")
    return principal


def _resolve_target(session: Session, login: str) -> Principal:
    principal = principal_by_login(session, login)
    if principal is None or not principal.active:
        raise LegacyOwnerRepairError("repair_target_inactive")
    return principal


def _lock_remaining_repair_rows(session: Session) -> None:
    """Complete the shared grant-command lock order before planning."""
    list(
        session.scalars(
            select(ObjectGrant)
            .order_by(ObjectGrant.id)
            .with_for_update(of=ObjectGrant)
            .execution_options(populate_existing=True)
        ).all()
    )
    list(
        session.scalars(
            select(CatalogObject)
            .order_by(CatalogObject.id)
            .with_for_update(of=CatalogObject)
            .execution_options(populate_existing=True)
        ).all()
    )


def _catalog_state(session: Session) -> list[dict[str, object]]:
    rows = session.scalars(select(CatalogObject).order_by(CatalogObject.id)).all()
    return [
        {
            "data_json": row.data_json,
            "health": row.health,
            "id": row.id,
            "instance_id": row.instance_id,
            "kind": row.kind,
            "label": row.label,
            "lifecycle": row.lifecycle,
            "provenance_json": row.provenance_json,
            "revision": row.revision,
            "status": row.status,
            "summary": row.summary,
        }
        for row in rows
    ]


def _object_grant_state(session: Session) -> list[dict[str, object]]:
    rows = session.scalars(select(ObjectGrant).order_by(ObjectGrant.id)).all()
    return [
        {
            "created_by_principal_id": row.created_by_principal_id,
            "id": row.id,
            "object_id": row.object_id,
            "principal_id": row.principal_id,
            "role": row.role,
            "scope": row.scope,
        }
        for row in rows
    ]


def _principal_state(session: Session) -> list[dict[str, object]]:
    rows = session.scalars(select(Principal).order_by(Principal.id)).all()
    return [
        {
            "active": row.active,
            "catalog_role": row.catalog_role,
            "id": row.id,
            "login": row.login,
            "revision": row.revision,
        }
        for row in rows
    ]


def _relationship_state(session: Session) -> list[dict[str, object]]:
    rows = session.scalars(select(Relationship).order_by(Relationship.id)).all()
    return [
        {
            "from_ref": row.from_ref,
            "id": row.id,
            "metadata_json": row.metadata_json,
            "relation_type": row.relation_type,
            "to_ref": row.to_ref,
        }
        for row in rows
    ]


def _canonical_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
