from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import delete, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.orm import Session

from blockwart.domain.auth import (
    CatalogRole,
    GrantScope,
    Permission,
    PrincipalContext,
    Role,
    permissions_for_role,
)
from blockwart.domain.relationships import (
    RelationshipIntegrityError,
    canonical_relationship_metadata_json,
    relationship_metadata,
    validate_relationship_collection,
    validate_relationship_metadata,
)
from blockwart.domain.security import redact_secret_values
from blockwart.models import (
    CatalogObject,
    IdempotencyRecord,
    ObjectGrant,
    Principal,
    Relationship,
)
from blockwart.schemas.catalog import CatalogObjectIn, CatalogObjectOut
from blockwart.services.audit import add_audit_event
from blockwart.services.catalog import (
    RevisionConflict,
    create_relationship,
    current_endpoint_descriptors,
    delete_object,
    delete_relationship,
    get_object,
    upsert_object,
)
from blockwart.services.identity import record_security_event
from blockwart.services.policy import PolicySnapshot
from blockwart.services.read_access import ReadAccess

_ETAG_PATTERN = re.compile(r'^"rev-([1-9][0-9]*)"$')
_IDEMPOTENCY_KEY_PATTERN = re.compile(r"^[\x21-\x7e]{16,128}$")
_WRITE_CHANNELS = frozenset({"ui", "api", "mcp"})


class CommandError(RuntimeError):
    """Stable base error for authorized write commands."""


class CommandNotFound(CommandError):
    """A resource is absent or intentionally concealed."""


class CommandAuthorizationDenied(CommandError):
    """The principal lacks the required object permission."""

    def __init__(self, *, object_id: str, permission: Permission) -> None:
        super().__init__("object permission denied")
        self.object_id = object_id
        self.permission = permission


class CommandConflict(CommandError):
    """The requested mutation conflicts with current catalog state."""


class CommandPreconditionRequired(CommandError):
    """The write omitted its required optimistic concurrency precondition."""


class CommandPreconditionFailed(CommandError):
    """The supplied optimistic concurrency precondition is stale."""


class IdempotencyConflict(CommandConflict):
    """An idempotency key was reused with a different operation or payload."""


@dataclass(frozen=True, slots=True)
class WriteContext:
    principal: PrincipalContext
    policy: PolicySnapshot
    channel: str
    request_id: str | None = None

    @classmethod
    def from_read_access(
        cls,
        access: ReadAccess,
        *,
        channel: str,
        request_id: str | None = None,
    ) -> WriteContext:
        if channel not in _WRITE_CHANNELS:
            raise ValueError("unsupported write channel")
        return cls(
            principal=access.principal,
            policy=access.policy,
            channel=channel,
            request_id=request_id,
        )


@dataclass(frozen=True, slots=True)
class ObjectCommandResult:
    catalog_object: CatalogObjectOut
    etag: str
    changed: bool
    replayed: bool = False


@dataclass(frozen=True, slots=True)
class DeleteCommandResult:
    object_id: str
    deleted_revision: int
    changed: bool = True


@dataclass(frozen=True, slots=True)
class RelationshipCommandResult:
    from_ref: str
    relation_type: str
    to_ref: str
    object_id: str
    revision: int
    etag: str
    changed: bool
    metadata: dict[str, object]


def revision_etag(revision: int) -> str:
    if revision < 1:
        raise ValueError("revision must be positive")
    return f'"rev-{revision}"'


def parse_if_match(value: str | None) -> int:
    if value is None:
        raise CommandPreconditionRequired("If-Match is required")
    match = _ETAG_PATTERN.fullmatch(value.strip())
    if match is None:
        raise CommandPreconditionFailed("If-Match must contain one current strong ETag")
    return int(match.group(1))


def update_catalog_object(
    session: Session,
    context: WriteContext,
    *,
    object_id: str,
    payload: CatalogObjectIn,
    expected_revision: int | str | None,
) -> ObjectCommandResult:
    row = _require_permission(
        session,
        context,
        object_id=object_id,
        permission=Permission.WRITE,
    )
    expected_revision = _resolve_expected_revision(expected_revision)
    if payload.id != object_id:
        raise CommandConflict("payload object id does not match the resource")
    if row.revision != expected_revision:
        raise CommandPreconditionFailed("object revision changed")
    before = _object_snapshot(row)
    try:
        upsert_object(
            session,
            payload,
            expected_revision=expected_revision,
            write_audit=False,
        )
    except RevisionConflict as exc:
        raise CommandPreconditionFailed("object revision changed") from exc
    session.flush()
    session.expire(row)
    session.refresh(row)
    changed = row.revision != expected_revision
    result = get_object(session, object_id)
    if result is None:
        raise CommandNotFound("catalog object not found")
    result = result.model_copy(
        update={
            "capabilities": sorted(
                context.policy.permissions_for(object_id),
                key=lambda permission: permission.value,
            )
        }
    )
    if changed:
        after = _object_snapshot(row)
        _write_command_audit(
            session,
            context,
            object_id=object_id,
            action="update",
            old_revision=expected_revision,
            new_revision=row.revision,
            before=before,
            after=after,
            changes=_structured_changes(before, after),
        )
    return ObjectCommandResult(
        catalog_object=result,
        etag=revision_etag(result.revision),
        changed=changed,
    )


def create_child_object(
    session: Session,
    context: WriteContext,
    *,
    parent_id: str,
    payload: CatalogObjectIn,
    idempotency_key: str,
    idempotency_ttl_seconds: int,
    now: datetime | None = None,
) -> ObjectCommandResult:
    timestamp = now or _now()
    parent = _require_permission(
        session,
        context,
        object_id=parent_id,
        permission=Permission.CREATE_CHILD,
    )
    request_payload = {
        "parent_id": parent_id,
        "payload": payload.model_dump(mode="json"),
    }
    record, replay = reserve_idempotency_record(
        session,
        context,
        key=idempotency_key,
        operation_context=f"create_child:{parent_id}",
        request_payload=request_payload,
        ttl_seconds=idempotency_ttl_seconds,
        now=timestamp,
    )
    if replay is not None:
        return ObjectCommandResult(
            catalog_object=CatalogObjectOut.model_validate(replay["catalog_object"]),
            etag=str(replay["etag"]),
            changed=bool(replay["changed"]),
            replayed=True,
        )
    if session.get(CatalogObject, payload.id) is not None:
        raise CommandConflict("catalog object id already exists")

    created = upsert_object(session, payload, write_audit=False)
    child_ref = f"{created.kind}:{created.id}"
    parent_ref = f"{parent.kind}:{parent.id}"
    create_relationship(
        session,
        from_ref=parent_ref,
        relation_type="hosts",
        to_ref=child_ref,
        write_audit=False,
        touch_revisions=False,
    )
    session.add(
        ObjectGrant(
            principal_id=context.principal.id,
            object_id=created.id,
            role=Role.OWNER,
            scope=GrantScope.SELF,
            created_by_principal_id=context.principal.id,
        )
    )
    parent_revision = _bump_object_revision(session, parent.id)
    session.flush()
    result = get_object(session, created.id)
    child_row = session.get(CatalogObject, created.id)
    if result is None or child_row is None:
        raise CommandConflict("created object could not be loaded")
    result = result.model_copy(
        update={
            "capabilities": sorted(
                permissions_for_role(Role.OWNER),
                key=lambda permission: permission.value,
            )
        }
    )
    _write_command_audit(
        session,
        context,
        object_id=created.id,
        action="create",
        old_revision=0,
        new_revision=child_row.revision,
        before=None,
        after=_object_snapshot(child_row),
        changes=[],
        extra={
            "object_ref": child_ref,
            "parent_ref": parent_ref,
            "creator_owner_grant": {
                "principal_id": context.principal.id,
                "role": Role.OWNER,
                "scope": GrantScope.SELF,
            },
            "affected_revisions": {
                parent.id: parent_revision,
            },
        },
    )
    response = {
        "catalog_object": result.model_dump(mode="json"),
        "etag": revision_etag(result.revision),
        "changed": True,
    }
    record.resource_id = result.id
    record.response_json = _canonical_json(response)
    session.flush()
    return ObjectCommandResult(
        catalog_object=result,
        etag=revision_etag(result.revision),
        changed=True,
    )


def create_catalog_root(
    session: Session,
    context: WriteContext,
    *,
    payload: CatalogObjectIn,
    idempotency_key: str,
    idempotency_ttl_seconds: int,
    now: datetime | None = None,
) -> ObjectCommandResult:
    """Atomically create one disconnected top-level catalog root.

    Authorization is resolved from current database state inside the
    transaction: the actor must be active and hold the ``catalog_owner`` role.
    Platform-admin alone is not sufficient, and an active catalog owner needs
    no platform-admin role for this catalog operation. The root and exactly
    one real direct Owner/self grant for the creating principal commit
    together; no placement parent, synthetic relationship, subtree grant,
    wildcard, or sentinel grant is ever created. Catalog-role membership is
    never changed by this catalog write.
    """
    timestamp = now or _now()
    _require_active_catalog_owner(session, context)
    request_payload = {"payload": payload.model_dump(mode="json")}
    record, replay = reserve_idempotency_record(
        session,
        context,
        key=idempotency_key,
        operation_context="create_root",
        request_payload=request_payload,
        ttl_seconds=idempotency_ttl_seconds,
        now=timestamp,
    )
    if replay is not None:
        return ObjectCommandResult(
            catalog_object=CatalogObjectOut.model_validate(replay["catalog_object"]),
            etag=str(replay["etag"]),
            changed=bool(replay["changed"]),
            replayed=True,
        )
    if session.get(CatalogObject, payload.id) is not None:
        raise CommandConflict("catalog object id already exists")

    created = upsert_object(session, payload, write_audit=False)
    object_ref = f"{created.kind}:{created.id}"
    session.add(
        ObjectGrant(
            principal_id=context.principal.id,
            object_id=created.id,
            role=Role.OWNER,
            scope=GrantScope.SELF,
            created_by_principal_id=context.principal.id,
        )
    )
    session.flush()
    result = get_object(session, created.id)
    root_row = session.get(CatalogObject, created.id)
    if result is None or root_row is None:
        raise CommandConflict("created object could not be loaded")
    result = result.model_copy(
        update={
            "capabilities": sorted(
                permissions_for_role(Role.OWNER),
                key=lambda permission: permission.value,
            )
        }
    )
    _write_command_audit(
        session,
        context,
        object_id=created.id,
        action="create_root",
        old_revision=0,
        new_revision=root_row.revision,
        before=None,
        after=_object_snapshot(root_row),
        changes=[],
        extra={
            "object_ref": object_ref,
            "parent_ref": None,
            "creator_owner_grant": {
                "principal_id": context.principal.id,
                "role": Role.OWNER,
                "scope": GrantScope.SELF,
            },
            "affected_revisions": {},
        },
    )
    response = {
        "catalog_object": result.model_dump(mode="json"),
        "etag": revision_etag(result.revision),
        "changed": True,
    }
    record.resource_id = result.id
    record.response_json = _canonical_json(response)
    session.flush()
    return ObjectCommandResult(
        catalog_object=result,
        etag=revision_etag(result.revision),
        changed=True,
    )


def create_attached_device(
    session: Session,
    context: WriteContext,
    *,
    parent_id: str,
    payload: CatalogObjectIn,
    metadata: Mapping[str, object] | None,
    idempotency_key: str,
    idempotency_ttl_seconds: int,
    now: datetime | None = None,
) -> ObjectCommandResult:
    """Atomically create a device, attach it to an existing upstream endpoint.

    Requires ``create_child`` on the upstream parent. The device is created
    with a direct Owner self-grant and an ``attached_to`` relationship in a
    single transaction. Relationship metadata is validated by the shared domain
    layer and covered by the idempotency record.
    """
    timestamp = now or _now()
    parent = _require_permission(
        session,
        context,
        object_id=parent_id,
        permission=Permission.CREATE_CHILD,
    )
    if payload.kind != "device":
        raise CommandConflict("attached device creation requires kind=device")
    canonical_metadata = _canonical_relationship_metadata("attached_to", metadata)
    request_payload = {
        "parent_id": parent_id,
        "payload": payload.model_dump(mode="json"),
        "metadata": canonical_metadata,
    }
    record, replay = reserve_idempotency_record(
        session,
        context,
        key=idempotency_key,
        operation_context=f"create_attached_device:{parent_id}",
        request_payload=request_payload,
        ttl_seconds=idempotency_ttl_seconds,
        now=timestamp,
    )
    if replay is not None:
        return ObjectCommandResult(
            catalog_object=CatalogObjectOut.model_validate(replay["catalog_object"]),
            etag=str(replay["etag"]),
            changed=bool(replay["changed"]),
            replayed=True,
        )
    if session.get(CatalogObject, payload.id) is not None:
        raise CommandConflict("catalog object id already exists")

    created = upsert_object(session, payload, write_audit=False)
    device_ref = f"{created.kind}:{created.id}"
    parent_ref = f"{parent.kind}:{parent.id}"
    try:
        create_relationship(
            session,
            from_ref=device_ref,
            relation_type="attached_to",
            to_ref=parent_ref,
            metadata=canonical_metadata,
            write_audit=False,
            touch_revisions=False,
        )
    except RelationshipIntegrityError as exc:
        raise CommandConflict(str(exc)) from exc
    session.add(
        ObjectGrant(
            principal_id=context.principal.id,
            object_id=created.id,
            role=Role.OWNER,
            scope=GrantScope.SELF,
            created_by_principal_id=context.principal.id,
        )
    )
    parent_revision = _bump_object_revision(session, parent.id)
    session.flush()
    result = get_object(session, created.id)
    child_row = session.get(CatalogObject, created.id)
    if result is None or child_row is None:
        raise CommandConflict("created object could not be loaded")
    result = result.model_copy(
        update={
            "capabilities": sorted(
                permissions_for_role(Role.OWNER),
                key=lambda permission: permission.value,
            )
        }
    )
    _write_command_audit(
        session,
        context,
        object_id=created.id,
        action="create_attached_device",
        old_revision=0,
        new_revision=child_row.revision,
        before=None,
        after=_object_snapshot(child_row),
        changes=[],
        extra={
            "object_ref": device_ref,
            "parent_ref": parent_ref,
            "relation_type": "attached_to",
            "metadata": canonical_metadata,
            "creator_owner_grant": {
                "principal_id": context.principal.id,
                "role": Role.OWNER,
                "scope": GrantScope.SELF,
            },
            "affected_revisions": {
                parent.id: parent_revision,
            },
        },
    )
    response = {
        "catalog_object": result.model_dump(mode="json"),
        "etag": revision_etag(result.revision),
        "changed": True,
    }
    record.resource_id = result.id
    record.response_json = _canonical_json(response)
    session.flush()
    return ObjectCommandResult(
        catalog_object=result,
        etag=revision_etag(result.revision),
        changed=True,
    )


def delete_catalog_object(
    session: Session,
    context: WriteContext,
    *,
    object_id: str,
    expected_revision: int | str | None,
) -> DeleteCommandResult:
    row = _require_permission(
        session,
        context,
        object_id=object_id,
        permission=Permission.DELETE,
    )
    expected_revision = _resolve_expected_revision(expected_revision)
    if row.revision != expected_revision:
        raise CommandPreconditionFailed("object revision changed")
    before = _object_snapshot(row)
    claimed_revision = _claim_object_revision(
        session,
        object_id=object_id,
        expected_revision=expected_revision,
    )
    session.execute(delete(ObjectGrant).where(ObjectGrant.object_id == object_id))
    if not delete_object(session, object_id, write_audit=False):
        raise CommandNotFound("catalog object not found")
    _write_command_audit(
        session,
        context,
        object_id=object_id,
        action="delete",
        old_revision=expected_revision,
        new_revision=claimed_revision,
        before=before,
        after=None,
        changes=[],
        extra={"object_ref": f"{row.kind}:{row.id}"},
    )
    return DeleteCommandResult(
        object_id=object_id,
        deleted_revision=claimed_revision,
    )


def create_object_relationship(
    session: Session,
    context: WriteContext,
    *,
    object_id: str,
    from_ref: str,
    relation_type: str,
    to_ref: str,
    expected_revision: int | str | None,
    metadata: Mapping[str, object] | None = None,
) -> RelationshipCommandResult:
    target, peer, expected_revision = _relationship_command_objects(
        session,
        context,
        object_id=object_id,
        from_ref=from_ref,
        to_ref=to_ref,
        expected_revision=expected_revision,
    )
    canonical_metadata = _canonical_relationship_metadata(relation_type, metadata)
    existing = session.scalar(
        select(Relationship).where(
            Relationship.from_ref == from_ref,
            Relationship.relation_type == relation_type,
            Relationship.to_ref == to_ref,
        )
    )
    if existing is not None:
        existing_metadata_json = canonical_relationship_metadata_json(
            relation_type,
            relationship_metadata(existing, relation_type=relation_type),
        )
        new_metadata_json = canonical_relationship_metadata_json(
            relation_type,
            canonical_metadata,
        )
        if existing_metadata_json == new_metadata_json:
            return _relationship_result(
                target,
                from_ref=from_ref,
                relation_type=relation_type,
                to_ref=to_ref,
                changed=False,
                metadata=canonical_metadata,
            )
        return _replace_relationship_metadata(
            session,
            context,
            target=target,
            peer=peer,
            relationship=existing,
            relation_type=relation_type,
            canonical_metadata=canonical_metadata,
            expected_revision=expected_revision,
        )
    old_revision = target.revision
    new_revision = _claim_object_revision(
        session,
        object_id=target.id,
        expected_revision=expected_revision,
    )
    try:
        create_relationship(
            session,
            from_ref=from_ref,
            relation_type=relation_type,
            to_ref=to_ref,
            metadata=canonical_metadata,
            write_audit=False,
            touch_revisions=False,
        )
    except RelationshipIntegrityError as exc:
        raise CommandConflict(str(exc)) from exc
    peer_revision = _bump_object_revision(session, peer.id)
    _write_command_audit(
        session,
        context,
        object_id=target.id,
        action="relationship_create",
        old_revision=old_revision,
        new_revision=new_revision,
        before=None,
        after={
            "from_ref": from_ref,
            "relation_type": relation_type,
            "to_ref": to_ref,
            "metadata": canonical_metadata,
        },
        changes=[],
        extra={
            "from_ref": from_ref,
            "relation_type": relation_type,
            "to_ref": to_ref,
            "metadata": canonical_metadata,
            "affected_revisions": {peer.id: peer_revision},
        },
    )
    target.revision = new_revision
    return _relationship_result(
        target,
        from_ref=from_ref,
        relation_type=relation_type,
        to_ref=to_ref,
        changed=True,
        metadata=canonical_metadata,
    )


def _replace_relationship_metadata(
    session: Session,
    context: WriteContext,
    *,
    target: CatalogObject,
    peer: CatalogObject,
    relationship: Relationship,
    relation_type: str,
    canonical_metadata: dict[str, object],
    expected_revision: int,
) -> RelationshipCommandResult:
    """Idempotent relationship metadata replacement.

    The caller must ensure the relationship row already exists. If the canonical
    metadata equals the stored metadata, this path must not be reached (handled
    as a no-op by ``create_object_relationship``).
    """
    old_metadata = relationship_metadata(relationship, relation_type=relation_type)
    replacement_json = canonical_relationship_metadata_json(
        relation_type,
        canonical_metadata,
    )
    old_revision = target.revision
    new_revision = _claim_object_revision(
        session,
        object_id=target.id,
        expected_revision=expected_revision,
    )
    relationship_rows: list[Relationship | dict[str, object]] = list(
        session.scalars(
            select(Relationship).order_by(
                Relationship.id,
                Relationship.from_ref,
                Relationship.relation_type,
                Relationship.to_ref,
            )
        ).all()
    )
    candidate_rows: list[Relationship | dict[str, object]] = [
        {
            "from_ref": row.from_ref,
            "relation_type": row.relation_type,
            "to_ref": row.to_ref,
            "metadata_json": replacement_json,
        }
        if row.id == relationship.id
        else row
        for row in relationship_rows
    ]
    validate_relationship_collection(
        candidate_rows,
        current_endpoint_descriptors(session),
    )
    relationship.metadata_json = replacement_json
    peer_revision = _bump_object_revision(session, peer.id)
    _write_command_audit(
        session,
        context,
        object_id=target.id,
        action="relationship_metadata_replace",
        old_revision=old_revision,
        new_revision=new_revision,
        before={
            "from_ref": relationship.from_ref,
            "relation_type": relation_type,
            "to_ref": relationship.to_ref,
            "metadata": old_metadata,
        },
        after={
            "from_ref": relationship.from_ref,
            "relation_type": relation_type,
            "to_ref": relationship.to_ref,
            "metadata": canonical_metadata,
        },
        changes=[],
        extra={
            "from_ref": relationship.from_ref,
            "relation_type": relation_type,
            "to_ref": relationship.to_ref,
            "metadata": canonical_metadata,
            "affected_revisions": {peer.id: peer_revision},
        },
    )
    target.revision = new_revision
    return _relationship_result(
        target,
        from_ref=relationship.from_ref,
        relation_type=relation_type,
        to_ref=relationship.to_ref,
        changed=True,
        metadata=canonical_metadata,
    )


def delete_object_relationship(
    session: Session,
    context: WriteContext,
    *,
    object_id: str,
    from_ref: str,
    relation_type: str,
    to_ref: str,
    expected_revision: int | str | None,
) -> RelationshipCommandResult:
    target, peer, expected_revision = _relationship_command_objects(
        session,
        context,
        object_id=object_id,
        from_ref=from_ref,
        to_ref=to_ref,
        expected_revision=expected_revision,
    )
    relationship = session.scalar(
        select(Relationship).where(
            Relationship.from_ref == from_ref,
            Relationship.relation_type == relation_type,
            Relationship.to_ref == to_ref,
        )
    )
    if relationship is None:
        raise CommandNotFound("relationship not found")
    canonical_metadata = relationship_metadata(
        relationship,
        relation_type=relation_type,
    )
    old_revision = target.revision
    new_revision = _claim_object_revision(
        session,
        object_id=target.id,
        expected_revision=expected_revision,
    )
    if not delete_relationship(
        session,
        relationship.id,
        write_audit=False,
        touch_revisions=False,
    ):
        raise CommandNotFound("relationship not found")
    peer_revision = _bump_object_revision(session, peer.id)
    _write_command_audit(
        session,
        context,
        object_id=target.id,
        action="relationship_delete",
        old_revision=old_revision,
        new_revision=new_revision,
        before={
            "from_ref": from_ref,
            "relation_type": relation_type,
            "to_ref": to_ref,
            "metadata": canonical_metadata,
        },
        after=None,
        changes=[],
        extra={
            "from_ref": from_ref,
            "relation_type": relation_type,
            "to_ref": to_ref,
            "metadata": canonical_metadata,
            "affected_revisions": {peer.id: peer_revision},
        },
    )
    target.revision = new_revision
    return _relationship_result(
        target,
        from_ref=from_ref,
        relation_type=relation_type,
        to_ref=to_ref,
        changed=True,
        metadata=canonical_metadata,
    )


def record_command_denial(
    session: Session,
    context: WriteContext,
    error: CommandAuthorizationDenied,
) -> None:
    principal_id = (
        context.principal.id
        if session.get(Principal, context.principal.id) is not None
        else None
    )
    record_security_event(
        session,
        event_type="object_command_authorization",
        outcome="denied",
        channel=context.channel,
        principal_id=principal_id,
        request_id=context.request_id,
        details={
            "object_id": error.object_id,
            "permission": error.permission,
            "principal_id": context.principal.id,
        },
    )


def authorize_object_command(
    session: Session,
    context: WriteContext,
    *,
    object_id: str,
    permission: Permission,
) -> None:
    """Fail closed before a UI parses object-specific mutation fields."""
    _require_permission(
        session,
        context,
        object_id=object_id,
        permission=permission,
    )


def _require_permission(
    session: Session,
    context: WriteContext,
    *,
    object_id: str,
    permission: Permission,
) -> CatalogObject:
    row = session.get(CatalogObject, object_id)
    if row is None or not context.policy.can(Permission.DISCOVER, object_id):
        raise CommandNotFound("catalog object not found")
    if not context.policy.can(permission, object_id):
        raise CommandAuthorizationDenied(
            object_id=object_id,
            permission=permission,
        )
    return row


def _require_active_catalog_owner(session: Session, context: WriteContext) -> None:
    """Require the actor to be an active catalog owner from current DB state.

    The check re-reads the principal row inside the command transaction so a
    stale access snapshot cannot satisfy the gate after a concurrent role or
    activation change. Platform-admin alone is denied; the catalog-owner axis
    is independent. The trusted channel must also match the token audience:
    browser UI actors carry no service-token audience, while api/mcp channel
    actors must hold the matching audience. One indistinguishable denial is
    raised for every missing property.
    """
    if context.channel == "ui":
        trusted_origin = context.principal.service_token_audience is None
    else:
        trusted_origin = context.principal.service_token_audience == context.channel
    actor = session.get(Principal, context.principal.id)
    if (
        not trusted_origin
        or actor is None
        or not actor.active
        or actor.catalog_role != CatalogRole.CATALOG_OWNER
    ):
        raise CommandAuthorizationDenied(
            object_id="<catalog-root>",
            permission=Permission.CREATE_CHILD,
        )


def _relationship_command_objects(
    session: Session,
    context: WriteContext,
    *,
    object_id: str,
    from_ref: str,
    to_ref: str,
    expected_revision: int | str | None,
) -> tuple[CatalogObject, CatalogObject, int]:
    target = _require_permission(
        session,
        context,
        object_id=object_id,
        permission=Permission.WRITE,
    )
    expected_revision = _resolve_expected_revision(expected_revision)
    target_ref = f"{target.kind}:{target.id}"
    if target_ref not in {from_ref, to_ref}:
        raise CommandConflict("relationship does not involve the target object")
    peer_ref = to_ref if from_ref == target_ref else from_ref
    if ":" not in peer_ref:
        raise CommandConflict("relationship reference is invalid")
    peer_kind, peer_id = peer_ref.split(":", 1)
    peer = session.get(CatalogObject, peer_id)
    if (
        peer is None
        or peer.kind != peer_kind
        or not context.policy.can(Permission.DISCOVER, peer_id)
    ):
        raise CommandNotFound("relationship target not found")
    if target.revision != expected_revision:
        raise CommandPreconditionFailed("object revision changed")
    return target, peer, expected_revision


def _resolve_expected_revision(value: int | str | None) -> int:
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
            updated_at=_now(),
        )
        .execution_options(synchronize_session=False)
    )
    if result.rowcount != 1:
        raise CommandPreconditionFailed("object revision changed")
    return expected_revision + 1


def _bump_object_revision(session: Session, object_id: str) -> int:
    row = session.get(CatalogObject, object_id)
    session.execute(
        update(CatalogObject)
        .where(CatalogObject.id == object_id)
        .values(
            revision=CatalogObject.revision + 1,
            updated_at=_now(),
        )
        .execution_options(synchronize_session=False)
    )
    if row is not None:
        session.expire(row, attribute_names=["revision", "updated_at"])
    revision = session.scalar(
        select(CatalogObject.revision).where(CatalogObject.id == object_id)
    )
    if revision is None:
        raise CommandNotFound("catalog object not found")
    return int(revision)


def reserve_idempotency_record(
    session: Session,
    context: WriteContext,
    *,
    key: str,
    operation_context: str,
    request_payload: dict[str, object],
    ttl_seconds: int,
    now: datetime,
) -> tuple[IdempotencyRecord, dict[str, object] | None]:
    if not _IDEMPOTENCY_KEY_PATTERN.fullmatch(key):
        raise CommandConflict(
            "Idempotency-Key must contain 16 to 128 visible ASCII characters"
        )
    if ttl_seconds < 300 or ttl_seconds > 604800:
        raise ValueError("idempotency TTL is outside the supported range")
    key_hash = hashlib.sha256(key.encode("utf-8")).hexdigest()
    request_hash = hashlib.sha256(
        _canonical_json(request_payload).encode("utf-8")
    ).hexdigest()
    existing = session.scalar(
        select(IdempotencyRecord).where(
            IdempotencyRecord.principal_id == context.principal.id,
            IdempotencyRecord.key_hash == key_hash,
        )
    )
    if existing is not None and existing.expires_at <= now:
        session.delete(existing)
        session.flush()
        existing = None
    if existing is None:
        inserted = session.execute(
            (sqlite_insert if session.bind.dialect.name == "sqlite" else pg_insert)(IdempotencyRecord)  # noqa: E501
            .values(
                principal_id=context.principal.id,
                key_hash=key_hash,
                operation_context=operation_context,
                request_hash=request_hash,
                created_at=now,
                expires_at=now + timedelta(seconds=ttl_seconds),
            )
            .on_conflict_do_nothing(
                index_elements=["principal_id", "key_hash"],
            )
        )
        existing = session.scalar(
            select(IdempotencyRecord).where(
                IdempotencyRecord.principal_id == context.principal.id,
                IdempotencyRecord.key_hash == key_hash,
            )
        )
        if existing is None:
            raise CommandConflict("idempotency key is currently in use")
        if inserted.rowcount == 1:
            return existing, None
    assert existing is not None
    if (
        existing.operation_context != operation_context
        or existing.request_hash != request_hash
    ):
        raise IdempotencyConflict(
            "Idempotency-Key was already used for a different request"
        )
    if existing.response_json is None:
        raise CommandConflict("idempotent request is still being processed")
    try:
        response = json.loads(existing.response_json)
    except json.JSONDecodeError as exc:
        raise CommandConflict("stored idempotency response is invalid") from exc
    if not isinstance(response, dict):
        raise CommandConflict("stored idempotency response is invalid")
    return existing, response


def _write_command_audit(
    session: Session,
    context: WriteContext,
    *,
    object_id: str,
    action: str,
    old_revision: int,
    new_revision: int,
    before: dict[str, object] | None,
    after: dict[str, object] | None,
    changes: list[dict[str, object]],
    extra: dict[str, object] | None = None,
) -> None:
    add_audit_event(
        session,
        object_id=object_id,
        action=action,
        actor=context.principal.id,
        details={
            "principal_id": context.principal.id,
            "principal_login": context.principal.login,
            "channel": context.channel,
            "request_id": context.request_id,
            "old_revision": old_revision,
            "new_revision": new_revision,
            "before": before,
            "after": after,
            "changes": changes,
            **dict(extra or {}),
        },
    )
    session.flush()


def _object_snapshot(row: CatalogObject) -> dict[str, object]:
    try:
        data = json.loads(row.data_json)
    except json.JSONDecodeError:
        data = {"record_state": "corrupt"}
    snapshot = {
        "id": row.id,
        "kind": row.kind,
        "label": row.label,
        "status": row.status,
        "lifecycle": row.lifecycle,
        "health": row.health,
        "summary": row.summary,
        "data": data,
    }
    redacted = redact_secret_values(snapshot)
    return redacted if isinstance(redacted, dict) else {}


def _structured_changes(
    before: dict[str, object],
    after: dict[str, object],
) -> list[dict[str, object]]:
    changes: list[dict[str, object]] = []
    for field in sorted(set(before) | set(after)):
        old_value = before.get(field)
        new_value = after.get(field)
        if old_value == new_value:
            continue
        if field == "data" and isinstance(old_value, dict) and isinstance(new_value, dict):
            changes.extend(_nested_changes(old_value, new_value))
            continue
        changes.append(_change(field, old_value, new_value))
    return changes


def _nested_changes(
    before: dict[str, object],
    after: dict[str, object],
    path: str = "",
) -> list[dict[str, object]]:
    changes: list[dict[str, object]] = []
    for key in sorted(set(before) | set(after)):
        field = f"{path}.{key}" if path else key
        old_value = before.get(key)
        new_value = after.get(key)
        if old_value == new_value:
            continue
        if isinstance(old_value, dict) and (
            isinstance(new_value, dict) or new_value is None
        ):
            changes.extend(
                _nested_changes(
                    old_value,
                    new_value if isinstance(new_value, dict) else {},
                    field,
                )
            )
        elif old_value is None and isinstance(new_value, dict):
            changes.extend(_nested_changes({}, new_value, field))
        else:
            changes.append(_change(field, old_value, new_value))
    return changes


def _change(
    field: str,
    before: object,
    after: object,
) -> dict[str, object]:
    scalar = (
        before is None or isinstance(before, str | int | float | bool)
    ) and (
        after is None or isinstance(after, str | int | float | bool)
    )
    return {
        "field": field,
        "before": before,
        "after": after,
        "old": "" if before is None else str(before) if scalar else "",
        "new": "" if after is None else str(after) if scalar else "",
        "value_change": scalar,
    }


def _relationship_result(
    target: CatalogObject,
    *,
    from_ref: str,
    relation_type: str,
    to_ref: str,
    changed: bool,
    metadata: dict[str, object],
) -> RelationshipCommandResult:
    return RelationshipCommandResult(
        from_ref=from_ref,
        relation_type=relation_type,
        to_ref=to_ref,
        object_id=target.id,
        revision=target.revision,
        etag=revision_etag(target.revision),
        changed=changed,
        metadata=metadata,
    )


def _canonical_json(value: object) -> str:
    return json.dumps(
        value,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    )


def _canonical_relationship_metadata(
    relation_type: str,
    metadata: Mapping[str, object] | None,
) -> dict[str, object]:
    """Validate and return canonical dict for relationship metadata.

    Accepts ``None``/``{}`` and returns an empty dict so the command layer never
    stores ``null`` metadata on a relationship row.
    """
    if metadata is None:
        return {}
    return validate_relationship_metadata(relation_type, metadata)


def _now() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)
