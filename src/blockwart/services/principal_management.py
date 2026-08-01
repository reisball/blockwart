from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime, timedelta

from sqlalchemy import func, select, update
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.orm import Session

from blockwart.domain.auth import (
    GrantScope,
    Permission,
    PlatformRole,
    PrincipalType,
    Role,
)
from blockwart.domain.timestamps import format_rfc3339_utc
from blockwart.models import (
    BrowserSession,
    CatalogObject,
    IdempotencyRecord,
    ObjectGrant,
    Principal,
    ServiceToken,
)
from blockwart.services.access import (
    ensure_principal_deactivation_preserves_owner_coverage,
)
from blockwart.services.commands import (
    WriteContext,
    parse_if_match,
    revision_etag,
)
from blockwart.services.grant_management import (
    GrantCommandResult,
    create_managed_grant,
    revoke_managed_grant,
    update_managed_grant,
)
from blockwart.services.identity import (
    IdentityError,
    IssuedServiceToken,
    authenticate_password,
    create_human_principal,
    create_service_account,
    issue_service_token,
    normalize_display_name,
    record_security_event,
    revoke_all_browser_sessions,
    revoke_service_token,
    rotate_service_token,
    set_human_password,
    utc_now,
)
from blockwart.services.pagination import paginate_items
from blockwart.services.policy import policy_for_principal
from blockwart.services.read_access import ReadAccess


class PrincipalManagementError(RuntimeError):
    """Stable base error for platform identity administration."""


class PlatformAdminDenied(PrincipalManagementError):
    """The actor is not an active platform administrator."""


class PlatformAdminReauthenticationDenied(PlatformAdminDenied):
    """A platform administrator failed the required credential check."""

    def __init__(
        self,
        message: str,
        *,
        principal_id: str,
        channel: str,
        request_id: str | None,
    ) -> None:
        super().__init__(message)
        self.principal_id = principal_id
        self.channel = channel
        self.request_id = request_id


class ManagedPrincipalNotFound(PrincipalManagementError):
    """The requested principal does not exist."""


class ManagedPrincipalConflict(PrincipalManagementError):
    """The requested mutation conflicts with current identity state."""


class ManagedPrincipalPreconditionRequired(PrincipalManagementError):
    """A principal mutation omitted its optimistic concurrency precondition."""


class ManagedPrincipalPreconditionFailed(PrincipalManagementError):
    """A principal mutation used a stale optimistic concurrency precondition."""


@dataclass(frozen=True, slots=True)
class PrincipalAdminSummary:
    id: str
    principal_type: PrincipalType
    login: str
    display_name: str
    active: bool
    platform_role: PlatformRole | None
    revision: int
    etag: str
    created_at: str
    updated_at: str
    last_used_at: str | None


@dataclass(frozen=True, slots=True)
class PrincipalTokenView:
    id: str
    name: str
    token_prefix: str
    active: bool
    expires_at: str | None
    revoked_at: str | None
    rotated_at: str | None
    created_at: str
    last_used_at: str | None


@dataclass(frozen=True, slots=True)
class DirectPrincipalGrantView:
    grant_id: int
    object_id: str
    object_kind: str
    object_label: str
    object_revision: int
    object_etag: str
    role: Role
    scope: GrantScope
    created_at: str
    updated_at: str


@dataclass(frozen=True, slots=True)
class PrincipalGrantSourceView:
    grant_id: int
    anchor_object_id: str
    anchor_object_kind: str
    anchor_object_label: str
    role: Role
    scope: GrantScope
    direct: bool


@dataclass(frozen=True, slots=True)
class EffectivePrincipalGrantView:
    object_id: str
    object_kind: str
    object_label: str
    permissions: tuple[Permission, ...]
    sources: tuple[PrincipalGrantSourceView, ...]


@dataclass(frozen=True, slots=True)
class PrincipalAdminDetail:
    principal: PrincipalAdminSummary
    direct_grants: tuple[DirectPrincipalGrantView, ...]
    effective_access: tuple[EffectivePrincipalGrantView, ...]
    service_tokens: tuple[PrincipalTokenView, ...]


@dataclass(frozen=True, slots=True)
class PrincipalAdminPage:
    items: tuple[PrincipalAdminSummary, ...]
    next_cursor: str | None


@dataclass(frozen=True, slots=True)
class PrincipalMutationResult:
    principal: PrincipalAdminSummary
    changed: bool


@dataclass(frozen=True, slots=True)
class PrincipalCredentialResult:
    principal: PrincipalAdminSummary
    changed: bool
    issued_token: IssuedServiceToken | None = None


_IDEMPOTENCY_KEY_PATTERN = re.compile(r"^[\x21-\x7e]{16,128}$")


def require_platform_admin(access: ReadAccess) -> None:
    if not access.principal.is_admin:
        raise PlatformAdminDenied("platform administrator permission required")


def reauthenticate_platform_admin(
    session: Session,
    access: ReadAccess,
    *,
    password: str,
    channel: str,
    request_id: str | None = None,
) -> None:
    require_platform_admin(access)
    _reauthenticate_human_admin(
        session,
        access,
        password=password,
        channel=channel,
        request_id=request_id,
    )


def record_failed_platform_admin_reauthentication(
    session: Session,
    denial: PlatformAdminReauthenticationDenied,
) -> None:
    record_security_event(
        session,
        event_type="platform_admin_reauthentication",
        outcome="failure",
        channel=denial.channel,
        principal_id=denial.principal_id,
        request_id=denial.request_id,
        details={"reason": "invalid_credentials"},
    )


def query_principals(
    session: Session,
    access: ReadAccess,
    *,
    query: str | None = None,
    principal_type: PrincipalType | str | None = None,
    active: bool | None = None,
    limit: int = 100,
) -> tuple[PrincipalAdminSummary, ...]:
    return query_principal_page(
        session,
        access,
        query=query,
        principal_type=principal_type,
        active=active,
        limit=limit,
        cursor=None,
    ).items


def query_principal_page(
    session: Session,
    access: ReadAccess,
    *,
    query: str | None = None,
    principal_type: PrincipalType | str | None = None,
    active: bool | None = None,
    limit: int = 100,
    cursor: str | None = None,
) -> PrincipalAdminPage:
    require_platform_admin(access)
    if limit < 1 or limit > 200:
        raise ManagedPrincipalConflict("principal limit must be between 1 and 200")
    statement = select(Principal)
    normalized_query = " ".join((query or "").split())
    if normalized_query:
        if len(normalized_query) > 100:
            raise ManagedPrincipalConflict("principal query is too long")
        folded = normalized_query.casefold()
        statement = statement.where(
            func.lower(Principal.login).contains(folded, autoescape=True)
            | func.lower(Principal.display_name).contains(folded, autoescape=True)
        )
    resolved_type = PrincipalType(principal_type) if principal_type is not None else None
    if resolved_type is not None:
        statement = statement.where(
            Principal.principal_type == resolved_type
        )
    if active is not None:
        statement = statement.where(Principal.active.is_(active))
    rows = session.scalars(statement).all()
    last_used = _last_used_by_principal(session, {row.id for row in rows})
    summaries = tuple(
        _summary(row, last_used_at=last_used.get(row.id))
        for row in rows
    )
    page = paginate_items(
        summaries,
        key=lambda item: (item.login.casefold(), item.id),
        limit=limit,
        resource="admin/principals",
        sort="login",
        direction="asc",
        query={
            "actor_principal_id": access.principal.id,
            "active": active,
            "principal_type": resolved_type.value if resolved_type is not None else None,
            "q": normalized_query.casefold() if normalized_query else None,
        },
        cursor=cursor,
        include_total=False,
    )
    return PrincipalAdminPage(
        items=tuple(page.items),
        next_cursor=page.next_cursor,
    )


def query_principal_detail(
    session: Session,
    access: ReadAccess,
    *,
    principal_id: str,
) -> PrincipalAdminDetail:
    require_platform_admin(access)
    principal = session.get(Principal, principal_id)
    if principal is None:
        raise ManagedPrincipalNotFound("principal not found")

    manageable_ids = access.policy.authorized_ids(Permission.MANAGE_ACCESS)
    visible_ids = access.policy.authorized_ids(Permission.DISCOVER)
    objects = {
        row.id: row
        for row in session.scalars(
            select(CatalogObject).where(CatalogObject.id.in_(manageable_ids))
        ).all()
    } if manageable_ids else {}
    direct_rows = session.scalars(
        select(ObjectGrant)
        .where(
            ObjectGrant.principal_id == principal.id,
            ObjectGrant.object_id.in_(manageable_ids),
        )
        .order_by(ObjectGrant.object_id, ObjectGrant.id)
    ).all() if manageable_ids else []
    direct_grants = tuple(
        DirectPrincipalGrantView(
            grant_id=grant.id,
            object_id=grant.object_id,
            object_kind=objects[grant.object_id].kind,
            object_label=objects[grant.object_id].label,
            object_revision=objects[grant.object_id].revision,
            object_etag=revision_etag(objects[grant.object_id].revision),
            role=Role(grant.role),
            scope=GrantScope(grant.scope),
            created_at=format_rfc3339_utc(grant.created_at),
            updated_at=format_rfc3339_utc(grant.updated_at),
        )
        for grant in direct_rows
    )

    target_policy = policy_for_principal(session, principal.id)
    visible_anchors = {
        row.id: row
        for row in session.scalars(
            select(CatalogObject).where(CatalogObject.id.in_(visible_ids))
        ).all()
    } if visible_ids else {}
    effective_access: list[EffectivePrincipalGrantView] = []
    for object_id in sorted(manageable_ids):
        object_row = objects.get(object_id)
        permissions = target_policy.permissions_for(object_id)
        if object_row is None or not permissions:
            continue
        sources = []
        for source in target_policy.grants_for(object_id):
            anchor = visible_anchors.get(source.anchor_object_id)
            if anchor is None:
                continue
            sources.append(
                PrincipalGrantSourceView(
                    grant_id=source.grant_id,
                    anchor_object_id=anchor.id,
                    anchor_object_kind=anchor.kind,
                    anchor_object_label=anchor.label,
                    role=source.role,
                    scope=source.scope,
                    direct=anchor.id == object_id,
                )
            )
        effective_access.append(
            EffectivePrincipalGrantView(
                object_id=object_row.id,
                object_kind=object_row.kind,
                object_label=object_row.label,
                permissions=tuple(
                    permission for permission in Permission if permission in permissions
                ),
                sources=tuple(
                    sorted(
                        sources,
                        key=lambda item: (
                            not item.direct,
                            item.anchor_object_id,
                            item.grant_id,
                        ),
                    )
                ),
            )
        )

    tokens = session.scalars(
        select(ServiceToken)
        .where(ServiceToken.principal_id == principal.id)
        .order_by(func.lower(ServiceToken.name), ServiceToken.id)
    ).all()
    last_used = _last_used_by_principal(session, {principal.id}).get(principal.id)
    return PrincipalAdminDetail(
        principal=_summary(principal, last_used_at=last_used),
        direct_grants=direct_grants,
        effective_access=tuple(effective_access),
        service_tokens=tuple(_token_view(row) for row in tokens),
    )


def create_managed_principal_grant(
    session: Session,
    context: WriteContext,
    *,
    principal_id: str,
    object_id: str,
    role: Role | str,
    scope: GrantScope | str,
    expected_revision: int | str | None,
) -> GrantCommandResult:
    return create_managed_grant(
        session,
        context,
        object_id=object_id,
        principal_id=principal_id,
        role=role,
        scope=scope,
        expected_revision=expected_revision,
    )


def update_managed_principal_grant(
    session: Session,
    context: WriteContext,
    *,
    principal_id: str,
    object_id: str,
    grant_id: int,
    role: Role | str,
    scope: GrantScope | str,
    expected_revision: int | str | None,
) -> GrantCommandResult:
    return update_managed_grant(
        session,
        context,
        object_id=object_id,
        grant_id=grant_id,
        role=role,
        scope=scope,
        expected_revision=expected_revision,
        expected_principal_id=principal_id,
    )


def revoke_managed_principal_grant(
    session: Session,
    context: WriteContext,
    *,
    principal_id: str,
    object_id: str,
    grant_id: int,
    expected_revision: int | str | None,
) -> GrantCommandResult:
    return revoke_managed_grant(
        session,
        context,
        object_id=object_id,
        grant_id=grant_id,
        expected_revision=expected_revision,
        expected_principal_id=principal_id,
    )


def create_managed_principal(
    session: Session,
    access: ReadAccess,
    *,
    principal_type: PrincipalType | str,
    login: str,
    display_name: str,
    password: str | None = None,
    platform_role: PlatformRole | str | None = None,
    channel: str,
    request_id: str | None = None,
) -> PrincipalMutationResult:
    require_platform_admin(access)
    resolved_type = PrincipalType(principal_type)
    try:
        if resolved_type == PrincipalType.HUMAN:
            if password is None:
                raise ManagedPrincipalConflict("initial password is required")
            created = create_human_principal(
                session,
                login=login,
                display_name=display_name,
                password=password,
                platform_role=platform_role,
            )
        else:
            if password is not None:
                raise ManagedPrincipalConflict("service accounts do not use passwords")
            created = create_service_account(
                session,
                login=login,
                display_name=display_name,
                platform_role=platform_role,
            )
    except IdentityError as exc:
        raise ManagedPrincipalConflict(str(exc)) from exc
    row = session.get(Principal, created.id)
    if row is None:
        raise ManagedPrincipalNotFound("principal not found after creation")
    record_security_event(
        session,
        event_type="principal_created",
        outcome="success",
        channel=channel,
        principal_id=row.id,
        request_id=request_id,
        details={
            "actor_principal_id": access.principal.id,
            "principal_type": resolved_type.value,
            "platform_role": row.platform_role or "none",
        },
    )
    return PrincipalMutationResult(
        principal=_summary(row, last_used_at=None),
        changed=True,
    )


def update_managed_principal(
    session: Session,
    access: ReadAccess,
    *,
    principal_id: str,
    expected_revision: int | str | None,
    display_name: str,
    active: bool,
    platform_role: PlatformRole | str | None,
    channel: str,
    request_id: str | None = None,
) -> PrincipalMutationResult:
    require_platform_admin(access)
    expected = _expected_revision(expected_revision)
    row = session.get(Principal, principal_id)
    if row is None:
        raise ManagedPrincipalNotFound("principal not found")
    if row.revision != expected:
        raise ManagedPrincipalPreconditionFailed("principal revision changed")
    normalized_name = normalize_display_name(display_name)
    resolved_role = PlatformRole(platform_role) if platform_role is not None else None
    changed = (
        row.display_name != normalized_name
        or row.active is not active
        or row.platform_role != resolved_role
    )
    if not changed:
        return PrincipalMutationResult(
            principal=_summary(
                row,
                last_used_at=_last_used_by_principal(session, {row.id}).get(row.id),
            ),
            changed=False,
        )
    deactivating = row.active and not active
    if deactivating:
        ensure_principal_deactivation_preserves_owner_coverage(
            session,
            principal_id=row.id,
        )
    if (
        row.active
        and row.platform_role == PlatformRole.ADMIN
        and (not active or resolved_role != PlatformRole.ADMIN)
    ):
        _ensure_another_active_admin(session, principal_id=row.id)
    timestamp = utc_now()
    result = session.execute(
        update(Principal)
        .where(Principal.id == row.id, Principal.revision == expected)
        .values(
            display_name=normalized_name,
            active=active,
            platform_role=resolved_role,
            revision=expected + 1,
            updated_at=timestamp,
        )
    )
    if result.rowcount != 1:
        raise ManagedPrincipalPreconditionFailed("principal revision changed")
    if deactivating:
        revoke_all_browser_sessions(session, principal_id=row.id, now=timestamp)
        session.execute(
            update(ServiceToken)
            .where(
                ServiceToken.principal_id == row.id,
                ServiceToken.revoked_at.is_(None),
            )
            .values(revoked_at=timestamp)
        )
    session.flush()
    session.expire(row)
    session.refresh(row)
    record_security_event(
        session,
        event_type="principal_updated",
        outcome="success",
        channel=channel,
        principal_id=row.id,
        request_id=request_id,
        details={
            "actor_principal_id": access.principal.id,
            "active": int(row.active),
            "platform_role": row.platform_role or "none",
            "revision": row.revision,
        },
    )
    return PrincipalMutationResult(
        principal=_summary(
            row,
            last_used_at=_last_used_by_principal(session, {row.id}).get(row.id),
        ),
        changed=True,
    )


def reset_managed_human_password(
    session: Session,
    access: ReadAccess,
    *,
    principal_id: str,
    expected_revision: int | str | None,
    new_password: str,
    actor_password: str | None,
    channel: str,
    request_id: str | None = None,
) -> PrincipalCredentialResult:
    require_platform_admin(access)
    _reauthenticate_human_admin(
        session,
        access,
        password=actor_password,
        channel=channel,
        request_id=request_id,
    )
    row = _claim_principal_revision(
        session,
        principal_id=principal_id,
        expected_revision=expected_revision,
        principal_type=PrincipalType.HUMAN,
    )
    set_human_password(
        session,
        principal_id=row.id,
        password=new_password,
        channel=channel,
        request_id=request_id,
        actor_principal_id=access.principal.id,
    )
    session.expire(row)
    session.refresh(row)
    return PrincipalCredentialResult(
        principal=_summary(row, last_used_at=None),
        changed=True,
    )


def issue_managed_service_token(
    session: Session,
    access: ReadAccess,
    *,
    principal_id: str,
    expected_revision: int | str | None,
    name: str,
    expires_at: datetime | None,
    actor_password: str | None,
    channel: str,
    request_id: str | None = None,
    rotate: bool = False,
    idempotency_key: str,
    idempotency_ttl_seconds: int,
    idempotency_request_expiry: str | None = None,
) -> PrincipalCredentialResult:
    require_platform_admin(access)
    _reauthenticate_human_admin(
        session,
        access,
        password=actor_password,
        channel=channel,
        request_id=request_id,
    )
    replay = _reserve_secret_idempotency(
        session,
        access,
        key=idempotency_key,
        operation_context=(
            f"principal_token_rotate:{principal_id}:{name}"
            if rotate
            else f"principal_token_issue:{principal_id}:{name}"
        ),
        request_payload={
            "principal_id": principal_id,
            "name": name,
            "expires_at": (
                idempotency_request_expiry
                if idempotency_request_expiry is not None
                else (expires_at.isoformat() if expires_at is not None else None)
            ),
            "rotate": rotate,
        },
        ttl_seconds=idempotency_ttl_seconds,
    )
    if replay:
        row = session.get(Principal, principal_id)
        if row is None:
            raise ManagedPrincipalNotFound("principal not found")
        return PrincipalCredentialResult(
            principal=_summary(row, last_used_at=None),
            changed=False,
        )
    row = _claim_principal_revision(
        session,
        principal_id=principal_id,
        expected_revision=expected_revision,
        principal_type=PrincipalType.SERVICE_ACCOUNT,
    )
    operation = rotate_service_token if rotate else issue_service_token
    try:
        issued = operation(
            session,
            principal_id=row.id,
            name=name,
            expires_at=expires_at,
            channel=channel,
            request_id=request_id,
            actor_principal_id=access.principal.id,
        )
    except IdentityError as exc:
        raise ManagedPrincipalConflict(str(exc)) from exc
    _complete_secret_idempotency(
        session,
        access,
        key=idempotency_key,
        resource_id=issued.token_id,
    )
    session.expire(row)
    session.refresh(row)
    return PrincipalCredentialResult(
        principal=_summary(row, last_used_at=None),
        changed=True,
        issued_token=issued,
    )


def revoke_managed_service_token(
    session: Session,
    access: ReadAccess,
    *,
    principal_id: str,
    expected_revision: int | str | None,
    name: str,
    channel: str,
    request_id: str | None = None,
) -> PrincipalCredentialResult:
    require_platform_admin(access)
    row, expected = _require_principal_revision(
        session,
        principal_id=principal_id,
        expected_revision=expected_revision,
        principal_type=PrincipalType.SERVICE_ACCOUNT,
    )
    try:
        changed = revoke_service_token(
            session,
            principal_id=row.id,
            name=name,
            channel=channel,
            request_id=request_id,
            actor_principal_id=access.principal.id,
        )
    except IdentityError as exc:
        raise ManagedPrincipalConflict(str(exc)) from exc
    if changed:
        row = _advance_principal_revision(
            session,
            row=row,
            expected_revision=expected,
        )
    session.expire(row)
    session.refresh(row)
    return PrincipalCredentialResult(
        principal=_summary(row, last_used_at=None),
        changed=changed,
    )


def _claim_principal_revision(
    session: Session,
    *,
    principal_id: str,
    expected_revision: int | str | None,
    principal_type: PrincipalType,
) -> Principal:
    row, expected = _require_principal_revision(
        session,
        principal_id=principal_id,
        expected_revision=expected_revision,
        principal_type=principal_type,
    )
    return _advance_principal_revision(
        session,
        row=row,
        expected_revision=expected,
    )


def _require_principal_revision(
    session: Session,
    *,
    principal_id: str,
    expected_revision: int | str | None,
    principal_type: PrincipalType,
) -> tuple[Principal, int]:
    expected = _expected_revision(expected_revision)
    row = session.get(Principal, principal_id)
    if row is None or row.principal_type != principal_type:
        raise ManagedPrincipalNotFound("principal not found")
    if not row.active:
        raise ManagedPrincipalConflict("principal is inactive")
    if row.revision != expected:
        raise ManagedPrincipalPreconditionFailed("principal revision changed")
    return row, expected


def _advance_principal_revision(
    session: Session,
    *,
    row: Principal,
    expected_revision: int,
) -> Principal:
    result = session.execute(
        update(Principal)
        .where(Principal.id == row.id, Principal.revision == expected_revision)
        .values(revision=expected_revision + 1, updated_at=utc_now())
    )
    if result.rowcount != 1:
        raise ManagedPrincipalPreconditionFailed("principal revision changed")
    session.flush()
    return row


def _reauthenticate_human_admin(
    session: Session,
    access: ReadAccess,
    *,
    password: str | None,
    channel: str,
    request_id: str | None,
) -> None:
    if (
        access.principal.principal_type == PrincipalType.SERVICE_ACCOUNT
        and channel == "api"
    ):
        return
    if access.principal.principal_type != PrincipalType.HUMAN or password is None:
        raise PlatformAdminReauthenticationDenied(
            "credential issuance requires an authenticated human administrator",
            principal_id=access.principal.id,
            channel=channel,
            request_id=request_id,
        )
    verified = authenticate_password(
        session,
        login=access.principal.login,
        password=password,
        channel=channel,
        request_id=request_id,
    )
    if verified is None or verified.id != access.principal.id or not verified.is_admin:
        raise PlatformAdminReauthenticationDenied(
            "administrator re-authentication failed",
            principal_id=access.principal.id,
            channel=channel,
            request_id=request_id,
        )


def _reserve_secret_idempotency(
    session: Session,
    access: ReadAccess,
    *,
    key: str,
    operation_context: str,
    request_payload: dict[str, object],
    ttl_seconds: int,
) -> bool:
    if not _IDEMPOTENCY_KEY_PATTERN.fullmatch(key):
        raise ManagedPrincipalConflict(
            "Idempotency-Key must contain 16 to 128 visible ASCII characters"
        )
    if ttl_seconds < 300 or ttl_seconds > 604800:
        raise ManagedPrincipalConflict("idempotency TTL is outside the supported range")
    now = utc_now()
    key_hash = hashlib.sha256(key.encode("utf-8")).hexdigest()
    request_hash = hashlib.sha256(
        json.dumps(
            request_payload,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    ).hexdigest()
    existing = session.scalar(
        select(IdempotencyRecord).where(
            IdempotencyRecord.principal_id == access.principal.id,
            IdempotencyRecord.key_hash == key_hash,
        )
    )
    if existing is not None and existing.expires_at <= now:
        session.delete(existing)
        session.flush()
        existing = None
    if existing is None:
        inserted = session.execute(
            sqlite_insert(IdempotencyRecord)
            .values(
                principal_id=access.principal.id,
                key_hash=key_hash,
                operation_context=operation_context,
                request_hash=request_hash,
                created_at=now,
                expires_at=now + timedelta(seconds=ttl_seconds),
            )
            .on_conflict_do_nothing(index_elements=["principal_id", "key_hash"])
        )
        existing = session.scalar(
            select(IdempotencyRecord).where(
                IdempotencyRecord.principal_id == access.principal.id,
                IdempotencyRecord.key_hash == key_hash,
            )
        )
        if existing is None:
            raise ManagedPrincipalConflict("idempotency key is currently in use")
        if inserted.rowcount == 1:
            return False
    if (
        existing.operation_context != operation_context
        or existing.request_hash != request_hash
    ):
        raise ManagedPrincipalConflict(
            "Idempotency-Key was already used for a different request"
        )
    if existing.response_json is None:
        raise ManagedPrincipalConflict("idempotent request is still being processed")
    return True


def _complete_secret_idempotency(
    session: Session,
    access: ReadAccess,
    *,
    key: str,
    resource_id: str,
) -> None:
    key_hash = hashlib.sha256(key.encode("utf-8")).hexdigest()
    row = session.scalar(
        select(IdempotencyRecord).where(
            IdempotencyRecord.principal_id == access.principal.id,
            IdempotencyRecord.key_hash == key_hash,
        )
    )
    if row is None:
        raise ManagedPrincipalConflict("idempotency record is missing")
    row.resource_id = resource_id
    row.response_json = '{"completed":true}'
    session.flush()


def _expected_revision(value: int | str | None) -> int:
    try:
        return parse_if_match(value) if isinstance(value, str) or value is None else value
    except Exception as exc:
        if value is None:
            raise ManagedPrincipalPreconditionRequired("If-Match is required") from exc
        raise ManagedPrincipalPreconditionFailed("invalid principal revision") from exc


def _ensure_another_active_admin(session: Session, *, principal_id: str) -> None:
    remaining = session.scalar(
        select(func.count())
        .select_from(Principal)
        .where(
            Principal.id != principal_id,
            Principal.active.is_(True),
            Principal.platform_role == PlatformRole.ADMIN,
        )
    ) or 0
    if remaining < 1:
        raise ManagedPrincipalConflict("at least one active platform admin is required")


def _last_used_by_principal(
    session: Session,
    principal_ids: set[str],
) -> dict[str, datetime]:
    if not principal_ids:
        return {}
    values: dict[str, datetime] = {}
    for principal_id, last_seen in session.execute(
        select(BrowserSession.principal_id, func.max(BrowserSession.last_seen_at))
        .where(BrowserSession.principal_id.in_(principal_ids))
        .group_by(BrowserSession.principal_id)
    ):
        if last_seen is not None:
            values[str(principal_id)] = last_seen
    for principal_id, last_seen in session.execute(
        select(ServiceToken.principal_id, func.max(ServiceToken.last_used_at))
        .where(ServiceToken.principal_id.in_(principal_ids))
        .group_by(ServiceToken.principal_id)
    ):
        if last_seen is not None:
            key = str(principal_id)
            if key not in values or last_seen > values[key]:
                values[key] = last_seen
    return values


def _summary(
    row: Principal,
    *,
    last_used_at: datetime | None,
) -> PrincipalAdminSummary:
    return PrincipalAdminSummary(
        id=row.id,
        principal_type=PrincipalType(row.principal_type),
        login=row.login,
        display_name=row.display_name,
        active=row.active,
        platform_role=(
            PlatformRole(row.platform_role) if row.platform_role is not None else None
        ),
        revision=row.revision,
        etag=revision_etag(row.revision),
        created_at=format_rfc3339_utc(row.created_at),
        updated_at=format_rfc3339_utc(row.updated_at),
        last_used_at=(
            format_rfc3339_utc(last_used_at) if last_used_at is not None else None
        ),
    )


def _token_view(row: ServiceToken) -> PrincipalTokenView:
    now = utc_now()
    active = (
        row.revoked_at is None
        and (row.expires_at is None or row.expires_at > now)
    )
    return PrincipalTokenView(
        id=row.id,
        name=row.name,
        token_prefix=row.token_prefix,
        active=active,
        expires_at=(
            format_rfc3339_utc(row.expires_at) if row.expires_at is not None else None
        ),
        revoked_at=(
            format_rfc3339_utc(row.revoked_at) if row.revoked_at is not None else None
        ),
        rotated_at=(
            format_rfc3339_utc(row.rotated_at) if row.rotated_at is not None else None
        ),
        created_at=format_rfc3339_utc(row.created_at),
        last_used_at=(
            format_rfc3339_utc(row.last_used_at) if row.last_used_at is not None else None
        ),
    )
