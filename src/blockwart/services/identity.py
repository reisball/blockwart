from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from argon2.low_level import Type
from sqlalchemy import delete, func, or_, select
from sqlalchemy.orm import Session

from blockwart.domain.auth import PlatformRole, PrincipalContext, PrincipalType
from blockwart.domain.security import find_secret_violations
from blockwart.models import (
    BrowserSession,
    LoginChallenge,
    PasswordCredential,
    Principal,
    SecurityEvent,
    ServiceToken,
)
from blockwart.services.access import (
    ensure_principal_deactivation_preserves_owner_coverage,
)

LOGIN_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._-]{1,126}[a-z0-9]$")
TOKEN_NAME_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._ -]{0,127}$")
REQUEST_ID_PATTERN = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
AUTH_CHANNELS = frozenset({"ui", "api", "mcp", "cli", "system"})
AUTH_OUTCOMES = frozenset({"success", "failure", "denied"})
SERVICE_TOKEN_PREFIX = "bwst"
BROWSER_SESSION_PREFIX = "bwss"
LOGIN_CHALLENGE_PREFIX = "bwlc"
MIN_PASSWORD_LENGTH = 12
MAX_PASSWORD_BYTES = 1024

_PASSWORD_HASHER = PasswordHasher(
    time_cost=3,
    memory_cost=65536,
    parallelism=2,
    hash_len=32,
    salt_len=16,
    type=Type.ID,
)
_DUMMY_PASSWORD_HASH = _PASSWORD_HASHER.hash(
    "blockwart-dummy-password-not-a-real-credential"
)


class IdentityError(ValueError):
    """Stable domain error for invalid identity operations."""


class IdentityConflict(IdentityError):
    """The requested identity or credential already exists."""


class IdentityNotFound(IdentityError):
    """The requested identity or credential does not exist."""


@dataclass(frozen=True)
class IssuedServiceToken:
    token_id: str
    principal_id: str
    name: str
    value: str = field(repr=False)
    expires_at: datetime | None = None


@dataclass(frozen=True)
class IssuedBrowserSession:
    session_id: str
    principal: PrincipalContext
    value: str = field(repr=False)
    csrf_token: str = field(repr=False)
    expires_at: datetime | None = None


@dataclass(frozen=True)
class IssuedLoginChallenge:
    challenge_id: str
    value: str = field(repr=False)
    expires_at: datetime | None = None


def utc_now() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


def normalize_login(value: str) -> str:
    normalized = value.strip().casefold()
    if not LOGIN_PATTERN.fullmatch(normalized):
        raise IdentityError(
            "login must contain 3-128 lowercase letters, digits, dots, dashes, or underscores"
        )
    return normalized


def normalize_display_name(value: str) -> str:
    normalized = " ".join(value.split())
    if not normalized or len(normalized) > 255:
        raise IdentityError("display name must contain 1-255 characters")
    return normalized


def normalize_token_name(value: str) -> str:
    normalized = " ".join(value.split())
    if not TOKEN_NAME_PATTERN.fullmatch(normalized):
        raise IdentityError(
            "token name must contain 1-128 letters, digits, spaces, dots, dashes, or underscores"
        )
    return normalized


def hash_password(password: str) -> str:
    _validate_password(password)
    return _PASSWORD_HASHER.hash(password)


def verify_password(password_hash: str, candidate: str) -> bool:
    try:
        return _PASSWORD_HASHER.verify(password_hash, candidate)
    except (InvalidHashError, VerificationError):
        return False


def password_needs_rehash(password_hash: str) -> bool:
    try:
        return _PASSWORD_HASHER.check_needs_rehash(password_hash)
    except InvalidHashError:
        return True


def create_human_principal(
    session: Session,
    *,
    login: str,
    display_name: str,
    password: str,
    platform_role: PlatformRole | str | None = None,
    now: datetime | None = None,
) -> PrincipalContext:
    normalized_login = normalize_login(login)
    normalized_name = normalize_display_name(display_name)
    if _principal_by_login(session, normalized_login) is not None:
        raise IdentityConflict("principal login already exists")
    timestamp = now or utc_now()
    principal = Principal(
        id=str(uuid4()),
        principal_type=PrincipalType.HUMAN,
        login=normalized_login,
        display_name=normalized_name,
        active=True,
        platform_role=(PlatformRole(platform_role) if platform_role is not None else None),
        revision=1,
        created_at=timestamp,
        updated_at=timestamp,
    )
    session.add(principal)
    session.flush()
    session.add(
        PasswordCredential(
            principal_id=principal.id,
            password_hash=hash_password(password),
            created_at=timestamp,
            updated_at=timestamp,
        )
    )
    session.flush()
    return principal_context(principal)


def create_service_account(
    session: Session,
    *,
    login: str,
    display_name: str,
    platform_role: PlatformRole | str | None = None,
    now: datetime | None = None,
) -> PrincipalContext:
    normalized_login = normalize_login(login)
    normalized_name = normalize_display_name(display_name)
    if _principal_by_login(session, normalized_login) is not None:
        raise IdentityConflict("principal login already exists")
    timestamp = now or utc_now()
    principal = Principal(
        id=str(uuid4()),
        principal_type=PrincipalType.SERVICE_ACCOUNT,
        login=normalized_login,
        display_name=normalized_name,
        active=True,
        platform_role=(PlatformRole(platform_role) if platform_role is not None else None),
        revision=1,
        created_at=timestamp,
        updated_at=timestamp,
    )
    session.add(principal)
    session.flush()
    return principal_context(principal)


def set_human_password(
    session: Session,
    *,
    principal_id: str,
    password: str,
    channel: str = "cli",
    request_id: str | None = None,
    actor_principal_id: str | None = None,
    now: datetime | None = None,
) -> None:
    principal = session.get(Principal, principal_id)
    if principal is None or principal.principal_type != PrincipalType.HUMAN:
        raise IdentityNotFound("human principal not found")
    timestamp = now or utc_now()
    credential = session.get(PasswordCredential, principal_id)
    if credential is None:
        credential = PasswordCredential(
            principal_id=principal_id,
            password_hash=hash_password(password),
            created_at=timestamp,
            updated_at=timestamp,
        )
        session.add(credential)
    else:
        credential.password_hash = hash_password(password)
        credential.updated_at = timestamp
    revoke_all_browser_sessions(
        session,
        principal_id=principal_id,
        now=timestamp,
    )
    record_security_event(
        session,
        event_type="password_credential_rotated",
        outcome="success",
        channel=channel,
        principal_id=principal_id,
        request_id=request_id,
        details=(
            {"actor_principal_id": actor_principal_id}
            if actor_principal_id is not None
            else {}
        ),
        now=timestamp,
    )
    principal.updated_at = timestamp
    session.flush()


def authenticate_password(
    session: Session,
    *,
    login: str,
    password: str,
    channel: str = "ui",
    request_id: str | None = None,
    now: datetime | None = None,
) -> PrincipalContext | None:
    timestamp = now or utc_now()
    try:
        normalized_login = normalize_login(login)
    except IdentityError:
        normalized_login = ""
    principal = (
        _principal_by_login(session, normalized_login)
        if normalized_login
        else None
    )
    credential = (
        session.get(PasswordCredential, principal.id)
        if principal is not None
        else None
    )
    password_hash = (
        credential.password_hash
        if credential is not None
        else _DUMMY_PASSWORD_HASH
    )
    password_within_limit = len(password.encode("utf-8")) <= MAX_PASSWORD_BYTES
    candidate = password if password_within_limit else "blockwart-overlong-password"
    password_matches = verify_password(password_hash, candidate)
    authenticated = bool(
        principal is not None
        and credential is not None
        and principal.active
        and principal.principal_type == PrincipalType.HUMAN
        and password_within_limit
        and password_matches
    )
    record_security_event(
        session,
        event_type="password_authentication",
        outcome="success" if authenticated else "failure",
        channel=channel,
        principal_id=principal.id if principal is not None else None,
        request_id=request_id,
        details={} if authenticated else {"reason": "invalid_credentials"},
        now=timestamp,
    )
    if not authenticated or principal is None:
        return None
    if password_needs_rehash(password_hash):
        credential.password_hash = hash_password(password)
        credential.updated_at = timestamp
    return principal_context(principal)


def issue_service_token(
    session: Session,
    *,
    principal_id: str,
    name: str,
    expires_at: datetime | None = None,
    channel: str = "cli",
    request_id: str | None = None,
    actor_principal_id: str | None = None,
    now: datetime | None = None,
) -> IssuedServiceToken:
    principal = _active_service_account(session, principal_id)
    normalized_name = normalize_token_name(name)
    existing = session.scalar(
        select(ServiceToken).where(
            ServiceToken.principal_id == principal.id,
            ServiceToken.name == normalized_name,
        )
    )
    if existing is not None:
        raise IdentityConflict("service token name already exists")
    timestamp = now or utc_now()
    _validate_future_expiry(expires_at, now=timestamp)
    token_id = str(uuid4())
    value = _new_opaque_value(SERVICE_TOKEN_PREFIX, token_id)
    row = ServiceToken(
        id=token_id,
        principal_id=principal.id,
        name=normalized_name,
        token_prefix=value[:24],
        token_hash=_secret_hash(value),
        expires_at=expires_at,
        created_at=timestamp,
    )
    session.add(row)
    record_security_event(
        session,
        event_type="service_token_issued",
        outcome="success",
        channel=channel,
        principal_id=principal.id,
        request_id=request_id,
        details={
            "credential_id": token_id,
            "credential_name": normalized_name,
            **(
                {"actor_principal_id": actor_principal_id}
                if actor_principal_id is not None
                else {}
            ),
        },
        now=timestamp,
    )
    session.flush()
    return IssuedServiceToken(
        token_id=token_id,
        principal_id=principal.id,
        name=normalized_name,
        value=value,
        expires_at=expires_at,
    )


def rotate_service_token(
    session: Session,
    *,
    principal_id: str,
    name: str,
    expires_at: datetime | None = None,
    channel: str = "cli",
    request_id: str | None = None,
    actor_principal_id: str | None = None,
    now: datetime | None = None,
) -> IssuedServiceToken:
    principal = _active_service_account(session, principal_id)
    normalized_name = normalize_token_name(name)
    row = session.scalar(
        select(ServiceToken).where(
            ServiceToken.principal_id == principal.id,
            ServiceToken.name == normalized_name,
        )
    )
    if row is None:
        raise IdentityNotFound("service token not found")
    timestamp = now or utc_now()
    _validate_future_expiry(expires_at, now=timestamp)
    value = _new_opaque_value(SERVICE_TOKEN_PREFIX, row.id)
    row.token_prefix = value[:24]
    row.token_hash = _secret_hash(value)
    row.expires_at = expires_at
    row.revoked_at = None
    row.rotated_at = timestamp
    row.last_used_at = None
    record_security_event(
        session,
        event_type="service_token_rotated",
        outcome="success",
        channel=channel,
        principal_id=principal.id,
        request_id=request_id,
        details={
            "credential_id": row.id,
            "credential_name": row.name,
            **(
                {"actor_principal_id": actor_principal_id}
                if actor_principal_id is not None
                else {}
            ),
        },
        now=timestamp,
    )
    session.flush()
    return IssuedServiceToken(
        token_id=row.id,
        principal_id=principal.id,
        name=row.name,
        value=value,
        expires_at=expires_at,
    )


def revoke_service_token(
    session: Session,
    *,
    principal_id: str,
    name: str,
    channel: str = "cli",
    request_id: str | None = None,
    actor_principal_id: str | None = None,
    now: datetime | None = None,
) -> bool:
    normalized_name = normalize_token_name(name)
    row = session.scalar(
        select(ServiceToken).where(
            ServiceToken.principal_id == principal_id,
            ServiceToken.name == normalized_name,
        )
    )
    if row is None:
        raise IdentityNotFound("service token not found")
    if row.revoked_at is not None:
        return False
    timestamp = now or utc_now()
    row.revoked_at = timestamp
    record_security_event(
        session,
        event_type="service_token_revoked",
        outcome="success",
        channel=channel,
        principal_id=principal_id,
        request_id=request_id,
        details={
            "credential_id": row.id,
            "credential_name": row.name,
            **(
                {"actor_principal_id": actor_principal_id}
                if actor_principal_id is not None
                else {}
            ),
        },
        now=timestamp,
    )
    session.flush()
    return True


def authenticate_service_token(
    session: Session,
    *,
    token: str,
    channel: str = "api",
    request_id: str | None = None,
    now: datetime | None = None,
    record_failure_event: bool = True,
) -> PrincipalContext | None:
    timestamp = now or utc_now()
    token_id = _opaque_id(token, SERVICE_TOKEN_PREFIX)
    row = session.get(ServiceToken, token_id) if token_id is not None else None
    supplied_hash = _secret_hash(token if len(token) <= 512 else "")
    expected_hash = row.token_hash if row is not None else "0" * 64
    token_matches = hmac.compare_digest(supplied_hash, expected_hash)
    principal = session.get(Principal, row.principal_id) if row is not None else None
    authenticated = bool(
        row is not None
        and principal is not None
        and principal.active
        and principal.principal_type == PrincipalType.SERVICE_ACCOUNT
        and row.revoked_at is None
        and (row.expires_at is None or row.expires_at > timestamp)
        and token_matches
    )
    if not authenticated and record_failure_event:
        record_security_event(
            session,
            event_type="service_token_authentication",
            outcome="failure",
            channel=channel,
            principal_id=principal.id if principal is not None else None,
            request_id=request_id,
            details={"reason": "invalid_credentials"},
            now=timestamp,
        )
    if not authenticated:
        return None
    row.last_used_at = timestamp
    session.flush()
    return principal_context(principal)


def authenticate_bearer_header(
    session: Session,
    *,
    authorization: str | None,
    channel: str = "api",
    request_id: str | None = None,
    now: datetime | None = None,
    record_failure_event: bool = True,
) -> PrincipalContext | None:
    if authorization is None:
        token = ""
    else:
        scheme, separator, value = authorization.partition(" ")
        token = value.strip() if separator and scheme.casefold() == "bearer" else ""
    return authenticate_service_token(
        session,
        token=token,
        channel=channel,
        request_id=request_id,
        now=now,
        record_failure_event=record_failure_event,
    )


def issue_browser_session(
    session: Session,
    *,
    principal_id: str,
    ttl_seconds: int,
    now: datetime | None = None,
) -> IssuedBrowserSession:
    principal = session.get(Principal, principal_id)
    if (
        principal is None
        or not principal.active
        or principal.principal_type != PrincipalType.HUMAN
    ):
        raise IdentityNotFound("active human principal not found")
    if ttl_seconds < 300 or ttl_seconds > 86400:
        raise IdentityError("browser session TTL must be between 300 and 86400 seconds")
    timestamp = now or utc_now()
    session_id = str(uuid4())
    value = _new_opaque_value(BROWSER_SESSION_PREFIX, session_id)
    csrf_token = secrets.token_urlsafe(32)
    expires_at = timestamp + timedelta(seconds=ttl_seconds)
    session.add(
        BrowserSession(
            id=session_id,
            principal_id=principal.id,
            token_hash=_secret_hash(value),
            csrf_hash=_secret_hash(csrf_token),
            expires_at=expires_at,
            created_at=timestamp,
        )
    )
    session.flush()
    return IssuedBrowserSession(
        session_id=session_id,
        principal=principal_context(principal),
        value=value,
        csrf_token=csrf_token,
        expires_at=expires_at,
    )


def authenticate_browser_session(
    session: Session,
    *,
    value: str | None,
    now: datetime | None = None,
) -> PrincipalContext | None:
    row, principal = _browser_session_record(session, value=value, now=now)
    if row is None or principal is None:
        return None
    return principal_context(principal)


def verify_browser_csrf(
    session: Session,
    *,
    session_value: str | None,
    csrf_token: str | None,
    now: datetime | None = None,
) -> PrincipalContext | None:
    row, principal = _browser_session_record(
        session,
        value=session_value,
        now=now,
    )
    if row is None or principal is None or not csrf_token:
        return None
    supplied_hash = _secret_hash(csrf_token)
    if not hmac.compare_digest(supplied_hash, row.csrf_hash):
        return None
    return principal_context(principal)


def revoke_browser_session(
    session: Session,
    *,
    value: str | None,
    now: datetime | None = None,
) -> bool:
    timestamp = now or utc_now()
    session_id = _opaque_id(value or "", BROWSER_SESSION_PREFIX)
    row = session.get(BrowserSession, session_id) if session_id is not None else None
    if row is None or not _secret_matches(value or "", row.token_hash):
        return False
    if row.revoked_at is not None:
        return False
    row.revoked_at = timestamp
    session.flush()
    return True


def revoke_all_browser_sessions(
    session: Session,
    *,
    principal_id: str,
    now: datetime | None = None,
) -> int:
    timestamp = now or utc_now()
    rows = list(
        session.scalars(
            select(BrowserSession).where(
                BrowserSession.principal_id == principal_id,
                BrowserSession.revoked_at.is_(None),
            )
        ).all()
    )
    for row in rows:
        row.revoked_at = timestamp
    session.flush()
    return len(rows)


def issue_login_challenge(
    session: Session,
    *,
    ttl_seconds: int,
    now: datetime | None = None,
) -> IssuedLoginChallenge:
    if ttl_seconds < 60 or ttl_seconds > 3600:
        raise IdentityError("login challenge TTL must be between 60 and 3600 seconds")
    timestamp = now or utc_now()
    session.execute(
        delete(LoginChallenge).where(
            or_(
                LoginChallenge.used_at.is_not(None),
                LoginChallenge.expires_at <= timestamp,
            )
        )
    )
    challenge_id = str(uuid4())
    value = _new_opaque_value(LOGIN_CHALLENGE_PREFIX, challenge_id)
    expires_at = timestamp + timedelta(seconds=ttl_seconds)
    session.add(
        LoginChallenge(
            id=challenge_id,
            token_hash=_secret_hash(value),
            expires_at=expires_at,
            created_at=timestamp,
        )
    )
    session.flush()
    return IssuedLoginChallenge(
        challenge_id=challenge_id,
        value=value,
        expires_at=expires_at,
    )


def consume_login_challenge(
    session: Session,
    *,
    cookie_value: str | None,
    form_value: str | None,
    now: datetime | None = None,
) -> bool:
    timestamp = now or utc_now()
    if not cookie_value or not form_value:
        return False
    if not hmac.compare_digest(cookie_value, form_value):
        return False
    challenge_id = _opaque_id(cookie_value, LOGIN_CHALLENGE_PREFIX)
    row = session.get(LoginChallenge, challenge_id) if challenge_id is not None else None
    valid = bool(
        row is not None
        and row.used_at is None
        and row.expires_at > timestamp
        and _secret_matches(cookie_value, row.token_hash)
    )
    if not valid or row is None:
        return False
    row.used_at = timestamp
    session.flush()
    return True


def deactivate_principal(
    session: Session,
    *,
    principal_id: str,
    channel: str = "cli",
    request_id: str | None = None,
    actor_principal_id: str | None = None,
    now: datetime | None = None,
) -> bool:
    principal = session.get(Principal, principal_id)
    if principal is None:
        raise IdentityNotFound("principal not found")
    if not principal.active:
        return False
    ensure_principal_deactivation_preserves_owner_coverage(
        session,
        principal_id=principal_id,
    )
    timestamp = now or utc_now()
    principal.active = False
    principal.updated_at = timestamp
    revoke_all_browser_sessions(
        session,
        principal_id=principal_id,
        now=timestamp,
    )
    tokens = list(
        session.scalars(
            select(ServiceToken).where(
                ServiceToken.principal_id == principal_id,
                ServiceToken.revoked_at.is_(None),
            )
        ).all()
    )
    for token in tokens:
        token.revoked_at = timestamp
    record_security_event(
        session,
        event_type="principal_deactivated",
        outcome="success",
        channel=channel,
        principal_id=principal_id,
        request_id=request_id,
        details=(
            {"actor_principal_id": actor_principal_id}
            if actor_principal_id is not None
            else {}
        ),
        now=timestamp,
    )
    session.flush()
    return True


def prune_security_events(
    session: Session,
    *,
    retention_days: int,
    max_rows: int,
    now: datetime | None = None,
) -> int:
    if retention_days < 1:
        raise IdentityError("security event retention must be at least one day")
    if max_rows < 1:
        raise IdentityError("security event maximum must be positive")
    timestamp = now or utc_now()
    cutoff = timestamp - timedelta(days=retention_days)
    expired = session.execute(
        delete(SecurityEvent).where(SecurityEvent.created_at < cutoff)
    ).rowcount
    remaining = session.scalar(select(func.count()).select_from(SecurityEvent)) or 0
    overflow = max(remaining - max_rows, 0)
    if overflow:
        oldest_ids = select(SecurityEvent.id).order_by(
            SecurityEvent.created_at,
            SecurityEvent.id,
        ).limit(overflow)
        session.execute(
            delete(SecurityEvent).where(SecurityEvent.id.in_(oldest_ids))
        )
    session.flush()
    return int(expired or 0) + overflow


def record_security_event(
    session: Session,
    *,
    event_type: str,
    outcome: str,
    channel: str,
    details: dict[str, object],
    principal_id: str | None = None,
    request_id: str | None = None,
    now: datetime | None = None,
) -> None:
    if outcome not in AUTH_OUTCOMES:
        raise IdentityError("invalid security event outcome")
    if channel not in AUTH_CHANNELS:
        raise IdentityError("invalid security event channel")
    if not event_type or len(event_type) > 96:
        raise IdentityError("invalid security event type")
    if request_id is not None and not REQUEST_ID_PATTERN.fullmatch(request_id):
        request_id = None
    violations = find_secret_violations(details)
    if violations:
        raise IdentityError("security event details contain forbidden secret-shaped data")
    session.add(
        SecurityEvent(
            principal_id=principal_id,
            event_type=event_type,
            outcome=outcome,
            channel=channel,
            request_id=request_id,
            details_json=json.dumps(
                details,
                sort_keys=True,
                separators=(",", ":"),
            ),
            created_at=now or utc_now(),
        )
    )
    session.flush()


def principal_context(principal: Principal) -> PrincipalContext:
    return PrincipalContext(
        id=principal.id,
        principal_type=PrincipalType(principal.principal_type),
        login=principal.login,
        display_name=principal.display_name,
        platform_role=(
            PlatformRole(principal.platform_role)
            if principal.platform_role is not None
            else None
        ),
        revision=principal.revision,
    )


def principal_by_login(session: Session, login: str) -> Principal | None:
    return _principal_by_login(session, normalize_login(login))


def _principal_by_login(session: Session, login: str) -> Principal | None:
    return session.scalar(
        select(Principal).where(Principal.login == login)
    )


def _active_service_account(session: Session, principal_id: str) -> Principal:
    principal = session.get(Principal, principal_id)
    if (
        principal is None
        or not principal.active
        or principal.principal_type != PrincipalType.SERVICE_ACCOUNT
    ):
        raise IdentityNotFound("active service account not found")
    return principal


def _browser_session_record(
    session: Session,
    *,
    value: str | None,
    now: datetime | None,
) -> tuple[BrowserSession | None, Principal | None]:
    timestamp = now or utc_now()
    session_id = _opaque_id(value or "", BROWSER_SESSION_PREFIX)
    row = session.get(BrowserSession, session_id) if session_id is not None else None
    if (
        row is None
        or row.revoked_at is not None
        or row.expires_at <= timestamp
        or not _secret_matches(value or "", row.token_hash)
    ):
        return None, None
    principal = session.get(Principal, row.principal_id)
    if (
        principal is None
        or not principal.active
        or principal.principal_type != PrincipalType.HUMAN
    ):
        return None, None
    return row, principal


def _validate_password(password: str) -> None:
    if len(password) < MIN_PASSWORD_LENGTH:
        raise IdentityError(
            f"password must contain at least {MIN_PASSWORD_LENGTH} characters"
        )
    if len(password.encode("utf-8")) > MAX_PASSWORD_BYTES:
        raise IdentityError("password is too long")


def _validate_future_expiry(
    expires_at: datetime | None,
    *,
    now: datetime,
) -> None:
    if expires_at is not None and expires_at <= now:
        raise IdentityError("credential expiry must be in the future")


def _new_opaque_value(prefix: str, public_id: str) -> str:
    return f"{prefix}_{public_id}.{secrets.token_urlsafe(32)}"


def _opaque_id(value: str, prefix: str) -> str | None:
    expected = f"{prefix}_"
    if not value.startswith(expected) or len(value) > 512:
        return None
    public_id, separator, secret = value[len(expected) :].partition(".")
    if not separator or len(secret) < 32:
        return None
    try:
        return str(UUID(public_id))
    except ValueError:
        return None


def _secret_hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _secret_matches(value: str, expected_hash: str) -> bool:
    return hmac.compare_digest(_secret_hash(value), expected_hash)
