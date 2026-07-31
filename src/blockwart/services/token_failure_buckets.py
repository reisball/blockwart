from __future__ import annotations

import hashlib
import ipaddress
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from functools import lru_cache

from sqlalchemy import delete, func, select
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.orm import Session

from blockwart.config import Settings
from blockwart.models import ServiceTokenFailureBucket
from blockwart.services.identity import record_security_event, utc_now

DIMENSION_GLOBAL = "global"
DIMENSION_SOURCE = "source"
DIMENSION_TOKEN = "token"
PRUNE_BATCH_SIZE = 256
_GLOBAL_KEY_HASH = hashlib.sha256(b"blockwart-service-token-global-v1").hexdigest()


@dataclass(frozen=True)
class TokenFailureDecision:
    allowed: bool
    dimension: str | None = None
    count: int = 0


@dataclass(frozen=True)
class TokenFailurePolicy:
    window_seconds: int
    global_limit: int
    source_limit: int
    token_limit: int
    max_rows: int

    @classmethod
    def from_settings(cls, settings: Settings) -> TokenFailurePolicy:
        return cls(
            window_seconds=settings.auth_service_token_rate_window_seconds,
            global_limit=settings.auth_service_token_global_failure_limit,
            source_limit=settings.auth_service_token_source_failure_limit,
            token_limit=settings.auth_service_token_fingerprint_failure_limit,
            max_rows=settings.auth_service_token_failure_bucket_max_rows,
        )


def precheck_service_token_failure(
    session: Session,
    *,
    token: str,
    source: str,
    policy: TokenFailurePolicy,
    channel: str,
    request_id: str | None,
    now: datetime | None = None,
) -> TokenFailureDecision:
    timestamp = now or utc_now()
    window_start = _window_start(timestamp, policy.window_seconds)
    for dimension, key_hash, limit in _bucket_specs(token, source, policy):
        bucket = session.scalar(
            select(ServiceTokenFailureBucket).where(
                ServiceTokenFailureBucket.dimension == dimension,
                ServiceTokenFailureBucket.key_hash == key_hash,
                ServiceTokenFailureBucket.window_start == window_start,
            )
        )
        if bucket is not None and bucket.failure_count >= limit:
            _emit_aggregate_event_if_due(
                session,
                bucket=bucket,
                limit=limit,
                channel=channel,
                request_id=request_id,
                now=timestamp,
            )
            return TokenFailureDecision(False, dimension, bucket.failure_count)
    return TokenFailureDecision(True)


def record_service_token_failure(
    session: Session,
    *,
    token: str,
    source: str,
    policy: TokenFailurePolicy,
    channel: str,
    request_id: str | None,
    now: datetime | None = None,
) -> TokenFailureDecision:
    timestamp = now or utc_now()
    window_start = _window_start(timestamp, policy.window_seconds)
    expires_at = window_start + timedelta(seconds=policy.window_seconds)
    specs = _bucket_specs(token, source, policy)

    global_bucket, global_reclaimed_active = _increment_bucket(
        session,
        dimension=DIMENSION_GLOBAL,
        key_hash=_GLOBAL_KEY_HASH,
        window_start=window_start,
        expires_at=expires_at,
        limit=policy.global_limit,
        max_rows=policy.max_rows,
        now=timestamp,
        evict_dimensions=(DIMENSION_TOKEN, DIMENSION_SOURCE),
    )
    if global_bucket is None:
        raise RuntimeError("Unable to allocate the global service-token failure bucket")
    if global_reclaimed_active:
        _saturate_bucket(global_bucket, policy.global_limit)
    source_dimension, source_hash, source_limit = specs[1]
    source_bucket, source_reclaimed_active = _increment_bucket(
        session,
        dimension=source_dimension,
        key_hash=source_hash,
        window_start=window_start,
        expires_at=expires_at,
        limit=source_limit,
        max_rows=policy.max_rows,
        now=timestamp,
        evict_dimensions=(DIMENSION_TOKEN,),
    )
    if source_bucket is None:
        # Losing active bucket state is safe only after the whole window fails closed.
        _saturate_bucket(global_bucket, policy.global_limit)
        source_bucket, source_reclaimed_active = _increment_bucket(
            session,
            dimension=source_dimension,
            key_hash=source_hash,
            window_start=window_start,
            expires_at=expires_at,
            limit=source_limit,
            max_rows=policy.max_rows,
            now=timestamp,
            evict_dimensions=(DIMENSION_SOURCE,),
        )
    if source_reclaimed_active:
        _saturate_bucket(global_bucket, policy.global_limit)
    buckets = ((global_bucket, policy.global_limit), (source_bucket, source_limit))

    token_bucket = None
    if global_bucket.failure_count <= policy.global_limit:
        token_dimension, token_hash, token_limit = specs[2]
        token_bucket, token_reclaimed_active = _increment_bucket(
            session,
            dimension=token_dimension,
            key_hash=token_hash,
            window_start=window_start,
            expires_at=expires_at,
            limit=token_limit,
            max_rows=policy.max_rows,
            now=timestamp,
            evict_dimensions=(DIMENSION_TOKEN,),
        )
        # An evicted active fingerprint could otherwise retry below its threshold.
        if token_bucket is None or token_reclaimed_active:
            _saturate_bucket(global_bucket, policy.global_limit)
        buckets += ((token_bucket, token_limit),)

    denied = TokenFailureDecision(True)
    for bucket, limit in buckets:
        if bucket is None:
            continue
        if bucket.failure_count >= limit:
            _emit_aggregate_event_if_due(
                session,
                bucket=bucket,
                limit=limit,
                channel=channel,
                request_id=request_id,
                now=timestamp,
            )
        if denied.allowed and bucket.failure_count > limit:
            denied = TokenFailureDecision(False, bucket.dimension, bucket.failure_count)
    return denied


def prune_service_token_failure_buckets(
    session: Session,
    *,
    max_rows: int,
    now: datetime | None = None,
) -> int:
    timestamp = now or utc_now()
    expired_ids = list(
        session.scalars(
            select(ServiceTokenFailureBucket.id)
            .where(ServiceTokenFailureBucket.expires_at <= timestamp)
            .order_by(ServiceTokenFailureBucket.expires_at, ServiceTokenFailureBucket.id)
            .limit(PRUNE_BATCH_SIZE)
        ).all()
    )
    if expired_ids:
        session.execute(
            delete(ServiceTokenFailureBucket).where(
                ServiceTokenFailureBucket.id.in_(expired_ids)
            )
        )
    remaining = session.scalar(
        select(func.count()).select_from(ServiceTokenFailureBucket)
    ) or 0
    overflow = min(max(remaining - max_rows, 0), PRUNE_BATCH_SIZE)
    overflow_ids: list[int] = []
    if overflow:
        overflow_ids = list(
            session.scalars(
                select(ServiceTokenFailureBucket.id)
                .order_by(ServiceTokenFailureBucket.expires_at, ServiceTokenFailureBucket.id)
                .limit(overflow)
            ).all()
        )
        session.execute(
            delete(ServiceTokenFailureBucket).where(
                ServiceTokenFailureBucket.id.in_(overflow_ids)
            )
        )
    session.flush()
    return len(expired_ids) + len(overflow_ids)


def resolve_service_token_source(
    *,
    direct_peer: str | None,
    forwarded_for: Sequence[str],
    trusted_proxy_cidrs: str,
) -> str:
    direct = _parse_ip(direct_peer) or "unknown"
    if direct == "unknown" or not _is_trusted_proxy(direct, trusted_proxy_cidrs):
        return direct
    if len(forwarded_for) != 1 or "," in forwarded_for[0]:
        return direct
    return _parse_ip(forwarded_for[0].strip()) or direct


def service_token_from_authorization(authorization: str | None) -> str:
    if authorization is None:
        return ""
    scheme, separator, value = authorization.partition(" ")
    return value.strip() if separator and scheme.casefold() == "bearer" else ""


def _bucket_specs(
    token: str,
    source: str,
    policy: TokenFailurePolicy,
) -> tuple[tuple[str, str, int], ...]:
    return (
        (DIMENSION_GLOBAL, _GLOBAL_KEY_HASH, policy.global_limit),
        (DIMENSION_SOURCE, _fingerprint(source), policy.source_limit),
        (DIMENSION_TOKEN, _token_fingerprint(token), policy.token_limit),
    )


def _increment_bucket(
    session: Session,
    *,
    dimension: str,
    key_hash: str,
    window_start: datetime,
    expires_at: datetime,
    limit: int,
    max_rows: int,
    now: datetime,
    evict_dimensions: tuple[str, ...],
) -> tuple[ServiceTokenFailureBucket | None, bool]:
    existing = session.scalar(
        select(ServiceTokenFailureBucket).where(
            ServiceTokenFailureBucket.dimension == dimension,
            ServiceTokenFailureBucket.key_hash == key_hash,
            ServiceTokenFailureBucket.window_start == window_start,
        )
    )
    reclaimed_active = False
    if existing is None:
        has_room, reclaimed_active = _make_bucket_room(
            session,
            max_rows=max_rows,
            now=now,
            evict_dimensions=evict_dimensions,
        )
        if not has_room:
            return None, False
    statement = sqlite_insert(ServiceTokenFailureBucket).values(
        dimension=dimension,
        key_hash=key_hash,
        window_start=window_start,
        failure_count=1,
        event_emitted=False,
        expires_at=expires_at,
    )
    statement = statement.on_conflict_do_update(
        index_elements=("dimension", "key_hash", "window_start"),
        set_={
            "failure_count": func.min(
                ServiceTokenFailureBucket.failure_count + 1,
                limit + 1,
            ),
            "expires_at": expires_at,
        },
    )
    session.execute(statement)
    session.flush()
    if existing is not None:
        session.expire(existing)
    return (
        session.scalar(
            select(ServiceTokenFailureBucket).where(
                ServiceTokenFailureBucket.dimension == dimension,
                ServiceTokenFailureBucket.key_hash == key_hash,
                ServiceTokenFailureBucket.window_start == window_start,
            )
        ),
        reclaimed_active,
    )


def _make_bucket_room(
    session: Session,
    *,
    max_rows: int,
    now: datetime,
    evict_dimensions: tuple[str, ...],
) -> tuple[bool, bool]:
    row_count = session.scalar(select(func.count()).select_from(ServiceTokenFailureBucket)) or 0
    if row_count < max_rows:
        return True, False
    expired_id = session.scalar(
        select(ServiceTokenFailureBucket.id)
        .where(ServiceTokenFailureBucket.expires_at <= now)
        .order_by(ServiceTokenFailureBucket.expires_at, ServiceTokenFailureBucket.id)
        .limit(1)
    )
    if expired_id is not None:
        session.execute(
            delete(ServiceTokenFailureBucket).where(
                ServiceTokenFailureBucket.id == expired_id
            )
        )
        session.flush()
        return True, False
    if not evict_dimensions:
        return False, False
    reclaim_id = session.scalar(
        select(ServiceTokenFailureBucket.id)
        .where(ServiceTokenFailureBucket.dimension.in_(evict_dimensions))
        .order_by(ServiceTokenFailureBucket.expires_at, ServiceTokenFailureBucket.id)
        .limit(1)
    )
    if reclaim_id is None:
        return False, False
    session.execute(
        delete(ServiceTokenFailureBucket).where(ServiceTokenFailureBucket.id == reclaim_id)
    )
    session.flush()
    return True, True


def _saturate_bucket(bucket: ServiceTokenFailureBucket, limit: int) -> None:
    bucket.failure_count = max(bucket.failure_count, limit + 1)


def _emit_aggregate_event_if_due(
    session: Session,
    *,
    bucket: ServiceTokenFailureBucket,
    limit: int,
    channel: str,
    request_id: str | None,
    now: datetime,
) -> None:
    if bucket.event_emitted:
        return
    bucket.event_emitted = True
    record_security_event(
        session,
        event_type="service_token_authentication_throttled",
        outcome="denied",
        channel=channel,
        request_id=request_id,
        details={
            "reason": "rate_limited",
            "dimension": bucket.dimension,
            "count": min(bucket.failure_count, limit),
        },
        now=now,
    )


def _window_start(timestamp: datetime, window_seconds: int) -> datetime:
    aware_timestamp = (
        timestamp.replace(tzinfo=UTC) if timestamp.tzinfo is None else timestamp
    )
    epoch_seconds = int(aware_timestamp.timestamp())
    return datetime.fromtimestamp(
        epoch_seconds - (epoch_seconds % window_seconds),
        tz=UTC,
    ).replace(tzinfo=None)


def _token_fingerprint(token: str) -> str:
    bounded = token if len(token) <= 512 else token[:512] + "\0overlong"
    return _fingerprint(bounded)


def _fingerprint(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()


def _parse_ip(value: str | None) -> str | None:
    if value is None or not value or len(value) > 64 or "%" in value:
        return None
    try:
        return ipaddress.ip_address(value).compressed
    except ValueError:
        return None


@lru_cache(maxsize=32)
def _trusted_proxy_networks(
    value: str,
) -> tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]:
    items = tuple(part.strip() for part in value.split(",") if part.strip())
    if len(items) > 64:
        return ()
    try:
        return tuple(ipaddress.ip_network(item, strict=True) for item in items)
    except ValueError:
        return ()


def _is_trusted_proxy(source: str, configured: str) -> bool:
    address = ipaddress.ip_address(source)
    return any(address in network for network in _trusted_proxy_networks(configured))
