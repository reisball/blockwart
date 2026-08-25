"""Authorized release projections, idempotent checks, and leased scheduling."""

from __future__ import annotations

import asyncio
import json
import logging
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from typing import Any

from sqlalchemy import delete, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.orm import Session, sessionmaker

from blockwart.config import Settings, get_settings
from blockwart.db.session import build_engine
from blockwart.domain.auth import ObjectVisibility
from blockwart.domain.release_monitoring import (
    DEFAULT_RELEASE_INTERVAL_SECONDS,
    MIN_RELEASE_CHECK_COOLDOWN_SECONDS,
    RELEASE_STATUSES,
    ReleaseObservation,
    ReleaseRecord,
    read_github_release_target,
    read_release_monitoring_config,
    release_monitoring_view,
    scheduled_release_due,
)
from blockwart.models import (
    CatalogObject,
    ServiceReleaseCheckLease,
    ServiceReleaseObservation,
)
from blockwart.services.pagination import SortDirection, paginate_items
from blockwart.services.read_access import ReadAccess
from blockwart.services.release_github import (
    GithubReleaseRequest,
    fetch_latest_github_release,
)

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class ReleaseMonitoringSettings:
    enabled: bool = False
    poller_enabled: bool = False
    default_interval_seconds: int = DEFAULT_RELEASE_INTERVAL_SECONDS
    connect_timeout_ms: int = 2000
    total_timeout_ms: int = 5000
    max_response_bytes: int = 65536
    max_checks_per_run: int = 10
    lease_seconds: int = 60
    jitter_seconds: int = 3600
    poll_interval_seconds: int = 30


@dataclass(frozen=True, slots=True)
class ReleaseCheckResult:
    object_id: str
    outcome: str
    projection: dict[str, Any] | None
    skipped_reason: str | None = None


@dataclass(frozen=True, slots=True)
class ReleaseRunResult:
    scheduled: int
    released: int
    claimed: int
    completed: int
    skipped_reason: str | None = None


@dataclass(frozen=True, slots=True)
class ReleaseOverviewItem:
    object_id: str
    ref: str
    label: str
    release_monitoring: dict[str, Any]

    @property
    def key(self) -> tuple[str, str]:
        return self.label.casefold(), self.object_id


@dataclass(frozen=True, slots=True)
class ReleaseOverviewPage:
    items: list[ReleaseOverviewItem]
    next_cursor: str | None
    total: int | None
    generated_at: str


def release_monitoring_settings(settings: Settings) -> ReleaseMonitoringSettings:
    return ReleaseMonitoringSettings(
        enabled=settings.release_monitoring_enabled,
        poller_enabled=settings.release_monitoring_poller_enabled,
        default_interval_seconds=settings.release_monitoring_default_interval_seconds,
        connect_timeout_ms=settings.release_monitoring_connect_timeout_ms,
        total_timeout_ms=settings.release_monitoring_total_timeout_ms,
        max_response_bytes=settings.release_monitoring_max_response_bytes,
        max_checks_per_run=settings.release_monitoring_max_checks_per_run,
        lease_seconds=settings.release_monitoring_lease_seconds,
        jitter_seconds=settings.release_monitoring_jitter_seconds,
        poll_interval_seconds=settings.release_monitoring_poll_interval_seconds,
    )


def current_release_monitoring_settings() -> ReleaseMonitoringSettings:
    return release_monitoring_settings(get_settings())


async def run_release_monitoring_poller(
    settings: Settings,
    stop_event: asyncio.Event,
) -> None:
    resolved = release_monitoring_settings(settings)
    if not resolved.enabled or not resolved.poller_enabled:
        return
    try:
        engine = build_engine(settings.database_url)
        sessions = sessionmaker(engine, expire_on_commit=False)
    except Exception:  # noqa: BLE001 - process boundary emits only a stable code
        logger.error("release_monitoring_poller_error code=initialization_failed")
        return
    owner = f"release-poller-{secrets.token_hex(12)}"
    try:
        while not stop_event.is_set():
            try:
                await asyncio.to_thread(_run_poller_pass, sessions, resolved, owner)
            except Exception:  # noqa: BLE001
                logger.error("release_monitoring_poller_error code=check_pass_failed")
            try:
                await asyncio.wait_for(
                    stop_event.wait(),
                    timeout=resolved.poll_interval_seconds,
                )
            except TimeoutError:
                pass
    finally:
        engine.dispose()


def _run_poller_pass(
    sessions: sessionmaker[Session],
    settings: ReleaseMonitoringSettings,
    owner: str,
) -> None:
    with sessions() as session:
        run_due_release_checks(session, settings=settings, owner=owner)


def load_release_observation_index(
    session: Session,
    *,
    object_ids: list[str],
) -> dict[tuple[str, str], ReleaseRecord]:
    if not object_ids:
        return {}
    rows = session.scalars(
        select(ServiceReleaseObservation).where(ServiceReleaseObservation.object_id.in_(object_ids))
    ).all()
    return {(row.object_id, row.provider): _record(row) for row in rows}


def query_release_overview(
    session: Session,
    access: ReadAccess,
    *,
    status: str | None = None,
    limit: int = 50,
    cursor: str | None = None,
    direction: SortDirection = "asc",
    include_total: bool = False,
    now: datetime | None = None,
) -> ReleaseOverviewPage:
    """Return enabled monitors only after full-detail authorization."""

    if status is not None and status not in RELEASE_STATUSES:
        raise ValueError("unknown release status")
    reference = _aware(now or datetime.now(UTC))
    rows = list(
        session.scalars(
            select(CatalogObject)
            .where(CatalogObject.kind == "service")
            .order_by(CatalogObject.label, CatalogObject.id)
        ).all()
    )
    readable = [
        row for row in rows if access.policy.visibility_for(row.id) == ObjectVisibility.DETAIL
    ]
    observations = load_release_observation_index(
        session,
        object_ids=[row.id for row in readable],
    )
    settings = current_release_monitoring_settings()
    items: list[ReleaseOverviewItem] = []
    for row in readable:
        view = release_monitoring_projection(
            kind=row.kind,
            object_id=row.id,
            object_instance_id=row.instance_id,
            data=_object_data(row),
            observations=observations,
            now=reference,
            settings=settings,
        )
        if view is None or not view["enabled"]:
            continue
        if status is not None and view["status"] != status:
            continue
        items.append(
            ReleaseOverviewItem(
                object_id=row.id,
                ref=f"service:{row.id}",
                label=row.label,
                release_monitoring=view,
            )
        )
    page = paginate_items(
        items,
        key=lambda item: item.key,
        limit=limit,
        resource="release-updates",
        sort="label",
        direction=direction,
        query={
            "access": access.cursor_scope,
            "limit": limit,
            "status": status or "",
        },
        cursor=cursor,
        include_total=include_total,
    )
    return ReleaseOverviewPage(
        items=page.items,
        next_cursor=page.next_cursor,
        total=page.total,
        generated_at=reference.isoformat().replace("+00:00", "Z"),
    )


def release_monitoring_projection(
    *,
    kind: str,
    object_id: str,
    object_instance_id: str | None,
    data: dict[str, Any],
    observations: dict[tuple[str, str], ReleaseRecord],
    now: datetime,
    settings: ReleaseMonitoringSettings,
) -> dict[str, Any] | None:
    if kind != "service" or "release_monitoring" not in data:
        return None
    record = observations.get((object_id, "github_releases"))
    if record is not None and record.object_instance_id != object_instance_id:
        record = None
    return release_monitoring_view(
        data=data,
        object_id=object_id,
        record=record,
        now=now,
        default_interval_seconds=settings.default_interval_seconds,
        jitter_seconds=settings.jitter_seconds,
    )


def synchronize_release_schedule(
    session: Session,
    *,
    now: datetime,
    settings: ReleaseMonitoringSettings,
) -> int:
    moment = _aware(now)
    wanted: dict[tuple[str, str], int] = {}
    services = session.scalars(select(CatalogObject).where(CatalogObject.kind == "service")).all()
    services_by_id = {row.id: row for row in services}
    for row in services:
        data = _object_data(row)
        config = read_release_monitoring_config(
            data,
            default_interval_seconds=settings.default_interval_seconds,
        )
        target = read_github_release_target(data)
        if (
            config.valid
            and config.enabled
            and config.provider == "github_releases"
            and config.interval_seconds is not None
            and target.target is not None
        ):
            wanted[(row.id, row.instance_id)] = config.interval_seconds
    observations = {
        (row.object_id, row.object_instance_id): row
        for row in session.scalars(select(ServiceReleaseObservation)).all()
    }
    existing = {
        (row.object_id, row.object_instance_id): row
        for row in session.scalars(select(ServiceReleaseCheckLease)).all()
    }
    created = 0
    for key, lease in existing.items():
        interval = wanted.get(key)
        if interval is None:
            if lease.lease_expires_at is None or lease.lease_expires_at <= _naive(moment):
                session.delete(lease)
            continue
        observation = observations.get(key)
        target = read_github_release_target(_object_data(services_by_id[key[0]])).target
        observation_matches = (
            observation is not None
            and target is not None
            and observation.target_key == target.cache_key
        )
        desired = (
            _naive(observation.next_due_at)
            if observation_matches and observation.next_due_at is not None
            else _naive(_initial_due(moment, *key, settings.jitter_seconds))
        )
        if lease.due_at != desired and lease.lease_owner is None:
            lease.due_at = desired
            lease.updated_at = _naive(moment)
    for key in wanted:
        if key in existing:
            continue
        observation = observations.get(key)
        target = read_github_release_target(_object_data(services_by_id[key[0]])).target
        observation_matches = (
            observation is not None
            and target is not None
            and observation.target_key == target.cache_key
        )
        due = (
            _aware(observation.next_due_at)
            if observation_matches and observation.next_due_at is not None
            else _initial_due(moment, *key, settings.jitter_seconds)
        )
        values = {
            "object_id": key[0],
            "object_instance_id": key[1],
            "provider": "github_releases",
            "due_at": _naive(due),
            "created_at": _naive(moment),
            "updated_at": _naive(moment),
        }
        table = ServiceReleaseCheckLease.__table__
        insert = (
            sqlite_insert(table)
            if session.get_bind().dialect.name == "sqlite"
            else pg_insert(table)
        )
        result = session.execute(
            insert.values(**values).on_conflict_do_nothing(
                index_elements=["object_id", "object_instance_id"]
            )
        )
        created += int(result.rowcount or 0)
    _prune_dead_rows(session)
    session.flush()
    return created


def check_service_release(
    session: Session,
    *,
    object_id: str,
    settings: ReleaseMonitoringSettings,
    manual: bool,
    now: datetime | None = None,
    owner: str | None = None,
) -> ReleaseCheckResult:
    """Run the one application path shared by scheduled and manual checks."""

    if not settings.enabled:
        return ReleaseCheckResult(object_id, "skipped", None, "runtime_disabled")
    row = session.get(CatalogObject, object_id)
    if row is None or row.kind != "service":
        return ReleaseCheckResult(object_id, "skipped", None, "not_found")
    data = _object_data(row)
    config = read_release_monitoring_config(
        data,
        default_interval_seconds=settings.default_interval_seconds,
    )
    resolution = read_github_release_target(data)
    if (
        not config.valid
        or not config.enabled
        or config.provider != "github_releases"
        or config.interval_seconds is None
        or resolution.target is None
    ):
        moment = _aware(now or _utcnow())
        projection = release_monitoring_view(
            data=data,
            object_id=object_id,
            record=None,
            now=moment,
            default_interval_seconds=settings.default_interval_seconds,
            jitter_seconds=settings.jitter_seconds,
        )
        return ReleaseCheckResult(object_id, "skipped", projection, "not_checkable")
    observation_row = session.scalar(
        select(ServiceReleaseObservation).where(
            ServiceReleaseObservation.object_id == row.id,
            ServiceReleaseObservation.object_instance_id == row.instance_id,
            ServiceReleaseObservation.provider == "github_releases",
        )
    )
    # The pass timestamp is only a due-selection snapshot. A scheduled pass may
    # spend most of one lease duration checking earlier services, so acquire a
    # fresh timestamp immediately before this service's conditional claim.
    claim_at = _aware(now or _utcnow())
    if (
        manual
        and observation_row is not None
        and observation_row.target_key == resolution.target.cache_key
        and observation_row.last_checked_at is not None
        and _aware(observation_row.last_checked_at)
        + timedelta(seconds=MIN_RELEASE_CHECK_COOLDOWN_SECONDS)
        > claim_at
    ):
        return ReleaseCheckResult(
            object_id,
            "skipped",
            release_monitoring_view(
                data=data,
                object_id=object_id,
                record=_record(observation_row),
                now=claim_at,
                default_interval_seconds=settings.default_interval_seconds,
                jitter_seconds=settings.jitter_seconds,
            ),
            "cooldown",
        )
    lease_owner = owner or f"release-check-{secrets.token_hex(8)}"
    lease = _claim_service(
        session,
        row=row,
        owner=lease_owner,
        now=claim_at,
        settings=settings,
        force=manual,
    )
    session.commit()
    if lease is None:
        return ReleaseCheckResult(object_id, "skipped", None, "already_claimed_or_not_due")
    # Re-read every catalog-controlled input after the claim, then close the
    # transaction before acquisition. A stale claim can never discover a new target.
    row = session.get(CatalogObject, object_id)
    if row is None or row.kind != "service" or row.instance_id != lease.object_instance_id:
        _delete_claim(session, lease.id, lease_owner)
        session.commit()
        return ReleaseCheckResult(object_id, "skipped", None, "changed")
    data = _object_data(row)
    config = read_release_monitoring_config(
        data,
        default_interval_seconds=settings.default_interval_seconds,
    )
    resolution = read_github_release_target(data)
    if (
        not config.valid
        or not config.enabled
        or config.provider != lease.provider
        or config.interval_seconds is None
        or resolution.target is None
    ):
        _delete_claim(session, lease.id, lease_owner)
        session.commit()
        return ReleaseCheckResult(object_id, "skipped", None, "changed")
    current = session.scalar(
        select(ServiceReleaseObservation).where(
            ServiceReleaseObservation.object_id == row.id,
            ServiceReleaseObservation.object_instance_id == row.instance_id,
            ServiceReleaseObservation.provider == lease.provider,
        )
    )
    request = GithubReleaseRequest(
        target=resolution.target,
        etag=(
            current.release_etag
            if current is not None and current.target_key == resolution.target.cache_key
            else None
        ),
        connect_timeout_ms=settings.connect_timeout_ms,
        total_timeout_ms=settings.total_timeout_ms,
        max_response_bytes=settings.max_response_bytes,
    )
    session.commit()
    try:
        observed = fetch_latest_github_release(request)
    except Exception:  # noqa: BLE001 - provider boundary is stable and redacted
        observed = ReleaseObservation(
            provider="github_releases",
            outcome="error",
            checked_at=claim_at,
            error_code="provider_failed",
        )
    record = record_release_observation(
        session,
        object_id=row.id,
        object_instance_id=row.instance_id,
        target_key=resolution.target.cache_key,
        observation=observed,
        interval_seconds=config.interval_seconds,
        settings=settings,
    )
    if record is None:
        _delete_claim(session, lease.id, lease_owner)
        session.commit()
        return ReleaseCheckResult(object_id, "skipped", None, "changed")
    session.execute(
        update(ServiceReleaseCheckLease)
        .where(
            ServiceReleaseCheckLease.id == lease.id,
            ServiceReleaseCheckLease.lease_owner == lease_owner,
        )
        .values(
            lease_owner=None,
            lease_expires_at=None,
            due_at=_naive(record.next_due_at or claim_at),
            updated_at=_naive(observed.checked_at),
        )
    )
    session.commit()
    return ReleaseCheckResult(
        object_id,
        observed.outcome,
        release_monitoring_view(
            data=data,
            object_id=object_id,
            record=record,
            now=observed.checked_at,
            default_interval_seconds=settings.default_interval_seconds,
            jitter_seconds=settings.jitter_seconds,
        ),
    )


def record_release_observation(
    session: Session,
    *,
    object_id: str,
    object_instance_id: str,
    target_key: str,
    observation: ReleaseObservation,
    interval_seconds: int,
    settings: ReleaseMonitoringSettings,
) -> ReleaseRecord | None:
    live = session.get(CatalogObject, object_id)
    if live is None or live.kind != "service" or live.instance_id != object_instance_id:
        return None
    live_target = read_github_release_target(_object_data(live)).target
    if live_target is None or live_target.cache_key != target_key:
        return None
    row = session.scalar(
        select(ServiceReleaseObservation).where(
            ServiceReleaseObservation.object_id == object_id,
            ServiceReleaseObservation.object_instance_id == object_instance_id,
            ServiceReleaseObservation.provider == observation.provider,
        )
    )
    if (
        row is not None
        and row.target_key == target_key
        and row.last_checked_at is not None
        and _aware(row.last_checked_at) >= _aware(observation.checked_at)
    ):
        return _record(row)
    if row is None:
        row = ServiceReleaseObservation(
            object_id=object_id,
            object_instance_id=object_instance_id,
            provider=observation.provider,
        )
        session.add(row)
    elif row.target_key != target_key:
        row.latest_tag = None
        row.latest_version = None
        row.released_at = None
        row.release_etag = None
        row.http_status = None
        row.error_code = None
        row.consecutive_failures = 0
        row.last_checked_at = None
        row.last_success_at = None
        row.next_due_at = None
    row.target_key = target_key
    failures = (row.consecutive_failures or 0) + 1 if observation.outcome == "error" else 0
    if observation.outcome == "observed":
        row.latest_tag = observation.latest_tag
        row.latest_version = observation.latest_version
        row.released_at = _naive(observation.released_at)
        row.release_etag = observation.etag
        row.last_success_at = _naive(observation.checked_at)
    elif observation.outcome == "not_modified":
        if row.latest_tag is None:
            observation = ReleaseObservation(
                provider=observation.provider,
                outcome="error",
                checked_at=observation.checked_at,
                http_status=304,
                error_code="unreadable_release",
            )
            failures = (row.consecutive_failures or 0) + 1
        else:
            row.release_etag = observation.etag or row.release_etag
            row.last_success_at = _naive(observation.checked_at)
    row.http_status = observation.http_status
    row.error_code = observation.error_code
    row.consecutive_failures = failures
    row.last_checked_at = _naive(observation.checked_at)
    due = scheduled_release_due(
        observation.checked_at,
        object_id=object_id,
        object_instance_id=object_instance_id,
        provider=observation.provider,
        interval_seconds=interval_seconds,
        jitter_seconds=settings.jitter_seconds,
        consecutive_failures=failures,
        retry_after_seconds=observation.retry_after_seconds,
    )
    row.next_due_at = _naive(due)
    row.updated_at = _naive(observation.checked_at)
    session.flush()
    return _record(row)


def run_due_release_checks(
    session: Session,
    *,
    settings: ReleaseMonitoringSettings,
    now: datetime | None = None,
    owner: str | None = None,
) -> ReleaseRunResult:
    moment = _aware(now or datetime.now(UTC))
    if not settings.enabled:
        return ReleaseRunResult(0, 0, 0, 0, "runtime_disabled")
    if not settings.poller_enabled:
        return ReleaseRunResult(0, 0, 0, 0, "poller_disabled")
    scheduled = synchronize_release_schedule(session, now=moment, settings=settings)
    released = _release_expired(session, moment)
    session.commit()
    object_ids = list(
        session.scalars(
            select(ServiceReleaseCheckLease.object_id)
            .where(ServiceReleaseCheckLease.due_at <= _naive(moment))
            .order_by(ServiceReleaseCheckLease.due_at, ServiceReleaseCheckLease.id)
            .limit(settings.max_checks_per_run)
        ).all()
    )
    completed = 0
    claimed = 0
    base_owner = owner or f"release-run-{secrets.token_hex(8)}"
    for index, object_id in enumerate(object_ids):
        result = check_service_release(
            session,
            object_id=object_id,
            settings=settings,
            manual=False,
            owner=f"{base_owner}-{index}",
        )
        if result.skipped_reason != "already_claimed_or_not_due":
            claimed += 1
        if result.skipped_reason is None:
            completed += 1
    return ReleaseRunResult(scheduled, released, claimed, completed)


def _claim_service(
    session: Session,
    *,
    row: CatalogObject,
    owner: str,
    now: datetime,
    settings: ReleaseMonitoringSettings,
    force: bool,
) -> ServiceReleaseCheckLease | None:
    table = ServiceReleaseCheckLease.__table__
    values = {
        "object_id": row.id,
        "object_instance_id": row.instance_id,
        "provider": "github_releases",
        "due_at": _naive(now),
        "created_at": _naive(now),
        "updated_at": _naive(now),
    }
    insert = (
        sqlite_insert(table) if session.get_bind().dialect.name == "sqlite" else pg_insert(table)
    )
    session.execute(
        insert.values(**values).on_conflict_do_nothing(
            index_elements=["object_id", "object_instance_id"]
        )
    )
    session.flush()
    conditions = [
        ServiceReleaseCheckLease.object_id == row.id,
        ServiceReleaseCheckLease.object_instance_id == row.instance_id,
        (ServiceReleaseCheckLease.lease_expires_at.is_(None))
        | (ServiceReleaseCheckLease.lease_expires_at <= _naive(now)),
    ]
    if not force:
        conditions.append(ServiceReleaseCheckLease.due_at <= _naive(now))
    result = session.execute(
        update(ServiceReleaseCheckLease)
        .where(*conditions)
        .values(
            lease_owner=owner,
            lease_expires_at=_naive(now + timedelta(seconds=settings.lease_seconds)),
            updated_at=_naive(now),
        )
    )
    if result.rowcount != 1:
        return None
    return session.scalar(
        select(ServiceReleaseCheckLease).where(
            ServiceReleaseCheckLease.object_id == row.id,
            ServiceReleaseCheckLease.object_instance_id == row.instance_id,
            ServiceReleaseCheckLease.lease_owner == owner,
        )
    )


def _release_expired(session: Session, now: datetime) -> int:
    result = session.execute(
        update(ServiceReleaseCheckLease)
        .where(
            ServiceReleaseCheckLease.lease_expires_at.is_not(None),
            ServiceReleaseCheckLease.lease_expires_at <= _naive(now),
        )
        .values(lease_owner=None, lease_expires_at=None, updated_at=_naive(now))
    )
    return int(result.rowcount or 0)


def _delete_claim(session: Session, lease_id: int, owner: str) -> None:
    session.execute(
        delete(ServiceReleaseCheckLease).where(
            ServiceReleaseCheckLease.id == lease_id,
            ServiceReleaseCheckLease.lease_owner == owner,
        )
    )


def _prune_dead_rows(session: Session) -> None:
    live_observation = select(CatalogObject.id).where(
        CatalogObject.id == ServiceReleaseObservation.object_id,
        CatalogObject.instance_id == ServiceReleaseObservation.object_instance_id,
        CatalogObject.kind == "service",
    )
    live_lease = select(CatalogObject.id).where(
        CatalogObject.id == ServiceReleaseCheckLease.object_id,
        CatalogObject.instance_id == ServiceReleaseCheckLease.object_instance_id,
        CatalogObject.kind == "service",
    )
    session.execute(delete(ServiceReleaseObservation).where(~live_observation.exists()))
    session.execute(delete(ServiceReleaseCheckLease).where(~live_lease.exists()))


def _record(row: ServiceReleaseObservation) -> ReleaseRecord:
    return ReleaseRecord(
        provider=row.provider,
        target_key=row.target_key,
        latest_tag=row.latest_tag,
        latest_version=row.latest_version,
        released_at=row.released_at,
        etag=row.release_etag,
        http_status=row.http_status,
        error_code=row.error_code,
        consecutive_failures=row.consecutive_failures,
        last_checked_at=row.last_checked_at,
        last_success_at=row.last_success_at,
        next_due_at=row.next_due_at,
        object_instance_id=row.object_instance_id,
    )


def _object_data(row: CatalogObject) -> dict[str, Any]:
    try:
        value = json.loads(row.data_json)
    except (TypeError, json.JSONDecodeError):
        return {}
    return value if isinstance(value, dict) else {}


def _initial_due(
    now: datetime,
    object_id: str,
    object_instance_id: str,
    jitter_seconds: int,
) -> datetime:
    if jitter_seconds <= 0:
        return now
    key = f"{object_id}\x1f{object_instance_id}\x1fgithub_releases"
    digest = sha256(key.encode("utf-8")).digest()
    return now + timedelta(seconds=int.from_bytes(digest[:8], "big") % (jitter_seconds + 1))


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


def _naive(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return _aware(value).astimezone(UTC).replace(tzinfo=None)


def _utcnow() -> datetime:
    return datetime.now(UTC)
