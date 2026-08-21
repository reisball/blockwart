"""Provider-neutral observation storage, projection, and leased scheduling.

This module owns everything a monitoring provider must not re-implement:

- one bounded read of the authorized observation index per request;
- the single monitoring projection every surface renders;
- the ingestion seam ``record_service_observation`` that a later receiver
  (for example the Gatus webhook tracked in #177) calls without touching the
  catalog, its revision, or its audit timeline;
- the database-backed lease that makes polling safe with multiple web
  processes.

Writing an observation never updates ``catalog_objects``. Polling therefore
cannot advance an object revision, move the business ``updated_at``, or emit a
repetitive object audit event.
"""

from __future__ import annotations

import asyncio
import json
import logging
import secrets
from collections.abc import Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import case, delete, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.orm import Session, sessionmaker

from blockwart.config import Settings, get_settings
from blockwart.db.session import build_engine
from blockwart.domain.monitoring import (
    DEFAULT_MONITORING_INTERVAL_SECONDS,
    MonitoringObservation,
    MonitoringRecord,
    monitoring_view,
    read_monitoring_config,
    resolve_monitoring_target,
    scheduled_next_due,
)
from blockwart.domain.monitoring_policy import (
    MonitoringPolicyError,
    TargetPolicy,
    parse_target_policy,
)
from blockwart.domain.timestamps import format_rfc3339_utc
from blockwart.models import CatalogObject, ServiceCheckLease, ServiceObservation
from blockwart.services.monitoring_registry import (
    ProbeLimits,
    ProviderCheckRequest,
    get_provider,
    has_provider,
    polling_providers,
)

logger = logging.getLogger(__name__)

# The observation index is keyed by object id and provider. The instance is not
# part of the key because the loading query already joins the live catalog row,
# so an observation left over from a deleted-and-recreated object id can never
# enter the index.
ObservationIndex = Mapping[tuple[str, str], MonitoringRecord]


@dataclass(frozen=True, slots=True)
class MonitoringSettings:
    """The deployment envelope for monitoring, resolved once per run."""

    poller_enabled: bool = False
    default_interval_seconds: int = DEFAULT_MONITORING_INTERVAL_SECONDS
    policy: TargetPolicy = TargetPolicy()
    connect_timeout_ms: int = 2000
    total_timeout_ms: int = 5000
    max_response_bytes: int = 65536
    max_checks_per_run: int = 20
    max_concurrent_checks: int = 4
    lease_seconds: int = 60
    jitter_seconds: int = 30
    poll_interval_seconds: int = 5

    @property
    def limits(self) -> ProbeLimits:
        return ProbeLimits(
            policy=self.policy,
            connect_timeout_ms=self.connect_timeout_ms,
            total_timeout_ms=self.total_timeout_ms,
            max_response_bytes=self.max_response_bytes,
        )


@dataclass(frozen=True, slots=True)
class DueCheck:
    lease_id: int
    object_id: str
    object_instance_id: str
    provider: str


@dataclass(frozen=True, slots=True)
class MonitoringRunResult:
    scheduled: int
    released: int
    claimed: int
    completed: int
    skipped_reason: str | None = None


def monitoring_settings(settings: Settings) -> MonitoringSettings:
    """Resolve the runtime envelope, failing closed on an unusable allowlist."""

    return MonitoringSettings(
        poller_enabled=settings.monitoring_poller_enabled,
        default_interval_seconds=settings.monitoring_default_interval_seconds,
        policy=parse_target_policy(
            allowed_networks=settings.monitoring_allowed_target_networks,
            allowed_ports=settings.monitoring_allowed_target_ports,
        ),
        connect_timeout_ms=settings.monitoring_connect_timeout_ms,
        total_timeout_ms=settings.monitoring_total_timeout_ms,
        max_response_bytes=settings.monitoring_max_response_bytes,
        max_checks_per_run=settings.monitoring_max_checks_per_run,
        max_concurrent_checks=settings.monitoring_max_concurrent_checks,
        lease_seconds=settings.monitoring_lease_seconds,
        jitter_seconds=settings.monitoring_jitter_seconds,
        poll_interval_seconds=settings.monitoring_poll_interval_seconds,
    )


async def run_monitoring_poller(
    settings: Settings,
    stop_event: asyncio.Event,
) -> None:
    """Run bounded due-check passes until application shutdown.

    Every web process may run this loop. Database leases, rather than process
    identity, decide the winner for each service, so worker count does not
    change the at-most-one-check guarantee.
    """

    try:
        resolved = monitoring_settings(settings)
        if not resolved.poller_enabled:
            return
        engine = build_engine(
            settings.database_url,
            sqlite_busy_timeout_ms=settings.sqlite_busy_timeout_ms,
            sqlite_wal_enabled=settings.sqlite_wal_enabled,
        )
    except Exception:  # noqa: BLE001 - never log database/config exception text
        logger.error("monitoring_poller_error code=initialization_failed")
        return
    sessions = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    owner = f"poller-{secrets.token_hex(12)}"
    try:
        while not stop_event.is_set():
            await asyncio.to_thread(_run_poller_pass, sessions, resolved, owner)
            try:
                await asyncio.wait_for(
                    stop_event.wait(),
                    timeout=resolved.poll_interval_seconds,
                )
            except TimeoutError:
                pass
    finally:
        try:
            await asyncio.to_thread(engine.dispose)
        except Exception:  # noqa: BLE001 - never log database exception text
            logger.error("monitoring_poller_error code=shutdown_failed")


def _run_poller_pass(
    sessions: sessionmaker[Session],
    settings: MonitoringSettings,
    owner: str,
) -> None:
    with sessions() as session:
        try:
            run_due_service_checks(session, settings=settings, owner=owner)
        except Exception:  # noqa: BLE001 - keep the worker alive with redacted logging
            session.rollback()
            logger.error("monitoring_poller_error code=check_pass_failed")


def load_observation_index(
    session: Session,
    *,
    object_ids: Sequence[str] | None = None,
) -> dict[tuple[str, str], MonitoringRecord]:
    """Load every live service observation in one bounded query.

    The join against ``catalog_objects`` on the instance id is the object-ID
    reuse guard: a recreated object never inherits the previous row's history.
    Loading the whole index at once also keeps per-object work constant, so a
    concealed or discover-only object cannot be distinguished by timing.
    """

    statement = (
        select(ServiceObservation)
        .join(
            CatalogObject,
            (CatalogObject.id == ServiceObservation.object_id)
            & (CatalogObject.instance_id == ServiceObservation.object_instance_id),
        )
        .where(CatalogObject.kind == "service")
    )
    if object_ids is not None:
        unique_ids = sorted(set(object_ids))
        if not unique_ids:
            return {}
        statement = statement.where(ServiceObservation.object_id.in_(unique_ids))
    return {
        (row.object_id, row.provider): _record(row)
        for row in session.scalars(statement).all()
    }


def monitoring_projection(
    *,
    kind: str,
    object_id: str,
    data: Mapping[str, Any],
    catalog_health: str | None,
    observations: ObservationIndex,
    now: datetime,
    settings: MonitoringSettings | None = None,
) -> dict[str, Any] | None:
    """Return the one shared monitoring read model, or ``None`` for non-services."""

    if kind != "service":
        return None
    resolved = settings or MonitoringSettings()
    config = read_monitoring_config(
        data,
        default_interval_seconds=resolved.default_interval_seconds,
    )
    record = (
        observations.get((object_id, config.provider))
        if config.valid and config.provider is not None
        else None
    )
    return monitoring_view(
        data=data,
        object_id=object_id,
        catalog_health=catalog_health,
        record=record,
        now=now,
        default_interval_seconds=resolved.default_interval_seconds,
        jitter_seconds=resolved.jitter_seconds,
    )


def record_service_observation(
    session: Session,
    *,
    object_id: str,
    object_instance_id: str,
    observation: MonitoringObservation,
    now: datetime | None = None,
    settings: MonitoringSettings | None = None,
    report_written: bool = False,
) -> MonitoringRecord | None | tuple[MonitoringRecord | None, bool]:
    """Ingest one canonical observation for a service.

    This is the seam every provider shares. A push-based receiver validates and
    authorizes its own transport, converts its payload into a
    ``MonitoringObservation``, and calls exactly this function; no vendor field
    reaches storage or any read model.

    The caller must name the concrete catalog-object instance it observed.
    Returns ``None`` when that instance no longer exists or is not a service;
    this prevents a delayed check or receiver delivery from crossing an
    object-ID delete/recreate boundary.

    With ``report_written=True`` the return is ``(record, written)`` instead of
    just ``record``. ``written`` is True only when this delivery actually
    inserted or advanced a row; a duplicate or stale replay that the conflict
    guard rejected reports ``(record, False)``. A push receiver uses this to
    answer "did this delivery land?" truthfully instead of pretending a
    rejected replay was stored.
    """

    resolved = settings or MonitoringSettings()
    moment = _aware(now or datetime.now(UTC))
    catalog_object = session.get(CatalogObject, object_id)
    if (
        catalog_object is None
        or catalog_object.kind != "service"
        or catalog_object.instance_id != object_instance_id
    ):
        return None
    config = read_monitoring_config(
        _object_data(catalog_object),
        default_interval_seconds=resolved.default_interval_seconds,
    )
    if not config.valid or config.interval_seconds is None:
        return None
    checked_at = _aware(observation.checked_at)
    next_due_at = _next_due(
        checked_at,
        object_id=object_id,
        object_instance_id=object_instance_id,
        provider=observation.provider,
        interval_seconds=config.interval_seconds,
        jitter_seconds=resolved.jitter_seconds,
    )
    identity = {
        "object_id": object_id,
        "object_instance_id": object_instance_id,
        "provider": observation.provider,
    }
    values = {
        **identity,
        "state": observation.state,
        "http_status": observation.http_status,
        "latency_ms": observation.latency_ms,
        "error_code": observation.error_code,
        "last_checked_at": _naive(checked_at),
        "last_success_at": (
            _naive(checked_at) if observation.state == "healthy" else None
        ),
        "next_due_at": _naive(next_due_at),
        "updated_at": _naive(moment),
    }
    table = ServiceObservation.__table__
    dialect = session.get_bind().dialect.name
    insert = sqlite_insert(table) if dialect == "sqlite" else pg_insert(table)
    excluded = insert.excluded
    statement = insert.values(**values).on_conflict_do_update(
        index_elements=["object_id", "object_instance_id", "provider"],
        set_={
            "state": excluded.state,
            "http_status": excluded.http_status,
            "latency_ms": excluded.latency_ms,
            "error_code": excluded.error_code,
            "last_checked_at": excluded.last_checked_at,
            "last_success_at": case(
                (excluded.state == "healthy", excluded.last_checked_at),
                else_=table.c.last_success_at,
            ),
            "next_due_at": excluded.next_due_at,
            "updated_at": excluded.updated_at,
        },
        where=(
            table.c.last_checked_at.is_(None)
            | (excluded.last_checked_at > table.c.last_checked_at)
        ),
    )
    result = session.execute(statement)
    row = session.scalars(
        select(ServiceObservation).where(
            ServiceObservation.object_id == object_id,
            ServiceObservation.object_instance_id == object_instance_id,
            ServiceObservation.provider == observation.provider,
        )
    ).one()
    record = _record(row)
    if report_written:
        # A genuine insert/update touched exactly one row. A stale or
        # duplicate delivery that the ``on_conflict_do_update`` guard rejected
        # performs no write and reports rowcount 0, so ``written`` is False
        # even though the existing row is returned.
        written = int(result.rowcount or 0) == 1
        return record, written
    return record


def synchronize_check_schedule(
    session: Session,
    *,
    now: datetime | None = None,
    settings: MonitoringSettings | None = None,
) -> int:
    """Reconcile lease rows with the current monitoring configuration.

    A newly enabled service receives a jittered first due time instead of being
    due immediately, so enabling several services — or restarting every web
    process — cannot produce a polling storm.
    """

    resolved = settings or MonitoringSettings()
    moment = _aware(now or datetime.now(UTC))
    drivers = set(polling_providers())

    wanted: dict[tuple[str, str], tuple[str, int]] = {}
    services = session.scalars(
        select(CatalogObject).where(CatalogObject.kind == "service")
    ).all()
    for catalog_object in services:
        config = read_monitoring_config(
            _object_data(catalog_object),
            default_interval_seconds=resolved.default_interval_seconds,
        )
        if (
            not config.valid
            or not config.enabled
            or config.provider not in drivers
            or config.interval_seconds is None
        ):
            continue
        assert config.provider is not None
        wanted[(catalog_object.id, catalog_object.instance_id)] = (
            config.provider,
            config.interval_seconds,
        )

    observations = {
        (row.object_id, row.object_instance_id, row.provider): row
        for row in session.scalars(select(ServiceObservation)).all()
    }

    existing = {
        (row.object_id, row.object_instance_id): row
        for row in session.scalars(select(ServiceCheckLease)).all()
    }
    for key, row in existing.items():
        if key not in wanted:
            if row.lease_expires_at is None or row.lease_expires_at <= _naive(moment):
                session.delete(row)
            continue
        selected_provider, interval_seconds = wanted[key]
        if row.provider != selected_provider and (
            row.lease_expires_at is None or row.lease_expires_at <= _naive(moment)
        ):
            row.provider = selected_provider
            row.due_at = _naive(
                _initial_due(
                    moment,
                    object_id=row.object_id,
                    object_instance_id=row.object_instance_id,
                    provider=selected_provider,
                    jitter_seconds=resolved.jitter_seconds,
                )
            )
            row.lease_owner = None
            row.lease_expires_at = None
            row.updated_at = _naive(moment)
        if row.provider != selected_provider:
            continue
        observation = observations.get((*key, selected_provider))
        if observation is None or observation.last_checked_at is None:
            continue
        desired_due = _next_due(
            _aware(observation.last_checked_at),
            object_id=row.object_id,
            object_instance_id=row.object_instance_id,
            provider=selected_provider,
            interval_seconds=interval_seconds,
            jitter_seconds=resolved.jitter_seconds,
        )
        desired_naive = _naive(desired_due)
        if observation.next_due_at != desired_naive:
            observation.next_due_at = desired_naive
            observation.updated_at = _naive(moment)
        if row.due_at != desired_naive:
            row.due_at = desired_naive
            row.updated_at = _naive(moment)
    created = 0
    for (object_id, instance_id), (provider, interval_seconds) in wanted.items():
        if (object_id, instance_id) in existing:
            continue
        observation = observations.get((object_id, instance_id, provider))
        due_at = (
            _next_due(
                _aware(observation.last_checked_at),
                object_id=object_id,
                object_instance_id=instance_id,
                provider=provider,
                interval_seconds=interval_seconds,
                jitter_seconds=resolved.jitter_seconds,
            )
            if observation is not None and observation.last_checked_at is not None
            else _initial_due(
                moment,
                object_id=object_id,
                object_instance_id=instance_id,
                provider=provider,
                jitter_seconds=resolved.jitter_seconds,
            )
        )
        if observation is not None and observation.next_due_at != _naive(due_at):
            observation.next_due_at = _naive(due_at)
            observation.updated_at = _naive(moment)
        values = {
            "object_id": object_id,
            "object_instance_id": instance_id,
            "provider": provider,
            "due_at": _naive(due_at),
            "created_at": _naive(moment),
            "updated_at": _naive(moment),
        }
        table = ServiceCheckLease.__table__
        dialect = session.get_bind().dialect.name
        insert = sqlite_insert(table) if dialect == "sqlite" else pg_insert(table)
        result = session.execute(
            insert.values(**values).on_conflict_do_nothing(
                index_elements=["object_id", "object_instance_id"]
            )
        )
        created += int(result.rowcount or 0)
    _prune_dead_observations(session)
    session.flush()
    return created


def claim_due_checks(
    session: Session,
    *,
    owner: str,
    now: datetime | None = None,
    settings: MonitoringSettings | None = None,
) -> list[DueCheck]:
    """Claim due leases with one conditional UPDATE each.

    The guard is re-evaluated inside the UPDATE, so two processes selecting the
    same candidate rows still produce exactly one winner per service on both
    SQLite and PostgreSQL, without ``SKIP LOCKED`` or a vendor-specific lock.
    """

    resolved = settings or MonitoringSettings()
    moment = _aware(now or datetime.now(UTC))
    naive_now = _naive(moment)
    expiry = _naive(moment + timedelta(seconds=resolved.lease_seconds))
    candidates = session.scalars(
        select(ServiceCheckLease)
        .where(
            ServiceCheckLease.due_at <= naive_now,
            (ServiceCheckLease.lease_expires_at.is_(None))
            | (ServiceCheckLease.lease_expires_at <= naive_now),
        )
        .order_by(ServiceCheckLease.due_at, ServiceCheckLease.id)
        # Never claim work that will wait behind this process's acquisition
        # pool. Every claimed network check can therefore start immediately,
        # and one lease only needs to cover one bounded adapter deadline.
        .limit(min(resolved.max_checks_per_run, resolved.max_concurrent_checks))
    ).all()
    claimed: list[DueCheck] = []
    for candidate in candidates:
        result = session.execute(
            update(ServiceCheckLease)
            .where(
                ServiceCheckLease.id == candidate.id,
                ServiceCheckLease.due_at <= naive_now,
                (ServiceCheckLease.lease_expires_at.is_(None))
                | (ServiceCheckLease.lease_expires_at <= naive_now),
            )
            .values(
                lease_owner=owner,
                lease_expires_at=expiry,
                updated_at=naive_now,
            )
        )
        if result.rowcount != 1:
            continue
        claimed.append(
            DueCheck(
                lease_id=candidate.id,
                object_id=candidate.object_id,
                object_instance_id=candidate.object_instance_id,
                provider=candidate.provider,
            )
        )
    session.commit()
    return claimed


def release_check_lease(
    session: Session,
    *,
    lease_id: int,
    owner: str,
    next_due_at: datetime,
    now: datetime | None = None,
) -> None:
    """Return one claimed lease and schedule its next jittered due time."""

    moment = _aware(now or datetime.now(UTC))
    session.execute(
        update(ServiceCheckLease)
        .where(
            ServiceCheckLease.id == lease_id,
            ServiceCheckLease.lease_owner == owner,
        )
        .values(
            lease_owner=None,
            lease_expires_at=None,
            due_at=_naive(next_due_at),
            updated_at=_naive(moment),
        )
    )


def run_due_service_checks(
    session: Session,
    *,
    settings: MonitoringSettings,
    now: datetime | None = None,
    owner: str | None = None,
) -> MonitoringRunResult:
    """Run one bounded scheduler pass.

    The pass is deliberately bounded and opt-in. It is called by the disabled-
    by-default application poller or explicitly by the database operations CLI.
    """

    moment = _aware(now or datetime.now(UTC))
    if not settings.poller_enabled:
        return MonitoringRunResult(0, 0, 0, 0, skipped_reason="poller_disabled")
    scheduled = synchronize_check_schedule(session, now=moment, settings=settings)
    released = _release_expired_leases(session, now=moment)
    session.commit()

    lease_owner = owner or f"{secrets.token_hex(8)}"
    claims = claim_due_checks(
        session,
        owner=lease_owner,
        now=moment,
        settings=settings,
    )
    if not claims:
        return MonitoringRunResult(scheduled, released, 0, 0)

    pending_requests: list[tuple[DueCheck, ProviderCheckRequest, int]] = []
    completed = 0
    for claim in claims:
        catalog_object = session.get(CatalogObject, claim.object_id)
        if (
            catalog_object is None
            or catalog_object.kind != "service"
            or catalog_object.instance_id != claim.object_instance_id
        ):
            _delete_claimed_lease(session, claim.lease_id, lease_owner)
            continue
        data = _object_data(catalog_object)
        config = read_monitoring_config(
            data,
            default_interval_seconds=settings.default_interval_seconds,
        )
        if (
            not config.valid
            or not config.enabled
            or config.provider != claim.provider
            or config.interval_seconds is None
        ):
            _delete_claimed_lease(session, claim.lease_id, lease_owner)
            continue
        current_observation = session.scalar(
            select(ServiceObservation).where(
                ServiceObservation.object_id == claim.object_id,
                ServiceObservation.object_instance_id == claim.object_instance_id,
                ServiceObservation.provider == claim.provider,
            )
        )
        if current_observation is not None and current_observation.last_checked_at is not None:
            current_due = _next_due(
                _aware(current_observation.last_checked_at),
                object_id=claim.object_id,
                object_instance_id=claim.object_instance_id,
                provider=claim.provider,
                interval_seconds=config.interval_seconds,
                jitter_seconds=settings.jitter_seconds,
            )
            current_observation.next_due_at = _naive(current_due)
            current_observation.updated_at = _naive(moment)
            if current_due > moment:
                release_check_lease(
                    session,
                    lease_id=claim.lease_id,
                    owner=lease_owner,
                    next_due_at=current_due,
                    now=moment,
                )
                continue
        resolution = resolve_monitoring_target(data, object_id=claim.object_id)
        if resolution.target is None:
            record = record_service_observation(
                session,
                object_id=claim.object_id,
                object_instance_id=claim.object_instance_id,
                observation=MonitoringObservation(
                    provider=claim.provider,
                    state="check_error",
                    checked_at=moment,
                    error_code="invalid_target",
                ),
                now=moment,
                settings=settings,
            )
            if record is not None and record.next_due_at is not None:
                release_check_lease(
                    session,
                    lease_id=claim.lease_id,
                    owner=lease_owner,
                    next_due_at=record.next_due_at,
                    now=moment,
                )
                completed += 1
            continue
        pending_requests.append(
            (
                claim,
                ProviderCheckRequest(
                    object_id=claim.object_id,
                    target=resolution.target,
                    diagnostic=resolution.diagnostic,
                    limits=settings.limits,
                ),
                config.interval_seconds,
            )
        )

    # Renew immediately before acquisition. If catalog/config processing ever
    # consumed the original lease, skip the expired claim rather than racing a
    # process that may already have reclaimed it. Claims are capped to the
    # worker count, so every renewed request starts without a local queue.
    renewal_time = datetime.now(UTC) if now is None else moment
    requests = [
        entry
        for entry in pending_requests
        if _renew_check_lease(
            session,
            lease_id=entry[0].lease_id,
            owner=lease_owner,
            now=renewal_time,
            lease_seconds=settings.lease_seconds,
        )
    ]
    # Release local diagnostics and close the catalog read transaction before
    # any outbound acquisition can block on a target.
    session.commit()
    observations = _acquire(requests, max_workers=settings.max_concurrent_checks)
    for (claim, _, interval_seconds), observation in zip(
        requests, observations, strict=True
    ):
        if observation is not None:
            record = record_service_observation(
                session,
                object_id=claim.object_id,
                object_instance_id=claim.object_instance_id,
                observation=observation,
                now=observation.checked_at,
                settings=settings,
            )
            if record is not None and record.next_due_at is not None:
                release_check_lease(
                    session,
                    lease_id=claim.lease_id,
                    owner=lease_owner,
                    next_due_at=record.next_due_at,
                    now=observation.checked_at,
                )
                completed += 1
                continue
            _delete_claimed_lease(session, claim.lease_id, lease_owner)
            continue
        release_check_lease(
            session,
            lease_id=claim.lease_id,
            owner=lease_owner,
            next_due_at=_next_due(
                moment,
                object_id=claim.object_id,
                object_instance_id=claim.object_instance_id,
                provider=claim.provider,
                interval_seconds=interval_seconds,
                jitter_seconds=settings.jitter_seconds,
            ),
            now=moment,
        )
    session.commit()
    return MonitoringRunResult(scheduled, released, len(claims), completed)


def _acquire(
    requests: Sequence[tuple[DueCheck, ProviderCheckRequest, int]],
    *,
    max_workers: int,
) -> list[MonitoringObservation | None]:
    """Run bounded acquisition off the database session.

    Probes never touch the session, so concurrency needs no per-thread
    connection and a slow target cannot hold a database transaction open.
    """

    if not requests:
        return []

    def acquire_one(
        entry: tuple[DueCheck, ProviderCheckRequest, int],
    ) -> MonitoringObservation | None:
        claim, request, _ = entry
        if not has_provider(claim.provider):
            return None
        spec = get_provider(claim.provider)
        if spec.acquire is None:
            return None
        try:
            observation = spec.acquire(request)
            if observation.provider != claim.provider:
                raise ValueError("monitoring adapter returned another provider")
            return observation
        except Exception:  # noqa: BLE001 - one failing probe must not stop a run
            return MonitoringObservation(
                provider=claim.provider,
                state="check_error",
                checked_at=datetime.now(UTC),
                error_code="probe_failed",
            )

    workers = max(1, min(max_workers, len(requests)))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        return list(pool.map(acquire_one, requests))


def _release_expired_leases(session: Session, *, now: datetime) -> int:
    """Free leases whose owner died mid-check so the service stays observable."""

    naive_now = _naive(_aware(now))
    result = session.execute(
        update(ServiceCheckLease)
        .where(
            ServiceCheckLease.lease_expires_at.is_not(None),
            ServiceCheckLease.lease_expires_at <= naive_now,
        )
        .values(lease_owner=None, lease_expires_at=None, updated_at=naive_now)
    )
    return int(result.rowcount or 0)


def _renew_check_lease(
    session: Session,
    *,
    lease_id: int,
    owner: str,
    now: datetime,
    lease_seconds: int,
) -> bool:
    """Extend one still-live claim immediately before bounded acquisition."""

    naive_now = _naive(_aware(now))
    result = session.execute(
        update(ServiceCheckLease)
        .where(
            ServiceCheckLease.id == lease_id,
            ServiceCheckLease.lease_owner == owner,
            ServiceCheckLease.lease_expires_at > naive_now,
        )
        .values(
            lease_expires_at=_naive(
                _aware(now) + timedelta(seconds=lease_seconds)
            ),
            updated_at=naive_now,
        )
    )
    return result.rowcount == 1


def _delete_claimed_lease(session: Session, lease_id: int, owner: str) -> None:
    session.execute(
        delete(ServiceCheckLease).where(
            ServiceCheckLease.id == lease_id,
            ServiceCheckLease.lease_owner == owner,
        )
    )


def _prune_dead_observations(session: Session) -> None:
    """Drop observation rows whose catalog object instance no longer exists."""

    live = select(CatalogObject.id).where(
        CatalogObject.id == ServiceObservation.object_id,
        CatalogObject.instance_id == ServiceObservation.object_instance_id,
        CatalogObject.kind == "service",
    )
    session.execute(delete(ServiceObservation).where(~live.exists()))


def _record(row: ServiceObservation) -> MonitoringRecord:
    return MonitoringRecord(
        provider=row.provider,
        state=row.state,  # type: ignore[arg-type]
        http_status=row.http_status,
        latency_ms=row.latency_ms,
        error_code=row.error_code,
        last_checked_at=_aware_or_none(row.last_checked_at),
        last_success_at=_aware_or_none(row.last_success_at),
        next_due_at=_aware_or_none(row.next_due_at),
        object_instance_id=row.object_instance_id,
    )


def _object_data(catalog_object: CatalogObject) -> dict[str, Any]:
    try:
        data = json.loads(catalog_object.data_json or "{}")
    except (TypeError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _next_due(
    moment: datetime,
    *,
    object_id: str,
    object_instance_id: str,
    provider: str,
    interval_seconds: int,
    jitter_seconds: int,
) -> datetime:
    return scheduled_next_due(
        moment,
        object_id=object_id,
        object_instance_id=object_instance_id,
        provider=provider,
        interval_seconds=interval_seconds,
        jitter_seconds=jitter_seconds,
    )


def _initial_due(
    moment: datetime,
    *,
    object_id: str,
    object_instance_id: str,
    provider: str,
    jitter_seconds: int,
) -> datetime:
    return scheduled_next_due(
        moment,
        object_id=object_id,
        object_instance_id=object_instance_id,
        provider=provider,
        interval_seconds=0,
        jitter_seconds=jitter_seconds,
    )


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


def _aware_or_none(value: datetime | None) -> datetime | None:
    return None if value is None else _aware(value)


def _naive(value: datetime) -> datetime:
    """Store UTC as naive datetimes, matching every other Blockwart table."""

    return _aware(value).astimezone(UTC).replace(tzinfo=None)


@dataclass(frozen=True, slots=True)
class MonitoringPlanEntry:
    object_id: str
    enabled: bool
    provider: str | None
    interval_seconds: int | None
    target_url: str | None
    target_source: str | None
    diagnostic: str | None
    state: str
    freshness: str
    due_at: str | None


@dataclass(frozen=True, slots=True)
class MonitoringPlan:
    entries: tuple[MonitoringPlanEntry, ...]
    scanned_services: int
    enabled_services: int
    diagnostics: int
    poller_enabled: bool
    allowlist_configured: bool


def build_monitoring_plan(
    session: Session,
    *,
    settings: MonitoringSettings,
    now: datetime | None = None,
) -> MonitoringPlan:
    """Describe the effective monitoring configuration without probing anything.

    This is the write-free operator view. It makes the resolved target — or the
    exact reason there is none — visible before monitoring is switched on.
    """

    moment = _aware(now or datetime.now(UTC))
    observations = load_observation_index(session)
    leases = {
        (row.object_id, row.provider): row
        for row in session.scalars(select(ServiceCheckLease)).all()
    }
    entries: list[MonitoringPlanEntry] = []
    enabled_services = 0
    diagnostics = 0
    services = session.scalars(
        select(CatalogObject)
        .where(CatalogObject.kind == "service")
        .order_by(CatalogObject.id)
    ).all()
    for catalog_object in services:
        data = _object_data(catalog_object)
        view = monitoring_projection(
            kind="service",
            object_id=catalog_object.id,
            data=data,
            catalog_health=catalog_object.health,
            observations=observations,
            now=moment,
            settings=settings,
        )
        assert view is not None
        if view["enabled"]:
            enabled_services += 1
            if view["diagnostic"] is not None:
                diagnostics += 1
        target = view["target"]
        provider = view["provider"]
        lease = (
            leases.get((catalog_object.id, provider))
            if isinstance(provider, str)
            else None
        )
        entries.append(
            MonitoringPlanEntry(
                object_id=catalog_object.id,
                enabled=bool(view["enabled"]),
                provider=provider if isinstance(provider, str) else None,
                interval_seconds=(
                    int(view["interval_seconds"])
                    if isinstance(view["interval_seconds"], int)
                    else None
                ),
                target_url=target["url"] if target else None,
                target_source=target["source"] if target else None,
                diagnostic=view["diagnostic"],
                state=str(view["state"]),
                freshness=str(view["freshness"]),
                due_at=format_rfc3339_utc(lease.due_at) if lease is not None else None,
            )
        )
    return MonitoringPlan(
        entries=tuple(entries),
        scanned_services=len(services),
        enabled_services=enabled_services,
        diagnostics=diagnostics,
        poller_enabled=settings.poller_enabled,
        allowlist_configured=settings.policy.enabled,
    )


def monitoring_plan_entry_payload(entry: MonitoringPlanEntry) -> dict[str, Any]:
    """Render one plan entry as a stable, redacted JSON record."""

    return {
        "object_id": entry.object_id,
        "enabled": entry.enabled,
        "provider": entry.provider,
        "interval_seconds": entry.interval_seconds,
        "target_url": entry.target_url,
        "target_source": entry.target_source,
        "diagnostic": entry.diagnostic,
        "state": entry.state,
        "freshness": entry.freshness,
        "due_at": entry.due_at,
    }


def current_monitoring_settings() -> MonitoringSettings:
    """Resolve the deployment envelope from the process environment.

    An unusable allowlist must never fail a catalog read, so a broken policy
    degrades to the deny-everything default instead of raising here.
    """

    try:
        return monitoring_settings(get_settings())
    except MonitoringPolicyError:
        return MonitoringSettings()
