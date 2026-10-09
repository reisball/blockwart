"""Replay, lease, fencing, and uniqueness regressions for agent notices (Issue #106).

Every test body runs against SQLite and, when ``BLOCKWART_TEST_PG_URL`` is
reachable, PostgreSQL. All HTTP is a loopback fake gateway on 127.0.0.1.
"""

from __future__ import annotations

import os
import sqlite3
import threading
import time
import uuid
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import datetime, timedelta

import pytest
from notice_support import LoopbackReceiver, seed_notice_env
from sqlalchemy import create_engine, make_url, select, text, update
from sqlalchemy.engine import Engine
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from blockwart.db.migrations import upgrade_database
from blockwart.db.session import build_engine
from blockwart.models import (
    AgentDeliveryAttempt,
    AgentDeliveryJob,
    AgentDeliveryTarget,
    AgentNoticeSubscription,
    ObjectGrant,
    Principal,
    ServiceToken,
)
from blockwart.services import agent_notices as notices
from blockwart.services.agent_notices import (
    NoticeDeliveryPolicy,
    SubscriptionValidationError,
    acknowledge_agent_notice,
    create_agent_delivery_target,
    create_agent_notice_subscription,
    deliver_due_agent_notices,
    list_own_agent_notices,
    record_agent_notice_event,
)
from blockwart.services.notice_transport import (
    DeliveryOutcome,
    DeliveryRequest,
    FakeNoticeTransport,
    OpenClawTestGatewayTransport,
)

NOW = datetime(2026, 8, 26, 12, 0, 0)
POLICY = NoticeDeliveryPolicy(
    max_attempts=3,
    ttl_seconds=3600,
    backoff_base_seconds=60,
    backoff_max_seconds=600,
    max_pending_jobs_per_target=50,
    lease_seconds=60,
)
_STAT_KEYS = ("delivered", "failed", "retried", "duplicate_confirmed", "lease_lost")
SAFE_MESSAGE = "Fuer Service 'Runtime API' ist ein neues stabiles Release verfuegbar (Tag v2.4.0)."

PG_BASE_URL = os.environ.get("BLOCKWART_TEST_PG_URL", "")


@dataclass
class NoticeBackend:
    name: str
    url: str
    engine: Engine
    sessions: sessionmaker[Session]

    def probe_write(self, job_id: int) -> None:
        """Take a write on the job row from an independent connection, fast-failing."""
        if self.name == "sqlite":
            path = make_url(self.url).database
            connection = sqlite3.connect(path, timeout=0.3)
            try:
                connection.execute(
                    "UPDATE agent_delivery_jobs SET next_attempt_at = next_attempt_at "
                    "WHERE id = ?",
                    (job_id,),
                )
                connection.commit()
            finally:
                connection.close()
            return
        probe = create_engine(self.url)
        try:
            with probe.begin() as connection:
                connection.execute(text("SET LOCAL lock_timeout = '300ms'"))
                connection.execute(
                    text(
                        "UPDATE agent_delivery_jobs SET next_attempt_at = next_attempt_at "
                        "WHERE id = :id"
                    ),
                    {"id": job_id},
                )
                connection.execute(text("UPDATE agent_delivery_targets SET label = label"))
                idle = connection.execute(
                    text(
                        "SELECT count(*) FROM pg_stat_activity WHERE datname = current_database() "
                        "AND pid <> pg_backend_pid() AND state LIKE 'idle in transaction%'"
                    )
                ).scalar_one()
                assert idle == 0, "a database transaction is open across the transport call"
        finally:
            probe.dispose()


def _pg_url_for(database: str) -> str:
    return make_url(PG_BASE_URL).set(database=database).render_as_string(hide_password=False)


@pytest.fixture(params=["sqlite", "postgresql"])
def backend(request: pytest.FixtureRequest, tmp_path) -> Iterator[NoticeBackend]:
    created: str | None = None
    if request.param == "sqlite":
        url = f"sqlite:///{tmp_path / 'notices.sqlite3'}"
    else:
        if not PG_BASE_URL:
            pytest.skip("BLOCKWART_TEST_PG_URL is not configured")
        created = f"bw_notice_{uuid.uuid4().hex[:12]}"
        admin = create_engine(_pg_url_for("postgres"), isolation_level="AUTOCOMMIT")
        try:
            with admin.connect() as connection:
                connection.execute(text(f'CREATE DATABASE "{created}"'))
        finally:
            admin.dispose()
        url = _pg_url_for(created)
    upgrade_database(url)
    engine = build_engine(url)
    sessions = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    with sessions() as session:
        seed_notice_env(session)
        session.commit()
    try:
        yield NoticeBackend(request.param, url, engine, sessions)
    finally:
        engine.dispose()
        if created is not None:
            admin = create_engine(_pg_url_for("postgres"), isolation_level="AUTOCOMMIT")
            try:
                with admin.connect() as connection:
                    connection.execute(
                        text(
                            "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                            "WHERE datname = :name AND pid <> pg_backend_pid()"
                        ),
                        {"name": created},
                    )
                    connection.execute(text(f'DROP DATABASE IF EXISTS "{created}"'))
            finally:
                admin.dispose()


def _emit(backend: NoticeBackend, version: str = "2.4.0") -> str:
    with backend.sessions() as session:
        event = record_agent_notice_event(
            session,
            event_type="release_update_available",
            object_id="svc-01",
            dedupe_key=f"inst-1:github_releases:{version}",
            latest_tag=f"v{version}",
            latest_version=version,
            occurred_at=NOW,
            policy=POLICY,
        ).event
        event_id = event.id
        session.commit()
    return event_id


def _run(
    backend: NoticeBackend,
    transport,
    moment: datetime = NOW,
    *,
    worker: str = "w",
    policy: NoticeDeliveryPolicy = POLICY,
) -> dict[str, int]:
    with backend.sessions() as session:
        return deliver_due_agent_notices(
            session, transport, now=moment, policy=policy, worker_id=worker
        )


def _job(backend: NoticeBackend) -> AgentDeliveryJob:
    with backend.sessions() as session:
        job = session.scalars(select(AgentDeliveryJob)).one()
        session.expunge(job)
        return job


def _attempts(backend: NoticeBackend) -> list[tuple[int, str]]:
    with backend.sessions() as session:
        return [
            (row.attempt_no, row.outcome)
            for row in session.scalars(
                select(AgentDeliveryAttempt).order_by(AgentDeliveryAttempt.id)
            )
        ]


# --- 1. Response-loss replay is idempotent end to end -------------------------------


def test_lost_response_retry_is_confirmed_prior_success(backend) -> None:
    event_id = _emit(backend)
    transport = FakeNoticeTransport()
    transport.enqueue_lost_response()

    first = _run(backend, transport)
    assert first["retried"] == 1 and first["delivered"] == 0
    assert _job(backend).status == "pending"

    second = _run(backend, transport, NOW + timedelta(seconds=61))
    assert second["delivered"] == 1
    assert second["duplicate_confirmed"] == 1
    assert second["failed"] == 0

    job = _job(backend)
    assert job.status == "delivered"
    assert job.last_error_code is None
    assert job.attempts == 2
    assert _attempts(backend) == [(1, "timeout"), (2, "confirmed_duplicate")]
    # One visible notice despite two sends of the same stable key.
    assert len(transport.calls) == 2
    assert len({call.delivery_id for call in transport.calls}) == 1
    assert len(transport.visible) == 1
    assert transport.visible[0].payload["event_id"] == event_id
    # A confirmed delivery is never sent again.
    third = _run(backend, transport, NOW + timedelta(seconds=999))
    assert third["delivered"] == 0
    assert len(transport.calls) == 2


@pytest.mark.parametrize(
    ("duplicate_status", "label"), [(409, "conflict"), (200, "ok")], ids=["409", "200"]
)
def test_loopback_lost_response_replay_is_idempotent(
    backend, duplicate_status: int, label: str
) -> None:
    event_id = _emit(backend)
    with LoopbackReceiver(duplicate_status=duplicate_status) as receiver:
        receiver.drop_responses = 1
        transport = OpenClawTestGatewayTransport(endpoint_url=receiver.url, timeout_seconds=3)

        first = _run(backend, transport)
        assert first["retried"] == 1, first
        assert _job(backend).status == "pending"
        # The receiver already holds the notice even though the sender saw a failure.
        assert len(receiver.visible) == 1

        second = _run(backend, transport, NOW + timedelta(seconds=61))
        assert second["delivered"] == 1 and second["duplicate_confirmed"] == 1, second
        assert second["failed"] == 0

        job = _job(backend)
        assert job.status == "delivered" and job.last_error_code is None
        assert _attempts(backend)[-1] == (2, "confirmed_duplicate")
        # Exactly one visible notice, and it is the fixed minimal safe payload.
        assert len(receiver.visible) == 1
        assert len(receiver.request_ids) == 2 and len(set(receiver.request_ids)) == 1
        envelope = receiver.visible[0]
        assert envelope["target"] == "openclaw-agent:test-inbox"
        assert envelope["notice"] == {
            "schema_version": 1,
            "event_type": "release_update_available",
            "event_id": event_id,
            "object_ref": "service:svc-01",
            "message": SAFE_MESSAGE,
            "blockwart_reference": "/api/v1/agent/objects/svc-01",
        }
        assert set(envelope) == {"delivery_id", "target", "notice"}


def test_unrelated_conflict_is_not_mistaken_for_a_duplicate(backend) -> None:
    _emit(backend)
    with LoopbackReceiver() as receiver:
        # A 409 that does not confirm *this* delivery_id must stay a failure.
        receiver._accepted.add(f"agent-notice-job-{_job(backend).id}")
        receiver._duplicate_body = {"status": "duplicate", "delivery_id": "someone-else"}
        transport = OpenClawTestGatewayTransport(endpoint_url=receiver.url, timeout_seconds=3)
        stats = _run(backend, transport)
    assert stats["retried"] == 1 and stats["delivered"] == 0
    assert _job(backend).status == "pending"
    assert _job(backend).last_error_code == "transport_unavailable"


def test_receiver_failure_then_success_is_ordinary_retry(backend) -> None:
    _emit(backend)
    with LoopbackReceiver() as receiver:
        receiver.fail_next = 1
        transport = OpenClawTestGatewayTransport(endpoint_url=receiver.url, timeout_seconds=3)
        assert _run(backend, transport)["retried"] == 1
        stats = _run(backend, transport, NOW + timedelta(seconds=61))
        assert stats["delivered"] == 1 and stats["duplicate_confirmed"] == 0
        assert len(receiver.visible) == 1
    assert _attempts(backend) == [(1, "unavailable"), (2, "success")]


def test_loopback_transport_ignores_environment_proxies_and_redirects(
    backend, monkeypatch
) -> None:
    _emit(backend)
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:9")
    monkeypatch.setenv("http_proxy", "http://127.0.0.1:9")
    monkeypatch.delenv("NO_PROXY", raising=False)
    monkeypatch.delenv("no_proxy", raising=False)
    with LoopbackReceiver() as receiver:
        transport = OpenClawTestGatewayTransport(endpoint_url=receiver.url, timeout_seconds=3)
        assert _run(backend, transport)["delivered"] == 1
        assert len(receiver.visible) == 1


# --- 2. Durable lease before network I/O; no lock across the transport --------------


class _ProbingTransport:
    """Records what a second, independent connection observes mid-delivery."""

    timeout_seconds = 0.0

    def __init__(self, backend: NoticeBackend) -> None:
        self.backend = backend
        self.observed: list[dict] = []
        self.calls: list[DeliveryRequest] = []

    def deliver(self, request: DeliveryRequest) -> DeliveryOutcome:
        self.calls.append(request)
        with self.backend.engine.connect() as connection:
            row = connection.execute(
                text(
                    "SELECT id, status, attempts, lease_token, lease_expires_at "
                    "FROM agent_delivery_jobs"
                )
            ).one()
        self.observed.append(dict(row._mapping))
        # Must not block or fail: no write lock is held by the delivering worker.
        self.backend.probe_write(row.id)
        return DeliveryOutcome(ok=True)


def test_lease_is_committed_and_no_lock_is_held_during_transport(backend) -> None:
    _emit(backend)
    transport = _ProbingTransport(backend)

    started = time.monotonic()
    stats = _run(backend, transport)
    assert time.monotonic() - started < 5, "worker blocked on its own lock"

    assert stats["delivered"] == 1
    (seen,) = transport.observed
    assert seen["status"] == "pending"
    assert seen["attempts"] == 1
    assert seen["lease_token"] is not None
    assert seen["lease_expires_at"] is not None
    job = _job(backend)
    assert job.status == "delivered"
    assert job.lease_token is None and job.lease_expires_at is None
    assert job.claimed_by is None


def test_concurrent_workers_send_each_job_exactly_once(backend) -> None:
    for index in range(6):
        _emit(backend, f"3.{index}.0")
    lock = threading.Lock()
    sent: list[str] = []

    class SlowTransport:
        timeout_seconds = 0.0

        def deliver(self, request: DeliveryRequest) -> DeliveryOutcome:
            with lock:
                sent.append(request.delivery_id)
            time.sleep(0.05)
            return DeliveryOutcome(ok=True)

    barrier = threading.Barrier(4)
    results: list[dict[str, int]] = []
    errors: list[BaseException] = []

    def worker(index: int) -> None:
        try:
            barrier.wait(timeout=10)
            stats = _run(backend, SlowTransport(), worker=f"worker-{index}")
            with lock:
                results.append(stats)
        except BaseException as exc:  # noqa: BLE001 - surfaced by the assertion below
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=60)
    assert not errors, errors
    assert sorted(sent) == sorted(set(sent)) and len(sent) == 6
    assert sum(stats["delivered"] for stats in results) == 6
    assert sum(stats["lease_lost"] for stats in results) == 0
    with backend.sessions() as session:
        jobs = session.scalars(select(AgentDeliveryJob)).all()
        assert [job.status for job in jobs] == ["delivered"] * 6
        assert all(job.attempts == 1 and job.lease_token is None for job in jobs)


def test_crashed_worker_lease_expires_and_stale_completion_is_fenced(backend) -> None:
    _emit(backend)
    with backend.sessions() as session:
        stale = notices._claim_next_job(
            session, worker_id="crashed", policy=POLICY, moment=NOW, skip_ids=set()
        )
    assert stale is not None and stale.attempt_no == 1  # the worker now "crashes"

    transport = FakeNoticeTransport()
    # Inside the lease window nobody else may send.
    assert _run(backend, transport, NOW + timedelta(seconds=30), worker="b")["delivered"] == 0
    assert transport.calls == []

    # After expiry another worker reclaims and delivers.
    assert _run(backend, transport, NOW + timedelta(seconds=61), worker="b")["delivered"] == 1
    assert _attempts(backend) == [(1, "lease_expired"), (2, "success")]
    delivered = _job(backend)
    assert delivered.status == "delivered" and delivered.attempts == 2

    # The original worker wakes up late: its completion changes nothing.
    stats = dict.fromkeys(_STAT_KEYS, 0)
    with backend.sessions() as session:
        notices._record_outcome(
            session,
            stale,
            DeliveryOutcome(ok=False, error_code="transport_timeout"),
            POLICY,
            NOW + timedelta(seconds=90),
            stats,
        )
    assert stats["lease_lost"] == 1 and stats["retried"] == 0
    after = _job(backend)
    assert after.status == "delivered" and after.delivered_at == delivered.delivered_at
    assert after.last_error_code is None and after.attempts == 2
    assert _attempts(backend) == [(1, "lease_expired"), (2, "success")]


def test_stale_failure_cannot_reschedule_a_job_held_by_a_new_lease(backend) -> None:
    _emit(backend)
    with backend.sessions() as session:
        stale = notices._claim_next_job(
            session, worker_id="a", policy=POLICY, moment=NOW, skip_ids=set()
        )
    with backend.sessions() as session:
        fresh = notices._claim_next_job(
            session,
            worker_id="b",
            policy=POLICY,
            moment=NOW + timedelta(seconds=61),
            skip_ids=set(),
        )
    assert stale is not None and fresh is not None and stale.token != fresh.token
    before = _job(backend)
    stats = dict.fromkeys(_STAT_KEYS, 0)
    with backend.sessions() as session:
        notices._record_outcome(
            session,
            stale,
            DeliveryOutcome(ok=True),
            POLICY,
            NOW + timedelta(seconds=62),
            stats,
        )
    assert stats["lease_lost"] == 1 and stats["delivered"] == 0
    after = _job(backend)
    assert after.status == "pending"
    assert after.lease_token == fresh.token == before.lease_token
    assert after.next_attempt_at == before.next_attempt_at


def test_crash_loop_is_bounded_by_the_attempt_budget(backend) -> None:
    _emit(backend)
    for index in range(POLICY.max_attempts):
        with backend.sessions() as session:
            claim = notices._claim_next_job(
                session,
                worker_id=f"crash-{index}",
                policy=POLICY,
                moment=NOW + timedelta(seconds=100 * index),
                skip_ids=set(),
            )
        assert claim is not None and claim.attempt_no == index + 1
    transport = FakeNoticeTransport()
    stats = _run(backend, transport, NOW + timedelta(seconds=400))
    assert stats["failed"] == 1
    assert transport.calls == []
    job = _job(backend)
    assert job.status == "failed" and job.last_error_code == "attempt_limit_reached"
    assert job.attempts == POLICY.max_attempts
    assert [outcome for _no, outcome in _attempts(backend)] == ["lease_expired"] * 3


@pytest.mark.parametrize(
    ("mutation", "expected_code"),
    [
        ("grant_removed", "read_permission_lost"),
        ("principal_deactivated", "principal_inactive"),
        ("token_revoked", "principal_inactive"),
        ("target_revoked", "target_inactive"),
        ("subscription_revoked", "subscription_revoked"),
    ],
)
def test_authorization_is_rechecked_before_every_attempt(
    backend, mutation: str, expected_code: str
) -> None:
    _emit(backend)
    transport = FakeNoticeTransport()
    transport.enqueue_result(DeliveryOutcome(ok=False, error_code="transport_timeout"))
    assert _run(backend, transport)["retried"] == 1

    with backend.sessions() as session:
        if mutation == "grant_removed":
            session.query(ObjectGrant).delete()
        elif mutation == "principal_deactivated":
            session.get(Principal, "principal-agent").active = False
        elif mutation == "token_revoked":
            session.get(ServiceToken, "token-principal-agent").revoked_at = NOW
        elif mutation == "target_revoked":
            session.scalars(select(AgentDeliveryTarget)).one().active = False
        else:
            subscription = session.scalars(select(AgentNoticeSubscription)).one()
            subscription.active = False
            subscription.revoked_at = NOW
        session.commit()

    stats = _run(backend, transport, NOW + timedelta(seconds=61))
    assert stats["suppressed"] == 1 and stats["delivered"] == 0
    job = _job(backend)
    assert job.status == "suppressed" and job.last_error_code == expected_code
    assert job.attempts == 1  # the suppressed claim handed its attempt back
    assert len(transport.calls) == 1  # nothing left Blockwart on the denied attempt


def test_unexpected_error_in_recheck_fails_closed_without_sending(backend, monkeypatch) -> None:
    _emit(backend)

    def explode(*_args, **_kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr(notices, "check_delivery_authorization", explode)
    transport = FakeNoticeTransport()
    stats = _run(backend, transport)
    assert stats["failed"] == 1
    assert transport.calls == []
    job = _job(backend)
    assert job.status == "failed" and job.last_error_code == "delivery_error"
    assert job.lease_token is None


def test_transport_exception_is_a_bounded_coarse_retry(backend) -> None:
    _emit(backend)

    class Exploding:
        timeout_seconds = 0.0

        def deliver(self, request: DeliveryRequest) -> DeliveryOutcome:
            raise RuntimeError("secret transport detail")

    for index in range(POLICY.max_attempts):
        _run(backend, Exploding(), NOW + timedelta(seconds=700 * index))
    job = _job(backend)
    assert job.status == "failed"
    assert job.last_error_code == "transport_unavailable"
    assert job.attempts == POLICY.max_attempts
    assert "secret" not in repr(_attempts(backend))


def test_lease_must_outlive_the_transport_timeout(backend) -> None:
    _emit(backend)
    slow = OpenClawTestGatewayTransport(
        endpoint_url="http://127.0.0.1:9/never", timeout_seconds=120
    )
    with pytest.raises(ValueError, match="lease_seconds"):
        _run(backend, slow)
    assert _job(backend).lease_token is None


def test_terminal_jobs_can_never_hold_a_lease(backend) -> None:
    _emit(backend)
    _run(backend, FakeNoticeTransport())
    with pytest.raises(IntegrityError):
        with backend.sessions() as session:
            session.execute(
                update(AgentDeliveryJob).values(
                    lease_token="x" * 32, lease_expires_at=NOW + timedelta(seconds=5)
                )
            )
            session.commit()
    with pytest.raises(IntegrityError):
        with backend.sessions() as session:
            session.execute(update(AgentDeliveryJob).values(lease_token="x" * 32))
            session.commit()


def test_clock_drives_lease_times_between_phases(backend) -> None:
    _emit(backend)
    ticks = iter(NOW + timedelta(seconds=n) for n in range(0, 100))
    leases: list[tuple[datetime, datetime]] = []

    class Recording:
        timeout_seconds = 0.0

        def deliver(self, request: DeliveryRequest) -> DeliveryOutcome:
            with backend.engine.connect() as connection:
                row = connection.execute(
                    text("SELECT claimed_at, lease_expires_at FROM agent_delivery_jobs")
                ).one()
            leases.append(
                tuple(
                    value if isinstance(value, datetime) else datetime.fromisoformat(value)
                    for value in (row.claimed_at, row.lease_expires_at)
                )
            )
            return DeliveryOutcome(ok=True)

    with backend.sessions() as session:
        deliver_due_agent_notices(
            session, Recording(), now=NOW, policy=POLICY, clock=lambda: next(ticks)
        )
    ((claimed_at, lease_end),) = leases
    assert lease_end - claimed_at == timedelta(seconds=POLICY.lease_seconds)
    assert _job(backend).delivered_at > NOW  # recorded with the later clock reading


# --- 3. Uniqueness of one logical agent route ----------------------------------------


def _make_principal(backend: NoticeBackend, principal_id: str) -> None:
    with backend.sessions() as session:
        session.add(
            Principal(
                id=principal_id,
                principal_type="service_account",
                login=principal_id,
                display_name=principal_id,
                active=True,
            )
        )
        session.commit()


def test_route_cannot_be_registered_twice(backend) -> None:
    _make_principal(backend, "principal-other")
    for principal in ("principal-agent", "principal-other"):
        with backend.sessions() as session:
            with pytest.raises(SubscriptionValidationError) as caught:
                create_agent_delivery_target(
                    session,
                    principal_id=principal,
                    label="dup",
                    route="openclaw-agent:test-inbox",
                    transport="openclaw_test_gateway",
                )
        assert caught.value.code == "route_already_registered"
        assert caught.value.is_conflict


def test_route_spelling_is_canonical(backend) -> None:
    for route in ("OpenClaw-Agent:Test-Inbox", " openclaw-agent:test-inbox", "x y", "", "-lead"):
        with backend.sessions() as session:
            with pytest.raises(SubscriptionValidationError) as caught:
                create_agent_delivery_target(
                    session,
                    principal_id="principal-agent",
                    label="bad",
                    route=route,
                    transport="openclaw_test_gateway",
                )
        assert caught.value.code == "invalid_target_route"


def test_database_rejects_duplicate_active_route_and_rule(backend) -> None:
    insert_target = text(
        "INSERT INTO agent_delivery_targets (id, principal_id, label, route, transport, active) "
        "VALUES (:id, 'principal-agent', 'raw', 'openclaw-agent:test-inbox', "
        "'openclaw_test_gateway', :active)"
    )
    with pytest.raises(IntegrityError):
        with backend.engine.begin() as connection:
            connection.execute(insert_target, {"id": "raw-1", "active": True})
    # An inactive (revoked) row of the same route is history, not a second registration.
    with backend.engine.begin() as connection:
        connection.execute(insert_target, {"id": "raw-2", "active": False})
    with backend.sessions() as session:
        target_id = session.scalars(
            select(AgentDeliveryTarget.id).where(AgentDeliveryTarget.active.is_(True))
        ).one()
    insert_rule = text(
        "INSERT INTO agent_notice_subscriptions (id, event_type, scope, object_id, principal_id, "
        "target_id, active) VALUES (:id, 'release_update_available', :scope, :object_id, "
        "'principal-agent', :target, true)"
    )
    with pytest.raises(IntegrityError):
        with backend.engine.begin() as connection:
            connection.execute(
                insert_rule,
                {"id": "r-1", "scope": "object", "object_id": "svc-01", "target": target_id},
            )
    # Catalog scope has no object id; NULLs must not defeat the uniqueness.
    with backend.engine.begin() as connection:
        connection.execute(
            insert_rule, {"id": "r-2", "scope": "catalog", "object_id": None, "target": target_id}
        )
    with pytest.raises(IntegrityError):
        with backend.engine.begin() as connection:
            connection.execute(
                insert_rule,
                {"id": "r-3", "scope": "catalog", "object_id": None, "target": target_id},
            )


def test_revoked_route_can_be_approved_again(backend) -> None:
    with backend.sessions() as session:
        target = session.scalars(select(AgentDeliveryTarget)).one()
        notices.deactivate_agent_delivery_target(session, target_id=target.id, now=NOW)
        session.commit()
        again = create_agent_delivery_target(
            session,
            principal_id="principal-agent",
            label="re-approved",
            route="openclaw-agent:test-inbox",
            transport="openclaw_test_gateway",
        )
        session.commit()
        assert again.id != target.id
        assert session.scalars(select(AgentDeliveryTarget)).all().__len__() == 2


def test_duplicate_subscription_is_rejected(backend) -> None:
    with backend.sessions() as session:
        target = session.scalars(select(AgentDeliveryTarget)).one()
        with pytest.raises(SubscriptionValidationError) as caught:
            create_agent_notice_subscription(
                session,
                event_type="release_update_available",
                scope="object",
                object_id="svc-01",
                principal_id="principal-agent",
                target_id=target.id,
            )
        assert caught.value.code == "subscription_already_registered"
        with pytest.raises(SubscriptionValidationError) as unknown:
            create_agent_notice_subscription(
                session,
                event_type="release_update_available",
                scope="object",
                object_id="does-not-exist",
                principal_id="principal-agent",
                target_id=target.id,
            )
        assert unknown.value.code == "unknown_object"


def test_concurrent_route_registration_has_exactly_one_winner(backend) -> None:
    barrier = threading.Barrier(6)
    outcomes: list[str] = []
    lock = threading.Lock()

    def register() -> None:
        with backend.sessions() as session:
            barrier.wait(timeout=10)
            try:
                create_agent_delivery_target(
                    session,
                    principal_id="principal-agent",
                    label="race",
                    route="openclaw-agent:race",
                    transport="openclaw_test_gateway",
                )
                session.commit()
                result = "created"
            except SubscriptionValidationError as exc:
                session.rollback()
                result = exc.code
            with lock:
                outcomes.append(result)

    threads = [threading.Thread(target=register) for _ in range(6)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=60)
    assert sorted(outcomes) == ["created"] + ["route_already_registered"] * 5
    with backend.sessions() as session:
        rows = session.scalars(
            select(AgentDeliveryTarget).where(AgentDeliveryTarget.route == "openclaw-agent:race")
        ).all()
        assert len(rows) == 1


def test_concurrent_subscription_registration_has_exactly_one_winner(backend) -> None:
    with backend.sessions() as session:
        target = create_agent_delivery_target(
            session,
            principal_id="principal-agent",
            label="second",
            route="openclaw-agent:second",
            transport="openclaw_test_gateway",
        )
        target_id = target.id
        session.commit()
    barrier = threading.Barrier(6)
    outcomes: list[str] = []
    lock = threading.Lock()

    def register() -> None:
        with backend.sessions() as session:
            barrier.wait(timeout=10)
            try:
                create_agent_notice_subscription(
                    session,
                    event_type="release_update_available",
                    scope="catalog",
                    object_id=None,
                    principal_id="principal-agent",
                    target_id=target_id,
                )
                session.commit()
                result = "created"
            except SubscriptionValidationError as exc:
                session.rollback()
                result = exc.code
            with lock:
                outcomes.append(result)

    threads = [threading.Thread(target=register) for _ in range(6)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=60)
    assert sorted(outcomes) == ["created"] + ["subscription_already_registered"] * 5


def test_overlapping_rules_still_produce_one_job_per_target(backend) -> None:
    with backend.sessions() as session:
        target = session.scalars(select(AgentDeliveryTarget)).one()
        # object-scoped (seeded) plus catalog-scoped rule for the same target
        create_agent_notice_subscription(
            session,
            event_type="release_update_available",
            scope="catalog",
            object_id=None,
            principal_id="principal-agent",
            target_id=target.id,
        )
        session.commit()
    _emit(backend)
    with backend.sessions() as session:
        assert len(session.scalars(select(AgentDeliveryJob)).all()) == 1


# --- 4. Acknowledgement and read semantics -------------------------------------------


def test_acknowledgement_is_idempotent_and_fail_closed(backend) -> None:
    event_id = _emit(backend)
    with backend.sessions() as session:
        assert acknowledge_agent_notice(
            session, principal_id="principal-agent", event_id=event_id, now=NOW
        ) == (False, "not_acknowledgeable_status_pending")
        session.commit()
    _run(backend, FakeNoticeTransport())
    with backend.sessions() as session:
        assert acknowledge_agent_notice(
            session, principal_id="principal-agent", event_id=event_id, now=NOW
        ) == (True, None)
        session.commit()
        # Repeating the receipt is a no-op success, never an error or a state change.
        assert acknowledge_agent_notice(
            session, principal_id="principal-agent", event_id=event_id, now=NOW
        ) == (True, None)
        session.commit()
        assert acknowledge_agent_notice(
            session, principal_id="someone-else", event_id=event_id, now=NOW
        ) == (False, "not_found")
    with backend.sessions() as session:
        session.query(ObjectGrant).delete()
        session.commit()
        # Without current read the notice does not exist for the agent.
        assert acknowledge_agent_notice(
            session, principal_id="principal-agent", event_id=event_id, now=NOW
        ) == (False, "not_found")
        assert list_own_agent_notices(session, principal_id="principal-agent", limit=10) == []


def test_two_routes_of_one_agent_show_one_notice_with_furthest_state(backend) -> None:
    with backend.sessions() as session:
        seed_notice_env(session, route="openclaw-agent:second-inbox")
        session.commit()
    event_id = _emit(backend)
    assert _run(backend, FakeNoticeTransport())["delivered"] == 2
    with backend.sessions() as session:
        notices_list = list_own_agent_notices(session, principal_id="principal-agent", limit=10)
        assert [n.event_id for n in notices_list] == [event_id]
        assert acknowledge_agent_notice(
            session, principal_id="principal-agent", event_id=event_id, now=NOW
        ) == (True, None)
        session.commit()
        statuses = {job.status for job in session.scalars(select(AgentDeliveryJob))}
        assert statuses == {"acknowledged"}
