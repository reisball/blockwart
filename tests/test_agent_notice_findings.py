"""Independent review regressions through the real emitter, SQLite and PostgreSQL."""

import json
from datetime import UTC, timedelta

import pytest
import test_agent_notice_hardening as support
from alembic import command
from fastapi.testclient import TestClient
from notice_support import LoopbackReceiver, seed_notice_env
from sqlalchemy import func, select
from sqlalchemy.exc import OperationalError
from test_agent_notice_hardening import (
    NOW,
    POLICY,
    _attempts,
    _emit,
    _job,
    _run,
)

from blockwart.config import Settings
from blockwart.db.migrations import build_alembic_config, upgrade_database
from blockwart.main import create_app
from blockwart.models import AgentDeliveryJob, AgentNoticeEvent, AuditEvent, CatalogObject
from blockwart.services import agent_notices as notices
from blockwart.services import release_monitoring as releases
from blockwart.services.notice_transport import FakeNoticeTransport, OpenClawTestGatewayTransport

backend = support.backend


def _configure(backend, running):
    with backend.sessions() as session:
        row = session.get(CatalogObject, "svc-01")
        row.data_json = json.dumps(
            {
                "schema_version": 1,
                "service_information": {"running_version": running},
                "release_monitoring": {
                    "enabled": True,
                    "provider": "github_releases",
                    "github": {"owner": "example-org", "repo": "example-service"},
                },
            }
        )
        session.commit()


def _check(backend, monkeypatch, version, index, outcome="observed"):
    moment = NOW.replace(tzinfo=UTC) + timedelta(days=index)
    observation = releases.ReleaseObservation(
        provider="github_releases",
        outcome=outcome,
        checked_at=moment,
        latest_tag=f"v{version}" if outcome == "observed" else None,
        latest_version=version if outcome == "observed" else None,
        http_status=200 if outcome == "observed" else 304,
    )
    monkeypatch.setattr(releases, "fetch_latest_github_release", lambda _: observation)
    with backend.sessions() as session:
        result = releases.check_service_release(
            session,
            object_id="svc-01",
            settings=releases.ReleaseMonitoringSettings(enabled=True),
            manual=True,
            now=moment,
        )
        assert result.outcome == outcome
        return result.projection


def _versions(backend):
    with backend.sessions() as session:
        return session.scalars(
            select(AgentNoticeEvent.latest_version).order_by(AgentNoticeEvent.occurred_at)
        ).all()


@pytest.mark.parametrize(
    ("running", "versions", "expected", "statuses"),
    [
        ("1.0.0", ["1.2.0"], ["1.2.0"], ["update_available"]),
        ("1.2.0", ["1.2.0"], [], ["current"]),
        ("2.0.0", ["1.9.0", "2.0.0"], [], ["current", "current"]),
        ("1.0.0", ["1.2.0", "1.1.0", "1.1.0"], ["1.2.0"], ["update_available"] * 3),
        ("1.0.0", ["1.2.0", "1.2.0", "1.3.0"], ["1.2.0", "1.3.0"], ["update_available"] * 3),
        ("unknown", ["1.2.0"], [], ["unknown"]),
        ("1.0.0", ["release", "1.2.0"], ["1.2.0"], ["unknown", "update_available"]),
    ],
)
def test_actual_release_emitter_matches_attention(
    backend, monkeypatch, running, versions, expected, statuses
):
    _configure(backend, running)
    for index, (version, status) in enumerate(zip(versions, statuses, strict=True)):
        assert _check(backend, monkeypatch, version, index)["status"] == status
    assert _versions(backend) == expected
    with backend.sessions() as session:
        assert session.scalar(select(func.count(AgentDeliveryJob.id))) == len(expected)
    transport = FakeNoticeTransport()
    if expected:
        # Check actual emitted jobs reach the receiver; preserve their observation timestamps.
        stats = _run(backend, transport, NOW + timedelta(days=len(versions) - 1))
        assert stats["delivered"] + stats["expired"] == len(expected)
        assert len(transport.visible) == sum(
            version == versions[-1] for version in expected
        )  # older events expire; only the newest accepted version can deliver


def test_fanout_failure_preserves_observation_and_rolls_back_every_notice_change(
    backend, monkeypatch, caplog
):
    _configure(backend, "1.0.0")
    original = notices.fanout_agent_notice_jobs
    with backend.sessions() as session:
        audit_count = session.scalar(select(func.count(AuditEvent.id)))

    def partial_then_fail(session, **kwargs):
        original(session, **kwargs)
        session.add(
            AuditEvent(action="test_partial", actor="test", summary="partial", details_json="{}")
        )
        session.flush()
        raise RuntimeError("secret upstream detail")

    with monkeypatch.context() as patch:
        patch.setattr(notices, "fanout_agent_notice_jobs", partial_then_fail)
        assert _check(backend, monkeypatch, "1.2.0", 0)["status"] == "update_available"
    assert _versions(backend) == []
    with backend.sessions() as session:
        assert session.scalar(select(func.count(AgentDeliveryJob.id))) == 0
        assert session.scalar(select(func.count(AuditEvent.id))) == audit_count
        stored = session.scalars(select(releases.ServiceReleaseObservation)).one()
        assert stored.latest_version == "1.2.0"
    assert "code=fanout_failed" in caplog.text and "secret upstream" not in caplog.text
    # A 304 of the persisted observation retries failed fan-out, then dedupes.
    _check(backend, monkeypatch, "1.2.0", 1, "not_modified")
    _check(backend, monkeypatch, "1.2.0", 2, "not_modified")
    assert _versions(backend) == ["1.2.0"]


def test_delivery_ids_survive_replay_but_do_not_collide_after_db_recreation(backend):
    with LoopbackReceiver() as receiver:
        transport = OpenClawTestGatewayTransport(endpoint_url=receiver.url)
        _emit(backend, "2.0.0")
        old = _job(backend)
        receiver.drop_responses = 1
        assert _run(backend, transport)["retried"] == 1
        assert _run(backend, transport, NOW + timedelta(seconds=61))["duplicate_confirmed"] == 1
        old_key = notices.delivery_id_for_job(old)
        command.downgrade(build_alembic_config(backend.url), "20260926_0026")
        upgrade_database(backend.url)
        with backend.sessions() as session:
            seed_notice_env(session)
            session.commit()
        _emit(backend, "3.0.0")
        new = _job(backend)
        assert new.id == old.id == 1
        assert notices.delivery_id_for_job(new) != old_key
        assert _run(backend, transport)["duplicate_confirmed"] == 0
        assert len(receiver.visible) == 2
        assert receiver.request_ids[0] == receiver.request_ids[1] == old_key
        assert receiver.request_ids[2] != old_key


def test_transient_prepare_db_error_retries_without_send_then_recovers(backend, monkeypatch):
    _emit(backend)
    transport = FakeNoticeTransport()
    with monkeypatch.context() as patch:

        def fail(*args, **kwargs):
            raise OperationalError("secret query", {}, RuntimeError("secret connection"))

        patch.setattr(notices, "check_delivery_authorization", fail)
        assert _run(backend, transport)["retried"] == 1
    job = _job(backend)
    assert job.status == "pending" and job.lease_token is None and job.attempts == 1
    assert transport.calls == []
    assert _run(backend, transport, NOW + timedelta(seconds=59))["delivered"] == 0
    assert _run(backend, transport, NOW + timedelta(seconds=61))["delivered"] == 1
    assert _attempts(backend) == [(1, "unavailable"), (2, "success")]


def test_expired_lease_completion_cannot_commit_even_before_reclaim(backend):
    _emit(backend)
    with backend.sessions() as session:
        claim = notices._claim_next_job(
            session, worker_id="stale", policy=POLICY, moment=NOW, skip_ids=set()
        )
        stats = dict.fromkeys(["delivered", "lease_lost"], 0)
        notices._record_outcome(
            session,
            claim,
            notices.DeliveryOutcome(True),
            POLICY,
            NOW + timedelta(seconds=60),
            stats,
        )
    assert stats["lease_lost"] == 1 and _job(backend).status == "pending"
    assert _attempts(backend) == []
    assert _run(backend, FakeNoticeTransport(), NOW + timedelta(seconds=61))["delivered"] == 1


@pytest.mark.parametrize(
    "endpoint",
    [
        "http://203.0.113.9:9/private?secret=token",
        "http://127.0.0.1:invalid/private",
        "http://[broken",
    ],
)
def test_refused_endpoint_lifespan_is_redacted_and_non_crashing(endpoint, caplog):
    app = create_app(
        Settings(notice_delivery_poller_enabled=True, notice_delivery_endpoint_url=endpoint)
    )
    with TestClient(app) as client:
        assert client.get("/api/health").status_code == 200
    assert "code=transport_invalid" in caplog.text
    assert endpoint not in caplog.text and "private" not in caplog.text


def test_withdrawal_after_fanout_failure_stays_silent_on_repeated_checks(backend, monkeypatch):
    _configure(backend, "1.0.0")
    with monkeypatch.context() as patch:

        def fail(*args, **kwargs):
            raise RuntimeError("fanout failed")

        patch.setattr(notices, "fanout_agent_notice_jobs", fail)
        _check(backend, monkeypatch, "1.2.0", 0)
    _check(backend, monkeypatch, "1.1.0", 1)
    _check(backend, monkeypatch, "1.1.0", 2, "not_modified")
    assert _versions(backend) == []
    _check(backend, monkeypatch, "1.3.0", 3)
    assert _versions(backend) == ["1.3.0"]


def test_revised_0027_backfills_highwater_and_roundtrips_on_both_backends(backend, monkeypatch):
    from alembic.autogenerate import compare_metadata
    from alembic.migration import MigrationContext
    from sqlalchemy import inspect, text

    from blockwart.db.base import Base

    _configure(backend, "1.0.0")
    _check(backend, monkeypatch, "1.2.0", 0)
    command.downgrade(build_alembic_config(backend.url), "20260926_0026")
    with backend.engine.connect() as connection:
        assert "notice_highest_version" not in {
            col["name"] for col in inspect(connection).get_columns("service_release_observations")
        }
        assert (
            connection.scalar(text("SELECT latest_version FROM service_release_observations"))
            == "1.2.0"
        )
    upgrade_database(backend.url)
    with backend.engine.connect() as connection:
        assert (
            connection.scalar(
                text("SELECT notice_highest_version FROM service_release_observations")
            )
            == "1.2.0"
        )
        context = MigrationContext.configure(
            connection,
            opts={
                "compare_type": True,
                "compare_server_default": True,
                "include_object": lambda obj, name, kind, reflected, compared: (
                    (obj.name if kind == "table" else getattr(obj.table, "name", ""))
                    in {
                        "service_release_observations",
                        "agent_delivery_targets",
                        "agent_notice_events",
                        "agent_notice_subscriptions",
                        "agent_delivery_jobs",
                        "agent_delivery_attempts",
                    }
                ),
            },
        )
        assert compare_metadata(context, Base.metadata) == []


def test_transient_prepare_failures_exhaust_budget_without_any_send(backend, monkeypatch):
    _emit(backend)
    transport = FakeNoticeTransport()

    def fail(*args, **kwargs):
        raise OperationalError("query", {}, RuntimeError("unavailable"))

    monkeypatch.setattr(notices, "check_delivery_authorization", fail)
    for offset in (0, 61, 182):
        _run(backend, transport, NOW + timedelta(seconds=offset))
    assert transport.calls == []
    assert _job(backend).status == "failed" and _job(backend).attempts == 3
    assert _attempts(backend) == [(1, "unavailable"), (2, "unavailable"), (3, "unavailable")]


def test_slow_prepare_cannot_send_after_lease_expiry(backend):
    _emit(backend)
    times = iter([NOW, NOW, NOW + timedelta(seconds=60)])
    transport = FakeNoticeTransport()
    with backend.sessions() as session:
        stats = notices.deliver_due_agent_notices(
            session,
            transport,
            now=NOW,
            policy=notices.NoticeDeliveryPolicy(max_deliveries_per_run=1, lease_seconds=60),
            clock=lambda: next(times),
        )
    assert stats["lease_lost"] == 1 and transport.calls == []
    assert _job(backend).status == "pending"


def test_production_poller_uses_db_time_despite_worker_clock_skew(backend, monkeypatch):
    from datetime import datetime

    moment = notices._database_now(backend.sessions)
    _emit(backend)
    with backend.sessions() as session:
        job = session.scalars(select(AgentDeliveryJob)).one()
        job.next_attempt_at = moment - timedelta(seconds=1)
        job.expires_at = moment + timedelta(hours=1)
        session.commit()

    class SkewedClock(datetime):
        @classmethod
        def now(cls, tz=None):
            return datetime(2100, 1, 1, tzinfo=tz)

    monkeypatch.setattr(notices, "datetime", SkewedClock)
    transport = FakeNoticeTransport()
    notices._run_delivery_pass(backend.sessions, transport, POLICY)
    assert _job(backend).status == "delivered" and len(transport.visible) == 1


def test_independent_instances_with_equal_local_job_ids_share_receiver_safely(backend, tmp_path):
    from sqlalchemy.orm import sessionmaker

    from blockwart.db.session import build_engine

    url = f"sqlite:///{tmp_path / 'independent.sqlite3'}"
    upgrade_database(url)
    engine = build_engine(url)
    other = support.NoticeBackend("sqlite", url, engine, sessionmaker(engine))
    try:
        with other.sessions() as session:
            seed_notice_env(session)
            session.commit()
        _emit(backend, "2.0.0")
        _emit(other, "3.0.0")
        assert _job(backend).id == _job(other).id == 1
        with LoopbackReceiver() as receiver:
            transport = OpenClawTestGatewayTransport(endpoint_url=receiver.url)
            assert _run(backend, transport)["delivered"] == 1
            assert _run(other, transport)["delivered"] == 1
            assert len(set(receiver.request_ids)) == len(receiver.visible) == 2
    finally:
        engine.dispose()
