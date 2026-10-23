"""Deterministic two-session monitoring races. Refs #269."""

from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.sql.dml import Delete, Insert, Update
from test_monitoring_target_binding import (
    NOW,
    _endpoint,
    _service,
    binding_session_factory,  # noqa: F401
    migrated_pg_engine,  # noqa: F401
    pg_database_name,  # noqa: F401
)

from blockwart.domain.monitoring import MonitoringObservation
from blockwart.models import CatalogObject, ServiceCheckLease, ServiceObservation
from blockwart.services.catalog import upsert_object
from blockwart.services.monitoring import (
    MonitoringSettings,
    claim_due_checks,
    load_observation_index,
    monitoring_projection,
    monitoring_target_fingerprint,
    record_service_observation,
    synchronize_check_schedule,
)

SETTINGS = MonitoringSettings(poller_enabled=True, jitter_seconds=0)


def payload(name):
    url = f"https://{name}.example/health"
    return _service(
        "race", monitoring={"enabled": True}, endpoints=[_endpoint(url=url, health_url=url)]
    )


def fingerprint(name):
    return monitoring_target_fingerprint(
        payload(name).data, object_id="race", provider="builtin_http", settings=SETTINGS
    )


def observe(session, instance, name, state, instant):
    return record_service_observation(
        session,
        object_id="race",
        object_instance_id=instance,
        observation=MonitoringObservation(provider="builtin_http", state=state, checked_at=instant),
        target_fingerprint=fingerprint(name),
        settings=SETTINGS,
        now=instant,
    )


def test_sqlite_late_a_cannot_overwrite_committed_b(alembic_session_factory, monkeypatch):
    factory = alembic_session_factory
    with factory() as s:
        upsert_object(s, payload("a"))
        s.commit()
        instance = s.get(CatalogObject, "race").instance_id
    with factory() as late:
        execute = late.execute
        fired = False

        def interleave(statement, *args, **kwargs):
            nonlocal fired
            if (
                isinstance(statement, Insert)
                and statement.table.name == "service_observations"
                and not fired
            ):
                fired = True
                with factory() as editor:
                    upsert_object(editor, payload("b"))
                    editor.commit()
                    observe(editor, instance, "b", "down", NOW + timedelta(seconds=1))
                    editor.commit()
                print("B edit and B down evidence committed before A INSERT")
            return execute(statement, *args, **kwargs)

        monkeypatch.setattr(late, "execute", interleave)
        accepted = observe(late, instance, "a", "healthy", NOW)
        late.commit()
        assert fired, "Ingestion write interleaving was not reached"
        assert accepted is None
        print("late A accepted:", accepted is not None)
    with factory() as s:
        stored = s.scalar(select(ServiceObservation))
        view = monitoring_projection(
            kind="service",
            object_id="race",
            data=payload("b").data,
            catalog_health="unknown",
            observations=load_observation_index(s),
            now=NOW + timedelta(seconds=2),
            settings=SETTINGS,
        )
        print(
            "stored target:",
            "a" if stored.target_fingerprint == fingerprint("a") else "b",
            "stored state:",
            stored.state,
            "B projection:",
            view["state"],
            view["freshness"],
        )
        assert stored.target_fingerprint == fingerprint("b"), "Late A replaced committed B evidence"
        assert stored.state == "down"
        assert (view["state"], view["freshness"]) == ("down", "fresh")


def test_reconciliation_preserves_other_workers_live_claim(
    binding_session_factory,  # noqa: F811
    monkeypatch,
):
    factory = binding_session_factory
    with factory() as s:
        upsert_object(s, payload("a"))
        synchronize_check_schedule(s, settings=SETTINGS, now=NOW)
        s.commit()
        lease = s.scalar(select(ServiceCheckLease))
        lease.lease_owner = "expired-a"
        lease.lease_expires_at = (NOW - timedelta(seconds=1)).replace(tzinfo=None)
        s.commit()
        upsert_object(s, payload("b"))
        s.commit()
    with factory() as slow:
        fired = False
        execute = slow.execute

        def interleave(statement, *args, **kwargs):
            nonlocal fired
            is_rebind = (
                isinstance(statement, Update) and statement.table.name == "service_check_leases"
            )
            is_old_flush = (
                isinstance(statement, Delete) and statement.table.name == "service_observations"
            )
            if (is_rebind or is_old_flush) and not fired:
                fired = True
                with factory() as fast:
                    synchronize_check_schedule(fast, settings=SETTINGS, now=NOW)
                    fast.commit()
                    claims = claim_due_checks(fast, owner="live-b", now=NOW, settings=SETTINGS)
                    assert len(claims) == 1
                    print(
                        "worker 2 claimed B until:",
                        fast.scalar(select(ServiceCheckLease)).lease_expires_at,
                    )
            return execute(statement, *args, **kwargs)

        monkeypatch.setattr(slow, "execute", interleave)
        synchronize_check_schedule(slow, settings=SETTINGS, now=NOW)
        slow.commit()
        assert fired, "Reconciliation write interleaving was not reached"
    with factory() as third:
        lease = third.scalar(select(ServiceCheckLease))
        assert lease.lease_owner == "live-b"
        assert lease.lease_expires_at == (NOW + timedelta(seconds=60)).replace(tzinfo=None)
        assert lease.target_fingerprint == fingerprint("b")
        print("after stale worker 1 flush:", lease.lease_owner, lease.lease_expires_at)
        claims = claim_due_checks(third, owner="duplicate-b", now=NOW, settings=SETTINGS)
        print("worker 3 duplicate claims:", len(claims))
        assert not claims, "Stale reconciliation cleared worker 2 live B lease"
