"""Target-bound evidence, late results and lease reset. Refs #269."""

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import func, select
from sqlalchemy.orm import sessionmaker
from test_postgresql_compat_regressions import (  # noqa: F401
    migrated_pg_engine,
    pg_database_name,
)

import blockwart.services.monitoring as monitoring_service
from blockwart.domain.monitoring import MonitoringObservation
from blockwart.domain.monitoring_sources import parse_monitoring_pull_sources
from blockwart.models import AuditEvent, CatalogObject, ServiceCheckLease
from blockwart.schemas.catalog import CatalogObjectIn
from blockwart.services.catalog import upsert_object
from blockwart.services.monitoring import (
    MonitoringSettings,
    load_observation_index,
    monitoring_projection,
    monitoring_target_fingerprint,
    record_service_observation,
    run_due_service_checks,
    synchronize_check_schedule,
)


@pytest.fixture(params=["sqlite", "postgresql"])
def binding_session_factory(request, alembic_session_factory):
    if request.param == "sqlite":
        return alembic_session_factory
    return sessionmaker(request.getfixturevalue("migrated_pg_engine"))


NOW = datetime(2026, 10, 22, 12, tzinfo=UTC)


def _endpoint(*, url, health_url):
    return {
        "id": "web",
        "type": "Web",
        "url": url,
        "health_url": health_url,
        "protocol": "https",
        "port": 443,
    }


def _service(object_id, *, monitoring, endpoints):
    return CatalogObjectIn(
        id=object_id,
        kind="service",
        label="Service",
        data={"schema_version": 1, "monitoring": monitoring, "endpoints": endpoints},
    )


def test_target_change_invalidates_old_health_and_schedules_new_check(binding_session_factory):
    settings = MonitoringSettings(jitter_seconds=0)

    def payload(url):
        return _service(
            "target-change",
            monitoring={"enabled": True},
            endpoints=[_endpoint(url=url, health_url=url)],
        )

    with binding_session_factory() as session:
        first = upsert_object(session, payload("https://old.example/health"))
        session.commit()
        row = session.get(CatalogObject, first.id)
        record_service_observation(
            session,
            object_id=first.id,
            object_instance_id=row.instance_id,
            observation=MonitoringObservation(
                provider="builtin_http", state="healthy", checked_at=NOW, http_status=200
            ),
            settings=settings,
        )
        synchronize_check_schedule(session, now=NOW, settings=settings)
        session.commit()
        changed = upsert_object(session, payload("https://new.example/health"))
        session.commit()
        view = monitoring_projection(
            kind="service",
            object_id=first.id,
            data=changed.data,
            catalog_health="unknown",
            observations=load_observation_index(session),
            now=NOW + timedelta(seconds=1),
            settings=settings,
        )
        assert view["state"] == "unknown"
        assert view["freshness"] == "pending"
        synchronize_check_schedule(session, now=NOW + timedelta(seconds=1), settings=settings)
        session.commit()
        lease = session.scalar(select(ServiceCheckLease))
        assert lease.due_at <= (NOW + timedelta(seconds=1)).replace(tzinfo=None)


@pytest.mark.parametrize("provider", ["builtin_http", "gatus"])
def test_delayed_old_target_result_is_rejected_and_new_target_recovers(
    binding_session_factory,
    provider,
):
    settings = MonitoringSettings(
        jitter_seconds=0,
        gatus_sources=parse_monitoring_pull_sources(sources="prod=https://gatus.example/status"),
    )

    def data(name):
        monitoring = {"enabled": True, "provider": provider}
        if provider == "gatus":
            monitoring["gatus"] = {"source": "prod", "group": "core", "endpoint": name}
        return _service(
            "delayed",
            monitoring=monitoring,
            endpoints=[
                _endpoint(
                    url=f"https://{name}.example/health",
                    health_url=f"https://{name}.example/health",
                )
            ],
        )

    with binding_session_factory() as session:
        first = upsert_object(session, data("old"))
        session.commit()
        instance = session.get(CatalogObject, first.id).instance_id
        old_fingerprint = monitoring_target_fingerprint(
            first.data, object_id=first.id, provider=provider, settings=settings
        )
        record_service_observation(
            session,
            object_id=first.id,
            object_instance_id=instance,
            observation=MonitoringObservation(provider=provider, state="healthy", checked_at=NOW),
            settings=settings,
            target_fingerprint=old_fingerprint,
        )
        session.commit()
        changed = upsert_object(session, data("new"))
        session.commit()
        revision = changed.revision
        audit_count = session.scalar(select(func.count(AuditEvent.id)))
        delayed = record_service_observation(
            session,
            object_id=first.id,
            object_instance_id=instance,
            settings=settings,
            target_fingerprint=old_fingerprint,
            observation=MonitoringObservation(
                provider=provider, state="healthy", checked_at=NOW + timedelta(seconds=2)
            ),
        )
        assert delayed is None
        view = monitoring_projection(
            kind="service",
            object_id=first.id,
            data=changed.data,
            catalog_health="unknown",
            observations=load_observation_index(session),
            now=NOW + timedelta(seconds=3),
            settings=settings,
        )
        assert (view["state"], view["freshness"]) == ("unknown", "pending")
        fingerprint = monitoring_target_fingerprint(
            changed.data, object_id=first.id, provider=provider, settings=settings
        )
        # New target's upstream instant may precede old target's evidence.
        recovered = record_service_observation(
            session,
            object_id=first.id,
            object_instance_id=instance,
            settings=settings,
            target_fingerprint=fingerprint,
            observation=MonitoringObservation(
                provider=provider,
                state="down",
                checked_at=NOW - timedelta(seconds=1),
                received_at=NOW + timedelta(seconds=4),
            ),
        )
        assert recovered.state == "down"
        assert recovered.last_success_at is None
        session.commit()
        assert session.get(CatalogObject, first.id).revision == revision
        assert session.scalar(select(func.count(AuditEvent.id))) == audit_count


def test_target_edit_during_acquisition_cannot_publish_old_success(
    binding_session_factory,
    monkeypatch,
):
    settings = MonitoringSettings(poller_enabled=True, jitter_seconds=0)

    def payload(name):
        return _service(
            "inflight",
            monitoring={"enabled": True},
            endpoints=[
                _endpoint(
                    url=f"https://{name}.example/health",
                    health_url=f"https://{name}.example/health",
                )
            ],
        )

    with binding_session_factory() as session:
        upsert_object(session, payload("old"))
        session.commit()

        def acquire(requests, *, max_workers):
            assert requests[0][1].target_fingerprint == requests[0][0].target_fingerprint
            with binding_session_factory() as editor:
                upsert_object(editor, payload("new"))
                editor.commit()
            return [MonitoringObservation(provider="builtin_http", state="healthy", checked_at=NOW)]

        monkeypatch.setattr(monitoring_service, "_acquire", acquire)
        result = run_due_service_checks(session, settings=settings, now=NOW, owner="target-test")
        assert result.claimed == 1
        assert result.completed == 0
        current = payload("new")
        view = monitoring_projection(
            kind="service",
            object_id=current.id,
            data=current.data,
            catalog_health="unknown",
            observations=load_observation_index(session),
            now=NOW,
            settings=settings,
        )
        assert view["state"] == "unknown"
        synchronize_check_schedule(session, now=NOW, settings=settings)
        assert session.scalar(select(ServiceCheckLease)).due_at == NOW.replace(tzinfo=None)


def test_interval_and_label_do_not_invalidate_evidence_but_gatus_binding_does():
    import copy

    settings = MonitoringSettings(
        gatus_sources=parse_monitoring_pull_sources(sources="prod=https://gatus.example/status")
    )
    data = {
        "schema_version": 1,
        "monitoring": {
            "enabled": True,
            "provider": "gatus",
            "gatus": {"source": "prod", "group": "core", "endpoint": "api"},
        },
    }
    baseline = monitoring_target_fingerprint(
        data, object_id="service", provider="gatus", settings=settings
    )
    changed = copy.deepcopy(data)
    changed["monitoring"]["interval_seconds"] = 900
    assert (
        monitoring_target_fingerprint(
            changed, object_id="service", provider="gatus", settings=settings
        )
        == baseline
    )
    rebound = MonitoringSettings(
        gatus_sources=parse_monitoring_pull_sources(sources="prod=https://different.example/status")
    )
    assert (
        monitoring_target_fingerprint(data, object_id="service", provider="gatus", settings=rebound)
        != baseline
    )
