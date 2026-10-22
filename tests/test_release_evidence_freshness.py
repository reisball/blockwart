"""Successful evidence expires independently from retry scheduling. Refs #268."""

from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select
from test_release_monitoring import _service

import blockwart.services.release_monitoring as service
from blockwart.domain.release_monitoring import (
    ReleaseObservation,
    ReleaseRecord,
    release_freshness_for,
)
from blockwart.models import ServiceReleaseObservation
from blockwart.services.catalog import upsert_object
from blockwart.services.release_monitoring import ReleaseMonitoringSettings, check_service_release

NOW = datetime(2026, 10, 22, 12, tzinfo=UTC)
INTERVAL = 86400


@pytest.mark.parametrize(
    ("offset", "expected"),
    [
        (timedelta(days=1, microseconds=-1), "fresh"),
        (timedelta(days=1), "fresh"),
        (timedelta(days=1, microseconds=1), "stale"),
        (timedelta(days=2.9), "stale"),
    ],
)
@pytest.mark.parametrize("retry_due", [timedelta(hours=1), timedelta(days=8), None])
def test_evidence_age_ignores_retry_deadline(offset, expected, retry_due):
    record = ReleaseRecord(
        provider="github_releases",
        last_success_at=NOW,
        last_checked_at=NOW + timedelta(days=1),
        consecutive_failures=3,
        error_code="not_found",
        next_due_at=NOW + retry_due if retry_due else None,
    )
    assert release_freshness_for(record, interval_seconds=INTERVAL, now=NOW + offset) == expected


def test_never_successful_is_pending_and_recovery_starts_new_window():
    never = ReleaseRecord(
        provider="github_releases",
        last_checked_at=NOW,
        next_due_at=NOW + timedelta(days=8),
        error_code="not_found",
    )
    assert release_freshness_for(never, interval_seconds=INTERVAL, now=NOW) == "pending"
    recovered = replace(never, last_success_at=NOW + timedelta(days=4), error_code=None)
    assert (
        release_freshness_for(recovered, interval_seconds=INTERVAL, now=NOW + timedelta(days=4))
        == "fresh"
    )


def test_success_then_failure_preserves_evidence_without_rejuvenation(
    alembic_session_factory,
    monkeypatch,
):
    moments = [NOW, NOW + timedelta(days=1), NOW + timedelta(days=3)]
    observations = iter(
        [
            ReleaseObservation(
                provider="github_releases",
                outcome="observed",
                checked_at=moments[0],
                latest_tag="v2.0.0",
                latest_version="2.0.0",
                http_status=200,
            ),
            ReleaseObservation(
                provider="github_releases",
                outcome="error",
                checked_at=moments[1],
                error_code="not_found",
                http_status=404,
            ),
            ReleaseObservation(
                provider="github_releases",
                outcome="not_modified",
                checked_at=moments[2],
                http_status=304,
            ),
        ]
    )
    monkeypatch.setattr(service, "fetch_latest_github_release", lambda request: next(observations))
    settings = ReleaseMonitoringSettings(enabled=True, jitter_seconds=0)
    with alembic_session_factory() as session:
        upsert_object(session, _service("backoff-evidence"))
        session.commit()
        first = check_service_release(
            session, object_id="backoff-evidence", settings=settings, manual=True, now=moments[0]
        )
        assert first.projection["freshness"] == "fresh"
        failed = check_service_release(
            session, object_id="backoff-evidence", settings=settings, manual=True, now=moments[1]
        )
        assert failed.projection["status"] == "error"
        row = session.scalar(select(ServiceReleaseObservation))
        assert row.last_success_at == NOW.replace(tzinfo=None)
        assert row.latest_version == "2.0.0"
        # Backoff scheduling is unchanged: second attempt is delayed by two intervals.
        assert row.next_due_at == moments[2].replace(tzinfo=None)
        record = service.load_release_observation_index(session, object_ids=["backoff-evidence"])[
            ("backoff-evidence", "github_releases")
        ]
        assert (
            release_freshness_for(record, interval_seconds=INTERVAL, now=NOW + timedelta(days=2.9))
            == "stale"
        )
        recovered = check_service_release(
            session, object_id="backoff-evidence", settings=settings, manual=True, now=moments[2]
        )
        assert recovered.projection["freshness"] == "fresh"
        assert recovered.projection["consecutive_failures"] == 0
