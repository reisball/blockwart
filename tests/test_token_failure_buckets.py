from __future__ import annotations

import json
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta

import pytest
from pydantic import ValidationError
from sqlalchemy import func, select

from blockwart.config import Settings
from blockwart.db.session import transaction
from blockwart.models import SecurityEvent, ServiceTokenFailureBucket
from blockwart.services.identity import utc_now
from blockwart.services.token_failure_buckets import (
    TokenFailurePolicy,
    precheck_service_token_failure,
    prune_service_token_failure_buckets,
    record_service_token_failure,
    resolve_service_token_source,
)

CANARY_TOKEN = "bwst_canary.secret-credential-material"
CANARY_SOURCE = "198.51.100.77"


def _policy(
    *,
    global_limit: int = 10,
    source_limit: int = 10,
    token_limit: int = 10,
    max_rows: int = 100,
) -> TokenFailurePolicy:
    return TokenFailurePolicy(
        window_seconds=60,
        global_limit=global_limit,
        source_limit=source_limit,
        token_limit=token_limit,
        max_rows=max_rows,
    )


@pytest.mark.parametrize(
    ("policy", "expected_dimension"),
    [
        (_policy(global_limit=1), "global"),
        (_policy(source_limit=1), "source"),
        (_policy(token_limit=1), "token"),
    ],
)
def test_each_failure_dimension_denies_uniformly_and_emits_once(
    alembic_session_factory,
    policy: TokenFailurePolicy,
    expected_dimension: str,
) -> None:
    now = utc_now()
    with alembic_session_factory() as session:
        with transaction(session):
            record_service_token_failure(
                session,
                token=CANARY_TOKEN,
                source=CANARY_SOURCE,
                policy=policy,
                channel="api",
                request_id="rate-test",
                now=now,
            )
    with alembic_session_factory() as session:
        with transaction(session):
            first = precheck_service_token_failure(
                session,
                token=CANARY_TOKEN,
                source=CANARY_SOURCE,
                policy=policy,
                channel="api",
                request_id="rate-test",
                now=now,
            )
            second = precheck_service_token_failure(
                session,
                token=CANARY_TOKEN,
                source=CANARY_SOURCE,
                policy=policy,
                channel="api",
                request_id="rate-test",
                now=now,
            )

    assert not first.allowed
    assert not second.allowed
    assert first.dimension == expected_dimension
    with alembic_session_factory() as session:
        events = list(
            session.scalars(
                select(SecurityEvent).where(
                    SecurityEvent.event_type
                    == "service_token_authentication_throttled"
                )
            ).all()
        )
        assert len(events) == 1
        assert json.loads(events[0].details_json) == {
            "count": 1,
            "dimension": expected_dimension,
            "reason": "rate_limited",
        }
        stored = " ".join(
            f"{row.dimension} {row.key_hash}"
            for row in session.scalars(select(ServiceTokenFailureBucket)).all()
        ) + " " + events[0].details_json
    assert CANARY_TOKEN not in stored
    assert CANARY_SOURCE not in stored


def test_expiry_pruning_and_row_cap_are_bounded(alembic_session_factory) -> None:
    now = utc_now()
    policy = _policy(max_rows=5)
    with alembic_session_factory() as session:
        with transaction(session):
            for index in range(20):
                record_service_token_failure(
                    session,
                    token=f"candidate-{index}",
                    source=f"198.51.100.{index + 1}",
                    policy=policy,
                    channel="api",
                    request_id="cap-test",
                    now=now,
                )
        assert session.scalar(
            select(func.count()).select_from(ServiceTokenFailureBucket)
        ) == 5
        with transaction(session):
            removed = prune_service_token_failure_buckets(
                session,
                max_rows=policy.max_rows,
                now=now + timedelta(seconds=61),
            )
        assert removed == 5
        assert session.scalar(
            select(func.count()).select_from(ServiceTokenFailureBucket)
        ) == 0


def test_parallel_failures_are_capped_and_visible_across_sessions(
    alembic_database,
) -> None:
    policy = _policy(global_limit=3, source_limit=50, token_limit=50)
    now = utc_now()

    def fail_once(index: int) -> None:
        with alembic_database.sessions() as session:
            with transaction(session):
                record_service_token_failure(
                    session,
                    token=f"parallel-{index}",
                    source=CANARY_SOURCE,
                    policy=policy,
                    channel="api",
                    request_id="parallel-test",
                    now=now,
                )

    with ThreadPoolExecutor(max_workers=8) as executor:
        list(executor.map(fail_once, range(12)))

    with alembic_database.sessions() as session:
        global_bucket = session.scalar(
            select(ServiceTokenFailureBucket).where(
                ServiceTokenFailureBucket.dimension == "global"
            )
        )
        assert global_bucket is not None
        assert global_bucket.failure_count == policy.global_limit + 1
        decision = precheck_service_token_failure(
            session,
            token="another-token",
            source="203.0.113.1",
            policy=policy,
            channel="mcp",
            request_id="parallel-check",
            now=now,
        )
        assert not decision.allowed
        assert decision.dimension == "global"

    script = """
import json, sys
from sqlalchemy.orm import Session
from blockwart.db.session import build_engine
from blockwart.services.token_failure_buckets import (
    TokenFailurePolicy,
    precheck_service_token_failure,
)
engine = build_engine(sys.argv[1])
with Session(engine) as session:
    result = precheck_service_token_failure(
        session, token='separate-process', source='203.0.113.2',
        policy=TokenFailurePolicy(window_seconds=60, global_limit=3, source_limit=50,
                                  token_limit=50, max_rows=100),
        channel='mcp', request_id='process-check')
print(json.dumps({'allowed': result.allowed, 'dimension': result.dimension}))
"""
    completed = subprocess.run(
        [sys.executable, "-c", script, alembic_database.database_url],
        capture_output=True,
        check=True,
        text=True,
    )
    assert json.loads(completed.stdout) == {"allowed": False, "dimension": "global"}


@pytest.mark.parametrize(
    ("direct", "forwarded", "trusted", "expected"),
    [
        ("192.0.2.10", "198.51.100.8", "", "192.0.2.10"),
        ("192.0.2.10", "198.51.100.8", "192.0.2.10/32", "198.51.100.8"),
        ("192.0.2.10", "198.51.100.8, 203.0.113.9", "192.0.2.10/32", "192.0.2.10"),
        ("192.0.2.10", "not-an-ip", "192.0.2.10/32", "192.0.2.10"),
        ("not-an-ip", "198.51.100.8", "0.0.0.0/0", "unknown"),
    ],
)
def test_forwarded_source_requires_exact_trusted_peer_and_strict_header(
    direct: str,
    forwarded: str,
    trusted: str,
    expected: str,
) -> None:
    assert resolve_service_token_source(
        direct_peer=direct,
        forwarded_for=forwarded,
        trusted_proxy_cidrs=trusted,
    ) == expected


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("auth_service_token_rate_window_seconds", 9),
        ("auth_service_token_global_failure_limit", 0),
        ("auth_service_token_source_failure_limit", 10001),
        ("auth_service_token_fingerprint_failure_limit", 1001),
        ("auth_service_token_failure_bucket_max_rows", 99),
        ("auth_service_token_failure_bucket_prune_interval_seconds", 9),
    ],
)
def test_failure_bucket_configuration_bounds(field: str, value: int) -> None:
    with pytest.raises(ValidationError):
        Settings(**{field: value})
