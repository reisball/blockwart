"""Honest, durable, bounded approver hints for access requests (Issue #100).

Every test body runs on SQLite and, when ``BLOCKWART_TEST_PG_URL`` is
reachable, on PostgreSQL. All HTTP is a loopback fake gateway on 127.0.0.1.
"""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
import time
from datetime import datetime, timedelta

import pytest
from access_request_support import (
    FrozenClock,
    authorization,
    make_backend_fixture,
    write_context,
)
from notice_support import LoopbackReceiver
from sqlalchemy import create_engine, make_url, select, text, update

from blockwart.config import Settings
from blockwart.db.session import transaction
from blockwart.domain.access_request_notices import (
    ACCESS_REQUEST_NOTICE_MESSAGE,
    delivery_id_for_notice,
)
from blockwart.domain.auth import GrantScope, Role
from blockwart.models import (
    AccessRequest,
    AccessRequestNotice,
    AccessRequestNoticeAttempt,
    AuditEvent,
    ObjectGrant,
    Principal,
    ServiceToken,
)
from blockwart.services import access_request_notices as notices
from blockwart.services import access_requests as service
from blockwart.services.access import create_object_grant, revoke_object_grant
from blockwart.services.access_request_notices import (
    DISABLED_ROUTING,
    NoticeRouting,
    count_notices_by_status,
    deliver_due_access_request_notices,
    notice_routing_from_settings,
    resolve_recipient_targets,
)
from blockwart.services.agent_notices import (
    NoticeDeliveryPolicy,
    create_agent_delivery_target,
    deactivate_agent_delivery_target,
)
from blockwart.services.identity import create_service_account
from blockwart.services.notice_transport import (
    DeliveryOutcome,
    FakeNoticeTransport,
    OpenClawTestGatewayTransport,
)

NOW = datetime(2026, 10, 9, 12, 0, 0)
POLICY = NoticeDeliveryPolicy(
    max_attempts=3,
    ttl_seconds=3600,
    backoff_base_seconds=60,
    backoff_max_seconds=600,
    max_pending_jobs_per_target=50,
    lease_seconds=60,
)
ROUTING = NoticeRouting(enabled=True, policy=POLICY)
SECRET_REASON = "my-password-is-hunter2 and also http://evil.example/x?token=abc"

backend = make_backend_fixture()


@pytest.fixture
def frozen(monkeypatch) -> FrozenClock:
    return FrozenClock(monkeypatch, NOW)


def _route(backend, who: str, route: str | None = None) -> str:
    with backend.session() as session:
        with transaction(session):
            target = create_agent_delivery_target(
                session,
                principal_id=backend.principals[who],
                label=f"inbox {who}",
                route=route or f"openclaw-agent:{who}-inbox",
                transport="openclaw_test_gateway",
            )
            return target.id


def _file(
    backend,
    *,
    who: str = "discoverer",
    routing: NoticeRouting = ROUTING,
    reason: str | None = SECRET_REASON,
    principal_id: str | None = None,
) -> str:
    with backend.session() as session:
        with transaction(session):
            return service.create_access_request(
                session,
                write_context(session, principal_id or backend.principals[who]),
                object_id="ar-root",
                duration="temporary",
                ttl_seconds=3600,
                reason=reason,
                routing=routing,
            ).request_id


def _notice_rows(backend) -> list[AccessRequestNotice]:
    with backend.session() as session:
        rows = list(
            session.scalars(
                select(AccessRequestNotice).order_by(
                    AccessRequestNotice.created_at, AccessRequestNotice.id
                )
            )
        )
        for row in rows:
            session.expunge(row)
        return rows


def _attempts(backend) -> list[tuple[int, str, str | None]]:
    with backend.session() as session:
        return [
            (row.attempt_no, row.outcome, row.error_code)
            for row in session.scalars(
                select(AccessRequestNoticeAttempt).order_by(AccessRequestNoticeAttempt.id)
            )
        ]


def _deliver(
    backend,
    transport,
    moment: datetime = NOW,
    *,
    worker: str = "w",
    policy: NoticeDeliveryPolicy = POLICY,
) -> dict[str, int]:
    with backend.session() as session:
        return deliver_due_access_request_notices(
            session, transport, now=moment, policy=policy, worker_id=worker
        )


def _creation_audit(backend) -> dict:
    with backend.session() as session:
        event = session.scalars(
            select(AuditEvent).where(AuditEvent.action == "access_request_create")
        ).one()
        return json.loads(event.details_json)


# --------------------------------------------------------------------------
# Honest routing state: nothing is "delivered" because a no-op ran
# --------------------------------------------------------------------------


def test_disabled_routing_creates_no_notice_and_reports_disabled(backend, frozen) -> None:
    _route(backend, "owner")
    _file(backend, routing=DISABLED_ROUTING)

    assert _notice_rows(backend) == []
    assert _creation_audit(backend)["notification"] == "disabled"
    assert count_notices_by_status_total(backend) == dict.fromkeys(
        ("pending", "delivered", "failed", "suppressed", "expired"), 0
    )


def test_no_approved_route_reports_no_route_not_delivered(backend, frozen) -> None:
    _file(backend)
    assert _notice_rows(backend) == []
    assert _creation_audit(backend)["notification"] == "no_route"


def count_notices_by_status_total(backend) -> dict[str, int]:
    with backend.session() as session:
        return count_notices_by_status(session)


def test_routes_exist_only_for_principals_that_can_decide_now(backend, frozen) -> None:
    owner = _route(backend, "owner")
    manager = _route(backend, "manager")
    _route(backend, "outsider")  # no manage_access
    _route(backend, "reader")  # read only
    _route(backend, "discoverer")  # the requester itself

    request_id = _file(backend)

    rows = _notice_rows(backend)
    assert {row.target_id for row in rows} == {owner, manager}
    assert {row.request_id for row in rows} == {request_id}
    assert all(row.status == "pending" and row.attempts == 0 for row in rows)
    assert _creation_audit(backend)["notification"] == "queued"


def test_inactive_revoked_or_tokenless_principals_are_never_recipients(
    backend, frozen
) -> None:
    for who in ("owner", "manager"):
        _route(backend, who)
    with backend.session() as session:
        with transaction(session):
            session.get(Principal, backend.principals["owner"]).active = False
            for token in session.scalars(
                select(ServiceToken).where(
                    ServiceToken.principal_id == backend.principals["manager"]
                )
            ):
                token.revoked_at = NOW - timedelta(hours=1)
    with backend.session() as session:
        assert (
            resolve_recipient_targets(
                session,
                object_id="ar-root",
                requester_principal_id=backend.principals["discoverer"],
                now=NOW,
            )
            == []
        )
    _file(backend)
    assert _notice_rows(backend) == []
    assert _creation_audit(backend)["notification"] == "no_route"


def test_routing_needs_opt_in_poller_and_a_loopback_endpoint() -> None:
    def routing(**flags):
        base = {
            "database_url": "sqlite://",
            "access_request_notices_enabled": True,
            "notice_delivery_poller_enabled": True,
            "notice_delivery_endpoint_url": "http://127.0.0.1:9/notify",
        }
        return notice_routing_from_settings(Settings(**{**base, **flags})).enabled

    assert routing() is True
    assert routing(access_request_notices_enabled=False) is False
    assert routing(notice_delivery_poller_enabled=False) is False
    assert routing(notice_delivery_endpoint_url="") is False
    assert notice_routing_from_settings(Settings(database_url="sqlite://")).enabled is False


def test_the_unrestricted_webhook_notifier_is_gone() -> None:
    with pytest.raises(ImportError):
        __import__("blockwart.services.access_notifications")


# --------------------------------------------------------------------------
# Delivery: minimal payload, delivered only on confirmed acceptance
# --------------------------------------------------------------------------


def test_payload_is_closed_minimal_and_free_of_untrusted_content(backend, frozen) -> None:
    owner = _route(backend, "owner", "openclaw-agent:owner-inbox")
    request_id = _file(backend)
    transport = FakeNoticeTransport()

    stats = _deliver(backend, transport)

    assert stats["delivered"] == 1 and stats["failed"] == 0
    (sent,) = transport.calls
    assert sent.target_route == "openclaw-agent:owner-inbox"
    assert sent.target_id == owner
    assert sent.payload == {
        "schema_version": 1,
        "event_type": "access_request_pending",
        "request_id": request_id,
        "object_ref": "host:ar-root",
        "message": ACCESS_REQUEST_NOTICE_MESSAGE,
        "blockwart_reference": "/api/v1/access-requests",
    }
    rendered = json.dumps(sent.payload) + sent.delivery_id + sent.target_route
    for forbidden in (
        "hunter2",
        "evil.example",
        "ar.discoverer",
        "Access Discoverer",
        backend.principals["discoverer"],
        "Access Root",
        "bwst_",
        "http",
    ):
        assert forbidden not in rendered
    (row,) = _notice_rows(backend)
    assert sent.delivery_id == delivery_id_for_notice(row.id)
    assert row.status == "delivered" and row.delivered_at == NOW
    assert _attempts(backend) == [(1, "success", None)]


def test_delivery_ids_are_unique_across_databases(tmp_path, monkeypatch) -> None:
    """The receiver-side key must not repeat for two different logical notices."""
    from access_request_support import seed_access_world
    from sqlalchemy.orm import sessionmaker

    from blockwart.db.migrations import upgrade_database
    from blockwart.db.session import build_engine

    FrozenClock(monkeypatch, NOW)
    ids: list[str] = []
    for index in range(2):
        url = f"sqlite:///{tmp_path / f'db-{index}.sqlite3'}"
        upgrade_database(url)
        engine = build_engine(url)
        sessions = sessionmaker(bind=engine, autoflush=False)
        with sessions() as session:
            with transaction(session):
                world = seed_access_world(session)
                create_agent_delivery_target(
                    session,
                    principal_id=world["principals"]["owner"],
                    label="inbox",
                    route="openclaw-agent:owner-inbox",
                    transport="openclaw_test_gateway",
                )
                service.create_access_request(
                    session,
                    write_context(session, world["principals"]["discoverer"]),
                    object_id="ar-root",
                    duration="temporary",
                    ttl_seconds=3600,
                    reason=None,
                    routing=ROUTING,
                )
            transport = FakeNoticeTransport()
            deliver_due_access_request_notices(session, transport, now=NOW, policy=POLICY)
            ids.append(transport.calls[0].delivery_id)
        engine.dispose()
    assert ids[0] != ids[1]


def test_an_unconfirmed_delivery_is_never_reported_as_delivered(backend, frozen) -> None:
    _route(backend, "owner")
    _file(backend)
    transport = FakeNoticeTransport()
    transport.enqueue_result(DeliveryOutcome(ok=False, error_code="transport_unavailable"))

    stats = _deliver(backend, transport)

    assert stats["delivered"] == 0 and stats["retried"] == 1
    (row,) = _notice_rows(backend)
    assert row.status == "pending" and row.delivered_at is None
    assert row.last_error_code == "transport_unavailable"
    assert row.next_attempt_at == NOW + timedelta(seconds=60)


# --------------------------------------------------------------------------
# Authorization is rechecked at every attempt
# --------------------------------------------------------------------------


def _set_request_status(backend, request_id: str, status: str) -> None:
    with backend.session() as session:
        with transaction(session):
            session.execute(
                update(AccessRequest)
                .where(AccessRequest.id == request_id)
                .values(status=status)
            )


def _revoke_manager_grant(backend) -> None:
    with backend.session() as session:
        with transaction(session):
            grant = session.scalar(
                select(ObjectGrant).where(
                    ObjectGrant.principal_id == backend.principals["manager"],
                    ObjectGrant.role == "access_manager",
                )
            )
            assert revoke_object_grant(session, grant_id=grant.id)


def _lose_authorization(backend, cause: str, target_id: str, request_id: str) -> str:
    """Apply one cause; return the safe code the attempt must record."""
    if cause == "target_revoked":
        with backend.session() as session:
            with transaction(session):
                assert deactivate_agent_delivery_target(session, target_id=target_id, now=NOW)
        return "target_inactive"
    if cause == "principal_deactivated":
        with backend.session() as session:
            with transaction(session):
                session.get(Principal, backend.principals["manager"]).active = False
        return "principal_inactive"
    if cause == "token_revoked":
        with backend.session() as session:
            with transaction(session):
                for token in session.scalars(
                    select(ServiceToken).where(
                        ServiceToken.principal_id == backend.principals["manager"]
                    )
                ):
                    token.revoked_at = NOW
        return "principal_inactive"
    if cause == "manage_access_lost":
        _revoke_manager_grant(backend)
        return "manage_access_lost"
    if cause == "request_cancelled":
        _set_request_status(backend, request_id, "cancelled")
        return "request_not_pending"
    if cause == "request_decided":
        _set_request_status(backend, request_id, "denied")
        return "request_not_pending"
    if cause == "requester_deactivated":
        with backend.session() as session:
            with transaction(session):
                session.get(Principal, backend.principals["discoverer"]).active = False
        return "request_not_pending"
    raise AssertionError(cause)


@pytest.mark.parametrize(
    "cause",
    [
        "target_revoked",
        "principal_deactivated",
        "token_revoked",
        "manage_access_lost",
        "request_cancelled",
        "request_decided",
        "requester_deactivated",
    ],
)
def test_every_lost_authorization_suppresses_the_notice_before_anything_is_sent(
    backend, frozen, cause
) -> None:
    target_id = _route(backend, "manager")
    request_id = _file(backend)
    code = _lose_authorization(backend, cause, target_id, request_id)
    transport = FakeNoticeTransport()

    stats = _deliver(backend, transport)

    assert transport.calls == [], "nothing may leave Blockwart"
    assert stats["suppressed"] == 1 and stats["delivered"] == 0
    (row,) = _notice_rows(backend)
    assert row.status == "suppressed" and row.last_error_code == code
    assert row.attempts == 0 and row.delivered_at is None
    assert _attempts(backend) == []


def test_a_request_window_that_elapsed_suppresses_the_notice(backend, frozen) -> None:
    _route(backend, "manager")
    long_ttl = NoticeDeliveryPolicy(ttl_seconds=86400, lease_seconds=60)
    _file(backend, routing=NoticeRouting(enabled=True, policy=long_ttl))
    transport = FakeNoticeTransport()

    # The request asked for one hour; two hours later it can no longer be decided.
    stats = _deliver(backend, transport, NOW + timedelta(hours=2), policy=long_ttl)

    assert transport.calls == [] and stats["suppressed"] == 1
    (row,) = _notice_rows(backend)
    assert row.last_error_code == "request_not_pending"


def test_deciding_or_cancelling_suppresses_unclaimed_notices_eagerly(backend, frozen) -> None:
    _route(backend, "owner")
    _route(backend, "manager")
    request_id = _file(backend)
    assert {row.status for row in _notice_rows(backend)} == {"pending"}

    with backend.session() as session:
        with transaction(session):
            service.decide_access_request(
                session,
                write_context(session, backend.principals["owner"]),
                request_id=request_id,
                approve=False,
            )
    rows = _notice_rows(backend)
    assert {row.status for row in rows} == {"suppressed"}
    assert {row.last_error_code for row in rows} == {"request_not_pending"}

    transport = FakeNoticeTransport()
    assert _deliver(backend, transport)["delivered"] == 0
    assert transport.calls == []


def test_a_global_catalog_owner_route_is_authorized_by_current_policy(backend, frozen) -> None:
    with backend.session() as session:
        with transaction(session):
            account = create_service_account(
                session, login="ar.catalog-owner", display_name="Catalog Owner"
            )
            session.get(Principal, account.id).catalog_role = "catalog_owner"
            from blockwart.services.identity import issue_service_token

            issue_service_token(session, principal_id=account.id, name="n")
            target = create_agent_delivery_target(
                session,
                principal_id=account.id,
                label="co",
                route="openclaw-agent:catalog-owner",
                transport="openclaw_test_gateway",
            )
            target_id = target.id
    _file(backend)
    assert [row.target_id for row in _notice_rows(backend)] == [target_id]


# --------------------------------------------------------------------------
# Bounded retries, TTL, dead letter, redacted outcomes
# --------------------------------------------------------------------------


def test_retries_back_off_then_dead_letter_with_redacted_attempts(backend, frozen) -> None:
    _route(backend, "owner")
    _file(backend)
    transport = FakeNoticeTransport()
    transport.enqueue_result(
        DeliveryOutcome(ok=False, error_code="transport_timeout"),
        DeliveryOutcome(ok=False, error_code="rate_limited"),
        DeliveryOutcome(ok=False, error_code="transport_unavailable"),
    )

    assert _deliver(backend, transport, NOW)["retried"] == 1
    assert _deliver(backend, transport, NOW + timedelta(seconds=30))["retried"] == 0  # not due
    (row,) = _notice_rows(backend)
    assert row.next_attempt_at == NOW + timedelta(seconds=60)

    assert _deliver(backend, transport, NOW + timedelta(seconds=60))["retried"] == 1
    (row,) = _notice_rows(backend)
    assert row.next_attempt_at == NOW + timedelta(seconds=60 + 120)

    last = _deliver(backend, transport, NOW + timedelta(seconds=180))
    assert last["failed"] == 1
    (row,) = _notice_rows(backend)
    assert row.status == "failed" and row.attempts == 3
    assert row.last_error_code == "transport_unavailable"
    assert _attempts(backend) == [
        (1, "timeout", "transport_timeout"),
        (2, "rate_limited", "rate_limited"),
        (3, "unavailable", "transport_unavailable"),
    ]
    # Dead letters are terminal: a later pass never touches them again.
    quiet = FakeNoticeTransport()
    _deliver(backend, quiet, NOW + timedelta(days=2))
    assert quiet.calls == []
    assert len(transport.calls) == 3


def test_ttl_expires_the_notice_without_sending(backend, frozen) -> None:
    _route(backend, "owner")
    _file(backend)
    transport = FakeNoticeTransport()

    stats = _deliver(backend, transport, NOW + timedelta(seconds=3601))

    assert stats["expired"] == 1 and transport.calls == []
    (row,) = _notice_rows(backend)
    assert row.status == "expired" and row.last_error_code == "ttl_expired"
    assert row.attempts == 0


def test_a_backoff_that_would_outlive_the_ttl_dead_letters_instead(backend, frozen) -> None:
    _route(backend, "owner")
    short = NoticeDeliveryPolicy(
        max_attempts=5, ttl_seconds=100, backoff_base_seconds=60, lease_seconds=60
    )
    _file(backend, routing=NoticeRouting(enabled=True, policy=short))
    transport = FakeNoticeTransport()
    transport.enqueue_result(
        DeliveryOutcome(ok=False, error_code="transport_unavailable"),
        DeliveryOutcome(ok=False, error_code="transport_unavailable"),
    )
    assert _deliver(backend, transport, NOW, policy=short)["retried"] == 1
    # The second retry would be due at NOW+60+120, after the TTL at NOW+100.
    assert _deliver(backend, transport, NOW + timedelta(seconds=60), policy=short)["failed"] == 1
    (row,) = _notice_rows(backend)
    assert row.status == "failed"


def test_a_transport_exception_is_a_coarse_retry_not_a_crash(backend, frozen) -> None:
    _route(backend, "owner")
    _file(backend)

    class Exploding:
        timeout_seconds = 0.0

        def deliver(self, request):
            raise RuntimeError("secret endpoint http://10.0.0.5/ token=abc")

    stats = _deliver(backend, Exploding())
    assert stats["retried"] == 1
    (row,) = _notice_rows(backend)
    assert row.last_error_code == "transport_unavailable"
    assert "secret" not in json.dumps(_attempts(backend))


def test_a_fault_while_rechecking_retries_instead_of_dead_lettering(
    backend, frozen, monkeypatch
) -> None:
    _route(backend, "owner")
    _file(backend)
    original = notices._recipient_state
    calls = {"count": 0}

    def flaky(*args, **kwargs):
        calls["count"] += 1
        if calls["count"] == 1:  # the first attempt-time recheck
            raise RuntimeError("transient database blip")
        return original(*args, **kwargs)

    calls["count"] = 0
    monkeypatch.setattr(notices, "_recipient_state", flaky)
    transport = FakeNoticeTransport()
    assert _deliver(backend, transport, NOW)["retried"] == 1
    assert transport.calls == []
    (row,) = _notice_rows(backend)
    assert row.status == "pending" and row.last_error_code == "delivery_error"

    assert _deliver(backend, transport, NOW + timedelta(seconds=60))["delivered"] == 1


def test_storm_guard_suppresses_notices_beyond_the_pending_cap(backend, frozen) -> None:
    _route(backend, "owner")
    capped = NoticeRouting(
        enabled=True,
        policy=NoticeDeliveryPolicy(max_pending_jobs_per_target=1, lease_seconds=60),
    )
    with backend.session() as session:
        with transaction(session):
            second = create_service_account(
                session, login="ar.second", display_name="Second Discoverer"
            )
            create_object_grant(
                session,
                principal_id=second.id,
                object_id="ar-root",
                role=Role.DISCOVERER,
                scope=GrantScope.SELF,
            )
            second_id = second.id
    _file(backend, routing=capped)
    _file(backend, routing=capped, principal_id=second_id)
    assert sorted((row.status, row.last_error_code) for row in _notice_rows(backend)) == [
        ("pending", None),
        ("suppressed", "storm_suppressed"),
    ]


# --------------------------------------------------------------------------
# Idempotency, fenced leases and no lock across the network
# --------------------------------------------------------------------------


def test_planning_twice_yields_one_notice_per_recipient_route(backend, frozen) -> None:
    _route(backend, "owner")
    request_id = _file(backend)
    with backend.session() as session:
        with transaction(session):
            request = session.get(AccessRequest, request_id)
            assert (
                notices.plan_access_request_notices(session, request, routing=ROUTING, now=NOW)
                == "queued"
            )
    assert len(_notice_rows(backend)) == 1


def test_a_lost_response_is_confirmed_by_the_receivers_duplicate_answer(
    backend, frozen
) -> None:
    _route(backend, "owner")
    _file(backend)
    with LoopbackReceiver() as receiver:
        receiver.drop_responses = 1
        transport = OpenClawTestGatewayTransport(endpoint_url=receiver.url, timeout_seconds=2.0)
        first = _deliver(backend, transport, NOW)
        assert first["retried"] == 1 and first["delivered"] == 0
        assert len(receiver.visible) == 1  # accepted, answer lost

        second = _deliver(backend, transport, NOW + timedelta(seconds=60))

    assert second["delivered"] == 1 and second["duplicate_confirmed"] == 1
    assert len(receiver.visible) == 1, "the retry never became a second visible notice"
    assert len(set(receiver.request_ids)) == 1
    (row,) = _notice_rows(backend)
    assert row.status == "delivered"
    assert _attempts(backend) == [
        (1, "unavailable", "transport_unavailable"),  # the dropped answer
        (2, "confirmed_duplicate", None),
    ]


def test_concurrent_workers_send_each_notice_exactly_once(backend, frozen) -> None:
    for index in range(3):
        _route(backend, "owner", f"openclaw-agent:owner-{index}")
        _route(backend, "manager", f"openclaw-agent:manager-{index}")
    _file(backend)
    assert len(_notice_rows(backend)) == 6
    results: list[dict[str, int]] = []
    barrier = threading.Barrier(4)

    with LoopbackReceiver() as receiver:
        transport = OpenClawTestGatewayTransport(endpoint_url=receiver.url, timeout_seconds=2.0)

        def worker(index: int) -> None:
            barrier.wait(timeout=10)
            results.append(_deliver(backend, transport, NOW, worker=f"w{index}"))

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(4)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=60)

    assert sum(result["delivered"] for result in results) == 6
    assert sum(result["lease_lost"] for result in results) == 0
    assert len(receiver.request_ids) == 6 and len(set(receiver.request_ids)) == 6
    assert {row.status for row in _notice_rows(backend)} == {"delivered"}


def test_a_crashed_workers_lease_expires_and_its_late_write_is_fenced(
    backend, frozen
) -> None:
    _route(backend, "owner")
    _file(backend)
    with backend.session() as session:
        stale = notices._claim_next(
            session, worker_id="crashed", policy=POLICY, moment=NOW, skip_ids=set()
        )
    assert stale is not None
    # While the lease is live nobody else may take the notice.
    quiet = FakeNoticeTransport()
    assert _deliver(backend, quiet, NOW + timedelta(seconds=10))["delivered"] == 0
    assert quiet.calls == []

    transport = FakeNoticeTransport()
    assert _deliver(backend, transport, NOW + timedelta(seconds=61))["delivered"] == 1
    with backend.session() as session:
        assert not notices._finish_claim(
            session, stale, uncount_attempt=False, status="failed", last_error_code="delivery_error"
        )
    (row,) = _notice_rows(backend)
    assert row.status == "delivered" and row.attempts == 2
    assert (1, "lease_expired", None) in _attempts(backend)


def test_a_stale_workers_write_cannot_overwrite_the_live_lease(backend, frozen) -> None:
    _route(backend, "owner")
    _file(backend)
    with backend.session() as session:
        stale = notices._claim_next(
            session, worker_id="stale", policy=POLICY, moment=NOW, skip_ids=set()
        )
    with backend.session() as session:
        live = notices._claim_next(
            session,
            worker_id="live",
            policy=POLICY,
            moment=NOW + timedelta(seconds=61),
            skip_ids=set(),
        )
    assert stale is not None and live is not None and stale.token != live.token

    with backend.session() as session:
        assert not notices._finish_claim(
            session, stale, uncount_attempt=False, status="failed", last_error_code="delivery_error"
        )
    (row,) = _notice_rows(backend)
    assert row.status == "pending" and row.lease_token == live.token

    with backend.session() as session:
        assert notices._finish_claim(
            session, live, uncount_attempt=False, status="delivered", last_error_code=None
        )
    assert _notice_rows(backend)[0].status == "delivered"


def test_a_crash_loop_is_bounded_by_the_attempt_budget(backend, frozen) -> None:
    _route(backend, "owner")
    _file(backend)
    moment = NOW
    for _ in range(POLICY.max_attempts):
        with backend.session() as session:
            assert notices._claim_next(
                session, worker_id="crash", policy=POLICY, moment=moment, skip_ids=set()
            )
        moment += timedelta(seconds=61)
    transport = FakeNoticeTransport()
    stats = _deliver(backend, transport, moment)
    assert transport.calls == [] and stats["failed"] == 1
    (row,) = _notice_rows(backend)
    assert row.status == "failed" and row.last_error_code == "attempt_limit_reached"


class _ProbingTransport:
    """Writes to the notice row from an independent connection mid-transport."""

    timeout_seconds = 1.0

    def __init__(self, backend, notice_id: str) -> None:
        self.backend = backend
        self.notice_id = notice_id
        self.probed = False

    def deliver(self, request):
        if self.backend.name == "sqlite":
            path = make_url(self.backend.url).database
            connection = sqlite3.connect(path, timeout=0.3)
            try:
                connection.execute(
                    "UPDATE access_request_notices SET next_attempt_at = next_attempt_at "
                    "WHERE id = ?",
                    (self.notice_id,),
                )
                connection.commit()
            finally:
                connection.close()
        else:
            probe = create_engine(self.backend.url)
            try:
                with probe.begin() as connection:
                    connection.execute(text("SET LOCAL lock_timeout = '300ms'"))
                    connection.execute(
                        text(
                            "UPDATE access_request_notices SET next_attempt_at = next_attempt_at "
                            "WHERE id = :id"
                        ),
                        {"id": self.notice_id},
                    )
                    idle = connection.execute(
                        text(
                            "SELECT count(*) FROM pg_stat_activity "
                            "WHERE datname = current_database() "
                            "AND pid <> pg_backend_pid() "
                            "AND state LIKE 'idle in transaction%'"
                        )
                    ).scalar_one()
                    assert idle == 0, "a database transaction is open across the transport"
            finally:
                probe.dispose()
        self.probed = True
        return DeliveryOutcome(ok=True)


def test_no_database_lock_or_transaction_is_held_across_the_transport(
    backend, frozen
) -> None:
    _route(backend, "owner")
    _file(backend)
    (row,) = _notice_rows(backend)
    transport = _ProbingTransport(backend, row.id)

    assert _deliver(backend, transport)["delivered"] == 1
    assert transport.probed


# --------------------------------------------------------------------------
# Notification can never change a request or a grant
# --------------------------------------------------------------------------


def test_failing_or_dead_lettered_notices_leave_requests_and_grants_untouched(
    backend, frozen
) -> None:
    _route(backend, "owner")
    request_id = _file(backend)

    class Down:
        timeout_seconds = 0.0

        def deliver(self, request):
            return DeliveryOutcome(ok=False, error_code="transport_unavailable")

    for step in range(POLICY.max_attempts):
        _deliver(backend, Down(), NOW + timedelta(minutes=10 * step))
    assert {row.status for row in _notice_rows(backend)} == {"failed"}

    with backend.session() as session:
        request = session.get(AccessRequest, request_id)
        assert request.status == "pending" and request.grant_id is None
    with backend.session() as session:
        with transaction(session):
            result = service.decide_access_request(
                session,
                write_context(session, backend.principals["owner"]),
                request_id=request_id,
                approve=True,
            )
    assert result.status == "approved"
    with backend.session() as session:
        grants = session.scalars(
            select(ObjectGrant).where(
                ObjectGrant.principal_id == backend.principals["discoverer"],
                ObjectGrant.role == "viewer",
            )
        ).all()
        assert len(grants) == 1


def test_planning_failure_rolls_back_with_the_request_never_half_creates(
    backend, frozen, monkeypatch
) -> None:
    _route(backend, "owner")

    def explode(*_args, **_kwargs):
        raise RuntimeError("outbox unavailable")

    monkeypatch.setattr(service, "plan_access_request_notices", explode)
    with pytest.raises(RuntimeError):
        _file(backend)
    with backend.session() as session:
        assert session.scalars(select(AccessRequest)).all() == []
    assert _notice_rows(backend) == []


# --------------------------------------------------------------------------
# End to end: a hint to an authorized owner leads only to an authenticated decision
# --------------------------------------------------------------------------


def test_a_hint_reaches_the_authorized_owner_and_never_approves_anything(
    backend, frozen
) -> None:
    _route(backend, "manager", "openclaw-agent:manager-inbox")
    _route(backend, "outsider", "openclaw-agent:outsider-inbox")
    settings = Settings(
        database_url=backend.url,
        access_request_notices_enabled=True,
        notice_delivery_poller_enabled=True,
        notice_delivery_poll_interval_seconds=300,
        notice_delivery_endpoint_url="http://127.0.0.1:9/never-used",
    )
    with backend.app_client(settings) as client:
        created = client.post(
            "/api/v1/objects/ar-root/access-requests",
            headers=authorization(backend.tokens["discoverer"]),
            json={"duration": "temporary", "ttl_seconds": 3600, "reason": SECRET_REASON},
        )
        assert created.status_code == 201
        request_id = created.json()["request_id"]
        # The requester's response says nothing about routing or approvers.
        assert set(created.json()) == {"request_id", "status", "changed"}

        with LoopbackReceiver() as receiver:
            transport = OpenClawTestGatewayTransport(
                endpoint_url=receiver.url, timeout_seconds=2.0
            )
            stats = _deliver(backend, transport, NOW)

        assert stats["delivered"] == 1
        # Exactly one hint, addressed to the authorized manager route only.
        (envelope,) = receiver.visible
        assert envelope["target"] == "openclaw-agent:manager-inbox"
        notice = envelope["notice"]
        assert set(notice) == {
            "schema_version",
            "event_type",
            "request_id",
            "object_ref",
            "message",
            "blockwart_reference",
        }
        assert notice["request_id"] == request_id
        assert "hunter2" not in json.dumps(envelope) and "evil.example" not in json.dumps(envelope)

        # The hint alone decided nothing.
        with backend.session() as session:
            assert session.get(AccessRequest, request_id).status == "pending"
            assert session.scalars(
                select(ObjectGrant).where(
                    ObjectGrant.principal_id == backend.principals["discoverer"],
                    ObjectGrant.role == "viewer",
                )
            ).all() == []

        reference = notice["blockwart_reference"]
        # Following the reference without credentials reveals nothing and decides nothing.
        assert client.get(reference).status_code == 401
        assert (
            client.post(f"{reference}/{request_id}/decision", json={"decision": "approve"})
        ).status_code == 401
        # Credentials of principals that cannot decide this request do not either.
        assert client.get(reference, headers=authorization(backend.tokens["outsider"])).json() == {
            "items": []
        }
        requester_view = client.get(
            reference, headers=authorization(backend.tokens["discoverer"])
        )
        assert requester_view.json() == {"items": []}
        forbidden = client.post(
            f"{reference}/{request_id}/decision",
            headers=authorization(backend.tokens["outsider"]),
            json={"decision": "approve"},
        )
        assert forbidden.status_code == 403

        # Only the authenticated owner-side decision changes anything.
        queue = client.get(reference, headers=authorization(backend.tokens["manager"]))
        assert [item["id"] for item in queue.json()["items"]] == [request_id]
        decided = client.post(
            f"{reference}/{request_id}/decision",
            headers=authorization(backend.tokens["manager"]),
            json={"decision": "approve"},
        )
        assert decided.status_code == 200 and decided.json()["status"] == "approved"

    with backend.session() as session:
        assert session.get(AccessRequest, request_id).status == "approved"


def test_the_rest_create_path_honors_settings(backend, frozen) -> None:
    _route(backend, "owner")
    body = {"duration": "temporary", "ttl_seconds": 3600}
    # Default settings: hints are off, so the request records "disabled".
    with backend.app_client(Settings(database_url=backend.url)) as client:
        created = client.post(
            "/api/v1/objects/ar-root/access-requests",
            headers=authorization(backend.tokens["discoverer"]),
            json=body,
        )
        assert created.status_code == 201
    assert _notice_rows(backend) == []
    assert _creation_audit(backend)["notification"] == "disabled"


def _wait_for(predicate, timeout: float = 20.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(0.25)
    return False


def test_lifespan_poller_delivers_the_hint_end_to_end(backend) -> None:
    """Request -> outbox -> lifespan poller -> loopback gateway -> terminal state."""
    _route(backend, "owner", "openclaw-agent:owner-inbox")
    with LoopbackReceiver() as receiver:
        settings = Settings(
            database_url=backend.url,
            access_request_notices_enabled=True,
            notice_delivery_poller_enabled=True,
            notice_delivery_poll_interval_seconds=5,
            notice_delivery_endpoint_url=receiver.url,
        )
        request_id = _file(backend, routing=notice_routing_from_settings(settings))
        with backend.app_client(settings):
            assert _wait_for(lambda: bool(receiver.visible)), "poller did not deliver"
            assert _wait_for(
                lambda: all(row.status == "delivered" for row in _notice_rows(backend))
            )
    assert len(receiver.visible) == 1
    assert receiver.visible[0]["notice"]["request_id"] == request_id
    assert [row.status for row in _notice_rows(backend)] == ["delivered"]


def test_a_refused_endpoint_logs_a_stable_code_and_ends_the_poller_cleanly(
    caplog,
) -> None:
    import asyncio

    settings = Settings(
        database_url="sqlite://",
        access_request_notices_enabled=True,
        notice_delivery_poller_enabled=True,
        notice_delivery_endpoint_url="http://203.0.113.9:9/notify",
    )

    async def run() -> None:
        await notices.run_access_request_notice_poller(settings, asyncio.Event())

    with caplog.at_level(logging.ERROR):
        asyncio.run(run())  # returns instead of raising into lifespan shutdown

    messages = [record.getMessage() for record in caplog.records]
    assert messages == ["access_request_notice_poller_error code=transport_refused"]


def test_the_poller_does_nothing_without_the_explicit_opt_in(caplog) -> None:
    import asyncio

    settings = Settings(
        database_url="sqlite://",
        notice_delivery_poller_enabled=True,
        notice_delivery_endpoint_url="http://127.0.0.1:9/notify",
    )
    with caplog.at_level(logging.ERROR):
        asyncio.run(notices.run_access_request_notice_poller(settings, asyncio.Event()))
    assert caplog.records == []
