"""Independent PR223 race schedules, using real write transactions on both DBs."""

import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta

import pytest
from access_request_support import (
    FrozenClock,
    asset,
    authorization,
    make_backend_fixture,
    snapshot_database,
    write_context,
)
from sqlalchemy import func, select

from blockwart.db.session import transaction
from blockwart.domain.auth import GrantScope, Role
from blockwart.models import AccessRequest, AuditEvent, ObjectGrant
from blockwart.services import access_requests as service
from blockwart.services.access import create_object_grant, revoke_object_grant
from blockwart.services.catalog import upsert_object
from blockwart.services.commands import (
    CommandAuthorizationDenied,
    CommandConflict,
    CommandNotFound,
)
from blockwart.services.identity import deactivate_principal

backend = make_backend_fixture()


def create(session, backend, object_id="ar-root", duration="temporary"):
    return service.create_access_request(
        session,
        write_context(session, backend.principals["discoverer"]),
        object_id=object_id,
        duration=duration,
        ttl_seconds=300 if duration == "temporary" else None,
        reason="preserve history",
    )


def seed_quota(backend, count):
    with backend.session() as session, transaction(session):
        for i in range(11):
            upsert_object(session, asset(f"quota-{i}", kind="host"))
            create_object_grant(
                session,
                principal_id=backend.principals["discoverer"],
                object_id=f"quota-{i}",
                role=Role.DISCOVERER,
                scope=GrantScope.SELF,
            )
        return [create(session, backend, f"quota-{i}").request_id for i in range(count)]


def mutate(session, backend, who, mutation):
    principal_id = backend.principals[who]
    if mutation == "inactive":
        deactivate_principal(session, principal_id=principal_id)
    else:
        grant = session.scalar(
            select(ObjectGrant).where(ObjectGrant.principal_id == principal_id)
        )
        assert revoke_object_grant(session, grant_id=grant.id)


@pytest.mark.parametrize("who,mutation", [
    ("manager", "revoke"), ("discoverer", "revoke"),
    ("manager", "inactive"), ("discoverer", "inactive"),
])
def test_committed_authorization_loss_before_decision_boundary(
    backend, monkeypatch, who, mutation
):
    with backend.session() as session, transaction(session):
        request_id = create(session, backend).request_id
    original = service._approved_expiry
    checked = threading.Event()
    committed = threading.Event()

    def expiry(**kwargs):
        checked.set()
        assert committed.wait(10)
        return original(**kwargs)

    monkeypatch.setattr(service, "_approved_expiry", expiry)

    def approve():
        with backend.session() as session:
            with pytest.raises((CommandAuthorizationDenied, CommandConflict)):
                with transaction(session):
                    service.decide_access_request(
                        session, write_context(session, backend.principals["manager"]),
                        request_id=request_id, approve=True,
                    )

    with ThreadPoolExecutor(1) as pool:
        future = pool.submit(approve)
        assert checked.wait(10)
        with backend.session() as session, transaction(session):
            mutate(session, backend, who, mutation)
        after_revoke = snapshot_database(backend.engine)
        committed.set()
        future.result(timeout=15)
    assert snapshot_database(backend.engine) == after_revoke
    with backend.session() as session:
        row = session.get(AccessRequest, request_id)
        assert row.status == "pending" and row.grant_id is None
        assert row.decided_at is None and row.decided_by_principal_id is None


@pytest.mark.parametrize("operation,who", [
    ("create", "discoverer"), ("cancel", "discoverer"),
    ("approve", "manager"), ("approve", "discoverer"),
])
@pytest.mark.parametrize("mutation", ["revoke", "inactive"])
def test_authorization_write_waits_for_lifecycle_commit(
    backend, monkeypatch, operation, who, mutation
):
    request_id = None
    if operation != "create":
        with backend.session() as session, transaction(session):
            request_id = create(session, backend).request_id
    claimed = threading.Event()
    release = threading.Event()
    attempted = threading.Event()
    finished = threading.Event()
    original = service.lock_grant_command_state

    def locked(*args, **kwargs):
        result = original(*args, **kwargs)
        claimed.set()
        assert release.wait(10)
        return result

    monkeypatch.setattr(service, "lock_grant_command_state", locked)

    def lifecycle():
        with backend.session() as session, transaction(session):
            if operation == "create":
                return create(session, backend)
            actor = "manager" if operation == "approve" else "discoverer"
            context = write_context(session, backend.principals[actor])
            if operation == "cancel":
                return service.cancel_access_request(session, context, request_id=request_id)
            return service.decide_access_request(
                session, context, request_id=request_id, approve=True
            )

    def change():
        with backend.session() as session, transaction(session):
            attempted.set()
            mutate(session, backend, who, mutation)
        finished.set()

    with ThreadPoolExecutor(2) as pool:
        first = pool.submit(lifecycle)
        assert claimed.wait(10)
        second = pool.submit(change)
        assert attempted.wait(10)
        try:
            assert not finished.wait(0.2), "authorization change bypassed lifecycle locks"
        finally:
            release.set()
        result = first.result(timeout=15)
        second.result(timeout=15)
    assert result.changed
    # The opposite ordering must fail closed, including stale service contexts.
    with backend.session() as session:
        with pytest.raises((CommandAuthorizationDenied, CommandConflict, CommandNotFound)):
            with transaction(session):
                if operation == "approve":
                    service.decide_access_request(
                        session, write_context(session, backend.principals["manager"]),
                        request_id=request_id, approve=True,
                    )
                elif operation == "cancel":
                    service.cancel_access_request(
                        session, write_context(session, backend.principals["discoverer"]),
                        request_id=request_id,
                    )
                else:
                    create(session, backend)


@pytest.mark.parametrize("identical", [False, True])
def test_concurrent_creates_at_global_cap(backend, monkeypatch, identical):
    seed_quota(backend, 9)
    counted = threading.Event()
    release = threading.Event()
    second_started = threading.Event()
    second_counted = threading.Event()
    original = service.sanitize_reason

    def after_count(reason):
        if not counted.is_set():
            counted.set()
            assert release.wait(10)
        else:
            second_counted.set()
        return original(reason)

    monkeypatch.setattr(service, "sanitize_reason", after_count)

    def run(index):
        with backend.session() as session:
            if index:
                second_started.set()
            try:
                with transaction(session):
                    return create(session, backend, f"quota-{9 if identical else 9 + index}")
            except CommandConflict as exc:
                assert str(exc) == "too many open access requests"
                return None

    with ThreadPoolExecutor(2) as pool:
        first = pool.submit(run, 0)
        assert counted.wait(10)
        second = pool.submit(run, 1)
        assert second_started.wait(10)
        try:
            # On the unfixed implementation the second count completes while
            # the first insert is paused. With locks it cannot reach this seam.
            second_counted.wait(0.3)
        finally:
            release.set()
        results = [first.result(timeout=15), second.result(timeout=15)]
    with backend.session() as session:
        assert session.scalar(select(func.count()).select_from(AccessRequest).where(
            AccessRequest.status == "pending")) == 10
        assert session.scalar(select(func.count()).select_from(AuditEvent).where(
            AuditEvent.action == "access_request_create")) == 10
    if identical:
        assert results[0].request_id == results[1].request_id
        assert sorted(r.changed for r in results) == [False, True]
    else:
        assert results[0].changed and results[1] is None


def test_new_object_creation_frees_elapsed_global_quota_without_prior_reads(
    backend, monkeypatch
):
    frozen = FrozenClock(monkeypatch)
    ids = seed_quota(backend, 10)
    before = snapshot_database(backend.engine)
    frozen.advance(minutes=10)
    with backend.client() as client:
        response = client.post(
            "/api/v1/objects/quota-10/access-requests",
            headers=authorization(backend.tokens["discoverer"]),
            json={"duration": "permanent"},
        )
        assert response.status_code == 201, response.text
        assert response.json()["changed"]
        after = snapshot_database(backend.engine)
        assert client.get("/api/v1/me/access-requests", headers=authorization(
            backend.tokens["discoverer"])).status_code == 200
        assert snapshot_database(backend.engine) == after
        retry = client.post(
            "/api/v1/objects/quota-10/access-requests",
            headers=authorization(backend.tokens["discoverer"]),
            json={"duration": "permanent"},
        )
        assert retry.status_code == 201 and not retry.json()["changed"]
        retried = snapshot_database(backend.engine)
        for table in ("access_requests", "audit_events", "object_grants",
                      "access_request_notices", "access_request_notice_attempts"):
            assert retried[table] == after[table]
    with backend.session() as session:
        rows = session.scalars(select(AccessRequest).where(AccessRequest.id.in_(ids))).all()
        assert len(rows) == 10 and {r.status for r in rows} == {"expired"}
        assert {r.reason for r in rows} == {"preserve history"}
        assert {r.ended_at for r in rows} == {frozen.now - timedelta(
            minutes=5)}
        assert session.scalar(select(func.count()).select_from(AuditEvent).where(
            AuditEvent.action == "access_request_expire")) == 10
    # Existing immutable audit rows remain byte-for-byte present.
    assert all(row in after["audit_events"] for row in before["audit_events"])


def test_identical_retry_does_not_materialize_unrelated_elapsed_history(backend, monkeypatch):
    frozen = FrozenClock(monkeypatch)
    seed_quota(backend, 0)
    with backend.session() as session, transaction(session):
        original = create(session, backend, "quota-0", duration="permanent")
        create(session, backend, "quota-1")
    frozen.advance(minutes=10)
    before = snapshot_database(backend.engine)
    with backend.session() as session, transaction(session):
        retry = create(session, backend, "quota-0", duration="permanent")
    assert retry.request_id == original.request_id and not retry.changed
    assert snapshot_database(backend.engine) == before


@pytest.mark.parametrize("operation", ["create", "cancel"])
@pytest.mark.parametrize("mutation", ["revoke", "inactive"])
def test_committed_visibility_loss_before_create_or_cancel_lock(
    backend, monkeypatch, operation, mutation
):
    request_id = None
    if operation == "cancel":
        with backend.session() as session, transaction(session):
            request_id = create(session, backend).request_id
    entering = threading.Event()
    committed = threading.Event()
    original = service.lock_grant_command_state

    def lock(*args, **kwargs):
        entering.set()
        assert committed.wait(10)
        return original(*args, **kwargs)

    monkeypatch.setattr(service, "lock_grant_command_state", lock)

    def run():
        with backend.session() as session:
            context = write_context(session, backend.principals["discoverer"])
            with pytest.raises(CommandNotFound):
                with transaction(session):
                    if operation == "create":
                        service.create_access_request(
                            session, context, object_id="ar-root", duration="permanent",
                            ttl_seconds=None, reason=None,
                        )
                    else:
                        service.cancel_access_request(session, context, request_id=request_id)

    with ThreadPoolExecutor(1) as pool:
        future = pool.submit(run)
        assert entering.wait(10)
        with backend.session() as session, transaction(session):
            mutate(session, backend, "discoverer", mutation)
        after_revoke = snapshot_database(backend.engine)
        committed.set()
        future.result(timeout=15)
    assert snapshot_database(backend.engine) == after_revoke
