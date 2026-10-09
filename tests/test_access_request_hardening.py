"""Concealment, replacement, read-purity and atomicity regressions (Issue #100).

Every test body runs on SQLite and, when ``BLOCKWART_TEST_PG_URL`` is
reachable, on PostgreSQL. Time moves through the ``services.clock`` seam so
expiry boundaries are crossed without editing rows.
"""

from __future__ import annotations

import json
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta

import pytest
from access_request_support import (
    FrozenClock,
    authorization,
    changed_tables,
    make_backend_fixture,
    snapshot_database,
    write_context,
)
from sqlalchemy import func, select

from blockwart.db.session import transaction
from blockwart.mcp.server import call_tool
from blockwart.models import (
    AccessRequest,
    AuditEvent,
    ObjectGrant,
    Principal,
)
from blockwart.services import access_requests as service
from blockwart.services.access import revoke_object_grant
from blockwart.services.commands import (
    CommandAuthorizationDenied,
    CommandConflict,
    CommandNotFound,
)
from blockwart.services.policy import policy_for_principal

backend = make_backend_fixture()


@pytest.fixture
def client(backend):
    with backend.client() as test_client:
        yield test_client


@pytest.fixture
def frozen(monkeypatch) -> FrozenClock:
    return FrozenClock(monkeypatch)


def _create(client, backend, who="discoverer", object_id="ar-root", **payload):
    body = {"duration": "temporary", "ttl_seconds": 3600, "reason": "incident work"}
    body.update(payload)
    return client.post(
        f"/api/v1/objects/{object_id}/access-requests",
        headers=authorization(backend.tokens[who]),
        json=body,
    )


def _decide(client, backend, request_id, decision="approve", who="owner", **payload):
    return client.post(
        f"/api/v1/access-requests/{request_id}/decision",
        headers=authorization(backend.tokens[who]),
        json={"decision": decision, **payload},
    )


def _mine(client, backend, who="discoverer"):
    return client.get("/api/v1/me/access-requests", headers=authorization(backend.tokens[who]))


def _queue(client, backend, who="owner"):
    return client.get("/api/v1/access-requests", headers=authorization(backend.tokens[who]))


def _row(backend, request_id):
    with backend.session() as session:
        row = session.get(AccessRequest, request_id)
        session.expunge(row)
        return row


def _viewer_grants(backend, who="discoverer"):
    with backend.session() as session:
        return list(
            session.scalars(
                select(ObjectGrant).where(
                    ObjectGrant.principal_id == backend.principals[who],
                    ObjectGrant.role == "viewer",
                )
            )
        )


def _audit_actions(backend, prefix=""):
    with backend.session() as session:
        return [
            action
            for action in session.scalars(select(AuditEvent.action).order_by(AuditEvent.id))
            if action.startswith(prefix)
        ]


def _revoke_direct(backend, who, role):
    with backend.session() as session:
        with transaction(session):
            grant = session.scalar(
                select(ObjectGrant).where(
                    ObjectGrant.principal_id == backend.principals[who],
                    ObjectGrant.object_id == "ar-root",
                    ObjectGrant.role == role,
                )
            )
            assert grant is not None
            assert revoke_object_grant(session, grant_id=grant.id)


_context = write_context


def _error(response):
    return {k: v for k, v in response.json()["error"].items() if k != "correlation_id"}


# --------------------------------------------------------------------------
# Blocker 1: current discover / active identity / approver policy
# --------------------------------------------------------------------------


def test_requester_loses_every_trace_after_discover_is_revoked(backend, client) -> None:
    created = _create(client, backend)
    request_id = created.json()["request_id"]
    assert [item["id"] for item in _mine(client, backend).json()["items"]] == [request_id]

    _revoke_direct(backend, "discoverer", "discoverer")

    listing = _mine(client, backend)
    assert listing.status_code == 200
    assert listing.json() == {"items": []}
    for secret in (request_id, "ar-root"):
        assert secret not in listing.text

    cancelled = client.post(
        f"/api/v1/access-requests/{request_id}/cancellation",
        headers=authorization(backend.tokens["discoverer"]),
    )
    unknown = client.post(
        "/api/v1/access-requests/00000000-0000-4000-8000-000000000000/cancellation",
        headers=authorization(backend.tokens["discoverer"]),
    )
    assert cancelled.status_code == unknown.status_code == 404
    assert _error(cancelled) == _error(unknown)
    # The hidden request was neither cancelled nor otherwise touched.
    assert _row(backend, request_id).status == "pending"
    # Approvers still see it: they manage the object.
    assert [i["id"] for i in _queue(client, backend).json()["items"]] == [request_id]


def test_approved_request_and_grant_id_disappear_with_visibility(backend, client) -> None:
    request_id = _create(client, backend).json()["request_id"]
    assert _decide(client, backend, request_id).status_code == 200
    mine = _mine(client, backend).json()["items"]
    grant_id = mine[0]["grant_id"]
    assert grant_id is not None and mine[0]["status"] == "approved"

    # Remove both the approved viewer grant and the original discoverer grant.
    with backend.session() as session:
        with transaction(session):
            for grant in session.scalars(
                select(ObjectGrant).where(
                    ObjectGrant.principal_id == backend.principals["discoverer"]
                )
            ).all():
                revoke_object_grant(session, grant_id=grant.id)

    listing = _mine(client, backend)
    assert listing.json() == {"items": []}
    assert request_id not in listing.text and str(grant_id) not in listing.text
    assert "ar-root" not in listing.text


def _deactivate(backend, who) -> None:
    with backend.session() as other:
        with transaction(other):
            other.get(Principal, backend.principals[who]).active = False


def test_inactive_principal_is_uniformly_not_found_on_every_requester_path(backend) -> None:
    with backend.session() as session:
        with transaction(session):
            request_id = service.create_access_request(
                session,
                _context(session, backend.principals["discoverer"]),
                object_id="ar-root",
                duration="temporary",
                ttl_seconds=3600,
                reason=None,
            ).request_id
    with backend.session() as session:
        # The context was built while the principal was still active (an
        # authenticated request already in flight); deactivation commits
        # afterwards and must not be outlived by that context.
        context = _context(session, backend.principals["discoverer"])
        session.commit()
        _deactivate(backend, "discoverer")
        with pytest.raises(CommandNotFound):
            service.list_my_access_requests(session, context)
        with pytest.raises(CommandNotFound):
            with transaction(session):
                service.cancel_access_request(session, context, request_id=request_id)
        with pytest.raises(CommandNotFound):
            with transaction(session):
                service.create_access_request(
                    session,
                    context,
                    object_id="ar-root",
                    duration="temporary",
                    ttl_seconds=3600,
                    reason=None,
                )
    assert _row(backend, request_id).status == "pending"


def test_approver_needs_current_policy_and_active_identity(backend, client) -> None:
    request_id = _create(client, backend).json()["request_id"]
    assert [i["id"] for i in _queue(client, backend, "manager").json()["items"]] == [request_id]

    # Policy lost -> queue empty and decision refused, nothing changes.
    _revoke_direct(backend, "manager", "access_manager")
    assert _queue(client, backend, "manager").json()["items"] == []
    refused = _decide(client, backend, request_id, who="manager")
    assert refused.status_code == 403
    assert _row(backend, request_id).status == "pending"
    assert _viewer_grants(backend) == []

    # Identity lost between authentication and decision (stale context).
    with backend.session() as session:
        stale = _context(session, backend.principals["owner"])
        session.commit()
        _deactivate(backend, "owner")
        with pytest.raises(CommandAuthorizationDenied):
            with transaction(session):
                service.decide_access_request(
                    session, stale, request_id=request_id, approve=True
                )
        with pytest.raises(CommandNotFound):
            service.list_pending_access_requests(session, stale)
    assert _row(backend, request_id).status == "pending"
    assert _viewer_grants(backend) == []


def test_approval_refuses_a_requester_that_lost_discover_but_denial_cleans_up(
    backend, client
) -> None:
    request_id = _create(client, backend).json()["request_id"]
    _revoke_direct(backend, "discoverer", "discoverer")

    approve = _decide(client, backend, request_id)
    assert approve.status_code == 409
    assert _viewer_grants(backend) == []
    assert _row(backend, request_id).status == "pending"

    deny = _decide(client, backend, request_id, decision="deny")
    assert deny.status_code == 200 and deny.json()["status"] == "denied"


# --------------------------------------------------------------------------
# Blocker 2: expired/revoked approvals never block replacements
# --------------------------------------------------------------------------


def test_expired_approval_never_blocks_a_replacement_and_keeps_its_history(
    backend, client, frozen
) -> None:
    first = _create(client, backend, ttl_seconds=600, reason="first window").json()
    assert _decide(client, backend, first["request_id"]).status_code == 200
    original = _row(backend, first["request_id"])
    assert original.status == "approved" and original.grant_id is not None

    frozen.advance(minutes=11)
    # No unrelated read happened. The requester can simply ask again.
    second = _create(client, backend, ttl_seconds=3600, reason="second window")
    assert second.status_code == 201, second.text
    assert second.json()["changed"] is True
    assert second.json()["request_id"] != first["request_id"]
    assert second.json()["status"] == "pending"

    kept = _row(backend, first["request_id"])
    assert kept.status == "expired"
    assert kept.reason == "first window"
    assert kept.decided_by_principal_id == original.decided_by_principal_id
    assert kept.decided_at == original.decided_at
    assert kept.approved_expires_at == original.approved_expires_at
    assert kept.ended_at == original.approved_expires_at
    assert "access_request_expire" in _audit_actions(backend)

    # Approving the replacement creates a fresh grant instead of reusing the dead row.
    assert _decide(client, backend, second.json()["request_id"]).status_code == 200
    grants = _viewer_grants(backend)
    assert len(grants) == 1
    assert grants[0].expires_at is not None and grants[0].expires_at > frozen.now
    assert "grant_expire" in _audit_actions(backend)
    # SQLite may reuse the deleted row id; the old request must not be linked
    # to the new grant, whatever id it received.
    assert _row(backend, first["request_id"]).grant_id != grants[0].id
    with backend.session() as session:
        assert policy_for_principal(session, backend.principals["discoverer"]).can(
            "read", "ar-root"
        )
    replaced = _row(backend, first["request_id"])
    assert replaced.status == "expired" and replaced.reason == "first window"
    items = {item["id"]: item for item in _mine(client, backend).json()["items"]}
    assert items[first["request_id"]]["status"] == "expired"
    assert items[second.json()["request_id"]]["status"] == "approved"


def test_revoked_permanent_approval_never_blocks_a_replacement(backend, client) -> None:
    first = _create(client, backend, duration="permanent", ttl_seconds=None).json()
    assert _decide(client, backend, first["request_id"]).status_code == 200
    grant_id = _viewer_grants(backend)[0].id

    revoked = client.delete(
        f"/api/v1/objects/ar-root/access/grants/{grant_id}",
        headers={**authorization(backend.tokens["owner"]), "If-Match": _etag(client, backend)},
    )
    assert revoked.status_code == 200, revoked.text

    # Revocation is persisted by the revoke lifecycle itself.
    assert _row(backend, first["request_id"]).status == "revoked"
    assert "access_request_revoke" in _audit_actions(backend)

    again = _create(client, backend, duration="permanent", ttl_seconds=None)
    assert again.status_code == 201
    assert again.json()["changed"] is True
    assert again.json()["request_id"] != first["request_id"]
    items = {i["id"]: i["status"] for i in _mine(client, backend).json()["items"]}
    assert items == {first["request_id"]: "revoked", again.json()["request_id"]: "pending"}


def _etag(client, backend) -> str:
    response = client.get(
        "/api/v1/objects/ar-root/access",
        headers=authorization(backend.tokens["owner"]),
    )
    assert response.status_code == 200, response.text
    return response.headers["ETag"]


def test_true_retry_preserves_original_request_and_history(backend, client) -> None:
    first = _create(client, backend, reason="original reason").json()
    before = _row(backend, first["request_id"])
    audit_before = _audit_actions(backend)

    retry = _create(client, backend, ttl_seconds=7200, reason="a different reason")
    assert retry.status_code == 201
    assert retry.json() == {**first, "changed": False}
    after = _row(backend, first["request_id"])
    assert after.reason == "original reason"
    assert after.requested_expires_at == before.requested_expires_at
    assert after.updated_at == before.updated_at
    assert _audit_actions(backend) == audit_before
    with backend.session() as session:
        assert session.scalar(select(func.count()).select_from(AccessRequest)) == 1


def test_lapsed_pending_request_cannot_be_approved_and_is_replaced(
    backend, client, frozen
) -> None:
    first = _create(client, backend, ttl_seconds=600).json()
    frozen.advance(minutes=11)

    # Projected as expired without any write.
    items = _mine(client, backend).json()["items"]
    assert [(i["id"], i["status"]) for i in items] == [(first["request_id"], "expired")]
    assert _row(backend, first["request_id"]).status == "pending"
    assert _queue(client, backend).json()["items"] == []
    stale = _decide(client, backend, first["request_id"])
    assert stale.status_code == 409
    assert _viewer_grants(backend) == []

    second = _create(client, backend, ttl_seconds=1800)
    assert second.status_code == 201 and second.json()["changed"] is True
    assert second.json()["request_id"] != first["request_id"]
    assert _row(backend, first["request_id"]).status == "expired"


def test_admin_created_grant_replaces_an_expired_temporary_grant(
    backend, client, frozen
) -> None:
    first = _create(client, backend, ttl_seconds=600).json()
    assert _decide(client, backend, first["request_id"]).status_code == 200
    frozen.advance(minutes=11)

    created = client.post(
        "/api/v1/objects/ar-root/access/grants",
        headers={**authorization(backend.tokens["owner"]), "If-Match": _etag(client, backend)},
        json={
            "principal_id": backend.principals["discoverer"],
            "role": "viewer",
            "scope": "self",
        },
    )
    assert created.status_code in {200, 201}, created.text
    assert created.json()["changed"] is True
    grants = _viewer_grants(backend)
    assert len(grants) == 1 and grants[0].expires_at is None
    assert _row(backend, first["request_id"]).status == "expired"
    with backend.session() as session:
        assert policy_for_principal(session, backend.principals["discoverer"]).can(
            "read", "ar-root"
        )


def test_expired_temporary_grant_is_not_reported_as_an_own_direct_grant(
    backend, client, frozen
) -> None:
    first = _create(client, backend, ttl_seconds=600).json()
    assert _decide(client, backend, first["request_id"]).status_code == 200

    def own_roles() -> set[str]:
        response = client.get(
            "/api/v1/auth/me/direct-grants",
            headers=authorization(backend.tokens["discoverer"]),
        )
        assert response.status_code == 200, response.text
        return {item["role"] for item in response.json()["items"]}

    assert own_roles() == {"discoverer", "viewer"}
    frozen.advance(minutes=11)
    assert own_roles() == {"discoverer"}


# --------------------------------------------------------------------------
# Blocker 3: reads never write
# --------------------------------------------------------------------------


def _mcp_fetcher(client, token):
    def fetcher(path, params):
        response = client.get(
            path,
            params=params,
            headers={**authorization(token), "X-Blockwart-Channel": "mcp"},
        )
        response.raise_for_status()
        return response.json()

    return fetcher


def _tool_json(result) -> dict:
    assert result["isError"] is False
    return json.loads(result["content"][0]["text"])


def _reads(client, backend) -> dict[str, dict]:
    """Every read surface for requester and approvers: REST and read-only MCP."""
    results: dict[str, dict] = {}
    for who in ("discoverer", "owner", "manager", "outsider"):
        results[f"rest:mine:{who}"] = _mine(client, backend, who).json()
        results[f"rest:queue:{who}"] = _queue(client, backend, who).json()
        fetcher = _mcp_fetcher(client, backend.tokens[who])
        results[f"mcp:mine:{who}"] = _tool_json(
            call_tool("blockwart.list_my_access_requests", {}, fetcher=fetcher)
        )
        results[f"mcp:queue:{who}"] = _tool_json(
            call_tool("blockwart.list_pending_access_requests", {}, fetcher=fetcher)
        )
    return results


def _assert_reads_write_nothing(client, backend) -> dict[str, dict]:
    before = snapshot_database(backend.engine)
    first = _reads(client, backend)
    middle = snapshot_database(backend.engine)
    second = _reads(client, backend)
    after = snapshot_database(backend.engine)
    assert changed_tables(before, middle) == []
    assert changed_tables(before, after) == []
    assert first == second
    return first


def test_reads_write_nothing_across_every_expiry_and_revocation_boundary(
    backend, client, frozen
) -> None:
    # pending, then lapsed pending
    pending = _create(client, backend, ttl_seconds=600).json()["request_id"]
    seen = _assert_reads_write_nothing(client, backend)
    assert seen["rest:mine:discoverer"]["items"][0]["status"] == "pending"
    assert [i["id"] for i in seen["rest:queue:owner"]["items"]] == [pending]

    frozen.advance(minutes=11)
    seen = _assert_reads_write_nothing(client, backend)
    assert seen["rest:mine:discoverer"]["items"][0]["status"] == "expired"
    assert seen["rest:queue:owner"]["items"] == []
    assert seen["mcp:mine:discoverer"]["items"][0]["status"] == "expired"

    # approved, active -> approved window elapsed
    approved = _create(client, backend, ttl_seconds=3600).json()["request_id"]
    assert _decide(client, backend, approved).status_code == 200
    seen = _assert_reads_write_nothing(client, backend)
    assert {i["id"]: i["status"] for i in seen["rest:mine:discoverer"]["items"]}[
        approved
    ] == "approved"
    frozen.advance(hours=2)
    seen = _assert_reads_write_nothing(client, backend)
    assert {i["id"]: i["status"] for i in seen["mcp:mine:discoverer"]["items"]}[
        approved
    ] == "expired"

    # a permanent approval whose grant disappears through another path is revoked
    permanent = _create(client, backend, duration="permanent", ttl_seconds=None).json()[
        "request_id"
    ]
    assert _decide(client, backend, permanent).status_code == 200
    with backend.session() as session:
        with transaction(session):
            grant = session.scalar(
                select(ObjectGrant).where(
                    ObjectGrant.principal_id == backend.principals["discoverer"],
                    ObjectGrant.role == "viewer",
                )
            )
            session.delete(grant)  # out-of-band removal: no request lifecycle ran
    seen = _assert_reads_write_nothing(client, backend)
    assert {i["id"]: i["status"] for i in seen["rest:mine:discoverer"]["items"]}[
        permanent
    ] == "revoked"


def test_materialization_happens_only_in_write_lifecycles(backend, client, frozen) -> None:
    first = _create(client, backend, ttl_seconds=600).json()["request_id"]
    assert _decide(client, backend, first).status_code == 200
    frozen.advance(minutes=11)
    _reads(client, backend)
    _reads(client, backend)
    assert _row(backend, first).status == "approved"  # reads left it alone
    assert "access_request_expire" not in _audit_actions(backend)

    assert _create(client, backend).status_code == 201  # a write lifecycle persists it
    assert _row(backend, first).status == "expired"
    assert _audit_actions(backend).count("access_request_expire") == 1


# --------------------------------------------------------------------------
# Blocker 2/5: exactly one logical winner under parallel lifecycles
# --------------------------------------------------------------------------


def _parallel(count, function):
    barrier = threading.Barrier(count)

    def run(index):
        barrier.wait(timeout=10)
        return function(index)

    with ThreadPoolExecutor(max_workers=count) as pool:
        return list(pool.map(run, range(count)))


def test_parallel_identical_creates_yield_one_request_and_one_audit_event(
    backend, client
) -> None:
    responses = _parallel(4, lambda _i: _create(client, backend))
    assert {r.status_code for r in responses} == {201}
    ids = {r.json()["request_id"] for r in responses}
    assert len(ids) == 1
    assert sorted(r.json()["changed"] for r in responses) == [False, False, False, True]
    with backend.session() as session:
        assert session.scalar(select(func.count()).select_from(AccessRequest)) == 1
    assert _audit_actions(backend, "access_request_create") == ["access_request_create"]


def test_parallel_approve_and_deny_have_exactly_one_winner(backend, client) -> None:
    request_id = _create(client, backend).json()["request_id"]
    decisions = ["approve", "deny", "approve", "deny"]
    responses = _parallel(
        4, lambda i: _decide(client, backend, request_id, decision=decisions[i])
    )
    codes = sorted(r.status_code for r in responses)
    assert codes == [200, 409, 409, 409]
    winner = next(r for r in responses if r.status_code == 200).json()
    row = _row(backend, request_id)
    assert row.status == winner["status"]
    grants = _viewer_grants(backend)
    assert len(grants) == (1 if row.status == "approved" else 0)
    outcomes = {"access_request_approve", "access_request_deny"}
    decided = [a for a in _audit_actions(backend) if a in outcomes]
    assert len(decided) == 1


@pytest.mark.parametrize("round_", range(3))
def test_parallel_cancel_and_decision_never_disagree(backend, client, round_) -> None:
    request_id = _create(client, backend).json()["request_id"]

    def act(index):
        if index == 0:
            return "cancel", client.post(
                f"/api/v1/access-requests/{request_id}/cancellation",
                headers=authorization(backend.tokens["discoverer"]),
            )
        return "approve", _decide(client, backend, request_id)

    results = _parallel(2, act)
    assert sorted(r.status_code for _k, r in results) == [200, 409]
    row = _row(backend, request_id)
    grants = _viewer_grants(backend)
    if row.status == "approved":
        assert len(grants) == 1 and row.grant_id == grants[0].id
    else:
        assert row.status == "cancelled" and grants == []


def test_parallel_cancellations_have_one_winner(backend, client) -> None:
    request_id = _create(client, backend).json()["request_id"]
    responses = _parallel(
        3,
        lambda _i: client.post(
            f"/api/v1/access-requests/{request_id}/cancellation",
            headers=authorization(backend.tokens["discoverer"]),
        ),
    )
    assert sorted(r.status_code for r in responses) == [200, 409, 409]
    assert _audit_actions(backend, "access_request_cancel") == ["access_request_cancel"]


def test_approval_is_all_or_nothing_when_the_grant_cannot_be_created(
    backend, client, monkeypatch
) -> None:
    request_id = _create(client, backend).json()["request_id"]

    def boom(*_args, **_kwargs):
        raise RuntimeError("grant storage unavailable")

    monkeypatch.setattr(service, "create_object_grant", boom)
    failed = _decide(client, backend, request_id)
    assert failed.status_code == 500
    row = _row(backend, request_id)
    assert row.status == "pending"
    assert row.decided_by_principal_id is None and row.grant_id is None
    assert _viewer_grants(backend) == []
    assert _audit_actions(backend, "access_request_approve") == []


def test_service_level_conflicts_are_stable(backend) -> None:
    with backend.session() as session:
        context = _context(session, backend.principals["discoverer"])
        with transaction(session):
            created = service.create_access_request(
                session,
                context,
                object_id="ar-root",
                duration="temporary",
                ttl_seconds=3600,
                reason=None,
            )
        with pytest.raises(CommandConflict):
            with transaction(session):
                service.decide_access_request(
                    session,
                    _context(session, backend.principals["owner"]),
                    request_id=created.request_id,
                    approve=True,
                    approved_ttl_seconds=10 * 24 * 3600,
                )
    assert _row(backend, created.request_id).status == "pending"


def test_new_request_window_is_bounded_from_now(backend, client, frozen) -> None:
    created = _create(client, backend, ttl_seconds=3600).json()
    row = _row(backend, created["request_id"])
    assert row.requested_expires_at == frozen.now + timedelta(seconds=3600)


# --------------------------------------------------------------------------
# Parity: MCP write tools run the same commands as REST and the UI
# --------------------------------------------------------------------------


def _mcp_requester(client, token):
    def requester(method, path, body, headers):
        response = client.request(
            method,
            path,
            json=body,
            headers={**authorization(token), **headers},
        )
        if response.status_code >= 400:
            raise AssertionError((response.status_code, response.text))
        return response.json()

    return requester


def test_mcp_write_tools_share_the_rest_commands_and_audit_channel(backend, client) -> None:
    requester_token = backend.tokens["discoverer"]
    owner_token = backend.tokens["owner"]
    created = _tool_json(
        call_tool(
            "blockwart.create_access_request",
            {"object_id": "ar-root", "duration": "temporary", "ttl_seconds": 3600},
            requester=_mcp_requester(client, requester_token),
        )
    )
    assert created["changed"] is True and created["status"] == "pending"
    retry = _tool_json(
        call_tool(
            "blockwart.create_access_request",
            {"object_id": "ar-root", "duration": "temporary", "ttl_seconds": 7200},
            requester=_mcp_requester(client, requester_token),
        )
    )
    assert retry == {**created, "changed": False}

    queue = _tool_json(
        call_tool(
            "blockwart.list_pending_access_requests",
            {},
            fetcher=_mcp_fetcher(client, owner_token),
        )
    )
    assert [item["id"] for item in queue["items"]] == [created["request_id"]]
    decided = _tool_json(
        call_tool(
            "blockwart.decide_access_request",
            {"request_id": created["request_id"], "decision": "approve"},
            requester=_mcp_requester(client, owner_token),
        )
    )
    assert decided["status"] == "approved"
    with backend.session() as session:
        channels = {
            json.loads(row.details_json).get("channel")
            for row in session.scalars(
                select(AuditEvent).where(
                    AuditEvent.action.in_(["access_request_create", "access_request_approve"])
                )
            )
        }
    assert channels == {"mcp"}
    # The same state through REST agrees with what MCP reported.
    assert _mine(client, backend).json()["items"][0]["status"] == "approved"


def test_the_read_only_mcp_tools_are_annotated_read_only() -> None:
    from blockwart.mcp.server import TOOL_DEFINITIONS

    for name in ("blockwart.list_my_access_requests", "blockwart.list_pending_access_requests"):
        assert TOOL_DEFINITIONS[name]["annotations"]["readOnlyHint"] is True
