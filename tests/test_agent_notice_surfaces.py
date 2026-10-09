"""REST, UI, and MCP surfaces of agent notices (Issue #106).

Management is platform-admin only and secret-free; the agent reads and
acknowledges only its own notices, through REST and the dedicated MCP tools.
All HTTP is in-process or loopback; no live gateway, credential, or network.
"""

from __future__ import annotations

import json
from collections.abc import Generator
from datetime import datetime, timedelta
from typing import Annotated

import pytest
from fastapi import Depends
from fastapi.testclient import TestClient
from notice_support import seed_notice_env
from sqlalchemy import select
from sqlalchemy.orm import Session

from blockwart.api.deps import get_session
from blockwart.api.security import require_api_read_access
from blockwart.config import Settings
from blockwart.db.session import transaction
from blockwart.domain.auth import PlatformRole, PrincipalContext, PrincipalType
from blockwart.main import create_app
from blockwart.mcp.server import TOOLS, UpstreamError, call_tool
from blockwart.models import (
    AgentDeliveryJob,
    AgentDeliveryTarget,
    AgentNoticeSubscription,
    ObjectGrant,
    SecurityEvent,
)
from blockwart.services.agent_notices import (
    NoticeDeliveryPolicy,
    deliver_due_agent_notices,
    record_agent_notice_event,
)
from blockwart.services.identity import create_human_principal, issue_browser_session
from blockwart.services.notice_transport import DeliveryOutcome, FakeNoticeTransport
from blockwart.services.read_access import read_access_for_principal
from blockwart.ui.security import AUTH_CSRF_COOKIE_NAME, AUTH_SESSION_COOKIE_NAME

NOW = datetime(2026, 8, 26, 12, 0, 0)
POLICY = NoticeDeliveryPolicy(
    max_attempts=3,
    ttl_seconds=3600,
    backoff_base_seconds=60,
    backoff_max_seconds=600,
    max_pending_jobs_per_target=50,
)
PASSWORD = "browser-platform-admin-password"
SECRET = "sekret-gateway-bearer-0123456789"


def _emit(session: Session, version: str) -> str:
    result = record_agent_notice_event(
        session,
        event_type="release_update_available",
        object_id="svc-01",
        dedupe_key=f"inst-1:github_releases:{version}",
        latest_tag=f"v{version}",
        latest_version=version,
        occurred_at=NOW,
        policy=POLICY,
    )
    return result.event.id


@pytest.fixture
def env(alembic_session_factory, monkeypatch):
    monkeypatch.setenv("BLOCKWART_NOTICE_DELIVERY_TOKEN", SECRET)
    with alembic_session_factory() as session:
        with transaction(session):
            ids = seed_notice_env(session)
            admin = create_human_principal(
                session,
                login="notice.admin",
                display_name="Notice Admin",
                password=PASSWORD,
                platform_role=PlatformRole.ADMIN,
            )
            ordinary = create_human_principal(
                session,
                login="notice.ordinary",
                display_name="Notice Ordinary",
                password=PASSWORD,
            )
            admin_session = issue_browser_session(session, principal_id=admin.id, ttl_seconds=3600)
            ordinary_session = issue_browser_session(
                session, principal_id=ordinary.id, ttl_seconds=3600
            )
    return {
        **ids,
        "sessions": alembic_session_factory,
        "admin_id": admin.id,
        "admin_session": admin_session,
        "ordinary_session": ordinary_session,
    }


@pytest.fixture
def client(env) -> Generator[TestClient, None, None]:
    app = create_app(Settings(notice_delivery_endpoint_url="http://127.0.0.1:9/never"))
    sessions = env["sessions"]

    def override_get_session() -> Generator[Session, None, None]:
        with sessions() as session:
            yield session

    app.dependency_overrides[get_session] = override_get_session
    with TestClient(app, base_url="https://testserver") as test_client:
        yield test_client


def _login(client: TestClient, issued) -> None:
    client.cookies.set(AUTH_SESSION_COOKIE_NAME, issued.value)
    client.cookies.set(AUTH_CSRF_COOKIE_NAME, issued.csrf_token)


def _csrf(client: TestClient) -> dict[str, str]:
    return {"csrf_token": client.cookies.get(AUTH_CSRF_COOKIE_NAME)}


def _act_as(client: TestClient, env, principal_id: str, *, admin: bool = False) -> None:
    sessions = env["sessions"]

    def provider(session: Annotated[Session, Depends(get_session)]):
        del session
        with sessions() as s:
            context = PrincipalContext(
                id=principal_id,
                principal_type=PrincipalType.HUMAN if admin else PrincipalType.SERVICE_ACCOUNT,
                login="admin" if admin else principal_id,
                display_name="Admin" if admin else "Agent Bot",
                platform_role="admin" if admin else None,
            )
            return read_access_for_principal(s, context)

    client.app.dependency_overrides[require_api_read_access] = provider


def _deliver(env, transport, moment: datetime = NOW) -> dict[str, int]:
    with env["sessions"]() as session:
        return deliver_due_agent_notices(session, transport, now=moment, policy=POLICY)


# --- REST management ------------------------------------------------------------------


def test_admin_target_management_is_typed_conflict_aware_and_audited(client, env) -> None:
    _act_as(client, env, env["admin_id"], admin=True)
    principal_id = "principal-agent"

    created = client.post(
        "/api/v1/admin/notices/targets",
        json={
            "principal_id": principal_id,
            "label": "second inbox",
            "route": "openclaw-agent:second-inbox",
            "transport": "openclaw_test_gateway",
        },
    )
    assert created.status_code == 201
    body = created.json()
    assert set(body) == {
        "id",
        "principal_id",
        "principal_login",
        "label",
        "route",
        "transport",
        "active",
    }
    assert body["principal_login"] == principal_id and body["active"] is True

    duplicate = client.post(
        "/api/v1/admin/notices/targets",
        json={
            "principal_id": principal_id,
            "label": "again",
            "route": "openclaw-agent:second-inbox",
            "transport": "openclaw_test_gateway",
        },
    )
    assert duplicate.status_code == 409
    assert duplicate.json()["error"]["code"] == "route_already_registered"

    for payload, status in (
        ({"principal_id": principal_id, "route": "x", "transport": "openclaw_test_gateway"}, 422),
        (
            {
                "principal_id": principal_id,
                "label": "l",
                "route": "Upper:Case",
                "transport": "openclaw_test_gateway",
            },
            422,
        ),
        (
            {
                "principal_id": principal_id,
                "label": "l",
                "route": "ok-route",
                "transport": "https_webhook",
            },
            422,
        ),
        (
            {
                "principal_id": "no-such",
                "label": "l",
                "route": "ok-route",
                "transport": "openclaw_test_gateway",
            },
            422,
        ),
    ):
        assert client.post("/api/v1/admin/notices/targets", json=payload).status_code == status

    listed = client.get("/api/v1/admin/notices/targets").json()
    assert listed["count"] == 2
    assert {item["route"] for item in listed["items"]} == {
        "openclaw-agent:test-inbox",
        "openclaw-agent:second-inbox",
    }

    assert client.delete(f"/api/v1/admin/notices/targets/{body['id']}").status_code == 204
    assert client.delete(f"/api/v1/admin/notices/targets/{body['id']}").status_code == 204
    assert client.delete("/api/v1/admin/notices/targets/missing").status_code == 404

    duplicate_rule = client.post(
        "/api/v1/admin/notices/subscriptions",
        json={
            "event_type": "release_update_available",
            "scope": "object",
            "object_id": "svc-01",
            "principal_id": principal_id,
            "target_id": env["target_id"],
        },
    )
    assert duplicate_rule.status_code == 409
    assert duplicate_rule.json()["error"]["code"] == "subscription_already_registered"

    with env["sessions"]() as session:
        events = session.scalars(
            select(SecurityEvent).where(SecurityEvent.event_type.like("agent_notice_%"))
        ).all()
        assert [event.event_type for event in events] == [
            "agent_notice_target_created",
            "agent_notice_target_revoked",
        ]
        assert all(
            event.principal_id == env["admin_id"] and event.channel == "api" for event in events
        )
        details = " ".join(event.details_json for event in events)
        assert "route" not in details and SECRET not in details


def test_management_and_diagnostics_reject_non_admins(client, env) -> None:
    _act_as(client, env, "principal-agent")
    assert client.get("/api/v1/admin/notices/targets").status_code == 403
    assert client.get("/api/v1/admin/notices/jobs").status_code == 403
    assert client.get("/api/v1/admin/notices").status_code == 403
    assert client.delete(f"/api/v1/admin/notices/targets/{env['target_id']}").status_code == 403
    with env["sessions"]() as session:
        assert session.get(AgentDeliveryTarget, env["target_id"]).active is True


def test_job_diagnostics_filter_and_expose_no_transport_or_lease_data(client, env) -> None:
    with env["sessions"]() as session:
        with transaction(session):
            _emit(session, "1.0.0")
    transport = FakeNoticeTransport()
    transport.enqueue_lost_response()
    _deliver(env, transport)
    _act_as(client, env, env["admin_id"], admin=True)

    pending = client.get("/api/v1/admin/notices/jobs", params={"status": "pending"}).json()
    assert pending["count"] == 1
    item = pending["items"][0]
    assert item["last_attempt_outcome"] == "timeout"
    assert item["last_error_code"] == "transport_timeout"
    assert set(item).isdisjoint(
        {"lease_token", "claimed_by", "payload", "message", "route", "endpoint", "token"}
    )
    delivered_early = client.get("/api/v1/admin/notices/jobs", params={"status": "delivered"})
    assert delivered_early.json()["count"] == 0
    assert client.get("/api/v1/admin/notices/jobs", params={"status": "bogus"}).status_code == 422

    _deliver(env, transport, NOW + timedelta(seconds=61))
    delivered = client.get("/api/v1/admin/notices/jobs", params={"status": "delivered"}).json()
    assert delivered["items"][0]["last_attempt_outcome"] == "confirmed_duplicate"
    assert SECRET not in json.dumps(delivered)


# --- Agent read and acknowledge (REST) --------------------------------------------------


def test_agent_notice_list_filters_by_status_and_hides_lost_objects(client, env) -> None:
    with env["sessions"]() as session:
        with transaction(session):
            first = _emit(session, "1.0.0")
            _emit(session, "2.0.0")
    transport = FakeNoticeTransport()
    transport.enqueue_result(
        DeliveryOutcome(ok=True),
        DeliveryOutcome(ok=False, error_code="rate_limited"),
    )
    _deliver(env, transport)
    _act_as(client, env, "principal-agent")

    everything = client.get("/api/v1/notices").json()
    assert everything["count"] == 2
    assert {n["status"] for n in everything["notices"]} == {"delivered", "pending"}
    only_delivered = client.get("/api/v1/notices", params={"status": "delivered"}).json()
    assert [n["event_id"] for n in only_delivered["notices"]] == [first]
    assert client.get("/api/v1/notices", params={"status": "bogus"}).status_code == 422

    assert client.post(f"/api/v1/notices/{first}/acknowledge").json() == {
        "acknowledged": True,
        "error_code": None,
    }
    again = client.post(f"/api/v1/notices/{first}/acknowledge")
    assert again.json() == {"acknowledged": True, "error_code": None}
    acknowledged = client.get("/api/v1/notices", params={"status": "acknowledged"}).json()
    assert acknowledged["notices"][0]["acknowledged_at"] is not None

    with env["sessions"]() as session:
        with transaction(session):
            session.query(ObjectGrant).delete()
    assert client.get("/api/v1/notices").json() == {"count": 0, "notices": []}
    assert client.post(f"/api/v1/notices/{first}/acknowledge").status_code == 404


# --- UI --------------------------------------------------------------------------------


def test_notice_ui_is_admin_only_secret_free_and_shows_all_states(client, env) -> None:
    with env["sessions"]() as session:
        with transaction(session):
            delivered = _emit(session, "1.0.0")
            _emit(session, "2.0.0")
    transport = FakeNoticeTransport()
    transport.enqueue_result(DeliveryOutcome(ok=True))
    for step in range(POLICY.max_attempts):
        transport.enqueue_result(DeliveryOutcome(ok=False, error_code="transport_timeout"))
        _deliver(env, transport, NOW + timedelta(seconds=1000 * step))
    with env["sessions"]() as session:
        with transaction(session):
            from blockwart.services.agent_notices import acknowledge_agent_notice

            acknowledge_agent_notice(
                session, principal_id="principal-agent", event_id=delivered, now=NOW
            )
            _emit(session, "3.0.0")

    _login(client, env["ordinary_session"])
    assert client.get("/admin/notices").status_code == 403
    assert 'href="/admin/notices"' not in client.get("/settings").text
    denied = client.post(
        "/admin/notices/targets",
        data={
            **_csrf(client),
            "principal_id": "principal-agent",
            "label": "x",
            "route": "denied",
            "transport": "openclaw_test_gateway",
        },
    )
    assert denied.status_code == 403

    _login(client, env["admin_session"])
    assert 'href="/admin/notices"' in client.get("/settings").text
    page = client.get("/admin/notices?lang=en")
    assert page.status_code == 200
    html = page.text
    for heading in ("Agent notices", "Delivery state", "Approved targets", "Routing rules"):
        assert heading in html
    # Each of the six states is shown with its count.
    for label, count in (
        ("Pending", 1),
        ("Delivered", 0),
        ("Failed", 1),
        ("Suppressed", 0),
        ("Expired", 0),
        ("Acknowledged", 1),
    ):
        assert f"{label}: {count}" in html
    assert "openclaw-agent:test-inbox" in html and "principal-agent" in html
    assert "transport_timeout" in html  # safe error code of the dead-lettered job
    for forbidden in (SECRET, "127.0.0.1:9", "Bearer", "lease_token", "token_hash", "Fuer Service"):
        assert forbidden not in html

    filtered = client.get("/admin/notices?status=failed&lang=de")
    assert filtered.status_code == 200 and "Agent-Hinweise" in filtered.text
    assert client.get("/admin/notices?status=bogus").status_code == 422


def test_notice_ui_manages_targets_and_rules_with_csrf_and_audit(client, env) -> None:
    _login(client, env["admin_session"])
    form = {
        "principal_id": "principal-agent",
        "label": "ui inbox",
        "route": "openclaw-agent:ui-inbox",
        "transport": "openclaw_test_gateway",
    }
    forged = client.post("/admin/notices/targets", data={**form, "csrf_token": "nope"})
    assert forged.status_code == 403
    created = client.post("/admin/notices/targets", data={**form, **_csrf(client)})
    assert created.status_code == 200 and created.url.path == "/admin/notices"
    assert "openclaw-agent:ui-inbox" in created.text

    conflict = client.post(
        "/admin/notices/targets",
        data={**form, **_csrf(client)},
        follow_redirects=False,
    )
    assert conflict.status_code == 409
    assert "already registered" in conflict.text

    with env["sessions"]() as session:
        target = session.scalars(
            select(AgentDeliveryTarget).where(
                AgentDeliveryTarget.route == "openclaw-agent:ui-inbox"
            )
        ).one()
        target_id = target.id
    rule = {
        "principal_id": "principal-agent",
        "target_id": target_id,
        "event_type": "release_update_available",
        "scope": "catalog",
        "object_id": "",
    }
    first_rule = client.post("/admin/notices/subscriptions", data={**rule, **_csrf(client)})
    assert first_rule.status_code == 200
    duplicate = client.post("/admin/notices/subscriptions", data={**rule, **_csrf(client)})
    assert duplicate.status_code == 409
    mismatch = client.post(
        "/admin/notices/subscriptions",
        data={**rule, "scope": "object", "object_id": "", **_csrf(client)},
    )
    assert mismatch.status_code == 422

    with env["sessions"]() as session:
        rule_id = session.scalars(
            select(AgentNoticeSubscription.id).where(
                AgentNoticeSubscription.target_id == target_id,
                AgentNoticeSubscription.active.is_(True),
            )
        ).one()
    assert client.post(
        f"/admin/notices/subscriptions/{rule_id}/revoke", data=_csrf(client)
    ).status_code == 200
    assert client.post(
        f"/admin/notices/targets/{target_id}/revoke", data=_csrf(client)
    ).status_code == 200
    assert client.post(
        "/admin/notices/targets/missing/revoke", data=_csrf(client)
    ).status_code == 404

    with env["sessions"]() as session:
        assert session.get(AgentDeliveryTarget, target_id).active is False
        assert session.get(AgentNoticeSubscription, rule_id).active is False
        events = session.scalars(
            select(SecurityEvent)
            .where(SecurityEvent.event_type.like("agent_notice_%"))
            .order_by(SecurityEvent.id)
        ).all()
        assert [event.event_type for event in events] == [
            "agent_notice_target_created",
            "agent_notice_subscription_created",
            "agent_notice_subscription_revoked",
            "agent_notice_target_revoked",
        ]
        assert {event.channel for event in events} == {"ui"}
        assert {event.principal_id for event in events} == {env["admin_id"]}

    # A revoked route can be approved again.
    again = client.post("/admin/notices/targets", data={**form, **_csrf(client)})
    assert again.status_code == 200


# --- MCP -------------------------------------------------------------------------------


def _bridge(client: TestClient):
    def fetch(path: str, params: dict) -> dict:
        response = client.get(
            path, params={key: value for key, value in params.items() if value is not None}
        )
        response.raise_for_status()
        return response.json()

    def request(method: str, path: str, body: dict, headers: dict) -> dict:
        response = client.request(method, path, json=body, headers=headers)
        if response.status_code >= 400:
            raise UpstreamError("not_found", "Notice not found")
        return response.json()

    return fetch, request


def test_mcp_notice_tools_match_rest_and_enforce_the_same_policy(client, env) -> None:
    with env["sessions"]() as session:
        with transaction(session):
            event_id = _emit(session, "1.0.0")
    _deliver(env, FakeNoticeTransport())
    _act_as(client, env, "principal-agent")
    fetch, request = _bridge(client)

    rest = client.get("/api/v1/notices", params={"limit": 20}).json()
    listed = json.loads(
        call_tool("blockwart.list_own_notices", {}, fetcher=fetch)["content"][0]["text"]
    )
    assert listed == rest and listed["count"] == 1
    assert json.loads(
        call_tool("blockwart.list_own_notices", {"status": "failed"}, fetcher=fetch)["content"][0][
            "text"
        ]
    ) == {"count": 0, "notices": []}

    acknowledged = json.loads(
        call_tool(
            "blockwart.acknowledge_notice", {"event_id": event_id}, requester=request, fetcher=fetch
        )["content"][0]["text"]
    )
    assert acknowledged == {"acknowledged": True, "error_code": None}

    with env["sessions"]() as session:
        with transaction(session):
            session.query(ObjectGrant).delete()
    after_loss = json.loads(
        call_tool("blockwart.list_own_notices", {}, fetcher=fetch)["content"][0]["text"]
    )
    assert after_loss == {"count": 0, "notices": []}
    with pytest.raises(UpstreamError):
        call_tool(
            "blockwart.acknowledge_notice", {"event_id": event_id}, requester=request, fetcher=fetch
        )

    tools = {tool["name"]: tool for tool in TOOLS}
    assert tools["blockwart.list_own_notices"]["annotations"]["readOnlyHint"] is True
    ack = tools["blockwart.acknowledge_notice"]["annotations"]
    assert ack["readOnlyHint"] is False and ack["destructiveHint"] is False
    assert ack["idempotentHint"] is True
    for name in ("blockwart.list_own_notices", "blockwart.acknowledge_notice"):
        schema = tools[name]["inputSchema"]
        assert schema["additionalProperties"] is False
        assert "principal_id" not in schema["properties"]  # never reads another agent's state


def test_agent_job_state_never_leaks_other_agents_notices(client, env) -> None:
    with env["sessions"]() as session:
        with transaction(session):
            seed_notice_env(session, route="openclaw-agent:other", principal_id="principal-other")
            event_id = _emit(session, "1.0.0")
    _deliver(env, FakeNoticeTransport())
    _act_as(client, env, "principal-other")
    own = client.get("/api/v1/notices").json()
    assert own["count"] == 1 and own["notices"][0]["event_id"] == event_id
    with env["sessions"]() as session:
        with transaction(session):
            session.query(ObjectGrant).filter_by(principal_id="principal-other").delete()
    assert client.get("/api/v1/notices").json()["count"] == 0
    _act_as(client, env, "principal-agent")
    assert client.get("/api/v1/notices").json()["count"] == 1
    with env["sessions"]() as session:
        assert {job.status for job in session.scalars(select(AgentDeliveryJob))} == {"delivered"}
