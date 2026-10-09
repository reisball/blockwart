"""Browser surface of the access request workflow (Issue #100).

The UI is a third client of the same service commands as REST and MCP. These
tests drive it with real browser sessions and CSRF tokens on both backends.
"""

from __future__ import annotations

import re

import pytest
from access_request_support import (
    FrozenClock,
    changed_tables,
    make_backend_fixture,
    seed_access_world,
    snapshot_database,
)
from sqlalchemy import select

from blockwart.db.session import transaction
from blockwart.domain.auth import GrantScope, Role
from blockwart.models import AccessRequest, AuditEvent, ObjectGrant
from blockwart.services.access import create_object_grant
from blockwart.services.identity import create_human_principal, issue_browser_session
from blockwart.ui.security import AUTH_CSRF_COOKIE_NAME, AUTH_SESSION_COOKIE_NAME

PASSWORD = "browser-access-request-password"


def _seed(session):
    world = seed_access_world(session)
    humans = {}
    for name, role, scope in (
        ("ui_requester", Role.DISCOVERER, GrantScope.SELF),
        ("ui_owner", Role.OWNER, GrantScope.SUBTREE),
        ("ui_outsider", None, None),
    ):
        human = create_human_principal(
            session,
            login=f"browser.{name}",
            display_name=f"Browser {name}",
            password=PASSWORD,
        )
        if role is not None:
            create_object_grant(
                session,
                principal_id=human.id,
                object_id="ar-root",
                role=role,
                scope=scope,
            )
        issued = issue_browser_session(session, principal_id=human.id, ttl_seconds=3600)
        humans[name] = {"id": human.id, "value": issued.value, "csrf": issued.csrf_token}
    world["extras"] = humans
    return world


backend = make_backend_fixture(seed=_seed)


@pytest.fixture
def frozen(monkeypatch) -> FrozenClock:
    return FrozenClock(monkeypatch)


def _browser(backend, who: str):
    client = backend.app_client()
    client.base_url = "https://testserver"
    session = backend.extras[who]
    client.cookies.set(AUTH_SESSION_COOKIE_NAME, session["value"])
    client.cookies.set(AUTH_CSRF_COOKIE_NAME, session["csrf"])
    return client, session["csrf"]


def _request_rows(backend):
    with backend.session() as session:
        rows = list(session.scalars(select(AccessRequest).order_by(AccessRequest.created_at)))
        for row in rows:
            session.expunge(row)
        return rows


def _create_via_ui(client, csrf, **form):
    data = {
        "csrf_token": csrf,
        "object_id": "ar-root",
        "duration": "temporary",
        "ttl_seconds": "3600",
        "reason": "ui reason",
    }
    data.update(form)
    return client.post("/access-requests", data=data, follow_redirects=False)


def test_page_carries_csrf_tokens_and_the_whole_flow_works_in_a_browser(backend) -> None:
    requester, requester_csrf = _browser(backend, "ui_requester")
    owner, owner_csrf = _browser(backend, "ui_owner")
    with requester, owner:
        page = requester.get("/access-requests")
        assert page.status_code == 200
        assert page.headers["Cache-Control"] == "private, no-store"
        tokens = re.findall(r'name="csrf_token" value="([^"]*)"', page.text)
        assert tokens and set(tokens) == {requester_csrf}

        created = _create_via_ui(requester, requester_csrf)
        assert created.status_code == 303
        assert created.headers["location"] == "/access-requests?notice=created"
        (row,) = _request_rows(backend)
        assert row.status == "pending" and row.reason == "ui reason"

        mine = requester.get("/access-requests")
        assert row.id in mine.text and "Pending" in mine.text
        assert f"/access-requests/{row.id}/cancellation" in mine.text

        queue = owner.get("/access-requests")
        assert row.id in queue.text and "browser.ui_requester" in queue.text
        assert f"/access-requests/{row.id}/decision" in queue.text

        approved = owner.post(
            f"/access-requests/{row.id}/decision",
            data={"csrf_token": owner_csrf, "decision": "approve"},
            follow_redirects=False,
        )
        assert approved.status_code == 303
        assert approved.headers["location"] == "/access-requests?notice=approved"
        assert _request_rows(backend)[0].status == "approved"
        assert "Approved" in requester.get("/access-requests").text
        with backend.session() as session:
            actions = set(session.scalars(select(AuditEvent.action)))
            assert {"access_request_create", "access_request_approve", "grant_create"} <= actions


def test_ui_writes_without_a_valid_csrf_token_change_nothing(backend) -> None:
    requester, requester_csrf = _browser(backend, "ui_requester")
    with requester:
        before = snapshot_database(backend.engine)
        missing = requester.post(
            "/access-requests",
            data={"object_id": "ar-root", "duration": "permanent"},
            follow_redirects=False,
        )
        wrong = _create_via_ui(requester, "not-the-token")
        assert missing.status_code in {400, 403, 422} and wrong.status_code in {400, 403}
        assert _request_rows(backend) == []
        # Only security evidence for the rejected writes may be added.
        assert set(changed_tables(before, snapshot_database(backend.engine))) <= {
            "security_events"
        }


def test_ui_get_is_read_only_across_expiry_and_revocation(backend, frozen) -> None:
    requester, requester_csrf = _browser(backend, "ui_requester")
    owner, owner_csrf = _browser(backend, "ui_owner")
    with requester, owner:
        _create_via_ui(requester, requester_csrf, ttl_seconds="600")
        (row,) = _request_rows(backend)
        owner.post(
            f"/access-requests/{row.id}/decision",
            data={"csrf_token": owner_csrf, "decision": "approve"},
        )
        frozen.advance(minutes=11)
        before = snapshot_database(backend.engine)
        pages = [client.get("/access-requests") for client in (requester, owner)]
        pages += [client.get("/access-requests") for client in (requester, owner)]
        after = snapshot_database(backend.engine)
        assert [page.status_code for page in pages] == [200] * 4
        assert changed_tables(before, after) == []
        assert "Expired" in pages[0].text
        assert _request_rows(backend)[0].status == "approved"  # projected, never written


def test_ui_hides_a_request_once_discover_is_lost(backend) -> None:
    requester, requester_csrf = _browser(backend, "ui_requester")
    with requester:
        _create_via_ui(requester, requester_csrf)
        (row,) = _request_rows(backend)
        assert row.id in requester.get("/access-requests").text
        with backend.session() as session:
            with transaction(session):
                grant = session.scalar(
                    select(ObjectGrant).where(
                        ObjectGrant.principal_id == backend.extras["ui_requester"]["id"]
                    )
                )
                session.delete(grant)
        hidden = requester.get("/access-requests")
        assert row.id not in hidden.text and "ar-root" not in hidden.text
        cancelled = requester.post(
            f"/access-requests/{row.id}/cancellation",
            data={"csrf_token": requester_csrf},
            follow_redirects=False,
        )
        assert cancelled.status_code == 303
        assert cancelled.headers["location"] == "/access-requests?error=not_found"
        assert _request_rows(backend)[0].status == "pending"


def test_ui_outsider_cannot_decide_or_see_the_queue(backend) -> None:
    requester, requester_csrf = _browser(backend, "ui_requester")
    outsider, outsider_csrf = _browser(backend, "ui_outsider")
    with requester, outsider:
        _create_via_ui(requester, requester_csrf)
        (row,) = _request_rows(backend)
        assert row.id not in outsider.get("/access-requests").text
        denied = outsider.post(
            f"/access-requests/{row.id}/decision",
            data={"csrf_token": outsider_csrf, "decision": "approve"},
            follow_redirects=False,
        )
        assert denied.headers["location"] == "/access-requests?error=denied"
        assert _request_rows(backend)[0].status == "pending"


def test_ui_messages_come_from_stable_codes_never_from_the_url(backend) -> None:
    requester, _csrf = _browser(backend, "ui_requester")
    with requester:
        spoofed = requester.get("/access-requests?error=Your+account+is+locked&notice=Send+money")
        assert "Your account is locked" not in spoofed.text
        assert "Send money" not in spoofed.text
        known = requester.get("/access-requests?error=conflict")
        assert "could not be applied" in known.text
        german = requester.get("/access-requests?lang=de")
        assert "Zugriffsanfragen" in german.text
        assert "Neue Anfrage" in german.text


def test_settings_hub_links_to_the_page(backend) -> None:
    requester, _csrf = _browser(backend, "ui_requester")
    with requester:
        hub = requester.get("/settings")
        assert hub.status_code == 200
        assert 'href="/access-requests"' in hub.text
