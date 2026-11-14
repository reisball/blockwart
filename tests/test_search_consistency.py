"""Five-domain local search over permission-safe synthetic projections."""

import json
import re
from datetime import UTC, datetime, timedelta
from html import unescape
from urllib.parse import parse_qs, urlsplit

import pytest
from test_activity_feed import _access, _asset, _audit
from test_attention_filters_313 import attention_browser  # noqa: F401
from test_catalog_root_creation import root_client, root_state  # noqa: F401
from test_ui import client, session_factory  # noqa: F401
from test_ux_v5 import seed_ux_v5

from blockwart.models import CatalogObject, ObjectComment, Principal, ProjectRecord
from blockwart.services.activity import query_activity_page
from blockwart.services.catalog import upsert_object
from blockwart.services.pagination import InvalidCursor


@pytest.fixture
def search_seed(session_factory):  # noqa: F811
    with session_factory() as session, session.begin():
        seed_ux_v5(session)
        project = session.get(CatalogObject, "ux-project")
        now = datetime.now(UTC).replace(tzinfo=None)
        session.add(
            ProjectRecord(
                id="local-task",
                project_instance_id=project.instance_id,
                kind="item",
                data_json=json.dumps({"title": "Needle task", "description": "Task Needle"}),
                version=1,
                created_at=now,
                updated_at=now,
            )
        )
        session.add(
            ObjectComment(
                id="local-log",
                object_id=project.id,
                object_instance_id=project.instance_id,
                object_created_at=project.created_at,
                body="Needle log",
                format="plain_text",
                origin="legacy",
                created_at=now,
            )
        )


def test_project_search_includes_labeled_contents_and_combines_filters(
    client,  # noqa: F811
    search_seed,
    session_factory,  # noqa: F811
):  # noqa: F811
    for query, labels, count in [
        ("Needle", ["Task", "Log"], 2),
        ("Proxmox", ["Page"], 25),
        ("Example UX Project", ["Project"], 1),
    ]:
        response = client.get("/projects", params={"q": query})
        assert response.status_code == 200, response.text
        assert f"{count} matches" in response.text
        assert all(f">{label}</span>" in response.text for label in labels)
        assert "Other Example Hardware" not in response.text
    assert (
        'href="/projects/ux-project/workspace/record/local-task"'
        in client.get("/projects?q=Needle").text
    )
    with session_factory() as session:
        category = json.loads(session.get(CatalogObject, "ux-project").data_json)["category"]
    response = client.get("/projects", params={"q": "Needle", "project_category": category})
    assert "2 matches" in response.text
    response = client.get("/projects", params={"q": "unfindable"})
    assert "0 matches" in response.text and 'data-smart-query="unfindable"' in response.text


def test_hint_text_is_filtered_before_summary_and_pagination(attention_browser):  # noqa: F811
    page = attention_browser.get("/attention?q=Host&kind=host&reason_code=lifecycle_health_down")
    assert page.status_code == 200
    assert page.text.count('class="attention-row ') == 100
    next_url = unescape(re.search(r'href="([^"]+)">More items</a>', page.text)[1])
    assert parse_qs(urlsplit(next_url).query)["q"] == ["Host"]
    assert attention_browser.get(next_url).text.count('class="attention-row ') == 2
    assert (
        attention_browser.get("/attention?q=NotAMatch&kind=host").text.count(
            'class="attention-row '
        )
        == 0
    )
    assert (
        "Service Down"
        in attention_browser.get("/attention?q=Service%20Down&kind=service&severity=critical").text
    )
    # Visible translated reason content, not just object IDs.
    assert (
        attention_browser.get("/attention?q=down&kind=host").text.count('class="attention-row ')
        == 100
    )
    tampered = next_url.replace("q=Host", "q=Other")
    assert attention_browser.get(tampered).status_code == 400


def test_activity_text_scans_nonmatches_and_binds_cursor(alembic_session_factory):
    now = datetime(2026, 11, 14, tzinfo=UTC)
    with alembic_session_factory() as session, session.begin():
        upsert_object(session, _asset("visible"), write_audit=False)
        for index in range(405):
            session.add(
                _audit(
                    "visible",
                    "update",
                    created_at=now + timedelta(seconds=index),
                    actor="author" if index in [0, 202, 404] else "other",
                )
            )
        session.add(
            Principal(
                id="author",
                principal_type="human",
                login="author",
                display_name="Needle Author",
                active=True,
            )
        )
    with alembic_session_factory() as session:
        access = _access("author", {"visible"})
        cursor, ids = None, []
        while True:
            page = query_activity_page(
                session, access, text_query="Needle Author", limit=1, cursor=cursor
            )
            ids.extend(item.event_id for item in page.items)
            cursor = page.next_cursor
            if not cursor:
                break
            with pytest.raises(InvalidCursor):
                query_activity_page(session, access, text_query="Different", limit=1, cursor=cursor)
        assert len(ids) == len(set(ids)) == 3
        denied = query_activity_page(
            session, _access("reader", {"visible"}), text_query="Needle Author"
        )
        assert denied.items == []  # Profile cannot become a search side channel.
        assert query_activity_page(session, access, text_query="Visible").items
        assert not query_activity_page(
            session, _access("reader", set()), text_query="Visible"
        ).items


def test_shared_forms_labels_escape_and_native_state(client, search_seed):  # noqa: F811
    for path, label in [
        ("/", "Katalog durchsuchen"),
        ("/?view=topology", "Topologie durchsuchen"),
        ("/projects", "Projekte durchsuchen"),
        ("/attention", "Hinweise durchsuchen"),
        ("/activity", "Aktivität durchsuchen"),
    ]:
        response = client.get(
            path + ("&" if "?" in path else "?") + "lang=de&q=%3Cscript%3Eevil()%3C/script%3E"
        )
        assert response.status_code == 200
        assert label in response.text and "data-local-search" in response.text
        assert "<script>evil()</script>" not in response.text
        assert 'data-smart-query="&lt;script&gt;evil()&lt;/script&gt;"' in response.text
        assert 'class="settings-gear" aria-hidden="true"' in response.text
    response = client.get(
        "/?view=catalog&q=Direct&kind=service&topology_mode=network&services=1&network_category=segment"
    )
    nav = unescape(re.search(r'<nav class="main-navigation".*?</nav>', response.text, re.S)[0])
    assert (
        "view=topology&q=Direct&kind=service&topology_mode=network&network_category=segment&services=1"
        in nav
    )
    for path in ["/projects/filters/normalize", "/attention/filters/normalize"]:
        response = client.get(path, params={"q": "Needle"}, follow_redirects=False)
        assert parse_qs(urlsplit(response.headers["location"]).query)["q"] == ["Needle"]


def test_project_local_search_permission_and_filter_binding(root_client, root_state):  # noqa: F811
    """Local projects reuse the existing body/chronology permission boundary."""
    from test_project_records import _browser
    from test_project_workspace import _create_project
    from test_workspace_search import _made

    _create_project(root_client, root_state["owner_token"], "local-project")
    _made(root_client, root_state, "local-project", "page", title="Private Needle", body="Needle")
    _browser(root_client, root_state)
    response = root_client.get("/projects?q=Needle")
    assert response.status_code == 200 and "Private Needle" in response.text
    assert 'href="/projects/local-project/workspace/record/' in response.text


def test_project_content_cursor_combines_structured_filter(session_factory, search_seed):  # noqa: F811
    """UI-only project hits page with existing content without changing REST output."""
    from conftest import _unrestricted_read_access

    from blockwart.services.workspace_search import search_workspaces

    with session_factory() as session:
        access = _unrestricted_read_access(session)
        category = json.loads(session.get(CatalogObject, "ux-project").data_json)["category"]
        page = search_workspaces(
            session, access, q="Proxmox", include_projects=True, project_category=category, limit=20
        )
        assert page.total == 25 and len(page.items) == 20 and page.next_cursor
        continuation = search_workspaces(
            session,
            access,
            q="Proxmox",
            include_projects=True,
            project_category=category,
            limit=20,
            cursor=page.next_cursor,
        )
        assert len(continuation.items) == 5 and continuation.next_cursor is None
        assert not ({hit.id for hit in page.items} & {hit.id for hit in continuation.items})
        with pytest.raises(InvalidCursor):
            search_workspaces(
                session,
                access,
                q="Proxmox",
                include_projects=True,
                project_status="active",
                limit=20,
                cursor=page.next_cursor,
            )
        denied = _access("stranger", set(), discoverable={"ux-project"})
        assert search_workspaces(session, denied, q="Proxmox", include_projects=True).total == 0


def test_activity_budget_continues_past_empty_text_page(alembic_session_factory, monkeypatch):
    """Sparse text matches remain reachable across a bounded empty scan."""
    import blockwart.services.activity as activity

    now = datetime(2026, 11, 14, tzinfo=UTC)
    with alembic_session_factory() as session, session.begin():
        upsert_object(session, _asset("visible"), write_audit=False)
        for index in range(8):
            session.add(
                _audit(
                    "visible",
                    "update",
                    created_at=now + timedelta(seconds=index),
                    actor="needle" if index == 0 else "other",
                )
            )
        session.add(
            Principal(
                id="needle",
                principal_type="human",
                login="needle",
                display_name="Sparse Author",
                active=True,
            )
        )
    monkeypatch.setattr(activity, "ACTIVITY_MAX_SCAN_EVENTS", 3)
    with alembic_session_factory() as session:
        access = _access("needle", {"visible"})
        first = activity.query_activity_page(session, access, text_query="Sparse Author", limit=1)
        assert first.items == [] and first.next_cursor
        second = activity.query_activity_page(
            session, access, text_query="Sparse Author", limit=1, cursor=first.next_cursor
        )
        assert second.items == [] and second.next_cursor
        third = activity.query_activity_page(
            session, access, text_query="Sparse Author", limit=1, cursor=second.next_cursor
        )
        assert len(third.items) == 1 and third.next_cursor is None
