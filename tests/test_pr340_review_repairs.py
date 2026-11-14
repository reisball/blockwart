"""Request-level review regressions with real browser authorization."""

import re
from html import unescape
from urllib.parse import parse_qs, urlsplit

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from test_search_consistency import search_seed  # noqa: F401
from test_ui import client, session_factory  # noqa: F401
from test_ux_v5 import seed_ux_v5

from blockwart.api.deps import get_session
from blockwart.domain.auth import CatalogRole, GrantScope, Role
from blockwart.domain.schema_projection import minimal_object_data
from blockwart.main import create_app
from blockwart.models import Principal
from blockwart.schemas.catalog import CatalogObjectIn
from blockwart.services.access import create_object_grant
from blockwart.services.catalog import upsert_object
from blockwart.services.identity import create_human_principal, issue_browser_session
from blockwart.ui.security import AUTH_SESSION_COOKIE_NAME


@pytest.fixture
def role_browser(alembic_session_factory):
    """Use actual cookies/dependencies; only persistence is fixture-injected."""
    sessions = alembic_session_factory
    cookies = {}
    with sessions() as session, session.begin():
        seed_ux_v5(session)
        for kind in ("runbook", "decision", "credential_reference"):
            data = minimal_object_data(kind)
            if kind == "credential_reference":
                data["reference"] = {
                    "name": "review-private-locator",
                    "path": "/review-private-locator",
                }
            upsert_object(
                session,
                CatalogObjectIn(
                    id="review-" + kind,
                    kind=kind,
                    label="Review " + kind,
                    data=data,
                ),
                write_audit=True,
            )
        for name, catalog_role, grant in [
            ("owner", CatalogRole.CATALOG_OWNER, None),
            ("viewer", CatalogRole.CATALOG_VIEWER, None),
            ("local-owner", None, Role.OWNER),
            ("reader", None, Role.VIEWER),
            ("discoverer", None, Role.DISCOVERER),
        ]:
            principal = create_human_principal(
                session,
                login="review." + name,
                display_name="Review " + name,
                password="synthetic-password-only-123",
                catalog_role=catalog_role,
            )
            if grant:
                for target in [
                    "ux-hardware",
                    "ux-project",
                    "review-runbook",
                    "review-decision",
                    "review-credential_reference",
                ]:
                    create_object_grant(
                        session,
                        principal_id=principal.id,
                        object_id=target,
                        role=grant,
                        scope=GrantScope.SELF,
                    )
            cookies[name] = issue_browser_session(
                session, principal_id=principal.id, ttl_seconds=3600
            ).value
    app = create_app()

    def dependency():
        """Dependency."""
        with sessions() as session:
            yield session

    app.dependency_overrides[get_session] = dependency
    with TestClient(app) as browser:
        yield browser, cookies


@pytest.mark.parametrize(
    "role,identity", [("owner", True), ("viewer", False), ("local-owner", True), ("reader", False)]
)
def test_real_role_activity_target_and_actor_contract(role_browser, role, identity):
    """Real role activity target and actor contract."""
    browser, cookies = role_browser
    browser.cookies.set(AUTH_SESSION_COOKIE_NAME, cookies[role])
    page = browser.get("/activity")
    assert page.status_code == 200
    assert 'value="host:ux-hardware"' in page.text
    for key in ["target", "object_id", "parent"]:
        filtered = browser.get(
            "/activity", params={key: "host:ux-hardware", "event_type": "object_revision"}
        )
        assert filtered.status_code == 200
        expected = 4 if key == "parent" and role in ("owner", "viewer") else 1
        assert filtered.text.count('class="attention-row"') == expected
        assert ("Example ux-human</span>" in filtered.text) == identity
    by_actor = browser.get("/activity?q=Example%20ux-human")
    assert (by_actor.text.count('class="attention-row"') > 0) == identity


@pytest.mark.parametrize("kind", ["project", "runbook", "decision", "credential_reference"])
def test_authorized_knowledge_targets(role_browser, kind):
    """Authorized knowledge targets."""
    browser, cookies = role_browser
    browser.cookies.set(AUTH_SESSION_COOKIE_NAME, cookies["reader"])
    identity = "ux-project" if kind == "project" else "review-" + kind
    ref = kind + ":" + identity
    for key in ["target", "object_id", "parent"]:
        response = browser.get("/activity", params={key: ref, "event_type": "object_revision"})
        assert response.status_code == 200
        assert f'value="{ref}"' in response.text
        assert response.text.count('class="attention-row"') == 1
    # Metadata READ permits selection; reference contents are still projected.
    if kind == "credential_reference":
        assert "review-private-locator" not in response.text
        searched = browser.get("/activity?q=review-private-locator")
        assert searched.text.count('class="attention-row"') == 0


@pytest.mark.parametrize("role", ["reader", "discoverer"])
def test_invalid_and_concealed_targets_fail_closed_without_sentinel(role_browser, role):
    """Invalid and concealed targets fail closed without sentinel."""
    browser, cookies = role_browser
    browser.cookies.set(AUTH_SESSION_COOKIE_NAME, cookies[role])
    for params in [
        {"target": "host:ux-other-hardware"},
        {"target": "host:unknown"},
        {"object_id": "host:ux-other-hardware"},
        {"parent": "host:ux-other-hardware"},
        {"parent": "host:unknown"},
    ]:
        response = browser.get("/activity", params=params)
        assert response.status_code == 200
        assert response.text.count('class="attention-row"') == 0
        assert 'role="alert"' in response.text
        assert "__invalid_target__" not in response.text
        assert "ux-other-hardware" not in response.text
        assert "host:unknown" not in response.text
        form = re.search(r"<form[^>]*data-local-search.*?</form>", response.text, re.S)[0]
        assert 'name="invalid_target" value="1"' in form
        assert 'name="object_id"' not in form
        assert 'name="target" value="invalid"' not in response.text
    resubmitted = browser.get("/activity?invalid_target=1&target=&q=Example")
    assert resubmitted.text.count('class="attention-row"') == 0
    assert 'role="alert"' in resubmitted.text
    if role == "reader":
        previous = browser.get("/activity?target=invalid&previous_object_id=ux-hardware")
        assert previous.text.count('class="attention-row"') == 4
        assert 'value="host:ux-hardware"' in previous.text
        recovered = browser.get("/activity?invalid_target=1&target=host:ux-hardware")
        assert recovered.text.count('class="attention-row"') == 4
        assert 'name="invalid_target"' not in recovered.text
        assert browser.get("/activity").text.count('class="attention-row"') > 0


def test_actor_batch_does_not_expand_identity_to_other_targets(
    role_browser, alembic_session_factory
):
    """Target access management, not a shared author ID, permits identity labels."""
    browser, cookies = role_browser
    with alembic_session_factory() as session, session.begin():
        principal = session.scalar(select(Principal).where(Principal.login == "review.local-owner"))
        create_object_grant(
            session,
            principal_id=principal.id,
            object_id="ux-other-hardware",
            role=Role.VIEWER,
            scope=GrantScope.SELF,
        )
    browser.cookies.set(AUTH_SESSION_COOKIE_NAME, cookies["local-owner"])
    page = browser.get("/activity?event_type=object_revision")
    assert page.status_code == 200
    rows = re.findall(r'<tr class="attention-row">.*?</tr>', page.text, re.S)
    managed = next(row for row in rows if "host:ux-hardware" in row)
    readable = next(row for row in rows if "host:ux-other-hardware" in row)
    assert "Example ux-human</span>" in managed
    assert "Example ux-human</span>" not in readable
    searched = browser.get("/activity?q=Example%20ux-human&event_type=object_revision")
    assert "host:ux-other-hardware" not in re.sub(
        r"<datalist.*?</datalist>", "", searched.text, flags=re.S
    )


@pytest.mark.parametrize("role", ["owner", "viewer", "reader"])
def test_every_rendered_global_kind_is_requestable(role_browser, role):
    """Every rendered global kind is requestable."""
    browser, cookies = role_browser
    browser.cookies.set(AUTH_SESSION_COOKIE_NAME, cookies[role])
    for path in ["/", "/search"]:
        page = browser.get(path)
        selects = re.findall(
            r'<select[^>]*(?:id="smart-kind"|name="object_kind")[^>]*>(.*?)</select>',
            page.text,
            re.S,
        )
        assert selects
        options = set(re.findall(r'<option value="([^"]*)"', "".join(selects)))
        assert {"host", "runbook", "decision", "project"} <= options
        for kind in options:
            for fragment in [False, True]:
                response = browser.get(
                    "/search",
                    params={"q": "Example", "object_kind": kind, "fragment": str(fragment).lower()},
                )
                assert response.status_code == 200, (kind, response.text)
    assert browser.get("/search?q=x&object_kind=unknown").status_code == 400


@pytest.mark.parametrize(
    "query",
    [
        "Example UX Project",
        "Example  UX  Project",
        "Ｅｘａｍｐｌｅ ＵＸ Ｐｒｏｊｅｃｔ",
        "Needle task",
        "Needle   task",
        "Ｎｅｅｄｌｅ ｔａｓｋ",
        "Needle log",
        "Needle   log",
        "Ｎｅｅｄｌｅ ｌｏｇ",
        "Proxmox",
        "Ｐｒｏｘｍｏｘ",
    ],
)
def test_project_hit_kinds_share_normalization(client, search_seed, query):  # noqa: F811
    """Project hit kinds share normalization."""
    page = client.get("/projects", params={"q": query})
    assert page.status_code == 200
    assert 'class="local-search-hit"' in page.text
    hits = page.context["search_page"].items
    if query.startswith(("Example", "Ｅｘａｍｐｌｅ")):
        assert {(hit.kind, hit.id) for hit in hits} == {("project", "ux-project")}
    elif "task" in query or "ｔａｓｋ" in query:
        assert {(hit.kind, hit.id) for hit in hits} == {("item", "local-task")}
    elif "log" in query or "ｌｏｇ" in query:
        assert {(hit.kind, hit.id) for hit in hits} == {("chronology", "local-log")}
    else:
        assert len(hits) == 25 and {hit.kind for hit in hits} == {"page"}


@pytest.mark.parametrize("locale,title", [("en", "Note"), ("de", "Notiz")])
def test_local_log_title_is_translated(client, search_seed, locale, title):  # noqa: F811
    """Local log title is translated."""
    page = client.get("/projects", params={"q": "Needle log", "lang": locale})
    assert re.search(r"/local-log[^>]*>" + title + "</a>", page.text)


def test_topology_detail_search_targets_overview_not_activity(client):  # noqa: F811
    """Topology detail search targets overview not activity."""
    page = client.get("/objects/brieftraeger?view=topology&q=brief&kind=system")
    assert page.status_code == 200
    form = re.search(r"<form[^>]*data-local-search.*?</form>", page.text, re.S)[0]
    assert 'action="/"' in form
    assert 'data-search-domain="objects"' in form
    assert "Search topology" in form


def test_severity_pills_count_their_destinations(client, search_seed):  # noqa: F811
    """Severity pills count their destinations."""
    for filters in [{}, {"q": "Example", "kind": "service"}]:
        page = client.get("/attention", params={**filters, "severity": "critical"})
        assert page.status_code == 200
        links = re.findall(
            r'<a class="attention-priority-pill[^"]*" href="([^"]+)"[^>]*>.*?<b>(\d+)</b></a>',
            page.text,
        )
        assert len(links) == 4
        for url, count in links:
            destination = client.get(unescape(url))
            assert destination.context["summary"].total == int(count), (url, count)
            params = parse_qs(urlsplit(unescape(url)).query)
            assert all(params.get(key) == [value] for key, value in filters.items())
