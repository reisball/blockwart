"""UX-v5 rendered contracts and safe synthetic data, never live inventory."""

import json
import re
from datetime import UTC, datetime
from html import unescape

import pytest
from test_ui import client, session_factory  # noqa: F401

from blockwart.domain.activity import ActivityItem, ActivityObject
from blockwart.domain.auth import Permission, PrincipalContext, PrincipalType
from blockwart.domain.release_monitoring import read_github_release_target
from blockwart.domain.schema_projection import minimal_object_data
from blockwart.models import AuditEvent, CatalogObject, Principal, ProjectRecord, Relationship
from blockwart.models.release_monitoring import ServiceReleaseObservation
from blockwart.schemas.catalog import CatalogObjectIn
from blockwart.services.activity import _resolve_actor_identities
from blockwart.services.catalog import upsert_object
from blockwart.services.policy import PolicySnapshot
from blockwart.services.read_access import ReadAccess
from blockwart.ui.presentation import activity_time


def seed_ux_v5(session):
    """Create deterministic offline objects, records, identities and cached releases.

    Args:
        session: Caller-owned isolated synthetic database transaction.

    Returns:
        Nothing; only the supplied local fixture database is populated.
    """
    now = datetime.now(UTC).replace(tzinfo=None)
    for identity, kind, active in (
        ("ux-human", "human", True),
        ("ux-service", "service_account", True),
        ("ux-inactive", "human", False),
    ):
        if session.get(Principal, identity) is None:
            session.add(
                Principal(
                    id=identity,
                    principal_type=kind,
                    login=identity + ".login",
                    display_name="Example " + identity,
                    active=active,
                )
            )
    for identity, kind, label in (
        ("ux-hardware", "host", "Proxmox Example Hardware"),
        ("ux-other-hardware", "host", "Other Example Hardware"),
        ("ux-host", "system", "Example Host"),
        ("ux-other-host", "system", "Other Example Host"),
        ("ux-direct", "service", "Direct Example Service"),
        ("ux-nested", "service", "Nested Example Service"),
        ("ux-other-service", "service", "Other Example Service"),
        ("ux-network", "network", "Example Network"),
        ("ux-device", "device", "Example Device"),
        ("ux-project", "project", "Example UX Project"),
    ):
        data = minimal_object_data(kind)
        if kind == "service":
            data.update(
                {
                    "service_information": {"running_version": "1.0.0"},
                    "release_monitoring": {
                        "enabled": True,
                        "provider": "github_releases",
                        "github": {"owner": "example-org", "repo": "example-service"},
                    },
                }
            )
        upsert_object(
            session,
            CatalogObjectIn(
                id=identity,
                kind=kind,
                label=label,
                data=data,
            ),
            write_audit=False,
        )
        session.flush()
        session.add(
            AuditEvent(
                object_id=identity,
                action="update",
                actor="ux-human",
                summary="Example update",
                details_json=json.dumps({"event": "update", "version": 1, "changes": []}),
                created_at=now,
            )
        )
        if kind == "service":
            target = read_github_release_target(data).target
            session.add(
                ServiceReleaseObservation(
                    object_id=identity,
                    object_instance_id=session.get(CatalogObject, identity).instance_id,
                    provider="github_releases",
                    target_key=target.cache_key,
                    latest_tag="v2.0.0" if identity == "ux-direct" else "v1.0.0",
                    latest_version="2.0.0" if identity == "ux-direct" else "1.0.0",
                    http_status=200,
                    last_checked_at=now,
                    last_success_at=now,
                )
            )
    session.add_all(
        Relationship(from_ref=parent, relation_type="hosts", to_ref=child)
        for parent, child in (
            ("host:ux-hardware", "system:ux-host"),
            ("host:ux-hardware", "service:ux-direct"),
            ("system:ux-host", "service:ux-nested"),
            ("host:ux-other-hardware", "system:ux-other-host"),
            ("system:ux-other-host", "service:ux-other-service"),
        )
    )
    session.flush()
    project = session.get(CatalogObject, "ux-project")
    for index in range(25):
        session.add(
            ProjectRecord(
                id=f"ux-page-{index:02}",
                project_instance_id=project.instance_id,
                kind="page",
                data_json=json.dumps(
                    {
                        "kind": "page",
                        "title": f"Proxmox page {index:02}",
                        "body": "Proxmox example knowledge",
                    }
                ),
                version=1,
                created_at=now,
                updated_at=now,
            )
        )


@pytest.fixture
def ux_seed(session_factory):  # noqa: F811
    with session_factory() as session, session.begin():
        seed_ux_v5(session)


@pytest.mark.parametrize(
    "path", ["/", "/?view=topology", "/projects", "/attention", "/activity", "/settings"]
)
def test_shared_five_destination_navigation(client, path):  # noqa: F811
    response = client.get(path)
    assert response.status_code == 200
    nav = re.search(r'<nav class="main-navigation".*?</nav>', response.text, re.S)[0]
    assert nav.count("<a ") == 5
    assert "/release-updates" not in nav and "/workspace/search" not in nav
    assert "data-smart-open" in response.text and "data-update-badge" in response.text
    assert '<aside class="filter-rail">' not in response.text


def test_catalog_full_parents_and_stable_stock(client, ux_seed):  # noqa: F811
    full = client.get("/").text
    filtered = client.get("/?kind=service&q=Proxmox%20Example").text
    row = re.search(
        r'<tr\s+class="asset-row[^>]*data-asset-ref="host:ux-hardware".*?</tr>', full, re.S
    )[0]
    assert row.count("<td") == 8 and "colspan=" not in row
    assert "/objects/ux-hardware?" in row and "host:ux-hardware" in row
    for kind in ("host", "service", "project"):
        pattern = rf'class="query-pill[^>]*href="[^\"]*kind={kind}"[^>]*>.*?<b>(\d+)</b>'
        assert re.search(pattern, full, re.S)[1] == re.search(pattern, filtered, re.S)[1]
    assert "q=Proxmox%20Example" in filtered and "Search all types" in filtered
    assert 'data-tree-parent="host:ux-hardware" data-tree-depth="2"' in full


def test_smart_search_object_scope_never_filters_content_or_loses_query(client, ux_seed):  # noqa: F811
    narrow = client.get("/search?q=Proxmox%20Example&object_kind=service")
    assert narrow.status_code == 200
    assert "Objects · 0" in narrow.text and "Project content and pages · 25" in narrow.text
    assert "20 matches in loaded rows" in narrow.text
    assert 'href="/search?q=Proxmox%20Example"' in narrow.text
    broad = client.get("/search?q=Proxmox%20Example").text
    assert "Objects · 1" in broad and "Proxmox Example Hardware" in broad
    next_url = unescape(re.search(r'href="([^\"]*content_cursor=[^\"]*)"', narrow.text)[1])
    last = client.get(next_url)
    assert last.status_code == 200 and "5 matches in loaded rows" in last.text
    assert "Project content and pages · 25" in last.text
    assert "private, no-store" == narrow.headers["cache-control"]
    assert client.get("/search?q=Proxmox%20Example&object_kind=invalid").status_code == 400


def test_priority_toggle_and_apply_preserve_other_filters(client):  # noqa: F811
    response = client.get("/attention?severity=critical&kind=service")
    assert response.status_code == 200
    href = re.search(
        r'class="attention-priority-pill attention-severity-critical[^>]*href="([^\"]*)"',
        response.text,
    )[1]
    assert unescape(href) == "/attention?kind=service"
    assert 'name="severity" value="critical"' in response.text
    assert "Information" in response.text


@pytest.mark.parametrize(
    ("stamp", "now", "day", "clock"),
    [
        ("2026-03-29T00:30:00Z", "2026-03-29T08:00:00Z", "Today", "01:30"),
        ("2026-03-29T01:30:00Z", "2026-03-29T08:00:00Z", "Today", "03:30"),
        ("2026-10-25T00:30:00Z", "2026-10-25T08:00:00Z", "Today", "02:30"),
        ("2026-10-25T01:30:00Z", "2026-10-25T08:00:00Z", "Today", "02:30"),
        ("2026-11-12T23:15:00Z", "2026-11-13T23:05:00Z", "Yesterday", "00:15"),
        ("2025-11-13T12:00:00Z", "2026-11-13T12:00:00Z", "2025-11-13", "13:00"),
    ],
)
def test_berlin_calendar_timestamp(stamp, now, day, clock):
    result = activity_time(stamp, "en", now=datetime.fromisoformat(now.replace("Z", "+00:00")))
    assert (result["day"], result["clock"], result["datetime"]) == (day, clock, stamp)
    assert "Europe/Berlin" in result["title"]


@pytest.mark.parametrize("value", [None, "", "garbage", "2026-01-01T12:00:00"])
def test_invalid_time_never_becomes_now(value):
    assert activity_time(value, "de")["day"] == "Zeit unbekannt"
    assert activity_time(value, "de")["datetime"] == ""


def test_identity_requires_active_stable_id_and_existing_profile_visibility(
    session_factory,  # noqa: F811
    ux_seed,
):
    def item(actor):
        return ActivityItem(
            ("1", "1"),
            "1",
            "audit",
            "2026-01-01T00:00:00Z",
            ActivityObject("host:ux-hardware", "ux-hardware", "host", "Example"),
            "Example",
            actor,
            "/objects/ux-hardware",
        )

    def access(manage):
        return ReadAccess(
            PrincipalContext(
                id="ux-viewer",
                principal_type=PrincipalType.HUMAN,
                login="ux-viewer",
                display_name="Viewer",
            ),
            PolicySnapshot(
                principal_id="ux-viewer",
                _permissions={
                    "ux-hardware": frozenset(
                        {Permission.READ, Permission.MANAGE_ACCESS} if manage else {Permission.READ}
                    ),
                },
                _grants={},
            ),
        )

    with session_factory() as session:
        actors = [
            "ux-human",
            "ux-service",
            "ux-inactive",
            "ux-human.login",
            "system",
            "missing",
            None,
        ]
        resolved = _resolve_actor_identities(
            session, access(True), [item(actor) for actor in actors]
        )
        assert [entry.actor_display for entry in resolved[:2]] == [
            "Example ux-human",
            "Example ux-service",
        ]
        assert resolved[1].actor_kind == "service_account"  # not an invented Agent
        assert all(
            entry.actor_display is None and entry.actor_kind is None for entry in resolved[2:]
        )
        hidden = _resolve_actor_identities(session, access(False), [item("ux-human")])
        assert hidden[0].actor_display is None


def test_activity_invalid_target_retains_previous_and_filter_reset_is_narrow(client, ux_seed):  # noqa: F811
    response = client.get(
        "/activity?target=garbage&previous_object_id=ux-direct&event_type=object_revision"
    )
    assert response.status_code == 200 and "previous filter remains active" in response.text
    assert "service:ux-direct" in response.text
    table = re.search(r'<table class="table activity-table">.*?</table>', response.text, re.S)[0]
    assert "Direct Example Service" in table and "Nested Example Service" not in table
    assert 'href="/activity?event_type=object_revision"' in response.text
    assert 'datetime="' in table and "Europe/Berlin" in table


def test_settings_badge_counts_available_updates_not_monitor_count(client, ux_seed):  # noqa: F811
    assert client.get("/navigation/updates").json() == {"count": 1}
    settings = client.get("/settings")
    assert 'href="/release-updates"' in settings.text
    assert 'href="/settings/integrations"' in settings.text
    assert client.get("/settings/integrations").status_code == 200


def test_global_search_and_badge_never_leak_hidden_or_discover_only_content(client, ux_seed):  # noqa: F811
    from fastapi import Request

    from blockwart.ui.security import require_browser_read_access

    def restricted(request: Request):
        request.state.read_access = ReadAccess(
            PrincipalContext(
                id="scoped",
                principal_type=PrincipalType.HUMAN,
                login="scoped",
                display_name="Scoped",
            ),
            PolicySnapshot(
                principal_id="scoped",
                _permissions={
                    "ux-direct": frozenset({Permission.DISCOVER}),
                    "ux-other-service": frozenset({Permission.DISCOVER, Permission.READ}),
                },
                _grants={},
            ),
        )
        return request.state.read_access

    client.app.dependency_overrides[require_browser_read_access] = restricted
    response = client.get("/search?q=Proxmox%20Example")
    assert response.status_code == 200
    assert "Objects · 0" in response.text and "Project content and pages · 0" in response.text
    assert "Proxmox Example Hardware" not in response.text and "ux-page-00" not in response.text
    assert client.get("/navigation/updates").json() == {"count": 0}
    assert "Example ux-human" not in client.get("/activity").text


def test_updated_priority_count_assertion_rejects_wrong_rendered_number():
    # A markup update is not permission to weaken the original Critical: 1 pin.
    pattern = r"attention-severity-critical[^>]*>\s*Critical\s*<b>(\d+)</b>"
    valid = (
        '<a class="attention-priority-pill attention-severity-critical" '
        'href="/attention">Critical <b>1</b></a>'
    )
    assert int(re.search(pattern, valid)[1]) == 1
    assert int(re.search(pattern, valid.replace("<b>1</b>", "<b>2</b>"))[1]) != 1


def test_polish_disclosures_keep_controls_and_diagnostics_reachable(client, ux_seed):  # noqa: F811
    """Preserve controls and coverage while making their default surfaces secondary."""
    catalog = client.get("/").text
    assert "data-view-menu" in catalog
    view = re.search(r'<details class="view-menu".*?</details>', catalog, re.S)[0]
    assert "<summary>View</summary>" in view
    for control in ["data-view-name", "data-save-view", "data-saved-views", "data-load-view"]:
        assert control in view
    assert '<aside class="asset-inspector" data-inspector hidden>' in catalog
    assert "data-inspector-close" in catalog and "data-inspector-details" in catalog
    hints = client.get("/attention").text
    diagnostic = re.search(
        r"<details[^>]*data-attention-diagnostics[^>]*>.*?</details>", hints, re.S
    )[0]
    assert " open" not in diagnostic.split(">")[0]
    assert "attention-signal-table" in diagnostic
    assert hints.index("attention-table") < hints.index("data-attention-diagnostics")
    assert 'name="signal_state"' in hints and 'name="reason_code"' in hints
    projects = client.get("/projects").text
    assert 'class="secondary-disclosure"' in projects
    assert 'name="project_category"' in projects and 'name="project_status"' in projects
    assert 'href="/projects/ux-project"' in projects


def test_polish_activity_retains_rfc3339_fallback_and_evidenced_labels(
    client,  # noqa: F811
    ux_seed,
    session_factory,  # noqa: F811
):
    """Keep exact input and attribution contracts, without a guessed timezone repair."""
    since = "2026-01-01T12:34:56%2B02:00"
    response = client.get("/activity?since=" + since)
    assert response.status_code == 200
    assert 'name="since"' in response.text and "data-activity-since" in response.text
    assert 'value="2026-01-01T12:34:56+02:00"' in response.text
    assert 'name="parent"' in response.text and 'name="kind"' in response.text
    with session_factory() as session, session.begin():
        session.add(
            AuditEvent(
                object_id="ux-direct",
                action="update",
                actor="ux-service",
                summary="Example",
                details_json=json.dumps({"event": "update", "version": 1, "changes": []}),
                created_at=datetime.now(UTC).replace(tzinfo=None),
            )
        )
    for lang, label in [("en", "Service account"), ("de", "Servicekonto")]:
        content = client.get("/activity?lang=" + lang).text
        assert label in content
        assert ">Agent<" not in content
    fallback = client.get("/search?q=Proxmox&object_kind=service").text
    assert 'action="/search" method="get"' in fallback
    assert 'name="q" value="Proxmox"' in fallback
    assert "data-smart-expand" in fallback
