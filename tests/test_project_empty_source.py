"""A rendered empty source row must be inert, not a partial source. Refs #275."""

import json
import re

import pytest
from sqlalchemy import func, select
from test_catalog_root_creation import root_client, root_state  # noqa: F401
from test_project_workspace import _create_project

from blockwart.models import AuditEvent, CatalogObject
from blockwart.ui.security import AUTH_CSRF_COOKIE_NAME, AUTH_SESSION_COOKIE_NAME


def _browser(client, state):
    browser = state["owner_session"]
    client.cookies.set(AUTH_SESSION_COOKIE_NAME, browser.value)
    client.cookies.set(AUTH_CSRF_COOKIE_NAME, browser.csrf_token)
    return browser.csrf_token


def test_rendered_starter_and_new_source_defaults_save_without_sources(root_client, root_state):  # noqa: F811
    _create_project(root_client, root_state["owner_token"], "empty-source")
    csrf = _browser(root_client, root_state)
    page = root_client.get("/projects/empty-source?edit=true")
    controls = re.findall(r'<select name="source_source_type">(.*?)</select>', page.text)
    assert len(controls) == 2  # Rendered starter and add-row template.
    for control in controls:
        options = re.findall(r'<option value="([^"]*)"([^>]*)>', control)
        default = next((value for value, attrs in options if "selected" in attrs), options[0][0])
        saved = root_client.post(
            "/projects/empty-source/work",
            data={
                "csrf_token": csrf,
                "if_match": page.headers["etag"],
                "objective": "Ordinary edit",
                "source_source_type": default,
                "source_id": "",
                "source_reference_kind": "",
                "source_title": "",
                "source_url": "",
                "source_author": "",
                "source_publisher": "",
                "source_published_at": "",
                "source_retrieved_at": "",
            },
            follow_redirects=False,
        )
        assert saved.status_code == 303, saved.text
        page = root_client.get("/projects/empty-source?edit=true")
    with root_state["session_factory"]() as session:
        data = json.loads(session.get(CatalogObject, "empty-source").data_json)
    assert data["objective"] == "Ordinary edit"
    assert "sources" not in data


@pytest.mark.parametrize(
    "source",
    [
        {"source_source_type": "reference"},
        {"source_title": "Entered but incomplete"},
    ],
)
def test_entered_incomplete_source_still_rejects_without_writes(
    root_client,
    root_state,
    source,  # noqa: F811
):
    _create_project(root_client, root_state["owner_token"], "incomplete-source")
    csrf = _browser(root_client, root_state)
    page = root_client.get("/projects/incomplete-source?edit=true")
    with root_state["session_factory"]() as session:
        revision = session.get(CatalogObject, "incomplete-source").revision
        audits = session.scalar(select(func.count(AuditEvent.id)))
    saved = root_client.post(
        "/projects/incomplete-source/work",
        data={
            "csrf_token": csrf,
            "if_match": page.headers["etag"],
            "objective": "Not saved",
            **source,
        },
        follow_redirects=False,
    )
    assert saved.status_code == 400
    with root_state["session_factory"]() as session:
        assert session.get(CatalogObject, "incomplete-source").revision == revision
        assert session.scalar(select(func.count(AuditEvent.id))) == audits


def test_empty_row_does_not_discard_legacy_source_metadata():
    from blockwart.ui.project_forms import ProjectForm, apply_project_workspace_form_data

    legacy = [{"historical_note": "Legacy provenance retained as stored"}]
    data = {"schema_version": 1, "sources": legacy}
    form = ProjectForm(objective="Edited", source_source_type=[""], source_id=[""])
    apply_project_workspace_form_data(
        data, form, submitted_controls=frozenset({"objective"}), preserve_legacy_sources=True
    )
    assert data["sources"] == legacy
    # Preserving legacy data does not bypass the canonical write validator.
