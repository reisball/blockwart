"""The reference-content UI separates metadata, reading and blind replacement. Refs #315."""

import html
import json
import re

import pytest
from test_catalog_root_creation import root_client, root_state  # noqa: F401

from blockwart.db.session import transaction
from blockwart.domain.auth import GrantScope, Role
from blockwart.domain.provenance import CatalogProvenance
from blockwart.models import AuditEvent, CatalogObject
from blockwart.schemas.catalog import CatalogObjectIn
from blockwart.services.access import create_object_grant
from blockwart.services.catalog import upsert_object
from blockwart.services.identity import create_human_principal, issue_browser_session
from blockwart.ui.security import AUTH_CSRF_COOKIE_NAME, AUTH_SESSION_COOKIE_NAME

REFERENCE_ID = "ui-protected-reference"
LOCATOR = "/protected/ui-315-original-locator"
HISTORICAL_LOCATOR = "/protected/ui-315-historical-locator"
CONTENT = {"path": LOCATOR, "key": "OPERATOR_KEY", "item_hint": "operator"}
DATA = {
    "schema_version": 1,
    "provider": "infisical",
    "reference": CONTENT,
    "handling_rules": {"telegram_allowed": False},
    "secret_value_stored": False,
}
PROVENANCE = CatalogProvenance(
    source_type="import",
    source_ref="inventory:ui-315",
    managed_by="ui-test",
)


@pytest.fixture
def reference_browser(root_client, root_state):  # noqa: F811
    """Issue real browser identities and grants against a migrated database."""
    factory = root_state["session_factory"]
    with factory() as session, transaction(session):
        upsert_object(
            session,
            CatalogObjectIn(
                id=REFERENCE_ID,
                kind="credential_reference",
                label="Operator reference",
                summary="Metadata summary",
                data=DATA,
                provenance=PROVENANCE,
            ),
        )
        # A pre-boundary legacy summary must not become a history side-channel.
        session.add(
            AuditEvent(
                object_id=REFERENCE_ID,
                action="update",
                actor="legacy-import",
                summary=f"Reference changed from {HISTORICAL_LOCATOR}",
            )
        )

    def login(*roles):
        with factory() as session, transaction(session):
            principal = create_human_principal(
                session,
                login="reference.ui",
                display_name="Reference UI",
                password="reference-ui-password-315",
            )
            for role in roles:
                create_object_grant(
                    session,
                    principal_id=principal.id,
                    object_id=REFERENCE_ID,
                    role=role,
                    scope=GrantScope.SELF,
                )
            browser = issue_browser_session(session, principal_id=principal.id, ttl_seconds=3600)
        root_client.cookies.set(AUTH_SESSION_COOKIE_NAME, browser.value)
        root_client.cookies.set(AUTH_CSRF_COOKIE_NAME, browser.csrf_token)
        return root_client, browser, factory

    return login


def _textarea(response, name):
    match = re.search(
        rf'<textarea\b[^>]*\bname="{name}"[^>]*>(.*?)</textarea>', response.text, re.DOTALL
    )
    assert match is not None, response.text[:500]
    return html.unescape(match.group(1))


def _post_content(client, browser, factory, content, **extra):
    with factory() as session:
        revision = session.get(CatalogObject, REFERENCE_ID).revision
    return client.post(
        f"/objects/{REFERENCE_ID}/reference-content?lang=en",
        data={
            "csrf_token": browser.csrf_token,
            "if_match": f'"rev-{revision}"',
            "reference_json": content,
            **extra,
        },
        follow_redirects=False,
    )


@pytest.mark.parametrize(
    "role", [Role.DISCOVERER, Role.VIEWER, Role.EDITOR, Role.REFERENCE_CONTENT_EDITOR]
)
def test_metadata_and_write_only_roles_never_echo_current_or_historical_locator(
    reference_browser,
    role,
):
    client, _, _ = reference_browser(role)
    response = client.get(f"/objects/{REFERENCE_ID}?lang=en&edit=reference-content")
    assert response.status_code == 200
    assert LOCATOR not in response.text
    assert HISTORICAL_LOCATOR not in response.text
    if role == Role.REFERENCE_CONTENT_EDITOR:
        assert _textarea(response, "reference_json") == ""
        assert "Replace reference content" in response.text
        assert 'name="data_json"' not in response.text
        assert 'name="primary_name"' not in response.text
    else:
        assert 'name="reference_json"' not in response.text


@pytest.mark.parametrize("role", [Role.REFERENCE_CONTENT_READER, Role.OWNER])
def test_content_reader_can_view_without_implicit_content_editor(reference_browser, role):
    client, _, _ = reference_browser(role)
    response = client.get(f"/objects/{REFERENCE_ID}?lang=en")
    assert response.status_code == 200
    assert LOCATOR in response.text
    assert "Read reference content" in response.text
    if role == Role.REFERENCE_CONTENT_READER:
        assert "edit=reference-content" not in response.text
        assert 'name="reference_json"' not in response.text


def test_readable_content_is_not_part_of_metadata_editor(reference_browser):
    client, browser, factory = reference_browser(Role.EDITOR, Role.REFERENCE_CONTENT_READER)
    response = client.get(f"/objects/{REFERENCE_ID}?lang=en&edit=overview")
    assert response.status_code == 200
    assert LOCATOR in response.text  # separate read-only content panel
    metadata = json.loads(_textarea(response, "data_json"))
    assert "reference" not in metadata
    metadata["provider"] = "vaultwarden"
    with factory() as session:
        revision = session.get(CatalogObject, REFERENCE_ID).revision
    saved = client.post(
        f"/objects/{REFERENCE_ID}",
        data={
            "csrf_token": browser.csrf_token,
            "if_match": f'"rev-{revision}"',
            "data_json": json.dumps(metadata),
        },
        follow_redirects=False,
    )
    assert saved.status_code == 303, saved.text[:500]
    with factory() as session:
        stored = json.loads(session.get(CatalogObject, REFERENCE_ID).data_json)
    assert stored["reference"] == CONTENT
    assert stored["provider"] == "vaultwarden"


@pytest.mark.parametrize("json_form", [False, True])
def test_metadata_only_editor_preserves_unreadable_reference(reference_browser, json_form):
    client, browser, factory = reference_browser(Role.EDITOR)
    with factory() as session:
        revision = session.get(CatalogObject, REFERENCE_ID).revision
    fields = {
        "csrf_token": browser.csrf_token,
        "if_match": f'"rev-{revision}"',
        "summary": "New metadata summary",
    }
    if json_form:
        fields["data_json"] = json.dumps(
            {key: value for key, value in DATA.items() if key != "reference"}
        )
    response = client.post(f"/objects/{REFERENCE_ID}", data=fields, follow_redirects=False)
    assert response.status_code == 303, response.text[:500]
    with factory() as session:
        stored = session.get(CatalogObject, REFERENCE_ID)
        assert stored.summary == "New metadata summary"
        assert json.loads(stored.data_json)["reference"] == CONTENT


@pytest.mark.parametrize("reference", [{}, CONTENT, {"path": "/tampered/locator"}])
def test_tampered_metadata_document_cannot_change_or_guess_protected_content(
    reference_browser,
    reference,
):
    client, browser, factory = reference_browser(Role.EDITOR)
    with factory() as session:
        revision = session.get(CatalogObject, REFERENCE_ID).revision
    response = client.post(
        f"/objects/{REFERENCE_ID}",
        data={
            "csrf_token": browser.csrf_token,
            "if_match": f'"rev-{revision}"',
            "data_json": json.dumps({**DATA, "reference": reference}),
        },
        follow_redirects=False,
    )
    assert response.status_code == 403
    assert LOCATOR not in response.text
    assert HISTORICAL_LOCATOR not in response.text
    with factory() as session:
        stored = session.get(CatalogObject, REFERENCE_ID)
        assert stored.revision == revision
        assert json.loads(stored.data_json)["reference"] == CONTENT


def test_content_only_writer_can_replace_without_read_or_metadata_authority(reference_browser):
    client, browser, factory = reference_browser(Role.REFERENCE_CONTENT_EDITOR)
    replacement = {"path": "/protected/replacement", "key": "NEW_KEY"}
    response = _post_content(
        client,
        browser,
        factory,
        json.dumps(replacement),
        summary="Tampered metadata",
        data_json='{"provider":"vaultwarden"}',
    )
    assert response.status_code == 303, response.text[:500]
    with factory() as session:
        stored = session.get(CatalogObject, REFERENCE_ID)
        assert stored.label == "Operator reference"
        assert stored.summary == "Metadata summary"
        assert json.loads(stored.data_json) == {**DATA, "reference": replacement}
        assert json.loads(stored.provenance_json) == PROVENANCE.model_dump()
    page = client.get(response.headers["location"])
    assert LOCATOR not in page.text
    assert replacement["path"] not in page.text
    assert HISTORICAL_LOCATOR not in page.text


@pytest.mark.parametrize(
    "invalid", ["", " ", "[]", "null", "42", '{"key":', '{"path": {"nested": "private-input"}}']
)
def test_blank_or_invalid_blind_replacement_never_clears_or_echoes_content(
    reference_browser,
    invalid,
):
    client, browser, factory = reference_browser(Role.REFERENCE_CONTENT_EDITOR)
    with factory() as session:
        revision = session.get(CatalogObject, REFERENCE_ID).revision
    response = _post_content(client, browser, factory, invalid)
    assert response.status_code == 422
    assert LOCATOR not in response.text
    assert HISTORICAL_LOCATOR not in response.text
    assert "private-input" not in response.text
    assert _textarea(response, "reference_json") == ""
    with factory() as session:
        stored = session.get(CatalogObject, REFERENCE_ID)
        assert stored.revision == revision
        assert json.loads(stored.data_json)["reference"] == CONTENT


def test_explicit_empty_object_clears_content_for_blind_writer(reference_browser):
    client, browser, factory = reference_browser(Role.REFERENCE_CONTENT_EDITOR)
    response = _post_content(client, browser, factory, "{}")
    assert response.status_code == 303, response.text[:500]
    with factory() as session:
        assert json.loads(session.get(CatalogObject, REFERENCE_ID).data_json)["reference"] == {}


@pytest.mark.parametrize("role", [Role.VIEWER, Role.EDITOR, Role.REFERENCE_CONTENT_READER])
def test_read_and_metadata_roles_cannot_call_content_route(reference_browser, role):
    client, browser, factory = reference_browser(role)
    response = _post_content(client, browser, factory, '{"path":"/unauthorized"}')
    assert response.status_code == 403
    with factory() as session:
        stored = session.get(CatalogObject, REFERENCE_ID)
        assert json.loads(stored.data_json)["reference"] == CONTENT


@pytest.mark.parametrize("object_id,expected", [(REFERENCE_ID, True), ("existing-object", False)])
def test_reference_content_roles_only_offered_for_reference_grants(
    reference_browser,
    root_state,  # noqa: F811
    object_id,
    expected,
):
    # Initialize reference fixture, then use its existing catalog-owner browser.
    client, _, _ = reference_browser(Role.VIEWER)
    owner = root_state["owner_session"]
    client.cookies.set(AUTH_SESSION_COOKIE_NAME, owner.value)
    client.cookies.set(AUTH_CSRF_COOKIE_NAME, owner.csrf_token)
    response = client.get(f"/objects/{object_id}?lang=en&edit=permissions")
    assert response.status_code == 200
    for role in (Role.REFERENCE_CONTENT_READER, Role.REFERENCE_CONTENT_EDITOR):
        assert (f'<option value="{role.value}"' in response.text) is expected
    assert 'name="csrf_token"' in response.text


def test_content_route_requires_csrf(reference_browser):
    client, _, factory = reference_browser(Role.REFERENCE_CONTENT_EDITOR)
    response = client.post(
        f"/objects/{REFERENCE_ID}/reference-content",
        data={"csrf_token": "not-the-session-csrf", "if_match": '"rev-1"', "reference_json": "{}"},
        follow_redirects=False,
    )
    assert response.status_code == 403
    assert LOCATOR not in response.text
    with factory() as session:
        stored = session.get(CatalogObject, REFERENCE_ID)
        assert json.loads(stored.data_json)["reference"] == CONTENT


def test_blind_content_writer_cannot_overwrite_a_stale_revision(reference_browser):
    client, browser, factory = reference_browser(Role.REFERENCE_CONTENT_EDITOR)
    response = client.post(
        f"/objects/{REFERENCE_ID}/reference-content",
        data={
            "csrf_token": browser.csrf_token,
            "if_match": '"rev-0"',
            "reference_json": '{"path":"/stale-update"}',
        },
        follow_redirects=False,
    )
    assert response.status_code == 412
    assert LOCATOR not in response.text
    assert HISTORICAL_LOCATOR not in response.text
    assert "/stale-update" not in response.text
    assert _textarea(response, "reference_json") == ""
    with factory() as session:
        stored = session.get(CatalogObject, REFERENCE_ID)
        assert json.loads(stored.data_json)["reference"] == CONTENT


def test_content_only_writer_cannot_use_metadata_update_route(reference_browser):
    client, browser, factory = reference_browser(Role.REFERENCE_CONTENT_EDITOR)
    with factory() as session:
        revision = session.get(CatalogObject, REFERENCE_ID).revision
    response = client.post(
        f"/objects/{REFERENCE_ID}",
        data={
            "csrf_token": browser.csrf_token,
            "if_match": f'"rev-{revision}"',
            "summary": "Unauthorized metadata update",
        },
        follow_redirects=False,
    )
    assert response.status_code == 403
    with factory() as session:
        assert session.get(CatalogObject, REFERENCE_ID).summary == "Metadata summary"


def test_reference_metadata_name_edit_uses_label_not_network_storage(reference_browser):
    client, browser, factory = reference_browser(Role.EDITOR)
    with factory() as session:
        revision = session.get(CatalogObject, REFERENCE_ID).revision
    response = client.post(
        f"/objects/{REFERENCE_ID}",
        data={
            "csrf_token": browser.csrf_token,
            "if_match": f'"rev-{revision}"',
            "primary_name": "Renamed reference",
        },
        follow_redirects=False,
    )
    assert response.status_code == 303, response.text[:500]
    with factory() as session:
        stored = session.get(CatalogObject, REFERENCE_ID)
        assert stored.label == "Renamed reference"
        assert json.loads(stored.data_json) == DATA
