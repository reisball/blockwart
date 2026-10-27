"""End-to-end field authorization for existing reference locators (#315)."""
from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from blockwart.api.deps import get_session
from blockwart.db.session import transaction
from blockwart.domain.auth import CatalogRole, GrantScope, Role
from blockwart.domain.search import SearchQuery
from blockwart.main import create_app
from blockwart.mcp.server import call_tool
from blockwart.models import AuditEvent, CatalogObject, ObjectGrant, Principal
from blockwart.schemas.catalog import CatalogObjectIn
from blockwart.services.access import create_object_grant
from blockwart.services.activity import query_activity_page
from blockwart.services.agent import get_agent_object_context, search_agent_objects
from blockwart.services.catalog import get_object, upsert_object
from blockwart.services.commands import (
    CommandAuthorizationDenied,
    CommandConflict,
    CommandPreconditionFailed,
    WriteContext,
    preview_catalog_object_update,
    update_catalog_object,
)
from blockwart.services.identity import (
    create_service_account,
    issue_service_token,
    principal_context,
)
from blockwart.services.policy import policy_for_principal
from blockwart.services.queries import (
    get_catalog_object,
    query_catalog_browse,
    query_catalog_detail,
)
from blockwart.services.read_access import ReadAccess

LOCATOR = "restricted-locator-315.example.invalid"
NEW_LOCATOR = "replacement-locator-315.example.invalid"
REF_ID = "boundary-reference"


def document(**updates):
    body = dict(id=REF_ID, kind="credential_reference", label="Reference", data={
        "schema_version": 1, "provider": "vaultwarden", "reference": {
            "name": LOCATOR, "path": "/restricted-315", "key": "account", "item_hint": LOCATOR,
        }, "secret_value_stored": False,
    })
    body.update(updates)
    return CatalogObjectIn(**body)


@pytest.fixture
def boundary_state(alembic_session_factory):
    actors = {}
    with alembic_session_factory() as session, transaction(session):
        upsert_object(session, document())
        for name, role in {
            "discoverer": Role.DISCOVERER, "viewer": Role.VIEWER, "editor": Role.EDITOR,
            "reader": Role.REFERENCE_CONTENT_READER, "writer": Role.REFERENCE_CONTENT_EDITOR,
            "owner": Role.OWNER,
        }.items():
            principal = create_service_account(session, login=f"boundary.{name}", display_name=name)
            create_object_grant(session, principal_id=principal.id, object_id=REF_ID,
                                role=role, scope=GrantScope.SELF)
            token = issue_service_token(session, principal_id=principal.id, name="api").value
            actors[name] = (principal.id, token)
        for name, catalog_role in {
            "catalog-viewer": CatalogRole.CATALOG_VIEWER,
            "catalog-owner": CatalogRole.CATALOG_OWNER,
        }.items():
            principal = create_service_account(session, login=f"boundary.{name}", display_name=name,
                                               catalog_role=catalog_role)
            token = issue_service_token(session, principal_id=principal.id, name="api").value
            actors[name] = (principal.id, token)
    return actors


def access_for(session, actors, name):
    principal_id = actors[name][0]
    return ReadAccess(principal_context(session.get(Principal, principal_id)),
                      policy_for_principal(session, principal_id))


def write_for(session, actors, name):
    return WriteContext.from_read_access(access_for(session, actors, name), channel="api")


def payload_from(session, *, reference=None, metadata=False):
    current = get_object(session, REF_ID)
    body = current.model_dump(include={
        "id", "kind", "label", "status", "summary", "data", "provenance",
    })
    body["data"].pop("reference", None)
    if reference is not None:
        body["data"]["reference"] = reference
    if metadata:
        body["summary"] = "updated metadata"
    return CatalogObjectIn.model_validate(body)


@pytest.mark.parametrize("name,has_content", [
    ("discoverer", False), ("viewer", False), ("editor", False), ("writer", False),
    ("catalog-viewer", False), ("reader", True), ("owner", True), ("catalog-owner", True),
])
def test_reads_and_search_use_same_content_boundary(
    alembic_session_factory, boundary_state, name, has_content,
):
    with alembic_session_factory() as session:
        access = access_for(session, boundary_state, name)
        catalog = get_catalog_object(session, REF_ID, access)
        agent = get_agent_object_context(session, REF_ID, access)
        assert (LOCATOR in catalog.model_dump_json()) is has_content
        assert (LOCATOR in agent.model_dump_json()) is has_content
        search = search_agent_objects(session, access, search=SearchQuery(query=LOCATOR))
        # Agent search intentionally has a closed index: locator fields were
        # never searchable. Do not widen it as part of this permission change.
        assert not search
        browse = query_catalog_browse(session, access)
        projected = next(item for item in browse.all_objects if item.id == REF_ID)
        assert (LOCATOR in projected.model_dump_json()) is has_content


@pytest.mark.parametrize("name", ["editor", "owner", "catalog-owner"])
def test_metadata_update_preserves_omitted_locator(
    alembic_session_factory, boundary_state, name,
):
    with alembic_session_factory() as session, transaction(session):
        revision = session.get(CatalogObject, REF_ID).revision
        result = update_catalog_object(session, write_for(session, boundary_state, name),
            object_id=REF_ID, payload=payload_from(session, metadata=True),
            expected_revision=revision)
        assert get_object(session, REF_ID).data["reference"]["name"] == LOCATOR
        assert result.catalog_object.summary == "updated metadata"
        assert ("reference" in result.catalog_object.data) is (name != "editor")


@pytest.mark.parametrize("name", ["editor", "viewer", "reader", "catalog-viewer"])
def test_unauthorized_reference_replacement_is_denied(
    alembic_session_factory, boundary_state, name,
):
    with alembic_session_factory() as session:
        revision = session.get(CatalogObject, REF_ID).revision
        payload = payload_from(session, reference={"name": NEW_LOCATOR})
        for command in (preview_catalog_object_update, update_catalog_object):
            with pytest.raises(CommandAuthorizationDenied):
                command(session, write_for(session, boundary_state, name), object_id=REF_ID,
                        payload=payload, expected_revision=revision)
        assert get_object(session, REF_ID).data["reference"]["name"] == LOCATOR
        assert session.get(CatalogObject, REF_ID).revision == revision


def test_write_only_updates_redact_response_preview_and_history(
    alembic_session_factory, boundary_state,
):
    with alembic_session_factory() as session, transaction(session):
        context = write_for(session, boundary_state, "writer")
        payload = payload_from(session, reference={"name": NEW_LOCATOR})
        revision = session.get(CatalogObject, REF_ID).revision
        preview = preview_catalog_object_update(session, context, object_id=REF_ID,
                                                payload=payload, expected_revision=revision)
        rendered = json.dumps([entry.as_json() for entry in preview.diff])
        assert LOCATOR not in rendered and NEW_LOCATOR not in rendered
        other = preview_catalog_object_update(session, context, object_id=REF_ID,
            payload=payload_from(session, reference={"name": "another.example.invalid"}),
            expected_revision=revision)
        assert preview.preview_digest == other.preview_digest
        result = update_catalog_object(session, context, object_id=REF_ID,
                                       payload=payload, expected_revision=revision)
        assert "reference" not in result.catalog_object.data
        assert get_object(session, REF_ID).data["reference"] == {"name": NEW_LOCATOR}
        detail = query_catalog_detail(
            session, REF_ID, access_for(session, boundary_state, "writer"),
        )
        rendered_history = json.dumps(detail.audit_events)
        assert LOCATOR not in rendered_history and NEW_LOCATOR not in rendered_history
        activity = query_activity_page(session, access_for(session, boundary_state, "writer"))
        assert NEW_LOCATOR not in str(activity)
        owner_history = query_catalog_detail(
            session, REF_ID, access_for(session, boundary_state, "owner"),
        )
        assert NEW_LOCATOR in json.dumps(owner_history.audit_events)


def test_write_only_cannot_change_metadata_and_stale_etag_is_rejected(
    alembic_session_factory, boundary_state,
):
    with alembic_session_factory() as session:
        context = write_for(session, boundary_state, "writer")
        revision = session.get(CatalogObject, REF_ID).revision
        with pytest.raises(CommandAuthorizationDenied):
            update_catalog_object(session, context, object_id=REF_ID,
                payload=payload_from(session, reference={}, metadata=True),
                expected_revision=revision)
        with pytest.raises(CommandPreconditionFailed):
            update_catalog_object(session, context, object_id=REF_ID,
                payload=payload_from(session, reference={}), expected_revision=revision + 1)
        assert get_object(session, REF_ID).data["reference"]["name"] == LOCATOR


def test_revocation_applies_to_old_context_and_current_reads(
    alembic_session_factory, boundary_state,
):
    with alembic_session_factory() as session:
        context = write_for(session, boundary_state, "writer")
        grant = session.scalar(select(ObjectGrant).where(
            ObjectGrant.principal_id == boundary_state["writer"][0],
        ))
        grant.role = Role.VIEWER
        session.commit()
        with pytest.raises(CommandAuthorizationDenied):
            update_catalog_object(session, context, object_id=REF_ID,
                payload=payload_from(session, reference={}),
                expected_revision=session.get(CatalogObject, REF_ID).revision)


def test_historical_legacy_summary_is_not_an_alternate_locator_channel(
    alembic_session_factory, boundary_state,
):
    with alembic_session_factory() as session, transaction(session):
        session.add(AuditEvent(object_id=REF_ID, action="legacy_update", actor="legacy",
                               summary=f"Old path {LOCATOR}", details_json="{}"))
        session.flush()
        access = access_for(session, boundary_state, "viewer")
        assert LOCATOR not in json.dumps(query_catalog_detail(session, REF_ID, access).audit_events)
        assert LOCATOR not in str(query_activity_page(session, access))


@pytest.fixture
def boundary_client(alembic_session_factory, boundary_state):
    app = create_app()
    def override():
        with alembic_session_factory() as session:
            yield session
    app.dependency_overrides[get_session] = override
    with TestClient(app) as client:
        yield client


@pytest.mark.parametrize("name,has_content", [
    ("viewer", False), ("editor", False), ("writer", False), ("reader", True), ("owner", True),
])
def test_rest_catalog_and_agent_read_parity(boundary_client, boundary_state, name, has_content):
    headers = {"Authorization": f"Bearer {boundary_state[name][1]}"}
    for path in (f"/api/objects/{REF_ID}", f"/api/v1/objects/{REF_ID}"):
        response = boundary_client.get(path, headers=headers)
        assert response.status_code == 200, response.text
        assert (LOCATOR in response.text) is has_content


def test_rest_write_only_put_and_metadata_put_preserve_boundary(
    alembic_session_factory, boundary_client, boundary_state,
):
    with alembic_session_factory() as session:
        payload = payload_from(session, reference={"name": NEW_LOCATOR}).model_dump(mode="json")
        revision = session.get(CatalogObject, REF_ID).revision
    response = boundary_client.put(f"/api/v1/objects/{REF_ID}", json=payload, headers={
        "Authorization": f"Bearer {boundary_state['writer'][1]}", "If-Match": f'"rev-{revision}"',
    })
    assert response.status_code == 200, response.text
    assert "reference" not in response.json()["catalog_object"]["data"]
    assert NEW_LOCATOR not in response.text
    with alembic_session_factory() as session:
        payload = payload_from(session, metadata=True).model_dump(mode="json")
        revision = session.get(CatalogObject, REF_ID).revision
    response = boundary_client.put(f"/api/v1/objects/{REF_ID}", json=payload, headers={
        "Authorization": f"Bearer {boundary_state['editor'][1]}", "If-Match": f'"rev-{revision}"',
    })
    assert response.status_code == 200, response.text
    assert NEW_LOCATOR not in response.text
    with alembic_session_factory() as session:
        assert get_object(session, REF_ID).data["reference"]["name"] == NEW_LOCATOR


@pytest.mark.parametrize("name,has_content", [("writer", False), ("reader", True)])
def test_mcp_direct_batch_and_context_reads_apply_content_boundary(
    boundary_client, boundary_state, name, has_content,
):
    def requester(method, path, body, headers):
        response = boundary_client.request(method, path, json=body, headers={
            **headers, "Authorization": f"Bearer {boundary_state[name][1]}",
        })
        response.raise_for_status()
        return response.json()

    def fetcher(path, params):
        response = boundary_client.get(path, params={
            key: value for key, value in params.items() if value is not None
        }, headers={
            "Authorization": f"Bearer {boundary_state[name][1]}",
        })
        response.raise_for_status()
        return response.json()

    for tool, args in (
        ("blockwart.get_object_context", {"object_id": REF_ID}),
        ("blockwart.get_object_contexts", {"object_ids": [REF_ID]}),
        ("blockwart.get_context", {"q": "Reference"}),
    ):
        result = call_tool(tool, args, fetcher=fetcher, requester=requester)
        assert (LOCATOR in json.dumps(result)) is has_content


def test_mcp_write_only_uses_shared_put_policy(
    alembic_session_factory, boundary_client, boundary_state,
):
    with alembic_session_factory() as session:
        payload = payload_from(session, reference={"name": NEW_LOCATOR}).model_dump(mode="json")
        revision = session.get(CatalogObject, REF_ID).revision

    def requester(method, path, body, headers):
        response = boundary_client.request(method, path, json=body, headers={
            **headers, "Authorization": f"Bearer {boundary_state['writer'][1]}",
        })
        response.raise_for_status()
        return response.json()

    result = call_tool("blockwart.update_object", {
        "object_id": REF_ID, "if_match": f'"rev-{revision}"', "object": payload,
    }, requester=requester)
    assert NEW_LOCATOR not in json.dumps(result)
    with alembic_session_factory() as session:
        assert get_object(session, REF_ID).data["reference"]["name"] == NEW_LOCATOR


def test_unclassified_historical_snapshot_data_is_not_disclosed(
    alembic_session_factory, boundary_state,
):
    with alembic_session_factory() as session, transaction(session):
        session.add(AuditEvent(
            object_id=REF_ID, action="update", actor="legacy", summary="update",
            details_json=json.dumps({
                "event": "update", "version": 1,
                "before": {"id": REF_ID, "data": LOCATOR},
                "after": {"id": REF_ID, "data": {"reference": {"path": LOCATOR}}},
            }),
        ))
        session.flush()
        access = access_for(session, boundary_state, "viewer")
        assert LOCATOR not in json.dumps(query_catalog_detail(session, REF_ID, access).audit_events)


def test_metadata_editor_cannot_declassify_reference_by_kind_conversion(
    alembic_session_factory, boundary_state,
):
    with alembic_session_factory() as session:
        revision = session.get(CatalogObject, REF_ID).revision
        payload = CatalogObjectIn(id=REF_ID, kind="service", label="Reference",
                                  data={"schema_version": 1})
        with pytest.raises(CommandAuthorizationDenied):
            preview_catalog_object_update(
                session, write_for(session, boundary_state, "editor"),
                object_id=REF_ID, payload=payload, expected_revision=revision,
            )


def test_historical_reference_kind_is_protected_after_conversion(
    alembic_session_factory, boundary_state,
):
    with alembic_session_factory() as session, transaction(session):
        session.add(AuditEvent(
            object_id=REF_ID, action="update", actor="legacy", summary="update",
            details_json=json.dumps({
                "event": "update", "version": 1,
                "before": {"id": REF_ID, "kind": "credential_reference", "data": {
                    "reference": {"path": LOCATOR},
                }},
                "changes": [{"field": "reference.path", "old": LOCATOR, "new": "",
                             "value_change": True}],
            }),
        ))
        row = session.get(CatalogObject, REF_ID)
        row.kind = "service"
        row.lifecycle = "active"
        row.health = "healthy"
        row.data_json = '{"schema_version": 1}'
        session.flush()
        access = access_for(session, boundary_state, "viewer")
        assert LOCATOR not in json.dumps(query_catalog_detail(session, REF_ID, access).audit_events)
        assert LOCATOR not in str(query_activity_page(session, access))



def test_owner_conversion_discards_locator_but_keeps_history_protected(
    alembic_session_factory, boundary_state,
):
    with alembic_session_factory() as session, transaction(session):
        revision = session.get(CatalogObject, REF_ID).revision
        result = update_catalog_object(
            session, write_for(session, boundary_state, "owner"), object_id=REF_ID,
            payload=CatalogObjectIn(id=REF_ID, kind="service", label="Converted reference",
                                    data={"schema_version": 1}),
            expected_revision=revision,
        )
        assert result.catalog_object.kind == "service"
        assert "reference" not in result.catalog_object.data
        viewer = access_for(session, boundary_state, "viewer")
        assert LOCATOR not in json.dumps(query_catalog_detail(session, REF_ID, viewer).audit_events)
        assert LOCATOR not in str(query_activity_page(session, viewer))
        assert LOCATOR in json.dumps(query_catalog_detail(
            session, REF_ID, access_for(session, boundary_state, "owner"),
        ).audit_events)


def test_kind_conversion_cannot_keep_locator_under_unprotected_kind(
    alembic_session_factory, boundary_state,
):
    with alembic_session_factory() as session:
        revision = session.get(CatalogObject, REF_ID).revision
        with pytest.raises(CommandConflict) as error:
            preview_catalog_object_update(
                session, write_for(session, boundary_state, "owner"), object_id=REF_ID,
                payload=CatalogObjectIn(id=REF_ID, kind="service", label="Reference",
                    data={"schema_version": 1, "reference": {"name": LOCATOR}}),
                expected_revision=revision,
            )
        assert error.value.code == "reference_content_requires_reference_kind"


def test_conversion_into_reference_requires_content_update_authority(
    alembic_session_factory, boundary_state,
):
    with alembic_session_factory() as session, transaction(session):
        row = session.get(CatalogObject, REF_ID)
        row.kind = "service"
        row.lifecycle = "active"
        row.health = "healthy"
        row.data_json = '{"schema_version":1}'
        session.flush()
        with pytest.raises(CommandAuthorizationDenied):
            preview_catalog_object_update(
                session, write_for(session, boundary_state, "editor"), object_id=REF_ID,
                payload=document(), expected_revision=row.revision,
            )


@pytest.mark.parametrize("stored_reference", [{"path": LOCATOR}, {}, None])
def test_blind_replacement_previews_do_not_reveal_equality_or_presence(
    alembic_session_factory, boundary_state, stored_reference,
):
    with alembic_session_factory() as session, transaction(session):
        row = session.get(CatalogObject, REF_ID)
        data = json.loads(row.data_json)
        if stored_reference is None:
            data.pop("reference", None)
        else:
            data["reference"] = stored_reference
        row.data_json = json.dumps(data)
        session.flush()
        revision = row.revision
        context = write_for(session, boundary_state, "writer")
        previews = [preview_catalog_object_update(
            session, context, object_id=REF_ID,
            payload=payload_from(session, reference=guess), expected_revision=revision,
        ) for guess in ({"path": LOCATOR}, {"path": NEW_LOCATOR}, {})]
        signatures = [(
            preview.changed, preview.expected_result_revision, preview.expected_result_etag,
            [entry.as_json() for entry in preview.diff], preview.diff_truncated,
            preview.diff_digest, preview.preview_digest,
        ) for preview in previews]
        assert signatures[0] == signatures[1] == signatures[2]
        assert previews[0].changed is True
        assert previews[0].expected_result_revision == revision + 1
        assert row.revision == revision


def test_blind_equal_replacement_advances_revision_like_other_replacements(
    alembic_session_factory, boundary_state,
):
    with alembic_session_factory() as session, transaction(session):
        row = session.get(CatalogObject, REF_ID)
        reference = json.loads(row.data_json)["reference"]
        revision = row.revision
        result = update_catalog_object(
            session, write_for(session, boundary_state, "writer"), object_id=REF_ID,
            payload=payload_from(session, reference=reference), expected_revision=revision,
        )
        assert result.changed is True
        assert result.catalog_object.revision == revision + 1
        assert "reference" not in result.catalog_object.data


@pytest.mark.parametrize("stored_value,proposed_value", [
    (True, 1), (1, True), (1, 1.0), ({"flags": [True]}, {"flags": [1]}),
])
def test_content_only_writer_cannot_change_metadata_json_types(
    alembic_session_factory, boundary_state, stored_value, proposed_value,
):
    with alembic_session_factory() as session, transaction(session):
        row = session.get(CatalogObject, REF_ID)
        data = json.loads(row.data_json)
        data["custom_metadata"] = {"enabled": stored_value}
        row.data_json = json.dumps(data)
        session.flush()
        stored_json = row.data_json
        revision = row.revision
        payload = payload_from(session, reference={"name": NEW_LOCATOR})
        payload.data["custom_metadata"]["enabled"] = proposed_value
        for command in (preview_catalog_object_update, update_catalog_object):
            with pytest.raises(CommandAuthorizationDenied):
                command(session, write_for(session, boundary_state, "writer"),
                        object_id=REF_ID, payload=payload, expected_revision=revision)
        assert row.data_json == stored_json
        assert row.revision == revision


@pytest.mark.parametrize("legacy_details", [{}, {"version": 1, "event": "legacy"}])
def test_unclassified_legacy_history_remains_protected_after_owner_conversion(
    alembic_session_factory, boundary_state, legacy_details,
):
    with alembic_session_factory() as session, transaction(session):
        session.add(AuditEvent(
            object_id=REF_ID, action="legacy_update", actor="legacy",
            summary=f"Old path {LOCATOR}", details_json=json.dumps(legacy_details),
        ))
        session.flush()
        row = session.get(CatalogObject, REF_ID)
        update_catalog_object(
            session, write_for(session, boundary_state, "owner"), object_id=REF_ID,
            payload=CatalogObjectIn(id=REF_ID, kind="service", label="Converted reference",
                                    data={"schema_version": 1}), expected_revision=row.revision,
        )
        viewer = access_for(session, boundary_state, "viewer")
        assert LOCATOR not in json.dumps(query_catalog_detail(session, REF_ID, viewer).audit_events)
        # The legacy row may be on a page without the later conversion event.
        page = query_activity_page(session, viewer, object_id=REF_ID, limit=1, direction="asc")
        assert LOCATOR not in str(page)
        owner = access_for(session, boundary_state, "owner")
        assert LOCATOR in json.dumps(query_catalog_detail(session, REF_ID, owner).audit_events)


@pytest.mark.parametrize("transport", ["rest", "mcp"])
def test_blind_equal_and_unequal_previews_are_identical_on_transports(
    alembic_session_factory, boundary_client, boundary_state, transport,
):
    with alembic_session_factory() as session:
        row = session.get(CatalogObject, REF_ID)
        revision = row.revision
        reference = json.loads(row.data_json)["reference"]
        payloads = [payload_from(session, reference=guess).model_dump(mode="json")
                    for guess in (reference, {"name": NEW_LOCATOR})]
    headers = {"Authorization": f"Bearer {boundary_state['writer'][1]}"}

    def requester(method, path, body, request_headers):
        response = boundary_client.request(method, path, json=body,
                                           headers={**request_headers, **headers})
        assert response.status_code == 200, response.text
        return response.json()

    results = []
    for payload in payloads:
        if transport == "rest":
            result = requester("POST", f"/api/v1/objects/{REF_ID}/update-preview", payload,
                               {"If-Match": f'"rev-{revision}"'})
        else:
            result = call_tool("blockwart.preview_object_update", {
                "object_id": REF_ID, "if_match": f'"rev-{revision}"', "object": payload,
            }, requester=requester)
        results.append(result)
    assert results[0] == results[1]
    assert LOCATOR not in json.dumps(results)
    with alembic_session_factory() as session:
        assert session.get(CatalogObject, REF_ID).revision == revision


@pytest.mark.parametrize("name", ["writer", "owner"])
def test_content_omission_retains_canonical_noop_for_all_writers(
    alembic_session_factory, boundary_state, name,
):
    with alembic_session_factory() as session, transaction(session):
        revision = session.get(CatalogObject, REF_ID).revision
        payload = payload_from(session)
        context = write_for(session, boundary_state, name)
        preview = preview_catalog_object_update(
            session, context, object_id=REF_ID, payload=payload, expected_revision=revision,
        )
        assert preview.changed is False
        assert preview.diff == []
        assert preview.expected_result_revision == revision
        result = update_catalog_object(session, context, object_id=REF_ID,
                                       payload=payload, expected_revision=revision)
        assert result.changed is False
        assert result.catalog_object.revision == revision


def test_metadata_writer_with_content_read_cannot_change_protected_extension_type(
    alembic_session_factory, boundary_state,
):
    with alembic_session_factory() as session, transaction(session):
        row = session.get(CatalogObject, REF_ID)
        data = json.loads(row.data_json)
        data["reference"]["custom"] = True
        row.data_json = json.dumps(data)
        session.flush()
        create_object_grant(session, principal_id=boundary_state["reader"][0],
                            object_id=REF_ID, role=Role.EDITOR, scope=GrantScope.SELF)
        session.flush()
        proposed_reference = {**data["reference"], "custom": 1}
        payload = payload_from(session, reference=proposed_reference)
        for command in (preview_catalog_object_update, update_catalog_object):
            with pytest.raises(CommandAuthorizationDenied):
                command(session, write_for(session, boundary_state, "reader"), object_id=REF_ID,
                        payload=payload, expected_revision=row.revision)


def test_blind_preview_repair_does_not_expose_unclassifiable_stored_data(
    alembic_session_factory, boundary_state,
):
    with alembic_session_factory() as session, transaction(session):
        row = session.get(CatalogObject, REF_ID)
        row.data_json = json.dumps(LOCATOR)
        session.flush()
        create_object_grant(session, principal_id=boundary_state["writer"][0],
                            object_id=REF_ID, role=Role.EDITOR, scope=GrantScope.SELF)
        session.flush()
        preview = preview_catalog_object_update(
            session, write_for(session, boundary_state, "writer"), object_id=REF_ID,
            payload=document(), expected_revision=row.revision,
        )
        assert preview.changed is True
        assert LOCATOR not in json.dumps([entry.as_json() for entry in preview.diff])
