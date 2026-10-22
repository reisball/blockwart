"""Valid JSON scalars/arrays are invalid catalog form documents. Refs #270."""

import json

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from test_catalog_root_creation import root_client, root_state  # noqa: F401

from blockwart.models import AuditEvent, CatalogObject, IdempotencyRecord
from blockwart.ui.security import AUTH_CSRF_COOKIE_NAME, AUTH_SESSION_COOKIE_NAME


@pytest.mark.parametrize("value", [[], [1], None, 42, "text", True, False])
@pytest.mark.parametrize("operation", ["create", "update"])
def test_nonobject_json_is_a_controlled_form_error_without_writes(
    root_client,  # noqa: F811
    root_state,  # noqa: F811
    value,
    operation,
):
    browser = root_state["owner_session"]
    with TestClient(root_client.app, raise_server_exceptions=False) as client:
        client.cookies.set(AUTH_SESSION_COOKIE_NAME, browser.value)
        client.cookies.set(AUTH_CSRF_COOKIE_NAME, browser.csrf_token)
        with root_state["session_factory"]() as session:
            original = session.get(CatalogObject, "existing-object")
            revision = original.revision
            before = (
                session.scalar(select(func.count(AuditEvent.id))),
                session.scalar(select(func.count(IdempotencyRecord.id))),
            )
        fields = {
            "csrf_token": browser.csrf_token,
            "object_id": "json-shape-child",
            "kind": "service" if operation == "create" else "host",
            "label": "Shape test",
            "data_json": json.dumps(value),
            "relation_target_ref": "host:existing-object",
            "idempotency_key": "shape-test-key-01",
            "if_match": f'"rev-{revision}"',
        }
        path = "/objects" if operation == "create" else "/objects/existing-object"
        response = client.post(path, data=fields, follow_redirects=False)
        assert response.status_code == 422, response.text[:300]
        assert "must be a JSON object" in response.text
        with root_state["session_factory"]() as session:
            assert session.get(CatalogObject, "json-shape-child") is None
            assert session.get(CatalogObject, "existing-object").revision == revision
            assert (
                session.scalar(select(func.count(AuditEvent.id))),
                session.scalar(select(func.count(IdempotencyRecord.id))),
            ) == before


@pytest.mark.parametrize("operation", ["create", "update"])
def test_valid_json_object_still_works(root_client, root_state, operation):  # noqa: F811
    browser = root_state["owner_session"]
    root_client.cookies.set(AUTH_SESSION_COOKIE_NAME, browser.value)
    root_client.cookies.set(AUTH_CSRF_COOKIE_NAME, browser.csrf_token)
    fields = {
        "csrf_token": browser.csrf_token,
        "object_id": "valid-json-child",
        "kind": "service" if operation == "create" else "host",
        "label": "Valid JSON",
        "data_json": '{"schema_version":1}',
        "relation_target_ref": "host:existing-object",
        "idempotency_key": "valid-json-key-01",
        "if_match": '"rev-1"',
    }
    path = "/objects" if operation == "create" else "/objects/existing-object"
    with root_state["session_factory"]() as session:
        fields["if_match"] = f'"rev-{session.get(CatalogObject, "existing-object").revision}"'
    response = root_client.post(path, data=fields, follow_redirects=False)
    assert response.status_code == 303, response.text[:300]
