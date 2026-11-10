"""Synthetic regression tests for dedicated safe transport and rights."""

import json

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from test_reference_content_boundary import (  # noqa: F401
    REF_ID,
    boundary_state,
    document,
)

from blockwart.api.deps import get_session
from blockwart.db.session import transaction
from blockwart.main import create_app
from blockwart.mcp.server import call_tool
from blockwart.models import AuditEvent, CatalogObject, ObjectGrant
from blockwart.services.catalog import upsert_object
from blockwart.services.credential_safe import Bao

VALUE = "synthetic-safe-only-335"


@pytest.fixture
def safe_client(alembic_session_factory, boundary_state, monkeypatch):  # noqa: F811
    versions = []

    def request(_self, method, path, body=None):
        if "/metadata/" in path:
            return {"data": {"current_version": len(versions),
                             "versions": {str(i): {} for i in range(1, len(versions) + 1)}}}
        if method == "POST":
            if body["options"]["cas"] != len(versions):
                raise HTTPException(409, "Safe version conflict")
            versions.append(body["data"])
            return {"data": {"version": len(versions)}}
        version = int(path.split("=")[1]) if "=" in path else len(versions)
        if not 1 <= version <= len(versions):
            raise HTTPException(404, "Safe version not found")
        return {"data": {"data": versions[version - 1], "metadata": {"version": version}}}

    monkeypatch.setattr(Bao, "__init__", lambda self, settings: None)
    monkeypatch.setattr(Bao, "request", request)
    with alembic_session_factory() as session, transaction(session):
        upsert_object(session, document(data={
            "schema_version": 1, "provider": "safe", "reference": {},
            "secret_value_stored": False,
        }))
    app = create_app()

    def dependency():
        with alembic_session_factory() as session:
            yield session

    app.dependency_overrides[get_session] = dependency
    with TestClient(app) as client:
        yield client, boundary_state, versions


def invoke(client, actors, name, **command):
    return client.post(f"/api/v1/objects/{REF_ID}/safe", json=command,
                       headers={"Authorization": "Bearer " + actors[name][1]})


@pytest.mark.parametrize("name", ["viewer", "editor", "discoverer", "catalog-viewer"])
@pytest.mark.parametrize("action", ["read", "history", "write", "restore", "delete", "undelete"])
def test_metadata_grants_never_reach_backend(safe_client, name, action):
    client, actors, versions = safe_client
    result = invoke(client, actors, name, action=action, fields={"token": VALUE}, cas=0, version=1)
    assert result.status_code == 403
    assert not versions
    assert VALUE not in result.text


def test_history_restore_cas_and_write_only(safe_client, alembic_session_factory):
    client, actors, versions = safe_client
    assert invoke(client, actors, "writer", action="write", cas=0,
                  fields={"multiline": VALUE + "\nline2"}, preset="key").json() == {"version": 1}
    assert invoke(client, actors, "writer", action="read").status_code == 403
    assert invoke(client, actors, "writer", action="history").status_code == 403
    assert invoke(client, actors, "reader", action="write", cas=1,
                  fields={"token": VALUE}).status_code == 403
    read = invoke(client, actors, "reader", action="read")
    assert read.status_code == 200 and VALUE in read.text
    assert "no-store" in read.headers["Cache-Control"]
    assert invoke(client, actors, "writer", action="delete", cas=1).json() == {"version": 2}
    assert invoke(client, actors, "reader", action="read").status_code == 404
    assert VALUE in invoke(client, actors, "reader", action="read", version=1).text
    assert invoke(client, actors, "writer", action="undelete", cas=2, version=1).json() == {
        "version": 3,
    }
    assert invoke(client, actors, "writer", action="restore", cas=2, version=1).status_code == 409
    assert invoke(client, actors, "writer", action="delete").status_code == 428
    assert len(versions) == 3
    assert invoke(client, actors, "reader", action="history").json()["current_version"] == 3
    with alembic_session_factory() as session:
        assert VALUE not in session.get(CatalogObject, REF_ID).data_json
        assert all(VALUE not in (row.details_json or "") for row in session.query(AuditEvent))
        # Immediate grant revocation also protects historical reads.
        session.query(ObjectGrant).filter_by(principal_id=actors["reader"][0]).delete()
        session.commit()
    assert invoke(client, actors, "reader", action="read", version=1).status_code in {403, 404}


def test_no_prefetch_validation_leak_and_no_get(safe_client):
    client, actors, versions = safe_client
    response = invoke(client, actors, "writer", action="write", cas=0,
                      fields={"token": {"bad": VALUE}})
    assert response.status_code == 422 and VALUE not in response.text
    assert client.get(f"/api/v1/objects/{REF_ID}/safe").status_code == 405
    assert not versions


def test_mcp_uses_dedicated_post_transport():
    calls = []
    result = call_tool("blockwart.credential_safe",
                       {"object_id": "test/id", "action": "write", "cas": 0,
                        "fields": {"token": VALUE}},
                       requester=lambda method, path, body, headers:
                       calls.append((method, path, body)) or {"version": 1})
    assert json.loads(result["content"][0]["text"]) == {"version": 1}
    assert calls[0][:2] == ("POST", "/api/v1/objects/test%2Fid/safe")
    assert calls[0][2]["fields"] == {"token": VALUE}


def test_unavailable_backend_keeps_catalog_usable(safe_client, monkeypatch):
    client, actors, _ = safe_client

    def down(*args, **kwargs):
        raise HTTPException(503, "Credential safe unavailable")

    monkeypatch.setattr(Bao, "request", down)
    assert invoke(client, actors, "reader", action="read").status_code == 503
    headers = {"Authorization": "Bearer " + actors["reader"][1]}
    assert client.get(f"/api/v1/objects/{REF_ID}", headers=headers).status_code == 200


def test_safe_locator_cannot_be_supplied_or_swapped(safe_client, monkeypatch):
    client, actors, _ = safe_client
    requests = []

    def capture(self, method, path, body=None):
        requests.append(path)
        return {"data": {"version": 1}}

    monkeypatch.setattr(Bao, "request", capture)
    rejected = invoke(client, actors, "owner", action="write", cas=0,
                      fields={"token": VALUE}, locator="another-entry")
    assert rejected.status_code == 422 and not requests
    saved = invoke(client, actors, "owner", action="write", cas=0, fields={"token": VALUE})
    assert saved.status_code == 200
    assert requests[0].startswith("blockwart/data/")
    assert len(requests[0].removeprefix("blockwart/data/")) == 64
    assert REF_ID not in requests[0] and VALUE not in requests[0]


def test_provider_switch_requires_content_write(
    alembic_session_factory, boundary_state,  # noqa: F811
):
    from test_reference_content_boundary import write_for

    from blockwart.services.commands import CommandAuthorizationDenied, update_catalog_object

    with alembic_session_factory() as session, transaction(session):
        row = session.get(CatalogObject, REF_ID)
        payload = document(data={"schema_version": 1, "provider": "safe",
                                 "secret_value_stored": False})
        with pytest.raises(CommandAuthorizationDenied):
            update_catalog_object(session, write_for(session, boundary_state, "editor"),
                                  object_id=REF_ID, payload=payload,
                                  expected_revision=row.revision)
