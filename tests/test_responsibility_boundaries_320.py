"""REST/MCP responsibility grants cannot become reference-content authority (#320)."""
from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient
from httpx import HTTPStatusError
from sqlalchemy import select

from blockwart.api.deps import get_session
from blockwart.db.session import transaction
from blockwart.main import create_app
from blockwart.mcp.server import ToolInputError, call_tool
from blockwart.models import CatalogObject, ObjectGrant, Relationship
from blockwart.services.access import create_object_grant
from blockwart.services.catalog import create_relationship, delete_relationship, get_object
from blockwart.services.identity import create_service_account, issue_service_token

LOCATOR = "private-responsibility-320.example.invalid"
OWNED = {"lxc", "service", "operations"}
REFERENCES = {"auth-ref", "method-ref", "top-ref", "runbook-ref"}
EXCLUDED = {"root", "descriptive", "related", "unrelated"}
HIDDEN_REFERENCES = {"related-ref", "nested-ref", "unrelated-ref", "transitive-ref"}


def _object(identity, kind, **data):
    return CatalogObject(
        id=identity, kind=kind, label=identity, status="active",
        lifecycle="active" if kind in {"host", "system", "service"} else None,
        health="healthy" if kind in {"host", "system", "service"} else None,
        data_json=json.dumps({"schema_version": 1, **data}), provenance_json="{}",
    )


@pytest.fixture
def responsibility_state(alembic_session_factory):
    with alembic_session_factory() as session, transaction(session):
        session.add_all([
            _object("root", "host"),
            _object("lxc", "system", auth={
                "credential_references": ["credential_reference:auth-ref"],
            }),
            _object("service", "service", access_methods=[{
                "type": "ssh", "auth_mode": "key",
                "credential_references": ["credential_reference:method-ref"],
            }], credential_references=["credential_reference:top-ref"],
                arbitrary={"credential_references": ["credential_reference:nested-ref"]}),
            _object("operations", "runbook", runbook_status="draft", approval_required=False,
                    credential_references=["credential_reference:runbook-ref"]),
            _object("descriptive", "runbook", runbook_status="draft", approval_required=False),
            _object("related", "service"),
            _object("unrelated", "service",
                    credential_references=["credential_reference:unrelated-ref"]),
        ])
        for identity in REFERENCES | HIDDEN_REFERENCES:
            session.add(_object(
                identity, "credential_reference", provider="vaultwarden",
                reference={"name": LOCATOR, "path": f"/private/{identity}"},
                secret_value_stored=False,
                **({"credential_references": ["credential_reference:transitive-ref"]}
                   if identity == "auth-ref" else {}),
            ))
        session.flush()
        for source, relation, target in [
            ("host:root", "hosts", "system:lxc"),
            ("system:lxc", "hosts", "service:service"),
            ("runbook:operations", "operations_runbook_for", "service:service"),
            ("runbook:descriptive", "documents", "service:service"),
            ("service:service", "related_to", "service:related"),
            ("service:service", "related_to", "credential_reference:related-ref"),
        ]:
            create_relationship(session, from_ref=source, relation_type=relation, to_ref=target)
        principals = {
            name: create_service_account(session, login=f"responsibility.{name}", display_name=name)
            for name in ("steward", "responsible", "candidate")
        }
        # Independent coverage isolates scope/delegation failures from last-owner protection.
        for identity in OWNED | REFERENCES | EXCLUDED | HIDDEN_REFERENCES:
            create_object_grant(session, principal_id=principals["steward"].id,
                                object_id=identity, role="owner", scope="self")
        grant = create_object_grant(
            session, principal_id=principals["responsible"].id,
            object_id="lxc", role="owner", scope="responsibility",
        )
        return {
            "principals": {name: principal.id for name, principal in principals.items()},
            "tokens": {name: issue_service_token(session, principal_id=principal.id,
                                                  name="boundary-test").value
                       for name, principal in principals.items()},
            "grant_id": grant.id,
        }


@pytest.fixture
def responsibility_client(alembic_session_factory, responsibility_state):
    app = create_app()

    def override_session():
        with alembic_session_factory() as session:
            yield session

    app.dependency_overrides[get_session] = override_session
    with TestClient(app) as client:
        yield client


@pytest.fixture(params=["rest", "mcp"])
def boundary(request, responsibility_client, responsibility_state):
    """Use the real API policy for both REST and MCP's injected HTTP adapter."""
    def invoke(tool, args, *, actor="responsible"):
        auth = {"Authorization": f"Bearer {responsibility_state['tokens'][actor]}"}
        responses = []

        def requester(method, path, body, headers):
            response = responsibility_client.request(
                method, path, json=body, headers={**headers, **auth},
            )
            responses.append(response)
            if request.param == "mcp":
                response.raise_for_status()
            return response.json()

        def fetcher(path, params):
            response = responsibility_client.get(path, params=params, headers=auth)
            responses.append(response)
            if request.param == "mcp":
                response.raise_for_status()
            return response.json()

        if request.param == "mcp":
            try:
                result = call_tool(f"blockwart.{tool}", args, requester=requester, fetcher=fetcher)
            except HTTPStatusError as exc:
                assert exc.response is responses[-1]
                return exc.response
            payload = json.loads(result["content"][0]["text"])
            if tool == "get_object_context":
                assert payload["objects"] == [responses[-1].json()]
                assert payload["count"] == 1
            else:
                assert payload == responses[-1].json()
            return responses[-1]

        path = f"/api/v1/objects/{args['object_id']}"
        headers = {"If-Match": args["if_match"]} if "if_match" in args else {}
        if tool == "get_object_context":
            fetcher(path, {})
        elif tool == "get_object_access":
            fetcher(f"{path}/access", {})
        elif tool == "preview_grant_scope":
            fetcher(f"{path}/access/preview", {"scope": args["scope"], "role": args["role"]})
        elif tool == "update_object":
            requester("PUT", path, args["object"], headers)
        elif tool in {"create_grant", "update_grant"}:
            body = {key: args[key] for key in ("role", "scope")}
            if tool == "create_grant":
                body["principal_id"] = args["principal_id"]
                requester("POST", f"{path}/access/grants", body, headers)
            else:
                requester("PUT", f"{path}/access/grants/{args['grant_id']}", body, headers)
        elif tool == "create_relationship":
            body = {key: args[key] for key in ("from_ref", "relation_type", "to_ref")}
            requester("POST", f"{path}/relationships", body, headers)
        else:
            raise AssertionError(f"Unsupported boundary test tool: {tool}")
        return responses[-1]

    return invoke


def _update_args(session, identity, **updates):
    current = get_object(session, identity)
    payload = current.model_dump(mode="json", include={
        "id", "kind", "label", "status", "lifecycle", "health", "summary", "data", "provenance",
    })
    payload.update(updates)
    return {"object_id": identity, "object": payload,
            "if_match": f'"rev-{session.get(CatalogObject, identity).revision}"'}


def _etag(session, identity):
    return f'"rev-{session.get(CatalogObject, identity).revision}"'


def test_owner_preview_lists_only_responsibility_objects(boundary):
    preview = boundary("preview_grant_scope", {
        "object_id": "lxc", "role": "owner", "scope": "responsibility",
    })
    assert preview.status_code == 200, preview.text
    assert preview.json()["role"] == "owner"
    assert {row["id"] for row in preview.json()["affected_objects"]} == OWNED
    assert "manage_access" in preview.json()["permissions"]
    assert not any(identity in preview.text for identity in REFERENCES | HIDDEN_REFERENCES)


@pytest.mark.parametrize("identity", sorted(OWNED))
def test_responsibility_owner_really_edits_lxc_service_and_operating_runbook(
    alembic_session_factory, boundary, identity,
):
    with alembic_session_factory() as session:
        args = _update_args(session, identity, summary=f"Edited through boundary: {identity}")
    response = boundary("update_object", args)
    assert response.status_code == 200, response.text
    with alembic_session_factory() as session:
        assert get_object(session, identity).summary == args["object"]["summary"]
        assert _etag(session, identity) == response.json()["etag"]


def test_documents_related_to_and_uncovered_objects_never_gain_access(
    alembic_session_factory, boundary,
):
    for identity in EXCLUDED | HIDDEN_REFERENCES:
        assert boundary("get_object_context", {"object_id": identity}).status_code == 404
        with alembic_session_factory() as session:
            args = _update_args(session, identity, summary="Must not be written")
            before = session.get(CatalogObject, identity).revision
        denied = boundary("update_object", args)
        assert denied.status_code == 404, denied.text
        with alembic_session_factory() as session:
            assert session.get(CatalogObject, identity).revision == before
            assert get_object(session, identity).summary != "Must not be written"


def test_credential_metadata_is_readable_but_locator_content_is_stripped(boundary):
    for identity in REFERENCES:
        response = boundary("get_object_context", {"object_id": identity})
        assert response.status_code == 200, response.text
        assert LOCATOR not in response.text
        assert f"/private/{identity}" not in response.text
        assert response.json()["data"]["provider"] == "vaultwarden"
        assert "reference" not in response.json()["data"]
        assert set(response.json()["capabilities"]) == {"discover", "read"}


def test_derived_reference_access_cannot_write_content_metadata_or_delegate(
    alembic_session_factory, boundary, responsibility_state,
):
    identity = "auth-ref"
    with alembic_session_factory() as session:
        content_args = _update_args(session, identity)
        content_args["object"]["data"]["reference"] = {"name": "replacement.invalid"}
        metadata_args = _update_args(session, identity, summary="Must not be written")
        etag = _etag(session, identity)
        revision = session.get(CatalogObject, identity).revision
    for args in (content_args, metadata_args):
        denied = boundary("update_object", args)
        assert denied.status_code == 403, denied.text
    for role in ("owner", "reference_content_reader", "reference_content_editor", "viewer"):
        denied = boundary("create_grant", {
            "object_id": identity, "if_match": etag,
            "principal_id": responsibility_state["principals"]["responsible"],
            "role": role, "scope": "self",
        })
        assert denied.status_code == 403, denied.text
    preview = boundary("preview_grant_scope", {
        "object_id": identity, "role": "owner", "scope": "self",
    })
    assert preview.status_code == 403, preview.text
    with alembic_session_factory() as session:
        assert session.get(CatalogObject, identity).revision == revision
        assert get_object(session, identity).data["reference"]["name"] == LOCATOR
        assert not session.scalar(select(ObjectGrant).where(
            ObjectGrant.principal_id == responsibility_state["principals"]["responsible"],
            ObjectGrant.object_id == identity,
        ))


@pytest.mark.parametrize("identity", ["root", "lxc", "service"])
def test_responsibility_grant_can_be_created_on_operational_anchors(
    alembic_session_factory, boundary, responsibility_state, identity,
):
    with alembic_session_factory() as session:
        etag = _etag(session, identity)
    response = boundary("create_grant", {
        "object_id": identity, "if_match": etag,
        "principal_id": responsibility_state["principals"]["candidate"],
        "role": "owner", "scope": "responsibility",
    }, actor="steward")
    assert response.status_code == 201, response.text
    assert response.json()["grant"]["scope"] == "responsibility"
    edited_id = "operations" if identity != "service" else "service"
    with alembic_session_factory() as session:
        args = _update_args(session, edited_id, summary="New responsible principal can edit")
    edited = boundary("update_object", args, actor="candidate")
    assert edited.status_code == 200, edited.text


@pytest.mark.parametrize("scope,reachable", [("self", {"lxc"}), ("subtree", {"lxc", "service"})])
def test_legacy_scopes_do_not_acquire_runbooks_or_credential_metadata(
    alembic_session_factory, boundary, responsibility_state, scope, reachable,
):
    with alembic_session_factory() as session:
        etag = _etag(session, "lxc")
    response = boundary("create_grant", {
        "object_id": "lxc", "if_match": etag,
        "principal_id": responsibility_state["principals"]["candidate"],
        "role": "owner", "scope": scope,
    }, actor="steward")
    assert response.status_code == 201, response.text
    for identity in OWNED | REFERENCES:
        read = boundary("get_object_context", {"object_id": identity}, actor="candidate")
        assert read.status_code == (200 if identity in reachable else 404), read.text


@pytest.mark.parametrize("identity,role", [
    ("lxc", "viewer"), ("service", "editor"), ("root", "creator"),
    ("lxc", "access_manager"), ("auth-ref", "reference_content_reader"),
    ("operations", "owner"), ("auth-ref", "owner"),
])
def test_invalid_responsibility_preview_create_and_update_are_write_free(
    alembic_session_factory, boundary, responsibility_state, identity, role,
):
    with alembic_session_factory() as session, transaction(session):
        grant = create_object_grant(
            session, principal_id=responsibility_state["principals"]["candidate"],
            object_id=identity, role="viewer", scope="self",
        )
        grant_id = grant.id
        etag = _etag(session, identity)
        revision = session.get(CatalogObject, identity).revision
        before = session.scalars(select(ObjectGrant.id)).all()
    common = {"object_id": identity, "role": role, "scope": "responsibility"}
    for tool, extra in [
        ("preview_grant_scope", {}),
        ("create_grant", {"if_match": etag,
                          "principal_id": responsibility_state["principals"]["candidate"]}),
        ("update_grant", {"if_match": etag, "grant_id": grant_id}),
    ]:
        response = boundary(tool, {**common, **extra}, actor="steward")
        assert response.status_code == 409, response.text
        with alembic_session_factory() as session:
            assert session.get(CatalogObject, identity).revision == revision
            assert session.scalars(select(ObjectGrant.id)).all() == before
            assert session.get(ObjectGrant, grant_id).scope == "self"
            assert session.get(ObjectGrant, grant_id).role == "viewer"


def test_operating_runbook_cannot_capture_a_second_responsibility_target(
    alembic_session_factory, boundary,
):
    with alembic_session_factory() as session:
        etag = _etag(session, "operations")
        before = session.scalars(select(Relationship.id)).all()
    response = boundary("create_relationship", {
        "object_id": "operations", "if_match": etag,
        "from_ref": "runbook:operations", "relation_type": "operations_runbook_for",
        "to_ref": "service:related",
    }, actor="steward")
    assert response.status_code == 409, response.text
    assert response.json()["error"]["code"] == "conflict"
    assert "responsible target" in response.json()["error"]["message"]
    with alembic_session_factory() as session:
        assert session.scalars(select(Relationship.id)).all() == before
        assert _etag(session, "operations") == etag


def test_access_view_preserves_owner_provenance_without_owning_credential_references(
    boundary, responsibility_state,
):
    for identity, role, inherited_owners in (("operations", "owner", 1), ("auth-ref", "viewer", 0)):
        response = boundary("get_object_access", {"object_id": identity}, actor="steward")
        assert response.status_code == 200, response.text
        payload = response.json()
        actor_id = responsibility_state["principals"]["responsible"]
        actor = next(entry for entry in payload["effective_access"]
                     if entry["principal"]["id"] == actor_id)
        assert actor["sources"] == [{
            "grant_id": responsibility_state["grant_id"], "anchor_object_id": "lxc",
            "anchor_object_kind": "system", "anchor_object_label": "lxc", "role": role,
            "scope": "responsibility", "direct": False,
        }]
        assert payload["owner_coverage"]["inherited_active_owner_grants"] == inherited_owners
        if role == "viewer":
            assert set(actor["permissions"]) == {"discover", "read"}


def test_unknown_scope_is_rejected_by_rest_and_mcp_without_a_grant_write(
    alembic_session_factory, responsibility_client, responsibility_state,
):
    with alembic_session_factory() as session:
        revision = session.get(CatalogObject, "lxc").revision
        before = session.scalars(select(ObjectGrant.id)).all()
    args = {
        "object_id": "lxc", "role": "owner", "scope": "responsibilty",
        "principal_id": responsibility_state["principals"]["candidate"],
        "if_match": f'"rev-{revision}"',
    }
    response = responsibility_client.post("/api/v1/objects/lxc/access/grants", json={
        key: args[key] for key in ("role", "scope", "principal_id")
    }, headers={"If-Match": args["if_match"],
                "Authorization": f"Bearer {responsibility_state['tokens']['steward']}"})
    assert response.status_code == 422, response.text

    def unexpected_request(*args, **kwargs):
        raise AssertionError("An unknown MCP scope must be rejected before HTTP")

    with pytest.raises(ToolInputError):
        call_tool("blockwart.create_grant", args, requester=unexpected_request)
    with alembic_session_factory() as session:
        assert session.get(CatalogObject, "lxc").revision == revision
        assert session.scalars(select(ObjectGrant.id)).all() == before


@pytest.mark.parametrize("identity,kind", [("root", "host"), ("lxc", "system")])
def test_operating_runbook_inherits_responsibility_from_host_or_system_target(
    alembic_session_factory, boundary, responsibility_state, identity, kind,
):
    with alembic_session_factory() as session, transaction(session):
        old = session.scalar(select(Relationship).where(
            Relationship.relation_type == "operations_runbook_for",
        ))
        delete_relationship(session, old.id)
        runbook_etag = _etag(session, "operations")
    linked = boundary("create_relationship", {
        "object_id": "operations", "if_match": runbook_etag,
        "from_ref": "runbook:operations", "relation_type": "operations_runbook_for",
        "to_ref": f"{kind}:{identity}",
    }, actor="steward")
    assert linked.status_code == 200, linked.text
    with alembic_session_factory() as session:
        etag = _etag(session, identity)
    granted = boundary("create_grant", {
        "object_id": identity, "if_match": etag,
        "principal_id": responsibility_state["principals"]["candidate"],
        "role": "owner", "scope": "responsibility",
    }, actor="steward")
    assert granted.status_code == 201, granted.text
    with alembic_session_factory() as session:
        args = _update_args(session, "operations", summary=f"Operations responsibility from {kind}")
    edited = boundary("update_object", args, actor="candidate")
    assert edited.status_code == 200, edited.text
    with alembic_session_factory() as session:
        assert get_object(session, "operations").summary == args["object"]["summary"]
