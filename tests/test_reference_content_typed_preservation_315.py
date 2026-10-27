"""Path-scoped typed-reference preservation must not validate hidden guesses (#315)."""

from __future__ import annotations

import json

import pytest
from sqlalchemy import select
from test_reference_content_boundary import (
    REF_ID,
    access_for,
    payload_from,
    write_for,
)
from test_reference_content_boundary import (
    boundary_client as boundary_client,
)
from test_reference_content_boundary import (
    boundary_state as boundary_state,
)

from blockwart.db.session import transaction
from blockwart.domain.auth import GrantScope, Permission, Role
from blockwart.mcp.server import call_tool
from blockwart.models import AuditEvent, CatalogObject
from blockwart.schemas.catalog import CatalogObjectIn
from blockwart.services.access import create_object_grant
from blockwart.services.catalog import get_object, upsert_object
from blockwart.services.commands import (
    CommandError,
    CommandNotFound,
    preview_catalog_object_update,
    update_catalog_object,
)

HIDDEN_REFERENCE = "service:hidden-a"
OTHER_HIDDEN_REFERENCE = "service:hidden-b"
COMMANDS = [preview_catalog_object_update, update_catalog_object]


@pytest.fixture
def typed_state(alembic_session_factory, boundary_state):
    """Both typed targets exist, but none of the reference's scoped actors can read them."""
    with alembic_session_factory() as session, transaction(session):
        for object_id in ("hidden-a", "hidden-b"):
            upsert_object(
                session,
                CatalogObjectIn(
                    id=object_id,
                    kind="service",
                    label=object_id,
                    data={"schema_version": 1},
                ),
            )
        row = session.get(CatalogObject, REF_ID)
        data = json.loads(row.data_json)
        data["reference"] = {"name": HIDDEN_REFERENCE}
        row.data_json = json.dumps(data)
        session.flush()
        for actor in ("writer", "editor", "owner"):
            policy = access_for(session, boundary_state, actor).policy
            assert not policy.can(Permission.READ, "hidden-a")
            assert not policy.can(Permission.READ, "hidden-b")
    return boundary_state


def _guess_payload(session, actor, guess):
    if actor == "writer":
        return payload_from(session, reference={"name": guess})
    payload = payload_from(session)
    payload.data["custom_metadata"] = {"candidate": guess}
    return payload


def _stored_state(session):
    """Include raw object timestamps/revision and audit rows in the no-write contract."""
    session.flush()
    objects = session.execute(select(CatalogObject.__table__).order_by(CatalogObject.id)).all()
    audit = session.execute(select(AuditEvent.__table__).order_by(AuditEvent.id)).all()
    return objects, audit


@pytest.mark.parametrize("actor", ["writer", "editor"])
@pytest.mark.parametrize("command", COMMANDS, ids=["preview", "update"])
def test_hidden_typed_equal_and_wrong_guesses_share_concealed_outcome(
    alembic_session_factory,
    typed_state,
    actor,
    command,
):
    with alembic_session_factory() as session:
        revision = session.get(CatalogObject, REF_ID).revision
        outcomes = []
        unchanged = []
        for guess in (HIDDEN_REFERENCE, OTHER_HIDDEN_REFERENCE):
            # Roll back each attempt so a vulnerable successful PUT cannot make
            # the second guess fail only because its revision became stale.
            with session.begin_nested() as attempt:
                before = _stored_state(session)
                try:
                    command(
                        session,
                        write_for(session, typed_state, actor),
                        object_id=REF_ID,
                        payload=_guess_payload(session, actor, guess),
                        expected_revision=revision,
                    )
                except CommandError as error:
                    outcomes.append((type(error), str(error)))
                else:
                    outcomes.append((None, "accepted"))
                unchanged.append(_stored_state(session) == before)
                attempt.rollback()
        assert outcomes == [(CommandNotFound, "reference target not found")] * 2
        assert all(unchanged), "A concealed-target rejection must not write objects or audit rows"


@pytest.mark.parametrize("actor", ["writer", "editor"])
@pytest.mark.parametrize("transport", ["rest", "mcp"])
@pytest.mark.parametrize("operation", ["preview", "update"])
@pytest.mark.parametrize(
    "guess", [HIDDEN_REFERENCE, OTHER_HIDDEN_REFERENCE], ids=["equal", "wrong"]
)
def test_transports_conceal_hidden_typed_guesses_without_writes(
    alembic_session_factory,
    boundary_client,
    typed_state,
    actor,
    transport,
    operation,
    guess,
):
    with alembic_session_factory() as session:
        revision = session.get(CatalogObject, REF_ID).revision
        payload = _guess_payload(session, actor, guess).model_dump(mode="json")
        before = _stored_state(session)
    headers = {"Authorization": f"Bearer {typed_state[actor][1]}"}
    responses = []

    def requester(method, path, body, request_headers):
        response = boundary_client.request(
            method,
            path,
            json=body,
            headers={**request_headers, **headers},
        )
        responses.append((response.status_code, response.json()))
        return response.json()

    if transport == "rest":
        requester(
            "POST" if operation == "preview" else "PUT",
            f"/api/v1/objects/{REF_ID}" + ("/update-preview" if operation == "preview" else ""),
            payload,
            {"If-Match": f'"rev-{revision}"'},
        )
    else:
        call_tool(
            "blockwart.preview_object_update"
            if operation == "preview"
            else "blockwart.update_object",
            {"object_id": REF_ID, "if_match": f'"rev-{revision}"', "object": payload},
            requester=requester,
        )
    assert len(responses) == 1
    status, body = responses[0]
    assert status == 404, body
    assert body["error"]["code"] == "not_found"
    assert body["error"]["message"] == "Resource not found"
    assert HIDDEN_REFERENCE not in json.dumps(body)
    assert OTHER_HIDDEN_REFERENCE not in json.dumps(body)
    with alembic_session_factory() as session:
        assert _stored_state(session) == before


@pytest.mark.parametrize("actor", ["writer", "editor"])
def test_omitted_hidden_typed_content_is_preserved_without_target_read(
    alembic_session_factory,
    typed_state,
    actor,
):
    with alembic_session_factory() as session, transaction(session):
        revision = session.get(CatalogObject, REF_ID).revision
        payload = payload_from(session, metadata=actor == "editor")
        assert "reference" not in payload.data
        context = write_for(session, typed_state, actor)
        before_preview = _stored_state(session)
        preview = preview_catalog_object_update(
            session,
            context,
            object_id=REF_ID,
            payload=payload,
            expected_revision=revision,
        )
        assert _stored_state(session) == before_preview
        assert preview.changed is (actor == "editor")
        result = update_catalog_object(
            session,
            context,
            object_id=REF_ID,
            payload=payload,
            expected_revision=revision,
        )
        assert result.changed is (actor == "editor")
        assert get_object(session, REF_ID).data["reference"] == {"name": HIDDEN_REFERENCE}
        assert "reference" not in result.catalog_object.data


@pytest.mark.parametrize("actor", ["editor", "owner"])
def test_unchanged_same_path_metadata_remains_preservable_without_target_read(
    alembic_session_factory,
    typed_state,
    actor,
):
    with alembic_session_factory() as session, transaction(session):
        row = session.get(CatalogObject, REF_ID)
        data = json.loads(row.data_json)
        data["custom_metadata"] = {
            "retained": HIDDEN_REFERENCE,
            "nested": [{"target": OTHER_HIDDEN_REFERENCE}],
        }
        row.data_json = json.dumps(data)
        session.flush()
        session.refresh(row)  # The database trigger advances revisions after raw fixture edits.
        revision = row.revision
        payload = payload_from(session, metadata=True)
        context = write_for(session, typed_state, actor)
        preview = preview_catalog_object_update(
            session,
            context,
            object_id=REF_ID,
            payload=payload,
            expected_revision=revision,
        )
        assert preview.changed is True
        result = update_catalog_object(
            session,
            context,
            object_id=REF_ID,
            payload=payload,
            expected_revision=revision,
        )
        assert result.catalog_object.summary == "updated metadata"
        assert get_object(session, REF_ID).data == data


@pytest.mark.parametrize("command", COMMANDS, ids=["preview", "update"])
@pytest.mark.parametrize(
    "stored,proposed",
    [
        ({"retained": HIDDEN_REFERENCE}, {"relocated": HIDDEN_REFERENCE}),
        (
            {"retained": HIDDEN_REFERENCE},
            {"retained": HIDDEN_REFERENCE, "candidate": HIDDEN_REFERENCE},
        ),
        ({"nested": {"retained": HIDDEN_REFERENCE}}, {"nested": {"relocated": HIDDEN_REFERENCE}}),
        (
            {"targets": [HIDDEN_REFERENCE, OTHER_HIDDEN_REFERENCE]},
            {"targets": [OTHER_HIDDEN_REFERENCE, HIDDEN_REFERENCE]},
        ),
    ],
    ids=["move-key", "duplicate-key", "move-nested-key", "swap-list-indices"],
)
def test_preservation_does_not_authorize_relocation_or_new_occurrences(
    alembic_session_factory,
    typed_state,
    command,
    stored,
    proposed,
):
    with alembic_session_factory() as session, transaction(session):
        row = session.get(CatalogObject, REF_ID)
        data = json.loads(row.data_json)
        data["custom_metadata"] = stored
        row.data_json = json.dumps(data)
        session.flush()
        session.refresh(row)  # The database trigger advances revisions after raw fixture edits.
        revision = row.revision
        payload = payload_from(session)
        payload.data["custom_metadata"] = proposed
        before = _stored_state(session)
        with pytest.raises(CommandNotFound, match="^reference target not found$"):
            command(
                session,
                write_for(session, typed_state, "editor"),
                object_id=REF_ID,
                payload=payload,
                expected_revision=revision,
            )
        assert _stored_state(session) == before


def test_content_reader_may_echo_same_path_typed_reference_without_target_read(
    alembic_session_factory,
    typed_state,
):
    with alembic_session_factory() as session:
        revision = session.get(CatalogObject, REF_ID).revision
        payload = payload_from(session, reference={"name": HIDDEN_REFERENCE})
        context = write_for(session, typed_state, "owner")
        before = _stored_state(session)
        preview = preview_catalog_object_update(
            session,
            context,
            object_id=REF_ID,
            payload=payload,
            expected_revision=revision,
        )
        result = update_catalog_object(
            session,
            context,
            object_id=REF_ID,
            payload=payload,
            expected_revision=revision,
        )
        assert preview.changed is result.changed is False
        assert _stored_state(session) == before


@pytest.mark.parametrize("actor", ["writer", "editor"])
@pytest.mark.parametrize(
    "guess", [HIDDEN_REFERENCE, OTHER_HIDDEN_REFERENCE], ids=["equal", "wrong"]
)
def test_explicit_typed_proposal_succeeds_after_target_read_is_granted(
    alembic_session_factory,
    typed_state,
    actor,
    guess,
):
    with alembic_session_factory() as session, transaction(session):
        create_object_grant(
            session,
            principal_id=typed_state[actor][0],
            object_id=guess.split(":", 1)[1],
            role=Role.VIEWER,
            scope=GrantScope.SELF,
        )
        session.flush()
        revision = session.get(CatalogObject, REF_ID).revision
        context = write_for(session, typed_state, actor)
        payload = _guess_payload(session, actor, guess)
        preview = preview_catalog_object_update(
            session,
            context,
            object_id=REF_ID,
            payload=payload,
            expected_revision=revision,
        )
        assert preview.changed is True
        result = update_catalog_object(
            session,
            context,
            object_id=REF_ID,
            payload=payload,
            expected_revision=revision,
        )
        assert result.changed is True
        assert "reference" not in result.catalog_object.data
        persisted = get_object(session, REF_ID).data
        if actor == "writer":
            assert persisted["reference"] == {"name": guess}
        else:
            assert persisted["custom_metadata"] == {"candidate": guess}
            assert persisted["reference"] == {"name": HIDDEN_REFERENCE}
