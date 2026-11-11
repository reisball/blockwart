"""Request outcomes must not be confused with persistent operation custody."""
# ruff: noqa: F401, F811
import json

import pytest
from test_credential_safe import VALUE, invoke, safe_client
from test_reference_content_boundary import boundary_state

from blockwart.models import AuditEvent, SafeOperation
from blockwart.services import credential_safe as safe


def states(factory):
    with factory() as session:
        return [json.loads(row.details_json)["state"] for row in
                session.query(AuditEvent).order_by(AuditEvent.id)
                if row.action == "credential_safe_write"]


def test_changed_retry_records_rejection_not_second_completion(
        safe_client, alembic_session_factory):
    client, actors, _ = safe_client
    command = dict(action="write", cas=0, fields={"token": VALUE})
    assert invoke(client, actors, "writer", **command).status_code == 200
    assert invoke(client, actors, "writer", **{**command,
                  "fields": {"token": "synthetic-different"}}).status_code == 409
    outcomes = states(alembic_session_factory)
    assert outcomes.count("succeeded") == 1
    assert outcomes[-1] == "payload_mismatch"
    assert invoke(client, actors, "writer", **command).status_code == 200
    assert states(alembic_session_factory)[-1] == "reconciled"
    assert states(alembic_session_factory).count("succeeded") == 1


def test_unavailable_before_send_is_request_outcome_not_intent(
        safe_client, alembic_session_factory, monkeypatch):
    client, actors, versions = safe_client
    def unavailable(*args):
        raise safe.HTTPException(503, "unavailable")
    monkeypatch.setattr(safe.Bao, "__init__", unavailable)
    assert invoke(client, actors, "writer", action="write", cas=0,
                  fields={"token": VALUE}).status_code == 503
    assert states(alembic_session_factory)[-1] == "unavailable"
    with alembic_session_factory() as session:
        assert session.query(SafeOperation).one().state == "intent"
    assert not versions


def test_malformed_dispatched_response_has_uncertain_outcome(
        safe_client, alembic_session_factory, monkeypatch):
    client, actors, versions = safe_client
    original = safe.Bao.request
    def malformed(self, method, path, body=None):
        result = original(self, method, path, body)
        return {"data": {}} if method == "POST" else result
    monkeypatch.setattr(safe.Bao, "request", malformed)
    assert invoke(client, actors, "writer", action="write", cas=0,
                  fields={"token": VALUE}).status_code == 503
    assert len(versions) == 1
    assert states(alembic_session_factory)[-1] == "uncertain"
    with alembic_session_factory() as session:
        assert session.query(SafeOperation).one().state == "dispatched"


def test_denial_digests_caller_identity(safe_client, alembic_session_factory):
    client, actors, _ = safe_client
    caller_id = "a" * 64
    assert invoke(client, actors, "reader", action="write", cas=0,
                  fields={"token": VALUE}, operation_id=caller_id).status_code == 403
    with alembic_session_factory() as session:
        audit = session.query(AuditEvent).filter_by(action="credential_safe_write").one()
        details = json.loads(audit.details_json)
        assert details["state"] == "denied"
        assert len(details["operation_id"]) == 64
        assert details["operation_id"] != caller_id
        assert caller_id not in audit.details_json
        assert VALUE not in audit.details_json


@pytest.mark.parametrize("winner_state", ["dispatched", "succeeded"])
def test_claim_loser_has_own_outcome(safe_client, alembic_session_factory,
                                     monkeypatch, winner_state):
    client, actors, versions = safe_client
    def competing_winner(self, method, path, body=None):
        with alembic_session_factory() as session:
            row = session.query(SafeOperation).one()
            row.state = winner_state
            row.result_version = 1 if winner_state == "succeeded" else None
            session.commit()
        self.before_mutation()
        raise AssertionError("loser reached backend POST")
    monkeypatch.setattr(safe.Bao, "request", competing_winner)
    assert invoke(client, actors, "writer", action="write", cas=0,
                  fields={"token": VALUE}).status_code == 409
    assert states(alembic_session_factory)[-1] == "claim_lost"
    assert not versions


def test_concurrent_reconciliation_records_completion_once(
        safe_client, alembic_session_factory, monkeypatch):
    client, actors, _ = safe_client
    original_request = safe.Bao.request
    def lost(self, method, path, body=None):
        result = original_request(self, method, path, body)
        if method == "POST":
            raise safe.HTTPException(503, "unavailable")
        return result
    monkeypatch.setattr(safe.Bao, "request", lost)
    command = dict(action="write", cas=0, fields={"token": VALUE})
    assert invoke(client, actors, "writer", **command).status_code == 503
    original_reconcile = safe._reconcile
    def competing_finish(backend, locator, row):
        result = original_reconcile(backend, locator, row)
        with alembic_session_factory() as session:
            safe._finish(session, row.id, result[0], result[1])
        return result
    monkeypatch.setattr(safe, "_reconcile", competing_finish)
    assert invoke(client, actors, "writer", **command).status_code == 200
    assert states(alembic_session_factory).count("succeeded") == 1
