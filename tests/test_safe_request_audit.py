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


@pytest.mark.parametrize("action", ["restore", "undelete"])
@pytest.mark.parametrize("source_error", ["deleted", "http400"])
def test_definite_source_rejection_is_not_pending(
        safe_client, alembic_session_factory, monkeypatch, action, source_error):
    from types import SimpleNamespace
    from urllib.error import HTTPError

    client, actors, versions = safe_client
    assert invoke(client, actors, "writer", action="write", cas=0,
                  fields={"token": VALUE}).status_code == 200
    assert invoke(client, actors, "writer", action="delete", cas=1).status_code == 200
    if source_error == "http400":
        original = safe.Bao.request
        def reject(request, **kwargs):
            raise HTTPError(request.full_url, 400, "synthetic-source-error", None, None)
        monkeypatch.setattr(safe, "build_opener", lambda *args: SimpleNamespace(open=reject))
        def source_read(self, method, path, body=None):
            if method == "GET":
                self.url = "http://127.0.0.1:1"
                return self.call(method, path, token="synthetic-token")
            return original(self, method, path, body)
        monkeypatch.setattr(safe.Bao, "request", source_read)
    response = invoke(client, actors, "writer", action=action, cas=2,
                      version=2 if source_error == "deleted" else 1)
    assert response.status_code == 409
    assert len(versions) == 2
    with alembic_session_factory() as session:
        row = session.query(SafeOperation).filter_by(action=action).one()
        assert (row.state, row.result_version) == ("intent", None)
        audits = [json.loads(event.details_json) for event in session.query(AuditEvent).order_by(
            AuditEvent.id) if event.action == "credential_safe_" + action]
        assert [event["state"] for event in audits] == ["intent", "rejected"]
        assert VALUE not in json.dumps(audits)


@pytest.mark.parametrize("dispatched", [False, True])
def test_reconciliation_keeps_true_pending_custody(
        safe_client, alembic_session_factory, monkeypatch, dispatched):
    client, actors, versions = safe_client
    original_init, original_request = safe.Bao.__init__, safe.Bao.request
    if dispatched:
        def interrupted(self, method, path, body=None):
            if method == "POST":
                self.before_mutation()
                raise safe.HTTPException(503, "unavailable")
            return original_request(self, method, path, body)
        monkeypatch.setattr(safe.Bao, "request", interrupted)
    else:
        def unavailable(*args):
            raise safe.HTTPException(503, "unavailable")
        monkeypatch.setattr(safe.Bao, "__init__", unavailable)
    operation_id = "e" * 64
    assert invoke(client, actors, "writer", action="write", cas=0, fields={"token": VALUE},
                  operation_id=operation_id).status_code == 503
    assert states(alembic_session_factory)[-1] == ("uncertain" if dispatched else "unavailable")
    monkeypatch.setattr(safe.Bao, "__init__", original_init)
    monkeypatch.setattr(safe.Bao, "request", original_request)
    assert invoke(client, actors, "writer", action="reconcile",
                  operation_id=operation_id).status_code == 409
    with alembic_session_factory() as session:
        row = session.query(SafeOperation).one()
        assert row.state == ("dispatched" if dispatched else "intent")
        event = session.query(AuditEvent).filter_by(action="credential_safe_reconcile").one()
        assert json.loads(event.details_json)["state"] == "pending"
    assert not versions
