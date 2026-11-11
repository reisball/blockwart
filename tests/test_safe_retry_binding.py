"""Retry identity binds backend content without persisting value fingerprints."""
# ruff: noqa: F401, F811
import json

import pytest
from test_credential_safe import VALUE, invoke, safe_client
from test_reference_content_boundary import boundary_state

from blockwart.models import AuditEvent, SafeOperation
from blockwart.services import credential_safe as safe


@pytest.mark.parametrize("lost", [False, True])
@pytest.mark.parametrize("changed", [{"fields": {"password": "different"}}, {"preset": "key"}])
def test_changed_retry_never_reports_success(safe_client, monkeypatch, lost, changed):
    client, actors, versions = safe_client
    original = safe.Bao.request
    def request(self, method, path, body=None):
        result = original(self, method, path, body)
        if lost and method == "POST":
            raise safe.HTTPException(503, "unavailable")
        return result
    monkeypatch.setattr(safe.Bao, "request", request)
    command = dict(action="write", cas=0, fields={"password": VALUE}, preset="login")
    assert invoke(client, actors, "writer", **command).status_code == (503 if lost else 200)
    assert invoke(client, actors, "writer", **{**command, **changed}).status_code == 409
    assert invoke(client, actors, "writer", **command).json() == {"version": 1}
    assert len(versions) == 1


def test_presend_configuration_failure_can_retry(safe_client, monkeypatch,
                                                 alembic_session_factory):
    client, actors, versions = safe_client
    original = safe.Bao.__init__
    def unavailable(*args):
        raise safe.HTTPException(503, "unavailable")
    monkeypatch.setattr(safe.Bao, "__init__", unavailable)
    command = dict(action="write", cas=0, fields={"token": VALUE})
    assert invoke(client, actors, "writer", **command).status_code == 503
    with alembic_session_factory() as session:
        assert session.query(SafeOperation).one().state == "intent"
    monkeypatch.setattr(safe.Bao, "__init__", original)
    assert invoke(client, actors, "writer", **command).json() == {"version": 1}
    assert len(versions) == 1


def test_future_cas_rejection_does_not_poison_legacy_retry(safe_client,
                                                          alembic_session_factory):
    client, actors, versions = safe_client
    assert invoke(client, actors, "writer", action="write", cas=2,
                  fields={"token": VALUE}).status_code == 409
    assert invoke(client, actors, "writer", action="write", cas=2,
                  fields={"token": VALUE}).status_code == 409
    with alembic_session_factory() as session:
        rows = [json.loads(a.details_json) for a in session.query(AuditEvent)
                if a.action == "credential_safe_write"]
        assert rows[-1]["state"] == "conflict"
    for cas in (0, 1, 2):
        assert invoke(client, actors, "writer", action="write", cas=cas,
                      fields={"token": str(cas)}).json() == {"version": cas + 1}
    assert len(versions) == 3


def test_concurrent_admission_is_pending_not_database_outage(safe_client, monkeypatch,
                                                             alembic_session_factory):
    client, actors, versions = safe_client
    original = SafeOperation.__init__
    admitted = []
    def race(self, **kwargs):
        original(self, **kwargs)
        if not admitted:
            admitted.append(True)
            with alembic_session_factory() as session:
                session.add(SafeOperation(**{**kwargs, "state": "dispatched"}))
                session.commit()
    monkeypatch.setattr(SafeOperation, "__init__", race)
    assert invoke(client, actors, "writer", action="write", cas=0,
                  fields={"token": VALUE}).status_code == 409
    assert not versions


def test_caller_identity_cannot_claim_another_actors_legacy_slot(
        safe_client, alembic_session_factory):
    from test_reference_content_boundary import REF_ID

    from blockwart.models import CatalogObject
    client, actors, versions = safe_client
    with alembic_session_factory() as session:
        instance = session.get(CatalogObject, REF_ID).instance_id
    import hashlib
    victim = hashlib.sha256(json.dumps([
        instance, actors["writer"][0], "api", "legacy", "write", 0, None,
    ]).encode()).hexdigest()
    # A co-writer's supplied ID is in a separate actor-scoped namespace.
    assert invoke(client, actors, "owner", action="write", cas=5,
                  fields={"token": "synthetic"}, operation_id=victim).status_code == 409
    assert invoke(client, actors, "writer", action="write", cas=0,
                  fields={"token": VALUE}).json() == {"version": 1}
    assert len(versions) == 1


def test_policy_revoked_during_pending_status_denies_response(
        safe_client, monkeypatch, alembic_session_factory):
    from blockwart.models import ObjectGrant
    client, actors, _ = safe_client
    original = safe.Bao.request
    def interrupted(self, method, path, body=None):
        if method == "POST":
            self.before_mutation()
            raise safe.HTTPException(503, "unavailable")
        with alembic_session_factory() as session:
            session.query(ObjectGrant).filter_by(principal_id=actors["writer"][0]).delete()
            session.commit()
        return original(self, method, path, body)
    monkeypatch.setattr(safe.Bao, "request", interrupted)
    command = dict(action="write", cas=0, fields={"token": VALUE})
    assert invoke(client, actors, "writer", **command).status_code == 503
    assert invoke(client, actors, "writer", **command).status_code in {403, 404}


@pytest.mark.parametrize("extras", [{}, {"fields": {"token": VALUE}}, {"cas": 0},
                                    {"version": 1}, {"preset": "key"}])
def test_reconciliation_requires_only_caller_id(safe_client, extras):
    client, actors, versions = safe_client
    command = dict(action="reconcile", **extras)
    if extras:
        command["operation_id"] = "a" * 64
    assert invoke(client, actors, "writer", **command).status_code == 422
    assert not versions


def test_invalid_operation_id_retains_precise_rest_location(safe_client):
    client, actors, versions = safe_client
    response = invoke(client, actors, "writer", action="write", cas=0,
                      fields={"token": VALUE}, operation_id="NOT-HEX")
    assert response.status_code == 422
    assert response.json()["error"]["details"][0]["location"] == "body.operation_id"
    assert VALUE not in response.text
    assert not versions
