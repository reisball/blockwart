"""Finite fault injection for value-free operation custody. Refs #335."""
# ruff: noqa: F811
import json

from fastapi import HTTPException
from sqlalchemy import text
from test_credential_safe import VALUE, invoke, safe_client  # noqa: F401
from test_reference_content_boundary import REF_ID, boundary_state  # noqa: F401

from blockwart.services import credential_safe as safe
from blockwart.services.credential_safe import Bao


def test_lost_write_response_reconciles_without_replay(safe_client, monkeypatch,
                                                       alembic_session_factory):
    client, actors, versions = safe_client
    original = Bao.request
    writes = []
    def lost(self, method, path, body=None):
        result = original(self, method, path, body)
        if method == "POST":
            writes.append(body)
            raise HTTPException(503, "Credential safe unavailable")
        return result
    monkeypatch.setattr(Bao, "request", lost)
    command = dict(action="write", cas=0, fields={"token": VALUE})
    assert invoke(client, actors, "writer", **command).status_code == 503
    retry = invoke(client, actors, "writer", **command)
    assert retry.status_code == 200
    assert retry.json() == {"version": 1}
    assert len(writes) == len(versions) == 1
    with alembic_session_factory() as session:
        rows = session.execute(text("SELECT * FROM safe_operations")).mappings().all()
        assert len(rows) == 1 and rows[0]["state"] == "succeeded"
        assert VALUE not in json.dumps([dict(row) for row in rows])


def test_intent_is_durable_before_backend(safe_client, monkeypatch, alembic_session_factory):
    client, actors, _ = safe_client
    original = Bao.request
    def inspect(self, method, path, body=None):
        if method == "POST":
            with alembic_session_factory() as session:
                assert session.query(safe.SafeOperation).one().state == "intent"
            claim = self.before_mutation
            def inspect_dispatch():
                claim()
                with alembic_session_factory() as session:
                    row = session.execute(text("SELECT * FROM safe_operations")).mappings().one()
                    assert row["state"] == "dispatched"
                    assert body["data"]["operation_id"] == row["id"]
                    assert VALUE not in json.dumps(dict(row))
            self.before_mutation = inspect_dispatch
        return original(self, method, path, body)
    monkeypatch.setattr(Bao, "request", inspect)
    assert invoke(client, actors, "writer", action="write", cas=0,
                  fields={"token": VALUE}).status_code == 200
