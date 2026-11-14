"""Bounded crash points, authorization and schema-upgrade proofs. Refs #335."""
# ruff: noqa: F401, F811
import json
from uuid import uuid4

import pytest
from sqlalchemy import text
from sqlalchemy.exc import OperationalError
from test_credential_safe import VALUE, invoke, safe_client
from test_reference_content_boundary import REF_ID, boundary_state

from blockwart.models import AuditEvent, ObjectGrant, SafeOperation
from blockwart.services import credential_safe as safe


@pytest.mark.parametrize("point", ["intent", "dispatch", "finish"])
def test_database_failure_never_blindly_replays(safe_client, monkeypatch,
                                                alembic_session_factory, point):
    client, actors, versions = safe_client
    original_commit = safe.Session.commit
    def commit(session):
        rows = [row for row in list(session.new) + list(session.dirty)
                if isinstance(row, SafeOperation)]
        state = {"intent": "intent", "dispatch": "dispatched", "finish": "succeeded"}[point]
        if any(row.state == state for row in rows) or any(
                isinstance(row, AuditEvent) and json.loads(row.details_json or "{}").get(
                    "state") == state for row in session.new):
            raise OperationalError("synthetic", {}, Exception("synthetic"))
        return original_commit(session)
    monkeypatch.setattr(safe.Session, "commit", commit)
    command = dict(action="write", cas=0, fields={"token": VALUE})
    assert invoke(client, actors, "writer", **command).status_code == 503
    assert len(versions) == (1 if point == "finish" else 0)
    monkeypatch.setattr(safe.Session, "commit", original_commit)
    retry = invoke(client, actors, "writer", **command)
    # A failed dispatch commit leaves unsent intent retryable; only committed
    # dispatch is ambiguous and must never be replayed.
    assert retry.status_code == 200 and retry.json() == {"version": 1}
    assert len(versions) == 1


def test_dispatched_interruption_is_pending_until_exact_evidence(safe_client, monkeypatch,
                                                               alembic_session_factory):
    client, actors, versions = safe_client
    original = safe._perform
    def interrupt(backend, *a, **kw):
        backend.before_mutation()
        raise RuntimeError("synthetic interruption after committed dispatch before send")
    monkeypatch.setattr(safe, "_perform", interrupt)
    assert invoke(client, actors, "writer", action="write", cas=0,
                  fields={"token": VALUE}).status_code == 500
    monkeypatch.setattr(safe, "_perform", original)
    retry = invoke(client, actors, "writer", action="write", cas=0, fields={"token": VALUE})
    assert retry.status_code == 409 and not versions
    with alembic_session_factory() as session:
        assert session.query(SafeOperation).one().state == "dispatched"


def test_explicit_operation_reconciliation_is_writer_only_and_never_copies_new_fields(safe_client):
    client, actors, versions = safe_client
    operation_id = uuid4().hex + uuid4().hex
    assert invoke(client, actors, "writer", action="write", cas=0,
                  fields={"token": VALUE}, operation_id=operation_id).status_code == 200
    assert invoke(client, actors, "writer", action="write", cas=0,
                  fields={"token": "changed"}, operation_id=operation_id).status_code == 409
    assert len(versions) == 1 and versions[0]["fields"] == {"token": VALUE}
    assert invoke(client, actors, "writer", action="reconcile",
                  operation_id=operation_id).json() == {"version": 1}
    assert invoke(client, actors, "reader", action="reconcile",
                  operation_id=operation_id).status_code == 403
    assert invoke(client, actors, "writer", action="delete", cas=1,
                  operation_id=operation_id).status_code == 409


def test_post_write_revocation_does_not_erase_completion(safe_client, monkeypatch,
                                                         alembic_session_factory):
    client, actors, versions = safe_client
    original = safe.Bao.request
    def revoke(self, method, path, body=None):
        result = original(self, method, path, body)
        with alembic_session_factory() as session:
            session.query(ObjectGrant).filter_by(principal_id=actors["writer"][0]).delete()
            session.commit()
        return result
    monkeypatch.setattr(safe.Bao, "request", revoke)
    assert invoke(client, actors, "writer", action="write", cas=0,
                  fields={"token": VALUE}).status_code in {403, 404}
    assert len(versions) == 1
    with alembic_session_factory() as session:
        row = session.query(SafeOperation).one()
        assert (row.state, row.result_version) == ("succeeded", 1)


def test_reconciliation_does_not_claim_somebody_elses_version(safe_client, monkeypatch):
    client, actors, versions = safe_client
    original = safe.Bao.request
    def lost(self, method, path, body=None):
        result = original(self, method, path, body)
        if method == "POST":
            versions[0]["operation_id"] = "different"
            raise safe.HTTPException(503, "unavailable")
        return result
    monkeypatch.setattr(safe.Bao, "request", lost)
    command = dict(action="write", cas=0, fields={"token": VALUE})
    assert invoke(client, actors, "writer", **command).status_code == 503
    assert invoke(client, actors, "writer", **command).status_code == 409
    assert len(versions) == 1


def test_failed_audit_commit_recovers_even_after_later_version(safe_client, monkeypatch):
    client, actors, versions = safe_client
    original = safe.add_audit_event
    def audit(*a, **kw):
        if kw.get("details", {}).get("state") == "succeeded":
            raise OperationalError("synthetic", {}, Exception("synthetic"))
        return original(*a, **kw)
    monkeypatch.setattr(safe, "add_audit_event", audit)
    assert invoke(client, actors, "writer", action="write", cas=0,
                  fields={"token": VALUE}).status_code == 503
    monkeypatch.setattr(safe, "add_audit_event", original)
    assert invoke(client, actors, "writer", action="write", cas=1,
                  fields={"token": "later"}).json() == {"version": 2}
    assert invoke(client, actors, "writer", action="write", cas=0,
                  fields={"token": "ignored"}).status_code == 409
    assert invoke(client, actors, "writer", action="write", cas=0,
                  fields={"token": VALUE}).json() == {"version": 1}
    assert len(versions) == 2


def test_additive_migration_has_no_value_columns_or_credential_rewrites(tmp_path):
    from alembic import command
    from sqlalchemy import inspect

    from blockwart.db.migrations import build_alembic_config
    from blockwart.db.session import build_engine
    url = "sqlite:///" + str(tmp_path / "migration.db")
    config = build_alembic_config(url)
    command.upgrade(config, "20261028_0032")
    engine = build_engine(url)
    from sqlalchemy.orm import Session
    from test_reference_content_boundary import document

    from blockwart.db.session import transaction
    from blockwart.services.catalog import upsert_object
    with Session(engine) as session, transaction(session):
        upsert_object(session, document(data={"schema_version": 1, "provider": "safe",
            "reference": {}, "secret_value_stored": False}))
    with engine.connect() as conn:
        before = conn.execute(text("SELECT * FROM catalog_objects")).all()
    command.upgrade(config, "head")
    with engine.connect() as conn:
        assert conn.execute(text("SELECT * FROM catalog_objects")).all() == before
    columns = {column["name"] for column in inspect(engine).get_columns("safe_operations")}
    assert columns == {"id", "actor", "channel", "object_id", "instance_id", "action",
                       "cas", "source_version", "state", "result_version"}
    command.downgrade(config, "20261028_0032")
    assert "safe_operations" not in inspect(engine).get_table_names()
    engine.dispose()


def test_concurrent_same_operation_only_one_dispatches(safe_client, monkeypatch):
    import threading
    from concurrent.futures import ThreadPoolExecutor
    client, actors, versions = safe_client
    entered, release = threading.Event(), threading.Event()
    original = safe.Bao.request
    def delayed(self, method, path, body=None):
        if method == "POST":
            self.before_mutation()
            self.before_mutation = None
            entered.set()
            assert release.wait(timeout=10)
        return original(self, method, path, body)
    monkeypatch.setattr(safe.Bao, "request", delayed)
    command = dict(action="write", cas=0, fields={"token": VALUE})
    with ThreadPoolExecutor(max_workers=1) as pool:
        first = pool.submit(invoke, client, actors, "writer", **command)
        try:
            assert entered.wait(timeout=10)
            assert invoke(client, actors, "writer", **command).status_code == 409
            assert not versions
        finally:
            release.set()
        assert first.result(timeout=10).json() == {"version": 1}
    assert invoke(client, actors, "writer", **command).json() == {"version": 1}
    assert len(versions) == 1


def test_nonempty_custody_blocks_downgrade(safe_client, alembic_database):
    from alembic import command

    from blockwart.db.migrations import build_alembic_config
    client, actors, _ = safe_client
    assert invoke(client, actors, "writer", action="write", cas=0,
                  fields={"token": VALUE}).status_code == 200
    with pytest.raises(RuntimeError, match="Retain Safe operation custody"):
        command.downgrade(build_alembic_config(alembic_database.database_url), "20261028_0032")
