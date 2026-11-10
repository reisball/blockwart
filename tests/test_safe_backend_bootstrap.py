"""Durable bootstrap state and fail-closed recovery with synthetic fixtures."""
import json
import os
from types import SimpleNamespace

import pytest

from blockwart.cli import safe_backend as backend


def test_control_files_are_private_durable_and_atomically_replaced(tmp_path, monkeypatch):
    monkeypatch.setattr(backend, "ROOT", tmp_path)
    backend.save("broker.json", {"role_id": "synthetic-role"})
    assert json.loads((tmp_path / "broker.json").read_text()) == {"role_id": "synthetic-role"}
    assert os.stat(tmp_path / "broker.json").st_mode & 0o777 == 0o600
    backend.save("broker.json", {"role_id": "replaced"})
    assert backend.load("broker.json") == {"role_id": "replaced"}
    assert not (tmp_path / "broker.json.tmp").exists()


@pytest.mark.parametrize("stage", ["mounting", None])
def test_existing_initialized_state_is_never_reinitialized(tmp_path, monkeypatch, stage):
    monkeypatch.setattr(backend, "ROOT", tmp_path)
    monkeypatch.setattr(backend, "wait_ready",
                        lambda _: {"initialized": True, "sealed": False})
    calls = []
    monkeypatch.setattr(backend, "call", lambda *args, **kwargs: calls.append(args))
    if stage is not None:
        backend.save("root.json", "synthetic-bootstrap-root")
        backend.save("stage.json", stage)
    with pytest.raises(RuntimeError):
        backend.bootstrap(SimpleNamespace())
    assert not calls  # no init, retry of failed first write, fallback, or new mount


def test_runtime_policy_excludes_destructive_backend_operations():
    assert "destroy" not in backend.POLICY
    assert '"delete"' not in backend.POLICY
    assert "sys/" not in backend.POLICY
    assert "auth/approle/" not in backend.POLICY
    assert "blockwart/data/*" in backend.POLICY


def test_pending_auth_is_published_without_exposing_bootstrap_root(tmp_path, monkeypatch):
    from urllib.error import HTTPError

    monkeypatch.setattr(backend, "ROOT", tmp_path)
    (tmp_path / "runtime").mkdir(mode=0o700)
    backend.save("root.json", "synthetic-root")
    backend.save("pending.json", {"role_id": "synthetic-role", "secret_id": "synthetic-id"})
    monkeypatch.setattr(backend, "wait_ready",
                        lambda _: {"initialized": True, "sealed": False})
    called = []

    def request(method, path, body=None, token=None, **kwargs):
        called.append((path, token))
        assert not (tmp_path / "runtime/broker.json").exists()
        if path == "auth/approle/login":
            return {"auth": {"client_token": "synthetic-runtime-token"}}
        if path == "blockwart/data/bootstrap":
            return {"data": {"data": backend.SENTINEL}}
        if token == "synthetic-root":
            raise HTTPError("http://localhost.invalid", 403, "already revoked", {}, None)
        return {}

    monkeypatch.setattr(backend, "call", request)
    assert backend.bootstrap(SimpleNamespace()) is False
    assert not (tmp_path / "root.json").exists()
    assert list((tmp_path / "runtime").iterdir()) == [tmp_path / "runtime/broker.json"]
    assert backend.load("runtime/broker.json")["role_id"] == "synthetic-role"
    assert ("auth/token/revoke-self", "synthetic-root") in called
