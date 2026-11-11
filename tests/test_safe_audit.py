"""Native audit configuration and lifecycle tests; no live services."""
from pathlib import Path
from types import SimpleNamespace

import pytest

from blockwart.cli import safe_backend as backend


def test_native_redacted_audit_is_declarative():
    config = Path("docs/credential-safe.hcl").read_text()
    assert 'audit "file" "blockwart"' in config
    assert 'log_raw = "false"' in config
    assert 'file_path = "/openbao/audit/audit.json"' in config


def test_correlation_header_provisioning_is_fixed_and_value_free(monkeypatch, tmp_path):
    calls = []
    monkeypatch.setattr(backend, "ROOT", tmp_path)
    monkeypatch.setattr(backend, "call", lambda *a, **k: calls.append(a) or {})
    backend.configure_audit("synthetic-admin")
    assert calls == [("POST", "sys/config/auditing/request-headers/x-blockwart-operation",
                      {"hmac": False}, "synthetic-admin")]
    assert backend.load("audit.json") == {"version": 1}


def test_rotation_failure_is_visible_and_fail_closed(monkeypatch, tmp_path):
    audit = tmp_path / "audit.json"
    audit.write_text("synthetic")
    monkeypatch.setattr(backend, "AUDIT_FILE", audit)
    monkeypatch.setattr(backend, "AUDIT_MAX_BYTES", 1)
    def fail(*a, **kw):
        raise OSError("sensitive system error")
    monkeypatch.setattr(backend.subprocess, "run", fail)
    with pytest.raises(RuntimeError, match="safe_backend_audit_rotation_failed"):
        backend.rotate_audit(SimpleNamespace(send_signal=lambda _: None))


def test_existing_instance_requires_explicit_header_provisioning(monkeypatch, tmp_path):
    monkeypatch.setattr(backend, "ROOT", tmp_path)
    (tmp_path / "runtime").mkdir()
    (tmp_path / "runtime/broker.json").write_text('{"role_id":"synthetic"}')
    monkeypatch.setattr(backend, "wait_ready", lambda _: {"initialized": True, "sealed": False})
    def unexpected(*a, **kw):
        raise AssertionError("existing auth or data must not be rewritten")
    monkeypatch.setattr(backend, "call", unexpected)
    with pytest.raises(RuntimeError, match="safe_backend_audit_configuration_required"):
        backend.bootstrap(SimpleNamespace())


@pytest.mark.parametrize("arguments", [["--configure-audit"], ["--unexpected"],
                                      ["--configure-audit", "token", "extra"]])
def test_malformed_helper_arguments_never_start_backend(monkeypatch, tmp_path, capsys, arguments):
    monkeypatch.setattr(backend.sys, "argv", ["supervisor.py", *arguments])
    root = tmp_path / "not-created"
    monkeypatch.setattr(backend, "ROOT", root)
    def unexpected(*args, **kwargs):
        raise AssertionError("invalid CLI attempted to start backend")
    monkeypatch.setattr(backend.subprocess, "Popen", unexpected)
    with pytest.raises(SystemExit) as error:
        backend.main()
    assert error.value.code == 2
    assert capsys.readouterr().out.strip() == "safe_backend_invalid_arguments"
    assert not root.exists()
