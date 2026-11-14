"""Fresh-only operator authority: focused unit and disposable pinned-Raft proof."""
import base64
import os
import shutil
import socket
import subprocess
import time
from pathlib import Path
from urllib.error import HTTPError

import pytest

from blockwart.cli import safe_backend as backend


def test_maintenance_policy_has_only_fixed_operator_paths():
    assert 'path "blockwart/' not in backend.MAINTENANCE_POLICY
    assert 'path "sys/policies/' not in backend.MAINTENANCE_POLICY
    assert 'path "sys/auth' not in backend.MAINTENANCE_POLICY
    assert 'path "auth/token/create' not in backend.MAINTENANCE_POLICY
    assert 'path "sys/config/auditing/request-headers/*"' not in backend.MAINTENANCE_POLICY
    assert backend.MAINTENANCE_ROLE["token_explicit_max_ttl"] == 900
    overlay = Path("compose.safe.yaml").read_text()
    app_mounts = overlay.split("  credential-safe:")[0]
    assert "/runtime:/safe-control:ro" in app_mounts
    assert "/operator" not in app_mounts


@pytest.mark.parametrize("unsafe", ["directory-mode", "directory-link", "file-mode", "file-link"])
def test_operator_files_fail_closed(tmp_path, monkeypatch, unsafe):
    monkeypatch.setattr(backend, "ROOT", tmp_path)
    operator = tmp_path / "operator"
    if unsafe == "directory-link":
        target = tmp_path / "elsewhere"
        target.mkdir(mode=0o700)
        operator.symlink_to(target)
    else:
        operator.mkdir(mode=0o700)
        if unsafe == "directory-mode":
            operator.chmod(0o755)
        elif unsafe == "file-mode":
            (operator / "maintenance.json").touch()
            (operator / "maintenance.json").chmod(0o644)
        else:
            (operator / "maintenance.json").symlink_to(tmp_path / "missing")
    with pytest.raises(RuntimeError, match="unsafe"):
        backend.maintenance_credentials()


def test_existing_controls_do_not_acquire_operator_credentials(tmp_path, monkeypatch):
    monkeypatch.setattr(backend, "ROOT", tmp_path)
    def forbidden(*args, **kwargs):
        raise AssertionError("existing control must not be provisioned")
    monkeypatch.setattr(backend, "call", forbidden)
    backend.provision_maintenance("synthetic")
    backend.finalize_maintenance("synthetic")
    assert not (tmp_path / "operator").exists()


@pytest.fixture
def raft(tmp_path, monkeypatch):
    binary = os.environ.get("BLOCKWART_TEST_BAO_BINARY")
    if not binary:
        pytest.skip("explicit disposable OpenBao executable not configured")
    assert "v2.7.2 " in subprocess.check_output([binary, "version"], text=True)
    sockets = [socket.socket(), socket.socket()]
    for sock in sockets:
        sock.bind(("127.0.0.1", 0))
    port, cluster = [sock.getsockname()[1] for sock in sockets]
    for sock in sockets:
        sock.close()
    control = tmp_path / "control"
    control.mkdir(mode=0o700)
    (control / "runtime").mkdir(mode=0o700)
    data = tmp_path / "raft"
    data.mkdir(mode=0o700)
    key = tmp_path / "seal.key"
    key.write_bytes(os.urandom(32))
    key.chmod(0o600)
    config = tmp_path / "bao.hcl"
    config.write_text(
        'disable_mlock = true\n'
        f'api_addr = "http://127.0.0.1:{port}"\n'
        f'cluster_addr = "http://127.0.0.1:{cluster}"\n'
        f'storage "raft" {{ node_id="proof" path="{data}" }}\n'
        f'listener "tcp" {{ address="127.0.0.1:{port}" tls_disable=true }}\n'
        f'seal "static" {{ current_key_id="proof" current_key="file://{key}" }}\n'
        'audit "file" "proof" { options { '
        f'file_path="{tmp_path / "audit.json"}" log_raw="false" mode="0600"'
        ' } }\n'
    )
    monkeypatch.setattr(backend, "ROOT", control)
    monkeypatch.setattr(backend, "URL", f"http://127.0.0.1:{port}")
    processes = []
    def start():
        process = subprocess.Popen([binary, "server", "-config=" + str(config)],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        processes.append(process)
        backend.wait_ready(process)
        return process
    try:
        yield start
    finally:
        for process in processes:
            if process.poll() is None:
                process.terminate()
            process.wait(timeout=15)
        shutil.rmtree(tmp_path)


def assert_forbidden(method, path, token, body=None):
    with pytest.raises(HTTPError) as denied:
        backend.call(method, path, body, token)
    assert denied.value.code == 403


def test_real_fresh_maintenance_survives_root_revocation_restart_and_expiry(raft):
    process = raft()
    assert backend.bootstrap(process) is True
    initial_root = backend.load("root.json")
    process.terminate()
    process.wait(timeout=15)
    process = raft()

    # A real 1s token from the same role exercises expiry without waiting 15min.
    # Restore the production role before final bootstrap validation/revocation.
    backend.configure_audit(initial_root)
    backend.call("POST", "sys/auth/approle", {"type": "approle"}, initial_root)
    backend.provision_maintenance(initial_root)
    backend.call("POST", backend.MAINTENANCE_PATH,
                 {**backend.MAINTENANCE_ROLE, "token_ttl": 1, "token_max_ttl": 1,
                  "token_explicit_max_ttl": 1}, initial_root)
    auth = backend.load("operator/maintenance.json")
    expiring = backend.approle_token(auth)
    backend.call("POST", backend.MAINTENANCE_PATH, backend.MAINTENANCE_ROLE, initial_root)
    time.sleep(1.2)
    assert_forbidden("GET", "auth/token/lookup-self", expiring)

    assert backend.bootstrap(process) is False
    assert_forbidden("GET", "auth/token/lookup-self", initial_root)
    assert_forbidden("PUT", "sys/policies/acl/forbidden", initial_root, {"policy": ""})
    assert not (backend.ROOT / "root.json").exists()
    assert not (backend.ROOT / "init.json").exists()
    assert list((backend.ROOT / "runtime").iterdir()) == [backend.ROOT / "runtime/broker.json"]
    assert (backend.ROOT / "operator").stat().st_mode & 0o777 == 0o700
    assert (backend.ROOT / "operator/maintenance.json").stat().st_mode & 0o777 == 0o600
    before = (backend.ROOT / "operator/maintenance.json").read_bytes()

    for _ in range(2):
        token = backend.approle_token(auth)
        lookup = backend.call("GET", "auth/token/lookup-self", token=token)["data"]
        assert lookup["policies"] == ["blockwart-maintenance"]
        assert 0 < lookup["ttl"] <= 900
        assert lookup["explicit_max_ttl"] == 900
        backend.configure_audit(token)
        backend.verify_maintenance_login()
        backend.call("GET", "sys/storage/raft/configuration", token=token)
        assert_forbidden("GET", "blockwart/data/bootstrap", token)
        assert_forbidden("POST", "blockwart/data/forbidden", token,
                         {"options": {"cas": 0}, "data": {"synthetic": True}})
        assert_forbidden("PUT", "sys/policies/acl/forbidden", token, {"policy": ""})
        assert_forbidden("POST", "sys/auth/forbidden", token, {"type": "approle"})
        assert_forbidden("POST", "auth/token/create", token, {"policies": ["root"]})
        assert_forbidden("POST", "sys/storage/raft/remove-peer", token, {"server_id": "proof"})
        assert_forbidden("POST", "sys/config/auditing/request-headers/authorization",
                         token, {"hmac": False})
        # New authenticated ceremony is available, but still requires a real share.
        assert_forbidden("POST", "sys/generate-root-token/attempt", None, {})
        attempt = backend.call("POST", "sys/generate-root-token/attempt", {}, token)["data"]
        with pytest.raises(HTTPError) as missing_share:
            backend.call("POST", "sys/generate-root-token/update",
                         {"nonce": attempt["nonce"], "key": ""}, token)
        assert missing_share.value.code == 400
        status = backend.call("GET", "sys/generate-root-token/attempt", token=token)["data"]
        assert status["progress"] == 0 and status["complete"] is False
        backend.call("DELETE", "sys/generate-root-token/attempt", token=token)
        attempt = backend.call("POST", "sys/generate-root-token/attempt", {}, token)["data"]
        completed = backend.call("POST", "sys/generate-root-token/update", {
            "nonce": attempt["nonce"],
            "key": backend.load("recovery.json")["recovery_keys_base64"][0],
        }, token)["data"]
        assert completed["complete"] is True
        encoded = base64.b64decode(completed["encoded_token"] + "===")
        pairs = zip(encoded, attempt["otp"].encode(), strict=True)
        generated = bytes(a ^ b for a, b in pairs).decode()
        try:
            lookup = backend.call("GET", "auth/token/lookup-self", token=generated)["data"]
            assert lookup["policies"] == ["root"]
        finally:
            backend.call("POST", "auth/token/revoke-self", {}, generated)
        assert_forbidden("GET", "auth/token/lookup-self", generated)
        backend.call("POST", "auth/token/revoke-self", {}, token)
        assert_forbidden("GET", "auth/token/lookup-self", token)
        process.terminate()
        process.wait(timeout=15)
        process = raft()
        assert backend.bootstrap(process) is False
    assert (backend.ROOT / "operator/maintenance.json").read_bytes() == before


@pytest.mark.parametrize(
    "boundary", ["planned", "custom-secret-response", "verified", "root-revoked"],
)
def test_real_interrupted_maintenance_bootstrap_resumes_same_credentials(
    raft, monkeypatch, boundary,
):
    process = raft()
    assert backend.bootstrap(process) is True
    root = backend.load("root.json")
    process.terminate()
    process.wait(timeout=15)
    process = raft()
    original_call, original_save = backend.call, backend.save
    created = []
    interrupted = False

    def save(name, value):
        nonlocal interrupted
        original_save(name, value)
        if not interrupted and (
            (boundary == "planned" and name == "operator/maintenance.json")
            or (boundary == "verified" and name == "maintenance-verified.json")
        ):
            interrupted = True
            raise RuntimeError("synthetic-interruption")

    def call(method, path, body=None, token=None, **kwargs):
        nonlocal interrupted
        result = original_call(method, path, body, token, **kwargs)
        if path == backend.MAINTENANCE_PATH + "/custom-secret-id":
            assert backend.load("operator/maintenance.json")["secret_id"] == body["secret_id"]
            created.append(body["secret_id"])
            if boundary == "custom-secret-response" and not interrupted:
                interrupted = True
                raise RuntimeError("synthetic-interruption")
        if (boundary == "root-revoked" and path == "auth/token/revoke-self"
                and token == root and not interrupted):
            interrupted = True
            raise RuntimeError("synthetic-interruption")
        return result

    monkeypatch.setattr(backend, "save", save)
    monkeypatch.setattr(backend, "call", call)
    with pytest.raises(RuntimeError, match="synthetic-interruption"):
        backend.bootstrap(process)
    assert interrupted
    planned = (backend.ROOT / "operator/maintenance.json").read_bytes()
    process.terminate()
    process.wait(timeout=15)
    process = raft()
    if boundary == "verified":
        # Previously verified files never bypass the final accepted-policy check.
        original_call("PUT", "sys/policies/acl/blockwart-maintenance", {
            "policy": backend.MAINTENANCE_POLICY
            + '\npath "blockwart/data/*" { capabilities=["read"] }',
        }, root)
        with pytest.raises(RuntimeError, match="maintenance_configuration_mismatch"):
            backend.bootstrap(process)
        original_call("GET", "auth/token/lookup-self", token=root)
        assert not (backend.ROOT / "runtime/broker.json").exists()
        original_call("PUT", "sys/policies/acl/blockwart-maintenance",
                      {"policy": backend.MAINTENANCE_POLICY}, root)
        original_call("POST", backend.MAINTENANCE_PATH,
                      {**backend.MAINTENANCE_ROLE, "token_ttl": 60}, root)
        with pytest.raises(RuntimeError, match="maintenance_configuration_mismatch"):
            backend.bootstrap(process)
        original_call("GET", "auth/token/lookup-self", token=root)
        original_call("POST", backend.MAINTENANCE_PATH, backend.MAINTENANCE_ROLE, root)
    assert backend.bootstrap(process) is False
    assert (backend.ROOT / "operator/maintenance.json").read_bytes() == planned
    assert len(created) == 1  # lost responses reconcile by lookup, not another creation
    backend.verify_maintenance_login()
    assert_forbidden("GET", "auth/token/lookup-self", root)
    assert backend.load("stage.json") == "ready"


def test_fresh_initialization_envelope_resumes_maintenance_opt_in(tmp_path, monkeypatch):
    monkeypatch.setattr(backend, "ROOT", tmp_path)
    backend.save("init.json", {
        "root_token": "synthetic-root", "recovery_keys_base64": ["synthetic-share"],
        "blockwart_maintenance": 1,
    })
    original_save = backend.save
    def interrupt(name, value):
        original_save(name, value)
        if name == "maintenance-required.json":
            raise RuntimeError("synthetic-interruption")
    monkeypatch.setattr(backend, "save", interrupt)
    with pytest.raises(RuntimeError, match="synthetic-interruption"):
        backend.preserve_initialization()
    monkeypatch.setattr(backend, "save", original_save)
    backend.preserve_initialization()
    assert backend.load("maintenance-required.json") == {"version": 1}
    assert backend.load("stage.json") == "initialized"
    assert not (tmp_path / "init.json").exists()
