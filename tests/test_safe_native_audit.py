"""Optional real pinned Bao audit fault bridge; synthetic disposable local server."""
# ruff: noqa: F401, F811
import json
import os
import re
import signal
import socket
import subprocess
import time
from pathlib import Path

import pytest
from fastapi import HTTPException
from test_credential_safe import VALUE, invoke, safe_client
from test_reference_content_boundary import REF_ID, boundary_state

from blockwart.config import Settings
from blockwart.services.credential_safe import Bao

_BAO_INIT = Bao.__init__
_BAO_REQUEST = Bao.request


@pytest.fixture
def native(tmp_path):
    binary = os.environ.get("BLOCKWART_TEST_BAO_BINARY")
    if not binary:
        pytest.skip("explicit disposable OpenBao executable not configured")
    version = subprocess.check_output([binary, "version"], text=True)
    assert "v2.7.2 " in version
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    audit = tmp_path / "audit.json"
    config = tmp_path / "bao.hcl"
    config.write_text('disable_mlock = true\naudit "file" "blockwart" { options { '
                      'file_path = "' + str(audit) + '" log_raw = "false" mode = "0600" } }')
    process = subprocess.Popen([binary, "server", "-dev", "-dev-root-token-id=synthetic-root",
        "-dev-listen-address=127.0.0.1:" + str(port), "-config=" + str(config)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    backend = object.__new__(Bao)
    backend.url = "http://127.0.0.1:" + str(port)
    backend.auth_file = str(tmp_path / "broker.json")
    def admin(method, path, body=None):
        return backend.call(method, path, body, token="synthetic-root")
    try:
        deadline = time.monotonic() + 20
        while True:
            assert process.poll() is None, "disposable Bao startup failed"
            try:
                admin("GET", "sys/health")
                break
            except HTTPException:
                assert time.monotonic() < deadline
                time.sleep(0.1)
        admin("POST", "sys/config/auditing/request-headers/x-blockwart-operation", {"hmac": False})
        admin("POST", "sys/mounts/blockwart", {"type": "kv", "options": {"version": "2"}})
        admin("POST", "sys/auth/approle", {"type": "approle"})
        admin("PUT", "sys/policies/acl/broker", {"policy":
            'path "blockwart/data/*" { capabilities=["create","update","read"] } '
            'path "auth/token/revoke-self" { capabilities=["update"] }'})
        admin("POST", "auth/approle/role/broker",
              {"token_policies": ["broker"], "token_ttl": "1s", "token_max_ttl": "1s"})
        role = admin("GET", "auth/approle/role/broker/role-id")["data"]["role_id"]
        secret = admin("POST", "auth/approle/role/broker/secret-id", {})["data"]["secret_id"]
        Path(backend.auth_file).write_text(json.dumps({"role_id": role, "secret_id": secret}))
        # KV startup readiness is read-only; never retry a mutation.
        while True:
            try:
                admin("GET", "blockwart/config")
                break
            except HTTPException:
                assert time.monotonic() < deadline
                time.sleep(0.1)
        yield backend, process, audit, admin
    finally:
        process.terminate()
        process.wait(timeout=10)


def test_native_expiry_relogin_and_revocation(native):
    backend, _, audit, _ = native
    token = backend.token()
    time.sleep(1.2)
    with pytest.raises(HTTPException) as expired:
        backend.call("GET", "blockwart/data/empty", token=token)
    assert expired.value.status_code == 503
    assert _BAO_REQUEST(backend, "POST", "blockwart/data/token-test", {
        "options": {"cas": 0}, "data": {"fields": {"token": VALUE}, "deleted": False},
    })["data"]["version"] == 1
    token = backend.token()
    backend.call("POST", "auth/token/revoke-self", {}, token=token)
    with pytest.raises(HTTPException):
        backend.call("GET", "blockwart/data/token-test", token=token)
    assert VALUE not in audit.read_text()


def test_native_audit_fault_leaves_catalog_and_login_usable(
        native, safe_client, monkeypatch, alembic_session_factory):
    backend, process, audit, _ = native
    client, actors, _ = safe_client
    def bridge(self, method, path, body=None):
        backend.operation_id = self.operation_id
        return _BAO_REQUEST(backend, method, path, body)
    monkeypatch.setattr(Bao, "request", bridge)
    command = dict(action="write", cas=0, fields={"token": VALUE})
    assert invoke(client, actors, "writer", **command).status_code == 200
    # Force native file append/open failure without killing the backend.
    saved = audit.with_name("saved")
    audit.rename(saved)
    audit.mkdir()
    process.send_signal(signal.SIGHUP)
    deadline = time.monotonic() + 5
    while True:
        response = invoke(client, actors, "reader", action="read")
        if response.status_code == 503:
            break
        assert time.monotonic() < deadline
        time.sleep(0.1)
    assert process.poll() is None
    headers = {"Authorization": "Bearer " + actors["reader"][1]}
    assert client.get(f"/api/v1/objects/{REF_ID}", headers=headers).status_code == 200
    from blockwart.services.identity import create_human_principal
    with alembic_session_factory() as session:
        create_human_principal(session, login="synthetic.audit.user", display_name="Audit test",
                               password="synthetic-audit-password-335")
        session.commit()
    client.base_url = "https://testserver"
    login_page = client.get("/auth")
    assert login_page.status_code == 200
    challenge = re.search(r'name="login_challenge" value="([^"]+)"', login_page.text).group(1)
    login = client.post("/auth/login", data={"login": "synthetic.audit.user",
        "password": "synthetic-audit-password-335", "login_challenge": challenge},
        follow_redirects=False)
    assert login.status_code == 303

    # No non-string secret reaches the backend or the native sink.
    assert invoke(client, actors, "writer", action="write", cas=1,
                  fields={"token": {"secret": VALUE}}).status_code == 422
    audit.rmdir()
    saved.rename(audit)
    process.send_signal(signal.SIGHUP)
    deadline = time.monotonic() + 5
    while invoke(client, actors, "reader", action="read").status_code != 200:
        assert time.monotonic() < deadline
        time.sleep(0.1)
    assert VALUE not in audit.read_text()
    with alembic_session_factory() as session:
        from blockwart.models import SafeOperation
        operation = session.query(SafeOperation).one()
        entries = [json.loads(line) for line in audit.read_text().splitlines()]
        assert any(row.get("request", {}).get("headers", {}).get(
            "x-blockwart-operation") == [operation.id] for row in entries)


def test_native_lost_response_is_joinable_and_reconciled(
        native, safe_client, monkeypatch):
    backend, _, audit, _ = native
    client, actors, _ = safe_client
    def lost(self, method, path, body=None):
        backend.operation_id = self.operation_id
        result = _BAO_REQUEST(backend, method, path, body)
        if method == "POST":
            raise HTTPException(503, "Credential safe unavailable")
        return result
    monkeypatch.setattr(Bao, "request", lost)
    command = dict(action="write", cas=0, fields={"token": VALUE})
    assert invoke(client, actors, "writer", **command).status_code == 503
    assert invoke(client, actors, "writer", **command).json() == {"version": 1}
    entries = [json.loads(line) for line in audit.read_text().splitlines()]
    writes = [row for row in entries if row["type"] == "request"
              and row["request"]["operation"] in {"create", "update"}
              and row["request"]["path"].startswith("blockwart/data/")]
    assert len(writes) == 1
    assert writes[0]["request"]["headers"]["x-blockwart-operation"] == [backend.operation_id]
    assert VALUE not in audit.read_text()
