"""Synthetic MCP protocol and pre-I/O credential-boundary regressions."""
import json
import os
import selectors
import subprocess
import sys
from pathlib import Path

import pytest

from blockwart.mcp import server


@pytest.mark.parametrize("configured", ["default", "before", "after"])
def test_subprocess_protocol_errors_never_log_secret_payloads(tmp_path, configured):
    # Intentionally unique names/values so SDK dumps cannot pass by key redaction.
    field = "synthetic_private_field_335"
    value = "synthetic_private_value_335"
    setup = ""
    if configured != "default":
        setup = '''
prior_factory = logging.getLogRecordFactory()
def cached_factory(*args, **kwargs):
    record = prior_factory(*args, **kwargs)
    record.factory_message = record.getMessage()
    return record
logging.setLogRecordFactory(cached_factory)
logging.basicConfig(level=logging.DEBUG, format="%(name)s %(message)s %(factory_message)s")
handler = logging.StreamHandler()
handler.setFormatter(logging.Formatter("%(message)s %(exc_text)s"))
sdk = logging.getLogger("mcp.server.lowlevel.server")
sdk.addHandler(handler)
sdk.propagate = False
sdk.setLevel(logging.DEBUG)
'''
    script = "import logging\n" + setup + "from blockwart.mcp.server import main\nmain()"
    if configured == "after":
        script = ("import logging\nfrom blockwart.mcp import server\n"
                  "server._install_safe_sdk_logging()\n" + setup + "server.main()")
    env = os.environ.copy()
    env["PYTHONPATH"] = str(Path(__file__).resolve().parents[1] / "src")
    for name in ("BLOCKWART_API_TOKEN", "BLOCKWART_API_TOKEN_FILE"):
        env.pop(name, None)
    output = []
    with (tmp_path / "stderr").open("wb") as err:
        process = subprocess.Popen([sys.executable, "-c", script], stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE, stderr=err, env=env, bufsize=0)
        selector = selectors.DefaultSelector()
        selector.register(process.stdout, selectors.EVENT_READ)

        def send(message):
            process.stdin.write(json.dumps(message).encode() + b"\n")
            process.stdin.flush()

        def response(request_id):
            for _ in range(10):
                assert selector.select(10), "protocol response timeout"
                line = process.stdout.readline()
                assert line, "protocol exited before response"
                output.append(line)
                message = json.loads(line)
                if message.get("id") == request_id:
                    return message
            raise AssertionError("missing requested protocol response")

        try:
            send({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
                "protocolVersion": "2025-11-25", "capabilities": {},
                "clientInfo": {"name": "synthetic-client", "version": "1"}}})
            assert "result" in response(1)
            send({"jsonrpc": "2.0", "method": "notifications/initialized"})
            send({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {
                "name": "blockwart.credential_safe",
                "arguments": json.dumps({"action": "write", "fields": {
                    "password": value, field: value}})}})
            assert response(2)["error"]["code"] == -32602
            # Also exercise transport parsing, invalid notifications and DEBUG request dumps.
            process.stdin.write(("not-json " + field + value + "\n").encode())
            process.stdin.flush()
            send({"jsonrpc": "2.0", "method": "notifications/cancelled",
                  "params": {"requestId": {field: value}}})
            send({"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {
                "name": "blockwart.credential_safe", "arguments": {
                    "object_id": "synthetic", "action": "write", "fields": {field: value},
                    "cas": "invalid"}}})
            assert response(3)["result"]["isError"]
            send({"jsonrpc": "2.0", "id": 4, "method": "ping"})
            assert response(4)["result"] == {}
        finally:
            selector.close()
            process.terminate()
            process.wait(timeout=5)
    stderr = (tmp_path / "stderr").read_bytes()
    private_found = any(s.encode() in stderr + b"".join(output) for s in (field, value))
    assert not private_found, "MCP protocol diagnostics exposed synthetic payload"
    if configured != "default":
        assert b"mcp_sdk_event" in stderr


@pytest.mark.parametrize("url", ["http://api.example.invalid", "https://api.example.invalid",
                                  "http://127.0.0.1:8000"])
def test_safe_missing_auth_never_opens_transport(monkeypatch, url):
    monkeypatch.setattr(server, "_api_token", lambda: None)
    calls = []
    monkeypatch.setattr(server, "build_opener", lambda *a: calls.append(a))
    with pytest.raises(server.UpstreamError) as error:
        server.request_json("POST", "/api/v1/objects/synthetic/safe", {
            "action": "write", "cas": 0, "fields": {"password": "synthetic"}}, {}, base_url=url)
    assert not calls
    assert error.value.code == "credential_configuration_error"


@pytest.mark.parametrize("token", [None, "synthetic-token"])
def test_safe_insecure_remote_never_opens_transport(monkeypatch, token):
    monkeypatch.setattr(server, "_api_token", lambda: token)
    calls = []
    monkeypatch.setattr(server, "build_opener", lambda *a: calls.append(a))
    with pytest.raises(server.UpstreamError) as error:
        server.request_json("POST", "/api/v1/objects/synthetic/safe", {
            "action": "write", "cas": 0, "fields": {"password": "synthetic"}}, {},
            base_url="http://api.example.invalid")
    assert not calls
    assert error.value.code == "credential_configuration_error"
