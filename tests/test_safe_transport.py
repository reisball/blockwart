"""Real local HTTP boundaries; all payloads are synthetic."""
import json
import threading
import time
from http.client import HTTPException as HTTPProtocolError
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from fastapi import HTTPException

from blockwart.cli import safe_backend
from blockwart.config import Settings
from blockwart.mcp import server as mcp
from blockwart.services.credential_safe import Bao, SafeAction, _perform


@pytest.fixture
def http_endpoint():
    state = {"status": 200, "body": b'{}', "calls": []}

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            if state.get("delay"):
                time.sleep(state["delay"])
            state["calls"].append(self.rfile.read(int(self.headers.get("Content-Length", 0))))
            self.send_response(state["status"])
            self.send_header("Location", state.get("location", "/redirect"))
            if state.get("truncated"):
                self.send_header("Content-Length", "100")
            self.end_headers()
            self.wfile.write(state["body"])

        do_GET = do_POST

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_port}", state
    server.shutdown()
    server.server_close()
    thread.join()


def caller(kind, url, monkeypatch):
    if kind == "broker":
        return lambda: Bao(Settings(safe_url=url, safe_auth_file="unused")).call(
            "POST", "test", {"value": "synthetic"}, token="synthetic-token")
    if kind == "supervisor":
        monkeypatch.setattr(safe_backend, "URL", url)
        return lambda: safe_backend.call("POST", "test", {"value": "synthetic"})
    monkeypatch.setattr(mcp, "_api_token", lambda: "synthetic-token")
    return lambda: mcp._http_json("POST", url + "/safe", body={"value": "synthetic"},
                                  headers={}, base_url=url, safe_operation=True)


@pytest.mark.parametrize("kind", ["broker", "supervisor", "mcp"])
def test_internal_transports_ignore_environment_proxy(http_endpoint, monkeypatch, kind):
    url, state = http_endpoint
    for key in ("HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"):
        monkeypatch.setenv(key, url)
    for key in ("NO_PROXY", "no_proxy"):
        monkeypatch.setenv(key, "")
    # A non-listening loopback destination must fail, never reach the proxy.
    with pytest.raises((HTTPException, mcp.UpstreamError, OSError, ValueError, HTTPProtocolError)):
        caller(kind, "http://127.0.0.1:1", monkeypatch)()
    assert not state["calls"]


@pytest.mark.parametrize("kind", ["broker", "supervisor", "mcp"])
@pytest.mark.parametrize("response", ["redirect", "invalid", "oversize", "error", "truncated"])
def test_response_boundaries(http_endpoint, monkeypatch, kind, response):
    url, state = http_endpoint
    state.update({"redirect": {"status": 307, "location": url + "/capture"},
                  "invalid": {"body": b'not-json'},
                  "truncated": {"truncated": True},
                  "oversize": {"body": b' ' * 1048577 + b'{}'},
                  "error": {"status": 500, "body": b'synthetic-private-error'}}[response])
    with pytest.raises(
        (HTTPException, mcp.UpstreamError, OSError, ValueError, HTTPProtocolError),
    ) as exc:
        caller(kind, url, monkeypatch)()
    assert "synthetic-private-error" not in str(exc.value)
    assert len(state["calls"]) == 1


@pytest.mark.parametrize("status", [400, 403, 404, 503])
def test_all_login_errors_unavailable(http_endpoint, tmp_path, status):
    url, state = http_endpoint
    state["status"] = status
    auth = tmp_path / "auth.json"
    auth.write_text(json.dumps({"role_id": "synthetic", "secret_id": "synthetic"}))
    with pytest.raises(HTTPException) as exc:
        _perform(Bao(Settings(safe_url=url, safe_auth_file=str(auth))),
                 "0" * 64, SafeAction(action="history"))
    assert exc.value.status_code == 503


@pytest.mark.parametrize("body", [b'[]', b'null', b'{"auth":{"client_token":null}}',
                                  b'{"auth":{"client_token":3}}', b'{"auth":{}}'])
def test_malformed_login_unavailable(http_endpoint, tmp_path, body):
    url, state = http_endpoint
    state["body"] = body
    auth = tmp_path / "auth.json"
    auth.write_text(json.dumps({"role_id": "synthetic", "secret_id": "synthetic"}))
    with pytest.raises(HTTPException) as exc:
        Bao(Settings(safe_url=url, safe_auth_file=str(auth))).token()
    assert exc.value.status_code == 503


def test_broker_timeout_is_bounded_and_redacted(http_endpoint):
    url, state = http_endpoint
    state["delay"] = 5.5
    state["body"] = b'{"secret":"synthetic-must-not-escape"}'
    started = time.monotonic()
    with pytest.raises(HTTPException) as error:
        Bao(Settings(safe_url=url, safe_auth_file="unused")).call("GET", "test")
    assert error.value.status_code == 503
    assert "synthetic-must-not-escape" not in str(error.value)
    assert 4.8 <= time.monotonic() - started < 6.5


def test_failed_token_revoke_is_visible_without_values(monkeypatch, caplog):
    backend = Bao(Settings(safe_url="http://localhost.invalid", safe_auth_file="unused"))
    backend.operation_id = "a" * 64
    monkeypatch.setattr(backend, "token", lambda: "synthetic-token")
    def call(method, path, body=None, *, token=None):
        if path == "auth/token/revoke-self":
            raise HTTPException(503, "synthetic-private-error")
        return {"data": {"fields": {"token": "synthetic-private-value"}}}
    monkeypatch.setattr(backend, "call", call)
    assert backend.request("GET", "test")["data"]["fields"]["token"]
    assert "safe_token_revoke_failed operation_id=" + "a" * 64 in caplog.text
    assert "synthetic-private" not in caplog.text
    assert "synthetic-token" not in caplog.text
