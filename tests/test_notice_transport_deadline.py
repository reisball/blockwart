"""The shared test transport must fit inside its delivery lease (Refs #100)."""

import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from blockwart.services.notice_transport import (
    DeliveryRequest,
    OpenClawTestGatewayTransport,
    TransportConfigError,
)


@pytest.mark.parametrize("phase", ["headers", "body"])
def test_slow_drip_is_stopped_by_total_deadline(phase: str) -> None:
    stopped = threading.Event()

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802
            self.rfile.read(int(self.headers["Content-Length"]))
            if phase == "body":
                self.send_response(200)
                self.send_header("Content-Length", "4096")
                self.end_headers()
            else:
                self.wfile.write(b"HTTP/1.1 200 OK\r\nX-Slow: ")
                self.wfile.flush()
            try:
                while not stopped.wait(0.04):
                    self.wfile.write(b"x")
                    self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError):
                pass

        def log_message(self, *args) -> None:
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    transport = OpenClawTestGatewayTransport(
        endpoint_url=f"http://127.0.0.1:{server.server_port}/hint", timeout_seconds=0.25
    )
    try:
        start = time.monotonic()
        outcome = transport.deliver(DeliveryRequest("target", "openclaw-agent:test", "key", {}))
        elapsed = time.monotonic() - start
        assert not outcome.ok and outcome.error_code == "transport_timeout"
        assert 0.15 <= elapsed < 1.5
    finally:
        stopped.set()
        server.shutdown()
        server.server_close()
        worker.join(timeout=2)


@pytest.mark.parametrize("timeout", [0, -1, float("inf"), float("nan")])
def test_transport_refuses_unbounded_timeouts(timeout: float) -> None:
    with pytest.raises(TransportConfigError):
        OpenClawTestGatewayTransport(endpoint_url="http://127.0.0.1:1", timeout_seconds=timeout)


def test_transport_never_follows_redirects(monkeypatch) -> None:
    visited = threading.Event()

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802
            self.send_response(302)
            self.send_header("Location", "/secret")
            self.end_headers()

        def do_GET(self) -> None:  # noqa: N802
            visited.set()
            self.send_response(200)
            self.end_headers()

        def log_message(self, *args) -> None:
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    # Proxy environment must never redirect the test transport off loopback.
    monkeypatch.setenv("HTTP_PROXY", "http://192.0.2.1:1")
    try:
        transport = OpenClawTestGatewayTransport(
            endpoint_url=f"http://127.0.0.1:{server.server_port}/hint", timeout_seconds=1
        )
        outcome = transport.deliver(DeliveryRequest("target", "openclaw-agent:test", "key", {}))
        assert not outcome.ok and not visited.is_set()
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=2)
