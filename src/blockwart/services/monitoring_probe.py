"""The built-in bounded HTTP(S) health probe.

This adapter is the only place in Blockwart that opens an outbound connection
on behalf of catalog data, so every SSRF control lives here:

- the target is already resolved by the domain; this module never scans a URL,
  port, or path, and never follows a redirect;
- DNS is resolved once, **every** returned address is validated against the
  deny-by-default policy, and one validated address is pinned for the socket.
  The hostname is never resolved a second time, so a rebinding answer cannot
  replace the validated target between check and connect;
- the pinned address is used for the connection while the original hostname
  supplies the ``Host`` header and the TLS SNI plus certificate validation, so
  pinning does not weaken transport authentication;
- no credential, cookie, authorization header, or proxy environment variable is
  attached, and no response body is kept;
- connect and total time, response size, and header count are bounded, and the
  caller only ever receives one stable, redacted error code.

Only the standard library is used. A general HTTP client would reintroduce
redirect following, proxy environment handling, and connection reuse across
hosts, all of which this contract forbids.
"""

from __future__ import annotations

import socket
import ssl
from dataclasses import dataclass
from datetime import UTC, datetime
from ipaddress import ip_address
from queue import Empty, Full, Queue
from threading import Event, Lock, Thread
from time import monotonic
from typing import TYPE_CHECKING

from blockwart.domain.monitoring import MonitoringObservation
from blockwart.domain.monitoring_policy import IPAddress, pin_address

if TYPE_CHECKING:
    from blockwart.services.monitoring_registry import ProviderCheckRequest

_PROVIDER = "builtin_http"
_USER_AGENT = "Blockwart-Healthcheck/1"
_MAX_HEADERS = 64
_MAX_HEADER_BYTES = 32768
_RESOLVER_WORKERS = 4
_RESOLVER_QUEUE_SIZE = 64


@dataclass(slots=True)
class _ResolverTask:
    host: str
    port: int
    result: Queue[tuple[bool, object]]
    cancelled: Event


_RESOLVER_QUEUE: Queue[_ResolverTask] = Queue(maxsize=_RESOLVER_QUEUE_SIZE)
_RESOLVER_START_LOCK = Lock()
_RESOLVER_STARTED = False


def probe_http_target(request: ProviderCheckRequest) -> MonitoringObservation:
    """Run one bounded, unauthenticated GET and normalize the outcome."""

    checked_at = datetime.now(UTC)
    target = request.target
    if target is None:
        # Missing or ambiguous configuration is a diagnostic, never a claim
        # that the service is down.
        return MonitoringObservation(
            provider=_PROVIDER,
            state="check_error",
            checked_at=checked_at,
            error_code="invalid_target",
        )

    limits = request.limits
    scheme_reason = limits.policy.check_scheme(target.scheme)
    port_reason = limits.policy.check_port(target.port)
    if scheme_reason is not None or port_reason is not None:
        return _denied(checked_at)

    if not limits.policy.enabled:
        return _denied(checked_at)

    started = monotonic()
    try:
        addresses = _resolve(
            target.host,
            target.port,
            timeout=min(
                limits.connect_timeout_ms / 1000,
                limits.total_timeout_ms / 1000,
            ),
        )
    except TimeoutError:
        return MonitoringObservation(
            provider=_PROVIDER,
            state="down",
            checked_at=checked_at,
            latency_ms=_elapsed_ms(started),
            error_code="timeout",
        )
    except OSError:
        return MonitoringObservation(
            provider=_PROVIDER,
            state="down",
            checked_at=checked_at,
            latency_ms=_elapsed_ms(started),
            error_code="dns_failed",
        )

    if limits.policy.check_target(
        scheme=target.scheme,
        port=target.port,
        addresses=addresses,
    ) is not None:
        return _denied(checked_at)

    pinned = pin_address(addresses)
    if pinned is None:
        return _denied(checked_at)

    remaining_total = limits.total_timeout_ms / 1000 - (monotonic() - started)
    if remaining_total <= 0:
        return MonitoringObservation(
            provider=_PROVIDER,
            state="down",
            checked_at=checked_at,
            latency_ms=_elapsed_ms(started),
            error_code="timeout",
        )
    try:
        status = _request_status(
            scheme=target.scheme,
            hostname=target.host,
            pinned=pinned,
            port=target.port,
            path=target.path,
            connect_timeout=limits.connect_timeout_ms / 1000,
            total_timeout=remaining_total,
            max_response_bytes=limits.max_response_bytes,
        )
    except _ProbeFailure as failure:
        return MonitoringObservation(
            provider=_PROVIDER,
            state=failure.state,
            checked_at=checked_at,
            latency_ms=_elapsed_ms(started),
            error_code=failure.error_code,
        )

    latency_ms = _elapsed_ms(started)
    state, error_code = _classify(status)
    return MonitoringObservation(
        provider=_PROVIDER,
        state=state,
        checked_at=checked_at,
        http_status=status,
        latency_ms=latency_ms,
        error_code=error_code,
    )


class _ProbeFailure(Exception):
    def __init__(self, state: str, error_code: str) -> None:
        super().__init__(error_code)
        self.state = state
        self.error_code = error_code


def _resolve(host: str, port: int, *, timeout: float) -> list[IPAddress]:
    """Resolve one hostname to every address it currently answers with."""

    try:
        return [ip_address(host)]
    except ValueError:
        pass
    _ensure_resolver_workers()
    result: Queue[tuple[bool, object]] = Queue(maxsize=1)
    task = _ResolverTask(host=host, port=port, result=result, cancelled=Event())
    try:
        _RESOLVER_QUEUE.put_nowait(task)
    except Full as exc:
        raise TimeoutError("resolver capacity unavailable") from exc
    try:
        succeeded, payload = result.get(timeout=max(0.01, timeout))
    except Empty as exc:
        task.cancelled.set()
        raise TimeoutError("resolver deadline exceeded") from exc
    if not succeeded or not isinstance(payload, list):
        raise OSError("name resolution failed")
    infos = payload
    resolved: list[IPAddress] = []
    for info in infos:
        candidate = info[4][0]
        try:
            address = ip_address(candidate)
        except ValueError:
            continue
        if address not in resolved:
            resolved.append(address)
    return resolved


def _ensure_resolver_workers() -> None:
    global _RESOLVER_STARTED

    if _RESOLVER_STARTED:
        return
    with _RESOLVER_START_LOCK:
        if _RESOLVER_STARTED:
            return
        for index in range(_RESOLVER_WORKERS):
            Thread(
                target=_resolver_worker,
                name=f"blockwart-monitoring-resolver-{index + 1}",
                daemon=True,
            ).start()
        _RESOLVER_STARTED = True


def _resolver_worker() -> None:
    while True:
        task = _RESOLVER_QUEUE.get()
        try:
            if task.cancelled.is_set():
                continue
            try:
                infos = socket.getaddrinfo(
                    task.host,
                    task.port,
                    proto=socket.IPPROTO_TCP,
                )
            except OSError:
                outcome: tuple[bool, object] = (False, None)
            else:
                outcome = (True, infos)
            if not task.cancelled.is_set():
                try:
                    task.result.put_nowait(outcome)
                except Full:
                    pass
        finally:
            _RESOLVER_QUEUE.task_done()


def _request_status(
    *,
    scheme: str,
    hostname: str,
    pinned: IPAddress,
    port: int,
    path: str,
    connect_timeout: float,
    total_timeout: float,
    max_response_bytes: int,
) -> int:
    deadline = monotonic() + total_timeout
    sock: socket.socket | None = None
    try:
        try:
            sock = socket.create_connection(
                (str(pinned), port),
                timeout=min(connect_timeout, _remaining(deadline)),
            )
        except TimeoutError as exc:
            raise _ProbeFailure("down", "timeout") from exc
        except OSError as exc:
            raise _ProbeFailure("down", "connect_failed") from exc

        if scheme == "https":
            context = ssl.create_default_context()
            context.check_hostname = True
            context.verify_mode = ssl.CERT_REQUIRED
            try:
                sock.settimeout(_remaining(deadline))
                # server_hostname keeps SNI and certificate validation bound to
                # the catalog hostname even though the socket is pinned to a
                # validated address.
                sock = context.wrap_socket(sock, server_hostname=hostname)
            except ssl.SSLError as exc:
                raise _ProbeFailure("down", "tls_failed") from exc
            except TimeoutError as exc:
                raise _ProbeFailure("down", "timeout") from exc
            except OSError as exc:
                raise _ProbeFailure("down", "connect_failed") from exc

        request = (
            f"GET {path or '/'} HTTP/1.1\r\n"
            f"Host: {_host_header(hostname, port, scheme)}\r\n"
            f"User-Agent: {_USER_AGENT}\r\n"
            "Accept: */*\r\n"
            "Connection: close\r\n\r\n"
        ).encode("ascii")
        try:
            _send_all(sock, request, deadline)
            header_block = _read_response_headers(sock, deadline)
        except TimeoutError as exc:
            raise _ProbeFailure("down", "timeout") from exc
        except ssl.SSLError as exc:
            raise _ProbeFailure("down", "tls_failed") from exc
        except OSError as exc:
            raise _ProbeFailure("down", "connect_failed") from exc

        status, headers = _parse_response_headers(header_block)
        if len(headers) > _MAX_HEADERS:
            raise _ProbeFailure("check_error", "response_too_large")
        declared = next(
            (value for name, value in headers if name.casefold() == "content-length"),
            None,
        )
        if declared is not None and declared.isdigit() and int(declared) > max_response_bytes:
            raise _ProbeFailure("check_error", "response_too_large")
        # Health is decided entirely by the status. The response body is never
        # read, allocated, inspected, logged, or stored; zero bytes is the
        # strictest possible body limit for data the product does not need.
        return status
    finally:
        if sock is not None:
            sock.close()


def _request_status_and_body(
    *,
    scheme: str,
    hostname: str,
    pinned: IPAddress,
    port: int,
    path: str,
    connect_timeout: float,
    total_timeout: float,
    max_response_bytes: int,
    authorization: str | None = None,
) -> tuple[int, bytes]:
    """Like ``_request_status`` but also reads a bounded response body.

    Used by adapters that need the response payload (for example the Gatus
    pull adapter, which parses the statuses JSON). Every SSRF and size control
    from ``_request_status`` applies identically; the body is read only up to
    ``max_response_bytes`` and never logged or persisted.
    """
    deadline = monotonic() + total_timeout
    sock: socket.socket | None = None
    try:
        try:
            sock = socket.create_connection(
                (str(pinned), port),
                timeout=min(connect_timeout, _remaining(deadline)),
            )
        except TimeoutError as exc:
            raise _ProbeFailure("down", "timeout") from exc
        except OSError as exc:
            raise _ProbeFailure("down", "connect_failed") from exc

        if scheme == "https":
            context = ssl.create_default_context()
            context.check_hostname = True
            context.verify_mode = ssl.CERT_REQUIRED
            try:
                sock.settimeout(_remaining(deadline))
                sock = context.wrap_socket(sock, server_hostname=hostname)
            except ssl.SSLError as exc:
                raise _ProbeFailure("down", "tls_failed") from exc
            except TimeoutError as exc:
                raise _ProbeFailure("down", "timeout") from exc
            except OSError as exc:
                raise _ProbeFailure("down", "connect_failed") from exc

        auth_line = f"Authorization: {authorization}\r\n" if authorization else ""
        request = (
            f"GET {path or '/'} HTTP/1.1\r\n"
            f"Host: {_host_header(hostname, port, scheme)}\r\n"
            f"User-Agent: {_USER_AGENT}\r\n"
            f"{auth_line}"
            "Accept: application/json\r\n"
            "Connection: close\r\n\r\n"
        ).encode("ascii")
        try:
            _send_all(sock, request, deadline)
            header_block = _read_response_headers(sock, deadline)
        except TimeoutError as exc:
            raise _ProbeFailure("down", "timeout") from exc
        except ssl.SSLError as exc:
            raise _ProbeFailure("down", "tls_failed") from exc
        except OSError as exc:
            raise _ProbeFailure("down", "connect_failed") from exc

        status, headers = _parse_response_headers(header_block)
        if len(headers) > _MAX_HEADERS:
            raise _ProbeFailure("check_error", "response_too_large")
        declared = next(
            (value for name, value in headers if name.casefold() == "content-length"),
            None,
        )
        if declared is not None and declared.isdigit() and int(declared) > max_response_bytes:
            raise _ProbeFailure("check_error", "response_too_large")
        try:
            body = _read_bounded_body(sock, max_response_bytes, deadline)
        except _ProbeFailure:
            raise
        except TimeoutError as exc:
            raise _ProbeFailure("down", "timeout") from exc
        except OSError as exc:
            raise _ProbeFailure("down", "connect_failed") from exc
        return status, body
    finally:
        if sock is not None:
            sock.close()


def _read_bounded_body(
    sock: socket.socket,
    max_bytes: int,
    deadline: float,
) -> bytes:
    """Read a response body up to ``max_bytes`` (plus a sentinel byte).

    The connection is ``Connection: close``, so reading until EOF is correct
    for both ``Content-Length`` and chunked responses; a transfer chunked body
    is parsed as JSON downstream, and a framing mismatch fails closed there.
    """
    chunks: list[bytes] = []
    total = 0
    while True:
        sock.settimeout(_remaining(deadline))
        try:
            chunk = sock.recv(4096)
        except TimeoutError:
            raise
        except OSError:
            raise
        if not chunk:
            break
        total += len(chunk)
        if total > max_bytes:
            raise _ProbeFailure("check_error", "response_too_large")
        chunks.append(chunk)
    return b"".join(chunks)


def _classify(status: int) -> tuple[str, str | None]:
    if 200 <= status < 300:
        return "healthy", None
    if 300 <= status < 400:
        # Redirects are not followed, so a redirect answers nothing about the
        # service's health.
        return "check_error", "redirect_not_supported"
    if 400 <= status < 500:
        return "check_error", "http_client_error"
    if 500 <= status < 600:
        return "down", "http_server_error"
    return "check_error", "probe_failed"


def _denied(checked_at: datetime) -> MonitoringObservation:
    return MonitoringObservation(
        provider=_PROVIDER,
        state="check_error",
        checked_at=checked_at,
        error_code="policy_denied",
    )


def _send_all(sock: socket.socket, payload: bytes, deadline: float) -> None:
    view = memoryview(payload)
    while view:
        sock.settimeout(_remaining(deadline))
        sent = sock.send(view)
        if sent <= 0:
            raise OSError("socket closed")
        view = view[sent:]


def _read_response_headers(sock: socket.socket, deadline: float) -> bytes:
    received = bytearray()
    while not received.endswith(b"\r\n\r\n"):
        if len(received) >= _MAX_HEADER_BYTES:
            raise _ProbeFailure("check_error", "response_too_large")
        sock.settimeout(_remaining(deadline))
        # Read only through the header terminator. A larger recv can consume
        # response-body bytes coalesced into the same TCP/TLS record, even if
        # they are discarded immediately afterwards. One-byte reads keep the
        # stronger contract that this client never reads a body at all; the
        # header byte and total-time ceilings keep the work bounded.
        chunk = sock.recv(1)
        if not chunk:
            raise _ProbeFailure("check_error", "probe_failed")
        received.extend(chunk)
    return bytes(received)


def _parse_response_headers(block: bytes) -> tuple[int, list[tuple[str, str]]]:
    try:
        lines = block[:-4].decode("iso-8859-1").split("\r\n")
        protocol, raw_status, _reason = lines[0].split(" ", 2)
        status = int(raw_status)
    except (UnicodeError, ValueError, IndexError) as exc:
        raise _ProbeFailure("check_error", "probe_failed") from exc
    if protocol not in {"HTTP/1.0", "HTTP/1.1"} or not 100 <= status <= 599:
        raise _ProbeFailure("check_error", "probe_failed")
    headers: list[tuple[str, str]] = []
    for line in lines[1:]:
        name, separator, value = line.partition(":")
        if not separator or not name or any(character.isspace() for character in name):
            raise _ProbeFailure("check_error", "probe_failed")
        headers.append((name, value.strip()))
    return status, headers


def _host_header(hostname: str, port: int, scheme: str) -> str:
    rendered = f"[{hostname}]" if ":" in hostname else hostname
    default_port = 443 if scheme == "https" else 80
    if port == default_port:
        return rendered
    return f"{rendered}:{port}"


def _elapsed_ms(started: float) -> int:
    return max(0, int((monotonic() - started) * 1000))


def _remaining(deadline: float) -> float:
    """Return the remaining hard deadline or stop before another socket call."""

    remaining = deadline - monotonic()
    if remaining <= 0:
        raise TimeoutError("probe deadline exceeded")
    return remaining
