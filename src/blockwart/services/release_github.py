"""Bounded unauthenticated client for GitHub's official latest release endpoint."""

from __future__ import annotations

import json
import socket
import ssl
from dataclasses import dataclass
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from time import monotonic
from typing import Any

from blockwart.domain.monitoring_policy import parse_target_policy, pin_address
from blockwart.domain.provenance import parse_rfc3339_utc
from blockwart.domain.release_monitoring import (
    GITHUB_API_HOST,
    GITHUB_API_PORT,
    GithubReleaseTarget,
    ReleaseObservation,
    normalize_version,
    valid_release_etag,
    valid_release_tag,
)
from blockwart.services.monitoring_probe import (
    _decode_chunked_body,
    _parse_response_headers,
    _ProbeFailure,
    _read_bounded_body,
    _read_response_headers,
    _remaining,
    _resolve,
    _send_all,
)

_USER_AGENT = "Blockwart-ReleaseMonitor/1"
_ACCEPT = "application/vnd.github+json"
_API_VERSION = "2026-03-10"
_MAX_HEADERS = 64
_MAX_RETRY_AFTER_SECONDS = 4_838_400
_PUBLIC_HTTPS_POLICY = parse_target_policy(
    allowed_networks="0.0.0.0/0,::/0",
    allowed_ports="443",
)


@dataclass(frozen=True, slots=True)
class GithubReleaseRequest:
    target: GithubReleaseTarget
    etag: str | None
    connect_timeout_ms: int
    total_timeout_ms: int
    max_response_bytes: int


def fetch_latest_github_release(request: GithubReleaseRequest) -> ReleaseObservation:
    """Fetch one stable full release without redirects, proxies, tokens, or retries."""

    checked_at = datetime.now(UTC)
    if request.etag is not None and not valid_release_etag(request.etag):
        return _error(checked_at, "provider_failed")
    started = monotonic()
    try:
        addresses = _resolve(
            GITHUB_API_HOST,
            GITHUB_API_PORT,
            timeout=min(request.connect_timeout_ms, request.total_timeout_ms) / 1000,
        )
    except TimeoutError:
        return _error(checked_at, "timeout")
    except OSError:
        return _error(checked_at, "dns_failed")
    if (
        _PUBLIC_HTTPS_POLICY.check_target(
            scheme="https",
            port=GITHUB_API_PORT,
            addresses=addresses,
        )
        is not None
    ):
        return _error(checked_at, "policy_denied")
    pinned = pin_address(addresses)
    if pinned is None:
        return _error(checked_at, "policy_denied")
    remaining = request.total_timeout_ms / 1000 - (monotonic() - started)
    if remaining <= 0:
        return _error(checked_at, "timeout")
    try:
        status, headers, body = _request(
            pinned=str(pinned),
            path=request.target.api_path,
            etag=request.etag,
            connect_timeout=min(request.connect_timeout_ms / 1000, remaining),
            total_timeout=remaining,
            max_response_bytes=request.max_response_bytes,
        )
    except _GithubFailure as failure:
        return _error(checked_at, failure.code)

    retry_after = _retry_after_seconds(headers, now=checked_at)
    if status == 304:
        return ReleaseObservation(
            provider="github_releases",
            outcome="not_modified",
            checked_at=checked_at,
            http_status=304,
            etag=_safe_etag(headers) or request.etag,
        )
    if 300 <= status < 400:
        return _error(checked_at, "redirect_not_supported", status=status)
    if status == 404:
        return _error(checked_at, "not_found", status=status)
    if status == 429 or (
        status == 403
        and (
            _header(headers, "x-ratelimit-remaining") == "0"
            or _header(headers, "retry-after") is not None
        )
    ):
        return _error(
            checked_at,
            "rate_limited",
            status=status,
            retry_after_seconds=retry_after,
        )
    if 400 <= status < 500:
        return _error(checked_at, "http_client_error", status=status)
    if 500 <= status < 600:
        return _error(
            checked_at,
            "http_server_error",
            status=status,
            retry_after_seconds=retry_after,
        )
    if status != 200:
        return _error(checked_at, "provider_failed", status=status)
    return _parse_release(body, headers=headers, checked_at=checked_at)


class _GithubFailure(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _request(
    *,
    pinned: str,
    path: str,
    etag: str | None,
    connect_timeout: float,
    total_timeout: float,
    max_response_bytes: int,
) -> tuple[int, list[tuple[str, str]], bytes]:
    deadline = monotonic() + total_timeout
    sock: socket.socket | None = None
    try:
        try:
            sock = socket.create_connection(
                (pinned, GITHUB_API_PORT),
                timeout=min(connect_timeout, _remaining(deadline)),
            )
        except TimeoutError as exc:
            raise _GithubFailure("timeout") from exc
        except OSError as exc:
            raise _GithubFailure("connect_failed") from exc
        context = ssl.create_default_context()
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        try:
            sock.settimeout(_remaining(deadline))
            sock = context.wrap_socket(sock, server_hostname=GITHUB_API_HOST)
        except ssl.SSLError as exc:
            raise _GithubFailure("tls_failed") from exc
        except TimeoutError as exc:
            raise _GithubFailure("timeout") from exc
        except OSError as exc:
            raise _GithubFailure("connect_failed") from exc
        conditional = f"If-None-Match: {etag}\r\n" if etag else ""
        wire = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {GITHUB_API_HOST}\r\n"
            f"User-Agent: {_USER_AGENT}\r\n"
            f"Accept: {_ACCEPT}\r\n"
            f"X-GitHub-Api-Version: {_API_VERSION}\r\n"
            f"{conditional}"
            "Connection: close\r\n\r\n"
        ).encode("ascii")
        try:
            _send_all(sock, wire, deadline)
            header_block = _read_response_headers(sock, deadline)
            status, headers = _parse_response_headers(header_block)
        except TimeoutError as exc:
            raise _GithubFailure("timeout") from exc
        except ssl.SSLError as exc:
            raise _GithubFailure("tls_failed") from exc
        except OSError as exc:
            raise _GithubFailure("connect_failed") from exc
        except _ProbeFailure as exc:
            raise _GithubFailure(
                "response_too_large"
                if exc.error_code == "response_too_large"
                else "provider_failed"
            ) from exc
        if len(headers) > _MAX_HEADERS:
            raise _GithubFailure("response_too_large")
        declared = _header(headers, "content-length")
        if declared is not None:
            if not declared.isdigit():
                raise _GithubFailure("provider_failed")
            if int(declared) > max_response_bytes:
                raise _GithubFailure("response_too_large")
        encoding = _header(headers, "content-encoding")
        if encoding is not None and encoding.casefold() not in {"", "identity"}:
            raise _GithubFailure("provider_failed")
        if status == 304:
            return status, headers, b""
        try:
            body = _read_bounded_body(sock, max_response_bytes, deadline)
            if "chunked" in (_header(headers, "transfer-encoding") or "").casefold():
                body = _decode_chunked_body(body)
        except TimeoutError as exc:
            raise _GithubFailure("timeout") from exc
        except (OSError, ssl.SSLError) as exc:
            raise _GithubFailure("connect_failed") from exc
        except _ProbeFailure as exc:
            raise _GithubFailure(
                "response_too_large"
                if exc.error_code == "response_too_large"
                else "provider_failed"
            ) from exc
        return status, headers, body
    finally:
        if sock is not None:
            sock.close()


def _parse_release(
    body: bytes,
    *,
    headers: list[tuple[str, str]],
    checked_at: datetime,
) -> ReleaseObservation:
    try:
        payload: Any = json.loads(body.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError):
        return _error(checked_at, "unreadable_release", status=200)
    if not isinstance(payload, dict):
        return _error(checked_at, "unreadable_release", status=200)
    if payload.get("draft") is not False or payload.get("prerelease") is not False:
        return _error(checked_at, "not_a_stable_release", status=200)
    tag = payload.get("tag_name")
    published = payload.get("published_at")
    if not isinstance(tag, str) or not valid_release_tag(tag):
        return _error(checked_at, "invalid_release_version", status=200)
    version = normalize_version(tag)
    try:
        released_at = parse_rfc3339_utc(published) if isinstance(published, str) else None
    except ValueError:
        released_at = None
    if version is None or released_at is None:
        return _error(checked_at, "unreadable_release", status=200)
    return ReleaseObservation(
        provider="github_releases",
        outcome="observed",
        checked_at=checked_at,
        latest_tag=tag,
        latest_version=version,
        released_at=released_at,
        etag=_safe_etag(headers),
        http_status=200,
    )


def _safe_etag(headers: list[tuple[str, str]]) -> str | None:
    value = _header(headers, "etag")
    return value if value is not None and valid_release_etag(value) else None


def _header(headers: list[tuple[str, str]], name: str) -> str | None:
    values = [value for key, value in headers if key.casefold() == name.casefold()]
    return values[0] if len(values) == 1 else None


def _retry_after_seconds(
    headers: list[tuple[str, str]],
    *,
    now: datetime,
) -> int | None:
    raw = _header(headers, "retry-after")
    delay: int | None = None
    if raw is not None and raw.isdigit():
        delay = int(raw)
    elif raw is not None:
        try:
            parsed = parsedate_to_datetime(raw)
        except (TypeError, ValueError):
            parsed = None
        if parsed is not None:
            delay = max(0, int((parsed.astimezone(UTC) - now).total_seconds()))
    reset = _header(headers, "x-ratelimit-reset")
    if delay is None and reset is not None and reset.isdigit():
        delay = max(0, int(reset) - int(now.timestamp()))
    if delay is None:
        return None
    return min(delay, _MAX_RETRY_AFTER_SECONDS)


def _error(
    checked_at: datetime,
    code: str,
    *,
    status: int | None = None,
    retry_after_seconds: int | None = None,
) -> ReleaseObservation:
    return ReleaseObservation(
        provider="github_releases",
        outcome="error",
        checked_at=checked_at,
        http_status=status,
        error_code=code,  # type: ignore[arg-type]
        retry_after_seconds=retry_after_seconds,
    )
