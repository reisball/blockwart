from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from ipaddress import ip_address

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError
from sqlalchemy import func, select

import blockwart.services.release_github as github_provider
import blockwart.services.release_monitoring as release_service
from blockwart.api.deps import get_session
from blockwart.config import Settings
from blockwart.domain.auth import Permission, PrincipalContext, PrincipalType
from blockwart.domain.release_monitoring import (
    GithubReleaseTarget,
    ReleaseObservation,
    compare_versions,
    read_release_monitoring_config,
    release_monitoring_view,
)
from blockwart.main import create_app
from blockwart.models import (
    AuditEvent,
    CatalogObject,
    ServiceReleaseCheckLease,
    ServiceReleaseObservation,
)
from blockwart.schemas.catalog import CatalogObjectIn
from blockwart.services.catalog import upsert_object
from blockwart.services.policy import PolicySnapshot
from blockwart.services.read_access import ReadAccess
from blockwart.services.release_github import GithubReleaseRequest
from blockwart.services.release_monitoring import (
    ReleaseMonitoringSettings,
    check_service_release,
    query_release_overview,
    run_due_release_checks,
    synchronize_release_schedule,
)

NOW = datetime(2026, 8, 25, 12, 0, tzinfo=UTC)


def _service(
    object_id: str,
    *,
    running_version: str = "1.0.0",
    enabled: bool = True,
    installed_software: list[dict] | None = None,
) -> CatalogObjectIn:
    data: dict = {
        "schema_version": 1,
        "service_information": {"running_version": running_version},
        "release_monitoring": {
            "enabled": enabled,
            "provider": "github_releases",
            "github": {"owner": "example-org", "repo": "example-service"},
        },
    }
    if installed_software is not None:
        data["installed_software"] = installed_software
    return CatalogObjectIn(
        id=object_id,
        kind="service",
        label=object_id,
        lifecycle="active",
        health="healthy",
        data=data,
    )


def _access(*readable: str, discoverable: tuple[str, ...] = ()) -> ReadAccess:
    permissions = {
        object_id: frozenset({Permission.DISCOVER, Permission.READ}) for object_id in readable
    }
    permissions.update({object_id: frozenset({Permission.DISCOVER}) for object_id in discoverable})
    return ReadAccess(
        principal=PrincipalContext(
            id="release-reader",
            principal_type=PrincipalType.HUMAN,
            login="release-reader",
            display_name="Release Reader",
        ),
        policy=PolicySnapshot(
            principal_id="release-reader",
            _permissions=permissions,
            _grants={},
        ),
    )


def _observed(tag: str = "v1.2.0", *, checked_at: datetime = NOW) -> ReleaseObservation:
    return ReleaseObservation(
        provider="github_releases",
        outcome="observed",
        checked_at=checked_at,
        latest_tag=tag,
        latest_version=tag.removeprefix("v"),
        released_at=checked_at - timedelta(days=1),
        etag='"release-etag"',
        http_status=200,
    )


def test_configuration_is_closed_opt_in_and_service_only() -> None:
    absent = read_release_monitoring_config({"schema_version": 1})
    assert absent.enabled is False
    assert absent.interval_seconds == 86400
    disabled = CatalogObjectIn(
        id="explicitly-disabled",
        kind="service",
        label="Disabled",
        data={
            "schema_version": 1,
            "service_information": {"running_version": "1.0.0"},
            "release_monitoring": {"enabled": False, "provider": "github_releases"},
        },
    )
    assert disabled.data["release_monitoring"] == {
        "enabled": False,
        "provider": "github_releases",
    }
    assert _service("configured").data["release_monitoring"]["github"] == {
        "owner": "example-org",
        "repo": "example-service",
    }
    with pytest.raises(ValidationError):
        CatalogObjectIn(
            id="host-monitor",
            kind="host",
            label="Host monitor",
            lifecycle="active",
            health="healthy",
            data=_service("source").data,
        )
    with pytest.raises(ValidationError):
        CatalogObjectIn(
            **_service("invalid-owner").model_dump()
            | {
                "data": {
                    **_service("invalid-owner").data,
                    "release_monitoring": {
                        "enabled": True,
                        "provider": "github_releases",
                        "github": {
                            "owner": "https://github.com/example-org",
                            "repo": "service",
                        },
                    },
                }
            }
        )
    with pytest.raises(ValidationError):
        _service(
            "installed-is-not-a-source",
            installed_software=[{"name": "example", "version": "9.9.9"}],
        )


@pytest.mark.parametrize(
    ("running", "latest", "expected"),
    [
        ("1.2.3", "v1.2.3", "current"),
        ("1.2.3", "1.2.4", "update_available"),
        ("2.0", "1.9.9", "current"),
        ("2.0.0-rc1", "2.0.0", "unknown"),
        ("2026.08", "2026.09", "update_available"),
        ("2026-Q3", "2026-Q4", "unknown"),
        ("release-a", "release-b", "unknown"),
    ],
)
def test_version_comparison_is_conservative(running, latest, expected) -> None:
    assert compare_versions(running, latest) == expected


def test_projection_ignores_free_sources_and_any_installed_software_shape() -> None:
    data = _service("projection").data
    data["sources"] = ["https://attacker.invalid/releases"]
    # This is deliberately injected after schema validation: even a legacy or
    # hand-edited row must never become a second release source.
    data["installed_software"] = [{"name": "example", "version": "99.0.0"}]
    view = release_monitoring_view(
        data=data,
        object_id="projection",
        record=None,
        now=NOW,
    )
    assert view["running_version"] == "1.0.0"
    assert view["latest_version"] is None
    assert view["target"]["api_url"] == (
        "https://api.github.com/repos/example-org/example-service/releases/latest"
    )
    data["service_information"]["running_version"] = "9" * 65
    bounded = release_monitoring_view(
        data=data,
        object_id="projection",
        record=None,
        now=NOW,
    )
    assert bounded["running_version"] is None
    assert bounded["status"] == "unknown"


def test_provider_accepts_only_bounded_stable_latest_release(monkeypatch) -> None:
    monkeypatch.setattr(
        github_provider,
        "_resolve",
        lambda *_args, **_kwargs: [ip_address("140.82.121.6")],
    )
    payload = json.dumps(
        {
            "tag_name": "v1.2.0",
            "draft": False,
            "prerelease": False,
            "published_at": "2026-08-24T12:00:00Z",
            "body": "never persisted or projected",
            "html_url": "https://attacker.invalid/not-used",
        }
    ).encode()
    monkeypatch.setattr(
        github_provider,
        "_request",
        lambda **_kwargs: (200, [("ETag", '"safe"')], payload),
    )
    result = github_provider.fetch_latest_github_release(
        GithubReleaseRequest(
            target=GithubReleaseTarget("example-org", "example-service"),
            etag=None,
            connect_timeout_ms=1000,
            total_timeout_ms=2000,
            max_response_bytes=65536,
        )
    )
    assert result.outcome == "observed"
    assert result.latest_version == "1.2.0"
    assert result.etag == '"safe"'
    assert not hasattr(result, "body")


def test_provider_wire_is_pinned_tls_conditional_and_credential_free(monkeypatch) -> None:
    body = b'{}'

    class FakeSocket:
        def __init__(self) -> None:
            self.sent = bytearray()
            self.response = bytearray(
                b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n" + body
            )

        def settimeout(self, _timeout: float) -> None:
            pass

        def send(self, payload) -> int:
            self.sent.extend(payload)
            return len(payload)

        def recv(self, size: int) -> bytes:
            result = bytes(self.response[:size])
            del self.response[:size]
            return result

        def close(self) -> None:
            pass

    sock = FakeSocket()
    connected: dict[str, object] = {}
    tls: dict[str, object] = {}

    def fake_connect(address, *, timeout):
        connected.update(address=address, timeout=timeout)
        return sock

    class FakeContext:
        check_hostname = False
        verify_mode = None

        def wrap_socket(self, wrapped, *, server_hostname):
            tls.update(socket=wrapped, server_hostname=server_hostname)
            return wrapped

    context = FakeContext()
    monkeypatch.setattr(github_provider.socket, "create_connection", fake_connect)
    monkeypatch.setattr(github_provider.ssl, "create_default_context", lambda: context)
    status, _headers, result_body = github_provider._request(
        pinned="140.82.121.6",
        path="/repos/example-org/example-service/releases/latest",
        etag='"cached"',
        connect_timeout=1,
        total_timeout=2,
        max_response_bytes=1024,
    )
    request = bytes(sock.sent).decode("ascii")
    assert (status, result_body) == (200, body)
    assert connected["address"] == ("140.82.121.6", 443)
    assert tls == {"socket": sock, "server_hostname": "api.github.com"}
    assert context.check_hostname is True
    assert context.verify_mode == github_provider.ssl.CERT_REQUIRED
    assert request.startswith(
        "GET /repos/example-org/example-service/releases/latest HTTP/1.1\r\n"
    )
    assert "Host: api.github.com\r\n" in request
    assert "User-Agent: Blockwart-ReleaseMonitor/1\r\n" in request
    assert "If-None-Match: \"cached\"\r\n" in request
    assert "Authorization:" not in request
    assert "Cookie:" not in request
    assert "Proxy-Authorization:" not in request


@pytest.mark.parametrize(
    "framing",
    ("invalid-delimiter", "incomplete-terminal", "incomplete-trailer"),
)
def test_malformed_chunked_provider_response_never_persists_release_evidence(
    alembic_session_factory,
    monkeypatch,
    framing,
) -> None:
    payload = json.dumps(
        {
            "tag_name": "v9.9.9",
            "draft": False,
            "prerelease": False,
            "published_at": "2026-08-24T12:00:00Z",
        }
    ).encode()
    chunk = f"{len(payload):x}\r\n".encode() + payload
    if framing == "invalid-delimiter":
        body = chunk + b"XX0\r\n\r\n"
    elif framing == "incomplete-terminal":
        body = chunk + b"\r\n0\r\n"
    else:
        body = chunk + b"\r\n0\r\nX-Check: incomplete\r\n"

    class FakeSocket:
        def __init__(self) -> None:
            self.response = bytearray(
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n" + body
            )

        def settimeout(self, _timeout: float) -> None:
            pass

        def send(self, data: bytes) -> int:
            return len(data)

        def recv(self, size: int) -> bytes:
            result = bytes(self.response[:size])
            del self.response[:size]
            return result

        def close(self) -> None:
            pass

    class FakeContext:
        check_hostname = False
        verify_mode = None

        def wrap_socket(self, wrapped, *, server_hostname):
            assert server_hostname == "api.github.com"
            return wrapped

    monkeypatch.setattr(
        github_provider,
        "_resolve",
        lambda *_args, **_kwargs: [ip_address("140.82.121.6")],
    )
    monkeypatch.setattr(
        github_provider.socket,
        "create_connection",
        lambda *_args, **_kwargs: FakeSocket(),
    )
    monkeypatch.setattr(
        github_provider.ssl,
        "create_default_context",
        FakeContext,
    )
    object_id = f"chunked-{framing}"
    with alembic_session_factory() as session:
        upsert_object(session, _service(object_id))
        session.commit()
        result = check_service_release(
            session,
            object_id=object_id,
            settings=ReleaseMonitoringSettings(enabled=True, jitter_seconds=0),
            manual=True,
            now=NOW,
        )
        observation = session.scalar(select(ServiceReleaseObservation))

    assert result.outcome == "error"
    assert result.projection is not None
    assert result.projection["status"] == "error"
    assert result.projection["error_code"] == "provider_failed"
    assert observation is not None
    assert observation.error_code == "provider_failed"
    assert observation.latest_tag is None
    assert observation.latest_version is None
    assert observation.released_at is None
    assert observation.last_success_at is None


@pytest.mark.parametrize(
    ("status", "headers", "expected"),
    [
        (304, [("ETag", '"same"')], "not_modified"),
        (302, [("Location", "https://internal.invalid")], "redirect_not_supported"),
        (404, [], "not_found"),
        (403, [("X-RateLimit-Remaining", "0"), ("Retry-After", "600")], "rate_limited"),
        (403, [("Retry-After", "600")], "rate_limited"),
        (429, [("Retry-After", "600")], "rate_limited"),
        (500, [], "http_server_error"),
    ],
)
def test_provider_http_failures_are_stable(monkeypatch, status, headers, expected) -> None:
    monkeypatch.setattr(
        github_provider,
        "_resolve",
        lambda *_args, **_kwargs: [ip_address("140.82.121.6")],
    )
    monkeypatch.setattr(
        github_provider,
        "_request",
        lambda **_kwargs: (status, headers, b""),
    )
    result = github_provider.fetch_latest_github_release(
        GithubReleaseRequest(
            target=GithubReleaseTarget("example-org", "example-service"),
            etag='"cached"',
            connect_timeout_ms=1000,
            total_timeout_ms=2000,
            max_response_bytes=65536,
        )
    )
    assert result.outcome == ("not_modified" if status == 304 else "error")
    assert result.error_code == (None if status == 304 else expected)
    if expected == "rate_limited":
        assert result.retry_after_seconds == 600


def test_provider_rejects_private_dns_before_socket(monkeypatch) -> None:
    monkeypatch.setattr(
        github_provider,
        "_resolve",
        lambda *_args, **_kwargs: [ip_address("127.0.0.1")],
    )
    monkeypatch.setattr(
        github_provider,
        "_request",
        lambda **_kwargs: pytest.fail("socket request must not run"),
    )
    result = github_provider.fetch_latest_github_release(
        GithubReleaseRequest(
            target=GithubReleaseTarget("example-org", "example-service"),
            etag=None,
            connect_timeout_ms=1000,
            total_timeout_ms=2000,
            max_response_bytes=65536,
        )
    )
    assert result.error_code == "policy_denied"


@pytest.mark.parametrize(
    ("failure", "expected"),
    [(OSError("resolver detail"), "dns_failed"), (TimeoutError(), "timeout")],
)
def test_provider_dns_failures_are_redacted(monkeypatch, failure, expected) -> None:
    def fail(*_args, **_kwargs):
        raise failure

    monkeypatch.setattr(github_provider, "_resolve", fail)
    result = github_provider.fetch_latest_github_release(
        GithubReleaseRequest(
            target=GithubReleaseTarget("example-org", "example-service"),
            etag=None,
            connect_timeout_ms=1000,
            total_timeout_ms=2000,
            max_response_bytes=65536,
        )
    )
    assert result.error_code == expected


@pytest.mark.parametrize(
    ("failure", "expected"),
    [
        (github_provider._GithubFailure("timeout"), "timeout"),
        (github_provider._GithubFailure("connect_failed"), "connect_failed"),
        (github_provider._GithubFailure("tls_failed"), "tls_failed"),
        (github_provider._GithubFailure("response_too_large"), "response_too_large"),
    ],
)
def test_provider_transport_failures_are_redacted(monkeypatch, failure, expected) -> None:
    monkeypatch.setattr(
        github_provider,
        "_resolve",
        lambda *_args, **_kwargs: [ip_address("140.82.121.6")],
    )

    def fail(**_kwargs):
        raise failure

    monkeypatch.setattr(github_provider, "_request", fail)
    result = github_provider.fetch_latest_github_release(
        GithubReleaseRequest(
            target=GithubReleaseTarget("example-org", "example-service"),
            etag=None,
            connect_timeout_ms=1000,
            total_timeout_ms=2000,
            max_response_bytes=65536,
        )
    )
    assert result.outcome == "error"
    assert result.error_code == expected


@pytest.mark.parametrize(
    ("payload", "expected"),
    [
        (b"not-json", "unreadable_release"),
        (b"[]", "unreadable_release"),
        (
            json.dumps(
                {
                    "tag_name": "v1.2.0",
                    "draft": False,
                    "prerelease": True,
                    "published_at": "2026-08-24T12:00:00Z",
                }
            ).encode(),
            "not_a_stable_release",
        ),
    ],
)
def test_provider_rejects_malformed_or_non_stable_payload(monkeypatch, payload, expected) -> None:
    monkeypatch.setattr(
        github_provider,
        "_resolve",
        lambda *_args, **_kwargs: [ip_address("140.82.121.6")],
    )
    monkeypatch.setattr(
        github_provider,
        "_request",
        lambda **_kwargs: (200, [], payload),
    )
    result = github_provider.fetch_latest_github_release(
        GithubReleaseRequest(
            target=GithubReleaseTarget("example-org", "example-service"),
            etag=None,
            connect_timeout_ms=1000,
            total_timeout_ms=2000,
            max_response_bytes=65536,
        )
    )
    assert result.error_code == expected


def test_manual_and_scheduled_checks_share_idempotent_storage(
    alembic_session_factory,
    monkeypatch,
) -> None:
    with alembic_session_factory() as session:
        upsert_object(session, _service("checked"))
        session.commit()
        row = session.get(CatalogObject, "checked")
        assert row is not None
        revision = row.revision
        updated_at = row.updated_at
        audit_count = session.scalar(select(func.count(AuditEvent.id)))
    monkeypatch.setattr(
        release_service, "fetch_latest_github_release", lambda _request: _observed()
    )
    settings = ReleaseMonitoringSettings(
        enabled=True,
        poller_enabled=True,
        jitter_seconds=0,
    )
    with alembic_session_factory() as session:
        first = check_service_release(
            session,
            object_id="checked",
            settings=settings,
            manual=True,
            now=NOW,
        )
        assert first.outcome == "observed"
        assert first.projection is not None
        assert first.projection["status"] == "update_available"
        second = check_service_release(
            session,
            object_id="checked",
            settings=settings,
            manual=True,
            now=NOW + timedelta(seconds=1),
        )
        assert second.skipped_reason == "cooldown"
        row = session.get(CatalogObject, "checked")
        assert row is not None
        assert row.revision == revision
        assert row.updated_at == updated_at
        assert session.scalar(select(func.count(ServiceReleaseObservation.id))) == 1
        assert session.scalar(select(func.count(AuditEvent.id))) == audit_count
        observation = session.scalar(select(ServiceReleaseObservation))
        assert observation is not None
        assert observation.latest_version == "1.2.0"
        assert observation.release_etag == '"release-etag"'


def test_conditional_304_refreshes_success_without_replacing_cached_release(
    alembic_session_factory,
    monkeypatch,
) -> None:
    with alembic_session_factory() as session:
        upsert_object(session, _service("conditional"))
        session.commit()
    seen_etags: list[str | None] = []
    results = [
        _observed(checked_at=NOW),
        ReleaseObservation(
            provider="github_releases",
            outcome="not_modified",
            checked_at=NOW + timedelta(seconds=301),
            etag='"release-etag"',
            http_status=304,
        ),
    ]

    def acquire(request):
        seen_etags.append(request.etag)
        return results.pop(0)

    monkeypatch.setattr(release_service, "fetch_latest_github_release", acquire)
    settings = ReleaseMonitoringSettings(enabled=True, jitter_seconds=0)
    with alembic_session_factory() as session:
        first = check_service_release(
            session, object_id="conditional", settings=settings, manual=True, now=NOW
        )
        second = check_service_release(
            session,
            object_id="conditional",
            settings=settings,
            manual=True,
            now=NOW + timedelta(seconds=301),
        )
        assert first.outcome == "observed"
        assert second.outcome == "not_modified"
        assert second.projection is not None
        assert second.projection["latest_version"] == "1.2.0"
        assert second.projection["last_success_at"] == "2026-08-25T12:05:01.000000Z"
        assert seen_etags == [None, '"release-etag"']
        assert session.scalar(select(func.count(ServiceReleaseObservation.id))) == 1


def test_repository_change_invalidates_cached_release_and_etag(
    alembic_session_factory,
    monkeypatch,
) -> None:
    with alembic_session_factory() as session:
        upsert_object(session, _service("retargeted"))
        session.commit()
    observations = [_observed(checked_at=NOW), _observed("v2.0.0", checked_at=NOW)]
    seen_etags: list[str | None] = []

    def acquire(request):
        seen_etags.append(request.etag)
        return observations.pop(0)

    monkeypatch.setattr(release_service, "fetch_latest_github_release", acquire)
    settings = ReleaseMonitoringSettings(enabled=True, jitter_seconds=0)
    with alembic_session_factory() as session:
        assert check_service_release(
            session, object_id="retargeted", settings=settings, manual=True, now=NOW
        ).outcome == "observed"
        changed = _service("retargeted")
        changed.data["release_monitoring"]["github"]["repo"] = "other-service"
        upsert_object(session, changed)
        session.commit()
        result = check_service_release(
            session,
            object_id="retargeted",
            settings=settings,
            manual=True,
            now=NOW + timedelta(seconds=1),
        )
        assert result.outcome == "observed"
        assert result.projection is not None
        assert result.projection["target"]["slug"] == "example-org/other-service"
        assert result.projection["latest_version"] == "2.0.0"
        assert seen_etags == [None, None]


def test_rate_limit_delay_and_failure_backoff_are_bounded(
    alembic_session_factory,
    monkeypatch,
) -> None:
    with alembic_session_factory() as session:
        upsert_object(session, _service("backoff"))
        session.commit()
    monkeypatch.setattr(
        release_service,
        "fetch_latest_github_release",
        lambda _request: ReleaseObservation(
            provider="github_releases",
            outcome="error",
            checked_at=NOW,
            error_code="rate_limited",
            http_status=429,
            retry_after_seconds=200_000,
        ),
    )
    with alembic_session_factory() as session:
        result = check_service_release(
            session,
            object_id="backoff",
            settings=ReleaseMonitoringSettings(enabled=True, jitter_seconds=0),
            manual=True,
            now=NOW,
        )
        assert result.outcome == "error"
        row = session.scalar(select(ServiceReleaseObservation))
        assert row is not None
        assert row.consecutive_failures == 1
        assert row.next_due_at == (NOW + timedelta(seconds=200_000)).replace(tzinfo=None)


def test_active_lease_prevents_parallel_manual_request(
    alembic_session_factory,
    monkeypatch,
) -> None:
    settings = ReleaseMonitoringSettings(enabled=True, jitter_seconds=0)
    with alembic_session_factory() as session:
        upsert_object(session, _service("leased"))
        session.commit()
        synchronize_release_schedule(session, now=NOW, settings=settings)
        lease = session.scalar(select(ServiceReleaseCheckLease))
        assert lease is not None
        lease.lease_owner = "other-process"
        lease.lease_expires_at = (NOW + timedelta(seconds=60)).replace(tzinfo=None)
        session.commit()
    monkeypatch.setattr(
        release_service,
        "fetch_latest_github_release",
        lambda _request: pytest.fail("active lease must prevent a second request"),
    )
    with alembic_session_factory() as session:
        result = check_service_release(
            session,
            object_id="leased",
            settings=settings,
            manual=True,
            now=NOW,
        )
        assert result.outcome == "skipped"
        assert result.skipped_reason == "already_claimed_or_not_due"


def test_schedule_is_bounded_leased_and_recovers_expiry(
    alembic_session_factory,
    monkeypatch,
) -> None:
    with alembic_session_factory() as session:
        upsert_object(session, _service("scheduled-a"))
        upsert_object(session, _service("scheduled-b"))
        session.commit()
        settings = ReleaseMonitoringSettings(
            enabled=True,
            poller_enabled=True,
            max_checks_per_run=1,
            jitter_seconds=0,
        )
        assert synchronize_release_schedule(session, now=NOW, settings=settings) == 2
        session.commit()
        lease = session.scalar(
            select(ServiceReleaseCheckLease).where(
                ServiceReleaseCheckLease.object_id == "scheduled-a"
            )
        )
        assert lease is not None
        lease.lease_owner = "dead-worker"
        lease.lease_expires_at = (NOW - timedelta(seconds=1)).replace(tzinfo=None)
        session.commit()
    calls: list[str] = []

    def acquire(request):
        calls.append(request.target.slug)
        return _observed()

    monkeypatch.setattr(release_service, "fetch_latest_github_release", acquire)
    monkeypatch.setattr(release_service, "_utcnow", lambda: NOW)
    with alembic_session_factory() as session:
        result = run_due_release_checks(session, settings=settings, now=NOW)
        assert result.released == 1
        assert result.completed == 1
        assert len(calls) == 1


def test_serial_pass_uses_a_fresh_lease_deadline_for_each_claim(
    alembic_session_factory,
    monkeypatch,
) -> None:
    first = _service("scheduled-a")
    first.data["release_monitoring"]["github"]["repo"] = "scheduled-a"
    second = _service("scheduled-b")
    second.data["release_monitoring"]["github"]["repo"] = "scheduled-b"
    settings = ReleaseMonitoringSettings(
        enabled=True,
        poller_enabled=True,
        max_checks_per_run=2,
        lease_seconds=60,
        jitter_seconds=0,
    )
    with alembic_session_factory() as session:
        upsert_object(session, first)
        upsert_object(session, second)
        session.commit()

    claim_times = iter((NOW, NOW + timedelta(seconds=55)))
    monkeypatch.setattr(release_service, "_utcnow", lambda: next(claim_times))
    calls: list[str] = []
    competing_results = []

    def acquire(request):
        calls.append(request.target.slug)
        if len(calls) == 2:
            later_object_id = request.target.repo
            with alembic_session_factory() as competing_session:
                competing_results.append(
                    check_service_release(
                        competing_session,
                        object_id=later_object_id,
                        settings=settings,
                        manual=False,
                        now=NOW + timedelta(seconds=70),
                        owner="competing-worker",
                    )
                )
        return _observed(checked_at=NOW + timedelta(seconds=55 * (len(calls) - 1)))

    monkeypatch.setattr(release_service, "fetch_latest_github_release", acquire)
    with alembic_session_factory() as session:
        result = run_due_release_checks(
            session,
            settings=settings,
            now=NOW,
            owner="serial-worker",
        )

    assert result.completed == 2
    assert calls == ["example-org/scheduled-a", "example-org/scheduled-b"]
    assert len(competing_results) == 1
    assert competing_results[0].outcome == "skipped"
    assert competing_results[0].skipped_reason == "already_claimed_or_not_due"


def test_overview_filters_after_authorization_without_hidden_counts(
    alembic_session_factory,
) -> None:
    with alembic_session_factory() as session:
        upsert_object(session, _service("visible"))
        upsert_object(session, _service("stub"))
        upsert_object(session, _service("concealed"))
        session.commit()
        page = query_release_overview(
            session,
            _access("visible", discoverable=("stub",)),
            include_total=True,
            now=NOW,
        )
        assert [item.object_id for item in page.items] == ["visible"]
        assert page.total == 1
        assert "stub" not in (page.next_cursor or "")
        assert "concealed" not in (page.next_cursor or "")


@pytest.mark.parametrize(
    ("language", "message", "running_version_label"),
    [
        ("en", "Release monitoring is not configured.", "Running version"),
        ("de", "Release-Monitoring ist nicht konfiguriert.", "Laufende Version"),
    ],
)
def test_unconfigured_release_monitoring_detail_is_localized_and_neutral(
    alembic_session_factory,
    install_unrestricted_read_access,
    language,
    message,
    running_version_label,
) -> None:
    object_id = f"unconfigured-release-{language}"
    with alembic_session_factory() as session:
        upsert_object(
            session,
            CatalogObjectIn(
                id=object_id,
                kind="service",
                label="Unconfigured release monitoring",
                lifecycle="active",
                health="healthy",
                data={
                    "schema_version": 1,
                    "service_information": {"running_version": "4.5.6"},
                },
            ),
        )
        session.commit()
    app = create_app(Settings())
    install_unrestricted_read_access(app)

    def override_get_session():
        with alembic_session_factory() as session:
            yield session

    app.dependency_overrides[get_session] = override_get_session
    with TestClient(app) as client:
        detail = client.get(f"/objects/{object_id}?lang={language}")
        editor = client.get(
            f"/objects/{object_id}?lang={language}&edit=release-monitoring"
        )
        rest = client.get("/api/v1/objects", params={"q": object_id})

    assert detail.status_code == 200
    release_panel = detail.text.split(
        'aria-labelledby="release-monitoring-title"', maxsplit=1
    )[1].split("</section>", maxsplit=1)[0]
    assert message in release_panel
    assert running_version_label in release_panel
    assert "<code>4.5.6</code>" in release_panel
    assert "release_monitoring." not in detail.text
    assert editor.status_code == 200
    assert 'name="release_monitoring_enabled"' in editor.text
    assert rest.status_code == 200
    assert rest.json()["items"][0]["release_monitoring"] is None


def test_ui_and_rest_publish_the_same_release_projection_in_english_and_german(
    alembic_session_factory,
    install_unrestricted_read_access,
    monkeypatch,
) -> None:
    with alembic_session_factory() as session:
        upsert_object(session, _service("ui-release"))
        session.commit()
    monkeypatch.setattr(
        release_service, "fetch_latest_github_release", lambda _request: _observed()
    )
    app = create_app(
        Settings(
            release_monitoring_enabled=True,
            release_monitoring_poller_enabled=False,
        )
    )
    install_unrestricted_read_access(app)

    def override_get_session():
        with alembic_session_factory() as session:
            yield session

    app.dependency_overrides[get_session] = override_get_session
    with TestClient(app) as client:
        detail = client.get("/objects/ui-release?lang=en")
        assert detail.status_code == 200
        assert "GitHub release monitoring" in detail.text
        checked = client.post(
            "/objects/ui-release/release-check",
            follow_redirects=False,
        )
        assert checked.status_code == 303
        rest = client.get("/api/v1/objects", params={"q": "ui-release"})
        assert rest.status_code == 200
        projected = rest.json()["items"][0]["release_monitoring"]
        assert projected["status"] == "update_available"
        overview = client.get("/release-updates?lang=en")
        assert "Update available" in overview.text
        german = client.get("/objects/ui-release?lang=de")
        assert "GitHub-Release-Monitoring" in german.text
        assert "Update verfügbar" in german.text
