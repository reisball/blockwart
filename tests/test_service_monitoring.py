from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from ipaddress import ip_address

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError
from sqlalchemy import func, select

import blockwart.services.agent as agent_service
import blockwart.services.monitoring as monitoring_service
import blockwart.services.monitoring_probe as monitoring_probe
from blockwart.api.deps import get_session
from blockwart.config import Settings
from blockwart.domain.auth import Permission, PrincipalContext, PrincipalType
from blockwart.domain.monitoring import (
    MonitoringObservation,
    MonitoringRecord,
    freshness_for,
    monitoring_view,
    read_monitoring_config,
    resolve_monitoring_target,
)
from blockwart.domain.monitoring_policy import (
    MonitoringPolicyError,
    TargetPolicy,
    parse_target_policy,
)
from blockwart.main import create_app
from blockwart.mcp.server import call_tool
from blockwart.models import (
    AuditEvent,
    CatalogObject,
    ServiceCheckLease,
    ServiceObservation,
)
from blockwart.schemas.catalog import CatalogObjectIn
from blockwart.services.agent import get_agent_object_context
from blockwart.services.catalog import upsert_object
from blockwart.services.monitoring import (
    MonitoringSettings,
    claim_due_checks,
    load_observation_index,
    monitoring_projection,
    record_service_observation,
    run_due_service_checks,
    synchronize_check_schedule,
)
from blockwart.services.monitoring_registry import ProbeLimits, ProviderCheckRequest
from blockwart.services.policy import PolicySnapshot
from blockwart.services.read_access import ReadAccess

NOW = datetime(2026, 8, 18, 12, 0, tzinfo=UTC)


def _service(
    object_id: str,
    *,
    monitoring: dict | None = None,
    endpoints: list[dict] | None = None,
    health: str = "unknown",
) -> CatalogObjectIn:
    data: dict = {"schema_version": 1}
    if monitoring is not None:
        data["monitoring"] = monitoring
    if endpoints is not None:
        data["endpoints"] = endpoints
    return CatalogObjectIn(
        id=object_id,
        kind="service",
        label=object_id,
        lifecycle="active",
        health=health,
        data=data,
    )


def _endpoint(
    *,
    endpoint_id: str = "web",
    url: str = "https://status.example.invalid:8443/app",
    health_url: str | None = None,
) -> dict:
    endpoint = {
        "id": endpoint_id,
        "type": "Web",
        "url": url,
        "protocol": "https",
        "port": 8443,
    }
    if health_url is not None:
        endpoint["health_url"] = health_url
    return endpoint


def _store_monitoring_document(
    row: CatalogObject,
    document: object,
) -> None:
    data = json.loads(row.data_json)
    data["monitoring"] = document
    row.data_json = json.dumps(data, ensure_ascii=False, sort_keys=True)


def test_monitoring_configuration_is_opt_in_bounded_and_secret_safe() -> None:
    absent = read_monitoring_config({"schema_version": 1})
    assert absent.enabled is False
    assert absent.provider == "builtin_http"
    assert absent.interval_seconds == 300
    assert absent.valid is True
    assert "monitoring" not in _service("legacy").data

    configured = _service(
        "configured",
        monitoring={
            "enabled": True,
            "provider": "builtin_http",
            "interval_seconds": 60,
        },
    )
    assert configured.data["monitoring"]["interval_seconds"] == 60

    for interval in (59, 86401):
        with pytest.raises(ValidationError):
            _service(
                f"invalid-{interval}",
                monitoring={"enabled": True, "interval_seconds": interval},
            )
    with pytest.raises(ValidationError):
        _service("missing-enabled", monitoring={"provider": "builtin_http"})
    with pytest.raises(ValidationError):
        _service(
            "secret-target",
            endpoints=[_endpoint(health_url="https://operator:password@example.invalid/health")],
        )
    with pytest.raises(ValidationError):
        _service(
            "secret-query-target",
            endpoints=[
                _endpoint(health_url="https://example.invalid/health?token=forbidden")
            ],
        )


@pytest.mark.parametrize(
    "document",
    [
        {"enabled": True, "provider": "unknown"},
        {"enabled": True, "provider": 7},
        {"enabled": True, "interval_seconds": 59},
        {"enabled": True, "interval_seconds": "60"},
        {"enabled": True, "interval_seconds": True},
        {"enabled": "true"},
        {"enabled": True, "unexpected": "value"},
    ],
)
def test_present_malformed_monitoring_configuration_has_one_fail_closed_view(
    document,
) -> None:
    config = read_monitoring_config({"schema_version": 1, "monitoring": document})
    assert config.valid is False
    assert config.provider is None
    assert config.interval_seconds is None

    view = monitoring_view(
        data={
            "schema_version": 1,
            "monitoring": document,
            "endpoints": [_endpoint()],
        },
        object_id="malformed",
        catalog_health="healthy",
        record=None,
        now=NOW,
    )
    assert view == {
        "enabled": document.get("enabled") is True,
        "provider": None,
        "interval_seconds": None,
        "interval_overridden": False,
        "target": None,
        "diagnostic": "invalid_monitoring_config",
        "state": "check_error",
        "observed_state": "unknown",
        "freshness": "pending",
        "http_status": None,
        "latency_ms": None,
        "error_code": None,
        "last_checked_at": None,
        "last_success_at": None,
        "next_due_at": None,
        "effective_health": (
            "unknown" if document.get("enabled") is True else "healthy"
        ),
    }


def test_absent_and_explicitly_disabled_monitoring_remain_valid_and_unscheduled(
    alembic_session_factory,
) -> None:
    absent = read_monitoring_config({"schema_version": 1})
    disabled = read_monitoring_config(
        {"schema_version": 1, "monitoring": {"enabled": False}}
    )
    assert (absent.valid, absent.enabled, absent.provider, absent.interval_seconds) == (
        True,
        False,
        "builtin_http",
        300,
    )
    assert (disabled.valid, disabled.enabled, disabled.provider, disabled.interval_seconds) == (
        True,
        False,
        "builtin_http",
        300,
    )

    with alembic_session_factory() as session:
        upsert_object(session, _service("absent"))
        upsert_object(
            session,
            _service("disabled", monitoring={"enabled": False}),
        )
        session.commit()
        assert synchronize_check_schedule(
            session,
            now=NOW,
            settings=MonitoringSettings(jitter_seconds=0),
        ) == 0
        assert session.scalar(select(func.count(ServiceCheckLease.id))) == 0


def test_target_resolution_is_explicit_then_exactly_one_complete_endpoint() -> None:
    explicit = resolve_monitoring_target(
        {
            "schema_version": 1,
            "endpoints": [
                _endpoint(health_url="https://health.example.invalid:9443/ready?full=true"),
                {
                    "id": "ssh",
                    "type": "SSH",
                    "host": "admin.example.invalid",
                    "port": 22,
                    "protocol": "ssh",
                },
            ],
        },
        object_id="explicit",
    )
    assert explicit.diagnostic is None
    assert explicit.target is not None
    assert explicit.target.url == "https://health.example.invalid:9443/ready?full=true"
    assert explicit.target.source == "endpoint_health_url"

    derived = resolve_monitoring_target(
        {"schema_version": 1, "endpoints": [_endpoint()]},
        object_id="derived",
    )
    assert derived.target is not None
    assert derived.target.url == "https://status.example.invalid:8443/health"
    assert derived.target.source == "derived_health_path"

    ambiguous_health = resolve_monitoring_target(
        {
            "schema_version": 1,
            "endpoints": [
                _endpoint(
                    endpoint_id="one",
                    url="https://one.example.invalid:8443",
                    health_url="https://one.example.invalid/health",
                ),
                _endpoint(
                    endpoint_id="two",
                    url="https://two.example.invalid:8443",
                    health_url="https://two.example.invalid/health",
                ),
            ],
        },
        object_id="ambiguous-health",
    )
    assert ambiguous_health.target is None
    assert ambiguous_health.diagnostic == "ambiguous_health_url"

    ambiguous_derived = resolve_monitoring_target(
        {
            "schema_version": 1,
            "endpoints": [
                _endpoint(endpoint_id="one"),
                _endpoint(endpoint_id="two", url="https://other.example.invalid:8443"),
            ],
        },
        object_id="ambiguous-derived",
    )
    assert ambiguous_derived.target is None
    assert ambiguous_derived.diagnostic == "ambiguous_endpoints"

    missing = resolve_monitoring_target({"schema_version": 1}, object_id="missing")
    assert missing.target is None
    assert missing.diagnostic == "no_http_endpoint"


def test_freshness_and_maintenance_precedence_keep_last_observation() -> None:
    checked = NOW - timedelta(seconds=30)
    record = MonitoringRecord(
        provider="builtin_http",
        state="down",
        http_status=503,
        latency_ms=40,
        error_code="http_server_error",
        last_checked_at=checked,
        last_success_at=NOW - timedelta(hours=1),
        next_due_at=NOW + timedelta(seconds=30),
    )
    assert freshness_for(record, interval_seconds=60, now=NOW) == "fresh"
    assert freshness_for(record, interval_seconds=60, now=NOW + timedelta(seconds=31)) == "stale"

    view = monitoring_view(
        data={
            "schema_version": 1,
            "monitoring": {"enabled": True, "interval_seconds": 60},
            "endpoints": [_endpoint()],
        },
        object_id="maintenance",
        catalog_health="maintenance",
        record=record,
        now=NOW,
    )
    assert view["state"] == "down"
    assert view["observed_state"] == "down"
    assert view["effective_health"] == "maintenance"
    assert view["http_status"] == 503

    stale = monitoring_view(
        data={
            "schema_version": 1,
            "monitoring": {"enabled": True, "interval_seconds": 60},
            "endpoints": [_endpoint()],
        },
        object_id="stale",
        catalog_health="healthy",
        record=record,
        now=NOW + timedelta(minutes=2),
    )
    assert stale["freshness"] == "stale"
    assert stale["state"] == "unknown"
    assert stale["observed_state"] == "down"
    assert stale["effective_health"] == "unknown"


def test_target_policy_is_deny_by_default_and_requires_specific_private_allow() -> None:
    empty = parse_target_policy(allowed_networks="", allowed_ports="80,443")
    assert empty.check_address(ip_address("8.8.8.8")) == "allowlist_empty"

    public = parse_target_policy(
        allowed_networks="0.0.0.0/0,::/0",
        allowed_ports="443",
    )
    assert public.check_address(ip_address("8.8.8.8")) is None
    assert public.check_address(ip_address("127.0.0.1")) == "special_purpose_address"
    assert public.check_address(ip_address("169.254.169.254")) == ("special_purpose_address")
    assert public.check_address(ip_address("10.2.3.4")) == "special_purpose_address"
    assert public.check_address(ip_address("::1")) == "special_purpose_address"

    private = parse_target_policy(
        allowed_networks="10.2.0.0/16",
        allowed_ports="8443",
    )
    assert private.check_address(ip_address("10.2.3.4")) is None
    assert private.check_port(443) == "port_not_allowed"
    assert (
        private.check_target(
            scheme="https",
            port=8443,
            addresses=[ip_address("10.2.3.4"), ip_address("127.0.0.1")],
        )
        == "not_allowlisted"
    )

    with pytest.raises(MonitoringPolicyError):
        parse_target_policy(allowed_networks="not-a-network", allowed_ports="443")


def test_probe_never_resolves_denied_targets_and_pins_allowed_address(monkeypatch) -> None:
    resolution = resolve_monitoring_target(
        {"schema_version": 1, "endpoints": [_endpoint()]},
        object_id="probe",
    )
    assert resolution.target is not None

    def forbidden_resolve(_host: str, _port: int, *, timeout: float):
        raise AssertionError("DNS must not run under an empty allowlist")

    monkeypatch.setattr(monitoring_probe, "_resolve", forbidden_resolve)
    denied = monitoring_probe.probe_http_target(
        ProviderCheckRequest(
            object_id="probe",
            target=resolution.target,
            diagnostic=None,
            limits=ProbeLimits(policy=TargetPolicy()),
        )
    )
    assert denied.state == "check_error"
    assert denied.error_code == "policy_denied"

    concrete = ip_address("203.0.113.9")
    monkeypatch.setattr(
        monitoring_probe,
        "_resolve",
        lambda _host, _port, *, timeout: [concrete],
    )
    connected: dict[str, object] = {}

    def fake_request_status(**kwargs):
        connected.update(kwargs)
        return 503

    monkeypatch.setattr(monitoring_probe, "_request_status", fake_request_status)
    allowed = monitoring_probe.probe_http_target(
        ProviderCheckRequest(
            object_id="probe",
            target=resolution.target,
            diagnostic=None,
            limits=ProbeLimits(
                policy=parse_target_policy(
                    allowed_networks="203.0.113.0/24",
                    allowed_ports="8443",
                )
            ),
        )
    )
    assert connected["pinned"] == concrete
    assert connected["hostname"] == "status.example.invalid"
    assert allowed.state == "down"
    assert allowed.http_status == 503
    assert allowed.error_code == "http_server_error"


def test_probe_dns_deadline_is_a_redacted_timeout(monkeypatch) -> None:
    resolution = resolve_monitoring_target(
        {"schema_version": 1, "endpoints": [_endpoint()]},
        object_id="dns-timeout",
    )
    assert resolution.target is not None

    def timed_out(_host: str, _port: int, *, timeout: float):
        assert timeout == pytest.approx(1.0)
        raise TimeoutError("resolver detail that must never escape")

    monkeypatch.setattr(monitoring_probe, "_resolve", timed_out)
    result = monitoring_probe.probe_http_target(
        ProviderCheckRequest(
            object_id="dns-timeout",
            target=resolution.target,
            diagnostic=None,
            limits=ProbeLimits(
                policy=parse_target_policy(
                    allowed_networks="203.0.113.0/24",
                    allowed_ports="8443",
                ),
                connect_timeout_ms=1000,
                total_timeout_ms=2000,
            ),
        )
    )

    assert result.state == "down"
    assert result.error_code == "timeout"


@pytest.mark.parametrize(
    ("status", "state", "error_code"),
    [
        (204, "healthy", None),
        (302, "check_error", "redirect_not_supported"),
        (404, "check_error", "http_client_error"),
        (503, "down", "http_server_error"),
    ],
)
def test_http_status_semantics_are_normalized(status, state, error_code) -> None:
    assert monitoring_probe._classify(status) == (state, error_code)


def test_probe_total_deadline_cannot_be_extended_by_trickle_io() -> None:
    with pytest.raises(TimeoutError):
        monitoring_probe._remaining(0.0)


def test_http_exchange_uses_only_original_host_and_safe_headers(monkeypatch) -> None:
    class FakeSocket:
        def __init__(self) -> None:
            self.sent = bytearray()
            self.recv_sizes: list[int] = []
            self.response = (
                b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n"
                b"body-must-remain-unread"
            )

        def settimeout(self, _timeout: float) -> None:
            pass

        def send(self, payload) -> int:
            self.sent.extend(payload)
            return len(payload)

        def recv(self, size: int) -> bytes:
            self.recv_sizes.append(size)
            response, self.response = self.response[:size], self.response[size:]
            return response

        def close(self) -> None:
            pass

    sock = FakeSocket()
    connected: dict[str, object] = {}

    def fake_connect(address, *, timeout):
        connected.update(address=address, timeout=timeout)
        return sock

    monkeypatch.setattr(monitoring_probe.socket, "create_connection", fake_connect)
    status = monitoring_probe._request_status(
        scheme="http",
        hostname="service.example.invalid",
        pinned=ip_address("203.0.113.10"),
        port=8080,
        path="/health?full=true",
        connect_timeout=1,
        total_timeout=2,
        max_response_bytes=1024,
    )

    request = bytes(sock.sent).decode("ascii")
    assert status == 204
    assert connected["address"] == ("203.0.113.10", 8080)
    assert request.startswith("GET /health?full=true HTTP/1.1\r\n")
    assert "Host: service.example.invalid:8080\r\n" in request
    assert "Authorization:" not in request
    assert "Cookie:" not in request
    assert "Proxy-Authorization:" not in request
    assert set(sock.recv_sizes) == {1}
    assert sock.response == b"body-must-remain-unread"


def test_http_exchange_enforces_declared_response_limit(monkeypatch) -> None:
    class FakeSocket:
        response = bytearray(
            b"HTTP/1.1 200 OK\r\nContent-Length: 2048\r\n\r\nignored"
        )

        def settimeout(self, _timeout: float) -> None:
            pass

        def send(self, payload) -> int:
            return len(payload)

        def recv(self, size: int) -> bytes:
            result = bytes(self.response[:size])
            del self.response[:size]
            return result

        def close(self) -> None:
            pass

    monkeypatch.setattr(
        monitoring_probe.socket,
        "create_connection",
        lambda _address, *, timeout: FakeSocket(),
    )
    with pytest.raises(monitoring_probe._ProbeFailure) as failure:
        monitoring_probe._request_status(
            scheme="http",
            hostname="service.example.invalid",
            pinned=ip_address("203.0.113.10"),
            port=8080,
            path="/health",
            connect_timeout=1,
            total_timeout=2,
            max_response_bytes=1024,
        )
    assert failure.value.state == "check_error"
    assert failure.value.error_code == "response_too_large"


def test_https_pin_keeps_original_tls_identity(monkeypatch) -> None:
    class FakeSocket:
        response = bytearray(b"HTTP/1.1 204 No Content\r\n\r\n")

        def settimeout(self, _timeout: float) -> None:
            pass

        def send(self, payload) -> int:
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
    monkeypatch.setattr(monitoring_probe.socket, "create_connection", fake_connect)
    monkeypatch.setattr(
        monitoring_probe.ssl,
        "create_default_context",
        lambda: context,
    )

    assert (
        monitoring_probe._request_status(
            scheme="https",
            hostname="service.example.invalid",
            pinned=ip_address("203.0.113.10"),
            port=443,
            path="/health",
            connect_timeout=1,
            total_timeout=2,
            max_response_bytes=1024,
        )
        == 204
    )
    assert connected["address"] == ("203.0.113.10", 443)
    assert tls == {"socket": sock, "server_hostname": "service.example.invalid"}
    assert context.check_hostname is True
    assert context.verify_mode == monitoring_probe.ssl.CERT_REQUIRED


def test_observation_ingestion_is_instance_scoped_monotone_and_catalog_neutral(
    alembic_session_factory,
) -> None:
    with alembic_session_factory() as session:
        service = upsert_object(
            session,
            _service(
                "observed",
                monitoring={"enabled": True},
                endpoints=[_endpoint()],
            ),
        )
        session.commit()
        stored_service = session.get(CatalogObject, service.id)
        assert stored_service is not None
        revision = stored_service.revision
        updated_at = stored_service.updated_at
        audit_count = session.scalar(select(func.count(AuditEvent.id)))

        first = record_service_observation(
            session,
            object_id="observed",
            object_instance_id=stored_service.instance_id,
            observation=MonitoringObservation(
                provider="builtin_http",
                state="healthy",
                checked_at=NOW,
                http_status=204,
                latency_ms=12,
            ),
            now=NOW,
            settings=MonitoringSettings(jitter_seconds=0),
        )
        assert first is not None
        older = record_service_observation(
            session,
            object_id="observed",
            object_instance_id=stored_service.instance_id,
            observation=MonitoringObservation(
                provider="builtin_http",
                state="down",
                checked_at=NOW - timedelta(minutes=1),
                error_code="timeout",
            ),
            now=NOW,
            settings=MonitoringSettings(jitter_seconds=0),
        )
        session.commit()

        assert older is not None
        assert older.state == "healthy"
        assert older.last_checked_at == NOW
        row = session.get(CatalogObject, "observed")
        assert row is not None
        assert row.revision == revision
        assert row.updated_at == updated_at
        assert session.scalar(select(func.count(AuditEvent.id))) == audit_count
        assert session.scalar(select(func.count(ServiceObservation.id))) == 1

        old_instance = row.instance_id
        session.delete(row)
        session.commit()
        replacement = upsert_object(
            session,
            _service(
                "observed",
                monitoring={"enabled": True},
                endpoints=[_endpoint()],
            ),
        )
        session.commit()
        replacement_row = session.get(CatalogObject, replacement.id)
        assert replacement_row is not None
        assert replacement_row.instance_id != old_instance
        delayed = record_service_observation(
            session,
            object_id="observed",
            object_instance_id=old_instance,
            observation=MonitoringObservation(
                provider="builtin_http",
                state="down",
                checked_at=NOW + timedelta(minutes=1),
                error_code="timeout",
            ),
            now=NOW + timedelta(minutes=1),
            settings=MonitoringSettings(jitter_seconds=0),
        )
        assert delayed is None
        assert load_observation_index(session) == {}


def test_scheduler_records_invalid_config_without_acquisition_and_avoids_restart_storm(
    alembic_session_factory,
    monkeypatch,
) -> None:
    with alembic_session_factory() as session:
        invalid = upsert_object(
            session,
            _service("invalid-target", monitoring={"enabled": True}),
        )
        healthy = upsert_object(
            session,
            _service(
                "scheduled",
                monitoring={"enabled": True},
                endpoints=[_endpoint()],
            ),
        )
        session.commit()
        before = {}
        for result in (invalid, healthy):
            row = session.get(CatalogObject, result.id)
            assert row is not None
            before[row.id] = (row.revision, row.updated_at)

        acquired_ids: list[str] = []

        def fake_acquire(requests, *, max_workers):
            assert max_workers == 2
            acquired_ids.extend(entry[0].object_id for entry in requests)
            return [
                MonitoringObservation(
                    provider=entry[0].provider,
                    state="healthy",
                    checked_at=NOW,
                    http_status=200,
                    latency_ms=5,
                )
                for entry in requests
            ]

        monkeypatch.setattr(monitoring_service, "_acquire", fake_acquire)
        settings = MonitoringSettings(
            poller_enabled=True,
            policy=parse_target_policy(
                allowed_networks="203.0.113.0/24",
                allowed_ports="8443",
            ),
            max_concurrent_checks=2,
            jitter_seconds=0,
        )
        first = run_due_service_checks(
            session,
            settings=settings,
            now=NOW,
            owner="worker-one",
        )
        assert first.claimed == 2
        assert first.completed == 2
        assert acquired_ids == ["scheduled"]

        observations = load_observation_index(session)
        assert observations[("invalid-target", "builtin_http")].state == "check_error"
        assert observations[("invalid-target", "builtin_http")].error_code == ("invalid_target")
        assert observations[("scheduled", "builtin_http")].state == "healthy"

        second = run_due_service_checks(
            session,
            settings=settings,
            now=NOW + timedelta(seconds=1),
            owner="worker-two",
        )
        assert second.claimed == 0
        assert second.completed == 0
        assert acquired_ids == ["scheduled"]
        for object_id, expected in before.items():
            row = session.get(CatalogObject, object_id)
            assert row is not None
            assert (row.revision, row.updated_at) == expected


def test_malformed_enabled_rows_are_never_ingested_scheduled_claimed_or_acquired(
    alembic_session_factory,
    monkeypatch,
) -> None:
    settings = MonitoringSettings(
        poller_enabled=True,
        jitter_seconds=0,
        max_concurrent_checks=3,
    )
    malformed = {
        "bad-provider": {"enabled": True, "provider": "other"},
        "bad-interval": {"enabled": True, "interval_seconds": "60"},
        "bad-type": {"enabled": True, "provider": ["builtin_http"]},
    }
    with alembic_session_factory() as session:
        instances: dict[str, str] = {}
        for object_id in malformed:
            upsert_object(
                session,
                _service(
                    object_id,
                    monitoring={"enabled": True},
                    endpoints=[_endpoint()],
                ),
            )
            row = session.get(CatalogObject, object_id)
            assert row is not None
            instances[object_id] = row.instance_id
        session.commit()
        assert synchronize_check_schedule(session, now=NOW, settings=settings) == 3
        session.commit()

        for object_id, document in malformed.items():
            row = session.get(CatalogObject, object_id)
            assert row is not None
            _store_monitoring_document(row, document)
        session.commit()
        before = {
            row.id: (row.revision, row.updated_at)
            for row in session.scalars(select(CatalogObject)).all()
        }
        audit_count = session.scalar(select(func.count(AuditEvent.id)))

        def forbidden_acquire(*_args, **_kwargs):
            raise AssertionError("malformed configuration must never acquire")

        monkeypatch.setattr(monitoring_service, "_acquire", forbidden_acquire)
        result = run_due_service_checks(
            session,
            settings=settings,
            now=NOW,
            owner="fail-closed",
        )
        assert result.claimed == 0
        assert result.completed == 0
        assert session.scalar(select(func.count(ServiceCheckLease.id))) == 0
        assert session.scalar(select(func.count(ServiceObservation.id))) == 0

        for object_id, instance_id in instances.items():
            assert record_service_observation(
                session,
                object_id=object_id,
                object_instance_id=instance_id,
                observation=MonitoringObservation(
                    provider="builtin_http",
                    state="healthy",
                    checked_at=NOW,
                    http_status=204,
                ),
                now=NOW,
                settings=settings,
            ) is None
        session.commit()
        assert session.scalar(select(func.count(ServiceObservation.id))) == 0
        assert session.scalar(select(func.count(AuditEvent.id))) == audit_count
        for object_id, expected in before.items():
            row = session.get(CatalogObject, object_id)
            assert row is not None
            assert (row.revision, row.updated_at) == expected


def test_interval_changes_reconcile_observation_and_lease_due_times_immediately(
    alembic_session_factory,
) -> None:
    settings = MonitoringSettings(poller_enabled=True, jitter_seconds=0)
    with alembic_session_factory() as session:
        for object_id, interval in (("shorter", 600), ("longer", 60)):
            upsert_object(
                session,
                _service(
                    object_id,
                    monitoring={"enabled": True, "interval_seconds": interval},
                    endpoints=[_endpoint()],
                ),
            )
            row = session.get(CatalogObject, object_id)
            assert row is not None
            assert record_service_observation(
                session,
                object_id=object_id,
                object_instance_id=row.instance_id,
                observation=MonitoringObservation(
                    provider="builtin_http",
                    state="healthy",
                    checked_at=NOW,
                    http_status=204,
                ),
                now=NOW,
                settings=settings,
            ) is not None
        session.commit()
        assert synchronize_check_schedule(
            session,
            now=NOW,
            settings=settings,
        ) == 2
        session.commit()

        shorter = session.get(CatalogObject, "shorter")
        longer = session.get(CatalogObject, "longer")
        assert shorter is not None and longer is not None
        _store_monitoring_document(
            shorter,
            {"enabled": True, "interval_seconds": 60},
        )
        _store_monitoring_document(
            longer,
            {"enabled": True, "interval_seconds": 600},
        )
        session.commit()

        synchronize_check_schedule(
            session,
            now=NOW + timedelta(seconds=100),
            settings=settings,
        )
        session.commit()
        leases = {
            row.object_id: row
            for row in session.scalars(select(ServiceCheckLease)).all()
        }
        observations = {
            row.object_id: row
            for row in session.scalars(select(ServiceObservation)).all()
        }
        assert leases["shorter"].due_at == (NOW + timedelta(seconds=60)).replace(
            tzinfo=None
        )
        assert observations["shorter"].next_due_at == leases["shorter"].due_at
        assert leases["longer"].due_at == (NOW + timedelta(seconds=600)).replace(
            tzinfo=None
        )
        assert observations["longer"].next_due_at == leases["longer"].due_at

        claims = claim_due_checks(
            session,
            owner="interval-worker",
            now=NOW + timedelta(seconds=100),
            settings=settings,
        )
        assert [claim.object_id for claim in claims] == ["shorter"]


def test_default_interval_reconciles_only_services_without_an_override(
    alembic_session_factory,
) -> None:
    old_settings = MonitoringSettings(
        poller_enabled=True,
        default_interval_seconds=300,
        jitter_seconds=0,
    )
    new_settings = MonitoringSettings(
        poller_enabled=True,
        default_interval_seconds=600,
        jitter_seconds=0,
    )
    with alembic_session_factory() as session:
        for object_id, document in (
            ("defaulted", {"enabled": True}),
            ("overridden", {"enabled": True, "interval_seconds": 120}),
        ):
            upsert_object(
                session,
                _service(object_id, monitoring=document, endpoints=[_endpoint()]),
            )
            row = session.get(CatalogObject, object_id)
            assert row is not None
            record_service_observation(
                session,
                object_id=object_id,
                object_instance_id=row.instance_id,
                observation=MonitoringObservation(
                    provider="builtin_http",
                    state="healthy",
                    checked_at=NOW,
                    http_status=204,
                ),
                now=NOW,
                settings=old_settings,
            )
        session.commit()
        synchronize_check_schedule(session, now=NOW, settings=old_settings)
        session.commit()

        observations = load_observation_index(session)
        defaulted = session.get(CatalogObject, "defaulted")
        assert defaulted is not None
        view = monitoring_projection(
            kind="service",
            object_id=defaulted.id,
            data=json.loads(defaulted.data_json),
            catalog_health=defaulted.health,
            observations=observations,
            now=NOW + timedelta(seconds=30),
            settings=new_settings,
        )
        assert view is not None
        assert view["next_due_at"] == "2026-08-18T12:10:00.000000Z"
        assert view["freshness"] == "fresh"

        synchronize_check_schedule(
            session,
            now=NOW + timedelta(seconds=30),
            settings=new_settings,
        )
        session.commit()
        due = {
            row.object_id: row.due_at
            for row in session.scalars(select(ServiceCheckLease)).all()
        }
        assert due["defaulted"] == (NOW + timedelta(seconds=600)).replace(tzinfo=None)
        assert due["overridden"] == (NOW + timedelta(seconds=120)).replace(tzinfo=None)


def test_post_claim_recheck_blocks_a_stale_short_interval_race(
    alembic_session_factory,
    monkeypatch,
) -> None:
    old_settings = MonitoringSettings(
        poller_enabled=True,
        jitter_seconds=0,
    )
    with alembic_session_factory() as session:
        upsert_object(
            session,
            _service(
                "claim-race",
                monitoring={"enabled": True, "interval_seconds": 60},
                endpoints=[_endpoint()],
            ),
        )
        row = session.get(CatalogObject, "claim-race")
        assert row is not None
        record_service_observation(
            session,
            object_id=row.id,
            object_instance_id=row.instance_id,
            observation=MonitoringObservation(
                provider="builtin_http",
                state="healthy",
                checked_at=NOW,
                http_status=204,
            ),
            now=NOW,
            settings=old_settings,
        )
        session.commit()
        synchronize_check_schedule(session, now=NOW, settings=old_settings)
        session.commit()

        row = session.get(CatalogObject, "claim-race")
        assert row is not None
        _store_monitoring_document(
            row,
            {"enabled": True, "interval_seconds": 600},
        )
        session.commit()

        # Simulate another process claiming the old due row immediately before
        # this process's normal reconciliation commits.
        monkeypatch.setattr(
            monitoring_service,
            "synchronize_check_schedule",
            lambda *_args, **_kwargs: 0,
        )

        def empty_acquire(requests, *, max_workers):
            assert requests == []
            assert max_workers == old_settings.max_concurrent_checks
            return []

        monkeypatch.setattr(monitoring_service, "_acquire", empty_acquire)
        result = run_due_service_checks(
            session,
            settings=old_settings,
            now=NOW + timedelta(seconds=100),
            owner="racing-process",
        )
        assert result.claimed == 1
        assert result.completed == 0
        lease = session.scalar(select(ServiceCheckLease))
        observation = session.scalar(select(ServiceObservation))
        expected = (NOW + timedelta(seconds=600)).replace(tzinfo=None)
        assert lease is not None and lease.due_at == expected
        assert lease.lease_owner is None
        assert observation is not None and observation.next_due_at == expected


def test_jittered_expired_schedule_is_restart_stable_and_has_one_winner(
    alembic_database,
) -> None:
    settings = MonitoringSettings(poller_enabled=True, jitter_seconds=30)
    with alembic_database.sessions() as session:
        upsert_object(
            session,
            _service(
                "stable-expired",
                monitoring={"enabled": True, "interval_seconds": 60},
                endpoints=[_endpoint()],
            ),
        )
        row = session.get(CatalogObject, "stable-expired")
        assert row is not None
        record_service_observation(
            session,
            object_id=row.id,
            object_instance_id=row.instance_id,
            observation=MonitoringObservation(
                provider="builtin_http",
                state="healthy",
                checked_at=NOW,
                http_status=204,
            ),
            now=NOW,
            settings=settings,
        )
        session.commit()
        synchronize_check_schedule(
            session,
            now=NOW + timedelta(seconds=100),
            settings=settings,
        )
        session.commit()
        first_due = session.scalar(select(ServiceCheckLease.due_at))
        assert first_due is not None
        assert NOW + timedelta(seconds=60) <= first_due.replace(tzinfo=UTC)
        assert first_due.replace(tzinfo=UTC) <= NOW + timedelta(seconds=90)

    with alembic_database.sessions() as restarted:
        synchronize_check_schedule(
            restarted,
            now=NOW + timedelta(seconds=100),
            settings=settings,
        )
        restarted.commit()
        assert restarted.scalar(select(ServiceCheckLease.due_at)) == first_due

    with alembic_database.sessions() as first, alembic_database.sessions() as second:
        first_claim = claim_due_checks(
            first,
            owner="process-one",
            now=NOW + timedelta(seconds=100),
            settings=settings,
        )
        second_claim = claim_due_checks(
            second,
            owner="process-two",
            now=NOW + timedelta(seconds=100),
            settings=settings,
        )
    assert [claim.object_id for claim in first_claim] == ["stable-expired"]
    assert second_claim == []


def test_database_lease_has_one_winner_across_sessions(alembic_database) -> None:
    settings = MonitoringSettings(poller_enabled=True, jitter_seconds=0)
    with alembic_database.sessions() as session:
        upsert_object(
            session,
            _service(
                "leased",
                monitoring={"enabled": True},
                endpoints=[_endpoint()],
            ),
        )
        session.commit()
        assert synchronize_check_schedule(session, now=NOW, settings=settings) == 1
        session.commit()

    with alembic_database.sessions() as first, alembic_database.sessions() as second:
        first_claim = claim_due_checks(
            first,
            owner="process-one",
            now=NOW,
            settings=settings,
        )
        second_claim = claim_due_checks(
            second,
            owner="process-two",
            now=NOW,
            settings=settings,
        )
    assert [claim.object_id for claim in first_claim] == ["leased"]
    assert second_claim == []


def test_claims_never_queue_behind_the_local_concurrency_bound(
    alembic_session_factory,
) -> None:
    settings = MonitoringSettings(
        poller_enabled=True,
        jitter_seconds=0,
        max_checks_per_run=20,
        max_concurrent_checks=2,
    )
    with alembic_session_factory() as session:
        for index in range(4):
            upsert_object(
                session,
                _service(
                    f"bounded-{index}",
                    monitoring={"enabled": True},
                    endpoints=[_endpoint()],
                ),
            )
        session.commit()
        assert synchronize_check_schedule(session, now=NOW, settings=settings) == 4
        session.commit()
        claims = claim_due_checks(
            session,
            owner="bounded-worker",
            now=NOW,
            settings=settings,
        )

    assert len(claims) == 2


def test_agent_projection_uses_effective_health_without_leaking_to_stubs(
    alembic_session_factory,
    monkeypatch,
) -> None:
    observation_scopes: list[tuple[str, ...] | None] = []
    real_load_observation_index = agent_service.load_observation_index

    def scoped_observations(session, *, object_ids=None):
        observation_scopes.append(
            None if object_ids is None else tuple(sorted(object_ids))
        )
        return real_load_observation_index(session, object_ids=object_ids)

    monkeypatch.setattr(
        agent_service,
        "load_observation_index",
        scoped_observations,
    )
    with alembic_session_factory() as session:
        observed_at = datetime.now(UTC)
        for object_id in ("readable", "stub", "concealed"):
            upsert_object(
                session,
                _service(
                    object_id,
                    monitoring={"enabled": True},
                    endpoints=[_endpoint()],
                    health="healthy",
                ),
            )
            row = session.get(CatalogObject, object_id)
            assert row is not None
            record_service_observation(
                session,
                object_id=object_id,
                object_instance_id=row.instance_id,
                observation=MonitoringObservation(
                    provider="builtin_http",
                    state="down",
                    checked_at=observed_at,
                    error_code="timeout",
                ),
                now=observed_at,
                settings=MonitoringSettings(jitter_seconds=0),
            )
        for object_id in ("malformed-readable", "malformed-stub"):
            upsert_object(
                session,
                _service(
                    object_id,
                    monitoring={"enabled": True},
                    endpoints=[_endpoint()],
                    health="healthy",
                ),
            )
            row = session.get(CatalogObject, object_id)
            assert row is not None
            _store_monitoring_document(
                row,
                {"enabled": True, "interval_seconds": "secret-invalid-value"},
            )
        session.commit()
        principal = PrincipalContext(
            id="monitoring-reader",
            principal_type=PrincipalType.SERVICE_ACCOUNT,
            login="monitoring-reader",
            display_name="Monitoring Reader",
        )
        access = ReadAccess(
            principal=principal,
            policy=PolicySnapshot(
                principal_id=principal.id,
                _permissions={
                    "readable": frozenset({Permission.DISCOVER, Permission.READ}),
                    "stub": frozenset({Permission.DISCOVER}),
                    "malformed-readable": frozenset(
                        {Permission.DISCOVER, Permission.READ}
                    ),
                    "malformed-stub": frozenset({Permission.DISCOVER}),
                },
                _grants={},
            ),
        )
        readable = get_agent_object_context(session, "readable", access)
        stub = get_agent_object_context(session, "stub", access)
        concealed = get_agent_object_context(session, "concealed", access)
        malformed_readable = get_agent_object_context(
            session,
            "malformed-readable",
            access,
        )
        malformed_stub = get_agent_object_context(
            session,
            "malformed-stub",
            access,
        )

    assert readable is not None and readable.visibility == "detail"
    assert readable.monitoring is not None
    assert readable.health == "down"
    assert readable.monitoring.observed_state == "down"
    assert stub is not None and stub.visibility == "stub"
    assert "monitoring" not in stub.model_dump()
    assert concealed is None
    assert malformed_readable is not None
    assert malformed_readable.visibility == "detail"
    assert malformed_readable.monitoring is not None
    assert malformed_readable.monitoring.diagnostic == "invalid_monitoring_config"
    assert malformed_readable.monitoring.state == "check_error"
    assert malformed_readable.monitoring.provider is None
    assert malformed_readable.monitoring.interval_seconds is None
    assert malformed_stub is not None and malformed_stub.visibility == "stub"
    assert "monitoring" not in malformed_stub.model_dump()
    assert observation_scopes
    assert set(observation_scopes) == {("malformed-readable", "readable")}


def test_monitoring_settings_keep_probe_and_lease_bounds_consistent() -> None:
    with pytest.raises(ValidationError):
        Settings(
            monitoring_connect_timeout_ms=6000,
            monitoring_total_timeout_ms=5000,
        )
    with pytest.raises(ValidationError):
        Settings(
            monitoring_total_timeout_ms=10000,
            monitoring_lease_seconds=10,
        )
    with pytest.raises(ValidationError):
        Settings(monitoring_allowed_target_networks="not-a-network")


def test_rest_agent_mcp_and_catalog_share_one_effective_observation(
    alembic_session_factory,
    install_unrestricted_read_access,
) -> None:
    observed_at = datetime.now(UTC)
    with alembic_session_factory() as session:
        upsert_object(
            session,
            _service(
                "cross-surface",
                monitoring={"enabled": True},
                endpoints=[_endpoint()],
                health="healthy",
            ),
        )
        row = session.get(CatalogObject, "cross-surface")
        assert row is not None
        record_service_observation(
            session,
            object_id="cross-surface",
            object_instance_id=row.instance_id,
            observation=MonitoringObservation(
                provider="builtin_http",
                state="down",
                checked_at=observed_at,
                http_status=503,
                latency_ms=25,
                error_code="http_server_error",
            ),
            now=observed_at,
            settings=MonitoringSettings(jitter_seconds=0),
        )
        session.commit()

    app = create_app()
    install_unrestricted_read_access(app)

    def override_get_session():
        with alembic_session_factory() as session:
            yield session

    app.dependency_overrides[get_session] = override_get_session
    with TestClient(app) as client:
        rest = client.get("/api/v1/objects/cross-surface")
        agent = client.get("/api/agent/objects/cross-surface")
        catalog = client.get("/?q=cross-surface&kind=service")
        down_page = client.get("/api/v1/objects?health=down")
        healthy_page = client.get("/api/v1/objects?health=healthy")

        def fetch(path: str, params: dict) -> dict:
            response = client.get(path, params=params)
            response.raise_for_status()
            return response.json()

        mcp = call_tool(
            "blockwart.get_object_context",
            {"object_id": "cross-surface"},
            fetcher=fetch,
        )

    assert rest.status_code == 200
    assert rest.json()["health"] == "down"
    assert rest.json()["monitoring"]["state"] == "down"
    assert agent.json()["objects"][0]["monitoring"] == rest.json()["monitoring"]
    assert "cross-surface" in {item["id"] for item in down_page.json()["items"]}
    assert "cross-surface" not in {
        item["id"] for item in healthy_page.json()["items"]
    }
    mcp_object = json.loads(mcp["content"][0]["text"])["objects"][0]
    assert mcp_object["health"] == "down"
    assert mcp_object["monitoring"] == rest.json()["monitoring"]
    assert catalog.status_code == 200
    assert "state-down" in catalog.text


def test_monitoring_ui_writes_through_etag_and_renders_english_and_german(
    alembic_session_factory,
    install_unrestricted_read_access,
) -> None:
    with alembic_session_factory() as session:
        upsert_object(session, _service("ui-monitoring", endpoints=[_endpoint()]))
        session.commit()

    app = create_app()
    install_unrestricted_read_access(app)

    def override_get_session():
        with alembic_session_factory() as session:
            yield session

    app.dependency_overrides[get_session] = override_get_session
    with TestClient(app) as client:
        detail = client.get("/objects/ui-monitoring?lang=en")
        assert detail.status_code == 200
        assert "Service monitoring" in detail.text
        assert "https://status.example.invalid:8443/health" in detail.text
        editor = client.get("/objects/ui-monitoring?edit=monitoring")
        assert 'name="monitoring_enabled"' in editor.text
        assert "https://status.example.invalid:8443/health" in editor.text
        changed = client.post(
            "/objects/ui-monitoring/monitoring",
            data={
                "monitoring_enabled": "true",
                "monitoring_provider": "builtin_http",
                "monitoring_interval_overridden": "true",
                "monitoring_interval_seconds": "120",
                "if_match": detail.headers["etag"],
            },
            follow_redirects=False,
        )
        assert changed.status_code == 303
        after_change = client.get("/objects/ui-monitoring?lang=en")
        assert after_change.headers["etag"] != detail.headers["etag"]
        stale = client.post(
            "/objects/ui-monitoring/monitoring",
            data={
                "monitoring_enabled": "false",
                "monitoring_provider": "builtin_http",
                "if_match": detail.headers["etag"],
            },
            follow_redirects=False,
        )
        assert stale.status_code == 412
        german = client.get("/objects/ui-monitoring?lang=de")
        assert german.status_code == 200
        assert "Service-Monitoring" in german.text
        assert "Effektives Ziel" in german.text

    with alembic_session_factory() as session:
        row = session.get(CatalogObject, "ui-monitoring")
        assert row is not None
        projected = monitoring_projection(
            kind=row.kind,
            object_id=row.id,
            data=_service_data(row),
            catalog_health=row.health,
            observations=load_observation_index(session),
            now=datetime.now(UTC),
        )
        assert projected is not None
        assert projected["enabled"] is True
        assert projected["interval_seconds"] == 120
        assert (
            session.scalar(
                select(func.count(AuditEvent.id)).where(
                    AuditEvent.object_id == "ui-monitoring",
                    AuditEvent.action == "update",
                )
            )
            == 1
        )


def _service_data(row: CatalogObject) -> dict:
    value = json.loads(row.data_json)
    assert isinstance(value, dict)
    return value
