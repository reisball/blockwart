"""Regression tests for the Gatus pull adapter (#177).

The pull adapter reads the current Gatus status API as the preferred source.
These tests cover the domain resolution, the mapping extraction, the
state-extraction logic, and the acquisition adapter with a mocked network
boundary (DNS resolution and the HTTP body read), so no real socket is opened.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from ipaddress import ip_address

import pytest

from blockwart.domain.monitoring import resolve_gatus_source_target
from blockwart.domain.monitoring_policy import parse_target_policy
from blockwart.services import monitoring_gatus, monitoring_probe
from blockwart.services.monitoring import _gatus_mapping_from_data
from blockwart.services.monitoring_probe import _ProbeFailure
from blockwart.services.monitoring_registry import ProbeLimits, ProviderCheckRequest

NOW = datetime(2026, 8, 19, 12, 0, tzinfo=UTC)


def _limits() -> ProbeLimits:
    return ProbeLimits(
        policy=parse_target_policy(
            allowed_networks="203.0.113.0/24",
            allowed_ports="443,8080",
        )
    )


def _target() -> object:
    resolution = resolve_gatus_source_target(
        {
            "monitoring": {
                "enabled": True,
                "provider": "gatus",
                "gatus": {
                    "source_url": "https://gatus.example.com/api/v1/endpoints/statuses",
                    "endpoint": "api-gateway",
                    "group": "core",
                },
            }
        },
        object_id="svc",
    )
    assert resolution.target is not None
    return resolution.target


def _request(endpoint: str = "api-gateway", group: str = "core") -> ProviderCheckRequest:
    return ProviderCheckRequest(
        object_id="svc",
        target=_target(),
        diagnostic=None,
        limits=_limits(),
        gatus_mapping={"endpoint": endpoint, "group": group},
    )


def _mock_network(monkeypatch: pytest.MonkeyPatch, *, status: int, body: bytes):
    """Mock the DNS + HTTP boundary so probe_gatus_endpoint reaches parsing."""
    monkeypatch.setattr(
        monitoring_probe,
        "_resolve",
        lambda _host, _port, *, timeout: [ip_address("203.0.113.9")],
    )
    monkeypatch.setattr(
        monitoring_probe,
        "_request_status_and_body",
        lambda **kwargs: (status, body),
    )


# ---------------------------------------------------------------------------
# Domain: resolve_gatus_source_target
# ---------------------------------------------------------------------------


def test_resolve_gatus_source_missing_source_url() -> None:
    resolution = resolve_gatus_source_target({}, object_id="svc")
    assert resolution.target is None
    assert resolution.diagnostic == "missing_gatus_source"


def test_resolve_gatus_source_invalid_url() -> None:
    resolution = resolve_gatus_source_target(
        {
            "monitoring": {
                "enabled": True,
                "provider": "gatus",
                "gatus": {"source_url": "ftp://not-http"},
            }
        },
        object_id="svc",
    )
    assert resolution.target is None
    assert resolution.diagnostic == "invalid_gatus_source_url"


def test_resolve_gatus_source_valid_url() -> None:
    resolution = resolve_gatus_source_target(
        {
            "monitoring": {
                "enabled": True,
                "provider": "gatus",
                "gatus": {
                    "source_url": "https://gatus.example.com/api/v1/endpoints/statuses"
                },
            }
        },
        object_id="svc",
    )
    assert resolution.target is not None
    assert resolution.target.scheme == "https"
    assert resolution.target.path == "/api/v1/endpoints/statuses"


# ---------------------------------------------------------------------------
# Mapping extraction
# ---------------------------------------------------------------------------


def test_gatus_mapping_extracts_bounded_keys() -> None:
    mapping = _gatus_mapping_from_data(
        {
            "monitoring": {
                "gatus": {
                    "endpoint": "api-gateway",
                    "group": "core",
                    "source": "prod",
                    "extra": "dropped",
                }
            }
        }
    )
    assert mapping == {"endpoint": "api-gateway", "group": "core", "source": "prod"}


def test_gatus_mapping_missing_endpoint_is_none() -> None:
    assert _gatus_mapping_from_data({"monitoring": {"gatus": {"group": "core"}}}) is None
    assert _gatus_mapping_from_data({}) is None


# ---------------------------------------------------------------------------
# Endpoint state extraction
# ---------------------------------------------------------------------------


def test_extract_endpoint_state_healthy() -> None:
    body = json.dumps(
        [
            {
                "name": "api-gateway",
                "group": "core",
                "results": [{"success": True, "status": 200, "timestamp": "2026-08-19T12:00:00Z"}],
            }
        ]
    ).encode()
    assert (
        monitoring_gatus._extract_endpoint_state(body, "api-gateway", group="core")
        == "healthy"
    )


def test_extract_endpoint_state_down() -> None:
    body = json.dumps(
        [
            {
                "name": "api-gateway",
                "group": "core",
                "results": [{"success": False, "status": 503, "timestamp": "2026-08-19T12:00:00Z"}],
            }
        ]
    ).encode()
    assert monitoring_gatus._extract_endpoint_state(body, "api-gateway", group="core") == "down"


def test_extract_endpoint_state_uses_latest_result() -> None:
    body = json.dumps(
        [
            {
                "name": "api-gateway",
                "group": "core",
                "results": [
                    {"success": False, "timestamp": "2026-08-19T11:00:00Z"},
                    {"success": True, "timestamp": "2026-08-19T12:00:00Z"},
                ],
            }
        ]
    ).encode()
    assert (
        monitoring_gatus._extract_endpoint_state(body, "api-gateway", group="core")
        == "healthy"
    )


def test_extract_endpoint_state_group_mismatch_returns_none() -> None:
    body = json.dumps(
        [{"name": "api-gateway", "group": "edge", "results": [{"success": True}]}]
    ).encode()
    assert (
        monitoring_gatus._extract_endpoint_state(body, "api-gateway", group="core") is None
    )


def test_extract_endpoint_state_malformed_body_returns_none() -> None:
    assert monitoring_gatus._extract_endpoint_state(b"not-json", "api", group=None) is None
    assert monitoring_gatus._extract_endpoint_state(b"{}", "api", group=None) is None
    assert monitoring_gatus._extract_endpoint_state(b"[]", "missing", group=None) is None


# ---------------------------------------------------------------------------
# Acquisition adapter (network mocked)
# ---------------------------------------------------------------------------


def test_probe_gatus_endpoint_healthy(monkeypatch: pytest.MonkeyPatch) -> None:
    body = json.dumps(
        [{"name": "api-gateway", "group": "core", "results": [{"success": True}]}]
    ).encode()
    _mock_network(monkeypatch, status=200, body=body)
    obs = monitoring_gatus.probe_gatus_endpoint(_request())
    assert obs.state == "healthy"
    assert obs.provider == "gatus"
    assert obs.error_code is None


def test_probe_gatus_endpoint_down(monkeypatch: pytest.MonkeyPatch) -> None:
    body = json.dumps(
        [{"name": "api-gateway", "group": "core", "results": [{"success": False}]}]
    ).encode()
    _mock_network(monkeypatch, status=200, body=body)
    obs = monitoring_gatus.probe_gatus_endpoint(_request())
    assert obs.state == "down"
    assert obs.error_code is None


def test_probe_gatus_endpoint_api_error(monkeypatch: pytest.MonkeyPatch) -> None:
    _mock_network(monkeypatch, status=503, body=b"upstream down")
    obs = monitoring_gatus.probe_gatus_endpoint(_request())
    assert obs.state == "check_error"
    assert obs.error_code == "http_server_error"


def test_probe_gatus_endpoint_network_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        monitoring_probe,
        "_resolve",
        lambda _host, _port, *, timeout: [ip_address("203.0.113.9")],
    )

    def fake(**kwargs):
        raise _ProbeFailure("down", "connect_failed")

    monkeypatch.setattr(monitoring_probe, "_request_status_and_body", fake)
    obs = monitoring_gatus.probe_gatus_endpoint(_request())
    assert obs.state == "down"
    assert obs.error_code == "connect_failed"


def test_probe_gatus_endpoint_policy_denied() -> None:
    # No allowed networks => the deny-by-default policy is disabled, so the
    # adapter reports policy_denied before any network attempt.
    limits = ProbeLimits(
        policy=parse_target_policy(allowed_networks="", allowed_ports="")
    )
    request = ProviderCheckRequest(
        object_id="svc",
        target=_target(),
        diagnostic=None,
        limits=limits,
        gatus_mapping={"endpoint": "api-gateway"},
    )
    obs = monitoring_gatus.probe_gatus_endpoint(request)
    assert obs.state == "check_error"
    assert obs.error_code == "policy_denied"
