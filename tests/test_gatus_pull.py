"""Regressions for the Gatus pull adapter and its runtime source binding (#177).

The adapter reads current Gatus status data as the preferred source. These
tests cover the deployment binding, the credential isolation, the observation
contract (upstream observed time vs. server receive time, replay, delay, skew),
the mapping semantics, the source-outage semantics, and the catalog/UI
round-trip. The network boundary (DNS and the HTTP request) is always mocked,
so no test opens a socket.
"""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime, timedelta
from ipaddress import ip_address

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

import blockwart.services.monitoring_probe as monitoring_probe
from blockwart.api.deps import get_session
from blockwart.config import Settings
from blockwart.domain.monitoring import (
    MAX_UPSTREAM_FUTURE_SKEW_SECONDS,
    MonitoringObservation,
    monitoring_view,
    read_gatus_mapping,
    read_monitoring_config,
)
from blockwart.domain.monitoring_policy import parse_target_policy
from blockwart.domain.monitoring_sources import (
    MAX_MONITORING_PULL_SOURCES,
    MonitoringSourceError,
    parse_monitoring_pull_sources,
)
from blockwart.domain.object_schema import ObjectSchemaError, validate_object_data
from blockwart.main import create_app
from blockwart.models import CatalogObject, ServiceCheckLease, ServiceObservation
from blockwart.schemas.catalog import CatalogObjectIn
from blockwart.services import monitoring_gatus
from blockwart.services.catalog import upsert_object
from blockwart.services.monitoring import (
    MonitoringSettings,
    monitoring_settings,
    record_service_observation,
    run_due_service_checks,
    synchronize_check_schedule,
)
from blockwart.services.monitoring_probe import _ProbeFailure
from blockwart.services.monitoring_registry import (
    ProbeLimits,
    ProviderCheckRequest,
    PullSourceRequest,
)

NOW = datetime(2026, 8, 24, 12, 0, tzinfo=UTC)
OBSERVED = datetime(2026, 8, 24, 11, 59, tzinfo=UTC)
STATUS_URL = "https://gatus.example.invalid/api/v1/endpoints/statuses"
OTHER_STATUS_URL = "https://gatus-two.example.invalid/api/v1/endpoints/statuses"

# Inert, non-functional canaries. They exist only so a test can prove a value
# never leaves the process; they authenticate nothing anywhere.
CANARY_TOKEN = "canary-not-a-real-token-0000"
OTHER_CANARY_TOKEN = "canary-not-a-real-token-1111"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _sources(**overrides) -> dict:
    return parse_monitoring_pull_sources(
        sources=overrides.pop("sources", f"prod={STATUS_URL}"),
        credential_files=overrides.pop("credential_files", ""),
    )


def _limits() -> ProbeLimits:
    return ProbeLimits(
        policy=parse_target_policy(
            allowed_networks="203.0.113.0/24",
            allowed_ports="443,8080",
        )
    )


def _request(
    *,
    source_name: str = "prod",
    group: str = "core",
    endpoint: str = "api-gateway",
    credential_file: str | None = None,
    limits: ProbeLimits | None = None,
) -> ProviderCheckRequest:
    sources = parse_monitoring_pull_sources(
        sources=f"{source_name}={STATUS_URL}",
        credential_files=f"{source_name}={credential_file}" if credential_file else "",
    )
    return ProviderCheckRequest(
        object_id="svc",
        target=None,
        diagnostic=None,
        limits=limits or _limits(),
        pull_source=PullSourceRequest(
            source=sources[source_name],
            group=group,
            endpoint=endpoint,
        ),
    )


def _statuses(
    *,
    name: str = "api-gateway",
    group: str = "core",
    results: list[dict] | None = None,
    extra: list[dict] | None = None,
) -> bytes:
    payload = [
        {
            "name": name,
            "group": group,
            "results": results
            if results is not None
            else [{"success": True, "timestamp": _rfc3339(OBSERVED)}],
        }
    ]
    payload.extend(extra or [])
    return json.dumps(payload).encode()


def _rfc3339(moment: datetime) -> str:
    return moment.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _mock_network(monkeypatch, *, status: int = 200, body: bytes = b"[]") -> list[dict]:
    """Mock DNS and the HTTP request; return the captured request kwargs."""

    captured: list[dict] = []
    monkeypatch.setattr(
        monitoring_probe,
        "_resolve",
        lambda _host, _port, *, timeout: [ip_address("203.0.113.9")],
    )

    def request(**kwargs):
        captured.append(kwargs)
        return status, body

    monkeypatch.setattr(monitoring_probe, "_request_status_and_body", request)
    return captured


def _gatus_service(
    object_id: str = "svc",
    *,
    source: str = "prod",
    group: str = "core",
    endpoint: str = "api-gateway",
    enabled: bool = True,
) -> CatalogObjectIn:
    return CatalogObjectIn(
        id=object_id,
        kind="service",
        label=object_id,
        lifecycle="active",
        health="unknown",
        data={
            "schema_version": 1,
            "monitoring": {
                "enabled": enabled,
                "provider": "gatus",
                "gatus": {"source": source, "group": group, "endpoint": endpoint},
            },
        },
    )


def _settings(sources: dict | None = None) -> MonitoringSettings:
    return MonitoringSettings(
        poller_enabled=True,
        jitter_seconds=0,
        policy=parse_target_policy(
            allowed_networks="203.0.113.0/24", allowed_ports="443"
        ),
        gatus_sources=sources if sources is not None else _sources(),
    )


# ---------------------------------------------------------------------------
# Deployment binding: catalog data names a source, it can never choose a URL
# ---------------------------------------------------------------------------


def test_catalog_data_cannot_express_a_url_or_a_credential() -> None:
    for forbidden in ("source_url", "url", "token", "password", "credential"):
        with pytest.raises(ObjectSchemaError) as error:
            validate_object_data(
                "service",
                {
                    "schema_version": 1,
                    "monitoring": {
                        "enabled": True,
                        "provider": "gatus",
                        "gatus": {
                            "source": "prod",
                            "group": "core",
                            "endpoint": "api",
                            forbidden: "https://attacker.example.invalid/",
                        },
                    },
                },
            )
        assert forbidden in error.value.path


def test_gatus_provider_requires_the_complete_closed_identity() -> None:
    with pytest.raises(ObjectSchemaError) as missing:
        validate_object_data(
            "service",
            {
                "schema_version": 1,
                "monitoring": {"enabled": True, "provider": "gatus"},
            },
        )
    assert missing.value.path == "data.monitoring.gatus"

    with pytest.raises(ObjectSchemaError) as partial:
        validate_object_data(
            "service",
            {
                "schema_version": 1,
                "monitoring": {
                    "enabled": True,
                    "provider": "gatus",
                    "gatus": {"source": "prod", "endpoint": "api"},
                },
            },
        )
    assert partial.value.path == "data.monitoring.gatus.group"


def test_an_ungrouped_gatus_endpoint_is_selected_explicitly() -> None:
    data = {
        "schema_version": 1,
        "monitoring": {
            "enabled": True,
            "provider": "gatus",
            "gatus": {"source": "prod", "group": "", "endpoint": "api"},
        },
    }
    validate_object_data("service", data)
    resolution = read_gatus_mapping(data)
    assert resolution.mapping is not None
    assert resolution.mapping.group == ""


def test_source_registry_is_bounded_and_fails_closed() -> None:
    bound = parse_monitoring_pull_sources(sources=f"prod={STATUS_URL}")
    assert bound["prod"].url == STATUS_URL
    assert bound["prod"].credential_file is None

    too_many = ",".join(
        f"s{index}=https://gatus{index}.example.invalid/api"
        for index in range(MAX_MONITORING_PULL_SOURCES + 1)
    )
    for invalid in (
        "prod",
        "PROD=https://gatus.example.invalid/api",
        "prod=ftp://gatus.example.invalid/api",
        "prod=https://user:pw@gatus.example.invalid/api",
        f"prod={STATUS_URL},prod={OTHER_STATUS_URL}",
        too_many,
    ):
        with pytest.raises(MonitoringSourceError):
            parse_monitoring_pull_sources(sources=invalid)


def test_a_credential_cannot_be_bound_to_an_undeclared_or_relative_source() -> None:
    with pytest.raises(MonitoringSourceError):
        parse_monitoring_pull_sources(
            sources=f"prod={STATUS_URL}", credential_files="staging=/run/secrets/x"
        )
    with pytest.raises(MonitoringSourceError):
        parse_monitoring_pull_sources(
            sources=f"prod={STATUS_URL}", credential_files="prod=relative/path"
        )


def test_settings_reject_an_unusable_binding_at_startup() -> None:
    with pytest.raises(ValueError) as error:
        Settings(monitoring_gatus_sources="prod=ftp://gatus.example.invalid/api")
    # The startup message names the rule, never the rejected URL or host.
    assert "gatus.example.invalid" not in str(error.value)


def test_settings_expose_no_credential_value(tmp_path) -> None:
    token_file = tmp_path / "token"
    token_file.write_text(CANARY_TOKEN, encoding="utf-8")
    settings = Settings(
        monitoring_gatus_sources=f"prod={STATUS_URL}",
        monitoring_gatus_credential_files=f"prod={token_file}",
    )
    projection = json.dumps(settings.model_dump(mode="json"))
    assert CANARY_TOKEN not in projection

    resolved = monitoring_settings(settings)
    assert CANARY_TOKEN not in json.dumps(str(resolved.gatus_sources))


# ---------------------------------------------------------------------------
# Credential isolation
# ---------------------------------------------------------------------------


def test_the_bound_credential_is_read_from_its_file_at_check_time(
    monkeypatch, tmp_path
) -> None:
    token_file = tmp_path / "token"
    token_file.write_text(f"  {CANARY_TOKEN}\n", encoding="utf-8")
    captured = _mock_network(monkeypatch, body=_statuses())

    observation = monitoring_gatus.probe_gatus_endpoint(
        _request(credential_file=str(token_file))
    )

    assert observation.state == "healthy"
    assert captured[0]["authorization"] == f"Bearer {CANARY_TOKEN}"


def test_no_credential_is_forwarded_to_another_source(monkeypatch, tmp_path) -> None:
    token_file = tmp_path / "prod-token"
    token_file.write_text(CANARY_TOKEN, encoding="utf-8")
    other_token_file = tmp_path / "staging-token"
    other_token_file.write_text(OTHER_CANARY_TOKEN, encoding="utf-8")
    sources = parse_monitoring_pull_sources(
        sources=f"prod={STATUS_URL},staging={OTHER_STATUS_URL}",
        credential_files=f"prod={token_file},staging={other_token_file}",
    )
    captured = _mock_network(monkeypatch, body=_statuses())

    for name, expected in (("prod", CANARY_TOKEN), ("staging", OTHER_CANARY_TOKEN)):
        monitoring_gatus.probe_gatus_endpoint(
            ProviderCheckRequest(
                object_id="svc",
                target=None,
                diagnostic=None,
                limits=_limits(),
                pull_source=PullSourceRequest(
                    source=sources[name], group="core", endpoint="api-gateway"
                ),
            )
        )
        assert captured[-1]["authorization"] == f"Bearer {expected}"
        assert captured[-1]["hostname"] == sources[name].host


def test_a_source_without_a_credential_sends_none(monkeypatch) -> None:
    captured = _mock_network(monkeypatch, body=_statuses())
    monitoring_gatus.probe_gatus_endpoint(_request())
    assert captured[0]["authorization"] is None


@pytest.mark.parametrize(
    "content",
    ["", "   ", "line-one\nline-two"],
)
def test_an_unusable_credential_file_fails_closed_without_a_request(
    monkeypatch, tmp_path, content: str
) -> None:
    token_file = tmp_path / "token"
    token_file.write_text(content, encoding="utf-8")
    captured = _mock_network(monkeypatch, body=_statuses())

    observation = monitoring_gatus.probe_gatus_endpoint(
        _request(credential_file=str(token_file))
    )

    assert (observation.state, observation.error_code) == (
        "check_error",
        "source_unconfigured",
    )
    assert captured == []


def test_a_missing_credential_file_fails_closed_without_a_request(
    monkeypatch, tmp_path
) -> None:
    captured = _mock_network(monkeypatch, body=_statuses())
    observation = monitoring_gatus.probe_gatus_endpoint(
        _request(credential_file=str(tmp_path / "absent"))
    )
    assert observation.error_code == "source_unconfigured"
    assert captured == []


def test_an_oversized_credential_file_is_refused(monkeypatch, tmp_path) -> None:
    token_file = tmp_path / "token"
    token_file.write_text("x" * (monitoring_gatus.MAX_CREDENTIAL_BYTES + 1))
    _mock_network(monkeypatch, body=_statuses())
    observation = monitoring_gatus.probe_gatus_endpoint(
        _request(credential_file=str(token_file))
    )
    assert observation.error_code == "source_unconfigured"


@pytest.mark.parametrize("kind", ["fifo", "directory", "symlink"])
def test_special_credential_paths_are_rejected_without_a_request(
    monkeypatch, tmp_path, kind: str
) -> None:
    credential_path = tmp_path / kind
    if kind == "fifo":
        os.mkfifo(credential_path)
    elif kind == "directory":
        credential_path.mkdir()
    else:
        target = tmp_path / "regular-target"
        target.write_text(CANARY_TOKEN, encoding="utf-8")
        credential_path.symlink_to(target)
    captured = _mock_network(monkeypatch, body=_statuses())

    observation = monitoring_gatus.probe_gatus_endpoint(
        _request(credential_file=str(credential_path))
    )

    assert (observation.state, observation.error_code) == (
        "check_error",
        "source_unconfigured",
    )
    assert captured == []


def test_a_credential_never_reaches_the_observation_or_the_logs(
    monkeypatch, tmp_path, caplog
) -> None:
    token_file = tmp_path / "token"
    token_file.write_text(CANARY_TOKEN, encoding="utf-8")
    _mock_network(monkeypatch, body=_statuses())

    with caplog.at_level("DEBUG"):
        observation = monitoring_gatus.probe_gatus_endpoint(
            _request(credential_file=str(token_file))
        )

    assert CANARY_TOKEN not in repr(observation)
    assert CANARY_TOKEN not in caplog.text
    assert str(token_file) not in repr(observation)


# ---------------------------------------------------------------------------
# Outbound policy: SSRF and denial
# ---------------------------------------------------------------------------


def test_a_denied_source_address_is_never_connected_to(monkeypatch) -> None:
    captured = _mock_network(monkeypatch, body=_statuses())
    monkeypatch.setattr(
        monitoring_probe,
        "_resolve",
        lambda _host, _port, *, timeout: [ip_address("127.0.0.1")],
    )

    observation = monitoring_gatus.probe_gatus_endpoint(_request())

    assert (observation.state, observation.error_code) == (
        "check_error",
        "policy_denied",
    )
    assert captured == []


def test_an_empty_allowlist_denies_every_source(monkeypatch) -> None:
    captured = _mock_network(monkeypatch, body=_statuses())
    observation = monitoring_gatus.probe_gatus_endpoint(
        _request(
            limits=ProbeLimits(
                policy=parse_target_policy(allowed_networks="", allowed_ports="")
            )
        )
    )
    assert observation.error_code == "policy_denied"
    assert captured == []


def test_a_denied_port_is_refused_before_resolution(monkeypatch) -> None:
    captured = _mock_network(monkeypatch, body=_statuses())
    observation = monitoring_gatus.probe_gatus_endpoint(
        _request(
            limits=ProbeLimits(
                policy=parse_target_policy(
                    allowed_networks="203.0.113.0/24", allowed_ports="8080"
                )
            )
        )
    )
    assert observation.error_code == "policy_denied"
    assert captured == []


def test_the_pinned_address_is_used_while_the_hostname_authenticates_tls(
    monkeypatch,
) -> None:
    captured = _mock_network(monkeypatch, body=_statuses())
    monitoring_gatus.probe_gatus_endpoint(_request())
    assert str(captured[0]["pinned"]) == "203.0.113.9"
    assert captured[0]["hostname"] == "gatus.example.invalid"
    assert captured[0]["scheme"] == "https"


# ---------------------------------------------------------------------------
# Upstream observation time, receive time, replay, delay, skew
# ---------------------------------------------------------------------------


def test_the_upstream_observation_time_is_preserved_and_receive_time_is_separate(
    monkeypatch,
) -> None:
    _mock_network(
        monkeypatch,
        body=_statuses(results=[{"success": True, "timestamp": _rfc3339(OBSERVED)}]),
    )
    before = datetime.now(UTC)

    observation = monitoring_gatus.probe_gatus_endpoint(_request())

    assert observation.checked_at == OBSERVED
    assert observation.received_at is not None
    assert observation.received_at >= before
    assert observation.received_at != observation.checked_at


def test_receive_time_is_stamped_only_after_acquisition_completes(monkeypatch) -> None:
    completed = False

    monkeypatch.setattr(
        monitoring_probe,
        "_resolve",
        lambda _host, _port, *, timeout: [ip_address("203.0.113.9")],
    )

    def request(**_kwargs):
        nonlocal completed
        completed = True
        return 200, _statuses()

    def completion_time() -> datetime:
        assert completed, "receive time was sampled before acquisition completed"
        return NOW

    monkeypatch.setattr(monitoring_probe, "_request_status_and_body", request)
    monkeypatch.setattr(monitoring_gatus, "_utcnow", completion_time)

    observation = monitoring_gatus.probe_gatus_endpoint(_request())

    assert observation.checked_at == OBSERVED
    assert observation.received_at == NOW


def test_one_deadline_bounds_cumulative_credential_dns_and_http_time(monkeypatch, tmp_path) -> None:
    class Clock:
        current = 100.0

        def __call__(self) -> float:
            return self.current

        def advance(self, seconds: float) -> None:
            self.current += seconds

    clock = Clock()
    budgets: list[tuple[str, float]] = []
    token_file = tmp_path / "token"
    token_file.write_text(CANARY_TOKEN, encoding="utf-8")

    def credential(_path, *, timeout):
        budgets.append(("credential", timeout))
        clock.advance(2)
        return CANARY_TOKEN

    def resolve(_host, _port, *, timeout):
        budgets.append(("dns", timeout))
        clock.advance(1)
        return [ip_address("203.0.113.9")]

    def request(**kwargs):
        budgets.append(("http", kwargs["total_timeout"]))
        assert kwargs["deadline"] == pytest.approx(105)
        clock.advance(2.01)
        return 200, _statuses()

    monkeypatch.setattr(monitoring_gatus, "monotonic", clock)
    monkeypatch.setattr(monitoring_probe, "monotonic", clock)
    monkeypatch.setattr(monitoring_gatus, "_read_credential", credential)
    monkeypatch.setattr(monitoring_probe, "_resolve", resolve)
    monkeypatch.setattr(monitoring_probe, "_request_status_and_body", request)

    observation = monitoring_gatus.probe_gatus_endpoint(
        _request(
            credential_file=str(token_file),
            limits=ProbeLimits(
                policy=parse_target_policy(allowed_networks="203.0.113.0/24", allowed_ports="443"),
                connect_timeout_ms=5000,
                total_timeout_ms=5000,
            ),
        )
    )

    assert [phase for phase, _ in budgets] == ["credential", "dns", "http"]
    assert [budget for _, budget in budgets] == pytest.approx([5, 3, 2])
    assert (observation.state, observation.error_code) == (
        "check_error",
        "timeout",
    )


def test_the_latest_result_wins_by_timestamp_not_list_position(monkeypatch) -> None:
    _mock_network(
        monkeypatch,
        body=_statuses(
            results=[
                {"success": True, "timestamp": _rfc3339(OBSERVED)},
                {"success": False, "timestamp": _rfc3339(OBSERVED - timedelta(hours=2))},
                {"success": False, "timestamp": _rfc3339(OBSERVED - timedelta(hours=1))},
            ]
        ),
    )
    observation = monitoring_gatus.probe_gatus_endpoint(_request())
    assert (observation.state, observation.checked_at) == ("healthy", OBSERVED)


def test_out_of_order_results_are_deterministic(monkeypatch) -> None:
    results = [
        {"success": False, "timestamp": _rfc3339(OBSERVED - timedelta(minutes=5))},
        {"success": True, "timestamp": _rfc3339(OBSERVED)},
    ]
    states = []
    for ordering in (results, list(reversed(results))):
        _mock_network(monkeypatch, body=_statuses(results=ordering))
        observation = monitoring_gatus.probe_gatus_endpoint(_request())
        states.append((observation.state, observation.checked_at))
    assert states[0] == states[1] == ("healthy", OBSERVED)


def test_conflicting_results_at_the_same_latest_timestamp_fail_closed(
    monkeypatch,
) -> None:
    _mock_network(
        monkeypatch,
        body=_statuses(
            results=[
                {"success": True, "timestamp": _rfc3339(OBSERVED)},
                {"success": False, "timestamp": _rfc3339(OBSERVED)},
            ]
        ),
    )
    observation = monitoring_gatus.probe_gatus_endpoint(_request())
    assert (observation.state, observation.error_code) == (
        "check_error",
        "mapping_ambiguous",
    )


def test_same_timestamp_supported_evidence_must_also_agree(monkeypatch) -> None:
    _mock_network(
        monkeypatch,
        body=_statuses(
            results=[
                {
                    "success": True,
                    "timestamp": _rfc3339(OBSERVED),
                    "status": 200,
                    "duration": 1_000_000,
                },
                {
                    "success": True,
                    "timestamp": _rfc3339(OBSERVED),
                    "status": 204,
                    "duration": 2_000_000,
                },
            ]
        ),
    )
    observation = monitoring_gatus.probe_gatus_endpoint(_request())
    assert (observation.state, observation.error_code) == (
        "check_error",
        "mapping_ambiguous",
    )


def test_agreeing_results_at_the_same_latest_timestamp_are_accepted(
    monkeypatch,
) -> None:
    _mock_network(
        monkeypatch,
        body=_statuses(
            results=[
                {"success": True, "timestamp": _rfc3339(OBSERVED)},
                {"success": True, "timestamp": _rfc3339(OBSERVED)},
            ]
        ),
    )
    assert monitoring_gatus.probe_gatus_endpoint(_request()).state == "healthy"


@pytest.mark.parametrize(
    "timestamp",
    [
        "2026-08-24T11:59:00",  # no zone: cannot be compared with our clock
        "20260824T115900Z",  # ISO basic form is not RFC 3339
        "not-a-timestamp",
        "",
        None,
        12345,
        "2026-08-24T11:59:00Z" + "0" * 64,
    ],
)
def test_an_invalid_upstream_timestamp_is_rejected(monkeypatch, timestamp) -> None:
    _mock_network(
        monkeypatch,
        body=_statuses(results=[{"success": True, "timestamp": timestamp}]),
    )
    observation = monitoring_gatus.probe_gatus_endpoint(_request())
    assert (observation.state, observation.error_code) == (
        "check_error",
        "invalid_observation_time",
    )


def test_a_materially_future_timestamp_is_rejected(monkeypatch) -> None:
    skewed = datetime.now(UTC) + timedelta(
        seconds=MAX_UPSTREAM_FUTURE_SKEW_SECONDS + 300
    )
    _mock_network(
        monkeypatch,
        body=_statuses(results=[{"success": True, "timestamp": _rfc3339(skewed)}]),
    )
    observation = monitoring_gatus.probe_gatus_endpoint(_request())
    assert (observation.state, observation.error_code) == (
        "check_error",
        "invalid_observation_time",
    )


def test_a_small_clock_skew_is_tolerated(monkeypatch) -> None:
    nearly_now = datetime.now(UTC) + timedelta(
        seconds=MAX_UPSTREAM_FUTURE_SKEW_SECONDS - 30
    )
    _mock_network(
        monkeypatch,
        body=_statuses(results=[{"success": True, "timestamp": _rfc3339(nearly_now)}]),
    )
    assert monitoring_gatus.probe_gatus_endpoint(_request()).state == "healthy"


def test_a_skewed_result_does_not_hide_an_older_valid_one(monkeypatch) -> None:
    skewed = datetime.now(UTC) + timedelta(days=1)
    _mock_network(
        monkeypatch,
        body=_statuses(
            results=[
                {"success": True, "timestamp": _rfc3339(OBSERVED)},
                {"success": False, "timestamp": _rfc3339(skewed)},
            ]
        ),
    )
    observation = monitoring_gatus.probe_gatus_endpoint(_request())
    assert (observation.state, observation.checked_at) == ("healthy", OBSERVED)


# ---------------------------------------------------------------------------
# Mapping semantics
# ---------------------------------------------------------------------------


def test_a_missing_mapping_writes_no_service_claim(monkeypatch) -> None:
    _mock_network(monkeypatch, body=_statuses(name="other-service"))
    observation = monitoring_gatus.probe_gatus_endpoint(_request())
    assert (observation.state, observation.error_code) == (
        "check_error",
        "mapping_missing",
    )


def test_a_group_mismatch_is_a_missing_mapping(monkeypatch) -> None:
    _mock_network(monkeypatch, body=_statuses(group="edge"))
    assert monitoring_gatus.probe_gatus_endpoint(_request()).error_code == (
        "mapping_missing"
    )


def test_duplicate_matching_endpoints_are_ambiguous(monkeypatch) -> None:
    duplicate = {
        "name": "api-gateway",
        "group": "core",
        "results": [{"success": False, "timestamp": _rfc3339(OBSERVED)}],
    }
    _mock_network(monkeypatch, body=_statuses(extra=[duplicate]))
    observation = monitoring_gatus.probe_gatus_endpoint(_request())
    assert (observation.state, observation.error_code) == (
        "check_error",
        "mapping_ambiguous",
    )


def test_a_matched_failure_maps_to_down_with_bounded_fields(monkeypatch) -> None:
    _mock_network(
        monkeypatch,
        body=_statuses(
            results=[
                {
                    "success": False,
                    "timestamp": _rfc3339(OBSERVED),
                    "status": 503,
                    "duration": 42_000_000,
                }
            ]
        ),
    )
    observation = monitoring_gatus.probe_gatus_endpoint(_request())
    assert observation.state == "down"
    assert observation.http_status == 503
    assert observation.latency_ms == 42


@pytest.mark.parametrize(
    "result",
    [
        {"status": 999, "duration": -1},
        {"status": "200", "duration": "5"},
        {"status": True, "duration": True},
        {"duration": 10**18},
    ],
)
def test_out_of_contract_upstream_fields_are_dropped(monkeypatch, result) -> None:
    _mock_network(
        monkeypatch,
        body=_statuses(
            results=[{"success": True, "timestamp": _rfc3339(OBSERVED), **result}]
        ),
    )
    observation = monitoring_gatus.probe_gatus_endpoint(_request())
    assert observation.state == "healthy"
    assert observation.http_status is None
    assert observation.latency_ms is None


# ---------------------------------------------------------------------------
# Source outage: never a claim that the service is down
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("failure", "expected"),
    [
        (_ProbeFailure("down", "connect_failed"), "connect_failed"),
        (_ProbeFailure("down", "tls_failed"), "tls_failed"),
        (_ProbeFailure("down", "timeout"), "timeout"),
        (_ProbeFailure("check_error", "response_too_large"), "response_too_large"),
    ],
)
def test_a_transport_failure_is_a_source_error_not_a_down_service(
    monkeypatch, failure, expected
) -> None:
    _mock_network(monkeypatch)

    def raise_failure(**_kwargs):
        raise failure

    monkeypatch.setattr(monitoring_probe, "_request_status_and_body", raise_failure)
    observation = monitoring_gatus.probe_gatus_endpoint(_request())
    assert observation.state == "check_error"
    assert observation.error_code == expected


def test_dns_and_resolution_failures_are_source_errors(monkeypatch) -> None:
    _mock_network(monkeypatch)
    for error, expected in ((OSError(), "dns_failed"), (TimeoutError(), "timeout")):

        def resolve(_host, _port, *, timeout, _error=error):
            raise _error

        monkeypatch.setattr(monitoring_probe, "_resolve", resolve)
        observation = monitoring_gatus.probe_gatus_endpoint(_request())
        assert (observation.state, observation.error_code) == ("check_error", expected)


@pytest.mark.parametrize(
    ("status", "expected"),
    [(401, "http_client_error"), (404, "http_client_error"), (503, "http_server_error")],
)
def test_a_non_2xx_status_source_is_a_source_error(monkeypatch, status, expected) -> None:
    _mock_network(monkeypatch, status=status, body=b"denied")
    observation = monitoring_gatus.probe_gatus_endpoint(_request())
    assert (observation.state, observation.error_code) == ("check_error", expected)


@pytest.mark.parametrize("body", [b"not-json", b"{}", b'"text"', b"[]", b"null"])
def test_an_unreadable_payload_is_a_source_error(monkeypatch, body) -> None:
    _mock_network(monkeypatch, body=body)
    observation = monitoring_gatus.probe_gatus_endpoint(_request())
    assert observation.state == "check_error"
    assert observation.error_code in {"source_unreadable", "mapping_missing"}


def test_an_endpoint_without_usable_results_is_a_source_error(monkeypatch) -> None:
    _mock_network(monkeypatch, body=_statuses(results=[]))
    assert monitoring_gatus.probe_gatus_endpoint(_request()).error_code == (
        "source_unreadable"
    )


def test_an_unbound_source_never_reaches_the_network(monkeypatch) -> None:
    captured = _mock_network(monkeypatch, body=_statuses())
    observation = monitoring_gatus.probe_gatus_endpoint(
        ProviderCheckRequest(
            object_id="svc",
            target=None,
            diagnostic=None,
            limits=_limits(),
            pull_source=None,
        )
    )
    assert (observation.state, observation.error_code) == (
        "check_error",
        "source_unconfigured",
    )
    assert captured == []


def test_a_chunked_status_response_is_decoded(monkeypatch) -> None:
    payload = _statuses()
    chunked = b"%x\r\n%s\r\n0\r\n\r\n" % (len(payload), payload)
    assert monitoring_probe._decode_chunked_body(chunked) == payload


# ---------------------------------------------------------------------------
# Storage: replay, delay, and the acquisition/evidence split
# ---------------------------------------------------------------------------


def _observe(session, *, state, checked_at, received_at, **fields):
    return record_service_observation(
        session,
        object_id="svc",
        object_instance_id=session.get(CatalogObject, "svc").instance_id,
        observation=MonitoringObservation(
            provider="gatus",
            state=state,
            checked_at=checked_at,
            received_at=received_at,
            **fields,
        ),
        now=received_at,
        settings=_settings(),
    )


def test_replaying_an_unchanged_snapshot_refreshes_nothing_but_the_schedule(
    alembic_session_factory,
) -> None:
    with alembic_session_factory() as session:
        upsert_object(session, _gatus_service())
        session.commit()

        first = _observe(
            session, state="healthy", checked_at=OBSERVED, received_at=NOW, latency_ms=5
        )
        session.commit()
        assert first is not None

        replay = _observe(
            session,
            state="healthy",
            checked_at=OBSERVED,
            received_at=NOW + timedelta(minutes=10),
            latency_ms=999,
        )
        session.commit()
        assert replay is not None

        # Evidence is untouched by a replay of the same upstream instant.
        assert replay.last_checked_at == first.last_checked_at
        assert replay.last_success_at == first.last_success_at
        assert replay.latency_ms == 5
        # Acquisition and the schedule still advance, so no tight poll loop.
        assert replay.last_received_at == NOW + timedelta(minutes=10)
        assert replay.next_due_at > first.next_due_at


def test_a_delayed_older_snapshot_never_replaces_newer_evidence(
    alembic_session_factory,
) -> None:
    with alembic_session_factory() as session:
        upsert_object(session, _gatus_service())
        session.commit()

        newer = _observe(
            session, state="healthy", checked_at=OBSERVED, received_at=NOW
        )
        session.commit()
        assert newer is not None

        delayed = _observe(
            session,
            state="down",
            checked_at=OBSERVED - timedelta(hours=1),
            received_at=NOW + timedelta(minutes=1),
        )
        session.commit()
        assert delayed is not None
        assert delayed.state == "healthy"
        assert delayed.last_checked_at == newer.last_checked_at
        assert delayed.last_success_at == newer.last_success_at


def test_last_success_does_not_move_when_evidence_does_not(
    alembic_session_factory,
) -> None:
    with alembic_session_factory() as session:
        upsert_object(session, _gatus_service())
        session.commit()

        healthy = _observe(
            session, state="healthy", checked_at=OBSERVED, received_at=NOW
        )
        session.commit()
        assert healthy is not None
        assert healthy.last_success_at == OBSERVED

        for offset in range(1, 4):
            replay = _observe(
                session,
                state="healthy",
                checked_at=OBSERVED,
                received_at=NOW + timedelta(minutes=offset),
            )
            session.commit()
            assert replay is not None
            assert replay.last_success_at == OBSERVED


def test_an_old_upstream_snapshot_is_stale_but_not_re_polled_immediately(
    alembic_session_factory,
) -> None:
    settings = _settings()
    old_observation = NOW - timedelta(days=2)
    with alembic_session_factory() as session:
        upsert_object(session, _gatus_service())
        session.commit()

        record = _observe(
            session, state="healthy", checked_at=old_observation, received_at=NOW
        )
        session.commit()
        assert record is not None

        # Evidence expired long ago, so the projection refuses to publish it.
        view = monitoring_view(
            data={
                "schema_version": 1,
                "monitoring": {
                    "enabled": True,
                    "provider": "gatus",
                    "gatus": {
                        "source": "prod",
                        "group": "core",
                        "endpoint": "api-gateway",
                    },
                },
            },
            object_id="svc",
            catalog_health="unknown",
            record=record,
            now=NOW,
            known_gatus_sources=settings.known_gatus_sources,
        )
        assert view["freshness"] == "stale"
        assert view["state"] == "unknown"
        assert view["observed_state"] == "healthy"

        # Acquisition, in contrast, is scheduled one ordinary interval out.
        assert record.next_due_at == NOW + timedelta(
            seconds=read_monitoring_config({}).interval_seconds or 300
        )

        synchronize_check_schedule(session, now=NOW, settings=settings)
        session.commit()
        lease = session.scalars(select(ServiceCheckLease)).one()
        assert lease.due_at > NOW.replace(tzinfo=None)


# ---------------------------------------------------------------------------
# Scheduler end to end
# ---------------------------------------------------------------------------


def test_a_bound_source_completes_one_scheduled_pull(
    alembic_session_factory, monkeypatch
) -> None:
    settings = _settings()
    _mock_network(
        monkeypatch,
        body=_statuses(results=[{"success": True, "timestamp": _rfc3339(OBSERVED)}]),
    )
    with alembic_session_factory() as session:
        upsert_object(session, _gatus_service())
        session.commit()
        synchronize_check_schedule(session, now=NOW, settings=settings)
        session.commit()

        result = run_due_service_checks(
            session,
            settings=settings,
            now=NOW + timedelta(hours=1),
            owner="test",
        )
        session.commit()

    assert result.completed == 1
    with alembic_session_factory() as session:
        row = session.scalars(select(ServiceObservation)).one()
        assert (row.provider, row.state) == ("gatus", "healthy")
        assert row.last_checked_at == OBSERVED.replace(tzinfo=None)
        assert row.last_received_at is not None
        assert row.last_received_at > row.last_checked_at


def test_an_unbound_source_records_a_source_error_without_a_request(
    alembic_session_factory, monkeypatch
) -> None:
    captured = _mock_network(monkeypatch, body=_statuses())
    settings = _settings(sources={})
    with alembic_session_factory() as session:
        upsert_object(session, _gatus_service())
        session.commit()
        synchronize_check_schedule(session, now=NOW, settings=settings)
        session.commit()
        run_due_service_checks(
            session, settings=settings, now=NOW + timedelta(hours=1), owner="test"
        )
        session.commit()

    assert captured == []
    with alembic_session_factory() as session:
        row = session.scalars(select(ServiceObservation)).one()
        assert (row.state, row.error_code) == ("check_error", "source_unconfigured")


def test_a_stored_incomplete_identity_is_never_scheduled_claimed_or_acquired(
    alembic_session_factory, monkeypatch
) -> None:
    """A hand-edited half identity is invalid configuration, not probe work."""

    captured = _mock_network(monkeypatch, body=_statuses())
    settings = _settings()
    with alembic_session_factory() as session:
        upsert_object(session, _gatus_service())
        session.commit()
        row = session.get(CatalogObject, "svc")
        data = json.loads(row.data_json)
        del data["monitoring"]["gatus"]["endpoint"]
        row.data_json = json.dumps(data, ensure_ascii=False, sort_keys=True)
        session.commit()

        assert read_monitoring_config(data).valid is False

        synchronize_check_schedule(session, now=NOW, settings=settings)
        session.commit()
        run_due_service_checks(
            session, settings=settings, now=NOW + timedelta(hours=1), owner="test"
        )
        session.commit()

    assert captured == []
    with alembic_session_factory() as session:
        assert session.scalars(select(ServiceCheckLease)).all() == []
        assert session.scalars(select(ServiceObservation)).all() == []


def test_a_complete_identity_naming_no_bound_source_still_fails_closed(
    alembic_session_factory, monkeypatch
) -> None:
    """The identity is well formed but this deployment binds no such source."""

    captured = _mock_network(monkeypatch, body=_statuses())
    settings = _settings(sources=_sources(sources=f"other={OTHER_STATUS_URL}"))
    with alembic_session_factory() as session:
        upsert_object(session, _gatus_service())
        session.commit()
        synchronize_check_schedule(session, now=NOW, settings=settings)
        session.commit()
        run_due_service_checks(
            session, settings=settings, now=NOW + timedelta(hours=1), owner="test"
        )
        session.commit()

    assert captured == []
    with alembic_session_factory() as session:
        row = session.scalars(select(ServiceObservation)).one()
        assert (row.state, row.error_code) == ("check_error", "source_unconfigured")


# ---------------------------------------------------------------------------
# Projection
# ---------------------------------------------------------------------------


def _view(*, source: str = "prod", known: frozenset[str] = frozenset({"prod"})) -> dict:
    return monitoring_view(
        data={
            "schema_version": 1,
            "monitoring": {
                "enabled": True,
                "provider": "gatus",
                "gatus": {"source": source, "group": "core", "endpoint": "api-gateway"},
            },
            "endpoints": [
                {
                    "id": "web",
                    "type": "Web",
                    "url": "https://svc.example.invalid/",
                    "protocol": "https",
                    "port": 443,
                }
            ],
        },
        object_id="svc",
        catalog_health="unknown",
        record=None,
        now=NOW,
        known_gatus_sources=known,
    )


def test_the_projection_never_publishes_the_bound_source_url() -> None:
    view = _view()
    assert view["provider"] == "gatus"
    # The service's own endpoint would resolve, but a pull provider observes
    # through a source whose URL is deployment state.
    assert view["target"] is None
    assert "gatus.example.invalid" not in json.dumps(view)
    assert view["diagnostic"] is None


def test_an_unbound_source_is_a_visible_configuration_diagnostic() -> None:
    view = _view(known=frozenset())
    assert view["diagnostic"] == "unknown_gatus_source"
    assert view["target"] is None


def test_an_incomplete_identity_is_a_visible_configuration_diagnostic() -> None:
    view = monitoring_view(
        data={
            "schema_version": 1,
            "monitoring": {"enabled": True, "provider": "gatus"},
        },
        object_id="svc",
        catalog_health="unknown",
        record=None,
        now=NOW,
        known_gatus_sources=frozenset({"prod"}),
    )
    assert view["diagnostic"] == "missing_gatus_source"


# ---------------------------------------------------------------------------
# UI: create, edit, round-trip, and provider switch
# ---------------------------------------------------------------------------


def _ui_client(alembic_session_factory, install_unrestricted_read_access):
    app = create_app()
    install_unrestricted_read_access(app)

    def override_get_session():
        with alembic_session_factory() as session:
            yield session

    app.dependency_overrides[get_session] = override_get_session
    return TestClient(app)


def _stored_gatus(alembic_session_factory, object_id: str = "svc"):
    with alembic_session_factory() as session:
        row = session.get(CatalogObject, object_id)
        assert row is not None
        return json.loads(row.data_json)["monitoring"].get("gatus")


def test_the_monitoring_form_creates_and_edits_the_gatus_identity(
    alembic_session_factory, install_unrestricted_read_access
) -> None:
    with alembic_session_factory() as session:
        upsert_object(
            session,
            CatalogObjectIn(
                id="svc",
                kind="service",
                label="svc",
                lifecycle="active",
                health="unknown",
                data={"schema_version": 1},
            ),
        )
        session.commit()

    with _ui_client(alembic_session_factory, install_unrestricted_read_access) as client:
        editor = client.get("/objects/svc?edit=monitoring&lang=en")
        assert 'name="monitoring_gatus_source"' in editor.text
        assert 'name="monitoring_gatus_endpoint"' in editor.text

        created = client.post(
            "/objects/svc/monitoring",
            data={
                "monitoring_enabled": "true",
                "monitoring_provider": "gatus",
                "monitoring_gatus_submitted": "true",
                "monitoring_gatus_source": "prod",
                "monitoring_gatus_group": "core",
                "monitoring_gatus_endpoint": "api-gateway",
                "if_match": client.get("/objects/svc").headers["etag"],
            },
            follow_redirects=False,
        )
        assert created.status_code == 303
        assert _stored_gatus(alembic_session_factory) == {
            "source": "prod",
            "group": "core",
            "endpoint": "api-gateway",
        }

        detail = client.get("/objects/svc?lang=en")
        assert "api-gateway" in detail.text
        edited = client.post(
            "/objects/svc/monitoring",
            data={
                "monitoring_enabled": "true",
                "monitoring_provider": "gatus",
                "monitoring_gatus_submitted": "true",
                "monitoring_gatus_source": "prod",
                "monitoring_gatus_group": "",
                "monitoring_gatus_endpoint": "api-gateway-v2",
                "if_match": detail.headers["etag"],
            },
            follow_redirects=False,
        )
        assert edited.status_code == 303
        assert _stored_gatus(alembic_session_factory) == {
            "source": "prod",
            "group": "",
            "endpoint": "api-gateway-v2",
        }


def test_an_unrelated_monitoring_save_never_destroys_the_gatus_identity(
    alembic_session_factory, install_unrestricted_read_access
) -> None:
    with alembic_session_factory() as session:
        upsert_object(session, _gatus_service())
        session.commit()

    with _ui_client(alembic_session_factory, install_unrestricted_read_access) as client:
        # A form that does not carry the Gatus section at all — the case that
        # silently dropped the identity before.
        response = client.post(
            "/objects/svc/monitoring",
            data={
                "monitoring_enabled": "true",
                "monitoring_provider": "gatus",
                "monitoring_interval_overridden": "true",
                "monitoring_interval_seconds": "600",
                "if_match": client.get("/objects/svc").headers["etag"],
            },
            follow_redirects=False,
        )
        assert response.status_code == 303

    assert _stored_gatus(alembic_session_factory) == {
        "source": "prod",
        "group": "core",
        "endpoint": "api-gateway",
    }


def test_switching_provider_keeps_the_gatus_identity_for_switching_back(
    alembic_session_factory, install_unrestricted_read_access
) -> None:
    with alembic_session_factory() as session:
        upsert_object(session, _gatus_service())
        session.commit()

    with _ui_client(alembic_session_factory, install_unrestricted_read_access) as client:
        switched = client.post(
            "/objects/svc/monitoring",
            data={
                "monitoring_enabled": "true",
                "monitoring_provider": "builtin_http",
                "monitoring_gatus_submitted": "true",
                "monitoring_gatus_source": "prod",
                "monitoring_gatus_group": "core",
                "monitoring_gatus_endpoint": "api-gateway",
                "if_match": client.get("/objects/svc").headers["etag"],
            },
            follow_redirects=False,
        )
        assert switched.status_code == 303

    with alembic_session_factory() as session:
        data = json.loads(session.get(CatalogObject, "svc").data_json)
    assert data["monitoring"]["provider"] == "builtin_http"
    assert data["monitoring"]["gatus"]["endpoint"] == "api-gateway"


def test_clearing_the_identity_is_explicit_and_possible(
    alembic_session_factory, install_unrestricted_read_access
) -> None:
    with alembic_session_factory() as session:
        upsert_object(session, _gatus_service())
        session.commit()

    with _ui_client(alembic_session_factory, install_unrestricted_read_access) as client:
        cleared = client.post(
            "/objects/svc/monitoring",
            data={
                "monitoring_enabled": "true",
                "monitoring_provider": "builtin_http",
                "monitoring_gatus_submitted": "true",
                "monitoring_gatus_source": "",
                "monitoring_gatus_group": "",
                "monitoring_gatus_endpoint": "",
                "if_match": client.get("/objects/svc").headers["etag"],
            },
            follow_redirects=False,
        )
        assert cleared.status_code == 303

    assert _stored_gatus(alembic_session_factory) is None


def test_an_invalid_transition_fails_closed_and_preserves_unrelated_data(
    alembic_session_factory, install_unrestricted_read_access
) -> None:
    with alembic_session_factory() as session:
        service = _gatus_service()
        service.data["summary_note"] = "keep me"
        upsert_object(session, service)
        session.commit()
        before = json.loads(session.get(CatalogObject, "svc").data_json)
        before_revision = session.get(CatalogObject, "svc").revision

    with _ui_client(alembic_session_factory, install_unrestricted_read_access) as client:
        rejected = client.post(
            "/objects/svc/monitoring",
            data={
                "monitoring_enabled": "true",
                "monitoring_provider": "gatus",
                "monitoring_gatus_submitted": "true",
                "monitoring_gatus_source": "NOT VALID",
                "monitoring_gatus_group": "core",
                "monitoring_gatus_endpoint": "api-gateway",
                "if_match": client.get("/objects/svc").headers["etag"],
            },
            follow_redirects=False,
        )
        assert rejected.status_code == 422

    with alembic_session_factory() as session:
        row = session.get(CatalogObject, "svc")
        assert json.loads(row.data_json) == before
        assert row.revision == before_revision


def test_the_detail_page_never_renders_the_bound_source_url(
    alembic_session_factory, install_unrestricted_read_access, monkeypatch
) -> None:
    monkeypatch.setenv("BLOCKWART_MONITORING_GATUS_SOURCES", f"prod={STATUS_URL}")
    with alembic_session_factory() as session:
        upsert_object(session, _gatus_service())
        session.commit()

    with _ui_client(alembic_session_factory, install_unrestricted_read_access) as client:
        for language in ("en", "de"):
            page = client.get(f"/objects/svc?lang={language}")
            assert page.status_code == 200
            assert "gatus.example.invalid" not in page.text
            assert "monitoring.provider.gatus" not in page.text


# ---------------------------------------------------------------------------
# Shared read models
# ---------------------------------------------------------------------------


def test_every_surface_shares_the_pull_observation_without_vendor_fields(
    alembic_session_factory, install_unrestricted_read_access, monkeypatch
) -> None:
    monkeypatch.setenv("BLOCKWART_MONITORING_GATUS_SOURCES", f"prod={STATUS_URL}")
    with alembic_session_factory() as session:
        upsert_object(session, _gatus_service())
        session.commit()
        record = _observe(
            session,
            state="down",
            checked_at=datetime.now(UTC) - timedelta(seconds=30),
            received_at=datetime.now(UTC),
            http_status=503,
        )
        session.commit()
        assert record is not None

    with _ui_client(alembic_session_factory, install_unrestricted_read_access) as client:
        rest = client.get("/api/v1/objects/svc")
        agent = client.get("/api/agent/objects/svc")

    assert rest.status_code == 200
    rest_monitoring = rest.json()["monitoring"]
    agent_monitoring = agent.json()["objects"][0]["monitoring"]
    assert rest_monitoring["provider"] == "gatus"
    assert rest_monitoring["state"] == "down"
    assert rest_monitoring["target"] is None
    assert rest_monitoring["last_received_at"] != rest_monitoring["last_checked_at"]
    assert agent_monitoring == rest_monitoring
    for payload in (rest.json(), agent.json()):
        rendered = json.dumps(payload)
        assert "gatus.example.invalid" not in rendered
        assert "source_url" not in rendered


def test_declared_maintenance_still_wins_over_a_pull_observation() -> None:
    record = None
    view = monitoring_view(
        data={
            "schema_version": 1,
            "monitoring": {
                "enabled": True,
                "provider": "gatus",
                "gatus": {"source": "prod", "group": "core", "endpoint": "api-gateway"},
            },
        },
        object_id="svc",
        catalog_health="maintenance",
        record=record,
        now=NOW,
        known_gatus_sources=frozenset({"prod"}),
    )
    assert view["effective_health"] == "maintenance"
