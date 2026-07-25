from __future__ import annotations

import pytest

from blockwart.domain.interfaces import (
    CANONICAL_ENDPOINT_TYPES,
    InterfaceContractError,
    normalize_endpoint,
    normalize_interface_data,
)


def test_legacy_interfaces_normalize_without_guessing_http_capability() -> None:
    source = {
        "schema_version": 1,
        "endpoints": [
            {
                "name": "Service",
                "url": "https://service.example.test:8443/api",
                "port": 8443,
                "protocol": "tcp",
                "exposure": "lan",
            }
        ],
        "ports": [
            {"port": 8443, "protocol": "tcp", "exposure": "lan"},
            {"port": 9090, "protocol": "tcp", "purpose": "debug"},
        ],
        "access_methods": [
            {
                "type": "api",
                "endpoint": "https://service.example.test:8443/api",
                "auth_mode": "token",
                "credential_references": ["credential_reference:service-api"],
            },
            {
                "type": "ssh",
                "endpoint": "ssh://admin@service.example.test:22",
                "auth_mode": "key",
                "credential_references": ["credential_reference:service-ssh"],
            },
        ],
    }

    result = normalize_interface_data(source, kind="service", object_id="service")

    assert result.changed
    assert [endpoint["type"] for endpoint in result.data["endpoints"]] == [
        "HTTP",
        "SSH",
    ]
    assert result.data["endpoints"][0] == {
        "name": "Service",
        "label": "Service",
        "id": "http-8443-service-example-test",
        "type": "HTTP",
        "url": "https://service.example.test:8443/api",
        "host": "service.example.test",
        "port": 8443,
        "path": "/api",
        "protocol": "https",
        "transport": "tcp",
        "exposure": "lan",
    }
    assert result.data["ports"] == [
        {
            "port": 9090,
            "transport": "tcp",
            "exposure": "unknown",
            "purpose": "debug",
        }
    ]
    assert result.data["access_methods"][0]["type"] == "admin_api"
    assert (
        result.data["access_methods"][0]["endpoint_id"]
        == "http-8443-service-example-test"
    )
    assert result.data["access_methods"][1]["endpoint_id"] == (
        "ssh-22-service-example-test"
    )
    assert result.data["interface"] == {"state": "available"}
    assert {
        diagnostic.code for diagnostic in result.diagnostics
    } >= {
        "access_endpoint_deduplicated",
        "access_endpoint_promoted",
        "endpoint_port_duplicate",
    }

    repeated = normalize_interface_data(
        result.data,
        kind="service",
        object_id="service",
    )
    assert repeated.data == result.data
    assert not repeated.changed
    assert repeated.diagnostics == ()


def test_service_without_endpoint_is_explicitly_incomplete() -> None:
    result = normalize_interface_data(
        {"schema_version": 1},
        kind="service",
        object_id="worker",
    )

    assert result.data["interface"] == {"state": "incomplete"}
    assert [diagnostic.code for diagnostic in result.diagnostics] == [
        "service_interface_incomplete"
    ]


def test_legacy_internal_service_is_not_forced_to_have_endpoint() -> None:
    result = normalize_interface_data(
        {
            "schema_version": 1,
            "service_interface": {
                "type": "queue_worker",
                "endpoint_required": False,
            },
            "endpoints": [],
        },
        kind="service",
        object_id="worker",
    )

    assert result.data["interface"] == {
        "state": "not_applicable",
        "reason": "queue_worker",
    }


def test_empty_legacy_access_endpoint_is_migrated_but_rejected_on_write() -> None:
    source = {
        "access_methods": [
            {
                "type": "api",
                "endpoint": "",
                "auth_mode": "token",
            }
        ]
    }

    with pytest.raises(InterfaceContractError, match="must be a non-empty string"):
        normalize_interface_data(source, kind="service", object_id="agent")

    result = normalize_interface_data(
        source,
        kind="service",
        object_id="agent",
        allow_legacy=True,
    )

    assert result.data["access_methods"] == [
        {
            "id": "admin_api",
            "type": "admin_api",
            "auth_mode": "token",
        }
    ]
    assert result.data["interface"] == {"state": "incomplete"}
    assert {
        diagnostic.code for diagnostic in result.diagnostics
    } == {
        "access_id_added",
        "empty_access_endpoint_removed",
        "service_interface_incomplete",
    }


def test_endpoint_ids_are_stable_and_unique() -> None:
    result = normalize_interface_data(
        {
            "endpoints": [
                {"type": "Web", "host": "service", "port": 8080},
                {"type": "REST API", "host": "service", "port": 8080},
            ]
        },
        kind="system",
        object_id="runtime",
    )

    assert [endpoint["id"] for endpoint in result.data["endpoints"]] == [
        "web-8080-service",
        "rest-api-8080-service",
    ]


@pytest.mark.parametrize("endpoint_type", CANONICAL_ENDPOINT_TYPES)
def test_all_builtin_endpoint_capabilities_are_supported(endpoint_type: str) -> None:
    endpoint = normalize_endpoint(
        {"type": endpoint_type, "host": "service.example.test"},
    )

    assert endpoint["type"] == endpoint_type
    assert endpoint["transport"] == ("udp" if endpoint_type == "UDP" else "tcp")


def test_custom_endpoint_type_requires_and_preserves_protocol() -> None:
    endpoint = normalize_endpoint(
        {
            "type": "x-grpc",
            "host": "service.example.test",
            "port": 50051,
            "protocol": "grpc",
        },
    )

    assert endpoint["type"] == "x-grpc"
    assert endpoint["protocol"] == "grpc"
    assert endpoint["transport"] == "tcp"

    with pytest.raises(InterfaceContractError, match="protocol is required"):
        normalize_endpoint({"type": "x-grpc", "host": "service.example.test"})


@pytest.mark.parametrize(
    ("data", "message"),
    [
        (
            {"endpoints": [{"type": "made up", "host": "service"}]},
            "endpoint type must be one of",
        ),
        (
            {
                "endpoints": [{"id": "web", "type": "Web", "host": "service"}],
                "access_methods": [{"type": "ssh", "endpoint_id": "missing"}],
            },
            "references a missing endpoint",
        ),
        (
            {
                "endpoints": [
                    {
                        "type": "Web",
                        "host": "service",
                        "transport": "sctp",
                    }
                ]
            },
            "transport must be tcp or udp",
        ),
    ],
)
def test_invalid_interface_contract_fails_closed(
    data: dict,
    message: str,
) -> None:
    with pytest.raises(InterfaceContractError, match=message):
        normalize_interface_data(data, kind="service", object_id="service")
