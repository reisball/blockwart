from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from blockwart.domain.auth import ObjectVisibility
from blockwart.services.queries import _explorer_asset


def _asset(data: dict[str, Any], *, kind: str = "network") -> dict[str, Any]:
    catalog_object = SimpleNamespace(
        id="explorer-test-object",
        kind=kind,
        label="Explorer test object",
        visibility=ObjectVisibility.DETAIL,
        capabilities=[],
        data=data,
        summary=None,
        status="active",
        lifecycle="active",
        health="healthy",
        last_changed=None,
        updated_at=None,
    )
    return _explorer_asset(catalog_object, monitoring_index={})


def test_explorer_prefers_explicit_network_ip_and_shows_network_model() -> None:
    asset = _asset(
        {
            "network": {
                "category": "access_point",
                "addresses": [{"ip": "192.0.2.10"}],
                "hostnames": ["router.example.invalid"],
                "manufacturer": "AVM",
                "model": "FRITZ!Repeater 6000",
            },
            "endpoints": [
                {
                    "type": "Web",
                    "host": "192.0.2.20",
                    "url": "https://192.0.2.30/admin",
                }
            ],
        }
    )

    assert asset["address"] == "192.0.2.10"
    assert asset["platform"] == "AVM FRITZ!Repeater 6000"


def test_explorer_uses_network_hostname_before_endpoint_host() -> None:
    asset = _asset(
        {
            "network": {
                "category": "router",
                "hostnames": ["router.example.invalid"],
            },
            "endpoints": [{"type": "Web", "host": "192.0.2.20"}],
        }
    )

    assert asset["address"] == "router.example.invalid"


def test_explorer_falls_back_to_endpoint_host_then_url_hostname() -> None:
    host_asset = _asset(
        {
            "network": {"category": "router"},
            "endpoints": [
                {
                    "type": "Web",
                    "host": "router.example.invalid",
                    "url": "https://192.0.2.20/admin",
                }
            ],
        }
    )
    url_asset = _asset(
        {
            "network": {"category": "router"},
            "endpoints": [{"type": "Web", "url": "https://router.example.invalid:8443/admin"}],
        }
    )

    assert host_asset["address"] == "router.example.invalid"
    assert url_asset["address"] == "router.example.invalid"


def test_explorer_preserves_explicit_platform_over_nested_model() -> None:
    asset = _asset(
        {
            "platform": "Proxmox VE 9.2.1",
            "hardware": {"manufacturer": "Lenovo", "model": "M75q"},
        },
        kind="host",
    )

    assert asset["platform"] == "Proxmox VE 9.2.1"


@pytest.mark.parametrize(
    "url",
    ["/relative/path", "https://[invalid"],
)
def test_explorer_ignores_endpoint_urls_without_a_valid_host(url: str) -> None:
    asset = _asset(
        {
            "network": {"category": "router"},
            "endpoints": [{"type": "Web", "url": url}],
        }
    )

    assert asset["address"] == ""
