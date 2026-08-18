from __future__ import annotations

import ipaddress
import re
import tomllib
from pathlib import Path
from urllib.parse import urlparse

import yaml

from blockwart.cli.import_markdown import DEFAULT_REFERENCES_ROOT, DEFAULT_TOOLS_PATH

ROOT = Path(__file__).resolve().parents[1]
SEED_PATH = ROOT / "seeds" / "pilot_objects.yaml"
GITHUB_WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"
GITEA_WORKFLOW = ROOT / ".gitea" / "workflows" / "ci.yml"


def test_project_declares_apache_license() -> None:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]

    assert project["license"] == "Apache-2.0"
    assert "Apache License" in (ROOT / "LICENSE").read_text(encoding="utf-8")


def test_ci_is_host_neutral_least_privilege_and_immutably_pinned() -> None:
    github = GITHUB_WORKFLOW.read_text(encoding="utf-8")
    gitea = GITEA_WORKFLOW.read_text(encoding="utf-8")

    assert github == gitea
    assert "permissions:\n  contents: read\n" in github
    uses = re.findall(r"^\s*uses:\s*[^@\s]+@([^\s#]+)", github, flags=re.MULTILINE)
    assert uses
    assert all(re.fullmatch(r"[0-9a-f]{40}", revision) for revision in uses)


def test_version_update_bots_are_not_scheduled() -> None:
    assert not (ROOT / ".github" / "dependabot.yml").exists()


def test_markdown_import_defaults_are_workspace_relative() -> None:
    assert DEFAULT_TOOLS_PATH == Path("TOOLS.md")
    assert DEFAULT_REFERENCES_ROOT == Path(".")


def test_example_seed_uses_only_documentation_network_identifiers() -> None:
    seed = yaml.safe_load(SEED_PATH.read_text(encoding="utf-8"))
    documentation_network = ipaddress.ip_network("192.0.2.0/24")

    assert seed["owner"] == "Example Operators"
    assert seed["objects"]
    for obj in seed["objects"]:
        data = obj.get("data") or {}
        network = data.get("network") or {}
        for address in network.get("addresses") or []:
            assert ipaddress.ip_address(address["ip"]) in documentation_network
            assert address.get("network", "") in {"", str(documentation_network)}
        for mac in network.get("mac_addresses") or []:
            first_octet = int(mac["value"].split(":", 1)[0], 16)
            assert first_octet & 0b10
            assert not first_octet & 0b1

        endpoints = list(data.get("access_methods") or [])
        endpoints.extend(data.get("endpoints") or [])
        for endpoint in endpoints:
            value = endpoint.get("endpoint") or endpoint.get("url") or ""
            if not value or "://" not in value:
                continue
            host = urlparse(value).hostname
            if not host or host == "localhost":
                continue
            try:
                address = ipaddress.ip_address(host)
            except ValueError:
                assert host.endswith(".invalid") or "." not in host
            else:
                assert address in documentation_network


def test_example_seed_has_no_absolute_home_or_agent_workspace_path() -> None:
    source = SEED_PATH.read_text(encoding="utf-8")

    assert "/home/" not in source
    assert ".openclaw" not in source
