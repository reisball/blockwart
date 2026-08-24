from __future__ import annotations

import json
import tomllib
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from blockwart.cli.release import main
from blockwart.release.schemas import SCHEMA_NAMES
from blockwart.release.spec import parse_spec


@pytest.mark.parametrize("name", SCHEMA_NAMES)
def test_release_cli_prints_valid_versioned_json_schemas(
    name: str, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["--print-schema", name]) == 0
    payload = json.loads(capsys.readouterr().out)
    Draft202012Validator.check_schema(payload)
    assert payload["$schema"] == "https://json-schema.org/draft/2020-12/schema"


@pytest.mark.parametrize(
    ("argv", "code"),
    [
        ([], "missing_required_argument"),
        (["plan", "--apply", "--spec", "/tmp/spec.json"], "apply_requires_release_action"),
        (
            ["release", "--apply", "--spec", "/tmp/spec.json"],
            "expect_current_required_for_apply",
        ),
        (["unknown-action"], "invalid_cli_arguments"),
    ],
)
def test_release_cli_usage_failures_are_stable_json(
    argv: list[str], code: str, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(argv) == 2
    error = json.loads(capsys.readouterr().err)
    assert error == {
        "error": code,
        "mode": "error",
        "outcome": "failed",
        "schema_version": 1,
    }


def test_release_console_script_is_packaged() -> None:
    project = Path(__file__).resolve().parents[1]
    document = tomllib.loads((project / "pyproject.toml").read_text(encoding="utf-8"))
    assert document["project"]["scripts"]["blockwart-release"] == (
        "blockwart.cli.release:main"
    )


def test_documented_release_spec_matches_the_v1_schema() -> None:
    project = Path(__file__).resolve().parents[1]
    document = json.loads(
        (project / "examples/release/spec-v1.json").read_text(encoding="utf-8")
    )

    parsed = parse_spec(document)

    assert parsed.spec_version == 1
    assert parsed.source.commit == "1" * 40
