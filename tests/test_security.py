import pytest
from pydantic import ValidationError

from blockwart.domain.security import find_secret_violations
from blockwart.schemas.catalog import CatalogObjectIn


@pytest.mark.parametrize("forbidden_key", ["secret", "password", "api_key"])
def test_secret_shaped_keys_are_rejected(forbidden_key: str) -> None:
    with pytest.raises(ValidationError, match="forbidden secret-shaped key"):
        CatalogObjectIn(
            id="bad",
            kind="system",
            label="Bad",
            data={forbidden_key: "not-allowed"},
        )


def test_reference_labels_are_allowed() -> None:
    obj = CatalogObjectIn(
        id="n8n",
        kind="system",
        label="n8n",
        data={"credential_references": ["credential_reference:n8n-api-credential"]},
    )

    assert obj.id == "n8n"


def test_private_key_pattern_is_rejected() -> None:
    violations = find_secret_violations({"value": "-----BEGIN PRIVATE KEY-----\nabc"})

    assert violations


@pytest.mark.parametrize("forbidden_key", ["value", "raw", "plaintext"])
def test_credential_references_reject_raw_value_fields(forbidden_key: str) -> None:
    with pytest.raises(
        ValidationError,
        match="credential references may not contain raw value fields",
    ):
        CatalogObjectIn(
            id="bad-reference",
            kind="credential_reference",
            label="Bad Reference",
            data={
                "provider": "external",
                "reference": {"name": "example", forbidden_key: "not-a-secret"},
            },
        )


@pytest.mark.parametrize(
    "data",
    [
        {"system_id": "service:wrong-kind"},
        {"dependencies": {"upstream": ["credential_reference:wrong-kind"]}},
        {
            "access_methods": [
                {"credential_references": ["service:wrong-kind"]},
            ]
        },
    ],
)
def test_typed_reference_kind_mismatches_are_rejected(data: dict) -> None:
    with pytest.raises(ValidationError, match="must reference one of"):
        CatalogObjectIn(
            id="wrong-reference",
            kind="service" if "system_id" in data else "system",
            label="Wrong Reference",
            data=data,
        )
