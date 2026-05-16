import pytest
from pydantic import ValidationError

from blockwart.domain.security import find_secret_violations
from blockwart.schemas.catalog import CatalogObjectIn


def test_secret_shaped_keys_are_rejected() -> None:
    with pytest.raises(ValidationError):
        CatalogObjectIn(
            id="bad",
            kind="system",
            label="Bad",
            data={"password": "not-allowed"},
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

