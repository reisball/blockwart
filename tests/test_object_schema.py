from copy import deepcopy

import pytest
from pydantic import ValidationError

from blockwart.domain.object_schema import (
    BUILTIN_SCHEMAS,
    SECRET_POLICY,
    FieldSpec,
    ObjectSchemaError,
    TypeSchema,
    validate_fields,
)
from blockwart.schemas.catalog import CatalogObjectIn
from blockwart.services.markdown_import import build_tools_import_plan
from blockwart.services.seeds import import_seed_payload


def test_builtin_schema_registry_is_fixed_and_complete() -> None:
    assert set(BUILTIN_SCHEMAS) == {
        "host",
        "system",
        "network",
        "service",
        "credential_reference",
        "runbook",
        "decision",
        "project",
    }
    assert all(schema.extra == "allow" for schema in BUILTIN_SCHEMAS.values())
    assert all(
        schema.secret_policy == SECRET_POLICY
        for schema in BUILTIN_SCHEMAS.values()
    )

    with pytest.raises(TypeError):
        BUILTIN_SCHEMAS["custom"] = TypeSchema("custom", ())  # type: ignore[index]


def test_generic_validator_supports_declared_field_types_and_nested_paths() -> None:
    fields = (
        FieldSpec("name", "string", required=True),
        FieldSpec("description", "text"),
        FieldSpec("retries", "integer"),
        FieldSpec("enabled", "boolean"),
        FieldSpec(
            "mode",
            "enum",
            enum_values=frozenset({"active", "passive"}),
        ),
        FieldSpec("homepage", "url"),
        FieldSpec("address", "ip"),
        FieldSpec("port", "port"),
        FieldSpec("metadata", "object"),
        FieldSpec("targets", "array"),
        FieldSpec("targets[]", "object"),
        FieldSpec(
            "targets[].ref",
            "reference",
            reference_kinds=frozenset({"service"}),
        ),
    )
    payload = {
        "name": "Example",
        "description": "Schema coverage",
        "retries": 3,
        "enabled": True,
        "mode": "active",
        "homepage": "https://example.invalid/path",
        "address": "2001:db8::1",
        "port": 8443,
        "metadata": {"owner": "operations"},
        "targets": [{"ref": "service:api"}],
        "future_field": {"remains": "allowed"},
    }
    before = deepcopy(payload)

    validate_fields(payload, fields)

    assert payload == before


@pytest.mark.parametrize(
    ("payload", "field", "path", "message"),
    [
        ({}, FieldSpec("name", "string", required=True), "data.name", "is required"),
        ({"count": True}, FieldSpec("count", "integer"), "data.count", "must be an integer"),
        (
            {"enabled": 1},
            FieldSpec("enabled", "boolean"),
            "data.enabled",
            "must be a boolean",
        ),
        (
            {"homepage": "not-a-url"},
            FieldSpec("homepage", "url"),
            "data.homepage",
            "must be a valid URL",
        ),
        (
            {"address": "999.1.1.1"},
            FieldSpec("address", "ip"),
            "data.address",
            "must be a valid IP address",
        ),
        (
            {"port": 0},
            FieldSpec("port", "port"),
            "data.port",
            "must be an integer from 1 to 65535",
        ),
        (
            {"items": [{"target": "host:wrong"}]},
            FieldSpec(
                "items[].target",
                "reference",
                reference_kinds=frozenset({"service"}),
            ),
            "data.items[0].target",
            "must reference one of: service",
        ),
    ],
)
def test_generic_validator_reports_exact_field_paths(
    payload: dict,
    field: FieldSpec,
    path: str,
    message: str,
) -> None:
    with pytest.raises(ObjectSchemaError) as exc_info:
        validate_fields(payload, (field,))

    assert exc_info.value.path == path
    assert exc_info.value.message == message
    assert str(exc_info.value) == f"{path} {message}"


@pytest.mark.parametrize(
    "path",
    [
        "password",
        "auth.token",
        "reference.value",
        "metadata.raw_value",
    ],
)
def test_schema_fields_cannot_declare_secret_value_paths(path: str) -> None:
    with pytest.raises(
        ValueError,
        match="schema fields may not declare secret value keys",
    ):
        FieldSpec(path, "string")


def test_schema_cannot_disable_global_secret_policy() -> None:
    with pytest.raises(
        ValueError,
        match="secret enforcement cannot be disabled",
    ):
        TypeSchema(  # type: ignore[arg-type]
            kind="unsafe",
            fields=(),
            secret_policy="disabled",
        )


@pytest.mark.parametrize(
    ("kind", "data", "expected_path"),
    [
        (
            "system",
            {
                "network": {
                    "addresses": [
                        {"ip": "192.168.50.1"},
                        {"ip": "not-an-ip"},
                    ]
                }
            },
            "data.network.addresses[1].ip",
        ),
        (
            "system",
            {"endpoints": [{"type": "Web", "url": "http://host", "port": 70000}]},
            "data.endpoints[0].port",
        ),
        (
            "system",
            {
                "access_methods": [
                    {"credential_references": ["service:wrong-kind"]}
                ]
            },
            "data.access_methods[0].credential_references[0]",
        ),
        (
            "service",
            {"owner": 23},
            "data.owner",
        ),
        (
            "credential_reference",
            {"scope": {"systems": ["service:wrong-kind"]}},
            "data.scope.systems[0]",
        ),
        (
            "runbook",
            {"steps": ["valid", 23]},
            "data.steps[1]",
        ),
    ],
)
def test_catalog_input_uses_schema_paths(
    kind: str,
    data: dict,
    expected_path: str,
) -> None:
    with pytest.raises(ValidationError, match=expected_path.replace("[", r"\[")):
        CatalogObjectIn.model_validate(
            {
                "id": "invalid-schema-record",
                "kind": kind,
                "label": "Invalid schema record",
                "data": data,
            }
        )


def test_builtin_schemas_preserve_unknown_fields_and_current_minimal_records() -> None:
    for kind in BUILTIN_SCHEMAS:
        record = CatalogObjectIn.model_validate(
            {
                "id": f"minimal-{kind.replace('_', '-')}",
                "kind": kind,
                "label": f"Minimal {kind}",
                "data": {
                    "schema_version": 1,
                    "future_extension": {"preserved": True},
                },
            }
        )
        assert record.data["future_extension"] == {"preserved": True}


def test_global_secret_guard_runs_independently_of_builtin_schema() -> None:
    with pytest.raises(ValidationError, match="forbidden secret-shaped key"):
        CatalogObjectIn.model_validate(
            {
                "id": "unsafe-extension",
                "kind": "project",
                "label": "Unsafe extension",
                "data": {
                    "future_extension": {
                        "password": "schema-extra-must-not-bypass-secret-policy"
                    }
                },
            }
        )


def test_credential_reference_post_rule_rejects_raw_value_paths() -> None:
    with pytest.raises(
        ValidationError,
        match=r"data\.reference\.value.*credential references may not contain raw value fields",
    ):
        CatalogObjectIn.model_validate(
            {
                "id": "unsafe-reference",
                "kind": "credential_reference",
                "label": "Unsafe reference",
                "data": {
                    "provider": "external",
                    "reference": {
                        "name": "Example",
                        "value": "not-secret-but-not-a-reference",
                    },
                },
            }
        )


def test_runbook_schema_keeps_conditional_approval_rule() -> None:
    with pytest.raises(
        ValidationError,
        match=r"data\.approval_required.*must be true",
    ):
        CatalogObjectIn.model_validate(
            {
                "id": "unsafe-runbook",
                "kind": "runbook",
                "label": "Unsafe runbook",
                "data": {
                    "risk_level": "destructive",
                    "approval_required": False,
                },
            }
        )


def test_seed_import_uses_same_nested_schema_paths(alembic_session_factory) -> None:
    payload = {
        "schema_version": 1,
        "objects": [
            {
                "id": "invalid-seed",
                "kind": "system",
                "label": "Invalid seed",
                "data": {
                    "network": {
                        "addresses": [
                            {"ip": "192.168.50.1"},
                            {"ip": "invalid"},
                        ]
                    }
                },
            }
        ],
        "relationships": [],
    }

    with alembic_session_factory() as session:
        with pytest.raises(
            ValueError,
            match=r"data\.network\.addresses\[1\]\.ip",
        ):
            import_seed_payload(session, payload)


def test_markdown_plan_validates_through_catalog_schema(tmp_path) -> None:
    tools_path = tmp_path / "TOOLS.md"
    tools_path.write_text(
        """
| System | Typ | IP:Port | Status | Access | Auth | Nutzung |
|---|---|---|---|---|---|---|
| Example | CT 222 | 192.168.50.222:8080 | ✅ | SSH | key | Test |
""".strip(),
        encoding="utf-8",
    )
    plan = build_tools_import_plan(tools_path)

    validated = [
        CatalogObjectIn.model_validate(raw_object)
        for raw_object in plan.payload["objects"]
    ]

    assert len(validated) == plan.object_count
