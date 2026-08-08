import json
import re
from pathlib import Path
from typing import get_args

import pytest
from pydantic import ValidationError

from blockwart.domain.asset_state import (
    ASSET_HEALTH_VALUES,
    ASSET_KINDS,
    ASSET_LIFECYCLES,
)
from blockwart.domain.object_schema import (
    BUILTIN_SCHEMAS,
    DEVICE_CATEGORIES,
    FORBIDDEN_DATA_VALUE_KEYS,
    NETWORK_CATEGORIES,
    SCHEMA_RULE_CONTRACTS,
    rule_name,
)
from blockwart.domain.references import VALID_REFERENCE_KINDS
from blockwart.domain.relationships import LINK_KINDS, RELATIONSHIP_RULES
from blockwart.domain.schema_projection import (
    SCHEMA_PROJECTION_VERSION,
    minimal_object_example,
)
from blockwart.domain.security import (
    FORBIDDEN_ACL_DATA_KEYS,
    FORBIDDEN_SECRET_KEYS,
    find_secret_violations,
)
from blockwart.mcp.server import (
    DEVICE_WRITE_SCHEMA,
    OBJECT_WRITE_SCHEMA,
    SCHEMA_TOOL_NAME,
    TOOL_DEFINITIONS,
    TOOL_INPUT_VALIDATORS,
    ToolInputError,
    call_tool,
    describe_schema_payload,
)
from blockwart.schemas.catalog import OBJECT_STATUSES, CatalogObjectIn, ObjectKind

CONTRACT_PATH = Path(__file__).resolve().parent / "contracts" / "openapi.json"
JSON_TYPES = {"array", "boolean", "integer", "number", "object", "string"}
OBJECT_WRITE_INTENTS = (
    ("blockwart.create_child", "object"),
    ("blockwart.create_root", "object"),
    ("blockwart.update_object", "object"),
    ("blockwart.create_attached_device", "device"),
)


def _projected_kinds(payload: dict) -> dict[str, dict]:
    return {kind["kind"]: kind for kind in payload["kinds"]}


def _fields(kind_payload: dict) -> dict[str, dict]:
    return {field["path"]: field for field in kind_payload["data"]["fields"]}


def _no_upstream(*args, **kwargs):
    raise AssertionError("the published schema contract must not call the API")


def test_every_writable_kind_is_published_exactly_once() -> None:
    payload = describe_schema_payload()
    published = [kind["kind"] for kind in payload["kinds"]]

    assert published == list(BUILTIN_SCHEMAS)
    assert published == list(get_args(ObjectKind))
    assert published == OBJECT_WRITE_SCHEMA["properties"]["kind"]["enum"]
    assert payload["version"] == SCHEMA_PROJECTION_VERSION
    assert payload["asset_kinds"] == sorted(ASSET_KINDS)
    assert payload["knowledge_kinds"] == sorted(set(published) - ASSET_KINDS)
    assert set(payload["asset_kinds"]) | set(payload["knowledge_kinds"]) == set(published)


def test_projected_fields_match_the_domain_registry_exactly() -> None:
    kinds = _projected_kinds(describe_schema_payload())

    for kind, schema in BUILTIN_SCHEMAS.items():
        projected = _fields(kinds[kind])
        assert list(projected) == [field.path for field in schema.fields]
        assert kinds[kind]["data"]["unknown_properties"] == schema.extra
        assert kinds[kind]["data"]["secret_policy"] == schema.secret_policy

        for field in schema.fields:
            entry = projected[field.path]
            expected_requirement = "optional"
            if field.forbidden_message is not None:
                expected_requirement = "forbidden"
            elif field.required:
                expected_requirement = "required"

            assert entry["type"] == field.field_type
            assert entry["requirement"] == expected_requirement
            assert entry["json_types"]
            assert set(entry["json_types"]) <= JSON_TYPES
            assert entry.get("enum", []) == sorted(field.enum_values)
            assert entry.get("reference_kinds", []) == sorted(field.reference_kinds)
            assert set(entry.get("reference_kinds", [])) <= VALID_REFERENCE_KINDS
            assert entry.get("min_length") == field.min_length
            assert entry.get("max_length") == field.max_length
            assert entry["normalization"] == (
                ["strip_whitespace"] if field.strip_whitespace else []
            )
            assert ("const" in entry) is field.has_literal
            if field.has_literal:
                assert entry["const"] == field.literal
            assert entry.get("reason") == field.forbidden_message
            if field.forbidden_message is None:
                assert entry.get("constraint") == field.message


def test_enum_fields_publish_the_json_type_of_their_canonical_values() -> None:
    kinds = _projected_kinds(describe_schema_payload())

    for kind, schema in BUILTIN_SCHEMAS.items():
        projected = _fields(kinds[kind])
        for field in schema.fields:
            if field.field_type != "enum":
                continue
            assert set(projected[field.path]["json_types"]) == {
                "boolean" if isinstance(value, bool) else "string"
                for value in field.enum_values
            }


def test_device_and_network_categories_come_from_the_canonical_registry() -> None:
    kinds = _projected_kinds(describe_schema_payload())
    device_category = _fields(kinds["device"])["device.category"]
    network_category = _fields(kinds["network"])["network.category"]

    assert device_category["requirement"] == "required"
    assert device_category["enum"] == sorted(DEVICE_CATEGORIES)
    assert network_category["requirement"] == "required"
    assert network_category["enum"] == sorted(NETWORK_CATEGORIES)
    assert _fields(kinds["device"])["device"]["requirement"] == "required"

    # Issue #138: `virtual` is a relationship link kind, never a device category.
    # The published contract must make that distinction discoverable.
    assert "virtual" in LINK_KINDS
    assert "virtual" not in device_category["enum"]
    with pytest.raises(ValidationError):
        CatalogObjectIn(
            id="device-with-link-kind",
            kind="device",
            label="Device",
            data={"device": {"category": "virtual"}},
        )


def test_required_nested_paths_are_published_and_enforced() -> None:
    kinds = _projected_kinds(describe_schema_payload())

    for kind in BUILTIN_SCHEMAS:
        required = [
            field["path"]
            for field in kinds[kind]["data"]["fields"]
            if field["requirement"] == "required"
        ]
        empty_data_write = {
            "id": f"empty-{kind.replace('_', '-')}",
            "kind": kind,
            "label": "Empty",
            "data": {},
        }
        if required:
            # Issue #138: an empty object passes the shallow MCP input schema but
            # the domain rejects it, so the missing paths must be discoverable.
            TOOL_INPUT_VALIDATORS["blockwart.create_root"].validate(
                {"idempotency_key": "empty-data-write-0001", "object": empty_data_write}
            )
            with pytest.raises(ValidationError):
                CatalogObjectIn(**empty_data_write)
        else:
            CatalogObjectIn(**empty_data_write)

    assert required_paths(kinds, "device") == ["device", "device.category"]
    assert required_paths(kinds, "network") == ["network.category"]


def required_paths(kinds: dict[str, dict], kind: str) -> list[str]:
    return [
        field["path"]
        for field in kinds[kind]["data"]["fields"]
        if field["requirement"] == "required"
    ]


def test_forbidden_paths_are_published_and_rejected() -> None:
    kinds = _projected_kinds(describe_schema_payload())
    forbidden = _fields(kinds["host"])["lifecycle"]

    assert forbidden["requirement"] == "forbidden"
    assert forbidden["reason"] == "is obsolete; use top-level fields"
    with pytest.raises(ValidationError):
        CatalogObjectIn(
            id="legacy-lifecycle-host",
            kind="host",
            label="Host",
            data={"lifecycle": "active"},
        )


def test_secret_rules_are_published_without_any_value() -> None:
    payload = describe_schema_payload()
    policy = payload["secret_policy"]

    assert policy["mode"] == "global_enforced"
    assert policy["enforced_before_kind_schema"] is True
    assert policy["can_be_disabled_by_a_kind_schema"] is False
    assert policy["raw_secret_values_rejected"] is True
    assert policy["forbidden_key_names"] == sorted(FORBIDDEN_SECRET_KEYS)
    assert policy["forbidden_value_key_names"] == sorted(FORBIDDEN_DATA_VALUE_KEYS)
    assert policy["forbidden_access_control_key_names"] == sorted(FORBIDDEN_ACL_DATA_KEYS)
    assert all(
        kind["data"]["secret_policy"] == "global_enforced" for kind in payload["kinds"]
    )

    # The contract names forbidden keys; it never carries a secret-shaped key or
    # a value that looks like a credential.
    assert find_secret_violations(payload) == []
    assert not any(
        path.split(".")[-1].removesuffix("[]") in FORBIDDEN_DATA_VALUE_KEYS
        for kind in payload["kinds"]
        for path in (field["path"] for field in kind["data"]["fields"])
    )


def test_every_schema_rule_publishes_a_contract() -> None:
    kinds = _projected_kinds(describe_schema_payload())

    for kind, schema in BUILTIN_SCHEMAS.items():
        published = kinds[kind]["data"]["rules"]
        assert [rule["rule"] for rule in published] == [
            rule_name(rule).lstrip("_") for rule in schema.rules
        ]
        for rule, entry in zip(schema.rules, published, strict=True):
            assert entry["description"] == SCHEMA_RULE_CONTRACTS[rule_name(rule)]
            assert entry["description"]

    assert [rule["rule"] for rule in kinds["runbook"]["data"]["rules"]] == [
        "validate_runbook_approval"
    ]
    assert [rule["rule"] for rule in kinds["credential_reference"]["data"]["rules"]] == [
        "reject_credential_value_keys"
    ]


def test_lifecycle_and_health_semantics_follow_asset_kinds() -> None:
    kinds = _projected_kinds(describe_schema_payload())

    for kind in BUILTIN_SCHEMAS:
        lifecycle = kinds[kind]["lifecycle"]
        health = kinds[kind]["health"]
        assert kinds[kind]["status"] == {
            "values": list(OBJECT_STATUSES),
            "default": "active",
        }
        if kind in ASSET_KINDS:
            assert kinds[kind]["kind_class"] == "asset"
            assert lifecycle == {
                "supported": True,
                "values": list(ASSET_LIFECYCLES),
                "requirement": "optional",
                "nullable": True,
                "default": None,
                "reason": None,
            }
            assert health["values"] == list(ASSET_HEALTH_VALUES)
            CatalogObjectIn(
                **minimal_object_example(kind),
                lifecycle="planned",
                health="degraded",
            )
        else:
            assert kinds[kind]["kind_class"] == "knowledge"
            assert lifecycle["supported"] is False
            assert lifecycle["values"] == []
            assert lifecycle["requirement"] == "forbidden"
            assert health["supported"] is False
            assert health["values"] == []
            assert health["requirement"] == "forbidden"
            with pytest.raises(ValidationError):
                CatalogObjectIn(**minimal_object_example(kind), lifecycle="planned")


def test_minimal_examples_validate_against_the_canonical_domain_model() -> None:
    payload = describe_schema_payload()

    for kind in payload["kinds"]:
        example = kind["minimal_example"]
        assert example == minimal_object_example(kind["kind"])
        assert example["kind"] == kind["kind"]
        validated = CatalogObjectIn(**example)
        assert validated.kind == kind["kind"]
        assert validated.lifecycle is None and validated.health is None
        for field in kind["data"]["fields"]:
            if field["requirement"] == "required":
                assert _resolve(example["data"], field["path"]) is not None


def _resolve(data, path: str):
    value = data
    for part in path.split("."):
        key = part.removesuffix("[]")
        if not isinstance(value, dict) or key not in value:
            return None
        value = value[key]
        if part.endswith("[]"):
            value = value[0] if value else None
    return value


def test_write_intent_examples_are_valid_for_their_tool_and_the_domain() -> None:
    payload = describe_schema_payload()
    intents = {intent["tool"]: intent for intent in payload["write_intents"]}

    assert list(intents) == [name for name, _ in OBJECT_WRITE_INTENTS]
    for name, argument in OBJECT_WRITE_INTENTS:
        intent = intents[name]
        assert intent["object_argument"] == argument
        assert intent["required_arguments"] == sorted(
            TOOL_DEFINITIONS[name]["inputSchema"]["required"],
            key=TOOL_DEFINITIONS[name]["inputSchema"]["required"].index,
        )
        TOOL_INPUT_VALIDATORS[name].validate(intent["example"])
        written = intent["example"][argument]
        assert written["kind"] in intent["kinds"]
        assert CatalogObjectIn(**written).kind == written["kind"]


def test_write_intent_kinds_follow_the_domain_relationship_rules() -> None:
    intents = {
        intent["tool"]: intent for intent in describe_schema_payload()["write_intents"]
    }
    placement = RELATIONSHIP_RULES["hosts"]
    attachment = RELATIONSHIP_RULES["attached_to"]

    assert set(intents["blockwart.create_child"]["kinds"]) == set(placement.to_kinds)
    assert intents["blockwart.create_child"]["parent_kinds"] == sorted(placement.from_kinds)
    assert intents["blockwart.create_child"]["relation_type"] == "hosts"
    assert intents["blockwart.create_attached_device"]["kinds"] == ["device"]
    assert intents["blockwart.create_attached_device"]["parent_kinds"] == sorted(
        attachment.to_kinds
    )
    assert intents["blockwart.create_attached_device"]["relation_type"] == "attached_to"
    for name in ("blockwart.create_root", "blockwart.update_object"):
        assert intents[name]["kinds"] == list(get_args(ObjectKind))
        assert intents[name]["relation_type"] is None


def test_object_write_intents_share_one_canonical_projection() -> None:
    data_schemas = [
        TOOL_DEFINITIONS[name]["inputSchema"]["properties"][argument]["properties"]["data"]
        for name, argument in OBJECT_WRITE_INTENTS
    ]

    # One shared schema object, not four maintained copies.
    assert all(schema is data_schemas[0] for schema in data_schemas)
    assert data_schemas[0] is OBJECT_WRITE_SCHEMA["properties"]["data"]
    assert DEVICE_WRITE_SCHEMA["properties"]["data"] is OBJECT_WRITE_SCHEMA["properties"]["data"]
    assert SCHEMA_TOOL_NAME in data_schemas[0]["description"]
    for name, _ in OBJECT_WRITE_INTENTS:
        assert SCHEMA_TOOL_NAME in TOOL_DEFINITIONS[name]["description"]
    for state in ("lifecycle", "health"):
        assert SCHEMA_TOOL_NAME in OBJECT_WRITE_SCHEMA["properties"][state]["description"]
        assert all(
            kind in OBJECT_WRITE_SCHEMA["properties"][state]["description"]
            for kind in ASSET_KINDS
        )


def test_describe_schema_tool_is_local_read_only_and_deterministic() -> None:
    tool = TOOL_DEFINITIONS[SCHEMA_TOOL_NAME]

    assert tool["annotations"] == {
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    }
    assert tool["inputSchema"]["properties"]["kind"]["enum"] == list(get_args(ObjectKind))
    assert tool["inputSchema"]["additionalProperties"] is False
    assert "required" not in tool["inputSchema"]

    result = call_tool(SCHEMA_TOOL_NAME, {}, fetcher=_no_upstream, requester=_no_upstream)
    repeated = call_tool(SCHEMA_TOOL_NAME, None, fetcher=_no_upstream, requester=_no_upstream)

    assert result["isError"] is False
    assert result == repeated
    payload = json.loads(result["content"][0]["text"])
    assert payload == describe_schema_payload()
    assert result["content"][0]["text"] == json.dumps(payload, indent=2, sort_keys=True)
    assert payload["requested_kind"] is None

    # Each call returns an independent document; a mutated result cannot leak
    # into the next published contract.
    payload["kinds"].clear()
    assert describe_schema_payload()["kinds"]


def test_describe_schema_filters_one_kind_without_losing_the_shared_contract() -> None:
    result = call_tool(
        SCHEMA_TOOL_NAME,
        {"kind": "device"},
        fetcher=_no_upstream,
        requester=_no_upstream,
    )
    payload = json.loads(result["content"][0]["text"])
    complete = describe_schema_payload()

    assert payload["requested_kind"] == "device"
    assert payload["kinds"] == [
        kind for kind in complete["kinds"] if kind["kind"] == "device"
    ]
    assert payload["secret_policy"] == complete["secret_policy"]
    assert [intent["tool"] for intent in payload["write_intents"]] == [
        "blockwart.create_root",
        "blockwart.update_object",
        "blockwart.create_attached_device",
    ]
    assert all(intent["kinds"] == ["device"] for intent in payload["write_intents"])


@pytest.mark.parametrize(
    "arguments",
    [{"kind": "virtual"}, {"kind": "appliance"}, {"unknown": "field"}, {"kind": 1}],
)
def test_describe_schema_rejects_invalid_arguments(arguments) -> None:
    with pytest.raises(ToolInputError):
        call_tool(
            SCHEMA_TOOL_NAME,
            arguments,
            fetcher=_no_upstream,
            requester=_no_upstream,
        )


def test_mcp_rest_and_domain_object_contracts_cannot_drift() -> None:
    rest = json.loads(CONTRACT_PATH.read_text())["components"]["schemas"]["CatalogObjectIn"]
    payload = describe_schema_payload()
    properties = OBJECT_WRITE_SCHEMA["properties"]

    assert rest["required"] == OBJECT_WRITE_SCHEMA["required"]
    assert rest["properties"]["kind"]["enum"] == properties["kind"]["enum"]
    assert rest["properties"]["kind"]["enum"] == [kind["kind"] for kind in payload["kinds"]]
    assert rest["properties"]["status"]["enum"] == properties["status"]["enum"]
    assert rest["properties"]["status"]["enum"] == payload["object_status"]["values"]
    assert rest["properties"]["status"]["default"] == payload["object_status"]["default"]

    for state, values in (
        ("lifecycle", list(ASSET_LIFECYCLES)),
        ("health", list(ASSET_HEALTH_VALUES)),
    ):
        rest_values = rest["properties"][state]["anyOf"][0]["enum"]
        assert rest_values == values
        assert properties[state]["enum"] == [*values, None]
        for kind in payload["kinds"]:
            assert kind[state]["values"] == (values if kind["kind"] in ASSET_KINDS else [])

    rest_id = re.compile(rest["properties"]["id"]["pattern"])
    mcp_id = re.compile(properties["id"]["pattern"])
    for candidate in ("a", "ab", "a-b_c1", "-abc", "abc-", "A", "", "a--b"):
        assert bool(rest_id.fullmatch(candidate)) is bool(mcp_id.fullmatch(candidate))


def test_published_contract_is_json_safe_and_stable() -> None:
    payload = describe_schema_payload()

    encoded = json.dumps(payload, indent=2, sort_keys=True, allow_nan=False)
    assert json.loads(encoded) == payload
    assert json.dumps(describe_schema_payload(), sort_keys=True) == json.dumps(
        payload, sort_keys=True
    )
