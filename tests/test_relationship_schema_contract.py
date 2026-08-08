"""Type-dependent relationship contract (Issue #139).

The domain relationship registry is the single source of the relationship
vocabulary, the accepted directed endpoint kinds, the endpoint predicates, the
type-dependent metadata, the graph rules, and the rejection catalog. These
tests pin the parity contract every machine boundary must publish: MCP, REST,
and OpenAPI project the same registry, an agent can decide before a write what
a relationship type accepts, and an invalid command falls into the canonical
field-accurate error contract without disclosing catalog state.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, get_args

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError
from sqlalchemy import text
from test_device_commands import (  # noqa: F401
    device_command_client,
    device_command_state,
)

from blockwart.domain.object_schema import SCHEMA_VIOLATION_CONTRACTS
from blockwart.domain.references import VALID_REFERENCE_KINDS
from blockwart.domain.relationship_projection import (
    RELATIONSHIP_PROJECTION_VERSION,
    metadata_json_schema,
    metadata_union_json_schema,
    relation_type_json_schema,
    relationship_metadata_conditions,
    relationship_projection,
)
from blockwart.domain.relationships import (
    ENDPOINT_PREDICATE_CONTRACTS,
    GRAPH_RULE_CONTRACTS,
    LINK_KINDS,
    NETWORK_DEVICE_CATEGORIES,
    RELATIONSHIP_PATH_ROOTS,
    RELATIONSHIP_REJECTIONS,
    RELATIONSHIP_RULES,
    RELATIONSHIP_TYPES,
    UPLINK_MODES,
    EndpointDescriptor,
    RelationshipIntegrityError,
    allowed_endpoint_pairs,
    relationship_graph_diagnostics,
    validate_relationship_request,
)
from blockwart.domain.security import find_secret_violations
from blockwart.domain.validation_errors import PUBLIC_DETAIL_FIELDS
from blockwart.mcp.server import (
    ATTACHED_DEVICE_METADATA_SCHEMA,
    FIELD_ACCURATE_TOOLS,
    RELATIONSHIP_PROPERTIES,
    RELATIONSHIP_TOOLS,
    SCHEMA_TOOL_NAME,
    TOOL_DEFINITIONS,
    TOOL_INPUT_VALIDATORS,
    ToolInputError,
    call_tool,
    describe_schema_payload,
)
from blockwart.models import Relationship
from blockwart.schemas.v1 import (
    V1AttachedDeviceCreateIn,
    V1RelationshipCommandIn,
    V1RelationshipMetadata,
)

CONTRACT_PATH = Path(__file__).resolve().parent / "contracts" / "openapi.json"
SECRET_MARKER = "issue-139-secret-marker-0123456789abcdef"


def _no_upstream(*args, **kwargs):
    raise AssertionError("the published relationship contract must not call the API")


def _types(payload: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {entry["relation_type"]: entry for entry in payload["types"]}


def _metadata_fields(entry: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {field["name"]: field for field in entry["metadata"]["fields"]}


def _rest_schema(name: str) -> dict[str, Any]:
    return json.loads(CONTRACT_PATH.read_text())["components"]["schemas"][name]


def _edge(from_ref: str, relation_type: str, to_ref: str, **metadata: Any) -> dict[str, Any]:
    return {
        "from_ref": from_ref,
        "relation_type": relation_type,
        "to_ref": to_ref,
        "metadata": metadata,
    }


# ---------------------------------------------------------------------------
# Domain registry -> published projection
# ---------------------------------------------------------------------------


def test_published_relation_types_are_exactly_the_domain_registry() -> None:
    payload = relationship_projection()

    assert payload["relation_types"] == list(RELATIONSHIP_RULES)
    assert payload["relation_types"] == list(RELATIONSHIP_TYPES)
    assert payload["relation_type_is_closed"] is True
    assert payload["version"] == RELATIONSHIP_PROJECTION_VERSION
    assert list(_types(payload)) == list(RELATIONSHIP_RULES)
    assert relation_type_json_schema()["enum"] == list(RELATIONSHIP_TYPES)


def test_every_machine_boundary_publishes_the_same_closed_vocabulary() -> None:
    registry = list(RELATIONSHIP_TYPES)
    rest = _rest_schema("V1RelationshipCommandIn")["properties"]["relation_type"]

    assert RELATIONSHIP_PROPERTIES["relation_type"]["enum"] == registry
    assert rest["enum"] == registry
    assert list(get_args(V1RelationshipCommandIn.model_fields["relation_type"].annotation)) == (
        registry
    )
    for tool in RELATIONSHIP_TOOLS:
        properties = TOOL_DEFINITIONS[tool]["inputSchema"]["properties"]
        assert properties["relation_type"]["enum"] == registry
        assert "maxLength" not in properties["relation_type"]


def test_stored_vocabulary_matches_the_registry(alembic_session_factory) -> None:
    constraint = next(
        entry
        for entry in Relationship.__table__.constraints
        if getattr(entry, "name", None) == "ck_relationships_known_type"
    )
    with alembic_session_factory() as session:
        migrated = session.execute(
            text("SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'relationships'")
        ).scalar_one()

    assert _constrained_types(str(constraint.sqltext)) == set(RELATIONSHIP_TYPES)
    assert _constrained_types(migrated) == set(RELATIONSHIP_TYPES)


def _constrained_types(sql: str) -> set[str]:
    values = re.search(r"relation_type\s+IN\s*\(([^)]*)\)", sql, re.DOTALL)
    assert values is not None, sql
    return set(re.findall(r"'([^']+)'", values.group(1)))


def test_published_directions_accept_exactly_what_the_domain_accepts() -> None:
    kinds = sorted(VALID_REFERENCE_KINDS)

    for relation_type in RELATIONSHIP_TYPES:
        entry = _types(relationship_projection())[relation_type]
        published = {
            (pair["from_kind"], pair["to_kind"]) for pair in entry["direction"]["directed_pairs"]
        }
        assert published == set(allowed_endpoint_pairs(relation_type))
        assert entry["direction"]["from_kinds"] == sorted({pair[0] for pair in published})
        assert entry["direction"]["to_kinds"] == sorted({pair[1] for pair in published})

        for from_kind in kinds:
            for to_kind in kinds:
                accepted = _accepts_direction(from_kind, relation_type, to_kind)
                assert accepted is ((from_kind, to_kind) in published), (
                    f"{from_kind} {relation_type} {to_kind} drifted from the published pairs"
                )


def _accepts_direction(from_kind: str, relation_type: str, to_kind: str) -> bool:
    try:
        validate_relationship_request(
            from_ref=f"{from_kind}:source",
            relation_type=relation_type,
            to_ref=f"{to_kind}:target",
        )
    except RelationshipIntegrityError as exc:
        assert exc.code == "invalid_relationship_direction"
        return False
    return True


def test_placement_direction_stays_narrower_than_its_endpoint_kinds() -> None:
    entry = _types(relationship_projection())["hosts"]

    # `hosts` accepts host->system, host->service, and system->service, but not
    # system->system: the published directed pairs, not the endpoint kind sets,
    # are the contract.
    pairs = {
        (pair["from_kind"], pair["to_kind"]) for pair in entry["direction"]["directed_pairs"]
    }
    assert pairs == {("host", "system"), ("host", "service"), ("system", "service")}
    assert _accepts_direction("system", "hosts", "system") is False


def test_metadata_contract_is_type_dependent() -> None:
    types = _types(relationship_projection())

    for relation_type, rule in RELATIONSHIP_RULES.items():
        entry = types[relation_type]
        published = _metadata_fields(entry)
        assert list(published) == [spec.name for spec in rule.metadata_fields]
        assert entry["metadata"]["supported"] is bool(rule.metadata_fields)
        assert entry["metadata"]["unknown_fields"] == "forbidden"
        assert entry["metadata"]["requirement"] == (
            "optional" if rule.metadata_fields else "forbidden"
        )
        for spec in rule.metadata_fields:
            field = published[spec.name]
            assert field["json_type"] == spec.json_type
            assert field.get("max_length") == spec.max_length
            assert field.get("enum", []) == sorted(spec.enum_values)
            assert set(field["violations"]) <= set(SCHEMA_VIOLATION_CONTRACTS)


def test_link_relationship_types_publish_exactly_their_own_fields() -> None:
    types = _types(relationship_projection())
    attached = _metadata_fields(types["attached_to"])
    uplinks = _metadata_fields(types["uplinks_to"])

    assert set(attached) == {
        "source_interface",
        "target_interface_or_port",
        "link_kind",
        "primary",
        "note",
    }
    assert set(uplinks) == set(attached) | {"mode"}
    assert attached["link_kind"]["enum"] == sorted(LINK_KINDS)
    assert uplinks["mode"]["enum"] == sorted(UPLINK_MODES)
    assert "mode" not in metadata_json_schema("attached_to")["properties"]

    # `mode` belongs to uplinks only, and the domain enforces exactly that.
    with pytest.raises(RelationshipIntegrityError) as rejected:
        validate_relationship_request(
            from_ref="device:a",
            relation_type="attached_to",
            to_ref="host:b",
            metadata={"mode": "trunk"},
        )
    assert rejected.value.path == "metadata.mode"


def test_shared_metadata_field_names_describe_one_shared_contract() -> None:
    union = metadata_union_json_schema()["properties"]
    specs: dict[str, Any] = {}

    for rule in RELATIONSHIP_RULES.values():
        for spec in rule.metadata_fields:
            # One field name must mean one contract, otherwise the published
            # union of every metadata field would hide a per-type difference.
            assert specs.setdefault(spec.name, spec) == spec
    assert set(union) == set(specs)


def test_depends_on_publishes_and_enforces_no_link_metadata() -> None:
    entry = _types(relationship_projection())["depends_on"]

    assert entry["metadata"]["supported"] is False
    assert entry["metadata"]["fields"] == []
    assert entry["metadata"]["json_schema"] == {
        "type": "object",
        "additionalProperties": False,
        "properties": {},
    }
    for field in ("link_kind", "primary", "note", "source_interface", "mode"):
        with pytest.raises(RelationshipIntegrityError) as rejected:
            validate_relationship_request(
                from_ref="service:a",
                relation_type="depends_on",
                to_ref="service:b",
                metadata={field: True if field == "primary" else "ethernet"},
            )
        assert rejected.value.code == "invalid_relationship_metadata"
        assert rejected.value.path == f"metadata.{field}"
        assert rejected.value.violation == "field_not_allowed"


def test_endpoint_predicates_publish_safe_general_rules_only() -> None:
    payload = relationship_projection()
    predicates = {entry["name"]: entry for entry in payload["endpoint_predicates"]}

    assert set(predicates) == set(ENDPOINT_PREDICATE_CONTRACTS)
    for relation_type, rule in RELATIONSHIP_RULES.items():
        published = _types(payload)[relation_type]["endpoint_predicate"]
        assert published["name"] == rule.endpoint_predicate_name
        assert published["description"] == ENDPOINT_PREDICATE_CONTRACTS[published["name"]]

    assert predicates["kind_pair_allowed"]["decidable_from_request"] is True
    for name in ("attached_endpoint_allowed", "network_devices_only"):
        assert predicates[name]["decidable_from_request"] is False
        assert predicates[name]["network_device_categories"] == sorted(NETWORK_DEVICE_CATEGORIES)


def test_declared_graph_rules_are_the_enforced_graph_rules() -> None:
    endpoints = {
        f"{kind}-{suffix}": EndpointDescriptor(kind=kind, data={})
        for kind in ("device", "network", "service")
        for suffix in ("a", "b", "c")
    }
    samples = {
        "attached_to": "device",
        "uplinks_to": "network",
        "related_to": "service",
    }

    for relation_type, kind in samples.items():
        rule = RELATIONSHIP_RULES[relation_type]
        source, target, third = (f"{kind}:{kind}-{suffix}" for suffix in ("a", "b", "c"))
        cycle = [
            _edge(source, relation_type, target),
            _edge(target, relation_type, source),
        ]
        primaries = [
            _edge(source, relation_type, target, primary=True),
            _edge(source, relation_type, third, primary=True),
        ]
        cycle_codes = {
            diagnostic.code for diagnostic in relationship_graph_diagnostics(cycle, endpoints)
        }
        assert ("relationship_cycle" in cycle_codes) is ("acyclic_edges" in rule.graph_rules)
        if "single_primary_per_source" in rule.graph_rules:
            primary_codes = {
                diagnostic.code
                for diagnostic in relationship_graph_diagnostics(primaries, endpoints)
            }
            assert "multiple_primary_relationships" in primary_codes

    published = {
        relation_type: {rule["rule"] for rule in entry["graph_rules"]}
        for relation_type, entry in _types(relationship_projection()).items()
    }
    assert published == {
        relation_type: set(rule.graph_rules)
        for relation_type, rule in RELATIONSHIP_RULES.items()
    }
    assert all(rule in GRAPH_RULE_CONTRACTS for rules in published.values() for rule in rules)


def test_rejection_catalog_separates_request_from_stored_state() -> None:
    policy = relationship_projection()["rejection_policy"]
    published = {entry["code"]: entry for entry in policy["rejections"]}

    assert policy["detail_fields"] == list(PUBLIC_DETAIL_FIELDS)
    assert policy["path_roots"] == list(RELATIONSHIP_PATH_ROOTS)
    assert set(published) == set(RELATIONSHIP_REJECTIONS)
    for code, entry in published.items():
        rejection = RELATIONSHIP_REJECTIONS[code]
        assert entry["stage"] == rejection.stage
        assert entry["field_accurate"] is (rejection.stage == "request")
        if entry["field_accurate"]:
            assert entry["violation"] in SCHEMA_VIOLATION_CONTRACTS
        else:
            assert entry["violation"] is None


@pytest.mark.parametrize(
    ("payload", "code", "path"),
    [
        (
            {"from_ref": "service:a", "relation_type": "invented", "to_ref": "service:b"},
            "unsupported_relation_type",
            "relation_type",
        ),
        (
            {"from_ref": "not-a-ref", "relation_type": "depends_on", "to_ref": "service:b"},
            "invalid_typed_reference",
            "from_ref",
        ),
        (
            {"from_ref": "service:a", "relation_type": "depends_on", "to_ref": "service:a"},
            "self_reference",
            "to_ref",
        ),
        (
            {"from_ref": "runbook:a", "relation_type": "depends_on", "to_ref": "service:b"},
            "invalid_relationship_direction",
            "from_ref",
        ),
        (
            {"from_ref": "service:a", "relation_type": "depends_on", "to_ref": "runbook:b"},
            "invalid_relationship_direction",
            "to_ref",
        ),
        (
            {
                "from_ref": "device:a",
                "relation_type": "attached_to",
                "to_ref": "host:b",
                "metadata": {"link_kind": "carrier-pigeon"},
            },
            "invalid_relationship_metadata",
            "metadata.link_kind",
        ),
        (
            {
                "from_ref": "device:a",
                "relation_type": "attached_to",
                "to_ref": "host:b",
                "metadata": {"primary": "yes"},
            },
            "invalid_relationship_metadata",
            "metadata.primary",
        ),
        (
            {
                "from_ref": "device:a",
                "relation_type": "attached_to",
                "to_ref": "host:b",
                "metadata": {"note": "x" * 513},
            },
            "invalid_relationship_metadata",
            "metadata.note",
        ),
        (
            {
                "from_ref": "device:a",
                "relation_type": "attached_to",
                "to_ref": "host:b",
                "metadata": {"password": "x"},
            },
            "secret_relationship_metadata",
            "metadata",
        ),
    ],
)
def test_request_rejections_name_their_canonical_path(payload, code, path) -> None:
    with pytest.raises(RelationshipIntegrityError) as rejected:
        validate_relationship_request(**payload)

    assert rejected.value.code == code
    assert rejected.value.path == path
    assert rejected.value.violation in SCHEMA_VIOLATION_CONTRACTS
    assert RELATIONSHIP_REJECTIONS[code].stage == "request"


def test_published_contract_is_json_safe_stable_and_carries_no_catalog_data() -> None:
    payload = relationship_projection()

    encoded = json.dumps(payload, indent=2, sort_keys=True, allow_nan=False)
    assert json.loads(encoded) == payload
    assert encoded == json.dumps(relationship_projection(), indent=2, sort_keys=True)
    assert find_secret_violations(payload) == []
    # The contract names types, kinds, and rules; it never names a stored
    # object, reference, or edge.
    assert not [
        value
        for value in _strings(payload)
        if any(value.startswith(f"{kind}:") for kind in VALID_REFERENCE_KINDS)
    ]


def _strings(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [item for child in value.values() for item in _strings(child)]
    if isinstance(value, list):
        return [item for child in value for item in _strings(child)]
    return []


# ---------------------------------------------------------------------------
# MCP contract
# ---------------------------------------------------------------------------


def test_describe_schema_publishes_the_relationship_contract_locally() -> None:
    result = call_tool(SCHEMA_TOOL_NAME, {}, fetcher=_no_upstream, requester=_no_upstream)
    payload = json.loads(result["content"][0]["text"])

    assert result["isError"] is False
    assert payload["relationships"] == relationship_projection(None)
    assert payload["relationships"]["relation_types"] == list(RELATIONSHIP_TYPES)
    for tool in RELATIONSHIP_TOOLS:
        assert SCHEMA_TOOL_NAME in TOOL_DEFINITIONS[tool]["description"]


def test_describe_schema_kind_filter_keeps_the_complete_vocabulary() -> None:
    payload = describe_schema_payload("device")
    relationships = payload["relationships"]

    assert relationships["relation_types"] == list(RELATIONSHIP_TYPES)
    published = [entry["relation_type"] for entry in relationships["types"]]
    assert published == [
        relation_type
        for relation_type in RELATIONSHIP_TYPES
        if any("device" in pair for pair in allowed_endpoint_pairs(relation_type))
    ]
    assert "attached_to" in published
    assert "uplinks_to" not in published
    assert "hosts" not in published


def test_relationship_tool_schemas_are_generated_from_the_registry() -> None:
    metadata = RELATIONSHIP_PROPERTIES["metadata"]
    conditions = relationship_metadata_conditions()

    assert metadata["additionalProperties"] is False
    assert set(metadata["properties"]) == set(metadata_union_json_schema()["properties"])
    assert ATTACHED_DEVICE_METADATA_SCHEMA["properties"] == (
        metadata_json_schema("attached_to")["properties"]
    )
    assert "mode" not in ATTACHED_DEVICE_METADATA_SCHEMA["properties"]
    for tool in RELATIONSHIP_TOOLS:
        assert TOOL_DEFINITIONS[tool]["inputSchema"]["allOf"] == conditions
        assert tool in FIELD_ACCURATE_TOOLS


@pytest.mark.parametrize(
    ("arguments", "code", "path"),
    [
        ({"relation_type": "invented"}, "value_not_allowed", "relation_type"),
        (
            {"relation_type": "depends_on", "metadata": {"link_kind": "ethernet"}},
            "field_not_allowed",
            "metadata.link_kind",
        ),
        (
            {"relation_type": "attached_to", "metadata": {"mode": "trunk"}},
            "field_not_allowed",
            "metadata.mode",
        ),
        (
            {"relation_type": "uplinks_to", "metadata": {"link_kind": "carrier-pigeon"}},
            "value_not_allowed",
            "metadata.link_kind",
        ),
        (
            {"relation_type": "uplinks_to", "metadata": {"primary": "yes"}},
            "type_mismatch",
            "metadata.primary",
        ),
    ],
)
def test_relationship_tools_reject_invalid_arguments_field_accurately(
    arguments,
    code,
    path,
) -> None:
    for tool in RELATIONSHIP_TOOLS:
        with pytest.raises(ToolInputError) as rejected:
            call_tool(
                tool,
                {
                    "object_id": "example",
                    "if_match": '"rev-1"',
                    "from_ref": "device:a",
                    "to_ref": "host:b",
                    **arguments,
                },
                fetcher=_no_upstream,
                requester=_no_upstream,
            )
        details = rejected.value.details
        assert [detail["code"] for detail in details] == [code]
        assert [detail["path"] for detail in details] == [path]
        assert all(set(detail) == set(PUBLIC_DETAIL_FIELDS) for detail in details)
        assert all(
            detail["message"] == SCHEMA_VIOLATION_CONTRACTS[detail["code"]] for detail in details
        )


def test_attached_device_tool_rejects_uplink_only_metadata() -> None:
    with pytest.raises(ToolInputError) as rejected:
        call_tool(
            "blockwart.create_attached_device",
            {
                "parent_id": "host-device-parent",
                "idempotency_key": "issue-139-attached-0001",
                "device": {"id": "d", "kind": "device", "label": "D"},
                "metadata": {"mode": "trunk"},
            },
            fetcher=_no_upstream,
            requester=_no_upstream,
        )

    assert [detail["path"] for detail in rejected.value.details] == ["metadata.mode"]
    assert [detail["code"] for detail in rejected.value.details] == ["field_not_allowed"]


def test_valid_relationship_arguments_stay_accepted_by_the_published_schema() -> None:
    accepted = [
        {"relation_type": "depends_on", "from_ref": "service:a", "to_ref": "service:b"},
        {
            "relation_type": "attached_to",
            "from_ref": "device:a",
            "to_ref": "host:b",
            "metadata": {"link_kind": "ethernet", "primary": True},
        },
        {
            "relation_type": "uplinks_to",
            "from_ref": "network:a",
            "to_ref": "network:b",
            "metadata": {"mode": "trunk", "note": "core uplink"},
        },
    ]
    for tool in RELATIONSHIP_TOOLS:
        for arguments in accepted:
            TOOL_INPUT_VALIDATORS[tool].validate(
                {"object_id": "example", "if_match": '"rev-1"', **arguments}
            )


# ---------------------------------------------------------------------------
# REST and OpenAPI contract
# ---------------------------------------------------------------------------


def test_openapi_publishes_the_same_generated_relationship_contract() -> None:
    command = _rest_schema("V1RelationshipCommandIn")
    attached = _rest_schema("V1AttachedDeviceCreateIn")

    assert command["allOf"] == relationship_metadata_conditions()
    assert command["properties"]["metadata"]["properties"] == (
        metadata_union_json_schema()["properties"]
    )
    assert command["properties"]["metadata"]["additionalProperties"] is False
    assert attached["properties"]["metadata"]["properties"] == (
        metadata_json_schema("attached_to")["properties"]
    )
    assert "mode" not in attached["properties"]["metadata"]["properties"]


def test_rest_output_metadata_enums_follow_the_domain_registry() -> None:
    fields = V1RelationshipMetadata.model_fields

    assert set(fields) == set(metadata_union_json_schema()["properties"])
    assert set(_optional_literal(fields["link_kind"].annotation)) == LINK_KINDS
    assert set(_optional_literal(fields["mode"].annotation)) == UPLINK_MODES
    assert V1RelationshipMetadata().model_dump() == {}


def _optional_literal(annotation: Any) -> tuple[Any, ...]:
    return get_args(next(arg for arg in get_args(annotation) if arg is not type(None)))


@pytest.mark.parametrize(
    ("body", "code", "path"),
    [
        (
            {"from_ref": "service:a", "relation_type": "invented", "to_ref": "service:b"},
            "value_not_allowed",
            "relation_type",
        ),
        (
            {
                "from_ref": "service:a",
                "relation_type": "depends_on",
                "to_ref": "service:b",
                "metadata": {"link_kind": "ethernet"},
            },
            "field_not_allowed",
            "metadata.link_kind",
        ),
        (
            {
                "from_ref": "device:a",
                "relation_type": "attached_to",
                "to_ref": "host:b",
                "metadata": {"mode": "trunk"},
            },
            "field_not_allowed",
            "metadata.mode",
        ),
        (
            {"from_ref": "service:a", "relation_type": "depends_on", "to_ref": "service:a"},
            "value_not_allowed",
            "to_ref",
        ),
        (
            {"from_ref": "runbook:a", "relation_type": "attached_to", "to_ref": "host:b"},
            "value_not_allowed",
            "from_ref",
        ),
    ],
)
def test_rest_relationship_commands_publish_field_accurate_rejections(
    device_command_client: TestClient,  # noqa: F811
    device_command_state,  # noqa: F811
    body,
    code,
    path,
) -> None:
    _, _, token = device_command_state
    headers = {"Authorization": f"Bearer {token}", "If-Match": '"rev-1"'}

    for method in ("POST", "DELETE"):
        response = device_command_client.request(
            method,
            "/api/v1/objects/host-device-parent/relationships",
            headers=headers,
            json=body,
        )

        assert response.status_code == 422, response.text
        error = response.json()["error"]
        assert error["code"] == "validation_error"
        detail = error["details"][0]
        assert detail["code"] == code
        assert detail["path"] == path
        assert detail["location"] == f"body.{path}"
        assert detail["message"] == SCHEMA_VIOLATION_CONTRACTS[code]
        assert set(detail) == set(PUBLIC_DETAIL_FIELDS)


def test_rest_rejects_secret_shaped_metadata_without_echoing_it(
    device_command_client: TestClient,  # noqa: F811
    device_command_state,  # noqa: F811
) -> None:
    _, _, token = device_command_state
    response = device_command_client.post(
        "/api/v1/objects/host-device-parent/relationships",
        headers={"Authorization": f"Bearer {token}", "If-Match": '"rev-1"'},
        json={
            "from_ref": "host:host-device-parent",
            "relation_type": "attached_to",
            "to_ref": "network:net-device-parent",
            "metadata": {"note": f"token {SECRET_MARKER}", "password": SECRET_MARKER},
        },
    )

    assert response.status_code == 422, response.text
    detail = response.json()["error"]["details"][0]
    assert detail["code"] == "forbidden_key"
    assert detail["path"] == "metadata"
    assert SECRET_MARKER not in response.text


def test_stored_endpoint_rules_stay_conflicts_without_a_field(
    device_command_client: TestClient,  # noqa: F811
    device_command_state,  # noqa: F811
) -> None:
    _, _, token = device_command_state
    auth = {"Authorization": f"Bearer {token}"}
    current = device_command_client.get("/api/v1/objects/host-device-parent", headers=auth)

    # A Network segment is not a network device: only the stored category can
    # decide this, so it stays a conflict instead of naming a request field.
    rejected = device_command_client.post(
        "/api/v1/objects/host-device-parent/relationships",
        headers={**auth, "If-Match": current.headers["etag"]},
        json={
            "from_ref": "host:host-device-parent",
            "relation_type": "attached_to",
            "to_ref": "network:net-segment-parent",
        },
    )

    assert rejected.status_code == 409, rejected.text
    error = rejected.json()["error"]
    assert error["code"] == "conflict"
    assert "details" not in error
    unchanged = device_command_client.get("/api/v1/objects/host-device-parent", headers=auth)
    assert unchanged.headers["etag"] == current.headers["etag"]


def test_create_replace_no_op_and_delete_stay_consistent_across_boundaries(
    device_command_client: TestClient,  # noqa: F811
    device_command_state,  # noqa: F811
) -> None:
    _, _, token = device_command_state
    auth = {"Authorization": f"Bearer {token}"}
    semantics = relationship_projection()["command_semantics"]
    edge = {
        "from_ref": "host:host-device-parent",
        "relation_type": "attached_to",
        "to_ref": "network:net-device-parent",
    }

    def current_etag() -> str:
        return device_command_client.get(
            "/api/v1/objects/host-device-parent",
            headers=auth,
        ).headers["etag"]

    created = device_command_client.post(
        "/api/v1/objects/host-device-parent/relationships",
        headers={**auth, "If-Match": current_etag()},
        json={**edge, "metadata": {"link_kind": "ethernet"}},
    )
    replaced = device_command_client.post(
        "/api/v1/objects/host-device-parent/relationships",
        headers={**auth, "If-Match": current_etag()},
        json={**edge, "metadata": {"link_kind": "wifi"}},
    )
    unchanged = device_command_client.post(
        "/api/v1/objects/host-device-parent/relationships",
        headers={**auth, "If-Match": current_etag()},
        json={**edge, "metadata": {"link_kind": "wifi"}},
    )
    deleted = device_command_client.request(
        "DELETE",
        "/api/v1/objects/host-device-parent/relationships",
        headers={**auth, "If-Match": current_etag()},
        json=edge,
    )

    assert [response.status_code for response in (created, replaced, unchanged, deleted)] == [
        200,
        200,
        200,
        200,
    ]
    assert semantics["create_replaces_metadata"] is True
    assert semantics["no_op_when_metadata_is_unchanged"] is True
    assert created.json()["changed"] is True
    assert replaced.json()["changed"] is True
    assert replaced.json()["metadata"] == {"link_kind": "wifi"}
    assert unchanged.json()["changed"] is False
    assert unchanged.json()["metadata"] == {"link_kind": "wifi"}
    assert deleted.json()["changed"] is True
    # Delete matches the triplet only, exactly as the contract publishes it.
    assert semantics["delete_ignores_metadata"] is True

    # The same accepted payloads validate against the published MCP schema.
    for tool in RELATIONSHIP_TOOLS:
        TOOL_INPUT_VALIDATORS[tool].validate(
            {
                "object_id": "host-device-parent",
                "if_match": '"rev-1"',
                **edge,
                "metadata": {"link_kind": "wifi"},
            }
        )


def test_existing_valid_callers_stay_compatible() -> None:
    command = V1RelationshipCommandIn(
        from_ref="device:existing-device",
        relation_type="attached_to",
        to_ref="host:host-device-parent",
        metadata={"source_interface": " eth0 ", "link_kind": "ethernet", "primary": True},
    )
    attached = V1AttachedDeviceCreateIn(
        device={
            "id": "compatible-device",
            "kind": "device",
            "label": "Compatible",
            "data": {"schema_version": 1, "device": {"category": "sensor"}},
        },
        metadata={"link_kind": "ethernet"},
    )

    assert command.metadata == {
        "source_interface": "eth0",
        "link_kind": "ethernet",
        "primary": True,
    }
    assert attached.metadata == {"link_kind": "ethernet"}
    assert V1RelationshipCommandIn(
        from_ref="service:a",
        relation_type="depends_on",
        to_ref="service:b",
    ).metadata == {}
    with pytest.raises(ValidationError):
        V1AttachedDeviceCreateIn(
            device={
                "id": "compatible-device",
                "kind": "device",
                "label": "Compatible",
                "data": {"schema_version": 1, "device": {"category": "sensor"}},
            },
            metadata={"mode": "trunk"},
        )
