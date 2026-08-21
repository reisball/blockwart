import json

import pytest
from pydantic import ValidationError
from sqlalchemy import select

from blockwart.domain.schema_projection import kind_schema_projection
from blockwart.domain.service_components import (
    MAX_SERVICE_COMPONENT_DEPENDENCIES,
    MAX_SERVICE_COMPONENTS,
    SERVICE_COMPONENT_ROLE_VALUES,
    put_service_component,
    put_service_component_dependency,
    remove_service_component,
)
from blockwart.domain.service_readiness import SERVICE_CRITICALITY_VALUES
from blockwart.models import AuditEvent, CatalogObject
from blockwart.schemas.catalog import CatalogObjectIn
from blockwart.services.catalog import upsert_object
from blockwart.services.seeds import import_seed_payload


def _component(component_id: str, role: str = "application") -> dict[str, str]:
    return {
        "id": component_id,
        "name": component_id.upper(),
        "role": role,
        "description": f"Internal {component_id} responsibility.",
    }


def _service_data(
    *,
    items: list[dict] | None = None,
    dependencies: list[dict] | None = None,
) -> dict:
    return {
        "schema_version": 1,
        "components": {
            "items": items if items is not None else [_component("api", "api")],
            "dependencies": dependencies if dependencies is not None else [],
        },
    }


def test_component_contract_normalizes_deterministically_and_allows_cycles() -> None:
    payload = CatalogObjectIn(
        id="component-service",
        kind="service",
        label="Component service",
        data=_service_data(
            items=[
                {
                    "id": "worker",
                    "name": " Worker ",
                    "role": "worker",
                    "description": " Processes jobs ",
                },
                {
                    "id": "api",
                    "name": " API ",
                    "role": "api",
                    "description": " Accepts work ",
                },
            ],
            dependencies=[
                {"component_id": "worker", "depends_on": "api"},
                {"component_id": "api", "depends_on": "worker"},
            ],
        ),
    )

    assert payload.data["components"] == {
        "items": [
            {
                "id": "api",
                "name": "API",
                "role": "api",
                "description": "Accepts work",
            },
            {
                "id": "worker",
                "name": "Worker",
                "role": "worker",
                "description": "Processes jobs",
            },
        ],
        "dependencies": [
            {"component_id": "api", "depends_on": "worker"},
            {"component_id": "worker", "depends_on": "api"},
        ],
    }


@pytest.mark.parametrize(
    ("data", "path"),
    [
        (
            _service_data(items=[_component("api"), _component("api")]),
            "data.components.items[1].id",
        ),
        (
            _service_data(
                dependencies=[{"component_id": "api", "depends_on": "api"}]
            ),
            "data.components.dependencies[0].depends_on",
        ),
        (
            _service_data(
                dependencies=[{"component_id": "api", "depends_on": "missing"}]
            ),
            "data.components.dependencies[0].depends_on",
        ),
        (
            _service_data(
                dependencies=[
                    {"component_id": "api", "depends_on": "service:other"}
                ]
            ),
            "data.components.dependencies[0].depends_on",
        ),
        (
            _service_data(
                dependencies=[
                    {"component_id": "api", "depends_on": "db"},
                    {"component_id": "api", "depends_on": "db"},
                ],
                items=[_component("api"), _component("db", "database")],
            ),
            "data.components.dependencies[1].depends_on",
        ),
        (
            {"components": {"items": []}},
            "data.components.dependencies",
        ),
    ],
)
def test_component_graph_rejections_report_safe_exact_paths(data: dict, path: str) -> None:
    with pytest.raises(ValidationError) as exc_info:
        CatalogObjectIn(
            id="invalid-component-service",
            kind="service",
            label="Invalid component service",
            data=data,
        )

    assert path in str(exc_info.value)


def test_component_shapes_roles_limits_and_kind_boundary_are_closed() -> None:
    invalid_payloads = (
        _service_data(items=[{**_component("api"), "role": "frontend"}]),
        _service_data(items=[{**_component("api"), "health": "healthy"}]),
        _service_data(
            items=[
                _component(f"c{index}")
                for index in range(MAX_SERVICE_COMPONENTS + 1)
            ]
        ),
        _service_data(
            items=[_component("api"), _component("db")],
            dependencies=[
                {"component_id": "api", "depends_on": "db", "description": str(index)}
                for index in range(MAX_SERVICE_COMPONENT_DEPENDENCIES + 1)
            ],
        ),
    )
    for data in invalid_payloads:
        with pytest.raises(ValidationError):
            CatalogObjectIn(
                id="closed-component-service",
                kind="service",
                label="Closed component service",
                data=data,
            )

    with pytest.raises(ValidationError, match="supported only for service"):
        CatalogObjectIn(
            id="component-host",
            kind="host",
            label="Component host",
            data=_service_data(),
        )


@pytest.mark.parametrize(
    "secret_value",
    [
        "Bearer abcdefghijklmnopqrstuvwxyz012345",
        "postgresql://catalog.internal/blockwart",
    ],
)
def test_component_and_edge_descriptions_reject_secret_like_values(
    secret_value: str,
) -> None:
    for data in (
        _service_data(items=[{**_component("api"), "description": secret_value}]),
        _service_data(
            items=[_component("api"), _component("db")],
            dependencies=[
                {
                    "component_id": "api",
                    "depends_on": "db",
                    "description": secret_value,
                }
            ],
        ),
    ):
        with pytest.raises(ValidationError) as exc_info:
            CatalogObjectIn(
                id="secret-component-service",
                kind="service",
                label="Secret component service",
                data=data,
            )
        assert exc_info.value.error_count() == 1


def test_component_contract_projection_is_complete_and_generated() -> None:
    service = kind_schema_projection("service")
    contract = service["service_components"]
    fields = {field["path"]: field for field in service["data"]["fields"]}

    assert contract["roles"] == list(SERVICE_COMPONENT_ROLE_VALUES)
    assert contract["cycles"]["allowed"] is True
    assert contract["cross_service_references_allowed"] is False
    assert contract["limits"] == {
        "components": 100,
        "dependencies": 400,
        "traversal_nodes": 100,
        "traversal_edges": 400,
    }
    assert fields["components.items"]["max_items"] == 100
    assert fields["components.dependencies"]["max_items"] == 400
    assert fields["components.items[].role"]["enum"] == sorted(
        SERVICE_COMPONENT_ROLE_VALUES
    )
    assert set(fields["criticality"]["enum"]) == set(SERVICE_CRITICALITY_VALUES)
    assert fields["criticality"]["requirement"] == "optional"


def test_component_edit_helpers_rename_edges_and_remove_incident_edges() -> None:
    data = _service_data(
        items=[_component("api", "api"), _component("db", "database")],
        dependencies=[{"component_id": "api", "depends_on": "db"}],
    )
    renamed = put_service_component(
        data,
        component_id="database",
        previous_id="db",
        name="Database",
        role="database",
        description="Stores records.",
    )
    assert renamed["components"]["dependencies"] == [
        {"component_id": "api", "depends_on": "database"}
    ]
    replaced = put_service_component_dependency(
        renamed,
        component_id="api",
        depends_on="database",
        description="Canonical records",
    )
    assert replaced["components"]["dependencies"][0]["description"] == (
        "Canonical records"
    )
    removed = remove_service_component(replaced, component_id="database")
    assert [item["id"] for item in removed["components"]["items"]] == ["api"]
    assert removed["components"]["dependencies"] == []


def test_seed_import_uses_canonical_component_validation_and_order(
    alembic_session_factory,
) -> None:
    payload = {
        "schema_version": 1,
        "objects": [
            {
                "id": "seed-components",
                "kind": "service",
                "label": "Seed components",
                "data": _service_data(
                    items=[_component("worker", "worker"), _component("api", "api")],
                    dependencies=[
                        {"component_id": "worker", "depends_on": "api"}
                    ],
                ),
            }
        ],
        "relationships": [],
    }
    with alembic_session_factory() as session:
        result = import_seed_payload(session, payload, source_ref="component-seed")
        row = session.get(CatalogObject, "seed-components")
        stored_data = json.loads(row.data_json) if row is not None else {}
    assert result.objects_imported == 1
    assert row is not None
    assert [item["id"] for item in stored_data["components"]["items"]] == [
        "api",
        "worker",
    ]


def test_reordered_parent_update_is_a_revision_and_audit_noop(
    alembic_session_factory,
) -> None:
    first = CatalogObjectIn(
        id="component-noop",
        kind="service",
        label="Component noop",
        data=_service_data(
            items=[_component("worker", "worker"), _component("api", "api")],
            dependencies=[{"component_id": "worker", "depends_on": "api"}],
        ),
    )
    second = CatalogObjectIn(
        id="component-noop",
        kind="service",
        label="Component noop",
        data=_service_data(
            items=[_component("api", "api"), _component("worker", "worker")],
            dependencies=[{"component_id": "worker", "depends_on": "api"}],
        ),
    )
    with alembic_session_factory() as session:
        created = upsert_object(session, first)
        before_audits = list(
            session.scalars(
                select(AuditEvent).where(AuditEvent.object_id == "component-noop")
            )
        )
        repeated = upsert_object(
            session,
            second,
            expected_revision=created.revision,
        )
        after_audits = list(
            session.scalars(
                select(AuditEvent).where(AuditEvent.object_id == "component-noop")
            )
        )
    assert repeated.revision == created.revision
    assert [event.id for event in after_audits] == [event.id for event in before_audits]
