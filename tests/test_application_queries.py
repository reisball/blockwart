from __future__ import annotations

from pathlib import Path

from sqlalchemy import event
from sqlalchemy.orm import Session

import blockwart.services.queries as query_module
from blockwart.db.session import transaction
from blockwart.schemas.catalog import CatalogObjectIn
from blockwart.services.catalog import create_relationship, upsert_object
from blockwart.services.queries import (
    get_catalog_object,
    list_catalog_objects,
    primary_name_value,
    query_catalog_browse,
    query_catalog_detail,
)


def _seed_query_graph(session: Session) -> None:
    with transaction(session):
        for payload in (
            CatalogObjectIn(
                id="query-host",
                kind="host",
                label="Query Host Label",
                data={
                    "schema_version": 1,
                    "network": {"hostnames": ["query-host.local"]},
                },
            ),
            CatalogObjectIn(
                id="query-system",
                kind="system",
                label="Query System",
                data={"schema_version": 1},
            ),
            CatalogObjectIn(
                id="query-service",
                kind="service",
                label="Query Service",
                data={
                    "schema_version": 1,
                    "endpoints": [
                        {
                            "type": "REST API",
                            "url": "http://query-service.local:8443",
                            "port": 8443,
                            "protocol": "https",
                        }
                    ],
                },
            ),
            CatalogObjectIn(
                id="query-runbook",
                kind="runbook",
                label="Private Query Runbook",
                data={"schema_version": 1},
            ),
        ):
            upsert_object(session, payload)
        create_relationship(
            session,
            from_ref="host:query-host",
            relation_type="hosts",
            to_ref="system:query-system",
        )
        create_relationship(
            session,
            from_ref="system:query-system",
            relation_type="hosts",
            to_ref="service:query-service",
        )


def test_application_queries_build_catalog_relationship_audit_and_topology_models(
    alembic_session_factory,
    unrestricted_read_access,
) -> None:
    with alembic_session_factory() as session:
        _seed_query_graph(session)

    with alembic_session_factory() as session:
        access = unrestricted_read_access(session)
        browse = query_catalog_browse(session, access)
        filtered = query_catalog_browse(
            session,
            access,
            query="query-service",
            kind="service",
        )
        detail = query_catalog_detail(session, "query-service", access)
        missing = query_catalog_detail(session, "missing", access)
        catalog_objects = list_catalog_objects(session, access)
        catalog_object = get_catalog_object(session, "query-service", access)

    assert [catalog_object.id for catalog_object in browse.objects] == [
        "query-host",
        "query-system",
        "query-service",
    ]
    assert browse.object_counts == {
        "host": 1,
        "system": 1,
        "service": 1,
    }
    assert browse.health_counts == {"unknown": 3}
    assert browse.total_objects == 3
    assert [catalog_object.id for catalog_object in filtered.objects] == [
        "query-service"
    ]
    assert [catalog_object.id for catalog_object in browse.systems] == [
        "query-system"
    ]
    assert [catalog_object.id for catalog_object in browse.relation_targets] == [
        "query-host",
        "query-system",
        "query-service",
    ]
    assert browse.display_names["query-host"] == "query-host.local"
    assert browse.explorer["clusters"][0]["host"]["ref"] == "host:query-host"
    assert browse.explorer["clusters"][0]["systems"][0]["system"]["ref"] == (
        "system:query-system"
    )
    assert browse.explorer["clusters"][0]["systems"][0]["services"][0]["ref"] == (
        "service:query-service"
    )
    assert set(filtered.explorer["assets"]) == {
        "host:query-host",
        "system:query-system",
        "service:query-service",
    }

    topology = browse.index_relationships["query-service"]["topology"]
    assert [
        node["ref"]
        for node in topology["chains"][0]["hosts"]
    ] == ["host:query-host"]
    assert [
        node["ref"]
        for node in topology["chains"][0]["systems"]
    ] == ["system:query-system"]
    assert topology["chains"][0]["services"][0]["ports"] == [
        {"label": "service", "value": "8443/https"}
    ]

    assert detail is not None
    assert detail.catalog_object.id == "query-service"
    assert [
        node.ref for node in detail.catalog_object.parent_path
    ] == ["host:query-host", "system:query-system"]
    assert detail.relationships == [
        {
            "from_ref": "system:query-system",
            "relation_type": "hosts",
            "to_ref": "service:query-service",
            "metadata": {},
        }
    ]
    assert detail.relationship_groups["inbound"][0]["other_ref"] == (
        "system:query-system"
    )
    assert detail.audit_events
    assert detail.audit_events[0]["created_at"].endswith("Z")
    assert "query-runbook" not in {
        candidate.id for candidate in detail.relationship_targets
    }
    assert missing is None

    assert len(catalog_objects) == 4
    assert catalog_object is not None
    assert [node.ref for node in catalog_object.parent_path] == [
        "host:query-host",
        "system:query-system",
    ]
    host = next(
        catalog_object
        for catalog_object in catalog_objects
        if catalog_object.id == "query-host"
    )
    assert primary_name_value(host) == "query-host.local"


def test_catalog_browse_query_has_a_bounded_select_count(
    alembic_database,
    unrestricted_read_access,
) -> None:
    with alembic_database.sessions() as session:
        _seed_query_graph(session)
        access = unrestricted_read_access(session)

    select_statements: list[str] = []

    def capture_selects(
        _connection,
        _cursor,
        statement: str,
        _parameters,
        _context,
        _executemany,
    ) -> None:
        if statement.lstrip().upper().startswith("SELECT"):
            select_statements.append(statement)

    event.listen(
        alembic_database.engine,
        "before_cursor_execute",
        capture_selects,
    )
    try:
        with alembic_database.sessions() as session:
            browse = query_catalog_browse(session, access)
    finally:
        event.remove(
            alembic_database.engine,
            "before_cursor_execute",
            capture_selects,
        )

    assert browse.total_objects == 3
    assert 0 < len(select_statements) <= 4


def test_application_query_module_has_no_fastapi_or_template_dependency() -> None:
    source = Path(query_module.__file__).read_text()

    assert "fastapi" not in source
    assert "TemplateResponse" not in source
