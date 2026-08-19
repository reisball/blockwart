"""Deterministic search relevance, exact modes, filters, and bounds (#186).

Every fixture below is synthetic and public-safe: fictitious identifiers,
reserved documentation domains, and documentation address ranges only.
"""

from __future__ import annotations

import json
from collections.abc import Generator

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError
from sqlalchemy.orm import Session

from blockwart.api.deps import get_session
from blockwart.db.session import transaction
from blockwart.domain.auth import Permission, PrincipalContext, PrincipalType
from blockwart.domain.provenance import CatalogProvenanceOut
from blockwart.domain.search import (
    AGENT_SEARCH_LIMIT_MAX,
    CONTEXT_LIMIT_MAX,
    SEARCH_LIMIT_MAX,
    SEARCH_SNIPPET_MAX_LENGTH,
    SNIPPET_TRUNCATION_MARKER,
    SearchQuery,
    search_snippet,
)
from blockwart.domain.validation_errors import SEARCH_LIMIT_DETAIL_FIELDS
from blockwart.main import create_app
from blockwart.mcp.server import ToolInputError, call_tool
from blockwart.models import CatalogObject
from blockwart.schemas.agent import AgentCatalogObjectSummary
from blockwart.services.agent import query_agent_objects_page, search_agent_objects
from blockwart.services.policy import PolicySnapshot
from blockwart.services.read_access import ReadAccess


def _object(
    object_id: str,
    kind: str,
    label: str,
    *,
    status: str = "active",
    lifecycle: str | None = None,
    health: str | None = None,
    summary: str | None = None,
    data: dict | None = None,
    provenance: dict | None = None,
) -> CatalogObject:
    if kind in {"host", "system", "network", "device", "service"}:
        lifecycle = lifecycle or "active"
        health = health or "unknown"
    return CatalogObject(
        id=object_id,
        kind=kind,
        label=label,
        status=status,
        lifecycle=lifecycle,
        health=health,
        summary=summary,
        data_json=json.dumps({"schema_version": 1, **(data or {})}),
        provenance_json=json.dumps(
            provenance or {"source_type": "manual", "manual_override": False}
        ),
    )


# One synthetic catalog covering every rank tier of the published ladder:
# exact ref/id, exact label, identity, structured domain field, summary, and
# one allowlisted secondary field. `legacy-migration-record` carries the search
# term only inside import metadata and must never match.
def catalog_objects() -> list[CatalogObject]:
    """Return one fresh, unattached copy of the synthetic search catalog."""
    return [
        _object(
            "gateway-01",
            "host",
            "Gateway 01",
            summary="Edge gateway of the documentation network.",
            data={
                "network": {
                    "hostnames": ["gateway-01.example.test"],
                    "addresses": [{"ip": "192.0.2.10"}],
                }
            },
        ),
        _object(
            "gateway-relay",
            "host",
            "Relay Beside Gateway 01",
            summary="Second edge node.",
            data={"network": {"addresses": [{"ip": "192.0.2.11"}]}},
        ),
        _object(
            "restart-runbook",
            "runbook",
            "Restart Procedure",
            data={
                "runbook_status": "active",
                "risk_level": "disruptive",
                "purpose": "Restart the gateway service without dropping sessions.",
                "steps": [{"id": "s1", "title": "Drain traffic"}],
            },
        ),
        _object(
            "north-south-decision",
            "decision",
            "North-South Traffic",
            data={
                "decision_status": "accepted",
                "decision": "Route all north-south traffic through the gateway.",
                "context": "Historical direct routes were unmanaged.",
            },
        ),
        _object(
            "rollout-project",
            "project",
            "Edge Rollout",
            data={
                "category": "implementation",
                "project_status": "active",
                "current_summary": "Gateway rollout is halfway through its pilot.",
            },
        ),
        _object(
            "warehouse-node",
            "system",
            "Warehouse Node",
            summary="Feeds the gateway uplink twice per hour.",
        ),
        _object(
            "depot-host",
            "host",
            "Depot Host",
            summary="Spare capacity.",
            data={"network": {"location": "Gateway room, rack 4"}},
        ),
        _object(
            "legacy-migration-record",
            "project",
            "Legacy Migration Record",
            summary="Imported inventory row.",
            data={
                "category": "migration",
                "project_status": "archived",
                "sources": [
                    {
                        "source_type": "documentation",
                        "title": "Gateway inventory export",
                        "url": "https://wiki.example.test/gateway-export",
                    }
                ],
            },
            provenance={
                "source_type": "import",
                "source_ref": "markdown://gateway-inventory.md",
                "managed_by": "gateway-import-bot",
                "manual_override": False,
            },
        ),
        _object(
            "decommissioned-gateway",
            "host",
            "Gateway Decommissioned",
            status="deleted",
            lifecycle="retired",
            health="unknown",
            summary="Removed from the rack.",
        ),
        _object(
            "staging-gateway",
            "service",
            "Gateway Staging",
            status="inactive",
            lifecycle="planned",
            health="unknown",
            summary="Not in production.",
        ),
        _object(
            "retired-gateway-runbook",
            "runbook",
            "Gateway Runbook Retired",
            data={"runbook_status": "retired", "purpose": "Superseded gateway steps."},
        ),
    ]


# Rank first, then the stable label/id tie-breaker inside one rank.
RANKED_GATEWAY_ORDER = [
    # identity: the term appears in the id or the label
    "gateway-01",
    "decommissioned-gateway",
    "retired-gateway-runbook",
    "staging-gateway",
    "gateway-relay",
    # structured domain fields
    "rollout-project",
    "north-south-decision",
    "restart-runbook",
    # top-level summary
    "warehouse-node",
    # other allowlisted bounded field
    "depot-host",
]


@pytest.fixture
def session_factory(alembic_session_factory):
    with alembic_session_factory() as session:
        with transaction(session):
            for catalog_object in catalog_objects():
                session.add(catalog_object)
    return alembic_session_factory


@pytest.fixture
def client(
    session_factory,
    install_unrestricted_read_access,
) -> Generator[TestClient, None, None]:
    app = create_app()
    install_unrestricted_read_access(app)

    def override_get_session() -> Generator[Session, None, None]:
        with session_factory() as session:
            yield session

    app.dependency_overrides[get_session] = override_get_session
    with TestClient(app) as test_client:
        yield test_client


def _reader(permissions: dict[str, frozenset[Permission]]) -> ReadAccess:
    return ReadAccess(
        principal=PrincipalContext(
            id="reader",
            principal_type=PrincipalType.HUMAN,
            login="reader",
            display_name="Reader",
        ),
        policy=PolicySnapshot("reader", permissions, {}),
    )


def full_reader() -> ReadAccess:
    """A principal with full permissions on every synthetic catalog object."""
    return _reader(
        {
            catalog_object.id: frozenset(Permission)
            for catalog_object in catalog_objects()
        }
    )


def _ids(session: Session, access: ReadAccess, search: SearchQuery) -> list[str]:
    return [
        item.id
        for item in search_agent_objects(session, access, search=search, limit=50)
    ]


# --------------------------------------------------------------------------
# Exact modes
# --------------------------------------------------------------------------


def test_exact_ref_matches_canonical_reference_and_exact_id(session_factory) -> None:
    with session_factory() as session:
        access = full_reader()
        assert _ids(session, access, SearchQuery(query="host:gateway-01", match="exact_ref")) == [
            "gateway-01"
        ]
        assert _ids(session, access, SearchQuery(query="gateway-01", match="exact_ref")) == [
            "gateway-01"
        ]
        assert _ids(session, access, SearchQuery(query=" HOST:Gateway-01 ", match="exact_ref")) == [
            "gateway-01"
        ]
        # A partial id, a label, and a foreign kind prefix are not exact refs.
        assert _ids(session, access, SearchQuery(query="gateway", match="exact_ref")) == []
        assert _ids(session, access, SearchQuery(query="Gateway 01", match="exact_ref")) == []
        assert _ids(
            session, access, SearchQuery(query="service:gateway-01", match="exact_ref")
        ) == []


def test_exact_label_uses_the_documented_normalization(session_factory) -> None:
    with session_factory() as session:
        access = full_reader()
        for term in ("Gateway 01", "gateway 01", "  GATEWAY   01  ", "ｇａｔｅｗａｙ 01"):
            assert _ids(session, access, SearchQuery(query=term, match="exact_label")) == [
                "gateway-01"
            ]
        assert _ids(session, access, SearchQuery(query="gateway", match="exact_label")) == []
        assert _ids(session, access, SearchQuery(query="gateway-01", match="exact_label")) == []


# --------------------------------------------------------------------------
# Relevance ordering
# --------------------------------------------------------------------------


def test_relevance_order_follows_the_published_rank_ladder(session_factory) -> None:
    with session_factory() as session:
        page = query_agent_objects_page(
            session,
            full_reader(),
            search=SearchQuery(query="gateway"),
            limit=50,
            sort="relevance",
        )
        assert [item.id for item in page.items] == RANKED_GATEWAY_ORDER


def test_equal_ranks_break_ties_by_label_then_id(session_factory) -> None:
    with session_factory() as session:
        page = query_agent_objects_page(
            session,
            full_reader(),
            search=SearchQuery(query="192.0.2.1"),
            limit=50,
            sort="relevance",
        )
        # Both hosts match one structured domain field, so only the stable
        # label/id tie-breaker decides their order.
        assert [item.id for item in page.items] == ["gateway-01", "gateway-relay"]


def test_relevance_order_is_reproducible_for_repeated_queries(session_factory) -> None:
    with session_factory() as session:
        access = full_reader()
        runs = {
            tuple(
                item.id
                for item in query_agent_objects_page(
                    session,
                    access,
                    search=SearchQuery(query="gateway"),
                    limit=50,
                    sort="relevance",
                ).items
            )
            for _ in range(3)
        }
        assert len(runs) == 1


# --------------------------------------------------------------------------
# Import boilerplate
# --------------------------------------------------------------------------


def test_import_boilerplate_never_creates_a_match(session_factory) -> None:
    with session_factory() as session:
        access = full_reader()
        assert "legacy-migration-record" not in _ids(session, access, SearchQuery(query="gateway"))
        # Neither the provenance header nor an imported source document is
        # searched, however the row entered the catalog.
        for term in (
            "gateway-inventory.md",
            "gateway-import-bot",
            "Gateway inventory export",
            "wiki.example.test",
            "markdown://gateway-inventory.md",
        ):
            assert _ids(session, access, SearchQuery(query=term)) == []
        # The record itself stays discoverable by its own identity.
        assert _ids(session, access, SearchQuery(query="legacy-migration-record")) == [
            "legacy-migration-record"
        ]


def test_serialized_data_document_is_not_searched(session_factory) -> None:
    with session_factory() as session:
        access = full_reader()
        # Structural JSON and non-allowlisted paths never match.
        for term in ("schema_version", "disruptive", "implementation", "wiki.example.test"):
            assert _ids(session, access, SearchQuery(query=term)) == []


# --------------------------------------------------------------------------
# operational_only
# --------------------------------------------------------------------------


def test_operational_only_excludes_retired_and_inactive_records(session_factory) -> None:
    with session_factory() as session:
        access = full_reader()
        default_ids = _ids(session, access, SearchQuery(query="gateway"))
        operational_ids = _ids(
            session,
            access,
            SearchQuery(query="gateway", operational_only=True),
        )
        assert set(default_ids) - set(operational_ids) == {
            "decommissioned-gateway",
            "staging-gateway",
            "retired-gateway-runbook",
        }
        assert "gateway-01" in operational_ids
        # The default is unchanged: every record remains visible without the flag.
        assert "decommissioned-gateway" in default_ids


def test_operational_only_excludes_retired_knowledge_states(session_factory) -> None:
    with session_factory() as session:
        access = full_reader()
        assert "legacy-migration-record" in _ids(
            session, access, SearchQuery(query="legacy-migration-record")
        )
        assert _ids(
            session,
            access,
            SearchQuery(query="legacy-migration-record", operational_only=True),
        ) == []


def test_operational_only_never_probes_a_discover_only_stub(session_factory) -> None:
    with session_factory() as session:
        access = _reader({"decommissioned-gateway": frozenset({Permission.DISCOVER})})
        assert _ids(session, access, SearchQuery(query="gateway")) == [
            "decommissioned-gateway"
        ]
        assert _ids(
            session, access, SearchQuery(query="gateway", operational_only=True)
        ) == []


# --------------------------------------------------------------------------
# Search snippets
# --------------------------------------------------------------------------


def test_search_snippet_uses_summary_then_the_authorized_knowledge_field(
    session_factory,
) -> None:
    with session_factory() as session:
        page = query_agent_objects_page(
            session,
            full_reader(),
            search=SearchQuery(query="gateway"),
            limit=50,
            sort="relevance",
        )
        snippets = {item.id: item.search_snippet for item in page.items}
        assert snippets["gateway-01"] == "Edge gateway of the documentation network."
        assert snippets["restart-runbook"] == (
            "Restart the gateway service without dropping sessions."
        )
        assert snippets["north-south-decision"] == (
            "Route all north-south traffic through the gateway."
        )
        assert snippets["rollout-project"] == (
            "Gateway rollout is halfway through its pilot."
        )


def test_search_snippet_is_bounded_and_absent_from_stubs(session_factory) -> None:
    long_purpose = "Rotate the documentation gateway certificate. " * 20
    with session_factory() as session:
        with transaction(session):
            session.merge(
                _object(
                    "long-runbook",
                    "runbook",
                    "Certificate Rotation",
                    data={"runbook_status": "active", "purpose": long_purpose},
                )
            )
        detail = search_agent_objects(
            session,
            _reader({"long-runbook": frozenset(Permission)}),
            search=SearchQuery(query="certificate rotation", match="exact_label"),
        )[0]
        # The published maximum includes the truncation marker: a snippet of
        # 241 characters would violate the documented contract.
        assert detail.search_snippet.endswith(SNIPPET_TRUNCATION_MARKER)
        assert len(detail.search_snippet) == SEARCH_SNIPPET_MAX_LENGTH
        assert (
            len(detail.search_snippet.removesuffix(SNIPPET_TRUNCATION_MARKER))
            == SEARCH_SNIPPET_MAX_LENGTH - len(SNIPPET_TRUNCATION_MARKER)
        )
        assert detail.search_snippet[:40] == long_purpose[:40]

        stub = search_agent_objects(
            session,
            _reader({"long-runbook": frozenset({Permission.DISCOVER})}),
            search=SearchQuery(query="certificate rotation", match="exact_label"),
        )[0]
        assert stub.visibility == "stub"
        assert "search_snippet" not in stub.model_dump()


@pytest.mark.parametrize(
    "length",
    [
        SEARCH_SNIPPET_MAX_LENGTH - 1,
        SEARCH_SNIPPET_MAX_LENGTH,
        SEARCH_SNIPPET_MAX_LENGTH + 1,
        SEARCH_SNIPPET_MAX_LENGTH * 3,
    ],
)
def test_search_snippet_never_exceeds_the_published_maximum(length: int) -> None:
    source = "a" * length
    snippet = search_snippet(kind="runbook", summary=None, data={"purpose": source})
    assert snippet is not None
    assert len(snippet) <= SEARCH_SNIPPET_MAX_LENGTH
    if length <= SEARCH_SNIPPET_MAX_LENGTH:
        # A snippet that already fits is published unchanged and unmarked.
        assert snippet == source
    else:
        assert snippet.endswith(SNIPPET_TRUNCATION_MARKER)
        assert len(snippet) == SEARCH_SNIPPET_MAX_LENGTH
        assert snippet.startswith(
            source[: SEARCH_SNIPPET_MAX_LENGTH - len(SNIPPET_TRUNCATION_MARKER)]
        )


def test_search_snippet_field_publishes_the_documented_maximum() -> None:
    field = AgentCatalogObjectSummary.model_fields["search_snippet"]
    published = [
        constraint.max_length
        for constraint in field.metadata
        if getattr(constraint, "max_length", None) is not None
    ]
    assert published == [SEARCH_SNIPPET_MAX_LENGTH]
    with pytest.raises(ValidationError):
        AgentCatalogObjectSummary(
            ref="runbook:oversized",
            id="oversized",
            kind="runbook",
            label="Oversized",
            status="active",
            revision=1,
            search_snippet="a" * (SEARCH_SNIPPET_MAX_LENGTH + 1),
            provenance=CatalogProvenanceOut(),
        )


def test_search_snippet_is_absent_without_a_summary_or_knowledge_field(
    session_factory,
) -> None:
    with session_factory() as session:
        detail = search_agent_objects(
            session,
            full_reader(),
            search=SearchQuery(query="warehouse-node", match="exact_ref"),
        )[0]
        assert detail.search_snippet == "Feeds the gateway uplink twice per hour."
        depot = search_agent_objects(
            session,
            full_reader(),
            search=SearchQuery(query="depot-host", match="exact_ref"),
        )[0]
        assert depot.search_snippet == "Spare capacity."


# --------------------------------------------------------------------------
# Authorization: stubs, concealment, counts, and order
# --------------------------------------------------------------------------


def test_stub_matching_uses_identity_only(session_factory) -> None:
    with session_factory() as session:
        access = _reader({"restart-runbook": frozenset({Permission.DISCOVER})})
        # The purpose of a discover-only Runbook is never compared.
        assert _ids(session, access, SearchQuery(query="dropping sessions")) == []
        assert _ids(session, access, SearchQuery(query="restart")) == ["restart-runbook"]
        assert _ids(
            session, access, SearchQuery(query="runbook:restart-runbook", match="exact_ref")
        ) == ["restart-runbook"]
        assert _ids(
            session, access, SearchQuery(query="Restart Procedure", match="exact_label")
        ) == ["restart-runbook"]


def test_concealed_objects_change_neither_results_counts_nor_order(session_factory) -> None:
    with session_factory() as session:
        visible = {"gateway-01", "gateway-relay", "warehouse-node"}
        access = _reader({object_id: frozenset(Permission) for object_id in visible})
        page = query_agent_objects_page(
            session,
            access,
            search=SearchQuery(query="gateway"),
            limit=50,
            sort="relevance",
            include_total=True,
        )
        assert [item.id for item in page.items] == [
            "gateway-01",
            "gateway-relay",
            "warehouse-node",
        ]
        # Ranking, ordering, and the total are computed over the authorized set
        # only, so a concealed record cannot be counted or positioned.
        assert page.total == 3


def test_exact_modes_do_not_reveal_concealed_objects(session_factory) -> None:
    with session_factory() as session:
        access = _reader({"gateway-relay": frozenset(Permission)})
        assert _ids(session, access, SearchQuery(query="host:gateway-01", match="exact_ref")) == []
        assert _ids(session, access, SearchQuery(query="Gateway 01", match="exact_label")) == []


# --------------------------------------------------------------------------
# Cursor binding and relevance pagination
# --------------------------------------------------------------------------


def _relevance_page(client: TestClient, **params) -> dict:
    response = client.get(
        "/api/v1/objects",
        params={"q": "gateway", "sort": "relevance", "limit": 3, **params},
    )
    assert response.status_code == 200
    return response.json()


def test_relevance_pagination_enumerates_the_ranked_set_once(client: TestClient) -> None:
    collected: list[str] = []
    cursor: str | None = None
    for _ in range(10):
        payload = _relevance_page(client, **({"cursor": cursor} if cursor else {}))
        collected.extend(item["id"] for item in payload["items"])
        cursor = payload["next_cursor"]
        if cursor is None:
            break
    assert collected == RANKED_GATEWAY_ORDER


@pytest.mark.parametrize(
    "changed",
    [
        {"q": "relay"},
        {"match": "exact_label"},
        {"operational_only": "true"},
        {"sort": "id"},
        {"direction": "desc"},
        {"kind": "host"},
    ],
)
def test_cursor_binds_every_search_parameter(client: TestClient, changed: dict) -> None:
    cursor = _relevance_page(client)["next_cursor"]
    assert cursor is not None
    response = client.get(
        "/api/v1/objects",
        params={
            "q": "gateway",
            "sort": "relevance",
            "limit": 3,
            "cursor": cursor,
            **changed,
        },
    )
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "invalid_request"


def test_cursor_of_a_normal_query_is_rejected_after_a_mode_switch(
    client: TestClient,
) -> None:
    first = client.get(
        "/api/v1/objects",
        params={"q": "gateway-01", "match": "exact_ref", "sort": "relevance", "limit": 1},
    )
    assert first.status_code == 200
    assert first.json()["next_cursor"] is None


# --------------------------------------------------------------------------
# Published bounds and the narrowly scoped limit error
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("path", "maximum"),
    [
        ("/api/v1/objects", SEARCH_LIMIT_MAX),
        ("/api/v1/context", CONTEXT_LIMIT_MAX),
        ("/api/agent/search", AGENT_SEARCH_LIMIT_MAX),
        ("/api/agent/context", CONTEXT_LIMIT_MAX),
    ],
)
def test_rejected_search_limit_publishes_the_field_and_range(
    client: TestClient,
    path: str,
    maximum: int,
) -> None:
    response = client.get(path, params={"limit": maximum + 1})
    assert response.status_code == 422
    error = response.json()["error"]
    assert error["code"] == "validation_error"
    assert set(error["details"][0]) == set(SEARCH_LIMIT_DETAIL_FIELDS)
    assert error["details"] == [
        {
            "code": "value_out_of_range",
            "field": "limit",
            "location": "query.limit",
            "maximum": maximum,
            "message": error["details"][0]["message"],
            "minimum": 1,
            "path": None,
            "received": maximum + 1,
            "rule": None,
        }
    ]


def test_rejected_search_limit_does_not_echo_an_unbounded_or_odd_value(
    client: TestClient,
) -> None:
    huge = client.get("/api/v1/objects", params={"limit": "9" * 12})
    assert huge.status_code == 422
    assert huge.json()["error"]["details"][0]["received"] is None

    text = client.get("/api/v1/objects", params={"limit": "not-a-number"})
    assert text.status_code == 422
    detail = text.json()["error"]["details"][0]
    assert detail["code"] == "type_mismatch"
    assert detail["received"] is None
    assert detail["maximum"] == SEARCH_LIMIT_MAX


def test_other_rejected_search_input_is_never_echoed(client: TestClient) -> None:
    response = client.get(
        "/api/v1/objects",
        params={"q": "s" * 500, "kind": "not-a-kind", "limit": 500},
    )
    assert response.status_code == 422
    details = response.json()["error"]["details"]
    limit_details = [detail for detail in details if detail.get("field") == "limit"]
    assert len(limit_details) == 1
    for detail in details:
        if detail.get("field") == "limit":
            continue
        assert set(detail) == {"code", "location", "message", "path", "rule"}
        assert "s" * 500 not in json.dumps(detail)
        assert "not-a-kind" not in json.dumps(detail)


def test_limit_is_not_enriched_outside_the_search_resources(client: TestClient) -> None:
    response = client.get("/api/v1/projects", params={"limit": 500})
    assert response.status_code == 422
    for detail in response.json()["error"]["details"]:
        assert set(detail) == {"code", "location", "message", "path", "rule"}


def test_mcp_publishes_the_search_limit_bounds_and_field_accurate_error() -> None:
    schemas = {
        "blockwart.search": AGENT_SEARCH_LIMIT_MAX,
        "blockwart.get_context": CONTEXT_LIMIT_MAX,
    }
    for name, maximum in schemas.items():
        with pytest.raises(ToolInputError) as rejected:
            call_tool(name, {"limit": maximum + 1})
        assert set(rejected.value.details[0]) == set(SEARCH_LIMIT_DETAIL_FIELDS)
        assert rejected.value.details == [
            {
                "code": "value_out_of_range",
                "field": "limit",
                "location": "limit",
                "maximum": maximum,
                "message": rejected.value.details[0]["message"],
                "minimum": 1,
                "path": None,
                "received": maximum + 1,
                "rule": None,
            }
        ]


def test_mcp_keeps_other_rejected_read_arguments_opaque() -> None:
    with pytest.raises(ToolInputError) as rejected:
        call_tool("blockwart.search", {"kind": "not-a-kind", "q": "secret-term"})
    assert rejected.value.details == []

    with pytest.raises(ToolInputError) as mixed:
        call_tool("blockwart.search", {"kind": "not-a-kind", "limit": 500})
    assert [detail["field"] for detail in mixed.value.details] == ["limit"]
    assert "not-a-kind" not in json.dumps(mixed.value.details)


# --------------------------------------------------------------------------
# Surface parity
# --------------------------------------------------------------------------


def test_rest_agent_and_service_surfaces_agree_on_one_query(client: TestClient) -> None:
    expected = [
        item
        for item in RANKED_GATEWAY_ORDER
        if item not in {"decommissioned-gateway", "staging-gateway", "retired-gateway-runbook"}
    ]
    v1 = client.get(
        "/api/v1/objects",
        params={
            "q": "gateway",
            "operational_only": "true",
            "sort": "relevance",
            "limit": 50,
        },
    )
    assert [item["id"] for item in v1.json()["items"]] == expected

    legacy = client.get(
        "/api/agent/search",
        params={"q": "gateway", "operational_only": "true", "limit": 50},
    )
    assert legacy.status_code == 200
    assert [item["id"] for item in legacy.json()["results"]] == expected
    assert legacy.json()["filters"]["operational_only"] is True

    context = client.get(
        "/api/agent/context",
        params={"q": "gateway", "match": "exact_label", "limit": 5},
    )
    assert context.status_code == 200
    assert [item["id"] for item in context.json()["objects"]] == []
    assert context.json()["filters"]["match"] == "exact_label"


def test_unchanged_requests_keep_their_historical_response_shape(
    client: TestClient,
) -> None:
    legacy = client.get("/api/agent/search", params={"q": "gateway"})
    assert legacy.status_code == 200
    assert "match" not in legacy.json()["filters"]
    assert "operational_only" not in legacy.json()["filters"]

    default_sorted = client.get("/api/v1/objects", params={"q": "gateway", "limit": 50})
    assert [item["id"] for item in default_sorted.json()["items"]] == sorted(
        RANKED_GATEWAY_ORDER
    )
