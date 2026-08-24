"""Hard size budgets for the agent read projections, on synthetic fixtures only.

Every number recorded here is measured against the deterministic synthetic
catalog in `tests/synthetic_projection_catalog.py`. None of it describes a real
Blockwart instance, and none of it is a public product claim about catalog
size: it is an audit case that fails when a change makes an agent read cost
materially more context than the reviewed contract allows.

The budgets are deliberately loose enough to survive an honest additive field
and tight enough to fail if a projection silently starts serializing a section
it should have dropped.
"""

from __future__ import annotations

import json
from collections.abc import Generator
from typing import Annotated

import pytest
from fastapi import Depends
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session
from synthetic_projection_catalog import (
    BATCH_OBJECT_COUNT,
    SEARCH_HIT_COUNT,
    SyntheticCatalog,
    build_synthetic_catalog,
    estimate_agent_tokens,
    synthetic_read_access,
)

from blockwart.api.deps import get_session
from blockwart.api.security import require_api_read_access
from blockwart.db.session import transaction
from blockwart.main import create_app
from blockwart.services.read_access import ReadAccess

# Reviewed budgets for the synthetic 50-hit discovery page.
COMPACT_SEARCH_BYTE_BUDGET = 26_000
COMPACT_SEARCH_TOKEN_BUDGET = 6_500
# Reviewed budgets for the synthetic 20-object known-id batch.
COMPACT_BATCH_BYTE_BUDGET = 10_000
COMPACT_BATCH_TOKEN_BUDGET = 2_500
CONTEXT_BATCH_BYTE_BUDGET = 38_000
# A compact read must stay a small fraction of the full contract, or the
# projection has stopped paying for the second contract it introduces.
MAX_COMPACT_SHARE_OF_FULL = 0.35


@pytest.fixture
def synthetic_catalog(alembic_session_factory) -> SyntheticCatalog:
    with alembic_session_factory() as session:
        with transaction(session):
            return build_synthetic_catalog(session)


@pytest.fixture
def synthetic_client(
    alembic_session_factory,
    synthetic_catalog: SyntheticCatalog,
) -> Generator[tuple[TestClient, SyntheticCatalog], None, None]:
    app = create_app()

    def override_get_session() -> Generator[Session, None, None]:
        with alembic_session_factory() as session:
            yield session

    def override_access(
        session: Annotated[Session, Depends(get_session)],
    ) -> ReadAccess:
        del session
        return synthetic_read_access(synthetic_catalog)

    app.dependency_overrides[get_session] = override_get_session
    app.dependency_overrides[require_api_read_access] = override_access
    with TestClient(app) as client:
        yield client, synthetic_catalog


def test_compact_50_hit_search_stays_inside_its_reviewed_budget(
    synthetic_client: tuple[TestClient, SyntheticCatalog],
) -> None:
    client, _ = synthetic_client

    full = client.get(f"/api/v1/objects?limit={SEARCH_HIT_COUNT}")
    compact = client.get(f"/api/v1/objects?limit={SEARCH_HIT_COUNT}&projection=compact")

    assert full.status_code == 200
    assert compact.status_code == 200
    assert len(full.json()["items"]) == SEARCH_HIT_COUNT
    assert len(compact.json()["items"]) == SEARCH_HIT_COUNT
    assert len(compact.content) <= COMPACT_SEARCH_BYTE_BUDGET
    assert estimate_agent_tokens(compact.content) <= COMPACT_SEARCH_TOKEN_BUDGET
    assert len(compact.content) <= MAX_COMPACT_SHARE_OF_FULL * len(full.content)


def test_compact_50_hit_search_publishes_each_capability_set_once(
    synthetic_client: tuple[TestClient, SyntheticCatalog],
) -> None:
    """A wide compact page must not repeat one capability block per hit."""
    client, _ = synthetic_client

    payload = client.get(f"/api/v1/objects?limit={SEARCH_HIT_COUNT}&projection=compact").json()

    # Every hit shares one effective permission set in this fixture, so the
    # table holds exactly one entry no matter how many hits are returned.
    assert list(payload["capability_sets"]) == ["cap-dr"]
    assert {item["capability_set"] for item in payload["items"]} == {"cap-dr"}
    serialized = json.dumps(payload)
    assert serialized.count('"discover"') == 1
    assert serialized.count('"read"') == 1
    # No hit carries a repeated parent capability block at all.
    assert '"capabilities"' not in serialized


def test_compact_20_object_batch_stays_inside_its_reviewed_budget(
    synthetic_client: tuple[TestClient, SyntheticCatalog],
) -> None:
    client, catalog = synthetic_client
    object_ids = catalog.batch_ids

    full = client.post("/api/v1/object-contexts", json={"object_ids": object_ids})
    compact = client.post(
        "/api/v1/object-contexts",
        json={"object_ids": object_ids, "projection": "compact"},
    )
    context = client.post(
        "/api/v1/object-contexts",
        json={"object_ids": object_ids, "projection": "context"},
    )

    assert full.json()["count"] == BATCH_OBJECT_COUNT
    assert compact.json()["count"] == BATCH_OBJECT_COUNT
    assert context.json()["count"] == BATCH_OBJECT_COUNT
    assert len(compact.content) <= COMPACT_BATCH_BYTE_BUDGET
    assert estimate_agent_tokens(compact.content) <= COMPACT_BATCH_TOKEN_BUDGET
    assert len(context.content) <= CONTEXT_BATCH_BYTE_BUDGET
    assert len(compact.content) <= MAX_COMPACT_SHARE_OF_FULL * len(full.content)
    assert len(context.content) < len(full.content)


def test_batch_carries_no_comment_preview_unless_it_is_asked_for(
    synthetic_client: tuple[TestClient, SyntheticCatalog],
) -> None:
    client, catalog = synthetic_client
    object_ids = catalog.batch_ids

    default_batch = client.post(
        "/api/v1/object-contexts",
        json={"object_ids": object_ids, "projection": "context"},
    )
    with_comments = client.post(
        "/api/v1/object-contexts",
        json={
            "object_ids": object_ids,
            "projection": "context",
            "include_recent_comments": True,
        },
    )

    assert "recent_comments" not in default_batch.text
    assert with_comments.json()["projection"]["sections"].count("activity") == 1
    assert len(default_batch.content) <= len(with_comments.content)


def test_measured_projection_costs_match_the_documented_audit_case(
    synthetic_client: tuple[TestClient, SyntheticCatalog],
) -> None:
    """Fail loudly when a change moves the documented before/after measurement.

    `docs/agent-read-projections.md` publishes these synthetic numbers as the reviewed
    before/after evidence for the compact projections. The bands below are the
    tolerance that review accepted, so an honest additive field passes and a
    silently re-expanded projection does not.
    """
    client, catalog = synthetic_client

    measurements = {
        "search_full": len(client.get(f"/api/v1/objects?limit={SEARCH_HIT_COUNT}").content),
        "search_compact": len(
            client.get(f"/api/v1/objects?limit={SEARCH_HIT_COUNT}&projection=compact").content
        ),
        "batch_full": len(
            client.post(
                "/api/v1/object-contexts",
                json={"object_ids": catalog.batch_ids},
            ).content
        ),
        "batch_compact": len(
            client.post(
                "/api/v1/object-contexts",
                json={"object_ids": catalog.batch_ids, "projection": "compact"},
            ).content
        ),
        "batch_context": len(
            client.post(
                "/api/v1/object-contexts",
                json={"object_ids": catalog.batch_ids, "projection": "context"},
            ).content
        ),
    }

    documented_bands = {
        "search_full": (65_000, 85_000),
        "search_compact": (16_000, 24_000),
        "batch_full": (62_000, 85_000),
        "batch_compact": (6_000, 10_000),
        "batch_context": (27_000, 38_000),
    }
    for name, (lower, upper) in documented_bands.items():
        assert lower <= measurements[name] <= upper, (name, measurements[name])
